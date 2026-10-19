from __future__ import annotations

import base64
import hashlib
import http.client
import io
import json
import re
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
G4C_ROOT = TELEMETRY_ROOT.parent / "g4c-live"
sys.path.insert(0, str(TELEMETRY_ROOT))
sys.path.insert(0, str(G4C_ROOT))
sys.path.insert(0, str(G4C_ROOT / "tests"))

from g5_control_plane.config import FLOORS, G5Config, G5ConfigError, GROUPS, load_config
from g5_control_plane.app import LIVE_GET_TERMINAL_CONFIRMATION, build_service, main, run_manual_live_get
from g5_control_plane.server import create_server
from g5_control_plane.service import G5ControlPlaneService
from g5_control_plane.store import ControlPlaneStore
from collector.action_ledger import ActionLedger
from collector.auto_reallocation_gate import AutoReallocationLimits
from collector.continuous import ContinuousMonitor
from collector.guard_store import GuardStore
from collector.gpu_identity import normalize_gpu_identity
from collector.salad_action_policy import SaladAction
from collector.salad_action_transport import SaladActionExecutor
from broker_ledger import BrokerLedger, LIVE_SALAD_GET, initialize_ledger
from broker_offline import KillSwitch
from live_broker_gate import LiveBrokerGate
from live_broker_gate import LiveSaladReadSession
from live_https_transport import LiveHTTPSTransport, LoopbackTLSConfig, ProductionSaladTransport
from live_secret_boundary import InteractiveSecretProvider, SYNTHETIC_SECRET_VALUE, SyntheticSecretProvider
from test_live_broker_gate import GateLocalTLSServer


class G5ControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ready = threading.Event()
        self.service = None
        self.server = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        if not self.ready.wait(timeout=5):
            self.fail("local test server did not start")
        self.port = int(self.server.server_port)
        self.origin = f"http://127.0.0.1:{self.port}"
        self.host = f"127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=3)

    def _serve(self):
        self.service = G5ControlPlaneService(G5Config())
        self.server = create_server(self.service, port=0)
        self.ready.set()
        self.server.serve_forever()
        self.server.server_close()
        self.service.close()

    def request(self, method: str, path: str, *, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        selected = {"Host": self.host, **(headers or {})}
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        if encoded is not None:
            selected.setdefault("Content-Type", "application/json")
            selected.setdefault("Content-Length", str(len(encoded)))
        connection.request(method, path, body=encoded, headers=selected)
        response = connection.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        connection.close()
        return result

    def test_offline_config_and_existing_continuous_monitor_are_composed(self):
        status, _headers, body = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        state = json.loads(body)
        self.assertIsInstance(self.service.monitor, ContinuousMonitor)
        self.assertEqual(state["mode"], "offline_local")
        self.assertEqual(state["server"]["host"], "127.0.0.1")
        self.assertEqual(state["monitor"]["implementation"], "ContinuousMonitor")
        self.assertFalse(state["actions"]["live_actions_enabled"])
        self.assertFalse(state["actions"]["auto_reallocate"])
        self.assertTrue(state["actions"]["kill_switch_engaged"])
        self.assertEqual(state["economics"]["profit_status"], "UNKNOWN")
        self.assertEqual(state["economics"]["budget"]["status"], "UNKNOWN")
        self.assertEqual(state["auto_reallocation_gate"]["mode"], "OFFLINE_SIMULATION_ONLY")
        self.assertEqual(state["auto_reallocation_gate"]["status"], "DISABLED")
        self.assertFalse(state["auto_reallocation_gate"]["simulation_enabled"])
        self.assertFalse(state["auto_reallocation_gate"]["live_action_eligible"])
        self.assertFalse(state["auto_reallocation_gate"]["dossier_created"])
        self.assertEqual(state["startup_admission"]["mode"], "STARTUP_FAST_PATH_SEPARATE_FROM_ROLLING_DEGRADATION")
        self.assertEqual(state["startup_admission"]["status"], "NO_OBSERVATION")
        self.assertEqual(state["startup_admission"]["production_calibration_count"], 0)
        self.assertEqual(state["startup_admission"]["unmapped_or_uncalibrated_gpu_state"], "EARLY_UNKNOWN")
        self.assertTrue(state["startup_admission"]["rolling_guard_unchanged"])
        self.assertFalse(state["startup_admission"]["actions_performed"])
        self.assertFalse(state["startup_admission"]["request_submitted"])
        self.assertFalse(state["startup_admission"]["live_action_eligible"])
        self.assertEqual(state["latency_model"]["current_default_poll_seconds"], 30)
        self.assertFalse(state["latency_model"]["polling_default_changed"])
        self.assertEqual(state["latency_model"]["actual_request_rate_status"], "UNKNOWN_UNTIL_WATCHER_MEASUREMENT")
        self.assertEqual(state["latency_model"]["cost_classification"], "ESTIMATED_OPERATOR_RATE_NOT_VERIFIED_BILLING")
        self.assertEqual(
            [row["poll_interval_seconds"] for row in state["latency_model"]["polling_scenarios"]],
            [30, 15],
        )
        self.assertEqual(
            state["latency_model"]["reaction_exposure_scenarios"]["180_seconds"]["estimated_exposure_usd"],
            4.1283,
        )
        self.assertEqual([row["container_group"] for row in state["salad"]["groups"]], list(GROUPS))
        self.assertTrue(all(row["instances"] == [] for row in state["salad"]["groups"]))
        self.assertEqual(sorted(self.service.guard_policy.gpu_floors_ths.values()), [120, 120, 209, 350])

    def test_dashboard_exposes_bounded_device_rollups_without_inventing_fleet_scope(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        service = G5ControlPlaneService(G5Config(), clock=lambda: now.timestamp())
        identity = normalize_gpu_identity(
            "NVIDIA GeForce RTX 5090 Laptop GPU",
            identity_source="synthetic_test_fixture",
            identity_verified=True,
        )
        try:
            for index in range(21):
                timestamp = now - timedelta(seconds=600 - index * 30)
                service.guard_store.ingest_observation({
                    "event_id": f"rollup-dashboard-{index}",
                    "fleet_id": "fleet-dashboard",
                    "worker_id": "worker-dashboard",
                    "allocation_id": "allocation-dashboard",
                    "assignment_id": "assignment-dashboard",
                    "run_id": "run-dashboard",
                    "machine_id": "machine-dashboard",
                    "instance_id": "instance-dashboard",
                    "device_namespace": "fl4shminer_device",
                    "device_id": "0",
                    "occurred_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
                    "assignment_started_at_utc": (now - timedelta(minutes=20)).isoformat().replace("+00:00", "Z"),
                    "start_anchor_verified": True,
                    "hashrate_ths": 100.0,
                    "hashrate_semantics": "fl4shminer_device_reported",
                    "hashrate_source": "synthetic_test_fixture",
                    "gpu_identity": identity,
                    "provenance": {"source": "synthetic_test_fixture", "data_classification": "SYNTHETIC/UNVERIFIED"},
                })

            state = service.state()

            self.assertEqual(state["monitor"]["hashrate_rollup_policy"]["windows_seconds"], {
                "10m": 600, "30m": 1800, "60m": 3600, "24h": 86400,
            })
            device = next(item for item in state["monitor"]["devices"] if item["fleet_id"] == "fleet-dashboard")
            rollups = device["hashrate_rollups"]
            self.assertEqual(rollups["current"]["status"], "FRESH")
            self.assertEqual(rollups["current"]["hashrate_ths"], 100.0)
            self.assertEqual(rollups["windows"]["10m"]["mean_hashrate_ths"], 100.0)
            self.assertEqual(rollups["windows"]["10m"]["status"], "COMPLETE")
            self.assertEqual(state["monitor"]["fleet_hashrate_rollups"][0]["provider_scope_status"], "UNKNOWN")
            self.assertIsNone(state["monitor"]["fleet_hashrate_rollups"][0]["windows"]["10m"]["fleet_time_weighted_average_hashrate_ths"])
            self.assertFalse(state["actions"]["live_actions_enabled"])
            self.assertFalse(rollups["actions_performed"])
        finally:
            service.close()

    def test_dashboard_exposes_scoped_cost_estimate_without_promoting_billing(self):
        service = G5ControlPlaneService(G5Config())
        try:
            service.register_fleet_record({
                "fleet_id": "billing-fleet",
                "worker_id": "billing-worker",
                "assignments": [],
                "salad_cost_accounting": {
                    "organization": "adrianfiverr",
                    "project": "miners",
                    "fleet_id": "billing-fleet",
                    "billing_account_id": "billing-account-1",
                    "window_start_utc": "2026-10-18T12:00:00Z",
                    "window_end_utc": "2026-10-18T13:00:00Z",
                    "lifecycle_events": [
                        {
                            "event_id": "billing-run-start",
                            "source": "provider_lifecycle",
                            "source_reference": "fixture-start",
                            "assignment_id": "assignment-1",
                            "machine_id": "machine-1",
                            "instance_id": "instance-1",
                            "gpu_model": "RTX_5080_LAPTOP",
                            "state": "RUNNING",
                            "occurred_at_utc": "2026-10-18T12:00:00Z",
                        },
                        {
                            "event_id": "billing-run-stop",
                            "source": "provider_lifecycle",
                            "source_reference": "fixture-stop",
                            "assignment_id": "assignment-1",
                            "machine_id": "machine-1",
                            "instance_id": "instance-1",
                            "gpu_model": "RTX_5080_LAPTOP",
                            "state": "STOPPED",
                            "occurred_at_utc": "2026-10-18T12:10:00Z",
                        },
                    ],
                    "quoted_rates": [{
                        "quote_id": "quote-1",
                        "organization": "adrianfiverr",
                        "project": "miners",
                        "fleet_id": "billing-fleet",
                        "billing_account_id": "billing-account-1",
                        "gpu_model": "RTX_5080_LAPTOP",
                        "usd_per_hour": "0.417",
                        "effective_from_utc": "2026-10-18T12:00:00Z",
                        "effective_until_utc": "2026-10-18T13:00:00Z",
                        "rate_classification": "QUOTED",
                        "source_reference": "synthetic-quote",
                        "source_timestamp_utc": "2026-10-18T11:59:00Z",
                    }],
                    "billing_evidence": [],
                },
            })
            state = service.state()
            fleet = next(item for item in state["fleets"] if item["fleet_id"] == "billing-fleet")
            cost = fleet["salad_cost_reconciliation"]
            self.assertEqual(cost["estimated_exposure_seconds"], "600")
            self.assertEqual(cost["estimated_accumulated_cost_usd"], "0.0695")
            self.assertEqual(cost["estimated_classification"], "ESTIMATED")
            self.assertEqual(cost["verified_billing_status"], "UNKNOWN")
            self.assertIsNone(cost["verified_billed_cost_usd"])
            self.assertEqual(state["economics"]["salad_cost_reconciliation"]["live_billing_read_status"], "NOT_ELIGIBLE_UNTIL_VERIFIED")
            self.assertEqual(state["latency_model"]["operator_cost_scenarios"]["scenarios"]["180_seconds"]["estimated_cost_usd"], "4.1283")
            self.assertFalse(state["actions"]["auto_reallocate"])
            self.assertFalse(cost["actions_performed"])
        finally:
            service.close()

    def test_config_rejects_external_bind_prod_project_live_actions_and_bad_budget(self):
        for mutation in (
            {"host": "0.0.0.0"},
            {"firebase_enabled": True},
            {"hard_budget_usd": 31.0},
            {"live_actions_enabled": True},
            {"live_get_enabled": "false"},
            {"kill_switch_engaged": 0},
            {"state_dir": None},
        ):
            with self.subTest(mutation=mutation):
                kwargs = {}
                if "host" in mutation:
                    kwargs["host"] = mutation["host"]
                if "firebase_enabled" in mutation:
                    kwargs["firebase_enabled"] = mutation["firebase_enabled"]
                if "hard_budget_usd" in mutation:
                    kwargs["hard_budget_usd"] = mutation["hard_budget_usd"]
                if "live_actions_enabled" in mutation:
                    kwargs["live_actions_enabled"] = mutation["live_actions_enabled"]
                if "live_get_enabled" in mutation:
                    kwargs["live_get_enabled"] = mutation["live_get_enabled"]
                if "kill_switch_engaged" in mutation:
                    kwargs["kill_switch_engaged"] = mutation["kill_switch_engaged"]
                if "state_dir" in mutation:
                    kwargs["state_dir"] = mutation["state_dir"]
                with self.assertRaises(G5ConfigError):
                    G5Config(**kwargs)
        with self.assertRaises(ValueError):
            create_server(self.service, host="0.0.0.0", port=8765)

    def test_internal_auto_gate_preview_is_closed_and_never_creates_an_action_dossier(self):
        service = G5ControlPlaneService(G5Config())
        try:
            denied_simulation_arm = service.arm_auto_reallocation_simulation(
                AutoReallocationLimits(10, 20, 0, 3, 5),
            )
            self.assertEqual(denied_simulation_arm["status"], "BLOCKED")
            self.assertFalse(denied_simulation_arm["simulation_armed"])
            result = service.preview_auto_reallocation(
                "EARLY", trigger_evidence={}, source_evidence={}, policy_evidence={},
                generation_evidence={}, provider_binding={}, provider_revalidation={},
                budget_evidence={}, allocation_history={}, fleet_id="", now_utc="not-a-time",
            )
            self.assertEqual(result["status"], "BLOCKED")
            self.assertIn("EARLY_DECISION_SCHEMA_INVALID", result["blockers"])
            self.assertFalse(result["actions_performed"])
            self.assertFalse(result["request_submitted"])
            self.assertFalse(result["dossier_created"])
            self.assertFalse(result["live_action_eligible"])
            self.assertEqual(service.action_ledger.snapshot(), [])
            state = service.state()
            self.assertFalse(state["actions"]["auto_reallocate"])
            self.assertFalse(state["auto_reallocation_gate"]["simulation_enabled"])
            self.assertEqual(state["auto_reallocation_gate"]["reviews"]["EARLY"]["status"], "BLOCKED")
        finally:
            service.close()

    def test_offline_simulation_control_is_internal_durable_and_restart_closed(self):
        with tempfile.TemporaryDirectory(prefix="g5-simulation-control-") as temp:
            ledger_path = Path(temp) / "action-ledger.sqlite3"
            ledger = ActionLedger(ledger_path)
            service = G5ControlPlaneService(G5Config(kill_switch_engaged=False), action_ledger=ledger)
            try:
                initial = service.state()
                self.assertFalse(initial["auto_reallocation_gate"]["simulation_enabled"])
                self.assertFalse(initial["actions"]["auto_armed"])
                self.assertFalse(initial["actions"]["live_actions_enabled"])

                # The existing public auto-reallocate command never arms either
                # the synthetic simulator or the production path.
                blocked_auto = service.set_auto_reallocate(True)
                self.assertEqual(blocked_auto["status"], "BLOCKED")
                self.assertFalse(service.state()["auto_reallocation_gate"]["simulation_enabled"])

                limits = AutoReallocationLimits(10, 20, 0, 3, 5)
                armed = service.arm_auto_reallocation_simulation(limits)
                self.assertEqual(armed["status"], "SIMULATION_ARMED")
                state = service.state()
                self.assertTrue(state["auto_reallocation_gate"]["simulation_enabled"])
                self.assertTrue(state["actions"]["simulation_armed"])
                self.assertFalse(state["actions"]["auto_armed"])
                self.assertFalse(state["actions"]["live_actions_enabled"])
                self.assertFalse(state["auto_reallocation_gate"]["live_action_eligible"])
                self.assertEqual(service.action_ledger.snapshot(), [])

                blocked_auto = service.set_auto_reallocate(True)
                self.assertEqual(blocked_auto["status"], "BLOCKED")
                self.assertTrue(service.state()["auto_reallocation_gate"]["simulation_enabled"])
                self.assertFalse(service.state()["actions"]["auto_armed"])

                base_time = datetime.now(timezone.utc).replace(microsecond=0)

                def reserve_synthetic(key: str, offset_seconds: int, assignment_scope: str, target_scope: str):
                    created = base_time + timedelta(seconds=offset_seconds)
                    created_text = created.isoformat().replace("+00:00", "Z")
                    scope_values = {
                        "organization": "2" * 64, "fleet": "3" * 64,
                        "assignment": assignment_scope, "target": target_scope,
                    }
                    return service.action_ledger.reserve_auto_reallocation_simulation(
                        simulation_key=key * 64, trigger_key=key * 64,
                        scopes=scope_values, at_utc=created_text, at_epoch=created.timestamp(),
                        limits=limits.as_ledger_limits(),
                        payload={
                            "simulation_only": True, "actions_performed": False,
                            "request_submitted": False, "dossier_created": False,
                            "live_action_eligible": False, "data_classification": "SYNTHETIC/UNVERIFIED",
                            "synthetic_fixture_id": "G5-SYNTHETIC-ACTION-PATH",
                            "reservation_identity": {
                                "assignment_scope": assignment_scope, "target_scope": target_scope,
                                "original_instance_fingerprint": "4" * 64,
                                "original_generation_fingerprint": "5" * 64,
                            },
                        },
                    )

                self.assertEqual(reserve_synthetic("1", 0, "a" * 64, "b" * 64)["status"], "SIMULATION_RESERVED")
                self.assertEqual(reserve_synthetic("2", 2, "c" * 64, "d" * 64)["status"], "SIMULATION_RESERVED")
                with patch.object(SaladActionExecutor, "execute", autospec=True) as executor:
                    accepted = service.simulate_auto_reallocation_transport(
                        "1" * 64, outcome="FAKE_HTTP_202",
                        at_utc=(base_time + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
                    )
                    timeout = service.simulate_auto_reallocation_transport(
                        "2" * 64, outcome="FAKE_TIMEOUT",
                        at_utc=(base_time + timedelta(seconds=3)).isoformat().replace("+00:00", "Z"),
                    )
                    executor.assert_not_called()
                self.assertEqual(accepted["status"], "SIMULATED_ACCEPTED_PENDING")
                self.assertEqual(timeout["status"], "SIMULATED_RECONCILIATION_REQUIRED")
                self.assertFalse(timeout["automatic_retry"])
                self.assertFalse(service.action_ledger.snapshot())

                service.set_kill_switch(True)
                self.assertFalse(service.state()["auto_reallocation_gate"]["simulation_enabled"])
                self.assertEqual(
                    service.simulate_auto_reallocation_transport("1" * 64, outcome="FAKE_HTTP_202", at_utc="2026-10-18T12:00:00Z")["reason"],
                    "SIMULATION_GATE_CLOSED",
                )
                service.set_kill_switch(False)
                self.assertFalse(service.state()["auto_reallocation_gate"]["simulation_enabled"])
                self.assertEqual(service.arm_auto_reallocation_simulation(limits)["status"], "SIMULATION_ARMED")
                control = service.audit()["auto_reallocation_simulation_control"]
                event_types = [event["event_type"] for event in control["events"]]
                self.assertIn("SERVICE_START_CLOSED", event_types)
                self.assertIn("SIMULATION_ARMED", event_types)
                self.assertIn("KILL_SWITCH_ENGAGED", event_types)
                self.assertIn("KILL_SWITCH_DISENGAGED", event_types)
            finally:
                service.close()

            reopened_ledger = ActionLedger(ledger_path)
            reopened_service = G5ControlPlaneService(
                G5Config(kill_switch_engaged=False), action_ledger=reopened_ledger,
            )
            try:
                reopened = reopened_service.state()
                self.assertFalse(reopened["auto_reallocation_gate"]["simulation_enabled"])
                self.assertFalse(reopened["actions"]["simulation_armed"])
                self.assertFalse(reopened["actions"]["auto_armed"])
                events = reopened_service.audit()["auto_reallocation_simulation_control"]["events"]
                self.assertEqual(events[-1]["event_type"], "SERVICE_START_CLOSED")
                self.assertFalse(reopened_service.action_ledger.snapshot())
            finally:
                reopened_service.close()

        status, _headers, _body = self.request(
            "POST", "/api/auto-reallocation-simulation/arm", body={}, headers={
                "Origin": self.origin, "X-CSRF-Token": self.server.csrf_token,
            },
        )
        self.assertEqual(status, 404)

    def test_example_config_has_exact_floors_and_all_real_gates_off(self):
        config_path = TELEMETRY_ROOT / "g5-live-config.example.json"
        config = load_config(config_path)
        self.assertEqual(dict(config.gpu_floors_ths), FLOORS)
        self.assertFalse(config.live_get_enabled)
        self.assertFalse(config.live_actions_enabled)
        self.assertFalse(config.live_spend_authorized)
        self.assertFalse(config.auto_reallocate)
        self.assertTrue(config.kill_switch_engaged)

    def test_operational_config_precedence_and_independent_gpu_form_factors(self):
        default_config = load_config(None, environ={})
        self.assertEqual(dict(default_config.gpu_floors_ths), {key: float(value) for key, value in FLOORS.items()})
        self.assertEqual(default_config.source_for("warmup_seconds"), "DEFAULTS")
        with self.assertRaises(TypeError):
            default_config.gpu_floors_ths["RTX 5080|laptop|salad_json_log_gpu_class_name"] = 1
        config_path = TELEMETRY_ROOT / "g5-live-config.example.json"
        data = json.loads(config_path.read_text(encoding="utf-8"))
        data["gpu_floors_ths"]["RTX 5080|laptop|salad_json_log_gpu_class_name"] = 105
        data["monitor"]["warmup_seconds"] = 100
        data["salad_hourly_price_usd_estimate"] = 0.09
        with tempfile.TemporaryDirectory(prefix="g5-config-precedence-") as temp:
            custom_path = Path(temp) / "config.json"
            custom_path.write_text(json.dumps(data), encoding="utf-8")
            config = load_config(custom_path, environ={
                "SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS": "110",
                "SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS": "115",
                "SALAD_G5_WARMUP_SECONDS": "120",
                "SALAD_G5_HASH_WINDOW_SECONDS": "240",
                "SALAD_G5_HOURLY_PRICE_USD_ESTIMATE": "0.08",
                "SALAD_API_KEY": "synthetic-secret-must-be-ignored",
                "SALAD_G5_LIVE_GET_ENABLED": "true",
                "SALAD_G5_LIVE_ACTIONS_ENABLED": "true",
                "SALAD_G5_AUTO_REALLOCATE": "true",
            })
        self.assertEqual(config.gpu_floors_ths["RTX 5080|laptop|salad_json_log_gpu_class_name"], 110)
        self.assertEqual(config.gpu_floors_ths["RTX 5090|laptop|salad_json_log_gpu_class_name"], 115)
        self.assertEqual(config.gpu_floors_ths["RTX 5080|desktop|salad_json_log_gpu_class_name"], 209)
        self.assertEqual(config.gpu_floors_ths["RTX 5090|desktop|salad_json_log_gpu_class_name"], 350)
        self.assertEqual(config.source_for("gpu_floors_ths.RTX 5080|laptop|salad_json_log_gpu_class_name"), "ENV")
        self.assertEqual(config.source_for("gpu_floors_ths.RTX 5090|laptop|salad_json_log_gpu_class_name"), "ENV")
        self.assertEqual(config.source_for("gpu_floors_ths.RTX 5080|desktop|salad_json_log_gpu_class_name"), "JSON")
        self.assertEqual(config.warmup_seconds, 120)
        self.assertEqual(config.source_for("warmup_seconds"), "ENV")
        self.assertEqual(config.hash_window_seconds, 240)
        self.assertEqual(config.salad_hourly_price_usd_estimate, 0.08)
        self.assertEqual(config.source_for("salad_hourly_price_usd_estimate"), "ENV")
        self.assertFalse(config.live_get_enabled)
        self.assertFalse(config.live_actions_enabled)
        self.assertFalse(config.auto_reallocate)
        self.assertNotIn("synthetic-secret-must-be-ignored", json.dumps(dict(config.value_sources)))

        service = G5ControlPlaneService(config)
        try:
            policy = service.guard_policy
            self.assertEqual(policy.gpu_floors_ths, config.gpu_floors_ths)
            self.assertEqual(policy.warmup_seconds, config.warmup_seconds)
            self.assertEqual(policy.hash_window_seconds, config.hash_window_seconds)
            self.assertEqual(policy.reevaluation_interval_seconds, config.reevaluation_interval_seconds)
            self.assertEqual(policy.minimum_samples_per_window, config.minimum_samples_per_window)
            self.assertEqual(policy.expected_sample_interval_seconds, config.expected_sample_interval_seconds)
            self.assertEqual(policy.maximum_sample_gap_seconds, config.maximum_sample_gap_seconds)
            self.assertEqual(policy.minimum_window_coverage_ratio, config.minimum_window_coverage_ratio)
            self.assertEqual(policy.consecutive_bad_windows, config.consecutive_bad_windows)
            controller_policy = service.reallocation_controller.policy
            self.assertEqual(controller_policy.gpu_floors_ths, config.gpu_floors_ths)
            self.assertEqual(controller_policy.minimum_window_coverage_ratio, config.minimum_window_coverage_ratio)
            self.assertEqual(controller_policy.maximum_sample_gap_seconds, config.maximum_sample_gap_seconds)
            self.assertEqual(controller_policy.maximum_telemetry_age_seconds, config.maximum_sample_gap_seconds)
            self.assertEqual(
                controller_policy.evaluation_max_age_seconds,
                config.maximum_sample_gap_seconds + config.reevaluation_interval_seconds * config.consecutive_bad_windows,
            )
            state = service.state()
            self.assertEqual(state["monitor"]["configuration"]["gpu_floors_ths"][1]["threshold_ths"], 110)
            self.assertEqual(state["monitor"]["configuration"]["gpu_floors_ths"][1]["source"], "ENV")
            self.assertEqual(state["monitor"]["policy_hash"], service.monitor.policy_hash)
            self.assertEqual(state["economics"]["hourly_price_estimate"]["usd_per_hour"], 0.08)
            self.assertEqual(state["economics"]["hourly_price_estimate"]["classification"], "OPERATOR_ESTIMATE_NOT_VERIFIED_BILLING")
            self.assertFalse(state["economics"]["hourly_price_estimate"]["billing_verified"])
            self.assertFalse(state["economics"]["hourly_price_estimate"]["spend_authorized"])
            self.assertEqual(state["economics"]["profit_status"], "UNKNOWN")
            self.assertFalse(state["salad"]["live_get_enabled"])
            self.assertFalse(state["actions"]["live_actions_enabled"])
            self.assertFalse(state["actions"]["auto_reallocate"])
        finally:
            service.close()

    def test_operational_config_rejects_invalid_floors_sampling_and_price(self):
        config_path = TELEMETRY_ROOT / "g5-live-config.example.json"
        base = json.loads(config_path.read_text(encoding="utf-8"))
        invalid_json_overrides = (
            ("gpu_floors_ths", {"RTX 5090|laptop|unverified": 120}),
            ("gpu_floors_ths", {"RTX 5080|laptop|salad_json_log_gpu_class_name": 0}),
            ("gpu_floors_ths", {"RTX 5080|laptop|salad_json_log_gpu_class_name": True}),
            ("gpu_floors_ths", {"RTX 5080|laptop|salad_json_log_gpu_class_name": float("inf")}),
            ("monitor", {"minimum_window_coverage_ratio": 1.1}),
            ("monitor", {"maximum_sample_gap_seconds": 5}),
            ("monitor", {"minimum_samples_per_window": 13}),
            ("monitor", {"consecutive_bad_windows": 0}),
            ("monitor", {"warmup_seconds": True}),
        )
        for key, override in invalid_json_overrides:
            with self.subTest(key=key, override=override):
                data = json.loads(json.dumps(base))
                if key == "monitor":
                    data["monitor"].update(override)
                else:
                    data[key] = override
                with tempfile.TemporaryDirectory(prefix="g5-invalid-config-") as temp:
                    path = Path(temp) / "config.json"
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(G5ConfigError):
                        load_config(path, environ={})
        with tempfile.TemporaryDirectory(prefix="g5-invalid-price-") as temp:
            data = json.loads(json.dumps(base))
            data["salad_hourly_price_usd_estimate"] = float("inf")
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(G5ConfigError):
                load_config(path, environ={})
        for env in (
            {"SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS": "0"},
            {"SALAD_G5_WARMUP_SECONDS": "-1"},
            {"SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO": "nan"},
            {"SALAD_G5_HOURLY_PRICE_USD_ESTIMATE": "inf"},
            {"SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "10.0"},
            {"SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS": "110", "SALAD_G5_HASH_WINDOW_SECONDS": "60", "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "10"},
        ):
            with self.subTest(env=env), self.assertRaises(G5ConfigError):
                load_config(None, environ=env)

    def test_monitor_policy_change_preserves_history_but_requires_current_policy_evaluations(self):
        with tempfile.TemporaryDirectory(prefix="g5-policy-restart-") as temp:
            db_path = Path(temp) / "guard.sqlite3"
            first_floors = dict(FLOORS)
            first = G5ControlPlaneService(G5Config(gpu_floors_ths=first_floors), guard_store=GuardStore(db_path))
            identity = normalize_gpu_identity(
                "NVIDIA GeForce RTX 5090 Laptop GPU",
                identity_source="synthetic_test_fixture",
                identity_verified=True,
            )
            sample_time = datetime.now(timezone.utc).replace(microsecond=0)
            assignment_start = sample_time - timedelta(minutes=10)
            sample = {
                "event_type": "gpu_sample", "event_id": "synthetic-policy-restart-sample",
                "fleet_id": "fleet-synthetic", "worker_id": "worker-synthetic",
                "allocation_id": "allocation-policy-restart", "assignment_id": "assignment-policy-restart",
                "run_id": "run-policy-restart", "machine_id": "machine-policy-restart",
                "instance_id": "instance-policy-restart", "device_namespace": "fl4shminer_device",
                "device_id": "0", "occurred_at_utc": sample_time.isoformat().replace("+00:00", "Z"),
                "assignment_started_at_utc": assignment_start.isoformat().replace("+00:00", "Z"), "start_anchor_verified": True,
                "hashrate_ths": 80.0, "hashrate_semantics": "fl4shminer_device_reported",
                "hashrate_source": "synthetic_test_fixture", "gpu_identity": identity,
                "reallocation_history_known": True, "reallocation_count": 0,
                "provenance": {"source": "synthetic_test_fixture", "data_classification": "SYNTHETIC/UNVERIFIED"},
            }
            first.ingest_miner_events([sample])
            track_id = first.guard_store.track_rows()[0]["track_id"]
            first_hash = first.monitor.policy_hash
            old_count = len(first.guard_store.evaluations_for_track(track_id))
            first.close()

            changed_floors = dict(FLOORS)
            changed_floors["RTX 5090|laptop|salad_json_log_gpu_class_name"] = 115
            second = G5ControlPlaneService(G5Config(gpu_floors_ths=changed_floors), guard_store=GuardStore(db_path))
            try:
                self.assertNotEqual(second.monitor.policy_hash, first_hash)
                self.assertEqual(len(second.guard_store.track_rows()), 1)
                before = second.guard_store.evaluations_for_track(track_id)
                self.assertGreaterEqual(len(before), old_count)
                self.assertTrue(any(row["policy_hash"] == first_hash for row in before))
                later = (sample_time + timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
                second.evaluate_control_cycle(later)
                rows = second.guard_store.evaluations_for_track(track_id)
                self.assertTrue(any(row["policy_hash"] == first_hash for row in rows))
                self.assertEqual(sum(row["policy_hash"] == second.monitor.policy_hash for row in rows), 1)
                decision = second._controller_decisions[track_id]
                self.assertIn("two_consecutive_low_evaluations_required", decision["blockers"])
                self.assertEqual(second.state()["monitor"]["policy_hash"], second.monitor.policy_hash)
            finally:
                second.close()

    def test_http_serves_local_dashboard_state_and_csrf_without_secret(self):
        status, headers, html = self.request("GET", "/")
        text = html.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("Salad GPU Control Plane", text)
        self.assertIn('name="csrf-token"', text)
        self.assertNotIn("Salad-Api-Key", text)
        self.assertEqual(headers.get("Content-Security-Policy", "").split(";", 1)[0], "default-src 'self'")
        token = re.search(r'<meta name="csrf-token" content="([^"]+)"', text).group(1)
        self.assertTrue(token)
        state_status, state_headers, state_bytes = self.request("GET", "/api/state")
        state = json.loads(state_bytes)
        self.assertEqual(state_status, 200)
        self.assertNotIn("Access-Control-Allow-Origin", state_headers)
        self.assertNotIn("secret", json.dumps(state).casefold())
        self.assertEqual(len(state["salad"]["groups"]), 4)

    def test_post_requires_same_origin_csrf_json_and_group_scope(self):
        status, _headers, body = self.request(
            "POST", "/api/actions/start", body={"container_group": "fl4shminer"},
            headers={"Origin": self.origin},
        )
        self.assertEqual(status, 403)
        self.assertIn("csrf", body.decode())

        status, _headers, _body = self.request(
            "POST", "/api/actions/start", body={"container_group": "fl4shminer"},
            headers={"Origin": "http://attacker.invalid", "X-CSRF-Token": self.server.csrf_token},
        )
        self.assertEqual(status, 403)

        status, _headers, body = self.request(
            "POST", "/api/actions/start", body={"container_group": "outside-scope"},
            headers={"Origin": self.origin, "X-CSRF-Token": self.server.csrf_token},
        )
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["actions_performed"])

        status, _headers, body = self.request(
            "POST", "/api/auto-reallocate", body={"armed": True},
            headers={"Origin": self.origin, "X-CSRF-Token": self.server.csrf_token},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "BLOCKED")
        _status, _headers, state_body = self.request("GET", "/api/state")
        self.assertFalse(json.loads(state_body)["actions"]["auto_armed"])

    def test_refresh_is_blocked_and_reallocation_binding_cannot_be_passed_by_browser(self):
        status, _headers, body = self.request(
            "POST", "/api/refresh", body={},
            headers={"Origin": self.origin, "X-CSRF-Token": self.server.csrf_token},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "LIVE_GET_DISABLED")
        self.assertFalse(json.loads(body)["live_calls_performed"])

        status, _headers, body = self.request(
            "POST", "/api/actions/reallocate",
            body={"container_group": "fl4shminer", "instance_id": "12345678-1234-5678-1234-567812345678", "binding_status": "VERIFIED", "machine_id": "machine-1"},
            headers={"Origin": self.origin, "X-CSRF-Token": self.server.csrf_token},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "BLOCKED")

        class MustNotExecuteAction:
            def __init__(self):
                self.calls = []

            def execute(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("offline control API must not dispatch actions")

        sentinel = MustNotExecuteAction()
        self.service.action_executor = sentinel
        # Keep the kill switch locally clear to prove the config gate and
        # absence of a browser-supplied dossier independently block dispatch.
        self.service._kill_switch_engaged = False
        status, _headers, body = self.request(
            "POST", "/api/actions/reallocate",
            body={
                "container_group": "fl4shminer", "instance_id": "12345678-1234-5678-1234-567812345678",
                "assignment_id": "assignment-synthetic", "deterioration_id": "synthetic-deterioration",
                "binding_status": "VERIFIED", "machine_id": "machine-synthetic",
                "decision_dossier": {"signed": True},
            },
            headers={"Origin": self.origin, "X-CSRF-Token": self.server.csrf_token},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "BLOCKED")
        self.assertEqual(sentinel.calls, [])

    def test_wrong_host_and_non_json_commands_are_denied(self):
        status, _headers, _body = self.request("GET", "/api/state", headers={"Host": "attacker.invalid"})
        self.assertEqual(status, 421)
        status, _headers, _body = self.request(
            "POST", "/api/refresh", body={},
            headers={"Origin": self.origin, "X-CSRF-Token": self.server.csrf_token, "Content-Type": "text/plain"},
        )
        self.assertEqual(status, 415)

    def test_store_rejects_secret_fields_and_browser_has_no_budget_or_binding_write_route(self):
        with self.assertRaises(ValueError):
            self.service.store.append_audit("TEST", {"api_key": "synthetic-never-store"}, "2026-10-11T00:00:00Z")
        for path in ("/api/budget", "/api/binding", "/api/provider-observation"):
            status, _headers, _body = self.request(
                "POST", path, body={"status": "VERIFIED"},
                headers={"Origin": self.origin, "X-CSRF-Token": self.server.csrf_token},
            )
            self.assertEqual(status, 404)

    def test_budget_import_rejects_non_usd_negative_and_non_finite_amounts(self):
        common = {
            "evidence_id": "synthetic-budget-1",
            "source_reference": "synthetic-only",
            "occurred_at_utc": "2026-10-11T00:00:00Z",
            "currency": "USD",
            "verification_status": "VERIFIED",
            "source": "trusted_backend_import",
        }
        for changes in ({"currency": "MXN"}, {"amount_usd": "-0.01"}, {"amount_usd": "NaN"}, {"amount_usd": "Infinity"}):
            values = {"amount_usd": "1.00", **common, **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.service.store.record_budget_evidence(**values)
        self.service.store.record_budget_evidence(**{"amount_usd": "29.99", **common})
        summary = self.service.store.budget_summary()
        self.assertEqual(summary["status"], "VERIFIED")
        self.assertEqual(summary["verified_spend_usd"], 29.99)

    def test_pending_action_exposure_is_atomic_and_blocks_the_next_action_at_usd_30(self):
        store = ControlPlaneStore(":memory:")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        now_text = now.isoformat().replace("+00:00", "Z")
        expiry = (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        try:
            store.record_budget_evidence(
                evidence_id="synthetic-current-invoice", source_reference="synthetic-invoice-source",
                occurred_at_utc=now_text, currency="USD", amount_usd="29.85",
                verification_status="VERIFIED", source="trusted_backend_import",
            )
            store.record_action_cost_evidence(
                evidence_id="synthetic-action-price", source_reference="synthetic-price-source",
                currency="USD", amount_usd="0.10", observed_at_utc=now_text,
                valid_until_utc=expiry, verification_status="VERIFIED", source="trusted_backend_import",
            )
            status = store.reserve_budget_exposure(
                action_key="synthetic-action-1", evidence_id="synthetic-action-price",
                source_reference="synthetic-price-source", amount_usd="0.10",
                occurred_at_utc=now_text, source="trusted_backend_reservation",
            )
            self.assertEqual(status, "RESERVED")
            summary = store.budget_summary()
            self.assertEqual(summary["pending_exposure_usd"], 0.1)
            self.assertEqual(summary["pending_exposure_status"], "VERIFIED")
            self.assertEqual(summary["maximum_exposure_usd"], 30.05)
            self.assertEqual(summary["maximum_exposure_status"], "VERIFIED")
            with self.assertRaisesRegex(ValueError, "exceeds the hard budget"):
                store.reserve_budget_exposure(
                    action_key="synthetic-action-2", evidence_id="synthetic-action-price",
                    source_reference="synthetic-price-source", amount_usd="0.10",
                    occurred_at_utc=now_text, source="trusted_backend_reservation",
                )
            with self.assertRaisesRegex(ValueError, "verified USD billing evidence"):
                store.reconcile_budget_exposure(
                    "synthetic-action-1", evidence_id="not-an-invoice", status="RELEASED",
                    occurred_at_utc=now_text, source="trusted_backend_reconciliation",
                )
            store.record_budget_evidence(
                evidence_id="synthetic-updated-invoice", source_reference="synthetic-invoice-source-2",
                occurred_at_utc=(now + timedelta(seconds=2)).isoformat().replace("+00:00", "Z"),
                currency="USD", amount_usd="29.95",
                verification_status="VERIFIED", source="trusted_backend_import",
            )
            store.reconcile_budget_exposure(
                "synthetic-action-1", evidence_id="synthetic-updated-invoice", status="RELEASED",
                occurred_at_utc=(now + timedelta(seconds=2)).isoformat().replace("+00:00", "Z"),
                source="trusted_backend_reconciliation",
            )
            released = store.budget_summary()
            self.assertEqual(released["pending_exposure_usd"], 0.0)
            self.assertEqual(released["maximum_exposure_usd"], 30.05)
        finally:
            store.close()

    def test_budget_exposure_is_serialized_across_store_connections_and_survives_restart(self):
        with tempfile.TemporaryDirectory(prefix="g5-budget-exposure-race-") as temp:
            path = Path(temp) / "control-plane.sqlite3"
            first_store = ControlPlaneStore(path)
            second_store = ControlPlaneStore(path)
            now = datetime.now(timezone.utc).replace(microsecond=0)
            now_text = now.isoformat().replace("+00:00", "Z")
            expiry = (now + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
            first_store.record_budget_evidence(
                evidence_id="synthetic-race-spend", source_reference="synthetic-race-invoice",
                occurred_at_utc=now_text, currency="USD", amount_usd="29.80",
                verification_status="VERIFIED", source="trusted_backend_import",
            )
            first_store.record_action_cost_evidence(
                evidence_id="synthetic-race-cost", source_reference="synthetic-race-price",
                currency="USD", amount_usd="0.15", observed_at_utc=now_text,
                valid_until_utc=expiry, verification_status="VERIFIED", source="trusted_backend_import",
            )
            barrier = threading.Barrier(3)

            def reserve(store, action_key):
                barrier.wait(timeout=3)
                try:
                    return store.reserve_budget_exposure(
                        action_key=action_key, evidence_id="synthetic-race-cost",
                        source_reference="synthetic-race-price", amount_usd="0.15",
                        occurred_at_utc=now_text, source="trusted_backend_reservation",
                    )
                except ValueError:
                    return "BLOCKED_BY_HARD_CAP"

            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(reserve, first_store, "synthetic-race-action-1")
                    second = pool.submit(reserve, second_store, "synthetic-race-action-2")
                    barrier.wait(timeout=3)
                    results = (first.result(timeout=5), second.result(timeout=5))
                self.assertEqual(results.count("RESERVED"), 1)
                self.assertEqual(results.count("BLOCKED_BY_HARD_CAP"), 1)
            finally:
                first_store.close()
                second_store.close()

            reopened = ControlPlaneStore(path)
            try:
                self.assertEqual(reopened.budget_summary()["pending_exposure_usd"], 0.15)
                with self.assertRaisesRegex(ValueError, "exceeds the hard budget"):
                    reopened.reserve_budget_exposure(
                        action_key="synthetic-race-action-after-restart", evidence_id="synthetic-race-cost",
                        source_reference="synthetic-race-price", amount_usd="0.15",
                        occurred_at_utc=(now + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
                        source="trusted_backend_reservation",
                    )
            finally:
                reopened.close()

    def test_application_composes_closed_sender_with_shared_local_audit_and_ledgers(self):
        with tempfile.TemporaryDirectory(prefix="g5-composed-offline-sender-") as temp:
            service = build_service(G5Config(state_dir=temp))
            try:
                executor = service.action_executor
                self.assertIsInstance(executor, SaladActionExecutor)
                self.assertIs(executor.ledger, service.action_ledger)
                self.assertIs(executor.budget_store, service.store)
                self.assertFalse(executor.transport.enabled)
                self.assertFalse(executor.policy.live_actions_enabled)
                self.assertFalse(executor.policy.live_spend_authorized)
                self.assertFalse(executor.policy.g5_reviewed)
                self.assertFalse(executor.kill_switch.enabled)
                self.assertEqual(executor.secret_provider.read_attempts, 0)

                target = {"organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer"}
                direct_result = executor.execute(SaladAction.START_GROUP, target, decision_dossier=None)
                self.assertEqual(direct_result.status, "BLOCKED")
                self.assertFalse(direct_result.actions_performed)
                self.assertEqual(executor.secret_provider.read_attempts, 0)

                # The actual localhost API reaches this same service instance;
                # browser requests remain blocked before the composed sender.
                api_result = service.request_action("START_GROUP", {"container_group": "fl4shminer"})
                self.assertEqual(api_result["status"], "BLOCKED")
                self.assertFalse(api_result["actions_performed"])
                self.assertEqual(service.action_ledger.snapshot(), [])
                self.assertEqual(executor.secret_provider.read_attempts, 0)

                self.assertEqual(service.set_auto_reallocate(True)["status"], "BLOCKED")
                state = service.state()
                self.assertFalse(state["actions"]["live_actions_enabled"])
                self.assertFalse(state["actions"]["auto_reallocate"])
                self.assertEqual(state["economics"]["profit_status"], "UNKNOWN")
                self.assertTrue(any(item["event_type"] == "ACTION_BLOCKED" for item in service.store.audit()))
            finally:
                service.close()

    def test_application_uses_persistent_local_monitor_and_action_ledgers(self):
        with tempfile.TemporaryDirectory(prefix="g5-local-state-") as temp:
            config = G5Config(state_dir=temp)
            service = build_service(config)
            identity = normalize_gpu_identity(
                "NVIDIA GeForce RTX 5090 Laptop GPU",
                identity_source="synthetic_test_fixture",
                identity_verified=True,
            )
            sample = {
                "event_type": "gpu_sample", "event_id": "synthetic-g5-sample-1",
                "fleet_id": "fleet-synthetic", "worker_id": "worker-synthetic",
                "allocation_id": "allocation-synthetic", "assignment_id": "assignment-synthetic",
                "run_id": "run-synthetic", "machine_id": "machine-synthetic",
                "instance_id": "instance-synthetic", "device_namespace": "fl4shminer_device",
                "device_id": "0", "occurred_at_utc": "2026-10-11T00:00:00Z",
                "assignment_started_at_utc": "2026-10-11T00:00:00Z", "start_anchor_verified": True,
                "hashrate_ths": 150.0, "hashrate_semantics": "fl4shminer_device_reported",
                "hashrate_source": "synthetic_test_fixture", "gpu_identity": identity,
                "reallocation_history_known": True, "reallocation_count": 0,
                "provenance": {"source": "synthetic_test_fixture", "data_classification": "SYNTHETIC/UNVERIFIED"},
            }
            ingested = service.ingest_miner_events([sample])
            self.assertEqual(ingested["inserted_sample_count"], 1)
            track_id = service.guard_store.track_rows()[0]["track_id"]
            target = {"organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer"}
            action_key = service.action_ledger.live_key_for(action="START_GROUP", target=target)
            service.action_ledger.reserve_live(action_key, "START_GROUP", target, "2026-10-11T00:00:01Z")
            service.close()

            reopened = build_service(config)
            try:
                self.assertEqual(reopened.guard_store.track_rows()[0]["track_id"], track_id)
                self.assertEqual(reopened.action_ledger.get(action_key)["state"], "RESERVED")
                self.assertTrue(reopened.state()["actions"]["kill_switch_engaged"])
            finally:
                reopened.close()

    def test_dashboard_includes_sanitized_monitor_feed_and_requires_exact_binding_for_track_ids(self):
        service = G5ControlPlaneService(G5Config())
        try:
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            identity = normalize_gpu_identity(
                "NVIDIA GeForce RTX 5090 Laptop GPU",
                identity_source="synthetic_test_fixture",
                identity_verified=True,
            )
            sample = {
                "event_type": "gpu_sample", "event_id": "g5-event-feed-sample",
                "fleet_id": "fleet-event-feed", "worker_id": "worker-event-feed",
                "allocation_id": "allocation-event-feed", "assignment_id": "assignment-event-feed",
                "run_id": "run-event-feed", "machine_id": "machine-event-feed",
                "instance_id": "instance-event-feed", "device_namespace": "fl4shminer_device",
                "device_id": "0", "occurred_at_utc": now,
                "assignment_started_at_utc": now, "start_anchor_verified": True,
                "hashrate_ths": 150.0, "hashrate_semantics": "fl4shminer_device_reported",
                "hashrate_source": "DO_NOT_EXPOSE_DASHBOARD_SOURCE", "gpu_identity": identity,
                "reallocation_history_known": True, "reallocation_count": 0,
                "provenance": {"private_marker": "DO_NOT_EXPOSE_DASHBOARD_PROVENANCE"},
            }
            service.ingest_miner_events([sample])
            state = service.state()
            feed = state["monitor"]["event_feed"]
            self.assertEqual(feed["status"], "OK")
            self.assertEqual(feed["pool_failures_source"], "EXISTING_CENTRAL_LOG_ALERT_PIPELINE")
            self.assertFalse(feed["actions_performed"])
            mining = next(item for item in feed["events"] if item["event_type"] == "ACTIVE_MINING_SAMPLE")
            self.assertEqual(mining["identity_status"], "UNKNOWN")
            self.assertIsNone(mining["machine_id"])
            self.assertIsNone(mining["instance_id"])
            serialized = json.dumps(feed, sort_keys=True)
            self.assertNotIn("DO_NOT_EXPOSE_DASHBOARD_SOURCE", serialized)
            self.assertNotIn("DO_NOT_EXPOSE_DASHBOARD_PROVENANCE", serialized)

            track = service.guard_store.track_rows()[0]
            binding = {
                "binding_status": "VERIFIED",
                "provider": {
                    "machine_id": track["machine_id"], "instance_id": track["instance_id"],
                    "assignment_id": track["assignment_id"], "container_group_id": "fl4shminer-4",
                },
                "assignment": {
                    "machine_id": track["machine_id"], "instance_id": track["instance_id"],
                    "assignment_id": track["assignment_id"], "container_group_id": "fl4shminer-4",
                },
            }
            service.register_binding_evidence(track["track_id"], binding)
            bound_feed = service.state()["monitor"]["event_feed"]
            bound_sample = next(item for item in bound_feed["events"] if item["event_type"] == "ACTIVE_MINING_SAMPLE")
            self.assertEqual(bound_sample["identity_status"], "VERIFIED")
            self.assertEqual(bound_sample["machine_id"], track["machine_id"])
            self.assertEqual(bound_sample["instance_id"], track["instance_id"])
            self.assertEqual(bound_sample["container_group_id"], "fl4shminer-4")
            self.assertFalse(bound_sample["actions_performed"])
            self.assertFalse(state["actions"]["live_actions_enabled"])
            self.assertFalse(state["actions"]["auto_reallocate"])
        finally:
            service.close()

    def test_local_source_monitor_and_four_group_tls_fixture_are_composed_end_to_end(self):
        server = GateLocalTLSServer()
        with tempfile.TemporaryDirectory(prefix="g5-offline-e2e-") as temp:
            source = Path(temp) / "miner.jsonl"
            now = datetime.now(timezone.utc).replace(microsecond=0)
            sample_at = now.isoformat().replace("+00:00", "Z")
            identity = normalize_gpu_identity(
                "NVIDIA GeForce RTX 5090 Laptop GPU",
                identity_source="synthetic_test_fixture",
                identity_verified=True,
            )
            sample = {
                "event_type": "gpu_sample", "event_id": "synthetic-g5-e2e-sample-1",
                "fleet_id": "fleet-synthetic", "worker_id": "worker-synthetic",
                "allocation_id": "allocation-synthetic", "assignment_id": "assignment-synthetic",
                "run_id": "run-synthetic", "machine_id": "machine-synthetic",
                "instance_id": "instance-synthetic", "device_namespace": "fl4shminer_device",
                "device_id": "0", "occurred_at_utc": sample_at,
                "assignment_started_at_utc": sample_at, "start_anchor_verified": True,
                "hashrate_ths": 150.0, "hashrate_semantics": "fl4shminer_device_reported",
                "hashrate_source": "synthetic_test_fixture", "gpu_identity": identity,
                "reallocation_history_known": True, "reallocation_count": 0,
                "provenance": {"source": "synthetic_test_fixture", "data_classification": "SYNTHETIC/UNVERIFIED"},
            }
            source.write_text(json.dumps(sample) + "\n", encoding="utf-8")
            broker_path = Path(temp) / "broker.sqlite3"
            broker_ledger = initialize_ledger(broker_path, now=time.time())
            provider = SyntheticSecretProvider()
            broker = LiveBrokerGate(
                broker_ledger,
                transport=LiveHTTPSTransport(local_tls=LoopbackTLSConfig(server.port, str(server.certificate))),
                secret_provider=provider,
                kill_switch=KillSwitch(enabled=True),
                clock=time.time,
            )
            service = G5ControlPlaneService(
                G5Config(local_telemetry_sources=(str(source),), state_dir=temp),
                control_store=ControlPlaneStore(":memory:"),
                guard_store=GuardStore(":memory:"),
                action_ledger=ActionLedger(":memory:"),
                offline_read_broker=broker,
            )
            try:
                first_ingest = service.ingest_configured_local_events()
                self.assertEqual(first_ingest["inserted_sample_count"], 1)
                self.assertEqual(len(service.guard_store.track_rows()), 1)
                self.assertEqual(len(service.guard_store.source_cursor_rows()), 1)
                second_ingest = service.ingest_configured_local_events()
                self.assertEqual(second_ingest["event_count"], 0)
                self.assertEqual(second_ingest["inserted_sample_count"], 0)

                refreshed = service.refresh()
                self.assertEqual(refreshed["groups_queried"], 4)
                self.assertEqual(refreshed["data_classification"], "SYNTHETIC/UNVERIFIED")
                self.assertFalse(refreshed["live_calls_performed"])
                self.assertFalse(refreshed["actions_performed"])
                self.assertEqual(len(server.received), 4)
                self.assertEqual(provider.read_count, 4)
                self.assertEqual(service.action_ledger.snapshot(), [])

                state = service.state()
                self.assertEqual([item["container_group"] for item in state["salad"]["groups"]], list(GROUPS))
                self.assertTrue(all(item["data_classification"] == "SYNTHETIC/UNVERIFIED" for item in state["salad"]["groups"]))
                self.assertTrue(all(item["gpu_binding_status"] == "UNKNOWN" for item in state["salad"]["groups"]))
                self.assertEqual(len(state["reallocation_reviews"]["items"]), 1)
                self.assertEqual(state["reallocation_reviews"]["items"][0]["eligibility"], "BLOCKED")
                self.assertFalse(state["reallocation_reviews"]["items"][0]["actions_performed"])
                self.assertEqual(state["actions"]["auto_reallocate"], False)
                self.assertTrue(all(row["payload"]["data_classification"] == "SYNTHETIC/UNVERIFIED" for row in service.store.observations()))
            finally:
                service.close()
                server.close()

    def test_manual_live_read_bridge_requires_typed_terminal_scope_and_persists_synthetic_dashboard_rows(self):
        server = GateLocalTLSServer()
        with tempfile.TemporaryDirectory(prefix="g5-live-read-bridge-") as temp:
            ledger_path = Path(temp) / "live-read.sqlite3"
            initialize_ledger(ledger_path, now=time.time(), run_mode=LIVE_SALAD_GET)
            ledger = BrokerLedger.open(ledger_path, expected_mode=LIVE_SALAD_GET)
            secret_provider = InteractiveSecretProvider(enabled=True)
            session = LiveSaladReadSession(
                ledger,
                transport=ProductionSaladTransport(
                    enabled=True,
                    test_local_port=server.port,
                    test_ca_file=str(server.certificate),
                ),
                secret_provider=secret_provider,
                kill_switch=KillSwitch(enabled=True),
                live_enabled=True,
            )
            service = self.service

            class InteractiveTerminal:
                def isatty(self):
                    return True

            try:
                with patch("live_secret_boundary.sys.stdin", InteractiveTerminal()), patch(
                    "live_secret_boundary.getpass.getpass", return_value=SYNTHETIC_SECRET_VALUE
                ) as hidden_prompt:
                    result = run_manual_live_get(
                        service,
                        session,
                        stdin=InteractiveTerminal(),
                        input_fn=lambda _prompt: LIVE_GET_TERMINAL_CONFIRMATION,
                    )

                self.assertEqual(result["status"], "ALL_GROUPS_OBSERVED", result)
                self.assertEqual(result["groups_queried"], 4)
                self.assertEqual(result["observations_saved"], 4)
                self.assertEqual(result["data_classification"], "SYNTHETIC/UNVERIFIED")
                self.assertFalse(result["live_calls_performed"])
                self.assertTrue(result["local_tls_test_requests_performed"])
                self.assertFalse(result["actions_performed"])
                self.assertFalse(result["reallocation_enabled"])
                self.assertEqual(secret_provider.read_count, 1)
                hidden_prompt.assert_called_once()
                expected_paths = [
                    f"/api/public/organizations/adrianfiverr/projects/miners/containers/{group}/instances"
                    for group in GROUPS
                ]
                self.assertEqual([row["method"] for row in server.received], ["GET"] * 4)
                self.assertEqual([row["path"] for row in server.received], expected_paths)
                self.assertEqual([row["host"] for row in server.received], ["api.salad.com"] * 4)

                http_status, _headers, body = self.request("GET", "/api/state")
                self.assertEqual(http_status, 200)
                dashboard_state = json.loads(body)
                dashboard_groups = dashboard_state["salad"]["groups"]
                self.assertEqual([row["container_group"] for row in dashboard_groups], list(GROUPS))
                self.assertTrue(all(row["data_classification"] == "SYNTHETIC/UNVERIFIED" for row in dashboard_groups))
                self.assertTrue(all(row["gpu_binding_status"] == "UNKNOWN" for row in dashboard_groups))
                self.assertTrue(all(row["billing_status"] == "UNKNOWN" for row in dashboard_groups))
                self.assertTrue(all(row["instance_count_observed"] == 1 for row in dashboard_groups))
                self.assertEqual(len(service.store.observations()), 4)
                for observation in service.store.observations():
                    evidence = dict(observation["payload"])
                    self.assertNotIn("sanitized_observation_sha256", evidence)
                    claimed_hash = evidence.pop("sanitized_fixture_sha256")
                    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
                    self.assertEqual(claimed_hash, hashlib.sha256(canonical).hexdigest())
                serialized = json.dumps({"result": result, "dashboard": dashboard_state, "audit": service.store.audit()}, sort_keys=True)
                self.assertNotIn(SYNTHETIC_SECRET_VALUE, serialized)
                self.assertFalse(dashboard_state["actions"]["auto_reallocate"])
            finally:
                server.close()

    def test_cli_prepares_a_fresh_durable_live_get_ledger_without_network_or_credentials(self):
        with tempfile.TemporaryDirectory(prefix="g5-cli-ledger-") as temp:
            ledger_path = Path(temp) / "prepared-live-get.sqlite3"
            config_path = Path(temp) / "g5.json"
            config_path.write_text(json.dumps({"state_dir": str(Path(temp) / "state")}), encoding="utf-8")
            output = io.StringIO()

            exit_code = main(
                ["--config", str(config_path), "--prepare-live-get-ledger", "--ledger-path", str(ledger_path)],
                stdout=output,
            )

            self.assertEqual(exit_code, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "LIVE_GET_LEDGER_PREPARED")
            self.assertEqual(result["maximum_requests"], 4)
            self.assertFalse(result["live_calls_performed"])
            self.assertFalse(result["actions_performed"])
            self.assertTrue(ledger_path.is_file())
            snapshot = BrokerLedger.open(ledger_path, expected_mode=LIVE_SALAD_GET).snapshot()
            self.assertEqual(snapshot["run_id"], result["run_id"])
            self.assertEqual(snapshot["request_count"], 0)

    def test_cli_manual_live_get_requires_tty_before_reading_authorization_material(self):
        class NonInteractiveTerminal:
            def isatty(self):
                return False

        output = io.StringIO()
        exit_code = main(
            [
                "--manual-live-get",
                "--ledger-path", "missing-ledger.sqlite3",
                "--authorization-file", "missing-grant.json",
                "--trust-anchor-file", "missing-trust-anchor.txt",
            ],
            stdin=NonInteractiveTerminal(),
            stdout=output,
        )
        self.assertEqual(exit_code, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "LIVE_GET_BLOCKED")
        self.assertFalse(result["live_calls_performed"])

    def test_cli_manual_live_get_uses_signed_scope_hidden_synthetic_key_and_loopback_tls(self):
        import uuid
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        server = GateLocalTLSServer()
        with tempfile.TemporaryDirectory(prefix="g5-cli-live-get-") as temp:
            root = Path(temp)
            state_dir = root / "state"
            config_path = root / "g5.json"
            config_path.write_text(json.dumps({"state_dir": str(state_dir)}), encoding="utf-8")
            ledger_path = root / "live-get.sqlite3"
            initialized = initialize_ledger(ledger_path, now=time.time(), run_mode=LIVE_SALAD_GET)
            run_id = initialized.snapshot()["run_id"]

            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            now = int(time.time())
            claims = {
                "schema_version": 1,
                "audience": "salad-g5-control-plane",
                "host": "api.salad.com",
                "purpose": "list_container_group_instances",
                "organization": "adrianfiverr",
                "project": "miners",
                "groups": list(GROUPS),
                "max_requests": 4,
                "run_id": run_id,
                "issued_at_epoch": now - 1,
                "expires_at_epoch": now + 600,
                "nonce": str(uuid.uuid4()),
            }
            payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
            signature = private_key.sign(payload)
            authorization_path = root / "grant.json"
            authorization_path.write_text(
                json.dumps({
                    "payload_b64": base64.b64encode(payload).decode("ascii"),
                    "signature_b64": base64.b64encode(signature).decode("ascii"),
                }),
                encoding="utf-8",
            )
            trust_anchor_path = root / "trusted-public-key.b64"
            trust_anchor_path.write_text(base64.b64encode(public_key).decode("ascii"), encoding="ascii")

            class InteractiveTerminal:
                def isatty(self):
                    return True

            def local_transport(**kwargs):
                return ProductionSaladTransport(
                    enabled=kwargs["enabled"],
                    test_local_port=server.port,
                    test_ca_file=str(server.certificate),
                    authorization_grant=kwargs["authorization_grant"],
                    authorization_verifier=kwargs["authorization_verifier"],
                )

            output = io.StringIO()
            try:
                with patch("live_secret_boundary.sys.stdin", InteractiveTerminal()), patch(
                    "live_secret_boundary.getpass.getpass", return_value=SYNTHETIC_SECRET_VALUE
                ) as hidden_prompt:
                    exit_code = main(
                        [
                            "--config", str(config_path),
                            "--manual-live-get",
                            "--ledger-path", str(ledger_path),
                            "--authorization-file", str(authorization_path),
                            "--trust-anchor-file", str(trust_anchor_path),
                        ],
                        live_transport_factory=local_transport,
                        stdin=InteractiveTerminal(),
                        input_fn=lambda _prompt: LIVE_GET_TERMINAL_CONFIRMATION,
                        stdout=output,
                    )

                self.assertEqual(exit_code, 0)
                result = json.loads(output.getvalue())
                self.assertEqual(result["status"], "ALL_GROUPS_OBSERVED")
                self.assertEqual(result["groups_queried"], 4)
                self.assertEqual(result["observations_saved"], 4)
                self.assertEqual(result["data_classification"], "SYNTHETIC/UNVERIFIED")
                self.assertFalse(result["live_calls_performed"])
                self.assertTrue(result["local_tls_test_requests_performed"])
                self.assertFalse(result["actions_performed"])
                self.assertFalse(result["reallocation_enabled"])
                hidden_prompt.assert_called_once()
                self.assertNotIn(SYNTHETIC_SECRET_VALUE, output.getvalue())
                self.assertEqual(len(server.received), 4)
                self.assertEqual([request["method"] for request in server.received], ["GET"] * 4)
                self.assertEqual([request["host"] for request in server.received], ["api.salad.com"] * 4)
                self.assertEqual(
                    [request["path"] for request in server.received],
                    [f"/api/public/organizations/adrianfiverr/projects/miners/containers/{group}/instances" for group in GROUPS],
                )
                snapshot = BrokerLedger.open(ledger_path, expected_mode=LIVE_SALAD_GET).snapshot()
                self.assertEqual(snapshot["request_count"], 4)
                persisted = ControlPlaneStore(state_dir / "control-plane.sqlite3")
                try:
                    self.assertEqual(len(persisted.observations()), 4)
                    self.assertTrue(all(row["payload"]["data_classification"] == "SYNTHETIC/UNVERIFIED" for row in persisted.observations()))
                finally:
                    persisted.close()
            finally:
                server.close()

    def test_cli_rejects_invalid_signed_scope_before_hidden_secret_or_network(self):
        import uuid
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        server = GateLocalTLSServer()
        with tempfile.TemporaryDirectory(prefix="g5-cli-live-deny-") as temp:
            root = Path(temp)
            ledger_path = root / "live-get.sqlite3"
            ledger = initialize_ledger(ledger_path, now=time.time(), run_mode=LIVE_SALAD_GET)
            run_id = ledger.snapshot()["run_id"]
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            now = int(time.time())
            claims = {
                "schema_version": 1,
                "audience": "salad-g5-control-plane",
                "host": "api.salad.com",
                "purpose": "list_container_group_instances",
                "organization": "adrianfiverr",
                "project": "miners",
                "groups": list(GROUPS),
                "max_requests": 4,
                "run_id": "different-run",
                "issued_at_epoch": now - 1,
                "expires_at_epoch": now + 600,
                "nonce": str(uuid.uuid4()),
            }
            payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
            authorization_path = root / "grant.json"
            authorization_path.write_text(
                json.dumps({
                    "payload_b64": base64.b64encode(payload).decode("ascii"),
                    "signature_b64": base64.b64encode(private_key.sign(payload)).decode("ascii"),
                }),
                encoding="utf-8",
            )
            trust_anchor_path = root / "trusted-public-key.b64"
            trust_anchor_path.write_text(base64.b64encode(public_key).decode("ascii"), encoding="ascii")
            config_path = root / "g5.json"
            config_path.write_text(json.dumps({"state_dir": str(root / "state")}), encoding="utf-8")

            class InteractiveTerminal:
                def isatty(self):
                    return True

            output = io.StringIO()
            try:
                with patch("live_secret_boundary.sys.stdin", InteractiveTerminal()), patch(
                    "live_secret_boundary.getpass.getpass"
                ) as hidden_prompt:
                    exit_code = main(
                        [
                            "--config", str(config_path),
                            "--manual-live-get",
                            "--ledger-path", str(ledger_path),
                            "--authorization-file", str(authorization_path),
                            "--trust-anchor-file", str(trust_anchor_path),
                        ],
                        live_transport_factory=lambda **kwargs: ProductionSaladTransport(
                            enabled=True,
                            test_local_port=server.port,
                            test_ca_file=str(server.certificate),
                            authorization_grant=kwargs["authorization_grant"],
                            authorization_verifier=kwargs["authorization_verifier"],
                        ),
                        stdin=InteractiveTerminal(),
                        input_fn=lambda _prompt: LIVE_GET_TERMINAL_CONFIRMATION,
                        stdout=output,
                    )
                self.assertEqual(exit_code, 2)
                self.assertIn("LIVE_GET_BLOCKED", output.getvalue())
                self.assertNotIn("different-run", output.getvalue())
                hidden_prompt.assert_not_called()
                self.assertEqual(server.received, [])
                self.assertEqual(BrokerLedger.open(ledger_path, expected_mode=LIVE_SALAD_GET).snapshot()["request_count"], 0)
            finally:
                server.close()

    def test_manual_live_read_bridge_rejects_noninteractive_or_wrong_terminal_authorization_before_session(self):
        class Terminal:
            def __init__(self, interactive):
                self.interactive = interactive

            def isatty(self):
                return self.interactive

        server = GateLocalTLSServer()
        with tempfile.TemporaryDirectory(prefix="g5-live-read-denied-") as temp:
            ledger_path = Path(temp) / "live-read.sqlite3"
            initialize_ledger(ledger_path, now=time.time(), run_mode=LIVE_SALAD_GET)
            ledger = BrokerLedger.open(ledger_path, expected_mode=LIVE_SALAD_GET)
            secret_provider = InteractiveSecretProvider(enabled=True)
            session = LiveSaladReadSession(
                ledger,
                transport=ProductionSaladTransport(
                    enabled=True,
                    test_local_port=server.port,
                    test_ca_file=str(server.certificate),
                ),
                secret_provider=secret_provider,
                kill_switch=KillSwitch(enabled=True),
                live_enabled=True,
            )
            service = G5ControlPlaneService(G5Config())
            try:
                with patch("live_secret_boundary.getpass.getpass") as hidden_prompt:
                    class UntrustedSession:
                        is_local_tls_test = True

                        def run_all(self):
                            raise AssertionError("only the concrete fixed-scope session is accepted")

                    untrusted = run_manual_live_get(
                        service,
                        UntrustedSession(),
                        stdin=Terminal(True),
                        input_fn=lambda _prompt: LIVE_GET_TERMINAL_CONFIRMATION,
                    )
                    self.assertEqual(untrusted["status"], "LIVE_GET_BLOCKED")

                    noninteractive = run_manual_live_get(service, session, stdin=Terminal(False))
                    self.assertEqual(noninteractive["status"], "LIVE_GET_BLOCKED")
                    self.assertFalse(noninteractive["live_calls_performed"])

                    wrong_phrase = run_manual_live_get(
                        service,
                        session,
                        stdin=Terminal(True),
                        input_fn=lambda _prompt: "READ ONLY GET another-scope",
                    )
                    self.assertEqual(wrong_phrase["status"], "LIVE_GET_BLOCKED")
                    self.assertFalse(wrong_phrase["live_calls_performed"])

                    disabled_session = LiveSaladReadSession(
                        ledger,
                        transport=ProductionSaladTransport(
                            enabled=True,
                            test_local_port=server.port,
                            test_ca_file=str(server.certificate),
                        ),
                        secret_provider=secret_provider,
                        kill_switch=KillSwitch(enabled=True),
                        live_enabled=False,
                    )
                    disabled = run_manual_live_get(
                        service,
                        disabled_session,
                        stdin=Terminal(True),
                        input_fn=lambda _prompt: LIVE_GET_TERMINAL_CONFIRMATION,
                    )
                    self.assertEqual(disabled["status"], "LIVE_GET_DISABLED")
                    self.assertFalse(disabled["live_calls_performed"])
                    self.assertEqual(len(disabled["groups"]), 4)
                    hidden_prompt.assert_not_called()
                self.assertEqual(ledger.snapshot()["request_count"], 0)
                self.assertEqual(server.received, [])
                self.assertEqual(service.action_ledger.snapshot(), [])
            finally:
                service.close()
                server.close()

    def test_browser_refresh_never_runs_an_injected_live_session(self):
        class SessionTrap:
            def __init__(self):
                self.calls = 0

            def run_all(self):
                self.calls += 1
                raise AssertionError("browser refresh must never initiate a live GET")

        session = SessionTrap()
        service = G5ControlPlaneService(G5Config(), read_session=session)
        try:
            result = service.refresh()
            self.assertEqual(result["status"], "LIVE_GET_DISABLED")
            self.assertFalse(result["live_calls_performed"])
            self.assertEqual(session.calls, 0)
        finally:
            service.close()

    def test_manual_live_read_errors_are_redacted_before_dashboard_and_audit(self):
        service = G5ControlPlaneService(G5Config())
        marker = "SYNTHETIC_ONLY_NOT_A_CREDENTIAL"
        try:
            row = {
                "container_group": GROUPS[0],
                "method": "GET",
                "request_path": f"/api/public/organizations/adrianfiverr/projects/miners/containers/{GROUPS[0]}/instances",
                "state": "REQUEST_OUTCOME_UNCERTAIN",
                "http_status_code": None,
                "error": f"{marker} raw transport failure contents must not escape",
                "live_call_attempted": True,
                "live_calls_performed": False,
                "actions_performed": False,
                "reallocation_enabled": False,
            }
            result = service.persist_live_read_result(
                {"execution_mode": "LIVE_SALAD_GET", "groups": [row], "actions_performed": False, "reallocation_enabled": False},
                local_tls_test=False,
            )
            rendered = json.dumps({"result": result, "state": service.state(), "audit": service.audit()}, sort_keys=True)
            self.assertNotIn(marker, rendered)
            self.assertIn("request outcome is uncertain", result["groups"][0]["error"])
            self.assertEqual(result["groups_queried"], 1)
            self.assertFalse(result["actions_performed"])
        finally:
            service.close()

    def test_manual_live_read_unexpected_session_exception_is_unknown_and_redacted(self):
        server = GateLocalTLSServer()
        with tempfile.TemporaryDirectory(prefix="g5-live-read-uncertain-") as temp:
            ledger_path = Path(temp) / "live-read.sqlite3"
            initialize_ledger(ledger_path, now=time.time(), run_mode=LIVE_SALAD_GET)
            ledger = BrokerLedger.open(ledger_path, expected_mode=LIVE_SALAD_GET)
            session = LiveSaladReadSession(
                ledger,
                transport=ProductionSaladTransport(
                    enabled=True,
                    test_local_port=server.port,
                    test_ca_file=str(server.certificate),
                ),
                secret_provider=InteractiveSecretProvider(enabled=True),
                kill_switch=KillSwitch(enabled=True),
                live_enabled=True,
            )
            service = G5ControlPlaneService(G5Config())

            class Terminal:
                def isatty(self):
                    return True

            marker = "SYNTHETIC_ONLY_NOT_A_CREDENTIAL raw failure marker"
            try:
                with patch.object(LiveSaladReadSession, "run_all", side_effect=RuntimeError(marker)), patch(
                    "live_secret_boundary.getpass.getpass"
                ) as hidden_prompt:
                    result = run_manual_live_get(
                        service,
                        session,
                        stdin=Terminal(),
                        input_fn=lambda _prompt: LIVE_GET_TERMINAL_CONFIRMATION,
                    )
                self.assertEqual(result["status"], "LIVE_GET_OUTCOME_UNCERTAIN")
                self.assertIsNone(result["live_calls_performed"])
                self.assertIsNone(result["groups_queried"])
                self.assertFalse(result["actions_performed"])
                self.assertFalse(result["reallocation_enabled"])
                hidden_prompt.assert_not_called()
                rendered = json.dumps({"result": result, "audit": service.audit()}, sort_keys=True)
                self.assertNotIn(marker, rendered)
                self.assertEqual(ledger.snapshot()["request_count"], 0)
                self.assertEqual(server.received, [])
            finally:
                service.close()
                server.close()


if __name__ == "__main__":
    unittest.main()
