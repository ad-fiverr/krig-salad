"""Synthetic-only tests for startup fast-path and its read-only log bridge."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.fl4sh_early_autotune import (  # noqa: E402
    AssociationEvidenceRecord,
    BindingAttestation,
    EarlyCalibration,
    EarlyEvaluationContext,
    EarlyObservation,
    EarlyPolicy,
    MonitorPolicyEvidence,
    ObservationReference,
    ProviderBinding,
    association_evidence_sha256,
    monitor_policy_evidence_sha256,
)
from collector.startup_admission import StartupAdmissionEngine  # noqa: E402
from collector.startup_recovery_policy import StartupCause, StartupRecoveryPolicy  # noqa: E402
from log_alerts.contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED  # noqa: E402
from log_alerts.normalize import normalize_log_entry  # noqa: E402
from log_alerts.startup_early_bridge import StartupEarlyBridge, normalize_observed_gpu_key  # noqa: E402
from g5_control_plane.config import G5Config, load_config  # noqa: E402
from g5_control_plane.service import G5ControlPlaneService  # noqa: E402


NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
POLICY_HASH = "a" * 64
SYNTHETIC_MACHINE = "machine-private-synthetic"
SYNTHETIC_INSTANCE = "instance-private-synthetic"


def make_evidence(*, gpu_key="RTX_5080_LAPTOP", floors=None, calibration=True, now=NOW, policy_hash=POLICY_HASH):
    selected_floors = floors or {"RTX_5080_LAPTOP": 120.0}
    policy = EarlyPolicy(policy_hash, selected_floors, margin_ths=0.0)
    policy_evidence = MonitorPolicyEvidence(
        "source-config", "c" * 64, 3, "org-synthetic", "project-synthetic",
        "fl4shminer", "group-version-synthetic", SYNTHETIC_MACHINE, SYNTHETIC_INSTANCE,
        "source-running", (now - timedelta(seconds=20)).isoformat().replace("+00:00", "Z"),
        (now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z"), policy_hash,
    )
    reference = ObservationReference(
        "source-autotune", "c" * 64, 4, "org-synthetic", "project-synthetic",
        "fl4shminer", "group-version-synthetic", SYNTHETIC_MACHINE, SYNTHETIC_INSTANCE,
        "fl4shminer_device", 1, gpu_key, "source-gpu-init",
        "source-running", (now - timedelta(seconds=20)).isoformat().replace("+00:00", "Z"),
        monitor_policy_evidence_sha256(policy_evidence),
    )
    observation = EarlyObservation(
        "PEARL_AUTOTUNE", 1, gpu_key, 80.0, now - timedelta(seconds=2), policy_hash,
        source_reference=reference,
        policy_evidence=policy_evidence,
        policy_evidence_status="PARSED",
    )
    record = AssociationEvidenceRecord(
        1, "association-synthetic", "SYNTHETIC_TEST_ONLY", "VERIFIED", reference,
        "assignment-synthetic", "generation-synthetic", now - timedelta(seconds=20),
        now + timedelta(minutes=5), now - timedelta(seconds=1), policy_hash,
        "synthetic-verifier", "test-v1", "",
    )
    record = replace(record, evidence_sha256=association_evidence_sha256(record))
    binding = ProviderBinding(
        1, gpu_key, "org-synthetic", "project-synthetic", "fl4shminer",
        SYNTHETIC_MACHINE, SYNTHETIC_INSTANCE, "assignment-synthetic", "generation-synthetic",
        now - timedelta(seconds=20), now - timedelta(seconds=1), policy_hash,
        source="SYNTHETIC_TEST_ONLY", observation_reference=reference,
        attestation=BindingAttestation(1, record.evidence_id, record.evidence_sha256),
        valid_until_utc=now + timedelta(minutes=5),
    )
    calibrations = ()
    if calibration:
        calibrations = (EarlyCalibration(
            "PEARL_AUTOTUNE", gpu_key, 0.9, 1.0, 40,
            now - timedelta(days=1), now + timedelta(days=1), policy_hash,
            "b" * 64, "SYNTHETIC_TEST_ONLY",
        ),)
    context = EarlyEvaluationContext(
        policy, (binding,), (record,), calibrations, now,
        allow_synthetic_calibration_for_test=True,
        allow_synthetic_binding_evidence_for_test=True,
    )
    return observation, context


def synthetic_log(text: str, *, classification: str = DATA_CLASSIFICATION):
    return normalize_log_entry({
        "data_classification": classification,
        "log_id": "synthetic-log-event",
        "event_time_utc": "2026-10-18T11:59:58Z",
        "resource": {
            "type": "salad.container_group_instance",
            "labels": {
                "organization_name": "org-synthetic",
                "project_name": "project-synthetic",
                "container_group_name": "fl4shminer",
                "machine_id": SYNTHETIC_MACHINE,
                "instance_id": SYNTHETIC_INSTANCE,
            },
        },
        "text_log": text,
        "structured_message": None,
    })


class StartupAdmissionEngineTests(unittest.TestCase):
    def test_exact_typed_pearl_binding_classifies_without_authorizing(self):
        observation, context = make_evidence()
        decision = StartupAdmissionEngine().evaluate(observation, context)
        self.assertEqual(decision.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(decision.reason, "PEARL_BELOW_FLOOR")
        self.assertFalse(decision.actions_performed)
        self.assertFalse(decision.action_eligible)

    def test_pearl_direct_floor_does_not_need_calibration(self):
        observation, context = make_evidence(calibration=False)
        decision = StartupAdmissionEngine().evaluate(observation, context)
        self.assertEqual(decision.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(decision.to_dict()["calibration_status"], "NOT_APPLICABLE")
        self.assertFalse(decision.actions_performed or decision.action_eligible)

    def test_unknown_4070_ti_without_empirical_floor_stays_unknown(self):
        observation, context = make_evidence(
            gpu_key="RTX_4070_TI", floors={"RTX_5080_LAPTOP": 120.0},
        )
        decision = StartupAdmissionEngine().evaluate(observation, context)
        self.assertEqual(decision.state, "EARLY_UNKNOWN")
        self.assertEqual(decision.reason, "FLOOR_UNCONFIGURED")
        self.assertIsNone(decision.floor_ths)
        self.assertFalse(decision.action_eligible)

    def test_duplicate_or_malformed_calibration_cannot_change_direct_pearl_result(self):
        observation, context = make_evidence()
        duplicate = replace(context.calibrations[0], evidence_sha256="e" * 64)
        malformed = object()
        context = replace(context, calibrations=context.calibrations + (duplicate, malformed))
        decision = StartupAdmissionEngine().evaluate(observation, context)
        self.assertEqual(decision.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(decision.reason, "PEARL_BELOW_FLOOR")
        self.assertFalse(decision.actions_performed or decision.action_eligible)

    def test_unverified_or_missing_context_cannot_be_promoted(self):
        observation, _context = make_evidence()
        decision = StartupAdmissionEngine().evaluate(
            observation, EarlyEvaluationContext(now_utc=NOW),
        )
        self.assertEqual(decision.state, "EARLY_UNKNOWN")
        self.assertIn(decision.reason, {"POLICY_UNAVAILABLE", "POLICY_EVIDENCE_UNVERIFIED"})
        self.assertFalse(decision.action_eligible)

    def test_stale_signal_stays_unknown(self):
        observation, context = make_evidence()
        context = replace(context, now_utc=NOW + timedelta(minutes=2))
        decision = StartupAdmissionEngine().evaluate(observation, context)
        self.assertEqual(decision.state, "EARLY_UNKNOWN")
        self.assertEqual(decision.reason, "SIGNAL_STALE_OR_FUTURE")

    def test_exact_type_boundary_rejects_arbitrary_objects(self):
        with self.assertRaises(TypeError):
            StartupAdmissionEngine().evaluate({"signal": "CUDA_POOL_EQUIVALENT"})

    def test_control_plane_preview_reuses_policy_and_never_reserves_or_audits_actions(self):
        service = G5ControlPlaneService(G5Config())
        try:
            observation, context = make_evidence(
                policy_hash=service.monitor.policy_hash,
                floors={"RTX_5080_LAPTOP": 120.0},
            )
            context = replace(context, policy=None)
            ledger_before = service.action_ledger.snapshot()
            audit_before = service.store.audit()

            preview = service.preview_startup_admission(
                observation, context, now_utc=NOW.isoformat().replace("+00:00", "Z"),
            )

            self.assertEqual(preview["state"], "EARLY_UNDER_FLOOR")
            self.assertEqual(preview["action_gate"]["status"], "BLOCKED")
            self.assertFalse(preview["actions_performed"])
            self.assertFalse(preview["request_submitted"])
            self.assertFalse(preview["live_action_eligible"])
            self.assertEqual(service.action_ledger.snapshot(), ledger_before)
            self.assertEqual(service.store.audit(), audit_before)
            self.assertEqual(service.state()["startup_admission"]["last_preview"], preview)
            self.assertEqual(preview["recovery_policy"]["state"], "EARLY_UNDER_FLOOR")
            self.assertTrue(preview["recovery_policy"]["gpu_floor_action_candidate"])
            self.assertFalse(preview["recovery_policy"]["actions_performed"])
        finally:
            service.close()

    def test_control_plane_uses_exact_configured_pearl_identity_and_reports_provenance(self):
        service = G5ControlPlaneService(
            G5Config(pearl_startup_floors_ths={"RTX_5070_TI": 100}),
        )
        try:
            observation, context = make_evidence(
                gpu_key="RTX_5070_TI",
                floors={"RTX_5080_LAPTOP": 120.0},
                policy_hash=service.monitor.policy_hash,
            )
            context = replace(context, policy=None)
            preview = service.preview_startup_admission(
                observation, context, now_utc=NOW.isoformat().replace("+00:00", "Z"),
            )
            self.assertEqual(preview["state"], "EARLY_UNDER_FLOOR")
            self.assertEqual(preview["floor_ths"], 100)
            self.assertEqual(preview["floor_source"], "PYTHON")
            self.assertEqual(preview["floor_catalog_hash"], service.config.pearl_startup_floor_catalog_hash)
            self.assertEqual(preview["policy_hash"], service.monitor.policy_hash)
            self.assertFalse(preview["actions_performed"])
            self.assertFalse(preview["request_submitted"])
            self.assertFalse(preview["live_action_eligible"])
        finally:
            service.close()

    def test_neutral_gpu_floor_never_falls_back_to_laptop_or_desktop(self):
        service = G5ControlPlaneService(
            G5Config(pearl_startup_floors_ths={"RTX_4070_TI": 100}),
        )
        try:
            observation, context = make_evidence(
                gpu_key="RTX_4070_TI_LAPTOP",
                floors={"RTX_4070_TI": 100.0},
                policy_hash=service.monitor.policy_hash,
            )
            context = replace(context, policy=None)
            preview = service.preview_startup_admission(
                observation, context, now_utc=NOW.isoformat().replace("+00:00", "Z"),
            )
            self.assertEqual(preview["state"], "EARLY_UNKNOWN")
            self.assertEqual(preview["reason"], "FLOOR_UNCONFIGURED")
            self.assertIsNone(preview["floor_ths"])
            self.assertEqual(preview["floor_source"], "NO_FLOOR_CONFIGURED")
            self.assertFalse(preview["actions_performed"])
            self.assertFalse(preview["request_submitted"])
        finally:
            service.close()

    def test_legacy_json_and_environment_floor_overrides_drive_pearl_startup(self):
        config_path = TELEMETRY_ROOT / "g5-live-config.example.json"
        data = json.loads(config_path.read_text(encoding="utf-8"))
        data["gpu_floors_ths"]["RTX 5080|laptop|salad_json_log_gpu_class_name"] = 110
        with tempfile.TemporaryDirectory(prefix="g5-startup-legacy-floor-") as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            json_config = load_config(path, environ={})

        env_config = load_config(None, environ={
            "SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS": "115",
        })
        for config, expected_floor, expected_source in (
            (json_config, 110, "LEGACY_JSON"),
            (env_config, 115, "LEGACY_ENV"),
        ):
            with self.subTest(source=expected_source):
                service = G5ControlPlaneService(config)
                try:
                    observation, context = make_evidence(
                        gpu_key="RTX_5080_LAPTOP",
                        floors={"RTX_5080_LAPTOP": 120.0},
                        policy_hash=service.monitor.policy_hash,
                    )
                    context = replace(context, policy=None)
                    preview = service.preview_startup_admission(
                        observation, context, now_utc=NOW.isoformat().replace("+00:00", "Z"),
                    )
                    self.assertEqual(preview["state"], "EARLY_UNDER_FLOOR")
                    self.assertEqual(preview["floor_ths"], expected_floor)
                    self.assertEqual(preview["floor_source"], expected_source)
                    self.assertFalse(preview["actions_performed"])
                    self.assertFalse(preview["request_submitted"])
                finally:
                    service.close()

    def test_non_rtx_exact_gpu_keys_are_configurable_without_family_fallback(self):
        service = G5ControlPlaneService(
            G5Config(pearl_startup_floors_ths={"A100_SXM4_80GB": 100}),
        )
        try:
            observation, context = make_evidence(
                gpu_key="A100_SXM4_80GB",
                floors={"RTX_5080_LAPTOP": 120.0},
                policy_hash=service.monitor.policy_hash,
            )
            context = replace(context, policy=None)
            exact = service.preview_startup_admission(
                observation, context, now_utc=NOW.isoformat().replace("+00:00", "Z"),
            )
            self.assertEqual(exact["state"], "EARLY_UNDER_FLOOR")
            self.assertEqual(exact["floor_ths"], 100)
            self.assertEqual(exact["floor_source"], "PYTHON")
            self.assertFalse(exact["actions_performed"])
        finally:
            service.close()

        no_fallback = G5ControlPlaneService(
            G5Config(pearl_startup_floors_ths={"A100_SXM4_80GB": 100}),
        )
        try:
            observation, context = make_evidence(
                gpu_key="A100_SXM4_80GB_PCIE",
                floors={"A100_SXM4_80GB": 100.0},
                policy_hash=no_fallback.monitor.policy_hash,
            )
            context = replace(context, policy=None)
            preview = no_fallback.preview_startup_admission(
                observation, context, now_utc=NOW.isoformat().replace("+00:00", "Z"),
            )
            self.assertEqual(preview["state"], "EARLY_UNKNOWN")
            self.assertEqual(preview["reason"], "FLOOR_UNCONFIGURED")
            self.assertIsNone(preview["floor_ths"])
            self.assertEqual(preview["floor_source"], "NO_FLOOR_CONFIGURED")
            self.assertFalse(preview["actions_performed"])
        finally:
            no_fallback.close()

    def test_control_plane_exposes_configured_read_only_startup_escalation(self):
        policy = StartupRecoveryPolicy(startup_timeout_seconds=120, escalation_interval_seconds=600)
        service = G5ControlPlaneService(G5Config())
        try:
            service.startup_admission_engine = StartupAdmissionEngine(policy)
            view = service.state()["startup_recovery_policy"]
            self.assertEqual(view["startup_timeout_seconds"], 120)
            self.assertEqual(view["escalation_interval_seconds"], 600)
            self.assertEqual(view["timeout_action"], "OBSERVE_AND_NOTIFY")
            self.assertFalse(view["pool_network_gpu_floor_action"])
        finally:
            service.close()


class StartupEarlyBridgeTests(unittest.TestCase):
    @staticmethod
    def _provider_log_fixture(text: str, *, organization: str = "adrianfiverr"):
        return normalize_log_entry({
            "data_classification": DATA_CLASSIFICATION,
            "log_id": "synthetic-startup-event",
            "event_time_utc": "2026-10-18T11:59:58Z",
            "resource": {
                "type": "salad.container_group_instance",
                "labels": {
                    "organization_name": organization,
                    "project_name": "miners",
                    "container_group_name": "fl4shminer",
                    "machine_id": SYNTHETIC_MACHINE,
                    "instance_id": SYNTHETIC_INSTANCE,
                },
            },
            "text_log": text,
            "structured_message": None,
        })

    def test_future_event_time_is_clock_inconsistent_and_never_clamped_to_zero_age(self):
        bridge = StartupEarlyBridge(monotonic=lambda: 10.0)
        entry = self._provider_log_fixture(
            "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 119.0 TH/s",
        )
        events = bridge.process_entries(
            [entry],
            response_received_at_utc="2026-10-18T11:59:57Z",
            watcher_ingested_at_utc="2026-10-18T11:59:57Z",
        )
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.state, "EARLY_UNKNOWN")
        self.assertEqual(event.reason, "CLOCK_INCONSISTENT")
        self.assertEqual(event.cause, StartupCause.UNKNOWN.value)
        self.assertIsNone(event.event_age_at_ingestion_seconds)
        self.assertEqual(event.recovery.disposition, "HOLD_FOR_VERIFIED_EVIDENCE")
        self.assertFalse(event.actions_performed or event.request_submitted)

    def test_provider_gpu_init_and_pearl_project_in_one_cycle_without_wait_or_action(self):
        service = G5ControlPlaneService(G5Config())
        try:
            snapshot = service.startup_policy_snapshot()
            snapshot = replace(snapshot, loaded_at_utc="2026-10-18T11:59:30Z")
            bridge = StartupEarlyBridge(policy_snapshot=snapshot)
            context = EarlyEvaluationContext(
                now_utc=NOW,
                allow_synthetic_provider_log_evidence_for_test=True,
            )
            init = self._provider_log_fixture(
                "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
            )
            pearl = self._provider_log_fixture(
                "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 119.0 TH/s",
            )
            response_at = "2026-10-18T11:59:59.000000Z"
            events = bridge.process_entries(
                [pearl, init],
                context=context,
                response_received_at_utc=response_at,
                watcher_ingested_at_utc="2026-10-18T12:00:00Z",
            )
            self.assertEqual([event.state for event in events], ["GPU_DETECTED", "EARLY_UNKNOWN"])
            projection = events[1].to_dict()
            self.assertEqual(projection["mode"], "STARTUP_FAST_PATH")
            self.assertEqual(projection["decision_signal"], "PEARL_AUTOTUNE")
            self.assertEqual(projection["gpu_key"], "RTX_5080_LAPTOP")
            self.assertEqual(projection["gpu_autotune_ths"], 119.0)
            self.assertEqual(projection["floor_ths"], 120.0)
            self.assertEqual(projection["reason"], "BINDING_UNVERIFIED")
            self.assertEqual(projection["provider_response_received_at_utc"], response_at)
            self.assertIsNone(projection["polling_latency_seconds"])
            self.assertEqual(projection["polling_latency_status"], "UNKNOWN_PROVIDER_AVAILABILITY_TIME")
            self.assertFalse(projection["actions_performed"])
            self.assertFalse(projection["request_submitted"])
            serialized = json.dumps([event.to_dict() for event in events])
            for private_value in (SYNTHETIC_MACHINE, SYNTHETIC_INSTANCE, "synthetic-startup-event", "Pearl autotune"):
                self.assertNotIn(private_value, serialized)
            self.assertEqual(bridge.process_entries(
                [init, pearl],
                context=context,
                response_received_at_utc=response_at,
                watcher_ingested_at_utc="2026-10-18T12:00:00Z",
            ), ())
        finally:
            service.close()

    def test_unconfigured_4070_ti_and_policy_scope_mismatch_do_not_receive_a_floor(self):
        service = G5ControlPlaneService(G5Config())
        try:
            snapshot = replace(
                service.startup_policy_snapshot(),
                loaded_at_utc="2026-10-18T11:59:30Z",
            )
            bridge = StartupEarlyBridge(policy_snapshot=snapshot)
            context = EarlyEvaluationContext(
                now_utc=NOW,
                allow_synthetic_provider_log_evidence_for_test=True,
            )
            events = bridge.process_entries([
                self._provider_log_fixture(
                    "Device [1] NVIDIA GeForce RTX 4070 Ti Laptop GPU: Initialized",
                ),
                self._provider_log_fixture(
                    "GPU=NVIDIA GeForce RTX 4070 Ti Laptop GPU Pearl autotune hashrate = 143.41 TH/s",
                ),
            ], context=context)
            pearl = events[-1].to_dict()
            self.assertEqual(pearl["state"], "EARLY_UNKNOWN")
            self.assertEqual(pearl["reason"], "FLOOR_UNCONFIGURED")
            self.assertEqual(pearl["gpu_key"], "RTX_4070_TI_LAPTOP")
            self.assertIsNone(pearl["floor_ths"])
            self.assertFalse(pearl["actions_performed"] or pearl["request_submitted"])

            scoped_out = StartupEarlyBridge(policy_snapshot=snapshot).process_entries([
                self._provider_log_fixture(
                    "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
                    organization="other-org",
                ),
                self._provider_log_fixture(
                    "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 119.0 TH/s",
                    organization="other-org",
                ),
            ], context=context)
            self.assertEqual(scoped_out[-1].state, "EARLY_UNKNOWN")
            self.assertIsNone(scoped_out[-1].floor_ths)
            self.assertEqual(scoped_out[-1].reason, "POLICY_SCOPE_UNVERIFIED")

            scoped_context = EarlyEvaluationContext(
                policy=snapshot.policy,
                now_utc=NOW,
                allow_synthetic_provider_log_evidence_for_test=True,
            )
            scoped_out_with_context_policy = StartupEarlyBridge(
                policy_snapshot=snapshot,
            ).process_entries([
                self._provider_log_fixture(
                    "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
                    organization="other-org",
                ),
                self._provider_log_fixture(
                    "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 100.0 TH/s",
                    organization="other-org",
                ),
            ], context=scoped_context)
            self.assertEqual(scoped_out_with_context_policy[-1].state, "EARLY_UNKNOWN")
            self.assertEqual(scoped_out_with_context_policy[-1].reason, "POLICY_SCOPE_UNVERIFIED")
            self.assertIsNone(scoped_out_with_context_policy[-1].floor_ths)
        finally:
            service.close()

    def test_gpu_identity_conflict_blocks_startup_floor_projection(self):
        service = G5ControlPlaneService(G5Config())
        try:
            snapshot = replace(service.startup_policy_snapshot(), loaded_at_utc="2026-10-18T11:59:30Z")
            bridge = StartupEarlyBridge(policy_snapshot=snapshot)
            context = EarlyEvaluationContext(
                now_utc=NOW,
                allow_synthetic_provider_log_evidence_for_test=True,
            )
            events = bridge.process_entries([
                self._provider_log_fixture(
                    "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
                ),
                self._provider_log_fixture(
                    "GPU=NVIDIA GeForce RTX 5090 Laptop GPU Pearl autotune hashrate = 130.0 TH/s",
                ),
            ], context=context)
            pearl = events[-1].to_dict()
            self.assertEqual(pearl["state"], "EARLY_UNKNOWN")
            self.assertEqual(pearl["reason"], "GPU_IDENTITY_CONFLICT")
            self.assertIsNone(pearl["floor_ths"])
            self.assertFalse(pearl["actions_performed"] or pearl["request_submitted"])
        finally:
            service.close()

    def test_gpu_identity_conflict_cannot_be_cleared_by_a_later_matching_detection(self):
        service = G5ControlPlaneService(G5Config())
        try:
            snapshot = replace(service.startup_policy_snapshot(), loaded_at_utc="2026-10-18T11:59:30Z")
            bridge = StartupEarlyBridge(policy_snapshot=snapshot)
            context = EarlyEvaluationContext(
                now_utc=NOW,
                allow_synthetic_provider_log_evidence_for_test=True,
            )
            first = self._provider_log_fixture(
                "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
            )
            conflict = replace(
                self._provider_log_fixture(
                    "Device [1] NVIDIA GeForce RTX 5090 Laptop GPU: Initialized",
                ),
                event_time_utc="2026-10-18T11:59:59Z",
            )
            later_matching = replace(
                self._provider_log_fixture(
                    "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
                ),
                event_time_utc="2026-10-18T12:00:00Z",
            )
            pearl = replace(
                self._provider_log_fixture(
                    "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 119.0 TH/s",
                ),
                event_time_utc="2026-10-18T12:00:01Z",
            )
            events = bridge.process_entries([first, conflict, later_matching, pearl], context=context)
            self.assertEqual([event.state for event in events], [
                "GPU_DETECTED", "GPU_IDENTITY_CONFLICT", "GPU_IDENTITY_CONFLICT", "EARLY_UNKNOWN",
            ])
            self.assertEqual(events[-1].reason, "GPU_IDENTITY_CONFLICT")
            self.assertIsNone(events[-1].floor_ths)
            self.assertFalse(events[-1].actions_performed or events[-1].request_submitted)
        finally:
            service.close()

    def test_list_instances_enrichment_is_not_silently_recast_as_log_label_evidence(self):
        service = G5ControlPlaneService(G5Config())
        try:
            snapshot = replace(service.startup_policy_snapshot(), loaded_at_utc="2026-10-18T11:59:30Z")
            bridge = StartupEarlyBridge(policy_snapshot=snapshot)
            context = EarlyEvaluationContext(
                now_utc=NOW,
                allow_synthetic_provider_log_evidence_for_test=True,
            )
            init = self._provider_log_fixture(
                "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
            )
            pearl = self._provider_log_fixture(
                "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 119.0 TH/s",
            )
            init = replace(init, identity=replace(init.identity, source="list_instances"))
            pearl = replace(pearl, identity=replace(pearl.identity, source="list_instances"))
            events = bridge.process_entries([init, pearl], context=context)
            self.assertEqual(events[0].state, "GPU_IDENTITY_UNKNOWN")
            self.assertEqual(events[-1].state, "EARLY_UNKNOWN")
            self.assertEqual(events[-1].reason, "GPU_IDENTITY_UNVERIFIED")
            self.assertIsNone(events[-1].floor_ths)
            self.assertFalse(events[-1].actions_performed or events[-1].request_submitted)
        finally:
            service.close()

    def test_4070_ti_pearl_estimate_is_recognized_but_unverified_and_unknown(self):
        raw = "GPU=NVIDIA GeForce RTX 4070 Ti Laptop GPU Pearl autotune hashrate = 143.41 TH/s"
        entry = synthetic_log(raw)
        event = StartupEarlyBridge().inspect(entry)
        self.assertIsNotNone(event)
        projection = event.to_dict()
        self.assertEqual(projection["state"], "EARLY_UNKNOWN")
        self.assertEqual(projection["signal_type"], "PEARL_AUTOTUNE")
        self.assertEqual(projection["gpu_key"], "RTX_4070_TI_LAPTOP")
        self.assertEqual(projection["estimate_ths"], 143.41)
        self.assertEqual(projection["cause"], "UNKNOWN")
        self.assertFalse(projection["actions_performed"])
        self.assertFalse(projection["request_submitted"])
        encoded = json.dumps(projection)
        for forbidden in (SYNTHETIC_MACHINE, SYNTHETIC_INSTANCE, raw, "machine_id", "instance_id"):
            self.assertNotIn(forbidden, encoded)

    def test_explicit_gpu_form_factor_is_not_inferred(self):
        self.assertEqual(normalize_observed_gpu_key("NVIDIA GeForce RTX 4070 Ti Laptop GPU"), "RTX_4070_TI_LAPTOP")
        self.assertEqual(normalize_observed_gpu_key("NVIDIA GeForce RTX 4070 Ti"), "RTX_4070_TI")
        self.assertIsNone(normalize_observed_gpu_key("NVIDIA GeForce RTX 4070 Ti Laptop Desktop GPU"))

    def test_cuda_autotune_is_early_estimate_not_device_hashrate_or_identity(self):
        entry = synthetic_log("Device [1] CUDA autotune: 160.47 TH/s (measured pool-equivalent)")
        event = StartupEarlyBridge().inspect(entry)
        self.assertIsNotNone(event)
        self.assertEqual(event.signal_type, "CUDA_POOL_EQUIVALENT")
        self.assertEqual(event.device_index, 1)
        self.assertIsNone(event.gpu_key)
        self.assertEqual(event.estimate_ths, 160.47)
        self.assertEqual(event.state, "EARLY_UNKNOWN")

    def test_device_hashrate_remains_outside_the_early_autotune_path(self):
        entry = synthetic_log("Device [1] hashRate: 217.81 TH/s, stale: 0/0 (0.0%), warm: 0")
        self.assertIsNone(StartupEarlyBridge().inspect(entry))

    def test_provider_observed_labels_do_not_create_verified_early_binding(self):
        raw = "GPU=NVIDIA GeForce RTX 4070 Ti Laptop GPU Pearl autotune hashrate = 160.47 TH/s"
        entry = replace(synthetic_log(raw), data_classification=PROVIDER_OBSERVED)
        event = StartupEarlyBridge().inspect(entry)
        self.assertEqual(event.state, "EARLY_UNKNOWN")
        self.assertEqual(event.data_classification, PROVIDER_OBSERVED)
        self.assertFalse(event.actions_performed)

    def test_pool_timeout_is_handed_to_controller_without_gpu_floor_candidate(self):
        entry = synthetic_log(
            "Pool connection failed: mining.authorize response timeout; "
            "reconnecting; retrying in 10s"
        )
        event = StartupEarlyBridge().inspect(entry)
        self.assertIsNotNone(event)
        projection = event.to_dict()
        self.assertEqual(projection["cause"], StartupCause.POOL_AUTH_TIMEOUT.value)
        self.assertEqual(projection["recovery_policy"]["disposition"], "PRESERVE_POOL_RETRIES_AND_NOTIFY")
        self.assertFalse(projection["recovery_policy"]["gpu_floor_action_candidate"])
        self.assertFalse(projection["recovery_policy"]["actions_performed"])

    def test_startup_timeout_is_observational_and_clean_exit_is_distinct(self):
        timeout = synthetic_log(
            "FL4SH_MONITOR state=STARTUP_HASHRATE_TIMEOUT "
            "reason=NO_POSITIVE_DEVICE_HASHRATE startup_timeout_seconds=180 "
            f"policy_hash={POLICY_HASH} actions_performed=false"
        )
        timeout_event = StartupEarlyBridge().inspect(timeout)
        self.assertEqual(timeout_event.cause, StartupCause.NO_POSITIVE_HASHRATE.value)
        self.assertEqual(timeout_event.recovery.state, "STARTUP_TIMEOUT")
        self.assertEqual(timeout_event.recovery.disposition, "NOTIFY_CONTROLLER_AND_CONTINUE")
        self.assertFalse(timeout_event.recovery.gpu_floor_action_candidate)

        clean_exit = synthetic_log(
            "FL4SH_MONITOR state=STARTUP_HASHRATE_FAILED "
            "reason=MINER_EXITED_BEFORE_HASHRATE startup_timeout_seconds=180 "
            f"policy_hash={POLICY_HASH} actions_performed=false"
        )
        exit_event = StartupEarlyBridge().inspect(clean_exit)
        self.assertEqual(exit_event.cause, StartupCause.PROCESS_EXIT.value)
        self.assertEqual(exit_event.recovery.state, "STARTUP_FAILED")
        self.assertEqual(exit_event.recovery.disposition, "RECORD_ACTUAL_PROCESS_EXIT")
        self.assertFalse(exit_event.recovery.gpu_floor_action_candidate)


if __name__ == "__main__":
    unittest.main()
