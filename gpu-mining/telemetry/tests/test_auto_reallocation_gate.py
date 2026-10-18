from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.action_ledger import ActionLedger, VerifiedSyntheticSimulationObservation
from collector.auto_reallocation_gate import AutoReallocationGate, AutoReallocationLimits
from collector.salad_action_policy import APPROVED_GROUPS, APPROVED_ORGANIZATION, APPROVED_PROJECT
from collector.salad_action_transport import SaladActionExecutor


POLICY_HASH = "c" * 64
SOURCE_HASH = "a" * 64
CALIBRATION_HASH = "b" * 64
FIXTURE = "G5-SYNTHETIC-ACTION-PATH"
FLOORS = {"RTX_5080_LAPTOP": 110.0}
NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


def _time(delta_seconds: int = 0) -> str:
    return (NOW + timedelta(seconds=delta_seconds)).isoformat().replace("+00:00", "Z")


def _arm_simulation_ledger(ledger: ActionLedger, limits: AutoReallocationLimits | None = None) -> None:
    selected = limits or AutoReallocationLimits(10, 20, 300, 3, 5)
    ledger.update_auto_reallocation_simulation_control(
        armed=True, event_type="SIMULATION_ARMED", kill_switch_engaged=False,
        live_actions_enabled=False, g5_authorized=False, at_utc=_time(),
        limits=selected.as_ledger_limits(),
    )


class _RegisteredFixtureVerifier:
    """Test-only registry verifier; observations cannot certify themselves."""

    def __init__(self, registered_record: dict):
        self.registered_record = dict(registered_record)

    def verify_synthetic_observation(self, *, observation: dict, reservation: dict):
        expected = {
            **self.registered_record,
            "simulation_key": reservation["simulation_key"],
            "assignment_scope": reservation["assignment_scope"],
            "target_scope": reservation["target_scope"],
            "original_instance_fingerprint": reservation["original_instance_fingerprint"],
            "original_generation_fingerprint": reservation["original_generation_fingerprint"],
        }
        if observation != expected:
            return None
        return VerifiedSyntheticSimulationObservation(**expected)


def _fixture_observation(row: dict, *, result: str, observed_at: str,
                         observed_instance: str | None, observed_generation: str | None,
                         evidence_suffix: str = "TERMINAL") -> tuple[dict, _RegisteredFixtureVerifier]:
    reservation = row["payload"]["reservation_identity"]
    registered = {
        "schema_version": "1.0",
        "synthetic_fixture_id": FIXTURE,
        "evidence_reference": f"{FIXTURE}:V1:{evidence_suffix}",
        "result": result,
        "observed_instance_fingerprint": observed_instance,
        "observed_generation_fingerprint": observed_generation,
        "observed_at_utc": observed_at,
    }
    complete = {
        **registered,
        "simulation_key": row["simulation_key"],
        "assignment_scope": row["assignment_scope"],
        "target_scope": row["target_scope"],
        "original_instance_fingerprint": reservation["original_instance_fingerprint"],
        "original_generation_fingerprint": reservation["original_generation_fingerprint"],
    }
    return complete, _RegisteredFixtureVerifier(registered)


def _synthetic_context(*, now: datetime = NOW, assignment: str = "assignment-a", generation: str = "generation-a",
                       machine: str = "56319ab3-d095-9359-b785-159fcf4b11c4",
                       instance: str = "6bbd35d9-1199-41f6-8a21-316cb41d559f",
                       device_index: int = 1, gpu_key: str = "RTX_5080_LAPTOP",
                       source_hash: str = SOURCE_HASH, floor: float = 110.0) -> dict:
    observed = now - timedelta(seconds=3)
    identity = {
        "organization_id": APPROVED_ORGANIZATION,
        "project_id": APPROVED_PROJECT,
        "container_group_id": APPROVED_GROUPS[0],
        "instance_id": instance,
        "machine_id": machine,
        "assignment_id": assignment,
        "assignment_generation": generation,
        "device_index": device_index,
        "gpu_key": gpu_key,
    }
    provider = {key: identity[key] for key in (
        "organization_id", "project_id", "container_group_id", "instance_id", "machine_id",
        "assignment_id", "assignment_generation", "device_index", "gpu_key",
    )}
    assignment_identity = dict(provider)
    return {
        "source": {
            "source": "FL4SHMINER_AUTOTUNE_LOG",
            "source_reference_sha256": source_hash,
            "observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "synthetic_fixture_id": FIXTURE,
        },
        "policy": {
            "policy_hash": POLICY_HASH,
            "gpu_floors_ths": dict(FLOORS),
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "synthetic_fixture_id": FIXTURE,
        },
        "generation": {
            "status": "CURRENT",
            "policy_hash": POLICY_HASH,
            "assignment_id": assignment,
            "assignment_generation": generation,
            "observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
            "valid_from_utc": (now - timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
            "valid_until_utc": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "synthetic_fixture_id": FIXTURE,
        },
        "binding": {
            "binding_status": "SYNTHETIC/UNVERIFIED",
            "policy_hash": POLICY_HASH,
            "actions_authorized_by_binding": False,
            "attestation_evidence_id": "synthetic-attestation-1",
            "valid_from_utc": (now - timedelta(seconds=30)).isoformat().replace("+00:00", "Z"),
            "revalidated_at_utc": observed.isoformat().replace("+00:00", "Z"),
            "valid_until_utc": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "provider": provider,
            "assignment": assignment_identity,
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "synthetic_fixture_id": FIXTURE,
        },
        "provider": {
            **identity,
            "reported_state": "running",
            "observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "source_provenance": {
                "system": "synthetic_test_fixture", "host": "loopback",
                "transport_tls_hostname_verified": False,
            },
            "synthetic_fixture_id": FIXTURE,
        },
        "budget": {
            "status": "VERIFIED", "currency": "USD",
            "verified_spend_usd": 1.0, "verified_next_action_cost_usd": 0.1,
            "pending_exposure_usd": 0.0, "maximum_exposure_usd": 1.1,
            "spend_evidence_id": "synthetic-spend", "next_action_cost_evidence_id": "synthetic-cost",
            "pending_exposure_evidence_id": "synthetic-pending", "maximum_exposure_evidence_id": "synthetic-max",
            "spend_observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
            "next_action_cost_observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
            "valid_until_utc": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "data_classification": "SYNTHETIC/UNVERIFIED", "synthetic_fixture_id": FIXTURE,
        },
        "history": {
            "history_known": True, "allocation_reallocation_count": 0,
            "fleet_reallocation_count": 0, "last_reallocation_at_utc": None,
            "observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
        },
        "fleet_id": "fleet-test",
        "now_utc": now.isoformat().replace("+00:00", "Z"),
        "floor": floor,
        "gpu_key": gpu_key,
        "device_index": device_index,
        "assignment_id": assignment,
        "assignment_generation": generation,
        "source_hash": source_hash,
    }


def _early(context: dict) -> dict:
    return {
        "decision_version": 1,
        "state": "EARLY_UNDER_FLOOR",
        "reason": "UPPER_BOUND_BELOW_THRESHOLD",
        "signal_type": "PEARL_AUTOTUNE",
        "device_index": context["device_index"],
        "gpu_key": context["gpu_key"],
        "estimate_ths": 100.0,
        "predicted_lower_ths": 96.0,
        "predicted_upper_ths": 104.0,
        "floor_ths": context["floor"],
        "policy_hash": POLICY_HASH,
        "assignment_id": context["assignment_id"],
        "assignment_generation": context["assignment_generation"],
        "actions_performed": False,
        "action_eligible": False,
        "evaluated_at_utc": context["now_utc"],
        "source_reference_sha256": context["source_hash"],
        "calibration_status": "APPLIED_SYNTHETIC_TEST_ONLY",
        "calibration_evidence_sha256": CALIBRATION_HASH,
    }


def _assessment(context: dict) -> dict:
    identity = {
        "model": "RTX 5080", "form_factor": "laptop", "identity_verified": True,
        "identity_source": "salad_json_log_gpu_class_name",
    }
    target = {
        "organization_id": APPROVED_ORGANIZATION,
        "project_id": APPROVED_PROJECT,
        "container_group_id": APPROVED_GROUPS[0],
        "instance_id": "6bbd35d9-1199-41f6-8a21-316cb41d559f",
        "machine_id": "56319ab3-d095-9359-b785-159fcf4b11c4",
        "assignment_id": context["assignment_id"],
    }
    return {
        "schema_version": "1.0", "eligibility": "CANDIDATE", "action_status": "DISABLED", "action_execution": "DISABLED",
        "actions_performed": False, "blockers": [], "guard_policy_hash": POLICY_HASH,
        "gpu_floor_ths": context["floor"], "evaluated_at_utc": context["now_utc"],
        "recommendation": {
            "action_key": "controller-preview-key",
            "guard_policy_hash": POLICY_HASH,
            "actions_performed": False,
            "target": target,
            "gpu_identity": identity,
            "evaluation_ids": ["low-window-1", "low-window-2"],
        },
    }


class AutoReallocationGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = ActionLedger(":memory:")
        _arm_simulation_ledger(self.ledger)
        self.gate = AutoReallocationGate(
            self.ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
            limits=AutoReallocationLimits(10, 20, 300, 3, 5),
            simulation_enabled=True,
        )

    def _complete_simulation(self, ledger: ActionLedger, simulation_key: str) -> dict:
        row = next(item for item in ledger.auto_reallocation_simulation_snapshot()
                   if item["simulation_key"] == simulation_key)
        reserved = datetime.fromisoformat(row["created_at_utc"].replace("Z", "+00:00"))
        transport_at = (reserved + timedelta(milliseconds=500)).isoformat().replace("+00:00", "Z")
        observed_at = (reserved + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        reconciled_at = (reserved + timedelta(seconds=2)).isoformat().replace("+00:00", "Z")
        ledger.record_auto_reallocation_simulation_transport(
            simulation_key, outcome="FAKE_HTTP_202", at_utc=transport_at,
        )
        reservation = row["payload"]["reservation_identity"]
        proof, verifier = _fixture_observation(
            row, result="SIMULATED_NO_CHANGE", observed_at=observed_at,
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"],
        )
        return ledger.reconcile_auto_reallocation_simulation(
            simulation_key, observation=proof, observation_verifier=verifier, at_utc=reconciled_at,
        )

    def tearDown(self) -> None:
        self.ledger.close()

    def _early_result(self, context: dict | None = None, decision: dict | None = None, **overrides):
        values = context or _synthetic_context()
        inputs = {
            "source_evidence": values["source"], "policy_evidence": values["policy"],
            "generation_evidence": values["generation"], "provider_binding": values["binding"],
            "provider_revalidation": values["provider"], "budget_evidence": values["budget"],
            "allocation_history": values["history"], "fleet_id": values["fleet_id"],
            "now_utc": values["now_utc"], "kill_switch_engaged": False, "auto_armed": True,
        }
        inputs.update(overrides)
        return self.gate.assess_early(decision or _early(values), **inputs)

    def test_calibrated_early_under_floor_reserves_only_synthetic_simulation(self):
        result = self._early_result()
        self.assertEqual(result["status"], "SIMULATION_RESERVED")
        self.assertEqual(result["evidence_classification"], "SYNTHETIC/UNVERIFIED")
        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["actions_performed"])
        self.assertFalse(result["request_submitted"])
        self.assertFalse(result["dossier_created"])
        self.assertFalse(result["live_action_eligible"])
        self.assertEqual(self.ledger.snapshot(), [])
        self.assertEqual(len(self.ledger.auto_reallocation_simulation_snapshot()), 1)

    def test_early_unknown_unqualified_and_invalid_version_are_blocked(self):
        context = _synthetic_context()
        for mutation, blocker in (
            ({"state": "EARLY_UNKNOWN", "reason": "PREDICTION_OVERLAPS_THRESHOLD"}, "EARLY_DECISION_NOT_ACTION_CANDIDATE"),
            ({"calibration_status": "UNAPPROVED"}, "EARLY_CALIBRATION_NOT_APPROVED"),
            ({"decision_version": 2}, "EARLY_DECISION_VERSION_UNSUPPORTED"),
            ({"actions_performed": True}, "EARLY_DECISION_CANNOT_AUTHORIZE_ACTION"),
            ({"gpu_key": "RTX_5090_LAPTOP"}, "GPU_FLOOR_MISMATCH"),
        ):
            with self.subTest(mutation=mutation):
                decision = _early(context)
                decision.update(mutation)
                result = self._early_result(context, decision)
                if blocker:
                    self.assertIn(blocker, result["blockers"])
                else:
                    self.fail("every invalid decision mutation must have a blocking reason")
        huge = _early(context)
        huge["estimate_ths"] = 10 ** 10000
        result = self._early_result(context, huge)
        self.assertIn("EARLY_PREDICTION_INVALID_OR_NOT_BELOW_FLOOR", result["blockers"])

    def test_gate_rejects_untyped_limit_configuration(self):
        with self.assertRaisesRegex(TypeError, "limits must be AutoReallocationLimits"):
            AutoReallocationGate(
                self.ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                limits={}, simulation_enabled=True,
            )

    def test_policy_source_binding_generation_and_device_mismatches_fail_closed(self):
        mutations = (
            ("policy", {"policy_hash": "d" * 64}, "POLICY_HASH_MISMATCH"),
            ("source", {"source_reference_sha256": "e" * 64}, "SOURCE_REFERENCE_MISMATCH"),
            ("generation", {"assignment_generation": "generation-old"}, "ASSIGNMENT_GENERATION_NOT_CURRENT"),
            ("generation", {"policy_hash": "d" * 64}, "ASSIGNMENT_GENERATION_NOT_CURRENT"),
            ("generation", {"valid_until_utc": _time(-1)}, "ASSIGNMENT_GENERATION_EXPIRED"),
            ("binding", {"actions_authorized_by_binding": True}, "SYNTHETIC_BINDING_CANNOT_AUTHORIZE_ACTION"),
            ("binding", {"revalidated_at_utc": _time(-120)}, "PROVIDER_BINDING_STALE_OR_OUTSIDE_VALIDITY"),
        )
        for section, change, expected in mutations:
            with self.subTest(section=section, expected=expected):
                context = _synthetic_context()
                context[section].update(change)
                result = self._early_result(context)
                self.assertIn(expected, result["blockers"])
        context = _synthetic_context()
        context["binding"]["provider"]["device_index"] = 0
        result = self._early_result(context)
        self.assertIn("EARLY_DEVICE_BINDING_MISMATCH", result["blockers"])

    def test_wrong_scope_stale_future_or_cross_machine_identity_is_blocked(self):
        for section, change, expected in (
            ("binding", {"provider": {"organization_id": "other-org"}}, "PROVIDER_BINDING_IDENTITY_MISMATCH"),
            ("provider", {"machine_id": "different-machine"}, "PROVIDER_REVALIDATION_IDENTITY_MISMATCH"),
            ("provider", {"reported_state": "stopped"}, "PROVIDER_REVALIDATION_INVALID"),
            ("provider", {"observed_at_utc": _time(-120)}, "PROVIDER_REVALIDATION_STALE_OR_UNTIMED"),
            ("source", {"observed_at_utc": _time(2)}, "SOURCE_EVIDENCE_STALE_OR_UNTIMED"),
        ):
            with self.subTest(section=section, expected=expected):
                context = _synthetic_context()
                if section == "binding" and "provider" in change:
                    context[section]["provider"].update(change["provider"])
                else:
                    context[section].update(change)
                result = self._early_result(context)
                self.assertIn(expected, result["blockers"])
        context = _synthetic_context()
        context["binding"]["provider"]["container_group_id"] = "not-approved"
        context["binding"]["assignment"]["container_group_id"] = "not-approved"
        result = self._early_result(context)
        self.assertIn("PROVIDER_GROUP_SCOPE_INVALID", result["blockers"])

    def test_verified_budget_unknown_over_cap_and_unconfigured_limits_block(self):
        context = _synthetic_context()
        context["budget"]["status"] = "UNKNOWN"
        self.assertIn("VERIFIED_BUDGET_REQUIRED", self._early_result(context)["blockers"])
        context = _synthetic_context()
        context["budget"].update({"maximum_exposure_usd": 30.01, "verified_spend_usd": 29.9,
                                  "verified_next_action_cost_usd": 0.1})
        self.assertIn("VERIFIED_BUDGET_REQUIRED", self._early_result(context)["blockers"])
        no_limits = AutoReallocationGate(self.ledger, policy_hash=POLICY_HASH,
                                         gpu_floors_ths=FLOORS, simulation_enabled=True)
        values = _synthetic_context()
        result = no_limits.assess_early(
            _early(values), source_evidence=values["source"], policy_evidence=values["policy"],
            generation_evidence=values["generation"], provider_binding=values["binding"],
            provider_revalidation=values["provider"], budget_evidence=values["budget"],
            allocation_history=values["history"], fleet_id=values["fleet_id"], now_utc=values["now_utc"],
            kill_switch_engaged=False, auto_armed=True,
        )
        self.assertIn("SIMULATION_QUOTAS_OR_COOLDOWN_UNCONFIGURED", result["blockers"])

    def test_kill_switch_and_unarmed_service_controls_block(self):
        result = self._early_result(kill_switch_engaged=True)
        self.assertIn("KILL_SWITCH_ACTIVE_OR_UNKNOWN", result["blockers"])
        result = self._early_result(auto_armed=False)
        self.assertIn("AUTO_REALLOCATE_NOT_ARMED_FOR_SIMULATION", result["blockers"])
        result = self._early_result(live_actions_enabled=True)
        self.assertIn("LIVE_ACTION_PATH_MUST_REMAIN_DISABLED", result["blockers"])

    def test_late_path_requires_exactly_two_existing_controller_low_windows(self):
        context = _synthetic_context()
        common = {
            "source_evidence": {**context["source"], "source": "CONTINUOUS_MONITOR"},
            "policy_evidence": context["policy"], "generation_evidence": context["generation"],
            "provider_binding": context["binding"], "provider_revalidation": context["provider"],
            "budget_evidence": context["budget"], "allocation_history": context["history"],
            "fleet_id": context["fleet_id"], "now_utc": context["now_utc"],
            "kill_switch_engaged": False, "auto_armed": True,
        }
        assessment = _assessment(context)
        result = self.gate.assess_steady_state(assessment, **common)
        self.assertEqual(result["status"], "SIMULATION_RESERVED")
        self.assertEqual(result["trigger_kind"], "STEADY_STATE")
        self.assertFalse(result["live_action_eligible"])
        assessment["recommendation"]["evaluation_ids"] = ["only-one-window"]
        result = self.gate.assess_steady_state(assessment, **common)
        self.assertIn("TWO_CURRENT_LOW_WINDOWS_REQUIRED", result["blockers"])

    def test_limits_apply_cooldown_per_assignment_and_organization_rate(self):
        limits = AutoReallocationLimits(10, 10, 300, 3, 10)
        gate = AutoReallocationGate(self.ledger, policy_hash=POLICY_HASH,
                                    gpu_floors_ths=FLOORS, limits=limits, simulation_enabled=True)
        context = _synthetic_context()
        kwargs = {
            "source_evidence": context["source"], "policy_evidence": context["policy"],
            "generation_evidence": context["generation"], "provider_binding": context["binding"],
            "provider_revalidation": context["provider"], "budget_evidence": context["budget"],
            "allocation_history": context["history"], "fleet_id": context["fleet_id"],
            "kill_switch_engaged": False, "auto_armed": True,
        }
        self.assertEqual(gate.assess_early(_early(context), now_utc=context["now_utc"], **kwargs)["status"], "SIMULATION_RESERVED")
        second = _synthetic_context(now=NOW + timedelta(seconds=1), source_hash="f" * 64)
        kwargs2 = {
            "source_evidence": second["source"], "policy_evidence": second["policy"],
            "generation_evidence": second["generation"], "provider_binding": second["binding"],
            "provider_revalidation": second["provider"], "budget_evidence": second["budget"],
            "allocation_history": second["history"], "fleet_id": second["fleet_id"],
            "kill_switch_engaged": False, "auto_armed": True,
        }
        self._complete_simulation(self.ledger, gate.assess_early(
            _early(context), now_utc=context["now_utc"], **kwargs,
        )["simulation_id"])
        self.assertEqual(gate.assess_early(_early(second), now_utc=second["now_utc"], **kwargs2)["status"], "BLOCKED_COOLDOWN")

    def test_organization_minute_and_assignment_daily_quotas_block_distinct_triggers(self):
        minute_ledger = ActionLedger(":memory:")
        try:
            _arm_simulation_ledger(minute_ledger, AutoReallocationLimits(1, 10, 0, 10, 10))
            minute_gate = AutoReallocationGate(
                minute_ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                limits=AutoReallocationLimits(1, 10, 0, 10, 10), simulation_enabled=True,
            )
            first = _synthetic_context()
            self.assertEqual(minute_gate.assess_early(
                _early(first), source_evidence=first["source"], policy_evidence=first["policy"],
                generation_evidence=first["generation"], provider_binding=first["binding"],
                provider_revalidation=first["provider"], budget_evidence=first["budget"],
                allocation_history=first["history"], fleet_id=first["fleet_id"], now_utc=first["now_utc"],
                kill_switch_engaged=False, auto_armed=True,
            )["status"], "SIMULATION_RESERVED")
            second = _synthetic_context(
                assignment="assignment-b", generation="generation-b",
                machine="a1bd35d9-1199-41f6-8a21-316cb41d559f",
                instance="b2cd35d9-1199-41f6-8a21-316cb41d559f", source_hash="f" * 64,
            )
            self.assertEqual(minute_gate.assess_early(
                _early(second), source_evidence=second["source"], policy_evidence=second["policy"],
                generation_evidence=second["generation"], provider_binding=second["binding"],
                provider_revalidation=second["provider"], budget_evidence=second["budget"],
                allocation_history=second["history"], fleet_id=second["fleet_id"], now_utc=second["now_utc"],
                kill_switch_engaged=False, auto_armed=True,
            )["blockers"], ["ORGANIZATION_MINUTE_QUOTA"])
        finally:
            minute_ledger.close()

        assignment_ledger = ActionLedger(":memory:")
        try:
            _arm_simulation_ledger(assignment_ledger, AutoReallocationLimits(10, 10, 0, 1, 10))
            assignment_gate = AutoReallocationGate(
                assignment_ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                limits=AutoReallocationLimits(10, 10, 0, 1, 10), simulation_enabled=True,
            )
            first = _synthetic_context()
            def assess(values: dict) -> dict:
                return assignment_gate.assess_early(
                    _early(values), source_evidence=values["source"], policy_evidence=values["policy"],
                    generation_evidence=values["generation"], provider_binding=values["binding"],
                    provider_revalidation=values["provider"], budget_evidence=values["budget"],
                    allocation_history=values["history"], fleet_id=values["fleet_id"], now_utc=values["now_utc"],
                    kill_switch_engaged=False, auto_armed=True,
                )
            self.assertEqual(assess(first)["status"], "SIMULATION_RESERVED")
            first_result = assess(first)
            self._complete_simulation(assignment_ledger, first_result["simulation_id"])
            second = _synthetic_context(now=NOW + timedelta(seconds=301), source_hash="f" * 64)
            self.assertEqual(assess(second)["blockers"], ["ASSIGNMENT_DAILY_QUOTA"])
        finally:
            assignment_ledger.close()

    def test_parallel_same_trigger_has_one_sqlite_reservation_and_no_live_action(self):
        with tempfile.TemporaryDirectory(prefix="scrum-101-sim-ledger-") as temp:
            path = Path(temp) / "simulation.sqlite3"
            context = _synthetic_context()
            barrier = threading.Barrier(10)
            # Open all independent SQLite connections serially. The race under
            # test starts at the admission transaction, not at SQLite PRAGMA setup.
            ledgers = [ActionLedger(path) for _ in range(10)]
            _arm_simulation_ledger(ledgers[0])
            gates = [AutoReallocationGate(
                ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                limits=AutoReallocationLimits(10, 20, 300, 3, 5), simulation_enabled=True,
            ) for ledger in ledgers]

            def attempt(index: int) -> str:
                barrier.wait(timeout=10)
                result = gates[index].assess_early(
                    _early(context), source_evidence=context["source"], policy_evidence=context["policy"],
                    generation_evidence=context["generation"], provider_binding=context["binding"],
                    provider_revalidation=context["provider"], budget_evidence=context["budget"],
                    allocation_history=context["history"], fleet_id=context["fleet_id"],
                    now_utc=context["now_utc"], kill_switch_engaged=False, auto_armed=True,
                )
                return result["status"]

            with patch.object(SaladActionExecutor, "execute", autospec=True) as execute:
                try:
                    with ThreadPoolExecutor(max_workers=10) as pool:
                        statuses = list(pool.map(attempt, range(10)))
                    execute.assert_not_called()
                finally:
                    for ledger in ledgers:
                        ledger.close()
            self.assertEqual(statuses.count("SIMULATION_RESERVED"), 1)
            self.assertEqual(statuses.count("DUPLICATE_SIMULATION"), 9)
            reopened = ActionLedger(path)
            try:
                self.assertEqual(len(reopened.auto_reallocation_simulation_snapshot()), 1)
                self.assertEqual(reopened.snapshot(), [])
            finally:
                reopened.close()

    def test_simulated_reconciliation_is_separate_and_provider_observed_change_is_impossible(self):
        result = self._early_result()
        row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        self.assertEqual(self.ledger.record_auto_reallocation_simulation_transport(
            row["simulation_key"], outcome="FAKE_HTTP_202", at_utc=_time(1),
        )["status"], "SIMULATED_ACCEPTED_PENDING")
        transported_row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        self.assertEqual(transported_row["payload"]["simulation_transport_at_utc"], _time(1))
        reservation = row["payload"]["reservation_identity"]
        proof, verifier = _fixture_observation(
            row, result="SIMULATED_CHANGE", observed_at=_time(2),
            observed_instance="d" * 64, observed_generation="e" * 64,
        )
        self.assertEqual(self.ledger.reconcile_auto_reallocation_simulation(
            row["simulation_key"], observation=proof, observation_verifier=verifier,
            at_utc=_time(3),
        )["status"], "SIMULATED_RECONCILED")
        self.assertEqual(self.ledger.snapshot(), [])
        self.assertEqual(self.ledger.auto_reallocation_simulation_snapshot()[0]["state"], "SIMULATED_RECONCILED")
        self.assertFalse(result["actions_performed"])
        self.assertEqual(reservation, row["payload"]["reservation_identity"])
        independent_payload = {
            "data_classification": "PROVIDER_EVIDENCE_PRESENT_SIMULATION_ONLY",
            "simulation_only": True, "actions_performed": False,
            "request_submitted": False, "dossier_created": False,
            "reservation_identity": {
                "assignment_scope": "6" * 64, "target_scope": "5" * 64,
                "original_instance_fingerprint": "4" * 64,
                "original_generation_fingerprint": "3" * 64,
            },
        }
        self.ledger.reserve_auto_reallocation_simulation(
            simulation_key="9" * 64, trigger_key="9" * 64,
            scopes={"organization": "8" * 64, "fleet": "7" * 64,
                    "assignment": "6" * 64, "target": "5" * 64},
            at_utc=_time(3), at_epoch=NOW.timestamp() + 3,
            limits={"max_per_minute": 10, "max_per_day": 20, "cooldown_seconds": 0,
                    "max_per_assignment": 3, "max_per_fleet": 5},
            payload=independent_payload,
        )
        self.ledger.record_auto_reallocation_simulation_transport(
            "9" * 64, outcome="FAKE_HTTP_202", at_utc=_time(4),
        )
        rejected = self.ledger.reconcile_auto_reallocation_simulation(
            "9" * 64, observation={}, observation_verifier=None, at_utc=_time(5),
        )
        self.assertEqual(rejected["reason"], "SYNTHETIC_PROVENANCE_REQUIRED")

    def test_active_assignment_or_target_fence_survives_restarts_and_different_triggers(self):
        with tempfile.TemporaryDirectory(prefix="scrum-101-fence-") as temp:
            path = Path(temp) / "ledger.sqlite3"
            first_ledger = ActionLedger(path)
            _arm_simulation_ledger(first_ledger)
            gate = AutoReallocationGate(
                first_ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                limits=AutoReallocationLimits(10, 20, 0, 10, 10), simulation_enabled=True,
            )
            first = _synthetic_context()
            kwargs = {
                "source_evidence": first["source"], "policy_evidence": first["policy"],
                "generation_evidence": first["generation"], "provider_binding": first["binding"],
                "provider_revalidation": first["provider"], "budget_evidence": first["budget"],
                "allocation_history": first["history"], "fleet_id": first["fleet_id"],
                "now_utc": first["now_utc"], "kill_switch_engaged": False, "auto_armed": True,
            }
            admitted = gate.assess_early(_early(first), **kwargs)
            self.assertEqual(admitted["status"], "SIMULATION_RESERVED")
            first_process_id = first_ledger.connection.execute(
                "SELECT process_id FROM auto_reallocation_simulation_control WHERE singleton=1"
            ).fetchone()[0]
            first_ledger.close()

            with patch("collector.action_ledger.os.getpid", return_value=first_process_id + 1):
                reopened = ActionLedger(path)
            try:
                closed_control = reopened.auto_reallocation_simulation_control_snapshot()
                self.assertFalse(closed_control["effective_armed"])
                self.assertTrue(closed_control["kill_switch_engaged"])
                _arm_simulation_ledger(reopened)
                reopened_gate = AutoReallocationGate(
                    reopened, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                    limits=AutoReallocationLimits(10, 20, 0, 10, 10), simulation_enabled=True,
                )
                second = _synthetic_context(now=NOW + timedelta(hours=1), source_hash="f" * 64)
                second_kwargs = {
                    "source_evidence": second["source"], "policy_evidence": second["policy"],
                    "generation_evidence": second["generation"], "provider_binding": second["binding"],
                    "provider_revalidation": second["provider"], "budget_evidence": second["budget"],
                    "allocation_history": second["history"], "fleet_id": second["fleet_id"],
                    "now_utc": second["now_utc"], "kill_switch_engaged": False, "auto_armed": True,
                }
                blocked = reopened_gate.assess_early(_early(second), **second_kwargs)
                self.assertEqual(blocked["status"], "BLOCKED_UNRESOLVED_SIMULATION")
                self.assertEqual(blocked["blockers"], ["UNRESOLVED_TARGET_OR_ASSIGNMENT_SIMULATION"])
                target_fence = _synthetic_context(
                    now=NOW + timedelta(hours=2), assignment="assignment-b", generation="generation-b",
                    source_hash="e" * 64,
                )
                target_blocked = reopened_gate.assess_early(
                    _early(target_fence), source_evidence=target_fence["source"],
                    policy_evidence=target_fence["policy"], generation_evidence=target_fence["generation"],
                    provider_binding=target_fence["binding"], provider_revalidation=target_fence["provider"],
                    budget_evidence=target_fence["budget"], allocation_history=target_fence["history"],
                    fleet_id=target_fence["fleet_id"], now_utc=target_fence["now_utc"],
                    kill_switch_engaged=False, auto_armed=True,
                )
                self.assertEqual(target_blocked["status"], "BLOCKED_UNRESOLVED_SIMULATION")
                assignment_fence = _synthetic_context(
                    now=NOW + timedelta(hours=3), source_hash="a" * 64,
                    machine="a1bd35d9-1199-41f6-8a21-316cb41d559f",
                    instance="b2cd35d9-1199-41f6-8a21-316cb41d559f",
                )
                assignment_blocked = reopened_gate.assess_early(
                    _early(assignment_fence), source_evidence=assignment_fence["source"],
                    policy_evidence=assignment_fence["policy"], generation_evidence=assignment_fence["generation"],
                    provider_binding=assignment_fence["binding"], provider_revalidation=assignment_fence["provider"],
                    budget_evidence=assignment_fence["budget"], allocation_history=assignment_fence["history"],
                    fleet_id=assignment_fence["fleet_id"], now_utc=assignment_fence["now_utc"],
                    kill_switch_engaged=False, auto_armed=True,
                )
                self.assertEqual(assignment_blocked["status"], "BLOCKED_UNRESOLVED_SIMULATION")
            finally:
                reopened.close()

    def test_ten_connections_with_distinct_triggers_admit_only_one_unresolved_target(self):
        with tempfile.TemporaryDirectory(prefix="scrum-101-distinct-trigger-race-") as temp:
            path = Path(temp) / "ledger.sqlite3"
            ledgers = [ActionLedger(path) for _ in range(10)]
            _arm_simulation_ledger(ledgers[0], AutoReallocationLimits(10, 20, 0, 10, 10))
            gates = [AutoReallocationGate(
                ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                limits=AutoReallocationLimits(10, 20, 0, 10, 10), simulation_enabled=True,
            ) for ledger in ledgers]
            contexts = [_synthetic_context(source_hash=f"{index + 1:064x}") for index in range(10)]
            barrier = threading.Barrier(10)

            def attempt(index: int) -> str:
                context = contexts[index]
                barrier.wait(timeout=10)
                result = gates[index].assess_early(
                    _early(context), source_evidence=context["source"],
                    policy_evidence=context["policy"], generation_evidence=context["generation"],
                    provider_binding=context["binding"], provider_revalidation=context["provider"],
                    budget_evidence=context["budget"], allocation_history=context["history"],
                    fleet_id=context["fleet_id"], now_utc=context["now_utc"],
                    kill_switch_engaged=False, auto_armed=True,
                )
                return result["status"]

            try:
                with ThreadPoolExecutor(max_workers=10) as pool:
                    statuses = list(pool.map(attempt, range(10)))
            finally:
                for ledger in ledgers:
                    ledger.close()
            self.assertEqual(statuses.count("SIMULATION_RESERVED"), 1)
            self.assertEqual(statuses.count("BLOCKED_UNRESOLVED_SIMULATION"), 9)
            reopened = ActionLedger(path)
            try:
                reservations = reopened.auto_reallocation_simulation_snapshot()
                self.assertEqual(len(reservations), 1)
                self.assertEqual(reservations[0]["state"], "SIMULATION_RESERVED")
            finally:
                reopened.close()

    def test_fake_timeout_requires_reconciliation_without_retry_and_unknown_keeps_fence(self):
        reserved = self._early_result()
        key = reserved["simulation_id"]
        transport = self.ledger.record_auto_reallocation_simulation_transport(
            key, outcome="FAKE_TIMEOUT", at_utc=_time(1),
        )
        self.assertEqual(transport["status"], "SIMULATED_RECONCILIATION_REQUIRED")
        self.assertFalse(transport["automatic_retry"])
        row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        proof, verifier = _fixture_observation(
            row, result="SIMULATED_UNKNOWN", observed_at=_time(2),
            observed_instance=None, observed_generation=None,
        )
        unknown = self.ledger.reconcile_auto_reallocation_simulation(
            key, observation=proof, observation_verifier=verifier, at_utc=_time(3),
        )
        self.assertEqual(unknown["status"], "SIMULATED_RECONCILIATION_REQUIRED")
        stale_row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        reservation = stale_row["payload"]["reservation_identity"]
        stale, stale_verifier = _fixture_observation(
            stale_row, result="SIMULATED_NO_CHANGE", observed_at=_time(1.5),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"], evidence_suffix="OLDER-THAN-UNKNOWN",
        )
        self.assertEqual(self.ledger.reconcile_auto_reallocation_simulation(
            key, observation=stale, observation_verifier=stale_verifier, at_utc=_time(4),
        )["reason"], "SYNTHETIC_OBSERVATION_TIME_REGRESSION")
        self.assertEqual(self.ledger.auto_reallocation_simulation_snapshot()[0]["state"], "SIMULATED_RECONCILIATION_REQUIRED")
        context = _synthetic_context(now=NOW + timedelta(seconds=4), source_hash="f" * 64)
        blocked = self._early_result(context)
        self.assertEqual(blocked["status"], "BLOCKED_UNRESOLVED_SIMULATION")

    def test_fake_202_requires_strictly_post_transport_observation(self):
        reserved = self._early_result()
        key = reserved["simulation_id"]
        row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        self.assertEqual(self.ledger.record_auto_reallocation_simulation_transport(
            key, outcome="FAKE_HTTP_202", at_utc=_time(10),
        )["status"], "SIMULATED_ACCEPTED_PENDING")

        reservation = row["payload"]["reservation_identity"]
        for observed_at, suffix in ((_time(5), "PREMATURE"), (_time(10), "AT-TRANSPORT")):
            proof, verifier = _fixture_observation(
                row, result="SIMULATED_NO_CHANGE", observed_at=observed_at,
                observed_instance=reservation["original_instance_fingerprint"],
                observed_generation=reservation["original_generation_fingerprint"],
                evidence_suffix=suffix,
            )
            rejected = self.ledger.reconcile_auto_reallocation_simulation(
                key, observation=proof, observation_verifier=verifier, at_utc=_time(11),
            )
            self.assertEqual(rejected["reason"], "SYNTHETIC_OBSERVATION_TIME_INVALID")
            self.assertEqual(
                self.ledger.auto_reallocation_simulation_snapshot()[0]["state"],
                "SIMULATED_ACCEPTED_PENDING",
            )

        context = _synthetic_context(now=NOW + timedelta(seconds=11), source_hash="f" * 64)
        self.assertEqual(self._early_result(context)["status"], "BLOCKED_UNRESOLVED_SIMULATION")
        duplicate_transport = self.ledger.record_auto_reallocation_simulation_transport(
            key, outcome="FAKE_TIMEOUT", at_utc=_time(11),
        )
        self.assertEqual(duplicate_transport["reason"], "SIMULATION_TRANSPORT_STATE_INVALID")
        current = self.ledger.auto_reallocation_simulation_snapshot()[0]
        self.assertEqual(current["payload"]["simulation_transport_at_utc"], _time(10))
        self.assertEqual(current["payload"]["simulation_transport_outcome"], "FAKE_HTTP_202")

        terminal, verifier = _fixture_observation(
            current, result="SIMULATED_NO_CHANGE", observed_at=_time(11),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"],
            evidence_suffix="AFTER-202",
        )
        reconciled = self.ledger.reconcile_auto_reallocation_simulation(
            key, observation=terminal, observation_verifier=verifier, at_utc=_time(12),
        )
        self.assertEqual(reconciled["status"], "SIMULATED_RECONCILED")

    def test_fake_timeout_requires_strictly_post_transport_observation(self):
        reserved = self._early_result()
        key = reserved["simulation_id"]
        row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        self.assertEqual(self.ledger.record_auto_reallocation_simulation_transport(
            key, outcome="FAKE_TIMEOUT", at_utc=_time(10),
        )["status"], "SIMULATED_RECONCILIATION_REQUIRED")
        reservation = row["payload"]["reservation_identity"]
        premature, premature_verifier = _fixture_observation(
            row, result="SIMULATED_NO_CHANGE", observed_at=_time(5),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"],
            evidence_suffix="PREMATURE-TIMEOUT",
        )
        rejected = self.ledger.reconcile_auto_reallocation_simulation(
            key, observation=premature, observation_verifier=premature_verifier, at_utc=_time(11),
        )
        self.assertEqual(rejected["reason"], "SYNTHETIC_OBSERVATION_TIME_INVALID")
        self.assertEqual(
            self.ledger.auto_reallocation_simulation_snapshot()[0]["state"],
            "SIMULATED_RECONCILIATION_REQUIRED",
        )
        context = _synthetic_context(now=NOW + timedelta(seconds=11), source_hash="e" * 64)
        self.assertEqual(self._early_result(context)["status"], "BLOCKED_UNRESOLVED_SIMULATION")
        current = self.ledger.auto_reallocation_simulation_snapshot()[0]
        terminal, verifier = _fixture_observation(
            current, result="SIMULATED_NO_CHANGE", observed_at=_time(11),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"],
            evidence_suffix="AFTER-TIMEOUT",
        )
        reconciled = self.ledger.reconcile_auto_reallocation_simulation(
            key, observation=terminal, observation_verifier=verifier, at_utc=_time(12),
        )
        self.assertEqual(reconciled["status"], "SIMULATED_RECONCILED")

    def test_legacy_simulation_without_transport_timestamp_fails_closed(self):
        reserved = self._early_result()
        key = reserved["simulation_id"]
        row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        self.ledger.record_auto_reallocation_simulation_transport(
            key, outcome="FAKE_HTTP_202", at_utc=_time(1),
        )
        payload = row["payload"]
        payload.pop("simulation_transport_at_utc", None)
        self.ledger.connection.execute(
            "UPDATE auto_reallocation_simulations SET payload_json=? WHERE simulation_key=?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), key),
        )
        reservation = payload["reservation_identity"]
        proof, verifier = _fixture_observation(
            row, result="SIMULATED_NO_CHANGE", observed_at=_time(2),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"],
            evidence_suffix="MISSING-TRANSPORT-TIME",
        )
        rejected = self.ledger.reconcile_auto_reallocation_simulation(
            key, observation=proof, observation_verifier=verifier, at_utc=_time(3),
        )
        self.assertEqual(rejected["reason"], "SYNTHETIC_TRANSPORT_TIME_INVALID")
        self.assertEqual(
            self.ledger.auto_reallocation_simulation_snapshot()[0]["state"],
            "SIMULATED_ACCEPTED_PENDING",
        )

    def test_reconciliation_rejects_forged_stale_and_wrong_generation_evidence(self):
        first = self._early_result()
        row = self.ledger.auto_reallocation_simulation_snapshot()[0]
        self.ledger.record_auto_reallocation_simulation_transport(
            first["simulation_id"], outcome="FAKE_HTTP_202", at_utc=_time(1),
        )
        reservation = row["payload"]["reservation_identity"]
        valid, verifier = _fixture_observation(
            row, result="SIMULATED_NO_CHANGE", observed_at=_time(2),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"],
        )
        stale, stale_verifier = _fixture_observation(
            row, result="SIMULATED_NO_CHANGE", observed_at=_time(0),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation=reservation["original_generation_fingerprint"], evidence_suffix="STALE",
        )
        self.assertEqual(self.ledger.reconcile_auto_reallocation_simulation(
            first["simulation_id"], observation=stale, observation_verifier=stale_verifier,
            at_utc=_time(3),
        )["reason"], "SYNTHETIC_OBSERVATION_TIME_INVALID")
        forged = dict(valid, target_scope="0" * 64)
        self.assertEqual(self.ledger.reconcile_auto_reallocation_simulation(
            first["simulation_id"], observation=forged, observation_verifier=verifier,
            at_utc=_time(3),
        )["reason"], "SYNTHETIC_OBSERVATION_VERIFICATION_FAILED")
        wrong_assignment = dict(valid, assignment_scope="1" * 64)
        self.assertEqual(self.ledger.reconcile_auto_reallocation_simulation(
            first["simulation_id"], observation=wrong_assignment, observation_verifier=verifier,
            at_utc=_time(3),
        )["reason"], "SYNTHETIC_OBSERVATION_VERIFICATION_FAILED")
        wrong_generation, wrong_generation_verifier = _fixture_observation(
            row, result="SIMULATED_NO_CHANGE", observed_at=_time(2),
            observed_instance=reservation["original_instance_fingerprint"],
            observed_generation="0" * 64, evidence_suffix="WRONG-GENERATION",
        )
        self.assertEqual(self.ledger.reconcile_auto_reallocation_simulation(
            first["simulation_id"], observation=wrong_generation,
            observation_verifier=wrong_generation_verifier, at_utc=_time(3),
        )["reason"], "SYNTHETIC_NO_CHANGE_NOT_PROVEN")
        self.assertEqual(self.ledger.auto_reallocation_simulation_snapshot()[0]["state"], "SIMULATED_ACCEPTED_PENDING")
        self.assertFalse(self.ledger.snapshot())

    def test_secret_like_fields_are_rejected_without_echo_and_persisted_rows_are_opaque(self):
        context = _synthetic_context()
        secret = "synthetic-never-print-credential"
        source = dict(context["source"], api_key=secret)
        result = self._early_result(context, source_evidence=source)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("SECRET_LIKE_FIELDS_REJECTED", result["blockers"])
        self.assertNotIn(secret, json.dumps(result))
        result = self._early_result(context)
        ledger_json = json.dumps(self.ledger.auto_reallocation_simulation_snapshot())
        self.assertNotIn("56319ab3", ledger_json)
        self.assertNotIn("6bbd35d9", ledger_json)
        self.assertFalse(result["request_submitted"])

    def test_default_gate_and_incomplete_or_malformed_evidence_fail_closed(self):
        context = _synthetic_context()
        disabled = AutoReallocationGate(self.ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS)
        common = {
            "source_evidence": context["source"], "policy_evidence": context["policy"],
            "generation_evidence": context["generation"], "provider_binding": context["binding"],
            "provider_revalidation": context["provider"], "budget_evidence": context["budget"],
            "allocation_history": context["history"], "fleet_id": context["fleet_id"],
            "now_utc": context["now_utc"], "kill_switch_engaged": False, "auto_armed": True,
        }
        self.assertIn("SIMULATION_GATE_DISABLED", disabled.assess_early(_early(context), **common)["blockers"])
        malformed = self._early_result(context, source_evidence=None)
        self.assertEqual(malformed["status"], "BLOCKED")
        self.assertFalse(self.ledger.auto_reallocation_simulation_snapshot())
        closed_ledger = ActionLedger(":memory:")
        try:
            internally_enabled_but_durably_closed = AutoReallocationGate(
                closed_ledger, policy_hash=POLICY_HASH, gpu_floors_ths=FLOORS,
                limits=AutoReallocationLimits(10, 20, 0, 3, 5), simulation_enabled=True,
            )
            closed = internally_enabled_but_durably_closed.assess_early(_early(context), **common)
            self.assertEqual(closed["status"], "BLOCKED_SIMULATION_DISARMED")
            self.assertEqual(closed["blockers"], ["SIMULATION_CONTROL_CLOSED"])
            self.assertFalse(closed_ledger.auto_reallocation_simulation_snapshot())
        finally:
            closed_ledger.close()


if __name__ == "__main__":
    unittest.main()
