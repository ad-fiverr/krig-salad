"""Hermetic tests for the SCRUM-175 EARLY dispatch and reconciliation bridge."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
TESTS_ROOT = Path(__file__).resolve().parent
G4C_ROOT = Path(__file__).resolve().parents[2] / "g4c-live"
sys.path.insert(0, str(TELEMETRY_ROOT))
sys.path.insert(0, str(G4C_ROOT))
sys.path.insert(0, str(TESTS_ROOT))

import test_provider_binding_revalidation as binding_fixtures  # noqa: E402
from collector.action_ledger import ActionLedger  # noqa: E402
from collector.auto_reallocation_gate import AutoReallocationGate, AutoReallocationLimits  # noqa: E402
from collector.early_reallocation_dispatch import EarlyReallocationDispatcher  # noqa: E402
from collector.salad_action_policy import (  # noqa: E402
    ActionCapabilityVerifier,
    DecisionDossierAuthority,
    SaladAction,
    SaladActionPolicy,
    SignedActionCapability,
)
from collector.salad_action_transport import (  # noqa: E402
    RestrictedSaladActionHTTPTransport,
    SaladActionExecutor,
    fixed_action_path,
)
from live_secret_boundary import SYNTHETIC_SECRET_VALUE, SyntheticSecretProvider  # noqa: E402
from log_alerts.provider_binding_revalidation import (  # noqa: E402
    ExplicitBindingAllowlist,
    ProviderBindingRevalidator,
    SyntheticFreshProviderSource,
)


FIXTURE = "G5-SYNTHETIC-ACTION-PATH"
NOW = binding_fixtures.NOW
POLICY_HASH = binding_fixtures.POLICY.policy_hash
INSTANCE = str(uuid.uuid4())
REPLACEMENT_INSTANCE = str(uuid.uuid4())
MACHINE = "machine-synthetic-175"
ASSIGNMENT = "assignment-synthetic-175"
GENERATION = "generation-synthetic-175-1"


class SyntheticEarlyEvidenceVerifier:
    synthetic_test_only = True

    @staticmethod
    def _tagged(value):
        return isinstance(value, dict) and value.get("synthetic_fixture_id") == FIXTURE

    def verify_early_decision(self, value):
        return (
            isinstance(value, dict)
            and value.get("state") == "EARLY_UNDER_FLOOR"
            and value.get("calibration_status") == "APPLIED_APPROVED_MEASURED_PAIRS"
        )

    def verify_early_calibration(self, value):
        return value.get("calibration_status") == "APPLIED_APPROVED_MEASURED_PAIRS"

    def verify_controller_assessment(self, value): return False
    def verify_early_generation(self, value): return self._tagged(value)
    def verify_early_revalidation(self, value): return self._tagged(value)
    def verify_binding(self, value): return self._tagged(value)
    def verify_provider(self, value): return self._tagged(value)
    def verify_telemetry(self, value): return self._tagged(value)
    def verify_low_evaluations(self, value): return False
    def verify_budget(self, value): return self._tagged(value)
    def verify_allocation_history(self, value): return self._tagged(value)


class SyntheticReconciliationVerifier:
    synthetic_test_only = True

    def verify_action_outcome(self, entry, observation):
        return (
            entry.get("state") == "ACCEPTED_PENDING"
            and observation.get("synthetic_fixture_id") == FIXTURE
            and observation.get("data_classification") == "SYNTHETIC/UNVERIFIED"
            and isinstance(observation.get("replacement_binding"), dict)
        )


class DummySwitch:
    enabled = True


class FakeBudgetStore:
    def __init__(self):
        self.audit = []
        self.reservations = []
        self.reconciliations = []

    def reserve_budget_exposure(self, **kwargs):
        self.reservations.append(dict(kwargs))
        return "RESERVED"

    def reconcile_budget_exposure(self, *args, **kwargs):
        self.reconciliations.append((args, dict(kwargs)))

    def append_audit(self, event, payload, at_utc):
        self.audit.append((event, dict(payload), at_utc))


class FakeActionTransport:
    synthetic_test_only = True
    enabled = False

    def __init__(self, *, capability, verifier, ledger, timeout=False):
        self.capability = capability
        self.verifier = verifier
        self.ledger = ledger
        self.timeout = timeout
        self.calls = []
        self.state_at_submit = []

    def action_capability_nonce(self, action, target, route, *, now_epoch):
        return self.verifier.verified_nonce(
            self.capability, action=action, target=target, route=route,
            now_epoch=now_epoch,
        )

    def submit_bound(self, action, target, secret, *, action_key, authorization_nonce, nonce_ledger):
        row = self.ledger.get(action_key)
        self.state_at_submit.append(row["state"] if row else None)
        self.calls.append({"action": action.value, "secret_type": type(secret).__name__})
        if not nonce_ledger.claim_signed_action_dispatch(
            authorization_nonce, action_key, _utc(NOW),
        ):
            raise RuntimeError("fake transport rejected duplicate dispatch claim")
        if self.timeout:
            raise TimeoutError("synthetic uncertainty")
        return {
            "http_status_code": 202,
            "actions_performed": False,
            "response_body": None,
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "synthetic_fixture_id": FIXTURE,
        }


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _capability(action, target, now_epoch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    nonce = str(uuid.uuid4())
    claims = {
        "schema_version": 2,
        "audience": "salad-g5-control-plane",
        "host": "api.salad.com",
        "organization": target["organization"],
        "project": target["project"],
        "container_group": target["container_group"],
        "action": action.value,
        "path": fixed_action_path(action, target),
        "issued_at_epoch": now_epoch - 1,
        "expires_at_epoch": now_epoch + 60,
        "nonce": nonce,
        "max_requests": 1,
        "assignment_generation": target["assignment_generation"],
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return SignedActionCapability(payload, private.sign(payload)), ActionCapabilityVerifier(public)


def _evidence(assignment=ASSIGNMENT, generation=GENERATION, source_hash="e" * 64):
    decision = {
        "decision_version": 1,
        "state": "EARLY_UNDER_FLOOR",
        "reason": "UPPER_BOUND_BELOW_THRESHOLD",
        "signal_type": "PEARL_AUTOTUNE",
        "device_index": 1,
        "gpu_key": "RTX_5080_LAPTOP",
        "estimate_ths": 100.0,
        "predicted_lower_ths": 96.0,
        "predicted_upper_ths": 104.0,
        "floor_ths": 120.0,
        "policy_hash": POLICY_HASH,
        "assignment_id": assignment,
        "assignment_generation": generation,
        "actions_performed": False,
        "action_eligible": False,
        "evaluated_at_utc": _utc(NOW),
        "source_reference_sha256": source_hash,
        "calibration_status": "APPLIED_APPROVED_MEASURED_PAIRS",
        "calibration_evidence_sha256": "f" * 64,
    }
    source = {
        "source": "FL4SHMINER_AUTOTUNE_LOG",
        "source_reference_sha256": source_hash,
        "data_classification": "SYNTHETIC/UNVERIFIED",
        "synthetic_fixture_id": FIXTURE,
    }
    policy = {
        "policy_hash": POLICY_HASH,
        "gpu_floors_ths": {"RTX_5080_LAPTOP": 120.0},
        "data_classification": "SYNTHETIC/UNVERIFIED",
        "synthetic_fixture_id": FIXTURE,
    }
    generation_data = {
        "status": "CURRENT",
        "assignment_id": assignment,
        "assignment_generation": generation,
        "policy_hash": POLICY_HASH,
        "observed_at_utc": _utc(NOW),
        "valid_from_utc": _utc(NOW - timedelta(minutes=1)),
        "valid_until_utc": _utc(NOW + timedelta(minutes=2)),
        "data_classification": "SYNTHETIC/UNVERIFIED",
        "synthetic_fixture_id": FIXTURE,
    }
    budget = {
        "status": "VERIFIED", "currency": "USD",
        "verified_spend_usd": "1.00", "verified_next_action_cost_usd": "0.25",
        "pending_exposure_usd": "0.00", "maximum_exposure_usd": "1.25",
        "spend_evidence_id": "synthetic-spend",
        "next_action_cost_evidence_id": "synthetic-next-cost",
        "pending_exposure_evidence_id": "synthetic-pending",
        "maximum_exposure_evidence_id": "synthetic-max",
        "action_cost_source_reference": "synthetic-test-source",
        "data_classification": "SYNTHETIC/UNVERIFIED",
        "synthetic_fixture_id": FIXTURE,
    }
    history = {
        "history_known": True,
        "allocation_reallocation_count": 0,
        "fleet_reallocation_count": 0,
        "observed_at_utc": _utc(NOW),
        "data_classification": "SYNTHETIC/UNVERIFIED",
        "synthetic_fixture_id": FIXTURE,
    }
    return decision, source, policy, generation_data, budget, history


def _proof_and_revalidator(*, assignment=ASSIGNMENT, generation=GENERATION, instance=INSTANCE,
                           machine=MACHINE, snapshots=None):
    old_values = (binding_fixtures.ASSIGNMENT, binding_fixtures.GENERATION, binding_fixtures.INSTANCE,
                  binding_fixtures.MACHINE)
    binding_fixtures.ASSIGNMENT = assignment
    binding_fixtures.GENERATION = generation
    binding_fixtures.INSTANCE = instance
    binding_fixtures.MACHINE = machine
    try:
        _resolution, proof, _response = binding_fixtures._resolution()
        assert proof is not None
        signed, trust = binding_fixtures._snapshot()
        response_set = snapshots() if callable(snapshots) else (snapshots or ((signed,), (signed,)))
        source = SyntheticFreshProviderSource(
            target=binding_fixtures.TARGET,
            trusted_authorities=trust,
            responses=response_set,
        )
        revalidator = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((binding_fixtures.TARGET,)),
            source=source,
        )
        return proof, revalidator, source, old_values
    except Exception:
        (binding_fixtures.ASSIGNMENT, binding_fixtures.GENERATION,
         binding_fixtures.INSTANCE, binding_fixtures.MACHINE) = old_values
        raise


def _restore_binding_globals(old_values):
    (binding_fixtures.ASSIGNMENT, binding_fixtures.GENERATION,
     binding_fixtures.INSTANCE, binding_fixtures.MACHINE) = old_values


def _dispatcher(*, ledger, timeout=False, epoch=None, revalidator=None, executor_override=None,
                assignment=ASSIGNMENT, generation=GENERATION, instance=INSTANCE, machine=MACHINE,
                source_hash="e" * 64):
    epoch = NOW.timestamp() if epoch is None else epoch
    action = SaladAction.REALLOCATE_INSTANCE
    target = {
        "organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer-2",
        "machine_id": machine, "instance_id": instance, "assignment_id": assignment,
        "assignment_generation": generation, "deterioration_id": source_hash,
    }
    capability, verifier = _capability(action, target, epoch)
    fake = FakeActionTransport(capability=capability, verifier=verifier, ledger=ledger, timeout=timeout)
    authority = DecisionDossierAuthority(action_evidence_verifier=SyntheticEarlyEvidenceVerifier())
    budget_store = FakeBudgetStore()
    policy = SaladActionPolicy(
        live_actions_enabled=True, live_spend_authorized=True, auto_reallocate=True, g5_reviewed=True,
    )
    executor = executor_override or SaladActionExecutor(
        policy=policy, ledger=ledger, transport=fake, secret_provider=SyntheticSecretProvider(),
        kill_switch=DummySwitch(), clock=lambda: epoch, dossier_authority=authority,
        budget_store=budget_store, reconciliation_verifier=SyntheticReconciliationVerifier(),
    )
    gate = AutoReallocationGate(
        ledger, policy_hash=POLICY_HASH, gpu_floors_ths={"RTX_5080_LAPTOP": 120.0},
        limits=AutoReallocationLimits(
            max_per_minute=4, max_per_day=12, cooldown_seconds=0,
            max_per_assignment=3, max_per_fleet=6,
        ),
        admission_mode="LIVE", simulation_enabled=False, live_transport_disabled=True,
    )
    return EarlyReallocationDispatcher(
        gate=gate, revalidator=revalidator, executor=executor,
        dossier_authority=authority, enabled=True, epoch_clock=lambda: epoch,
    ), gate, executor, fake, budget_store


def _eligible_admission():
    return {
        "status": "LIVE_ADMISSION_ELIGIBLE", "admission_only": True,
        "live_action_eligible": True, "actions_performed": False,
        "request_submitted": False, "dossier_created": False,
        "policy_hash": POLICY_HASH,
    }


class EarlyReallocationDispatchTests(unittest.TestCase):
    def _run_dispatch(self, *, timeout=False, assignment=ASSIGNMENT, generation=GENERATION,
                      instance=INSTANCE, snapshots=None, decision_mutator=None, enabled=True,
                      revalidation_state_log=None, source_hash="e" * 64, capture_proof=False):
        temp = tempfile.TemporaryDirectory(prefix="scrum-175-")
        ledger = ActionLedger(Path(temp.name) / "actions.sqlite3")
        proof, revalidator, source, old_values = _proof_and_revalidator(
            assignment=assignment, generation=generation, instance=instance, snapshots=snapshots,
        )
        try:
            dispatcher, gate, executor, fake, budget_store = _dispatcher(
                ledger=ledger, timeout=timeout, revalidator=revalidator, source_hash=source_hash,
            )
            dispatcher.enabled = enabled
            decision, source_evidence, policy, generation_data, budget, history = _evidence(
                assignment=assignment, generation=generation, source_hash=source_hash,
            )
            if decision_mutator:
                decision_mutator(decision)
            with patch.object(gate, "assess_early", return_value=_eligible_admission()) as gate_call, \
                 patch.object(socket, "create_connection", side_effect=AssertionError("socket forbidden")), \
                 patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("network forbidden")):
                if revalidation_state_log is not None:
                    original_revalidate = ProviderBindingRevalidator.revalidate_pre_dispatch
                    expected_target = {
                        "organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer-2",
                        "machine_id": proof.binding.machine_id,
                        "instance_id": proof.binding.instance_id, "assignment_id": proof.record.assignment_id,
                        "assignment_generation": proof.record.assignment_generation,
                        "deterioration_id": source_hash,
                    }
                    expected_key = ActionLedger.early_live_key_for(
                        action=SaladAction.REALLOCATE_INSTANCE.value, target=expected_target,
                    )

                    def observe_revalidation(instance_of_class, proof_handle, *, now_utc):
                        result = original_revalidate(instance_of_class, proof_handle, now_utc=now_utc)
                        reserved = ledger.get(expected_key)
                        revalidation_state_log.append(reserved["state"] if reserved else None)
                        return result

                    with patch.object(ProviderBindingRevalidator, "revalidate_pre_dispatch", new=observe_revalidation):
                        result = dispatcher.dispatch(
                            decision, proof_handle=proof, source_evidence=source_evidence,
                            policy_evidence=policy, generation_evidence=generation_data,
                            budget_evidence=budget, allocation_history=history,
                            fleet_id="synthetic-fleet", now_utc=NOW,
                        )
                else:
                    result = dispatcher.dispatch(
                        decision, proof_handle=proof, source_evidence=source_evidence,
                        policy_evidence=policy, generation_evidence=generation_data,
                        budget_evidence=budget, allocation_history=history,
                        fleet_id="synthetic-fleet", now_utc=NOW,
                    )
            packed = (result, ledger, gate_call, executor, fake, budget_store, source, old_values, temp)
            if capture_proof:
                return packed + (proof, revalidator)
            return packed
        except Exception:
            ledger.close()
            temp.cleanup()
            _restore_binding_globals(old_values)
            raise

    def test_fake_gate_positive_dispatch_orchestration_only_is_one_synthetic_attempt(self):
        """A fake positive gate verifies sequencing, not actual LIVE eligibility."""
        result, ledger, gate_call, executor, fake, budget_store, source, old_values, temp = self._run_dispatch()
        try:
            self.assertEqual(result.status, "ACCEPTED_PENDING", result)
            self.assertEqual(result.http_status_code, 202)
            self.assertFalse(result.actions_performed)
            self.assertFalse(result.request_submitted)  # Synthetic transport never claims a real provider request.
            self.assertEqual(result.data_classification, "SYNTHETIC/UNVERIFIED")
            self.assertEqual(len(fake.calls), 1)
            self.assertEqual(fake.state_at_submit, ["SEND_STARTED"])
            self.assertEqual(source.read_calls, 2)
            self.assertEqual(gate_call.call_count, 1)
            self.assertEqual(len(budget_store.reservations), 1)
            row = ledger.get(result.action_key)
            self.assertEqual(row["state"], "ACCEPTED_PENDING")
            self.assertEqual(row["recommendation"]["dispatch_kind"], "EARLY")
            self.assertEqual(row["recommendation"]["target"]["assignment_generation"], GENERATION)
            self.assertEqual(ledger.connection.execute("SELECT COUNT(*) FROM early_generation_dispatch_locks").fetchone()[0], 1)
        finally:
            ledger.close()
            temp.cleanup()
            _restore_binding_globals(old_values)

    def test_real_live_gate_rejects_synthetic_evidence_without_reservation_or_secret(self):
        temp = tempfile.TemporaryDirectory(prefix="scrum-175-real-gate-")
        ledger = ActionLedger(Path(temp.name) / "actions.sqlite3")
        proof, revalidator, _source, old_values = _proof_and_revalidator()
        try:
            _dispatcher_value, gate, executor, fake, budget_store = _dispatcher(
                ledger=ledger, revalidator=revalidator,
            )
            decision, source_evidence, policy, generation_data, budget, history = _evidence()
            classification = proof.record.observation_reference.data_classification
            revalidation = revalidator.revalidate_pre_dispatch(proof, now_utc=NOW)
            binding = EarlyReallocationDispatcher._typed_binding_evidence(proof, classification)
            provider_revalidation = EarlyReallocationDispatcher._typed_revalidation_evidence(
                proof, revalidation, classification,
            )
            with patch.object(socket, "create_connection", side_effect=AssertionError("socket forbidden")), \
                 patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("network forbidden")), \
                 patch.object(executor.secret_provider, "acquire", wraps=executor.secret_provider.acquire) as acquire:
                admission = gate.assess_early(
                    decision,
                    source_evidence=source_evidence,
                    policy_evidence=policy,
                    generation_evidence=generation_data,
                    provider_binding=binding,
                    provider_revalidation=provider_revalidation,
                    budget_evidence=budget,
                    allocation_history=history,
                    fleet_id="synthetic-fleet",
                    now_utc=_utc(NOW),
                    kill_switch_engaged=False,
                    auto_armed=False,
                    live_actions_enabled=False,
                    g5_authorized=False,
                )
            self.assertEqual(admission["status"], "BLOCKED")
            self.assertIn("SYNTHETIC_EVIDENCE_CANNOT_AUTHORIZE_LIVE_ADMISSION", admission["blockers"])
            self.assertEqual(classification, "SYNTHETIC/UNVERIFIED")
            self.assertEqual(acquire.call_count, 0)
            self.assertEqual(fake.calls, [])
            self.assertEqual(budget_store.reservations, [])
            self.assertEqual(ledger.snapshot(), [])
            self.assertEqual(ledger.connection.execute(
                "SELECT COUNT(*) FROM early_generation_dispatch_locks",
            ).fetchone()[0], 0)
        finally:
            ledger.close()
            temp.cleanup()
            _restore_binding_globals(old_values)

    def test_timeout_becomes_reconciliation_required_without_retry_after_restart(self):
        result, ledger, gate_call, _executor, fake, _budget, _source, old_values, temp = self._run_dispatch(timeout=True)
        try:
            self.assertEqual(result.status, "RECONCILIATION_REQUIRED")
            self.assertFalse(result.actions_performed)
            self.assertEqual(len(fake.calls), 1)
            row = ledger.get(result.action_key)
            self.assertEqual(row["state"], "RECONCILIATION_REQUIRED")
            self.assertEqual(ledger.connection.execute("SELECT COUNT(*) FROM early_generation_dispatch_locks").fetchone()[0], 1)
            ledger.close()
            reopened = ActionLedger(Path(temp.name) / "actions.sqlite3")
            proof, revalidator, source, second_old_values = _proof_and_revalidator()
            try:
                dispatcher, gate, _executor, _transport, _budget = _dispatcher(
                    ledger=reopened, revalidator=revalidator,
                )
                decision, source_evidence, policy, generation_data, budget, history = _evidence()
                with patch.object(gate, "assess_early", return_value=_eligible_admission()):
                    repeated = dispatcher.dispatch(
                        decision, proof_handle=proof, source_evidence=source_evidence,
                        policy_evidence=policy, generation_evidence=generation_data,
                        budget_evidence=budget, allocation_history=history,
                        fleet_id="synthetic-fleet", now_utc=NOW,
                    )
                self.assertEqual(repeated.status, "BLOCKED")
                self.assertEqual(repeated.reason_code, "EARLY_DOSSIER_REJECTED")
                self.assertEqual(reopened.get(result.action_key)["state"], "RECONCILIATION_REQUIRED")
                self.assertEqual(reopened.connection.execute("SELECT COUNT(*) FROM early_generation_dispatch_locks").fetchone()[0], 1)
                self.assertEqual(source.read_calls, 1)
                self.assertEqual(_transport.calls, [])
            finally:
                reopened.close()
                _restore_binding_globals(second_old_values)
        finally:
            if not ledger.connection is None:
                try: ledger.close()
                except Exception: pass
            temp.cleanup()
            _restore_binding_globals(old_values)

    def test_exact_provider_revalidation_occurs_after_durable_reservation_and_before_send(self):
        states = []
        result, ledger, _gate, _executor, fake, _budget, source, old_values, _temp = self._run_dispatch(
            revalidation_state_log=states,
        )
        try:
            self.assertEqual(result.status, "ACCEPTED_PENDING")
            self.assertEqual(source.read_calls, 2)
            self.assertEqual(states, [None, "RESERVED"])
            self.assertEqual(fake.state_at_submit, ["SEND_STARTED"])
            call_kwargs = _gate.call_args.kwargs
            self.assertFalse(call_kwargs["auto_armed"])
            self.assertFalse(call_kwargs["live_actions_enabled"])
            self.assertFalse(call_kwargs["g5_authorized"])
        finally:
            ledger.close()
            _temp.cleanup()
            _restore_binding_globals(old_values)

    def test_actual_http_transport_enabled_during_gate_evaluation_blocks_dispatch(self):
        temp = tempfile.TemporaryDirectory(prefix="scrum-175-transport-state-")
        ledger = ActionLedger(Path(temp.name) / "actions.sqlite3")
        proof, revalidator, _source, old_values = _proof_and_revalidator()
        try:
            dispatcher, gate, executor, fake, _budget = _dispatcher(
                ledger=ledger, revalidator=revalidator,
            )
            transport = RestrictedSaladActionHTTPTransport(
                enabled=False,
                authorization_capability=fake.capability,
                authorization_verifier=fake.verifier,
            )
            executor.transport = transport
            decision, source_evidence, policy, generation_data, budget, history = _evidence()
            def enable_after_gate(*_args, **_kwargs):
                transport.enabled = True
                return _eligible_admission()

            with patch.object(gate, "assess_early", side_effect=enable_after_gate) as assess, \
                 patch.object(socket, "create_connection", side_effect=AssertionError("socket forbidden")), \
                 patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("network forbidden")), \
                 patch.object(executor.secret_provider, "acquire", wraps=executor.secret_provider.acquire) as acquire:
                result = dispatcher.dispatch(
                    decision, proof_handle=proof, source_evidence=source_evidence,
                    policy_evidence=policy, generation_evidence=generation_data,
                    budget_evidence=budget, allocation_history=history,
                    fleet_id="synthetic-fleet", now_utc=NOW,
                )

            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(result.reason_code, "LIVE_TRANSPORT_EFFECTIVE_STATE_INVALID")
            self.assertEqual(assess.call_count, 1)
            self.assertFalse(result.request_submitted)
            self.assertEqual(acquire.call_count, 0)
            self.assertEqual(fake.calls, [])
            self.assertEqual(ledger.snapshot(), [])
            self.assertEqual(_budget.reservations, [])
            self.assertEqual(ledger.connection.execute(
                "SELECT COUNT(*) FROM early_generation_dispatch_locks",
            ).fetchone()[0], 0)
        finally:
            ledger.close()
            temp.cleanup()
            _restore_binding_globals(old_values)

    def test_synthetic_transport_enabled_after_reservation_aborts_before_secret_or_send(self):
        temp = tempfile.TemporaryDirectory(prefix="scrum-175-pre-send-transport-state-")
        ledger = ActionLedger(Path(temp.name) / "actions.sqlite3")
        proof, revalidator, _source, old_values = _proof_and_revalidator()
        try:
            dispatcher, gate, executor, fake, _budget = _dispatcher(
                ledger=ledger, revalidator=revalidator,
            )
            decision, source_evidence, policy, generation_data, budget, history = _evidence()
            original_reserve = ledger.reserve_live_early

            def reserve_then_enable(*args, **kwargs):
                reservation = original_reserve(*args, **kwargs)
                fake.enabled = True
                return reservation

            with patch.object(gate, "assess_early", return_value=_eligible_admission()), \
                 patch.object(ledger, "reserve_live_early", side_effect=reserve_then_enable), \
                 patch.object(socket, "create_connection", side_effect=AssertionError("socket forbidden")), \
                 patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("network forbidden")), \
                 patch.object(executor.secret_provider, "acquire", wraps=executor.secret_provider.acquire) as acquire:
                result = dispatcher.dispatch(
                    decision, proof_handle=proof, source_evidence=source_evidence,
                    policy_evidence=policy, generation_evidence=generation_data,
                    budget_evidence=budget, allocation_history=history,
                    fleet_id="synthetic-fleet", now_utc=NOW,
                )

            self.assertEqual(result.status, "ABORTED_PRE_SEND", result)
            self.assertFalse(result.request_submitted)
            self.assertEqual(acquire.call_count, 0)
            self.assertEqual(fake.calls, [])
            row = ledger.get(result.action_key)
            self.assertEqual(row["state"], "ABORTED_PRE_SEND")
            self.assertEqual(row["receipt"]["request_submitted"], False)
            self.assertEqual(ledger.connection.execute(
                "SELECT COUNT(*) FROM early_generation_dispatch_locks",
            ).fetchone()[0], 1)
        finally:
            ledger.close()
            temp.cleanup()
            _restore_binding_globals(old_values)

    def test_wrong_generation_and_replaced_current_binding_block_without_post(self):
        wrong, ledger, _gate, _executor, fake, _budget, _source, old_values, _temp = self._run_dispatch(
            decision_mutator=lambda decision: decision.update(assignment_generation="generation-stale"),
        )
        try:
            self.assertEqual(wrong.status, "BLOCKED")
            self.assertEqual(wrong.reason_code, "EARLY_PROOF_OR_DECISION_MISMATCH")
            self.assertEqual(fake.calls, [])
        finally:
            ledger.close()
            _temp.cleanup()
            _restore_binding_globals(old_values)

        replacement, ledger, _gate, _executor, fake, _budget, _source, old_values, _temp = self._run_dispatch(
            snapshots=lambda: ((binding_fixtures._snapshot(assignment_generation="generation-replaced")[0],),),
        )
        try:
            self.assertEqual(replacement.status, "BLOCKED")
            self.assertEqual(replacement.reason_code, "EARLY_PROVIDER_REVALIDATION_FAILED")
            self.assertEqual(fake.calls, [])
            row = ledger.snapshot()
            self.assertEqual(row, [])
        finally:
            ledger.close()
            _temp.cleanup()
            _restore_binding_globals(old_values)

    def test_off_and_simulation_modes_never_dispatch(self):
        result, ledger, _gate, _executor, fake, _budget, _source, old_values, _temp = self._run_dispatch(enabled=False)
        try:
            self.assertEqual((result.status, result.reason_code), ("BLOCKED", "EARLY_DISPATCH_DISABLED"))
            self.assertEqual(fake.calls, [])
            self.assertEqual(ledger.snapshot(), [])
        finally:
            ledger.close()
            _temp.cleanup()
            _restore_binding_globals(old_values)

        temp = tempfile.TemporaryDirectory(prefix="scrum-175-simulation-")
        ledger = ActionLedger(Path(temp.name) / "actions.sqlite3")
        proof, revalidator, source, old_values = _proof_and_revalidator()
        try:
            dispatcher, gate, _executor, fake, _budget = _dispatcher(
                ledger=ledger, revalidator=revalidator,
            )
            gate.admission_mode = "SIMULATION"
            decision, source_evidence, policy, generation_data, budget, history = _evidence()
            result = dispatcher.dispatch(
                decision, proof_handle=proof, source_evidence=source_evidence,
                policy_evidence=policy, generation_evidence=generation_data,
                budget_evidence=budget, allocation_history=history,
                fleet_id="synthetic-fleet", now_utc=NOW,
            )
            self.assertEqual(result.reason_code, "LIVE_ADMISSION_CONFIGURATION_INVALID")
            self.assertEqual(fake.calls, [])
            self.assertEqual(ledger.snapshot(), [])
        finally:
            ledger.close()
            temp.cleanup()
            _restore_binding_globals(old_values)

    def test_same_generation_atomic_reservation_survives_terminal_state(self):
        ledger = ActionLedger(":memory:")
        target = {
            "organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer-2",
            "machine_id": MACHINE, "instance_id": INSTANCE, "assignment_id": ASSIGNMENT,
            "assignment_generation": GENERATION, "deterioration_id": "e" * 64,
        }
        key = ActionLedger.early_live_key_for(action=SaladAction.REALLOCATE_INSTANCE.value, target=target)
        try:
            first = ledger.reserve_live_early(key, SaladAction.REALLOCATE_INSTANCE.value, target, GENERATION, _utc(NOW))
            self.assertTrue(first["inserted"])
            ledger.transition(key, "SEND_STARTED", _utc(NOW))
            ledger.transition(key, "RECONCILIATION_REQUIRED", _utc(NOW + timedelta(seconds=1)))
            retry = ledger.reserve_live_early(key, SaladAction.REALLOCATE_INSTANCE.value, target, GENERATION, _utc(NOW + timedelta(seconds=2)))
            self.assertFalse(retry["inserted"])
            self.assertEqual(retry["blocker"], "EARLY_GENERATION_ALREADY_DISPATCHED")
            self.assertEqual(ledger.connection.execute("SELECT COUNT(*) FROM early_generation_dispatch_locks").fetchone()[0], 1)
        finally:
            ledger.close()

    def test_concurrent_same_generation_reservations_have_one_winner(self):
        with tempfile.TemporaryDirectory(prefix="scrum-175-race-") as temp:
            path = Path(temp) / "actions.sqlite3"
            ledgers = (ActionLedger(path), ActionLedger(path))
            target = {
                "organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer-2",
                "machine_id": MACHINE, "instance_id": INSTANCE, "assignment_id": ASSIGNMENT,
                "assignment_generation": GENERATION, "deterioration_id": "e" * 64,
            }
            key = ActionLedger.early_live_key_for(action=SaladAction.REALLOCATE_INSTANCE.value, target=target)
            barrier = threading.Barrier(3)

            def reserve(ledger):
                barrier.wait(timeout=3)
                return ledger.reserve_live_early(
                    key, SaladAction.REALLOCATE_INSTANCE.value, target, GENERATION, _utc(NOW),
                )

            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(reserve, ledgers[0])
                    second = pool.submit(reserve, ledgers[1])
                    barrier.wait(timeout=3)
                    results = (first.result(timeout=5), second.result(timeout=5))
                self.assertEqual(sum(result["inserted"] is True for result in results), 1)
                self.assertEqual(sum(result.get("blocker") == "EARLY_GENERATION_ALREADY_DISPATCHED" for result in results), 1)
                self.assertEqual(ledgers[0].connection.execute("SELECT COUNT(*) FROM early_generation_dispatch_locks").fetchone()[0], 1)
                self.assertEqual(len(ledgers[0].snapshot()), 1)
            finally:
                for ledger in ledgers:
                    ledger.close()

    def test_generation_lock_survives_terminal_state_target_changes_connections_and_restart(self):
        temp = tempfile.TemporaryDirectory(prefix="scrum-175-generation-lock-")
        path = Path(temp.name) / "actions.sqlite3"
        ledger_a = ActionLedger(path)
        ledger_b = ActionLedger(path)
        base = {
            "organization": "adrianfiverr", "project": "miners",
            "container_group": "fl4shminer-2", "machine_id": MACHINE,
            "instance_id": INSTANCE, "assignment_id": ASSIGNMENT,
            "assignment_generation": GENERATION, "deterioration_id": "e" * 64,
        }
        moved = dict(
            base,
            machine_id="machine-synthetic-175-replaced",
            instance_id=REPLACEMENT_INSTANCE,
            deterioration_id="f" * 64,
        )
        changed_deterioration = dict(moved, deterioration_id="a" * 64)
        action = SaladAction.REALLOCATE_INSTANCE.value
        first_key = ActionLedger.early_live_key_for(action=action, target=base)
        moved_key = ActionLedger.early_live_key_for(action=action, target=moved)
        final_key = ActionLedger.early_live_key_for(action=action, target=changed_deterioration)
        try:
            first = ledger_a.reserve_live_early(
                first_key, action, base, GENERATION, _utc(NOW),
            )
            self.assertTrue(first["inserted"])
            terminal = ledger_a.transition(first_key, "BLOCKED", _utc(NOW + timedelta(seconds=1)))
            self.assertEqual(terminal["state"], "BLOCKED")

            concurrent_retry = ledger_b.reserve_live_early(
                moved_key, action, moved, GENERATION, _utc(NOW + timedelta(seconds=2)),
            )
            self.assertFalse(concurrent_retry["inserted"])
            self.assertEqual(concurrent_retry["blocker"], "EARLY_GENERATION_ALREADY_DISPATCHED")
            self.assertIsNone(ledger_b.get(moved_key))
            self.assertEqual(ledger_b.connection.execute(
                "SELECT COUNT(*) FROM early_generation_dispatch_locks",
            ).fetchone()[0], 1)

            ledger_a.close()
            ledger_b.close()
            reopened = ActionLedger(path)
            try:
                after_restart = reopened.reserve_live_early(
                    final_key, action, changed_deterioration, GENERATION,
                    _utc(NOW + timedelta(seconds=3)),
                )
                self.assertFalse(after_restart["inserted"])
                self.assertEqual(after_restart["blocker"], "EARLY_GENERATION_ALREADY_DISPATCHED")
                self.assertEqual(reopened.connection.execute(
                    "SELECT COUNT(*) FROM early_generation_dispatch_locks",
                ).fetchone()[0], 1)
                self.assertEqual(len(reopened.snapshot()), 1)
            finally:
                reopened.close()
        finally:
            try:
                ledger_a.close()
            except Exception:
                pass
            try:
                ledger_b.close()
            except Exception:
                pass
            temp.cleanup()

    def test_legacy_machine_scoped_generation_lock_blocks_moved_target_after_upgrade(self):
        ledger = ActionLedger(":memory:")
        base = {
            "organization": "adrianfiverr", "project": "miners",
            "container_group": "fl4shminer-2", "machine_id": MACHINE,
            "instance_id": INSTANCE, "assignment_id": ASSIGNMENT,
            "assignment_generation": GENERATION, "deterioration_id": "e" * 64,
        }
        moved = dict(base, machine_id="machine-synthetic-175-moved", instance_id=REPLACEMENT_INSTANCE)
        action = SaladAction.REALLOCATE_INSTANCE.value
        key = ActionLedger.early_live_key_for(action=action, target=base)
        moved_key = ActionLedger.early_live_key_for(action=action, target=moved)
        try:
            first = ledger.reserve_live_early(key, action, base, GENERATION, _utc(NOW))
            self.assertTrue(first["inserted"])
            legacy_values = (
                base["organization"], base["project"], base["container_group"],
                base["machine_id"], base["assignment_id"], GENERATION,
            )
            legacy_scope = hashlib.sha256("\0".join(legacy_values).encode("utf-8")).hexdigest()
            ledger.connection.execute(
                "UPDATE early_generation_dispatch_locks SET generation_scope_sha256=? WHERE action_key=?",
                (legacy_scope, key),
            )
            ledger.connection.commit()

            moved_retry = ledger.reserve_live_early(
                moved_key, action, moved, GENERATION, _utc(NOW + timedelta(seconds=1)),
            )
            self.assertFalse(moved_retry["inserted"])
            self.assertEqual(moved_retry["blocker"], "EARLY_GENERATION_ALREADY_DISPATCHED")
            self.assertIsNone(ledger.get(moved_key))
            self.assertEqual(ledger.connection.execute(
                "SELECT COUNT(*) FROM early_generation_dispatch_locks",
            ).fetchone()[0], 1)
        finally:
            ledger.close()

    def test_replacement_reconciliation_is_generation_scoped_and_synthetic_stays_synthetic(self):
        result, ledger, _gate, executor, fake, _budget, _source, old_values, _temp = self._run_dispatch()
        try:
            observation = {
                "container_group": "fl4shminer-2",
                "data_classification": "SYNTHETIC/UNVERIFIED",
                "synthetic_fixture_id": FIXTURE,
                "source_provenance": {"system": "synthetic_test_fixture", "host": "loopback", "transport_tls_hostname_verified": False},
                "sanitized_observation_sha256": "a" * 64,
                "replacement_binding": {
                    "organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer-2",
                    "machine_id": "machine-synthetic-175-new", "instance_id": REPLACEMENT_INSTANCE,
                    "assignment_id": "assignment-synthetic-175-new",
                    "assignment_generation": "generation-synthetic-175-new",
                    "observed_at_utc": _utc(NOW + timedelta(seconds=10)),
                },
            }
            with patch.object(socket, "create_connection", side_effect=AssertionError("socket forbidden")):
                reconciled = executor.reconcile(
                    result.action_key, observation, at_utc=_utc(NOW + timedelta(seconds=11)),
                )
            self.assertEqual(reconciled.status, "RECONCILED_SYNTHETIC_SIMULATION")
            self.assertFalse(reconciled.actions_performed)
            entry = ledger.get(result.action_key)
            self.assertEqual(entry["state"], "RECONCILED_SYNTHETIC_SIMULATION")
            self.assertEqual(entry["receipt"]["reconciled_from"]["instance_id"], INSTANCE)
            self.assertEqual(entry["receipt"]["reconciled_to"]["instance_id"], REPLACEMENT_INSTANCE)
            self.assertEqual(entry["receipt"]["data_classification"], "SYNTHETIC/UNVERIFIED")
            self.assertNotEqual(entry["state"], "RECONCILED_OBSERVED_CHANGE")
        finally:
            ledger.close()
            _temp.cleanup()
            _restore_binding_globals(old_values)

    def test_new_assignment_generation_can_start_a_new_episode_after_reconciliation(self):
        (
            result, ledger, _gate, executor, _fake, _budget, _source,
            old_values, temp, old_proof, _old_revalidator,
        ) = self._run_dispatch(capture_proof=True)
        second_old_values = None
        try:
            replacement = {
                "container_group": "fl4shminer-2",
                "data_classification": "SYNTHETIC/UNVERIFIED",
                "synthetic_fixture_id": FIXTURE,
                "source_provenance": {"system": "synthetic_test_fixture", "host": "loopback", "transport_tls_hostname_verified": False},
                "sanitized_observation_sha256": "c" * 64,
                "replacement_binding": {
                    "organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer-2",
                    "machine_id": "machine-synthetic-175-new", "instance_id": REPLACEMENT_INSTANCE,
                    "assignment_id": "assignment-synthetic-175-new",
                    "assignment_generation": "generation-synthetic-175-new",
                    "observed_at_utc": _utc(NOW + timedelta(seconds=10)),
                },
            }
            reconciled = executor.reconcile(
                result.action_key, replacement, at_utc=_utc(NOW + timedelta(seconds=11)),
            )
            self.assertEqual(reconciled.status, "RECONCILED_SYNTHETIC_SIMULATION")
            new_assignment = "assignment-synthetic-175-new"
            new_generation = "generation-synthetic-175-new"
            new_instance = REPLACEMENT_INSTANCE
            new_machine = "machine-synthetic-175-new"
            new_source_hash = "d" * 64

            old_entry = ledger.get(result.action_key)
            self.assertEqual(old_entry["state"], "RECONCILED_SYNTHETIC_SIMULATION")
            self.assertEqual(old_entry["receipt"]["reconciled_from"]["assignment_generation"], GENERATION)
            self.assertEqual(old_entry["receipt"]["reconciled_to"]["assignment_generation"], new_generation)
            ledger.close()
            ledger = ActionLedger(Path(temp.name) / "actions.sqlite3")
            persisted = ledger.get(result.action_key)
            self.assertEqual(persisted["state"], "RECONCILED_SYNTHETIC_SIMULATION")
            self.assertEqual(persisted["receipt"]["reconciled_to"]["assignment_id"], new_assignment)

            replacement_snapshot, _trust = binding_fixtures._snapshot(
                instance_id=new_instance,
                machine_id=new_machine,
                assignment_id=new_assignment,
                assignment_generation=new_generation,
                observed_at_utc=NOW + timedelta(seconds=12),
            )
            replacement_source = binding_fixtures._source_with_snapshots(
                binding_fixtures.TARGET,
                ((replacement_snapshot,),),
            )
            replacement_revalidator = ProviderBindingRevalidator(
                allowlist=ExplicitBindingAllowlist((binding_fixtures.TARGET,)),
                source=replacement_source,
            )
            old_dispatcher, old_gate, _old_executor, old_fake, _old_budget = _dispatcher(
                ledger=ledger, revalidator=replacement_revalidator,
            )
            old_decision, old_source_evidence, old_policy, old_generation_data, old_budget_evidence, old_history = _evidence()
            with patch.object(old_gate, "assess_early", return_value=_eligible_admission()):
                stale_episode = old_dispatcher.dispatch(
                    old_decision, proof_handle=old_proof, source_evidence=old_source_evidence,
                    policy_evidence=old_policy, generation_evidence=old_generation_data,
                    budget_evidence=old_budget_evidence, allocation_history=old_history,
                    fleet_id="synthetic-fleet", now_utc=NOW + timedelta(seconds=12),
                )
            self.assertEqual(stale_episode.status, "BLOCKED")
            self.assertEqual(stale_episode.reason_code, "EARLY_PROVIDER_REVALIDATION_FAILED")
            self.assertEqual(old_fake.calls, [])
            self.assertEqual(len(ledger.snapshot()), 1)
            self.assertEqual(ledger.connection.execute(
                "SELECT COUNT(*) FROM early_generation_dispatch_locks",
            ).fetchone()[0], 1)

            proof, revalidator, _source, second_old_values = _proof_and_revalidator(
                assignment=new_assignment, generation=new_generation, instance=new_instance,
                machine=new_machine,
            )
            dispatcher, gate, _executor, fake, _budget_store = _dispatcher(
                ledger=ledger, revalidator=revalidator, assignment=new_assignment,
                generation=new_generation, instance=new_instance, machine=new_machine,
                source_hash=new_source_hash,
            )
            decision, source_evidence, policy, generation_data, budget, history = _evidence(
                assignment=new_assignment, generation=new_generation, source_hash=new_source_hash,
            )
            with patch.object(gate, "assess_early", return_value=_eligible_admission()):
                next_episode = dispatcher.dispatch(
                    decision, proof_handle=proof, source_evidence=source_evidence,
                    policy_evidence=policy, generation_evidence=generation_data,
                    budget_evidence=budget, allocation_history=history,
                    fleet_id="synthetic-fleet", now_utc=NOW,
                )
            self.assertEqual(next_episode.status, "ACCEPTED_PENDING", next_episode)
            self.assertEqual(len(fake.calls), 1)
            self.assertEqual(ledger.get(next_episode.action_key)["recommendation"]["target"]["assignment_generation"], new_generation)
            self.assertEqual(ledger.connection.execute("SELECT COUNT(*) FROM early_generation_dispatch_locks").fetchone()[0], 2)
        finally:
            try:
                ledger.close()
            except Exception:
                pass
            temp.cleanup()
            if second_old_values is not None:
                _restore_binding_globals(second_old_values)
            _restore_binding_globals(old_values)

    def test_reconciliation_rejects_old_or_wrong_scope_replacement(self):
        result, ledger, _gate, executor, _fake, _budget, _source, old_values, _temp = self._run_dispatch()
        try:
            invalid = {
                "container_group": "fl4shminer-2", "data_classification": "SYNTHETIC/UNVERIFIED",
                "synthetic_fixture_id": FIXTURE,
                "source_provenance": {"system": "synthetic_test_fixture", "host": "loopback", "transport_tls_hostname_verified": False},
                "sanitized_observation_sha256": "b" * 64,
                "replacement_binding": {
                    "organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer-3",
                    "machine_id": "machine-synthetic-175-new", "instance_id": REPLACEMENT_INSTANCE,
                    "assignment_id": "assignment-new", "assignment_generation": "generation-new",
                    "observed_at_utc": _utc(NOW + timedelta(seconds=10)),
                },
            }
            blocked = executor.reconcile(result.action_key, invalid, at_utc=_utc(NOW + timedelta(seconds=11)))
            self.assertEqual(blocked.status, "RECONCILIATION_REQUIRED")
            self.assertEqual(blocked.reason, "EARLY_REPLACEMENT_SCOPE_MISMATCH")
            self.assertEqual(ledger.get(result.action_key)["state"], "ACCEPTED_PENDING")
        finally:
            ledger.close()
            _temp.cleanup()
            _restore_binding_globals(old_values)

    def test_secret_material_never_enters_ledger_audit_result_or_transport_record(self):
        result, ledger, _gate, _executor, fake, budget_store, _source, old_values, _temp = self._run_dispatch()
        try:
            material = json.dumps({
                "result": repr(result), "ledger": ledger.snapshot(),
                "audit": budget_store.audit, "calls": fake.calls,
                "budget": budget_store.reservations,
            }, sort_keys=True, default=str)
            self.assertNotIn(SYNTHETIC_SECRET_VALUE, material)
            self.assertNotIn(SYNTHETIC_SECRET_VALUE, repr(result))
            self.assertEqual(fake.calls[0]["secret_type"], "SecretMaterial")
        finally:
            ledger.close()
            _temp.cleanup()
            _restore_binding_globals(old_values)


if __name__ == "__main__":
    unittest.main()
