from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid
from unittest.mock import patch

G4C_ROOT = Path(__file__).resolve().parents[2] / "g4c-live"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(G4C_ROOT))

from collector.action_ledger import ActionLedger
from collector.gpu_identity import normalize_gpu_identity
from collector.reallocation_controller import ReallocationController, ReallocationPolicy
from collector.salad_action_policy import (
    ActionCapabilityVerifier,
    DossierRejected,
    DecisionDossierAuthority,
    SaladAction,
    SaladActionPolicy,
    SignedActionCapability,
)
from collector.salad_action_transport import (
    ActionTransportBlocked,
    RestrictedSaladActionHTTPTransport,
    SaladActionExecutor,
    fixed_action_path,
)
from live_secret_boundary import SYNTHETIC_SECRET_VALUE, SyntheticSecretProvider
from g5_control_plane.app import build_service
from g5_control_plane.config import G5Config
from g5_control_plane.store import ControlPlaneStore


NOW = 1_000.0
TARGET_GROUP = {"organization": "adrianfiverr", "project": "miners", "container_group": "fl4shminer"}
TARGET_INSTANCE = {**TARGET_GROUP, "instance_id": "12345678-1234-5678-1234-567812345678", "assignment_id": "assignment-1", "deterioration_id": "low-window-start"}


class DummySwitch:
    def __init__(self, enabled: bool):
        self.enabled = enabled


class FakeActionTransport:
    synthetic_test_only = True

    def __init__(self, *, status=202, fail=False, capability=None, verifier=None):
        self.status = status
        self.fail = fail
        self.capability = capability
        self.verifier = verifier
        self.calls = []

    def action_capability_nonce(self, action, target, route, *, now_epoch):
        if self.capability is None or self.verifier is None:
            return None
        return self.verifier.verified_nonce(
            self.capability, action=action, target=target, route=route, now_epoch=now_epoch,
        )

    def submit_bound(self, action, target, secret, *, action_key, authorization_nonce, nonce_ledger):
        if not nonce_ledger.claim_signed_action_dispatch(
            authorization_nonce, action_key, _utc(time.time()),
        ):
            raise RuntimeError("synthetic fake refused replayed or unbound action nonce")
        self.calls.append((action, dict(target), secret._header_value()))
        if self.fail:
            raise TimeoutError("synthetic uncertain response")
        return {
            "http_status_code": self.status,
            "actions_performed": False,
            "response_body": None,
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
        }


def verified_budget(spend=1.0, cost=0.25):
    return {
        "status": "VERIFIED", "currency": "USD", "verified_spend_usd": spend,
        "verified_next_action_cost_usd": cost, "spend_evidence_id": "synthetic-invoice",
        "spend_source_reference": "synthetic-test-only", "action_cost_evidence_id": "synthetic-price",
        "action_cost_source_reference": "synthetic-test-only", "valid_until_epoch": 2000.0,
        "spend_observed_at_epoch": 900.0, "action_cost_observed_at_epoch": 950.0,
    }


SYNTHETIC_ACTION_FIXTURE = "G5-SYNTHETIC-ACTION-PATH"
SYNTHETIC_POLICY_HASH = "synthetic-guard-policy-sha256"


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _arm_simulation_ledger(ledger: ActionLedger, at_utc: str) -> None:
    ledger.update_auto_reallocation_simulation_control(
        armed=True, event_type="SIMULATION_ARMED", kill_switch_engaged=False,
        live_actions_enabled=False, g5_authorized=False, at_utc=at_utc,
        limits={"max_per_minute": 4, "max_per_day": 12, "cooldown_seconds": 0,
                "max_per_assignment": 2, "max_per_fleet": 4},
    )


class SyntheticActionEvidenceVerifier:
    """Test-only verifier; it accepts only the named synthetic fixture family."""

    synthetic_test_only = True

    @staticmethod
    def _tagged(value):
        return isinstance(value, dict) and value.get("synthetic_fixture_id") == SYNTHETIC_ACTION_FIXTURE

    def verify_controller_assessment(self, value):
        provenance = value.get("provenance", {}) if isinstance(value, dict) else {}
        candidate = provenance.get("candidate", {}) if isinstance(provenance, dict) else {}
        return (
            isinstance(value, dict) and value.get("eligibility") == "CANDIDATE"
            and isinstance(candidate, dict) and candidate.get("source") == "synthetic_test_fixture"
        )

    def verify_binding(self, value): return self._tagged(value)
    def verify_provider(self, value): return self._tagged(value)
    def verify_telemetry(self, value): return self._tagged(value)
    def verify_low_evaluations(self, value): return isinstance(value, list) and len(value) == 2 and all(self._tagged(row) for row in value)
    def verify_allocation_history(self, value): return self._tagged(value)
    def verify_budget(self, value): return self._tagged(value)


class SyntheticReconciliationVerifier:
    synthetic_test_only = True

    def verify_action_outcome(self, entry, observation):
        return (
            observation.get("synthetic_fixture_id") == SYNTHETIC_ACTION_FIXTURE
            and observation.get("data_classification") == "SYNTHETIC/UNVERIFIED"
            and entry.get("state") == "ACCEPTED_PENDING"
        )


def _signed_test_capability(action, target, now_epoch, *, nonce=None):
    import json
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    route = fixed_action_path(action, target)
    claims = {
        "schema_version": 1, "audience": "salad-g5-control-plane", "host": "api.salad.com",
        "organization": "adrianfiverr", "project": "miners", "container_group": target["container_group"],
        "action": action.value, "path": route, "issued_at_epoch": now_epoch - 1,
        "expires_at_epoch": now_epoch + 60, "nonce": nonce or str(uuid.uuid4()), "max_requests": 1,
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return SignedActionCapability(payload, private_key.sign(payload)), ActionCapabilityVerifier(public_key)


def _seed_synthetic_budget_store(store, budget, *, spend_amount="1.00", cost_amount="0.10"):
    store.record_budget_evidence(
        evidence_id=budget["spend_evidence_id"], source_reference=budget["spend_source_reference"],
        occurred_at_utc=budget["spend_observed_at_utc"], currency="USD", amount_usd=spend_amount,
        verification_status="VERIFIED", source="trusted_backend_import",
    )
    store.record_action_cost_evidence(
        evidence_id=budget["action_cost_evidence_id"], source_reference=budget["action_cost_source_reference"],
        currency="USD", amount_usd=cost_amount,
        observed_at_utc=budget["action_cost_observed_at_utc"], valid_until_utc=budget["valid_until_utc"],
        verification_status="VERIFIED", source="trusted_backend_import",
    )


def _valid_synthetic_reallocation_context(now_epoch: float, *, controller: ReallocationController | None = None):
    """Compose the real G2 controller with evidence explicitly labeled synthetic."""
    identity = normalize_gpu_identity(
        "NVIDIA GeForce RTX 5090 Laptop GPU",
        identity_source="salad_json_log_gpu_class_name", identity_verified=True,
    )
    deterioration_id = _utc(now_epoch - 60)
    instance_id = TARGET_INSTANCE["instance_id"]
    assignment_id = TARGET_INSTANCE["assignment_id"]
    target_fields = {
        "organization_id": "adrianfiverr", "project_id": "miners", "container_group_id": "fl4shminer",
        "instance_id": instance_id, "machine_id": "machine-synthetic", "allocation_id": "allocation-synthetic",
        "assignment_id": assignment_id,
    }
    required_evidence = {
        "track_id": "track-synthetic", "allocation_id": "allocation-synthetic",
        "assignment_id": assignment_id, "device_namespace": "fl4shminer_device", "device_id": "0",
    }
    allow = {
        **target_fields, "gpu_model": "RTX 5090", "form_factor": "laptop",
        "identity_source": "salad_json_log_gpu_class_name",
    }
    controller_policy = ReallocationPolicy(
        allowed_targets=(allow,),
        gpu_floors_ths={"RTX 5090|laptop|salad_json_log_gpu_class_name": 120},
        maximum_telemetry_age_seconds=30, minimum_window_coverage_ratio=0.8,
        maximum_sample_gap_seconds=30, evaluation_max_age_seconds=90,
        cooldown_seconds=300, maximum_per_assignment=2, maximum_per_fleet=5,
        budget_limit_usd=30,
    )
    candidate = {
        **target_fields, "fleet_id": "fleet-synthetic", **required_evidence,
        "track_active": True, "guard_policy_hash": SYNTHETIC_POLICY_HASH,
        "gpu_identity": dict(identity), "gpu_floor_ths": 120,
        "deterioration_start_utc": deterioration_id,
        "provenance": {"source": "synthetic_test_fixture", "data_classification": "SYNTHETIC/UNVERIFIED"},
    }
    provider_binding = {
        **target_fields, **required_evidence, "gpu_identity": dict(identity),
        "guard_policy_hash": SYNTHETIC_POLICY_HASH,
    }
    provider_for_controller = {
        **target_fields, "reported_state": "running", "occurred_at_utc": _utc(now_epoch - 2),
        "allocation_id": target_fields["allocation_id"], "assignment_id": assignment_id,
        "target_binding": provider_binding,
        "provenance": {"source": "synthetic_test_fixture", "data_classification": "SYNTHETIC/UNVERIFIED"},
    }
    sample_for_controller = {
        "event_id": "synthetic-sample-latest", "occurred_at_utc": _utc(now_epoch - 1),
        "machine_id": target_fields["machine_id"], "instance_id": instance_id,
        **required_evidence, "hashrate_ths": 90,
        "hashrate_semantics": "fl4shminer_device_reported", "hashrate_source": "synthetic fixture only",
        "gpu_identity": dict(identity), "monitor_policy_hash": SYNTHETIC_POLICY_HASH,
        "provenance": {"source": "synthetic_test_fixture", "data_classification": "SYNTHETIC/UNVERIFIED"},
    }
    evaluations = []
    for index, offset in enumerate((20, 10), start=1):
        evaluations.append({
            "evaluation_id": f"synthetic-eval-{index}", "evaluated_at_utc": _utc(now_epoch - offset),
            "policy_hash": SYNTHETIC_POLICY_HASH, "deterioration_start_utc": deterioration_id,
            "decision": "WOULD_REALLOCATE", "hash_health": "BELOW_CONFIGURED_FLOOR",
            **required_evidence, "track_active": True,
            "machine_id": target_fields["machine_id"], "instance_id": instance_id,
            "gpu_identity": dict(identity), "gpu_floor_ths": 120,
            "observed_window_hashrate_ths": 90,
            "sample_quality": {"coverage_ratio": 0.95, "maximum_observed_gap_seconds": 10, "sample_count": 12},
        })
    history = {
        "history_known": True, "allocation_reallocation_count": 0, "fleet_reallocation_count": 0,
        "cooldown_seconds": 300, "last_reallocation_at_utc": None, "last_reallocation_epoch": None,
        "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
    }
    now_text = _utc(now_epoch)
    budget = {
        "status": "VERIFIED", "currency": "USD", "verified_spend_usd": 1.0,
        "spend_evidence_id": "synthetic-spend-evidence", "spend_source_reference": "synthetic-spend-source",
        "spend_observed_at_utc": _utc(now_epoch - 10), "spend_observed_at_epoch": now_epoch - 10,
        "verified_next_action_cost_usd": 0.10, "action_cost_evidence_id": "synthetic-action-cost",
        "action_cost_source_reference": "synthetic-action-cost-source",
        "action_cost_observed_at_utc": _utc(now_epoch - 5), "action_cost_observed_at_epoch": now_epoch - 5,
        "next_action_cost_evidence_id": "synthetic-action-cost",
        "next_action_cost_source_reference": "synthetic-action-cost-source",
        "next_action_cost_observed_at_utc": _utc(now_epoch - 5),
        "valid_until_utc": _utc(now_epoch + 600), "valid_until_epoch": now_epoch + 600,
        "pending_exposure_usd": 0.0, "pending_exposure_status": "VERIFIED",
        "pending_exposure_evidence_id": "synthetic-pending-ledger",
        "maximum_exposure_usd": 1.10, "maximum_exposure_status": "VERIFIED",
        "maximum_exposure_evidence_id": "synthetic-maximum-ledger",
        "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
    }
    owns_controller = controller is None
    if controller is None:
        controller = ReallocationController(
            controller_policy, ActionLedger(":memory:"), guard_policy_hash=SYNTHETIC_POLICY_HASH,
        )
    else:
        # Exercise the controller already composed by build_service; these
        # permissive inputs exist only within this synthetic unit test.
        controller.policy = controller_policy
        controller.guard_policy_hash = SYNTHETIC_POLICY_HASH
    inputs = {
        "candidate": candidate, "evaluations": evaluations,
        "provider_revalidation": provider_for_controller,
        "revalidated_sample": sample_for_controller,
        "allocation_history": history, "budget": budget,
        "now_utc": now_text,
    }
    assessment = controller.preview(**inputs)
    if assessment["eligibility"] != "CANDIDATE":
        if owns_controller:
            controller.ledger.close()
        raise AssertionError(f"synthetic controller fixture unexpectedly blocked: {assessment['blockers']}")
    evidence = {
        "binding_evidence": {
            "provider": {**target_fields, "container_group": "fl4shminer"},
            "assignment": {**target_fields, "container_group": "fl4shminer"},
            "miner": {"track_id": "track-synthetic", "device_namespace": "fl4shminer_device", "device_id": "0"},
            "binding_status": "SYNTHETIC/UNVERIFIED", "actions_authorized_by_binding": False,
            "attestation_evidence_id": "synthetic-attestation-only",
            "data_classification": "SYNTHETIC/UNVERIFIED", "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
        },
        "provider_revalidation": {
            "organization_id": "adrianfiverr", "project_id": "miners", "container_group_id": "fl4shminer",
            "instance_id": instance_id, "assignment_id": assignment_id, "reported_state": "running",
            "allocation_id": target_fields["allocation_id"],
            "machine_id": target_fields["machine_id"],
            "data_classification": "SYNTHETIC/UNVERIFIED",
            "source_provenance": {"system": "synthetic_test_fixture", "host": "loopback", "transport_tls_hostname_verified": False},
            "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
        },
        "telemetry_sample": {
            "track_id": "track-synthetic", "device_namespace": "fl4shminer_device", "device_id": "0",
            "instance_id": instance_id, "assignment_id": assignment_id,
            "hashrate_semantics": "fl4shminer_device_reported",
            "data_classification": "SYNTHETIC/UNVERIFIED", "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
        },
        "low_evaluations": [
            {
                "evaluation_id": f"synthetic-eval-{index}", "evaluated_at_epoch": now_epoch - offset,
                "decision": "WOULD_REALLOCATE", "hash_health": "BELOW_CONFIGURED_FLOOR",
                "guard_policy_hash": SYNTHETIC_POLICY_HASH, "instance_id": instance_id,
                "assignment_id": assignment_id, "gpu_floor_ths": 120,
                "observed_window_hashrate_ths": 90, "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
            }
            for index, offset in ((1, 20), (2, 10))
        ],
    }
    action_target = {**TARGET_INSTANCE, "deterioration_id": deterioration_id}
    return controller, assessment, inputs, evidence, budget, action_target


class SaladActionTransportTests(unittest.TestCase):
    def test_fixed_group_and_instance_routes_match_official_contract_shapes(self):
        self.assertEqual(
            fixed_action_path(SaladAction.START_GROUP, TARGET_GROUP),
            "/api/public/organizations/adrianfiverr/projects/miners/containers/fl4shminer/start",
        )
        self.assertEqual(
            fixed_action_path(SaladAction.STOP_GROUP, TARGET_GROUP),
            "/api/public/organizations/adrianfiverr/projects/miners/containers/fl4shminer/stop",
        )
        self.assertEqual(
            fixed_action_path(SaladAction.REALLOCATE_INSTANCE, TARGET_INSTANCE),
            "/api/public/organizations/adrianfiverr/projects/miners/containers/fl4shminer/instances/12345678-1234-5678-1234-567812345678/reallocate",
        )

    def test_paths_reject_caller_controlled_scope_or_group_instance_mixup(self):
        for action, target in (
            (SaladAction.START_GROUP, {**TARGET_GROUP, "instance_id": "instance-1"}),
            (SaladAction.STOP_GROUP, {**TARGET_GROUP, "container_group": "attacker"}),
            (SaladAction.REALLOCATE_INSTANCE, {**TARGET_GROUP, "instance_id": "../bad"}),
            (SaladAction.START_GROUP, {key: value for key, value in TARGET_GROUP.items() if key != "organization"}),
        ):
            with self.subTest(action=action):
                with self.assertRaises(ValueError):
                    fixed_action_path(action, target)

    def test_policy_rejects_wrong_organization_and_unbound_reallocation_identity(self):
        policy = SaladActionPolicy(live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True)
        common = {
            "decision_dossier": None,
            "dossier_authority": DecisionDossierAuthority(),
            "kill_switch_clear": True, "now_epoch": NOW,
        }
        wrong_scope = policy.evaluate(
            SaladAction.START_GROUP, target={**TARGET_GROUP, "organization": "other"},
            **common,
        )
        self.assertIn("TARGET_ORGANIZATION_OR_PROJECT_NOT_ALLOWLISTED", wrong_scope.blockers)
        incomplete = policy.evaluate(
            SaladAction.REALLOCATE_INSTANCE,
            target={**TARGET_INSTANCE, "assignment_id": None, "deterioration_id": None},
            **common,
        )
        self.assertIn("ASSIGNMENT_ID_UNKNOWN", incomplete.blockers)
        self.assertIn("DETERIORATION_ID_UNKNOWN", incomplete.blockers)
        self.assertIn("BACKEND_DECISION_DOSSIER_REQUIRED", incomplete.blockers)

    def test_http_post_transport_is_disabled_before_dns_and_socket(self):
        transport = RestrictedSaladActionHTTPTransport()
        secret = SyntheticSecretProvider().acquire()
        with patch("collector.salad_action_transport.socket.create_connection") as connect, patch(
            "collector.salad_action_transport.socket.getaddrinfo"
        ) as resolve:
            with self.assertRaises(ActionTransportBlocked):
                transport.submit(SaladAction.START_GROUP, TARGET_GROUP, secret)
        connect.assert_not_called()
        resolve.assert_not_called()

    def test_enabled_production_post_requires_externally_signed_capability_before_dns(self):
        transport = RestrictedSaladActionHTTPTransport(enabled=True)
        secret = SyntheticSecretProvider().acquire()
        with patch("collector.salad_action_transport.socket.create_connection") as connect, patch(
            "collector.salad_action_transport.socket.getaddrinfo"
        ) as resolve, patch("collector.salad_action_transport.http.client.HTTPSConnection") as https:
            with self.assertRaises(ActionTransportBlocked):
                transport.submit(SaladAction.START_GROUP, TARGET_GROUP, secret)
        connect.assert_not_called()
        resolve.assert_not_called()
        https.assert_not_called()

    def test_signed_action_capability_is_bound_to_exact_action_route_and_expiry(self):
        import json
        import uuid
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        route = fixed_action_path(SaladAction.START_GROUP, TARGET_GROUP)
        claims = {
            "schema_version": 1,
            "audience": "salad-g5-control-plane",
            "host": "api.salad.com",
            "organization": "adrianfiverr",
            "project": "miners",
            "container_group": "fl4shminer",
            "action": SaladAction.START_GROUP.value,
            "path": route,
            "issued_at_epoch": 1000,
            "expires_at_epoch": 1050,
            "nonce": str(uuid.uuid4()),
            "max_requests": 1,
        }
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        capability = SignedActionCapability(payload, private_key.sign(payload))
        verifier = ActionCapabilityVerifier(public_key)
        self.assertTrue(verifier.verify(capability, action=SaladAction.START_GROUP, target=TARGET_GROUP, route=route, now_epoch=1025))
        self.assertFalse(verifier.verify(capability, action=SaladAction.STOP_GROUP, target=TARGET_GROUP, route=route, now_epoch=1025))
        self.assertFalse(verifier.verify(capability, action=SaladAction.START_GROUP, target=TARGET_GROUP, route=route, now_epoch=1050))

    def test_default_policy_blocks_start_stop_manual_and_auto_without_side_effects(self):
        ledger = ActionLedger(":memory:")
        fake = FakeActionTransport()
        executor = SaladActionExecutor(
            policy=SaladActionPolicy(), ledger=ledger, transport=fake,
            secret_provider=SyntheticSecretProvider(), kill_switch=DummySwitch(True), clock=lambda: NOW,
        )
        try:
            for action, target in ((SaladAction.START_GROUP, TARGET_GROUP), (SaladAction.STOP_GROUP, TARGET_GROUP), (SaladAction.REALLOCATE_INSTANCE, TARGET_INSTANCE)):
                result = executor.execute(
                    action, target, decision_dossier=None,
                )
                self.assertEqual(result.status, "BLOCKED")
                self.assertFalse(result.actions_performed)
            self.assertEqual(fake.calls, [])
            self.assertEqual(ledger.snapshot(), [])
        finally:
            ledger.close()

    def test_fabricated_booleans_and_budget_cannot_replace_backend_dossier(self):
        ledger = ActionLedger(":memory:")
        fake = FakeActionTransport(status=202)
        policy = SaladActionPolicy(
            live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True,
        )
        executor = SaladActionExecutor(
            policy=policy, ledger=ledger, transport=fake,
            secret_provider=SyntheticSecretProvider(), kill_switch=DummySwitch(True), clock=lambda: NOW,
        )
        try:
            result = executor.execute(
                SaladAction.REALLOCATE_INSTANCE, TARGET_INSTANCE,
                decision_dossier=None,
            )
            self.assertEqual(result.status, "BLOCKED")
            self.assertIn("BACKEND_DECISION_DOSSIER_REQUIRED", result.reason)
            self.assertIn("BUDGET_UNVERIFIABLE", result.reason)
            self.assertFalse(result.actions_performed)
            self.assertFalse(result.request_submitted)
            self.assertEqual(ledger.get(result.action_key), None)
            self.assertEqual(fake.calls, [])
        finally:
            ledger.close()

    def test_fabricated_binding_and_budget_mappings_cannot_mint_backend_dossier(self):
        authority = DecisionDossierAuthority()
        fabricated = {
            "binding_status": "VERIFIED",
            "actions_authorized_by_binding": True,
            "attestation_evidence_id": "synthetic-id-match-only",
            "data_classification": "INDEPENDENT_BINDING_ATTESTATION",
        }
        with self.assertRaisesRegex(DossierRejected, "INDEPENDENT_ACTION_EVIDENCE_VERIFIER_NOT_CONFIGURED"):
            authority.issue_reallocation(
                action=SaladAction.REALLOCATE_INSTANCE,
                target=TARGET_INSTANCE,
                controller_assessment={"eligibility": "CANDIDATE"},
                binding_evidence=fabricated,
                provider_revalidation={"data_classification": "PROVIDER_OBSERVED"},
                telemetry_sample={"data_classification": "INDEPENDENT_WORKLOAD_EVIDENCE"},
                low_evaluations=[],
                allocation_history={"history_known": True},
                budget_evidence={"status": "VERIFIED", "maximum_exposure_usd": 0.01},
                reservation_snapshot=[],
                hard_budget_usd=30.0,
                now_epoch=NOW,
            )

        class RejectBindingEvidence:
            def verify_controller_assessment(self, _value): return True
            def verify_binding(self, _value): return False
            def verify_provider(self, _value): return True
            def verify_telemetry(self, _value): return True
            def verify_low_evaluations(self, _value): return True
            def verify_allocation_history(self, _value): return True
            def verify_budget(self, _value): return True

        verifier_authority = DecisionDossierAuthority(action_evidence_verifier=RejectBindingEvidence())
        with self.assertRaisesRegex(DossierRejected, "independent action evidence verification failed"):
            verifier_authority.issue_reallocation(
                action=SaladAction.REALLOCATE_INSTANCE,
                target=TARGET_INSTANCE,
                controller_assessment={"eligibility": "CANDIDATE"},
                binding_evidence=fabricated,
                provider_revalidation={"data_classification": "PROVIDER_OBSERVED"},
                telemetry_sample={"data_classification": "INDEPENDENT_WORKLOAD_EVIDENCE"},
                low_evaluations=[],
                allocation_history={"history_known": True},
                budget_evidence={"status": "VERIFIED", "maximum_exposure_usd": 0.01},
                reservation_snapshot=[],
                hard_budget_usd=30.0,
                now_epoch=NOW,
            )

    def test_synthetic_controller_dossier_dispatch_202_and_reconciliation_path(self):
        now = time.time()
        temp_dir = tempfile.TemporaryDirectory(prefix="g5-app-action-integration-")
        service = build_service(G5Config(state_dir=temp_dir.name))
        controller, assessment, controller_inputs, evidence, budget, target = _valid_synthetic_reallocation_context(
            now, controller=service.reallocation_controller,
        )
        authority = DecisionDossierAuthority(action_evidence_verifier=SyntheticActionEvidenceVerifier())
        ledger = service.action_ledger
        budget_store = service.store
        secret_provider = SyntheticSecretProvider()
        reservation_order = []

        class ObservedBudgetStore:
            def reserve_budget_exposure(self, **kwargs):
                reservation_order.append((kwargs["action_key"], ledger.get(kwargs["action_key"])["state"]))
                return budget_store.reserve_budget_exposure(**kwargs)

            def reconcile_budget_exposure(self, *args, **kwargs):
                return budget_store.reconcile_budget_exposure(*args, **kwargs)

            def append_audit(self, *args, **kwargs):
                return budget_store.append_audit(*args, **kwargs)

        try:
            _seed_synthetic_budget_store(budget_store, budget)
            dossier = authority.issue_reallocation(
                action=SaladAction.REALLOCATE_INSTANCE, target=target,
                controller_assessment=assessment, binding_evidence=evidence["binding_evidence"],
                provider_revalidation=evidence["provider_revalidation"],
                telemetry_sample=evidence["telemetry_sample"], low_evaluations=evidence["low_evaluations"],
                allocation_history=controller_inputs["allocation_history"], budget_evidence=budget,
                reservation_snapshot=ledger.snapshot(), hard_budget_usd=30.0, now_epoch=now,
            )
            capability, verifier = _signed_test_capability(SaladAction.REALLOCATE_INSTANCE, target, now)
            fake = FakeActionTransport(capability=capability, verifier=verifier)
            executor = SaladActionExecutor(
                policy=SaladActionPolicy(live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True),
                ledger=ledger, transport=fake, secret_provider=secret_provider,
                kill_switch=DummySwitch(True), clock=lambda: now, reconciliation_verifier=SyntheticReconciliationVerifier(),
                dossier_authority=authority, budget_store=ObservedBudgetStore(),
            )
            # The browser-facing action route remains disabled on this service
            # even while the test substitutes a synthetic-only sender. The
            # backend test then exercises the same service-owned controller,
            # action ledger, budget store, and audit sink end to end.
            service.action_executor = executor
            api_block = service.request_action(
                "REALLOCATE_INSTANCE",
                {"container_group": "fl4shminer", "instance_id": target["instance_id"],
                 "assignment_id": target["assignment_id"], "deterioration_id": target["deterioration_id"]},
            )
            self.assertEqual(api_block["status"], "BLOCKED")
            self.assertFalse(api_block["actions_performed"])
            self.assertEqual(fake.calls, [])
            accepted = service.action_executor.execute(
                SaladAction.REALLOCATE_INSTANCE, target, decision_dossier=dossier,
            )
            self.assertEqual(accepted.status, "ACCEPTED_PENDING")
            self.assertFalse(accepted.actions_performed)
            self.assertFalse(accepted.request_submitted)
            self.assertEqual(accepted.data_classification, "SYNTHETIC/UNVERIFIED")
            self.assertEqual(accepted.synthetic_fixture_id, SYNTHETIC_ACTION_FIXTURE)
            self.assertEqual(reservation_order, [(accepted.action_key, "RESERVED")])
            exposure = budget_store._db.execute(
                "SELECT action_key, status FROM budget_exposures",
            ).fetchone()
            self.assertEqual((exposure["action_key"], exposure["status"]), (accepted.action_key, "PENDING"))
            self.assertEqual(ledger.get(accepted.action_key)["state"], "ACCEPTED_PENDING")
            self.assertEqual(len(fake.calls), 1)
            self.assertEqual(secret_provider.read_count, 1)
            nonce = fake.action_capability_nonce(
                SaladAction.REALLOCATE_INSTANCE, target,
                fixed_action_path(SaladAction.REALLOCATE_INSTANCE, target), now_epoch=now,
            )
            self.assertFalse(ledger.claim_signed_action_dispatch(nonce, accepted.action_key, _utc(now + 2)))
            self.assertEqual(budget_store.budget_summary()["pending_exposure_usd"], 0.10)
            pending_entry = ledger.get(accepted.action_key)
            self.assertEqual(pending_entry["receipt"]["data_classification"], "SYNTHETIC/UNVERIFIED")
            self.assertFalse(pending_entry["receipt"]["request_submitted"])
            with self.assertRaisesRegex(ValueError, "synthetic action history cannot become"):
                ledger.transition(
                    accepted.action_key, "RECONCILED_OBSERVED_CHANGE", _utc(now + 1),
                    {"evidence_id": "a" * 64, "result": "provider_observed"},
                )
            provider_observation_cannot_upgrade_fixture = {
                "container_group": "fl4shminer", "data_classification": "PROVIDER_OBSERVED",
                "source_provenance": {
                    "system": "salad_api", "host": "api.salad.com",
                    "transport_tls_hostname_verified": True,
                },
                "sanitized_observation_sha256": "b" * 64,
            }
            provider_reconcile = executor.reconcile(
                accepted.action_key, provider_observation_cannot_upgrade_fixture,
                at_utc=_utc(now + 1),
            )
            self.assertEqual(provider_reconcile.status, "RECONCILIATION_REQUIRED")
            self.assertEqual(ledger.get(accepted.action_key)["state"], "ACCEPTED_PENDING")

            synthetic_observation = {
                "container_group": "fl4shminer", "data_classification": "SYNTHETIC/UNVERIFIED",
                "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
                "source_provenance": {
                    "system": "synthetic_test_fixture", "host": "loopback",
                    "transport_tls_hostname_verified": False,
                },
                "sanitized_observation_sha256": "a" * 64,
            }
            reconciled = executor.reconcile(
                accepted.action_key, synthetic_observation, at_utc=_utc(now + 1),
            )
            self.assertEqual(reconciled.status, "RECONCILED_SYNTHETIC_SIMULATION")
            self.assertFalse(reconciled.actions_performed)
            self.assertFalse(reconciled.request_submitted)
            self.assertEqual(reconciled.data_classification, "SYNTHETIC/UNVERIFIED")
            terminal = ledger.get(accepted.action_key)
            self.assertEqual(terminal["state"], "RECONCILED_SYNTHETIC_SIMULATION")
            self.assertEqual(terminal["receipt"]["data_classification"], "SYNTHETIC/UNVERIFIED")
            self.assertFalse(terminal["receipt"]["actions_performed"])
            self.assertFalse(terminal["receipt"]["request_submitted"])
            # Synthetic reconciliation leaves exposure pending; it cannot confirm
            # provider state or release capacity from the hard budget.
            self.assertEqual(budget_store.budget_summary()["pending_exposure_usd"], 0.10)
            event_types = {row["event_type"] for row in budget_store.audit()}
            self.assertTrue({
                "ACTION_DISPATCH_PREPARED", "ACTION_SEND_STARTED_SYNTHETIC_SIMULATION",
                "ACTION_ACCEPTED_PENDING_SYNTHETIC_SIMULATION", "ACTION_RECONCILED_SYNTHETIC_SIMULATION",
            }.issubset(event_types))
            self.assertNotIn("ACTION_RECONCILED_OBSERVED_CHANGE", event_types)
            self.assertEqual(service.audit()["actions"][0]["state"], "RECONCILED_SYNTHETIC_SIMULATION")
        finally:
            service.close()
            temp_dir.cleanup()

    def test_synthetic_action_path_missing_one_binding_fact_is_rejected(self):
        now = time.time()
        controller, assessment, controller_inputs, evidence, budget, target = _valid_synthetic_reallocation_context(now)
        evidence["binding_evidence"]["miner"].pop("device_namespace")
        authority = DecisionDossierAuthority(action_evidence_verifier=SyntheticActionEvidenceVerifier())
        with self.assertRaisesRegex(DossierRejected, "device telemetry does not match"):
            authority.issue_reallocation(
                action=SaladAction.REALLOCATE_INSTANCE, target=target,
                controller_assessment=assessment, binding_evidence=evidence["binding_evidence"],
                provider_revalidation=evidence["provider_revalidation"],
                telemetry_sample=evidence["telemetry_sample"], low_evaluations=evidence["low_evaluations"],
                allocation_history=controller_inputs["allocation_history"], budget_evidence=budget,
                reservation_snapshot=[], hard_budget_usd=30.0, now_epoch=now,
            )
        controller.ledger.close()

    def test_dispatch_budget_reservation_failure_blocks_before_secret_and_post(self):
        now = time.time()
        controller, assessment, controller_inputs, evidence, budget, target = _valid_synthetic_reallocation_context(now)
        authority = DecisionDossierAuthority(action_evidence_verifier=SyntheticActionEvidenceVerifier())
        ledger = ActionLedger(":memory:")
        budget_store = ControlPlaneStore(":memory:")
        secret_provider = SyntheticSecretProvider()
        try:
            # The dossier sees an earlier synthetic amount; dispatch rechecks the
            # durable current spend and catches that the USD 30 cap is now crossed.
            _seed_synthetic_budget_store(budget_store, budget, spend_amount="29.95")
            dossier = authority.issue_reallocation(
                action=SaladAction.REALLOCATE_INSTANCE, target=target,
                controller_assessment=assessment, binding_evidence=evidence["binding_evidence"],
                provider_revalidation=evidence["provider_revalidation"],
                telemetry_sample=evidence["telemetry_sample"], low_evaluations=evidence["low_evaluations"],
                allocation_history=controller_inputs["allocation_history"], budget_evidence=budget,
                reservation_snapshot=[], hard_budget_usd=30.0, now_epoch=now,
            )
            capability, verifier = _signed_test_capability(SaladAction.REALLOCATE_INSTANCE, target, now)
            fake = FakeActionTransport(capability=capability, verifier=verifier)
            executor = SaladActionExecutor(
                policy=SaladActionPolicy(live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True),
                ledger=ledger, transport=fake, secret_provider=secret_provider,
                kill_switch=DummySwitch(True), clock=lambda: now,
                dossier_authority=authority, budget_store=budget_store,
            )
            result = executor.execute(SaladAction.REALLOCATE_INSTANCE, target, decision_dossier=dossier)
            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(result.reason, "DURABLE_BUDGET_RESERVATION_FAILED")
            self.assertEqual(ledger.get(result.action_key)["state"], "BLOCKED")
            self.assertEqual(secret_provider.read_count, 0)
            self.assertEqual(fake.calls, [])
            self.assertEqual(budget_store.budget_summary()["pending_exposure_usd"], 0.0)
        finally:
            controller.ledger.close()
            ledger.close()
            budget_store.close()

    def test_signed_capability_nonce_replay_is_rejected_after_ledger_restart(self):
        now = time.time()
        capability, verifier = _signed_test_capability(SaladAction.START_GROUP, TARGET_GROUP, now)
        nonce = verifier.verified_nonce(
            capability, action=SaladAction.START_GROUP, target=TARGET_GROUP,
            route=fixed_action_path(SaladAction.START_GROUP, TARGET_GROUP), now_epoch=now,
        )
        self.assertIsInstance(nonce, str)
        with tempfile.TemporaryDirectory(prefix="g5-capability-nonce-") as temp:
            path = Path(temp) / "actions.sqlite3"
            first = ActionLedger(path)
            key_one = "synthetic-action-key-one"
            try:
                self.assertTrue(first.reserve_live(key_one, SaladAction.START_GROUP.value, TARGET_GROUP, _utc(now))["inserted"])
                self.assertTrue(first.consume_signed_action_nonce(nonce, key_one, _utc(now)))
                digest = first.connection.execute(
                    "SELECT nonce_sha256 FROM action_capability_nonces WHERE action_key=?", (key_one,),
                ).fetchone()[0]
                self.assertEqual(len(digest), 64)
                self.assertNotEqual(digest, nonce)
                first.transition(key_one, "SEND_STARTED", _utc(now + 1), {"reason": "synthetic restart fixture"})
                self.assertTrue(first.claim_signed_action_dispatch(nonce, key_one, _utc(now + 1)))
                self.assertFalse(first.claim_signed_action_dispatch(nonce, key_one, _utc(now + 1)))
            finally:
                first.close()

            reopened = ActionLedger(path)
            try:
                self.assertFalse(reopened.consume_signed_action_nonce(nonce, key_one, _utc(now + 2)))
                self.assertFalse(reopened.claim_signed_action_dispatch(nonce, key_one, _utc(now + 2)))
                self.assertEqual(reopened.get(key_one)["state"], "SEND_STARTED")
            finally:
                reopened.close()

    def test_action_ledger_keeps_uncertain_operation_pending_and_blocks_another(self):
        ledger = ActionLedger(":memory:")
        try:
            key = ActionLedger.live_key_for(action="START_GROUP", target=TARGET_GROUP)
            first = ledger.reserve_live(key, "START_GROUP", TARGET_GROUP, "2026-10-11T00:00:01Z")
            self.assertTrue(first["inserted"])
            ledger.transition(key, "SEND_STARTED", "2026-10-11T00:00:02Z", {"reason": "synthetic ledger test"})
            ledger.transition(key, "RECONCILIATION_REQUIRED", "2026-10-11T00:00:03Z", {"reason": "synthetic uncertain outcome"})
            second = ledger.reserve_live(
                ActionLedger.live_key_for(action="STOP_GROUP", target=TARGET_GROUP),
                "STOP_GROUP", TARGET_GROUP, "2026-10-11T00:00:04Z",
            )
            self.assertFalse(second["inserted"])
            self.assertEqual(second["blocker"], "ANOTHER_PROVIDER_ACTION_REQUIRES_RECONCILIATION")
        finally:
            ledger.close()

    def test_sqlite_reservation_serializes_concurrent_replicas(self):
        with tempfile.TemporaryDirectory(prefix="g5-action-reservation-") as temp:
            path = Path(temp) / "actions.sqlite3"
            ledgers = (ActionLedger(path), ActionLedger(path))
            fake = FakeActionTransport(status=202)
            barrier = threading.Barrier(3)

            def attempt(ledger, action):
                barrier.wait(timeout=3)
                key = ActionLedger.live_key_for(action=action.value, target=TARGET_GROUP)
                return ledger.reserve_live(
                    key, action.value, TARGET_GROUP, "2026-10-11T00:00:01Z",
                )

            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(attempt, ledgers[0], SaladAction.START_GROUP)
                    second = pool.submit(attempt, ledgers[1], SaladAction.STOP_GROUP)
                    barrier.wait(timeout=3)
                    results = (first.result(timeout=5), second.result(timeout=5))
                self.assertEqual(sum(result["inserted"] is True for result in results), 1)
                self.assertEqual(sum(result.get("blocker") == "ANOTHER_PROVIDER_ACTION_REQUIRES_RECONCILIATION" for result in results), 1)
                self.assertEqual(len(fake.calls), 0)
                self.assertEqual(len(ledgers[0].snapshot()), 1)
            finally:
                for ledger in ledgers:
                    ledger.close()

    def test_synthetic_observation_cannot_resolve_provider_action(self):
        ledger = ActionLedger(":memory:")
        fake = FakeActionTransport(status=202)
        policy = SaladActionPolicy(live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True)
        executor = SaladActionExecutor(
            policy=policy, ledger=ledger, transport=fake, secret_provider=SyntheticSecretProvider(),
            kill_switch=DummySwitch(True), clock=lambda: NOW,
        )
        try:
            action_key = ActionLedger.live_key_for(action="START_GROUP", target=TARGET_GROUP)
            ledger.reserve_live(action_key, "START_GROUP", TARGET_GROUP, "2026-10-11T00:00:01Z")
            ledger.transition(action_key, "SEND_STARTED", "2026-10-11T00:00:02Z")
            ledger.transition(action_key, "ACCEPTED_PENDING", "2026-10-11T00:00:03Z")
            with self.assertRaisesRegex(ValueError, "synthetic reconciliation requires"):
                ledger.transition(
                    action_key, "RECONCILED_SYNTHETIC_SIMULATION", "2026-10-11T00:00:04Z",
                    {"data_classification": "SYNTHETIC/UNVERIFIED",
                     "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE, "simulation_only": True},
                )
            observation = {
                "container_group": "fl4shminer",
                "data_classification": "SYNTHETIC/UNVERIFIED",
                "source_provenance": {
                    "system": "synthetic_test_fixture", "host": "loopback",
                    "transport_tls_hostname_verified": False,
                },
                "sanitized_observation_sha256": "0" * 64,
            }
            blocked = executor.reconcile(action_key, observation, at_utc="2026-10-11T00:00:04Z")
            self.assertEqual(blocked.status, "RECONCILIATION_REQUIRED")
            self.assertFalse(blocked.actions_performed)
            self.assertEqual(blocked.reason, "INDEPENDENT_PROVIDER_OBSERVATION_REQUIRED")
            self.assertEqual(ledger.get(action_key)["state"], "ACCEPTED_PENDING")
        finally:
            ledger.close()

    def test_timeout_after_send_started_requires_reconciliation_and_never_retries(self):
        ledger = ActionLedger(":memory:")
        fake = FakeActionTransport(fail=True)
        executor = SaladActionExecutor(
            policy=SaladActionPolicy(live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True),
            ledger=ledger, transport=fake, secret_provider=SyntheticSecretProvider(),
            kill_switch=DummySwitch(True), clock=lambda: NOW,
        )
        try:
            result = executor.execute(SaladAction.START_GROUP, TARGET_GROUP, decision_dossier=None)
            self.assertEqual(result.status, "BLOCKED")
            self.assertIn("SALAD_GROUP_ACTION_CONTRACT_UNVERIFIED", result.reason)
            self.assertEqual(ledger.snapshot(), [])
            self.assertEqual(len(fake.calls), 0)
        finally:
            ledger.close()

    def test_unknown_or_over_budget_evidence_blocks_without_reservation(self):
        ledger = ActionLedger(":memory:")
        fake = FakeActionTransport()
        executor = SaladActionExecutor(
            policy=SaladActionPolicy(live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True),
            ledger=ledger, transport=fake, secret_provider=SyntheticSecretProvider(),
            kill_switch=DummySwitch(True), clock=lambda: NOW,
        )
        try:
            result = executor.execute(SaladAction.REALLOCATE_INSTANCE, TARGET_INSTANCE, decision_dossier=None)
            self.assertEqual(result.status, "BLOCKED")
            self.assertIn("BUDGET_UNVERIFIABLE", result.reason)
            self.assertEqual(fake.calls, [])
            self.assertEqual(ledger.snapshot(), [])
        finally:
            ledger.close()

    def test_legacy_caller_booleans_are_rejected_and_cannot_send(self):
        ledger = ActionLedger(":memory:")
        fake = FakeActionTransport()
        executor = SaladActionExecutor(
            policy=SaladActionPolicy(live_actions_enabled=True, live_spend_authorized=True, g5_reviewed=True),
            ledger=ledger, transport=fake, secret_provider=SyntheticSecretProvider(),
            kill_switch=DummySwitch(True), clock=lambda: NOW,
        )
        try:
            with self.assertRaises(TypeError):
                executor.execute(
                    SaladAction.REALLOCATE_INSTANCE, TARGET_INSTANCE,
                    binding={"binding_status": "VERIFIED"}, budget=verified_budget(),
                    operator_authorized=True, provider_revalidated=True,
                    telemetry_fresh=True, two_low_windows=True,
                )
            self.assertEqual(fake.calls, [])
            self.assertEqual(ledger.snapshot(), [])
        finally:
            ledger.close()

    def test_hard_budget_cannot_exceed_thirty_usd(self):
        with self.assertRaises(ValueError):
            SaladActionPolicy(hard_budget_usd=30.01)

    def test_auto_reallocation_simulation_ledger_isolated_from_provider_action_state(self):
        ledger = ActionLedger(":memory:")
        try:
            _arm_simulation_ledger(ledger, "2026-10-11T00:00:00Z")
            reserved = ledger.reserve_live(
                "existing-provider-action", "START_GROUP", TARGET_GROUP, "2026-10-11T00:00:00Z",
            )
            self.assertEqual(reserved["state"], "RESERVED")
            before = ledger.snapshot()
            simulation = ledger.reserve_auto_reallocation_simulation(
                simulation_key="1" * 64,
                trigger_key="1" * 64,
                scopes={
                    "organization": "2" * 64, "fleet": "3" * 64,
                    "assignment": "4" * 64, "target": "5" * 64,
                },
                at_utc="2026-10-11T00:00:01Z", at_epoch=1791676801.0,
                limits={
                    "max_per_minute": 4, "max_per_day": 12, "cooldown_seconds": 300,
                    "max_per_assignment": 2, "max_per_fleet": 4,
                },
                payload={
                    "simulation_only": True, "actions_performed": False,
                    "request_submitted": False, "dossier_created": False,
                    "live_action_eligible": False,
                    "data_classification": "SYNTHETIC/UNVERIFIED",
                    "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
                    "reservation_identity": {
                        "assignment_scope": "4" * 64,
                        "target_scope": "5" * 64,
                        "original_instance_fingerprint": "6" * 64,
                        "original_generation_fingerprint": "7" * 64,
                    },
                },
            )
            self.assertEqual(simulation["status"], "SIMULATION_RESERVED")
            self.assertEqual(ledger.snapshot(), before)
            self.assertEqual(len(ledger.auto_reallocation_simulation_snapshot()), 1)
            self.assertEqual(ledger.get("existing-provider-action")["state"], "RESERVED")

            before_actions = ledger.snapshot()
            for outcome, expected in (
                ("FAKE_HTTP_202", "SIMULATED_ACCEPTED_PENDING"),
                ("FAKE_TIMEOUT", "SIMULATED_RECONCILIATION_REQUIRED"),
            ):
                current = ledger.auto_reallocation_simulation_snapshot()[0]
                # A second fake transport is a distinct admission, with a
                # different scope so the first unresolved record does not
                # mask state-transition behavior under test.
                if current["state"] != "SIMULATION_RESERVED":
                    simulation = ledger.reserve_auto_reallocation_simulation(
                        simulation_key="8" * 64, trigger_key="8" * 64,
                        scopes={"organization": "2" * 64, "fleet": "3" * 64,
                                "assignment": "a" * 64, "target": "b" * 64},
                        at_utc="2026-10-11T00:00:02Z", at_epoch=1791676802.0,
                        limits={"max_per_minute": 4, "max_per_day": 12, "cooldown_seconds": 0,
                                "max_per_assignment": 2, "max_per_fleet": 4},
                        payload={
                            "simulation_only": True, "actions_performed": False,
                            "request_submitted": False, "dossier_created": False,
                            "live_action_eligible": False, "data_classification": "SYNTHETIC/UNVERIFIED",
                            "synthetic_fixture_id": SYNTHETIC_ACTION_FIXTURE,
                            "reservation_identity": {
                                "assignment_scope": "a" * 64, "target_scope": "b" * 64,
                                "original_instance_fingerprint": "c" * 64,
                                "original_generation_fingerprint": "d" * 64,
                            },
                        },
                    )
                    self.assertEqual(simulation["status"], "SIMULATION_RESERVED")
                selected = ledger.auto_reallocation_simulation_snapshot()[-1]
                with patch.object(SaladActionExecutor, "execute", autospec=True) as real_executor:
                    result = ledger.record_auto_reallocation_simulation_transport(
                        selected["simulation_key"], outcome=outcome, at_utc="2026-10-11T00:00:03Z",
                    )
                    real_executor.assert_not_called()
                self.assertEqual(result["status"], expected)
                self.assertFalse(result["actions_performed"])
                self.assertFalse(result["request_submitted"])
                self.assertEqual(ledger.snapshot(), before_actions)
            self.assertFalse(ledger.auto_reallocation_simulation_snapshot()[-1]["payload"].get("automatic_retry", True))
        finally:
            ledger.close()


if __name__ == "__main__":
    unittest.main()
