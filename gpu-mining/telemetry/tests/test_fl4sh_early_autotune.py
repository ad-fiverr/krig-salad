"""Synthetic-only tests for the pure startup estimate classifier."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.fl4sh_early_autotune import (  # noqa: E402
    AssociationEvidenceRecord, BindingAttestation, EarlyCalibration, EarlyObservation,
    EarlyPolicy, MonitorPolicyEvidence, ObservationReference, ProviderBinding,
    association_evidence_sha256, evaluate_early_autotune, monitor_policy_evidence_sha256,
)


NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
POLICY_HASH = "a" * 64


class EarlyAutotuneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = EarlyPolicy(POLICY_HASH, {"RTX_5090_LAPTOP": 120.0, "RTX_5080_DESKTOP": 209.0}, 2.0)
        self.policy_evidence = MonitorPolicyEvidence(
            "fl4sh-source-event_config", "c" * 64, 3, "org-synthetic", "project-synthetic",
            "group-synthetic", "version-synthetic", "machine-synthetic", "instance-synthetic",
            "fl4sh-source-event_start", "2026-10-18T11:59:40Z", "2026-10-18T11:59:50Z",
            POLICY_HASH,
        )
        self.source_reference = ObservationReference(
            "fl4sh-source-event_a", "c" * 64, 4, "org-synthetic", "project-synthetic",
            "group-synthetic", "version-synthetic", "machine-synthetic", "instance-synthetic",
            "fl4shminer_device", 1, "RTX_5090_LAPTOP", "fl4sh-gpu-init_b",
            "fl4sh-source-event_start", "2026-10-18T11:59:40Z",
            monitor_policy_evidence_sha256(self.policy_evidence),
        )
        self.signal = EarlyObservation("PEARL_AUTOTUNE", 1, "RTX_5090_LAPTOP", 80.0,
                                       NOW - timedelta(seconds=2), POLICY_HASH,
                                       source_reference=self.source_reference,
                                       policy_evidence=self.policy_evidence,
                                       policy_evidence_status="PARSED")
        record = AssociationEvidenceRecord(
            1, "association-synthetic", "SYNTHETIC_TEST_ONLY", "VERIFIED", self.source_reference,
            "assignment-synthetic", "generation-synthetic", NOW - timedelta(seconds=20),
            NOW + timedelta(seconds=30),
            NOW - timedelta(seconds=1), POLICY_HASH, "synthetic-verifier", "test-v1", "",
        )
        self.association_record = replace(record, evidence_sha256=association_evidence_sha256(record))
        self.binding = ProviderBinding(
            1, "RTX_5090_LAPTOP", "org-synthetic", "project-synthetic", "group-synthetic",
            "machine-synthetic", "instance-synthetic", "assignment-synthetic", "generation-synthetic",
            NOW - timedelta(seconds=20), NOW - timedelta(seconds=1), POLICY_HASH,
            source="SYNTHETIC_TEST_ONLY", observation_reference=self.source_reference,
            attestation=BindingAttestation(1, self.association_record.evidence_id,
                                           self.association_record.evidence_sha256),
            valid_until_utc=NOW + timedelta(seconds=30),
        )
        self.calibration = EarlyCalibration(
            "CUDA_POOL_EQUIVALENT", "RTX_5090_LAPTOP", 0.9, 1.1, 40,
            NOW - timedelta(days=1), NOW + timedelta(days=1), POLICY_HASH, "b" * 64,
            "SYNTHETIC_TEST_ONLY",
        )

    def decide(self, **overrides):
        arguments = dict(
            now_utc=NOW,
            allow_synthetic_calibration_for_test=True,
            association_records=(self.association_record,),
            allow_synthetic_binding_evidence_for_test=True,
        )
        arguments.update(overrides)
        return evaluate_early_autotune(
            arguments.pop("signal", self.signal), arguments.pop("binding", self.binding),
            arguments.pop("calibration", self.calibration), arguments.pop("policy", self.policy),
            **arguments,
        )

    def test_underfloor_is_informational_even_with_explicit_synthetic_binding(self):
        result = self.decide()
        self.assertEqual(result.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(result.reason, "PEARL_BELOW_FLOOR")
        self.assertEqual(result.floor_ths, 120.0)
        self.assertIsNone(result.predicted_lower_ths)
        self.assertIsNone(result.predicted_upper_ths)
        self.assertEqual(result.assignment_generation, "generation-synthetic")
        self.assertFalse(result.actions_performed)
        self.assertFalse(result.action_eligible)

    def test_pass_is_not_steady_state_health(self):
        result = self.decide(signal=replace(self.signal, estimate_ths=150.0))
        self.assertEqual(result.state, "EARLY_PASS")
        self.assertFalse(result.action_eligible)

    def test_duplicate_estimate_is_deterministic_and_cannot_perform_action(self):
        first = self.decide()
        replay = self.decide()
        self.assertEqual(first, replay)
        self.assertFalse(first.actions_performed or replay.actions_performed)

    def test_pearl_below_floor_is_direct_underfloor_without_prediction_interval(self):
        result = self.decide(signal=replace(self.signal, estimate_ths=119.99))
        self.assertEqual(result.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(result.reason, "PEARL_BELOW_FLOOR")
        self.assertIsNone(result.predicted_lower_ths)
        self.assertIsNone(result.predicted_upper_ths)

    def test_exact_threshold_boundary_passes_without_margin(self):
        result = self.decide(signal=replace(self.signal, estimate_ths=120.0))
        self.assertEqual(result.state, "EARLY_PASS")
        self.assertEqual(result.reason, "PEARL_AT_OR_ABOVE_FLOOR")

    def test_pearl_150_passes_while_cuda_80_is_diagnostic_only(self):
        pearl = self.decide(signal=replace(self.signal, estimate_ths=150.0))
        pearl_at_floor = self.decide(signal=replace(self.signal, estimate_ths=120.0))
        cuda = self.decide(signal=replace(
            self.signal, signal_type="CUDA_POOL_EQUIVALENT", estimate_ths=80.0,
        ))
        self.assertEqual(pearl.state, "EARLY_PASS")
        self.assertEqual(pearl.reason, "PEARL_AT_OR_ABOVE_FLOOR")
        self.assertEqual(pearl_at_floor.state, "EARLY_PASS")
        self.assertEqual(pearl_at_floor.reason, "PEARL_AT_OR_ABOVE_FLOOR")
        self.assertEqual(cuda.state, "EARLY_UNKNOWN")
        self.assertEqual(cuda.reason, "CUDA_POOL_EQUIVALENT_DIAGNOSTIC_ONLY")

    def test_pearl_100_is_underfloor_even_when_cuda_is_150(self):
        pearl = self.decide(signal=replace(self.signal, estimate_ths=100.0))
        cuda = self.decide(signal=replace(
            self.signal, signal_type="CUDA_POOL_EQUIVALENT", estimate_ths=150.0,
        ))
        self.assertEqual(pearl.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(pearl.reason, "PEARL_BELOW_FLOOR")
        self.assertEqual(cuda.state, "EARLY_UNKNOWN")
        self.assertFalse(pearl.action_eligible or pearl.actions_performed)

    def test_policy_margin_does_not_change_direct_pearl_comparison(self):
        policy_with_margin = replace(self.policy, margin_ths=25.0)
        at_floor = self.decide(signal=replace(self.signal, estimate_ths=120.0), policy=policy_with_margin)
        below = self.decide(signal=replace(self.signal, estimate_ths=119.0), policy=policy_with_margin)
        self.assertEqual(at_floor.state, "EARLY_PASS")
        self.assertEqual(below.state, "EARLY_UNDER_FLOOR")

    def test_unindexed_pearl_is_not_bound_by_one_device_coincidence(self):
        signal = replace(self.signal, signal_type="PEARL_AUTOTUNE", device_index=None)
        calibration = replace(self.calibration, signal_type="PEARL_AUTOTUNE")
        self.assertEqual(self.decide(signal=signal, calibration=calibration).reason, "DEVICE_UNVERIFIED")

    def test_pearl_with_explicit_device_uses_floor_without_calibration(self):
        result = self.decide(calibration=None)
        self.assertEqual(result.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(result.calibration_status, "NOT_APPLICABLE")
        self.assertIsNone(result.calibration_evidence_sha256)

    def test_cuda_pool_equivalent_is_diagnostic_only(self):
        result = self.decide(signal=replace(
            self.signal, signal_type="CUDA_POOL_EQUIVALENT", estimate_ths=1.0,
        ), calibration=None)
        self.assertEqual(result.state, "EARLY_UNKNOWN")
        self.assertEqual(result.reason, "CUDA_POOL_EQUIVALENT_DIAGNOSTIC_ONLY")
        self.assertFalse(result.action_eligible or result.actions_performed)

    def test_invalid_stale_or_wrong_profile_calibration_cannot_change_pearl_decision(self):
        variants = (
            replace(self.calibration, status="UNAPPROVED"),
            replace(self.calibration, expires_at_utc=NOW - timedelta(seconds=1)),
            replace(self.calibration, pair_count=0, gpu_key="RTX_5080_DESKTOP"),
        )
        for calibration in variants:
            with self.subTest(status=calibration.status, gpu=calibration.gpu_key):
                self.assertEqual(self.decide(calibration=calibration).state, "EARLY_UNDER_FLOOR")

    def test_changed_policy_hash_invalidates_signal_binding_and_calibration(self):
        changed = replace(self.policy, policy_hash="c" * 64)
        self.assertEqual(self.decide(policy=changed).reason, "POLICY_MISMATCH")
        self.assertEqual(self.decide(binding=replace(self.binding, policy_hash="c" * 64)).reason,
                         "BINDING_UNVERIFIED")
        self.assertEqual(self.decide(calibration=replace(self.calibration, policy_hash="c" * 64)).state,
                         "EARLY_UNDER_FLOOR")

    def test_stale_or_future_signal_is_unknown(self):
        old = replace(self.signal, event_time_utc=NOW - timedelta(seconds=61))
        future = replace(self.signal, event_time_utc=NOW + timedelta(seconds=1))
        self.assertEqual(self.decide(signal=old).reason, "SIGNAL_STALE_OR_FUTURE")
        self.assertEqual(self.decide(signal=future).reason, "SIGNAL_STALE_OR_FUTURE")

    def test_stale_binding_is_unknown(self):
        anchor_time = NOW - timedelta(seconds=50)
        config_time = NOW - timedelta(seconds=40)
        older_evidence = replace(
            self.policy_evidence,
            startup_anchor_time_utc=anchor_time.isoformat().replace("+00:00", "Z"),
            occurred_at_utc=config_time.isoformat().replace("+00:00", "Z"),
        )
        older_reference = replace(
            self.source_reference,
            startup_anchor_time_utc=anchor_time.isoformat().replace("+00:00", "Z"),
            policy_evidence_sha256=monitor_policy_evidence_sha256(older_evidence),
        )
        older_signal = replace(self.signal, event_time_utc=config_time, source_reference=older_reference,
                               policy_evidence=older_evidence)
        old_record = replace(
            self.association_record,
            observation_reference=older_reference,
            valid_from_utc=anchor_time,
            valid_until_utc=NOW + timedelta(seconds=30),
            revalidated_at_utc=NOW - timedelta(seconds=31),
            evidence_sha256="",
        )
        old_record = replace(old_record, evidence_sha256=association_evidence_sha256(old_record))
        older_binding = replace(
            self.binding,
            valid_from_utc=anchor_time,
            valid_until_utc=NOW + timedelta(seconds=30),
            revalidated_at_utc=NOW - timedelta(seconds=31),
            observation_reference=older_reference,
            attestation=BindingAttestation(1, old_record.evidence_id, old_record.evidence_sha256),
        )
        self.assertEqual(self.decide(signal=older_signal, binding=older_binding,
                                     association_records=(old_record,)).reason,
                         "BINDING_STALE")

    def test_replacement_generation_cannot_reuse_old_evidence(self):
        replacement = replace(self.binding, assignment_generation="generation-new")
        self.assertEqual(self.decide(binding=replacement).reason, "BINDING_ATTESTATION_CONFLICT")

    def test_recovered_generation_gets_a_fresh_decision_without_reusing_underfloor(self):
        first = self.decide()
        recovered_reference = replace(
            self.source_reference,
            source_event_id="fl4sh-source-event_recovered",
            source_row=5,
        )
        recovered_signal = replace(
            self.signal,
            estimate_ths=150.0,
            event_time_utc=NOW - timedelta(seconds=1),
            source_reference=recovered_reference,
        )
        recovered_binding = replace(
            self.binding,
            assignment_id="assignment-recovered",
            assignment_generation="generation-recovered",
            valid_from_utc=NOW - timedelta(seconds=2),
            valid_until_utc=NOW + timedelta(seconds=30),
            revalidated_at_utc=NOW,
            observation_reference=recovered_reference,
        )
        recovered_record = replace(
            self.association_record,
            evidence_id="association-recovered",
            observation_reference=recovered_reference,
            assignment_id="assignment-recovered",
            assignment_generation="generation-recovered",
            valid_from_utc=NOW - timedelta(seconds=2),
            revalidated_at_utc=NOW,
            evidence_sha256="",
        )
        recovered_record = replace(recovered_record, evidence_sha256=association_evidence_sha256(recovered_record))
        recovered_binding = replace(
            recovered_binding,
            source="SYNTHETIC_TEST_ONLY",
            attestation=BindingAttestation(1, recovered_record.evidence_id, recovered_record.evidence_sha256),
        )
        recovered = self.decide(
            signal=recovered_signal,
            binding=recovered_binding,
            association_records=(recovered_record,),
        )
        self.assertEqual(first.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(recovered.state, "EARLY_PASS")
        self.assertEqual(first.assignment_generation, "generation-synthetic")
        self.assertEqual(recovered.assignment_generation, "generation-recovered")
        self.assertFalse(recovered.action_eligible or recovered.actions_performed)

    def test_provider_binding_mismatch_blocks_action(self):
        for changed in (replace(self.binding, device_index=2), replace(self.binding, gpu_key="RTX_5080_DESKTOP")):
            self.assertEqual(self.decide(binding=changed).reason, "BINDING_CONFLICT")

    def test_same_gpu_and_device_from_another_machine_cannot_reuse_binding(self):
        other_source = replace(
            self.source_reference,
            source_event_id="fl4sh-source-event_machine-b",
            machine_id="machine-b",
            instance_id="instance-b",
        )
        other_binding = replace(self.binding, observation_reference=other_source,
                                machine_id="machine-b", instance_id="instance-b")
        result = self.decide(binding=other_binding)
        self.assertEqual(result.state, "EARLY_UNKNOWN")
        self.assertEqual(result.reason, "BINDING_SOURCE_CONFLICT")
        self.assertFalse(result.action_eligible or result.actions_performed)

    def test_missing_or_unverified_provenance_fails_closed(self):
        signal = replace(self.signal, source_reference=None)
        binding = replace(self.binding, observation_reference=None, attestation=None)
        self.assertEqual(self.decide(signal=signal).reason, "POLICY_EVIDENCE_UNVERIFIED")
        self.assertEqual(self.decide(binding=binding).reason, "PROVENANCE_UNVERIFIED")

    def test_synthetic_binding_is_rejected_without_explicit_test_gate(self):
        result = evaluate_early_autotune(
            self.signal, self.binding, self.calibration, self.policy, now_utc=NOW,
            association_records=(self.association_record,),
            allow_synthetic_calibration_for_test=True,
        )
        self.assertEqual(result.reason, "BINDING_NOT_AUTHORIZED_FOR_PRODUCTION")

    def test_arbitrary_digest_without_independent_record_is_rejected(self):
        binding = replace(self.binding, attestation=BindingAttestation(1, "association-synthetic", "d" * 64))
        self.assertEqual(self.decide(binding=binding).reason, "PROVENANCE_UNVERIFIED")

    def test_tampered_independent_record_is_rejected(self):
        tampered = replace(self.association_record, assignment_generation="generation-other")
        self.assertEqual(self.decide(association_records=(tampered,)).reason, "PROVENANCE_UNVERIFIED")

    def test_missing_malformed_ambiguous_and_mismatched_policy_declaration_fail_closed(self):
        cases = (
            (replace(self.signal, policy_hash=None, policy_evidence=None,
                     policy_evidence_status="MISSING"), "POLICY_EVIDENCE_UNVERIFIED"),
            (replace(self.signal, policy_hash=None, policy_evidence=None,
                     policy_evidence_status="AMBIGUOUS"), "POLICY_EVIDENCE_AMBIGUOUS"),
            (replace(self.signal, policy_hash=None,
                     policy_evidence=replace(self.policy_evidence, status="MALFORMED", policy_hash=None),
                     policy_evidence_status="MALFORMED"), "POLICY_EVIDENCE_UNVERIFIED"),
            (replace(
                self.signal,
                policy_hash="c" * 64,
                policy_evidence=replace(self.policy_evidence, policy_hash="c" * 64),
                source_reference=replace(
                    self.source_reference,
                    policy_evidence_sha256=monitor_policy_evidence_sha256(
                        replace(self.policy_evidence, policy_hash="c" * 64)
                    ),
                ),
            ), "POLICY_MISMATCH"),
        )
        for signal, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self.decide(signal=signal).reason, expected)

    def test_active_evaluator_hash_cannot_substitute_for_missing_source_declaration(self):
        signal = replace(self.signal, policy_hash=None, policy_evidence=None,
                         policy_evidence_status="MISSING")
        self.assertEqual(self.decide(signal=signal).reason, "POLICY_EVIDENCE_UNVERIFIED")

    def test_policy_witness_from_another_machine_or_startup_anchor_is_rejected(self):
        other_machine = replace(self.policy_evidence, machine_id="machine-other")
        result = self.decide(signal=replace(self.signal, policy_evidence=other_machine))
        self.assertEqual(result.reason, "POLICY_EVIDENCE_UNVERIFIED")
        other_anchor = replace(self.policy_evidence, startup_anchor_source_event_id="fl4sh-source-event_other")
        result = self.decide(signal=replace(self.signal, policy_evidence=other_anchor))
        self.assertEqual(result.reason, "POLICY_EVIDENCE_UNVERIFIED")

    def test_binding_scope_fields_must_match_its_observation_reference(self):
        binding = replace(self.binding, machine_id="machine-b", instance_id="instance-b")
        result = self.decide(binding=binding)
        self.assertEqual(result.state, "EARLY_UNKNOWN")
        self.assertEqual(result.reason, "BINDING_SOURCE_CONFLICT")

    def test_unconfigured_policy_is_unknown_without_a_floor(self):
        result = evaluate_early_autotune(
            self.signal, self.binding, self.calibration, None, now_utc=NOW,
            allow_synthetic_calibration_for_test=True,
        )
        self.assertEqual(result.state, "EARLY_UNKNOWN")
        self.assertEqual(result.reason, "POLICY_UNAVAILABLE")
        self.assertIsNone(result.policy_hash)
        self.assertFalse(result.action_eligible or result.actions_performed)

    def test_decision_serialization_has_version_and_only_hashed_source_reference(self):
        result = self.decide()
        serialized = result.to_dict()
        self.assertEqual(serialized["decision_version"], 1)
        self.assertEqual(serialized["source_reference_sha256"], result.source_reference_sha256)
        self.assertNotIn("machine_id", serialized)
        self.assertNotIn("instance_id", serialized)
        self.assertTrue(serialized["evaluated_at_utc"].endswith("Z"))
        self.assertEqual(serialized["calibration_status"], "NOT_APPLICABLE")
        self.assertIsNone(serialized["calibration_evidence_sha256"])
        self.assertFalse(serialized["action_eligible"] or serialized["actions_performed"])

    def test_missing_calibration_is_explicitly_irrelevant_in_serialized_decision(self):
        result = self.decide(calibration=None)
        self.assertEqual(result.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(result.to_dict()["calibration_status"], "NOT_APPLICABLE")
        self.assertIsNone(result.to_dict()["calibration_evidence_sha256"])

    def test_unverified_provider_binding_and_ambiguity_fail_closed(self):
        self.assertEqual(self.decide(binding=None).reason, "BINDING_UNVERIFIED")
        self.assertEqual(self.decide(binding=replace(self.binding, status="UNKNOWN")).reason, "BINDING_UNVERIFIED")
        self.assertEqual(self.decide(contradictory_evidence=True).reason, "CONTRADICTORY_EVIDENCE")

    def test_missing_gpu_or_floor_is_unknown(self):
        self.assertEqual(self.decide(signal=replace(self.signal, gpu_key=None)).reason, "GPU_UNVERIFIED")
        other = replace(self.signal, gpu_key="RTX_3060")
        other_binding = replace(self.binding, gpu_key="RTX_3060")
        self.assertEqual(self.decide(signal=other, binding=other_binding).reason, "FLOOR_UNCONFIGURED")

    def test_known_cuda_initialization_failure_is_unqualified_but_not_actionable(self):
        failed = replace(self.signal, estimate_ths=None, startup_failure_reason="CUDA_DRIVER_VERSION_INSUFFICIENT",
                         source="FL4SHMINER_STARTUP_LOG")
        result = self.decide(signal=failed, binding=None, calibration=None)
        self.assertEqual(result.state, "STARTUP_UNQUALIFIED")
        self.assertFalse(result.action_eligible)

    def test_unrecognized_failure_or_pool_timeout_is_unknown(self):
        failed = replace(self.signal, startup_failure_reason="POOL_CONNECTION_FAILED")
        self.assertEqual(self.decide(signal=failed).state, "EARLY_UNKNOWN")

    def test_invalid_policy_does_not_accept_nonfinite_floors_or_margin(self):
        for floors, margin in (({"RTX_5090_LAPTOP": float("nan")}, 2.0),
                               ({"RTX_5090_LAPTOP": 120}, float("inf")),
                               ({"RTX_5090_LAPTOP": 10001}, 2.0),
                               ({"rtx_5090_laptop": 120}, 2.0)):
            with self.assertRaises(ValueError):
                EarlyPolicy(POLICY_HASH, floors, margin)

    def test_policy_floors_cannot_mutate_after_creation(self):
        floors = {"RTX_5090_LAPTOP": 120.0}
        policy = EarlyPolicy(POLICY_HASH, floors, 2.0)
        floors["RTX_5090_LAPTOP"] = 1.0
        self.assertEqual(policy.floors_ths["RTX_5090_LAPTOP"], 120.0)
        with self.assertRaises(TypeError):
            policy.floors_ths["RTX_5090_LAPTOP"] = 1.0


if __name__ == "__main__":
    unittest.main()
