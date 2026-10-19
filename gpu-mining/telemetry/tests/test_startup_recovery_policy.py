"""Offline, synthetic tests for cause-specific startup recovery decisions."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.fl4sh_early_autotune import EarlyDecision  # noqa: E402
from collector.startup_recovery_policy import (  # noqa: E402
    StartupCause,
    StartupRecoveryDecision,
    StartupRecoveryPolicy,
)


def early_decision(*, eligible: bool) -> EarlyDecision:
    return EarlyDecision(
        state="EARLY_UNDER_FLOOR" if eligible else "EARLY_UNKNOWN",
        reason="BELOW_FLOOR" if eligible else "FLOOR_UNAVAILABLE",
        signal_type="PEARL_AUTOTUNE",
        device_index=1,
        gpu_key="RTX_5080_LAPTOP",
        estimate_ths=80.0,
        predicted_lower_ths=75.0 if eligible else None,
        predicted_upper_ths=85.0 if eligible else None,
        floor_ths=120.0 if eligible else None,
        policy_hash="a" * 64,
        actions_performed=False,
        action_eligible=eligible,
    )


class StartupRecoveryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = StartupRecoveryPolicy(startup_timeout_seconds=180, escalation_interval_seconds=300)

    def test_pool_and_network_causes_never_become_gpu_floor_candidates(self) -> None:
        for cause, disposition in (
            (StartupCause.POOL_AUTH_TIMEOUT, "PRESERVE_POOL_RETRIES_AND_NOTIFY"),
            (StartupCause.NETWORK_FAILURE, "PRESERVE_NETWORK_RECOVERY_AND_NOTIFY"),
        ):
            with self.subTest(cause=cause.value):
                result = self.policy.evaluate(cause, admission_decision=early_decision(eligible=True))
                self.assertEqual(result.state, "STARTUP_NON_GPU_CAUSE")
                self.assertEqual(result.disposition, disposition)
                self.assertFalse(result.gpu_floor_action_candidate)
                self.assertFalse(result.actions_performed)
                self.assertFalse(result.request_submitted)

    def test_low_autotune_requires_exact_eligible_admission_decision(self) -> None:
        candidate = self.policy.evaluate(
            StartupCause.LOW_AUTOTUNE,
            admission_decision=early_decision(eligible=True),
        )
        self.assertEqual(candidate.state, "EARLY_UNDER_FLOOR")
        self.assertEqual(candidate.disposition, "REVIEW_CENTRAL_ACTION_GATE")
        self.assertTrue(candidate.gpu_floor_action_candidate)
        self.assertFalse(candidate.actions_performed)
        self.assertFalse(candidate.request_submitted)

        for decision in (None, early_decision(eligible=False), {"state": "EARLY_UNDER_FLOOR"}):
            result = self.policy.evaluate(StartupCause.LOW_AUTOTUNE, admission_decision=decision)
            self.assertEqual(result.state, "EARLY_UNKNOWN")
            self.assertFalse(result.gpu_floor_action_candidate)

    def test_cuda_no_gpu_and_process_exit_are_separate_non_actionable_causes(self) -> None:
        cuda = self.policy.evaluate(StartupCause.CUDA_INCOMPATIBLE)
        self.assertEqual((cuda.state, cuda.disposition), ("STARTUP_UNQUALIFIED", "NOTIFY_DRIVER_DIAGNOSTIC"))
        no_gpu = self.policy.evaluate(StartupCause.NO_GPU)
        self.assertEqual((no_gpu.state, no_gpu.disposition), ("EARLY_UNKNOWN", "VERIFY_GPU_AND_PROVIDER_BINDING"))
        exited = self.policy.evaluate(StartupCause.PROCESS_EXIT)
        self.assertEqual((exited.state, exited.disposition), ("STARTUP_FAILED", "RECORD_ACTUAL_PROCESS_EXIT"))
        for result in (cuda, no_gpu, exited):
            self.assertFalse(result.gpu_floor_action_candidate)
            self.assertFalse(result.actions_performed)
            self.assertFalse(result.request_submitted)

    def test_no_positive_hashrate_escalates_only_as_read_only_controller_attention(self) -> None:
        pending = self.policy.evaluate(StartupCause.NO_POSITIVE_HASHRATE, elapsed_seconds=179)
        timed_out = self.policy.evaluate(StartupCause.NO_POSITIVE_HASHRATE, elapsed_seconds=180)
        escalated = self.policy.evaluate(StartupCause.NO_POSITIVE_HASHRATE, elapsed_seconds=480)
        self.assertEqual((pending.state, pending.notification_required), ("STARTUP_PENDING", False))
        self.assertEqual((timed_out.state, timed_out.escalation_stage), ("STARTUP_TIMEOUT", "ATTENTION"))
        self.assertEqual((escalated.state, escalated.escalation_stage), ("STARTUP_ESCALATED", "ESCALATED"))
        self.assertEqual(timed_out.disposition, "NOTIFY_CONTROLLER_AND_CONTINUE")
        self.assertEqual(escalated.disposition, "ESCALATE_CONTROLLER_ATTENTION_AND_CONTINUE")
        for result in (pending, timed_out, escalated):
            self.assertFalse(result.gpu_floor_action_candidate)
            self.assertFalse(result.actions_performed)
            self.assertFalse(result.request_submitted)

    def test_provider_preemption_requires_trusted_provider_evidence(self) -> None:
        untrusted = self.policy.evaluate(StartupCause.PROVIDER_PREEMPTION)
        trusted = self.policy.evaluate(
            StartupCause.PROVIDER_PREEMPTION,
            trusted_provider_evidence=True,
        )
        self.assertEqual(untrusted.state, "EARLY_UNKNOWN")
        self.assertEqual(trusted.state, "PROVIDER_PREEMPTED")
        self.assertEqual(trusted.disposition, "RECONCILE_TRUSTED_PROVIDER_LIFECYCLE")
        self.assertFalse(trusted.gpu_floor_action_candidate)
        self.assertFalse(trusted.actions_performed)

    def test_missing_conflicting_or_unknown_cause_fails_closed(self) -> None:
        for cause in (StartupCause.UNKNOWN, "CONFLICTING_CAUSES", None):
            result = self.policy.evaluate(cause)
            self.assertEqual(result.state, "EARLY_UNKNOWN")
            self.assertFalse(result.gpu_floor_action_candidate)
            self.assertFalse(result.actions_performed)
        self.assertEqual(
            self.policy.evaluate(StartupCause.NO_POSITIVE_HASHRATE, elapsed_seconds=float("nan")).state,
            "EARLY_UNKNOWN",
        )
        self.assertEqual(
            self.policy.evaluate(StartupCause.NO_POSITIVE_HASHRATE, elapsed_seconds=10**1000).state,
            "EARLY_UNKNOWN",
        )

    def test_public_decision_projection_rejects_unbounded_values_and_actions(self) -> None:
        with self.assertRaisesRegex(ValueError, "INVALID_STARTUP_RECOVERY_CAUSE"):
            StartupRecoveryDecision("secret-value", "EARLY_UNKNOWN", "HOLD_FOR_VERIFIED_EVIDENCE", False)
        with self.assertRaisesRegex(ValueError, "STARTUP_RECOVERY_DECISION_MUST_REMAIN_READ_ONLY"):
            StartupRecoveryDecision(
                StartupCause.UNKNOWN.value,
                "EARLY_UNKNOWN",
                "HOLD_FOR_VERIFIED_EVIDENCE",
                False,
                actions_performed=True,
            )

    def test_positive_device_rate_recovers_only_with_trusted_generation(self) -> None:
        recovered = self.policy.recovery_after_timeout(
            positive_device_hashrate=True,
            trusted_generation=True,
        )
        self.assertEqual(recovered.state, "MINER_STARTUP_RECOVERED")
        self.assertEqual(recovered.disposition, "CONTINUE_STEADY_STATE_MONITORING")
        self.assertFalse(recovered.gpu_floor_action_candidate)
        self.assertFalse(recovered.actions_performed)
        self.assertFalse(
            self.policy.recovery_after_timeout(
                positive_device_hashrate=True,
                trusted_generation=False,
            ).state == "MINER_STARTUP_RECOVERED"
        )
        self.assertEqual(
            self.policy.recovery_after_timeout(
                positive_device_hashrate=False,
                trusted_generation=True,
            ).state,
            "EARLY_UNKNOWN",
        )

    def test_policy_configuration_is_bounded_and_read_only(self) -> None:
        config = StartupRecoveryPolicy.from_env({
            "FL4SH_STARTUP_HASHRATE_TIMEOUT_SECONDS": "120",
            "SALAD_G5_STARTUP_ESCALATION_INTERVAL_SECONDS": "600",
        })
        self.assertEqual(config.startup_timeout_seconds, 120)
        self.assertEqual(config.escalation_interval_seconds, 600)
        self.assertEqual(config.to_dict()["timeout_action"], "OBSERVE_AND_NOTIFY")
        with self.assertRaisesRegex(ValueError, "supported positive integer"):
            StartupRecoveryPolicy.from_env({"FL4SH_STARTUP_HASHRATE_TIMEOUT_SECONDS": "0"})
        with self.assertRaisesRegex(ValueError, "supported limit"):
            StartupRecoveryPolicy.from_env({"SALAD_G5_STARTUP_ESCALATION_INTERVAL_SECONDS": "99999"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
