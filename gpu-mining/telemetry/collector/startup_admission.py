"""Fail-closed orchestration for the typed Pearl startup floor decision.

Provider binding and generation evidence remain exact and independently
verified. Calibration inputs are retained for API compatibility but do not
participate in the direct PEARL_AUTOTUNE floor comparison.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .fl4sh_early_autotune import (
    EarlyDecision,
    EarlyEvaluationContext,
    EarlyObservation,
    ProviderBinding,
    evaluate_early_autotune,
)
from .startup_recovery_policy import (
    StartupCause,
    StartupRecoveryDecision,
    StartupRecoveryPolicy,
)


# No empirical production calibration for RTX_4070_TI or other unreviewed
# startup profiles is bundled here. A missing calibration stays UNKNOWN.
APPROVED_PRODUCTION_CALIBRATIONS: tuple[EarlyCalibration, ...] = ()


class StartupAdmissionEngine:
    """Select exact typed evidence and run the existing pure early classifier."""

    def __init__(self, recovery_policy: StartupRecoveryPolicy | None = None) -> None:
        self.recovery_policy = recovery_policy or StartupRecoveryPolicy()
        if type(self.recovery_policy) is not StartupRecoveryPolicy:
            raise TypeError("startup admission requires the exact recovery policy")

    def classify_recovery(
        self,
        cause: StartupCause | str,
        *,
        elapsed_seconds: int | float = 0,
        admission_decision: EarlyDecision | None = None,
        trusted_provider_evidence: bool = False,
    ) -> StartupRecoveryDecision:
        """Return read-only cause handling; the action gate remains authoritative."""
        return self.recovery_policy.evaluate(
            cause,
            elapsed_seconds=elapsed_seconds,
            admission_decision=admission_decision,
            trusted_provider_evidence=trusted_provider_evidence,
        )

    def evaluate(
        self,
        observation: EarlyObservation,
        context: EarlyEvaluationContext | None = None,
        *,
        contradictory_evidence: bool = False,
    ) -> EarlyDecision:
        if type(observation) is not EarlyObservation:
            raise TypeError("startup observation must use the approved exact evidence type")
        active = context if context is not None else EarlyEvaluationContext()
        if type(active) is not EarlyEvaluationContext:
            raise TypeError("startup context must use the approved exact evidence type")

        invalid_binding = any(type(item) is not ProviderBinding for item in active.bindings)
        bindings = [
            item for item in active.bindings
            if type(item) is ProviderBinding
            and item.device_index == observation.device_index
            and item.gpu_key == observation.gpu_key
            and item.observation_reference == observation.source_reference
        ]
        binding = bindings[0] if len(bindings) == 1 else None
        # Pearl uses the configured floor directly. Calibration objects cannot
        # change, suppress, or promote this decision.
        calibration = None
        conflicting = (
            contradictory_evidence
            or invalid_binding
            or len(bindings) > 1
        )
        now = active.now_utc or datetime.now(timezone.utc)
        return evaluate_early_autotune(
            observation,
            binding,
            calibration,
            active.policy,
            now_utc=now,
            contradictory_evidence=conflicting,
            allow_synthetic_calibration_for_test=active.allow_synthetic_calibration_for_test,
            association_records=active.association_records,
            allow_synthetic_binding_evidence_for_test=active.allow_synthetic_binding_evidence_for_test,
            allow_synthetic_provider_log_evidence_for_test=active.allow_synthetic_provider_log_evidence_for_test,
        )
