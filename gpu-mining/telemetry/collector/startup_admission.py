"""Fail-closed orchestration for the existing typed startup estimator.

This module does not define new calibration or provider-binding semantics. It
selects only an unambiguous, exact match from the already approved evidence
types and delegates the decision to ``evaluate_early_autotune``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .fl4sh_early_autotune import (
    EarlyCalibration,
    EarlyDecision,
    EarlyEvaluationContext,
    EarlyObservation,
    ProviderBinding,
    evaluate_early_autotune,
)


# No empirical production calibration for RTX_4070_TI or other unreviewed
# startup profiles is bundled here. A missing calibration stays UNKNOWN.
APPROVED_PRODUCTION_CALIBRATIONS: tuple[EarlyCalibration, ...] = ()


class StartupAdmissionEngine:
    """Select exact typed evidence and run the existing pure early classifier."""

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
        invalid_calibration = any(type(item) is not EarlyCalibration for item in active.calibrations)
        calibrations = [
            item for item in active.calibrations
            if type(item) is EarlyCalibration
            and item.signal_type == observation.signal_type
            and item.gpu_key == observation.gpu_key
        ]

        binding = bindings[0] if len(bindings) == 1 else None
        calibration = calibrations[0] if len(calibrations) == 1 else None
        conflicting = (
            contradictory_evidence
            or invalid_binding
            or invalid_calibration
            or len(bindings) > 1
            or len(calibrations) > 1
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
        )
