"""Typed, read-only policy for classifying Fl4shMiner startup outcomes.

This module recommends recovery handling only. It never performs provider
actions, changes the miner process, writes a ledger, or submits a request.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
import os
import re
from typing import Mapping

from .fl4sh_early_autotune import EarlyDecision


STARTUP_TIMEOUT_ENV = "FL4SH_STARTUP_HASHRATE_TIMEOUT_SECONDS"
STARTUP_ESCALATION_ENV = "SALAD_G5_STARTUP_ESCALATION_INTERVAL_SECONDS"
DEFAULT_STARTUP_TIMEOUT_SECONDS = 180
DEFAULT_ESCALATION_INTERVAL_SECONDS = 300
MAX_STARTUP_TIMEOUT_SECONDS = 3600
MAX_ESCALATION_INTERVAL_SECONDS = 86_400
MAX_ELAPSED_SECONDS = 31_536_000

_VALID_DECISION_STATES = frozenset({
    "EARLY_UNDER_FLOOR",
    "EARLY_UNKNOWN",
    "STARTUP_NON_GPU_CAUSE",
    "STARTUP_PENDING",
    "STARTUP_TIMEOUT",
    "STARTUP_ESCALATED",
    "STARTUP_UNQUALIFIED",
    "STARTUP_FAILED",
    "PROVIDER_PREEMPTED",
    "MINER_STARTUP_RECOVERED",
})
_VALID_DISPOSITIONS = frozenset({
    "REVIEW_CENTRAL_ACTION_GATE",
    "REQUIRE_VERIFIED_ADMISSION",
    "PRESERVE_POOL_RETRIES_AND_NOTIFY",
    "PRESERVE_NETWORK_RECOVERY_AND_NOTIFY",
    "NOTIFY_DRIVER_DIAGNOSTIC",
    "VERIFY_GPU_AND_PROVIDER_BINDING",
    "WAIT_FOR_POSITIVE_DEVICE_HASHRATE",
    "NOTIFY_CONTROLLER_AND_CONTINUE",
    "ESCALATE_CONTROLLER_ATTENTION_AND_CONTINUE",
    "RECORD_ACTUAL_PROCESS_EXIT",
    "RECONCILE_TRUSTED_PROVIDER_LIFECYCLE",
    "HOLD_FOR_VERIFIED_EVIDENCE",
    "CONTINUE_STEADY_STATE_MONITORING",
})


class StartupCause(str, Enum):
    LOW_AUTOTUNE = "LOW_AUTOTUNE"
    POOL_AUTH_TIMEOUT = "POOL_AUTH_TIMEOUT"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    CUDA_INCOMPATIBLE = "CUDA_INCOMPATIBLE"
    NO_GPU = "NO_GPU"
    NO_POSITIVE_HASHRATE = "NO_POSITIVE_HASHRATE"
    PROCESS_EXIT = "PROCESS_EXIT"
    PROVIDER_PREEMPTION = "PROVIDER_PREEMPTION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class StartupRecoveryDecision:
    cause: str
    state: str
    disposition: str
    notification_required: bool
    gpu_floor_action_candidate: bool = False
    escalation_stage: str = "NONE"
    actions_performed: bool = False
    request_submitted: bool = False

    def __post_init__(self) -> None:
        causes = {cause.value for cause in StartupCause}
        if type(self.cause) is not str or self.cause not in causes:
            raise ValueError("INVALID_STARTUP_RECOVERY_CAUSE")
        if type(self.state) is not str or self.state not in _VALID_DECISION_STATES:
            raise ValueError("INVALID_STARTUP_RECOVERY_STATE")
        if type(self.disposition) is not str or self.disposition not in _VALID_DISPOSITIONS:
            raise ValueError("INVALID_STARTUP_RECOVERY_DISPOSITION")
        if type(self.notification_required) is not bool:
            raise ValueError("INVALID_STARTUP_RECOVERY_NOTIFICATION")
        if type(self.gpu_floor_action_candidate) is not bool:
            raise ValueError("INVALID_STARTUP_RECOVERY_CANDIDATE")
        if type(self.escalation_stage) is not str or self.escalation_stage not in {
            "NONE", "ATTENTION", "ESCALATED", "RECOVERED",
        }:
            raise ValueError("INVALID_STARTUP_RECOVERY_STAGE")
        if self.actions_performed is not False or self.request_submitted is not False:
            raise ValueError("STARTUP_RECOVERY_DECISION_MUST_REMAIN_READ_ONLY")

    def to_dict(self) -> dict[str, object]:
        return {
            "cause": self.cause,
            "state": self.state,
            "disposition": self.disposition,
            "notification_required": self.notification_required,
            "gpu_floor_action_candidate": self.gpu_floor_action_candidate,
            "escalation_stage": self.escalation_stage,
            "actions_performed": False,
            "request_submitted": False,
        }


@dataclass(frozen=True, slots=True)
class StartupRecoveryPolicy:
    startup_timeout_seconds: int = DEFAULT_STARTUP_TIMEOUT_SECONDS
    escalation_interval_seconds: int = DEFAULT_ESCALATION_INTERVAL_SECONDS

    def __post_init__(self) -> None:
        if (
            type(self.startup_timeout_seconds) is not int
            or not 1 <= self.startup_timeout_seconds <= MAX_STARTUP_TIMEOUT_SECONDS
        ):
            raise ValueError("INVALID_STARTUP_TIMEOUT_POLICY")
        if (
            type(self.escalation_interval_seconds) is not int
            or not 1 <= self.escalation_interval_seconds <= MAX_ESCALATION_INTERVAL_SECONDS
        ):
            raise ValueError("INVALID_STARTUP_ESCALATION_POLICY")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "StartupRecoveryPolicy":
        env = os.environ if environ is None else environ
        return cls(
            startup_timeout_seconds=_bounded_env_integer(
                env.get(STARTUP_TIMEOUT_ENV, str(DEFAULT_STARTUP_TIMEOUT_SECONDS)),
                STARTUP_TIMEOUT_ENV,
                maximum=MAX_STARTUP_TIMEOUT_SECONDS,
            ),
            escalation_interval_seconds=_bounded_env_integer(
                env.get(STARTUP_ESCALATION_ENV, str(DEFAULT_ESCALATION_INTERVAL_SECONDS)),
                STARTUP_ESCALATION_ENV,
                maximum=MAX_ESCALATION_INTERVAL_SECONDS,
            ),
        )

    def evaluate(
        self,
        cause: StartupCause | str,
        *,
        elapsed_seconds: int | float = 0,
        admission_decision: EarlyDecision | None = None,
        trusted_provider_evidence: bool = False,
    ) -> StartupRecoveryDecision:
        if type(trusted_provider_evidence) is not bool:
            return _unknown_decision()
        if type(elapsed_seconds) is int:
            if elapsed_seconds < 0 or elapsed_seconds > MAX_ELAPSED_SECONDS:
                return _unknown_decision()
        elif (
            type(elapsed_seconds) is not float
            or not math.isfinite(elapsed_seconds)
            or elapsed_seconds < 0
            or elapsed_seconds > MAX_ELAPSED_SECONDS
        ):
            return _unknown_decision()
        if type(cause) is StartupCause:
            selected = cause
        elif type(cause) is str:
            try:
                selected = StartupCause(cause)
            except ValueError:
                selected = StartupCause.UNKNOWN
        else:
            selected = StartupCause.UNKNOWN

        if selected is StartupCause.LOW_AUTOTUNE:
            if (
                type(admission_decision) is EarlyDecision
                and admission_decision.state == "EARLY_UNDER_FLOOR"
                and admission_decision.actions_performed is False
            ):
                return StartupRecoveryDecision(
                    selected.value, "EARLY_UNDER_FLOOR", "REVIEW_CENTRAL_ACTION_GATE",
                    True, gpu_floor_action_candidate=True,
                )
            return StartupRecoveryDecision(
                selected.value, "EARLY_UNKNOWN", "REQUIRE_VERIFIED_ADMISSION", False,
            )

        if selected is StartupCause.POOL_AUTH_TIMEOUT:
            return StartupRecoveryDecision(
                selected.value, "STARTUP_NON_GPU_CAUSE", "PRESERVE_POOL_RETRIES_AND_NOTIFY",
                True,
            )
        if selected is StartupCause.NETWORK_FAILURE:
            return StartupRecoveryDecision(
                selected.value, "STARTUP_NON_GPU_CAUSE", "PRESERVE_NETWORK_RECOVERY_AND_NOTIFY",
                True,
            )
        if selected is StartupCause.CUDA_INCOMPATIBLE:
            return StartupRecoveryDecision(
                selected.value, "STARTUP_UNQUALIFIED", "NOTIFY_DRIVER_DIAGNOSTIC", True,
            )
        if selected is StartupCause.NO_GPU:
            return StartupRecoveryDecision(
                selected.value, "EARLY_UNKNOWN", "VERIFY_GPU_AND_PROVIDER_BINDING", True,
            )
        if selected is StartupCause.NO_POSITIVE_HASHRATE:
            elapsed = float(elapsed_seconds)
            if elapsed < self.startup_timeout_seconds:
                return StartupRecoveryDecision(
                    selected.value, "STARTUP_PENDING", "WAIT_FOR_POSITIVE_DEVICE_HASHRATE", False,
                )
            if elapsed < self.startup_timeout_seconds + self.escalation_interval_seconds:
                return StartupRecoveryDecision(
                    selected.value, "STARTUP_TIMEOUT", "NOTIFY_CONTROLLER_AND_CONTINUE", True,
                    escalation_stage="ATTENTION",
                )
            return StartupRecoveryDecision(
                selected.value, "STARTUP_ESCALATED", "ESCALATE_CONTROLLER_ATTENTION_AND_CONTINUE", True,
                escalation_stage="ESCALATED",
            )
        if selected is StartupCause.PROCESS_EXIT:
            return StartupRecoveryDecision(
                selected.value, "STARTUP_FAILED", "RECORD_ACTUAL_PROCESS_EXIT", True,
            )
        if selected is StartupCause.PROVIDER_PREEMPTION:
            if not trusted_provider_evidence:
                return _unknown_decision()
            return StartupRecoveryDecision(
                selected.value, "PROVIDER_PREEMPTED", "RECONCILE_TRUSTED_PROVIDER_LIFECYCLE", True,
            )
        return _unknown_decision()

    def recovery_after_timeout(
        self,
        *,
        positive_device_hashrate: bool,
        trusted_generation: bool,
    ) -> StartupRecoveryDecision:
        if type(positive_device_hashrate) is not bool or type(trusted_generation) is not bool:
            return _unknown_decision()
        if not positive_device_hashrate or not trusted_generation:
            return _unknown_decision()
        return StartupRecoveryDecision(
            "NO_POSITIVE_HASHRATE", "MINER_STARTUP_RECOVERED", "CONTINUE_STEADY_STATE_MONITORING",
            True, escalation_stage="RECOVERED",
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "startup_timeout_seconds": self.startup_timeout_seconds,
            "escalation_interval_seconds": self.escalation_interval_seconds,
            "timeout_action": "OBSERVE_AND_NOTIFY",
            "gpu_floor_action_requires_exact_admission": True,
            "pool_network_gpu_floor_action": False,
            "actions_performed": False,
            "request_submitted": False,
        }


def _bounded_env_integer(value: object, name: str, *, maximum: int) -> int:
    if not isinstance(value, str) or len(value) > 5 or re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise ValueError(f"{name} must be a supported positive integer")
    result = int(value)
    if result > maximum:
        raise ValueError(f"{name} exceeds the supported limit")
    return result


def _unknown_decision() -> StartupRecoveryDecision:
    return StartupRecoveryDecision(
        StartupCause.UNKNOWN.value, "EARLY_UNKNOWN", "HOLD_FOR_VERIFIED_EVIDENCE", False,
    )
