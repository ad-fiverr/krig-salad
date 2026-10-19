"""Read-only bridge from bounded normalized logs to startup-admission summaries.

Provider labels alone never create a workload binding. Salad log text can
identify an early signal, but without CSV source references, policy evidence,
generation binding and empirical calibration the decision remains UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import math
import re
from typing import Any, Mapping

from collector.fl4sh_early_autotune import EarlyEvaluationContext, EarlyObservation
from collector.fl4shminer import _classify
from collector.startup_admission import StartupAdmissionEngine

from .contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED, canonical_utc
from .normalize import MAX_TEXT_LOG_CHARS, NormalizedLogEntry


_GPU_NAME_RE = re.compile(
    r"NVIDIA +(?P<geforce>GeForce +)?(?P<name>[A-Za-z0-9]+(?:[ _-]+[A-Za-z0-9]+)*)",
    re.IGNORECASE,
)
_GPU_KEY_RE = re.compile(r"[A-Z0-9]+(?:_[A-Z0-9]+)*\Z")
_MODEL_ONLY_TOKENS = frozenset({"NVIDIA", "GEFORCE", "GPU", "UNKNOWN", "SERIES", "FAMILY"})
_FORM_FACTOR_TOKENS = frozenset({"LAPTOP", "NOTEBOOK", "MOBILE", "DESKTOP"})
_SAFE_REASON_RE = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")

CAUSE_CODES = frozenset({
    "LOW_AUTOTUNE", "POOL_AUTH_TIMEOUT", "NETWORK_FAILURE", "CUDA_INCOMPATIBLE",
    "NO_GPU", "NO_POSITIVE_HASHRATE", "PROCESS_EXIT", "PROVIDER_PREEMPTION", "UNKNOWN",
})


def normalize_observed_gpu_key(raw_name: Any) -> str | None:
    """Canonicalize an explicit NVIDIA model without inventing form factor."""
    if (
        not isinstance(raw_name, str) or not 1 <= len(raw_name) <= 256
        or any(ord(char) < 32 or ord(char) > 126 for char in raw_name)
    ):
        return None
    match = _GPU_NAME_RE.fullmatch(raw_name.strip())
    if match is None:
        return None
    name = match.group("name").upper()
    tokens = re.split(r"[ _-]+", name)
    if tokens and tokens[-1] == "GPU":
        tokens.pop()
    if not tokens or any(token in _MODEL_ONLY_TOKENS for token in tokens):
        return None
    if sum(bool(re.search(r"[0-9]", word)) for word in name.split()) != 1 or tokens.count("RTX") > 1:
        return None
    forms = [token for token in tokens if token in _FORM_FACTOR_TOKENS]
    if len(forms) > 1:
        return None
    suffix: list[str] = []
    if forms:
        suffix.append("LAPTOP" if forms[0] in {"LAPTOP", "NOTEBOOK", "MOBILE"} else "DESKTOP")
        tokens = [token for token in tokens if token not in _FORM_FACTOR_TOKENS]
    key = "_".join(tokens + suffix)
    return key if len(key) <= 128 and _GPU_KEY_RE.fullmatch(key) else None


@dataclass(frozen=True, slots=True)
class StartupEarlyEvent:
    state: str
    reason: str
    cause: str
    signal_type: str | None
    device_index: int | None
    gpu_key: str | None
    estimate_ths: float | None
    floor_ths: float | None
    event_time_utc: str
    data_classification: str
    actions_performed: bool = False
    request_submitted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "cause": self.cause,
            "signal_type": self.signal_type,
            "device_index": self.device_index,
            "gpu_key": self.gpu_key,
            "estimate_ths": self.estimate_ths,
            "floor_ths": self.floor_ths,
            "event_time_utc": self.event_time_utc,
            "data_classification": self.data_classification,
            "actions_performed": False,
            "request_submitted": False,
        }


class StartupEarlyBridge:
    """Classify only existing exact log grammars; never changes alert state."""

    def __init__(self, engine: StartupAdmissionEngine | None = None) -> None:
        self.engine = engine or StartupAdmissionEngine()
        if type(self.engine) is not StartupAdmissionEngine:
            raise TypeError("startup bridge requires the existing admission engine")

    def inspect(
        self,
        entry: NormalizedLogEntry,
        context: EarlyEvaluationContext | None = None,
    ) -> StartupEarlyEvent | None:
        if type(entry) is not NormalizedLogEntry:
            raise TypeError("startup bridge accepts only normalized log evidence")
        if entry.data_classification not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}:
            return None
        event_time = canonical_utc(entry.event_time_utc)

        if entry.cuda_signal == "CUDA_DRIVER_INCOMPATIBLE":
            return self._event(
                state="STARTUP_UNQUALIFIED", reason="CUDA_DRIVER_VERSION_INSUFFICIENT",
                cause="CUDA_INCOMPATIBLE", event_time=event_time,
                classification=entry.data_classification,
            )
        if entry.alert is not None and entry.alert.event_type in {"POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE"}:
            if entry.alert.fields.get("reason") == "MINING_AUTHORIZE_RESPONSE_TIMEOUT":
                return self._event(
                    state="STARTUP_NON_GPU_CAUSE", reason="POOL_AUTH_TIMEOUT",
                    cause="POOL_AUTH_TIMEOUT", event_time=event_time,
                    classification=entry.data_classification,
                )
        if entry.alert is not None and entry.alert.event_type == "MINER_STARTUP_HASHRATE_TIMEOUT":
            reason = entry.alert.fields.get("reason")
            cause = {
                "NO_POSITIVE_DEVICE_HASHRATE": "NO_POSITIVE_HASHRATE",
                "MINER_EXITED_BEFORE_HASHRATE": "PROCESS_EXIT",
            }.get(reason, "UNKNOWN")
            return self._event(
                state="STARTUP_NON_GPU_CAUSE", reason=cause, cause=cause,
                event_time=event_time, classification=entry.data_classification,
            )

        message = self._message(entry)
        if message is None:
            return None
        parsed = _classify(message)
        if not isinstance(parsed, tuple) or len(parsed) != 2:
            return None
        event_type, payload = parsed
        if event_type != "hashrate_estimate" or not isinstance(payload, Mapping):
            return None
        signal_type = payload.get("early_signal_type")
        if signal_type not in {"CUDA_POOL_EQUIVALENT", "PEARL_AUTOTUNE"}:
            return None
        device_value = payload.get("device_id")
        device_index = int(device_value) if isinstance(device_value, str) and device_value.isdigit() else None
        estimate = payload.get("hashrate_ths")
        if type(estimate) not in {int, float} or not math.isfinite(float(estimate)) or not 0 < estimate <= 10_000:
            estimate = None
        model = payload.get("reported_gpu_model_label")
        gpu_key = normalize_observed_gpu_key(model) if isinstance(model, str) else None
        timestamp = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        observation = EarlyObservation(
            signal_type=signal_type,
            device_index=device_index,
            gpu_key=gpu_key,
            estimate_ths=float(estimate) if estimate is not None else None,
            event_time_utc=timestamp,
            policy_hash=None,
            source="FL4SHMINER_AUTOTUNE_LOG",
        )
        decision = self.engine.evaluate(observation, context)
        reason = decision.reason if _SAFE_REASON_RE.fullmatch(decision.reason) else "UNSAFE_DECISION_REASON"
        cause = "LOW_AUTOTUNE" if decision.state == "EARLY_UNDER_FLOOR" else "UNKNOWN"
        return StartupEarlyEvent(
            state=decision.state,
            reason=reason,
            cause=cause,
            signal_type=signal_type,
            device_index=device_index,
            gpu_key=gpu_key,
            estimate_ths=float(estimate) if estimate is not None else None,
            floor_ths=decision.floor_ths,
            event_time_utc=event_time,
            data_classification=entry.data_classification,
        )

    @staticmethod
    def _message(entry: NormalizedLogEntry) -> str | None:
        candidates: list[str] = []
        if isinstance(entry.text_log, str):
            candidates.append(entry.text_log)
        structured = entry.structured_message
        if isinstance(structured, str):
            candidates.append(structured)
        elif isinstance(structured, Mapping):
            for key in ("message", "text"):
                value = structured.get(key)
                if isinstance(value, str):
                    candidates.append(value)
        if not candidates or any(len(item) > MAX_TEXT_LOG_CHARS for item in candidates):
            return None
        distinct = set(candidates)
        return candidates[0] if len(distinct) == 1 else None

    @staticmethod
    def _event(*, state: str, reason: str, cause: str, event_time: str,
               classification: str) -> StartupEarlyEvent:
        if cause not in CAUSE_CODES:
            cause = "UNKNOWN"
        return StartupEarlyEvent(
            state=state,
            reason=reason if _SAFE_REASON_RE.fullmatch(reason) else "UNKNOWN",
            cause=cause,
            signal_type=None,
            device_index=None,
            gpu_key=None,
            estimate_ths=None,
            floor_ths=None,
            event_time_utc=event_time,
            data_classification=classification,
        )
