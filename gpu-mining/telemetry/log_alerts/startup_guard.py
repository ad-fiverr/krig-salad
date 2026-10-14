"""Synthetic provider-log startup guard with restart-safe, local state."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any
import hashlib
import json

from .contract import DATA_CLASSIFICATION, canonical_utc
from .normalize import FIXTURE_LIFECYCLE_SOURCE, NormalizedLogEntry


STARTUP_GRACE_SECONDS = 90
_STATE_FIELDS = frozenset({
    "resource_type", "identity", "running_time_utc", "ready_time_utc",
    "running_evidence_sha256", "ready_evidence_sha256", "generation_id",
    "progress_time_utc", "progress_signal", "status", "alerted_at_utc",
    "resolved_at_utc", "last_event_time_utc", "running_source", "ready_source",
    "progress_source", "terminal_failure_time_utc", "terminal_failure_reason",
    "terminal_failure_evidence_sha256", "terminal_failure_source",
})
_LEGACY_STATE_FIELDS = _STATE_FIELDS - {
    "terminal_failure_time_utc", "terminal_failure_reason",
    "terminal_failure_evidence_sha256", "terminal_failure_source",
}


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(canonical_utc(value).replace("Z", "+00:00"))


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _complete_resource_identity(identity: Mapping[str, Any]) -> bool:
    required = (
        "organization_name", "project_name", "container_group_name",
        "machine_id", "instance_id",
    )
    return (
        identity.get("identity_status") == DATA_CLASSIFICATION
        and identity.get("identity_source") == "resource.labels"
        and all(isinstance(identity.get(field), str) and identity[field] for field in required)
    )


class StartupGuard:
    """Correlate provider lifecycle and miner progress only within one resource."""

    def process(
        self,
        entries: Sequence[NormalizedLogEntry],
        *,
        prior_states: Mapping[str, Mapping[str, Any]],
        end_time_utc: str,
    ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        end = canonical_utc(end_time_utc)
        states: dict[str, dict[str, Any]] = {}
        for resource_key, raw_state in prior_states.items():
            if not isinstance(resource_key, str) or len(resource_key) != 64 or not isinstance(raw_state, Mapping):
                continue
            if set(raw_state) == _LEGACY_STATE_FIELDS:
                raw_state = {
                    **raw_state,
                    "terminal_failure_time_utc": None,
                    "terminal_failure_reason": None,
                    "terminal_failure_evidence_sha256": None,
                    "terminal_failure_source": None,
                }
            elif set(raw_state) != _STATE_FIELDS:
                continue
            raw_identity = raw_state.get("identity")
            if not isinstance(raw_identity, Mapping) or not _complete_resource_identity(raw_identity):
                continue
            if (
                raw_state.get("running_time_utc") is not None
                and raw_state.get("running_source") != FIXTURE_LIFECYCLE_SOURCE
            ):
                continue
            if (
                raw_state.get("ready_time_utc") is not None
                and raw_state.get("ready_source") != FIXTURE_LIFECYCLE_SOURCE
            ):
                continue
            states[resource_key] = dict(raw_state)

        recovery_events: list[dict[str, Any]] = []
        for entry in entries:
            signal = entry.startup_signal
            cuda_terminal = entry.cuda_signal == "CUDA_DRIVER_INCOMPATIBLE"
            if signal is None and not cuda_terminal:
                continue
            identity = entry.identity.public_fields()
            if not _complete_resource_identity(identity):
                # A label fingerprint over partial labels is not a resource
                # identity and must never join Running/Ready/progress records.
                continue
            if (
                signal in {"INSTANCE_RUNNING", "INSTANCE_READY"}
                and entry.startup_signal_source != FIXTURE_LIFECYCLE_SOURCE
            ):
                # Raw text, including miner stdout, cannot establish provider
                # lifecycle state. Current fixtures must mark this evidence
                # explicitly and remain SYNTHETIC/UNVERIFIED.
                continue
            key_material = "\0".join((entry.resource_type, entry.identity.resource_key()))
            resource_key = _digest(key_material)
            state = states.get(resource_key)
            if state is None and cuda_terminal:
                # Without a prior provider Running event there is no local
                # allocation generation to suppress or mutate.
                continue
            public_identity = identity
            if state is None:
                state = {
                    "resource_type": entry.resource_type,
                    "identity": public_identity,
                    "running_time_utc": None,
                    "ready_time_utc": None,
                    "running_evidence_sha256": None,
                    "ready_evidence_sha256": None,
                    "running_source": None,
                    "ready_source": None,
                    "progress_source": None,
                    "generation_id": None,
                    "progress_time_utc": None,
                    "progress_signal": None,
                    "status": "OBSERVING",
                    "alerted_at_utc": None,
                    "resolved_at_utc": None,
                    "last_event_time_utc": entry.event_time_utc,
                    "terminal_failure_time_utc": None,
                    "terminal_failure_reason": None,
                    "terminal_failure_evidence_sha256": None,
                    "terminal_failure_source": None,
                }
                states[resource_key] = state
            # Identity values come only from resource.labels after alias conflict checks.
            state["identity"] = public_identity
            state["resource_type"] = entry.resource_type
            state["last_event_time_utc"] = max(
                str(state.get("last_event_time_utc") or entry.event_time_utc),
                entry.event_time_utc,
            )

            if signal == "INSTANCE_RUNNING":
                persisted_running_time = state.get("running_time_utc")
                if (
                    isinstance(persisted_running_time, str)
                    and _parse_time(entry.event_time_utc) < _parse_time(persisted_running_time)
                ):
                    # Overlapping provider queries can surface an older
                    # Running record after a newer generation is already
                    # durable. Ignore that late evidence instead of rolling
                    # the resource state back to an earlier local generation.
                    continue
                generation_material = f"{resource_key}\0{entry.event_time_utc}"
                generation_id = _digest(generation_material)
                if state.get("generation_id") != generation_id:
                    running_time = _parse_time(entry.event_time_utc)
                    prior_ready_time = state.get("ready_time_utc")
                    keep_ready = (
                        isinstance(prior_ready_time, str)
                        and _parse_time(prior_ready_time) >= running_time
                    )
                    prior_progress_time = state.get("progress_time_utc")
                    keep_progress = (
                        isinstance(prior_progress_time, str)
                        and _parse_time(prior_progress_time) >= running_time
                    )
                    # This is a local generation fingerprint derived from the
                    # provider Running record, not a provider allocation ID.
                    # Salad pages can deliver Ready (or miner progress) before
                    # Running even when timestamps describe the same/newer
                    # lifecycle instant. Preserve only evidence at or after
                    # this Running timestamp; older evidence belongs to the
                    # previous local generation and is reset.
                    state.update({
                        "running_time_utc": entry.event_time_utc,
                        "ready_time_utc": prior_ready_time if keep_ready else None,
                        "running_evidence_sha256": entry.evidence_sha256,
                        "ready_evidence_sha256": state.get("ready_evidence_sha256") if keep_ready else None,
                        "running_source": entry.startup_signal_source,
                        "ready_source": state.get("ready_source") if keep_ready else None,
                        "progress_source": state.get("progress_source") if keep_progress else None,
                        "generation_id": generation_id,
                        "progress_time_utc": prior_progress_time if keep_progress else None,
                        "progress_signal": state.get("progress_signal") if keep_progress else None,
                        "status": "OBSERVING",
                        "alerted_at_utc": None,
                        "resolved_at_utc": None,
                        "terminal_failure_time_utc": None,
                        "terminal_failure_reason": None,
                        "terminal_failure_evidence_sha256": None,
                        "terminal_failure_source": None,
                    })
            elif signal == "INSTANCE_READY":
                running = state.get("running_time_utc")
                if running is None or _parse_time(entry.event_time_utc) >= _parse_time(running):
                    state["ready_time_utc"] = entry.event_time_utc
                    state["ready_evidence_sha256"] = entry.evidence_sha256
                    state["ready_source"] = entry.startup_signal_source
            elif signal == "DEVICE_HASHRATE":
                running = state.get("running_time_utc")
                if running is not None and _parse_time(entry.event_time_utc) >= _parse_time(running):
                    prior_progress = state.get("progress_time_utc")
                    if prior_progress is None or _parse_time(entry.event_time_utc) < _parse_time(prior_progress):
                        state["progress_time_utc"] = entry.event_time_utc
                        state["progress_signal"] = signal
                        state["progress_source"] = entry.startup_signal_source
            elif cuda_terminal:
                running = state.get("running_time_utc")
                if running is not None and _parse_time(entry.event_time_utc) >= _parse_time(running):
                    previous_terminal = state.get("terminal_failure_time_utc")
                    if (
                        previous_terminal is None
                        or _parse_time(entry.event_time_utc) < _parse_time(previous_terminal)
                    ):
                        state["terminal_failure_time_utc"] = entry.event_time_utc
                        state["terminal_failure_reason"] = "CUDA_DRIVER_VERSION_INSUFFICIENT"
                        state["terminal_failure_evidence_sha256"] = entry.evidence_sha256
                        state["terminal_failure_source"] = entry.cuda_signal_source
                    state["status"] = "CUDA_DRIVER_INCOMPATIBLE"

        events: list[dict[str, Any]] = []
        for resource_key, state in states.items():
            running = state.get("running_time_utc")
            ready = state.get("ready_time_utc")
            if not isinstance(running, str) or not isinstance(ready, str):
                continue
            start = max(_parse_time(running), _parse_time(ready))
            deadline = start + timedelta(seconds=STARTUP_GRACE_SECONDS)
            if _parse_time(end) <= deadline:
                continue
            terminal_failure = state.get("terminal_failure_time_utc")
            terminal_failure_for_generation = (
                isinstance(terminal_failure, str)
                and _parse_time(terminal_failure) >= _parse_time(running)
            )
            progress_time = state.get("progress_time_utc")
            progress_before_deadline = (
                isinstance(progress_time, str) and _parse_time(progress_time) <= deadline
            )
            if (
                not terminal_failure_for_generation
                and not progress_before_deadline
                and state.get("alerted_at_utc") is None
            ):
                state["status"] = "RUNNING_READY_BUT_MINER_NOT_STARTED"
                state["alerted_at_utc"] = canonical_utc(deadline)
                alert_state = dict(state)
                if isinstance(progress_time, str) and _parse_time(progress_time) > deadline:
                    # Snapshot startup status at the deadline. Progress may be
                    # present later in the same fetched page and is emitted as
                    # a separate recovery transition below.
                    alert_state["progress_time_utc"] = None
                    alert_state["progress_signal"] = None
                    alert_state["progress_source"] = None
                events.append(self._event(
                    event_type="RUNNING_READY_BUT_MINER_NOT_STARTED",
                    resource_key=resource_key,
                    state=alert_state,
                    event_time_utc=canonical_utc(deadline),
                    source_hash=_digest(
                        str(state.get("running_evidence_sha256") or "") + "\0" +
                        str(state.get("ready_evidence_sha256") or "") + "\0" +
                        str(state.get("generation_id") or "")
                    ),
                ))
            if (
                state.get("alerted_at_utc") is not None
                and isinstance(progress_time, str)
                and state.get("resolved_at_utc") is None
            ):
                state["status"] = "MINER_STARTUP_RECOVERED"
                # A provider log can arrive after the alert even when its event
                # timestamp falls inside the original grace period. Resolve the
                # alert on observation time; retain the source event time for
                # audit so delayed ingestion cannot leave a false alert open.
                state["resolved_at_utc"] = end
                events.append(self._event(
                    event_type="MINER_STARTUP_RECOVERED",
                    resource_key=resource_key,
                    state=state,
                    event_time_utc=end,
                    source_hash=_digest(
                        str(state.get("generation_id") or "") + "\0" +
                        str(state.get("progress_signal") or "") + "\0" + progress_time
                    ),
                ))
            elif progress_before_deadline and not terminal_failure_for_generation:
                state["status"] = "STARTUP_PROGRESS_OBSERVED"
        return events, states

    @staticmethod
    def _event(
        *, event_type: str, resource_key: str, state: Mapping[str, Any],
        event_time_utc: str, source_hash: str,
    ) -> dict[str, Any]:
        event_fields = {
            "grace_seconds": STARTUP_GRACE_SECONDS,
            "running_time_utc": state.get("running_time_utc"),
            "ready_time_utc": state.get("ready_time_utc"),
            "progress_signal": state.get("progress_signal"),
            "progress_event_time_utc": state.get("progress_time_utc"),
            "running_source": state.get("running_source"),
            "ready_source": state.get("ready_source"),
            "progress_source": state.get("progress_source"),
            "generation_fingerprint_scope": "LOCAL_PROVIDER_RUNNING_LOG",
            "actions_performed": False,
        }
        if event_type == "RUNNING_READY_BUT_MINER_NOT_STARTED":
            ready_time = _parse_time(str(state["ready_time_utc"]))
            deadline = _parse_time(event_time_utc)
            event_fields.update({
                "provider_state": "Running / Ready",
                "miner_started": False,
                "gpu_detected": False,
                "hashrate_samples": 0,
                "elapsed_since_ready_seconds": max(0, int((deadline - ready_time).total_seconds())),
                "recommendation": "REALLOCATE",
            })
        return {
            "data_classification": DATA_CLASSIFICATION,
            "event_type": event_type,
            "resource_key": resource_key,
            "resource_type": state["resource_type"],
            "identity": dict(state["identity"]),
            "event_time_utc": event_time_utc,
            "generation_id": state.get("generation_id"),
            "source_evidence_sha256": source_hash,
            "event_fields": event_fields,
            "actions_performed": False,
        }


def sanitize_startup_state(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return only allowlisted scalar state; raw resource labels are forbidden."""
    if not isinstance(value, Mapping) or set(value) != _STATE_FIELDS:
        raise ValueError("startup state contains unsupported fields")
    identity = value.get("identity")
    if not isinstance(identity, Mapping):
        raise ValueError("startup state identity is malformed")
    allowed_identity = {
        "identity_status", "machine_id", "instance_id", "container_group_name",
        "organization_name", "project_name", "identity_source",
    }
    if set(identity) - allowed_identity:
        raise ValueError("startup state identity contains unsupported fields")
    if identity.get("identity_status") not in {"SYNTHETIC/UNVERIFIED", "UNKNOWN", "CONFLICTING"}:
        raise ValueError("startup state identity status is invalid")
    for key, item in identity.items():
        if item is not None and (not isinstance(item, str) or len(item) > 128 or any(ord(c) < 32 for c in item)):
            raise ValueError("startup state identity value is invalid")
    if identity.get("identity_source") not in {"resource.labels", "resource.labels:unknown"}:
        raise ValueError("startup state identity source is invalid")
    safe = dict(value)
    safe["identity"] = dict(identity)
    for key in ("resource_type", "status", "progress_signal"):
        item = safe.get(key)
        if item is not None and (not isinstance(item, str) or len(item) > 128):
            raise ValueError("startup state text is invalid")
    for key in (
        "running_evidence_sha256", "ready_evidence_sha256", "generation_id",
        "terminal_failure_evidence_sha256",
    ):
        item = safe.get(key)
        if item is not None and (not isinstance(item, str) or len(item) != 64 or any(c not in "0123456789abcdef" for c in item)):
            raise ValueError("startup state digest is invalid")
    for key in (
        "running_time_utc", "ready_time_utc", "progress_time_utc", "alerted_at_utc",
        "resolved_at_utc", "last_event_time_utc", "terminal_failure_time_utc",
    ):
        if safe.get(key) is not None:
            safe[key] = canonical_utc(safe[key])
    if safe.get("status") not in {
        "OBSERVING", "STARTUP_PROGRESS_OBSERVED", "RUNNING_READY_BUT_MINER_NOT_STARTED",
        "MINER_STARTUP_RECOVERED", "CUDA_DRIVER_INCOMPATIBLE",
    }:
        raise ValueError("startup state status is invalid")
    if safe.get("terminal_failure_reason") not in {
        None, "CUDA_DRIVER_VERSION_INSUFFICIENT",
    }:
        raise ValueError("startup terminal failure reason is invalid")
    if safe.get("progress_signal") in {"MONITOR_CONFIG", "GPU_DETECTED", "DEVICE_INITIALIZED"}:
        # Older local state may have recorded configuration/GPU initialization
        # as progress. Migrate it to no progress so only a positive Device
        # hashRate sample can satisfy the startup guard.
        safe["progress_time_utc"] = None
        safe["progress_signal"] = None
        safe["progress_source"] = None
    if safe.get("progress_signal") not in {None, "DEVICE_HASHRATE"}:
        raise ValueError("startup progress signal is invalid")
    for key in ("running_source", "ready_source", "progress_source", "terminal_failure_source"):
        if safe.get(key) not in {
            None, "text_log", "structured_message", "text_log+structured_message",
            FIXTURE_LIFECYCLE_SOURCE,
        }:
            raise ValueError("startup evidence source is invalid")
    return json.loads(json.dumps(safe, sort_keys=True, separators=(",", ":"), allow_nan=False))
