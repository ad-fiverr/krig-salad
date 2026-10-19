"""Incremental, restartable, dry-run-only continuous GPU health monitor."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Protocol

from .gpu_identity import normalize_gpu_identity
from .guard_store import GuardStore, canonical_utc
from .guards import HashGuardPolicy, evaluate_hash_floor


class ReallocationActionAdapter(Protocol):
    """Future provider boundary; V2 contains no authenticated implementation."""

    enabled: bool

    def request_reallocation(self, recommendation: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return an action receipt; implementations must be separately authorized."""


class DisabledReallocationActionAdapter:
    """Safe default used by offline workflows; it never invokes a provider."""

    enabled = False

    def request_reallocation(self, recommendation: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            "status": "DISABLED",
            "actions_performed": False,
            "track_id": recommendation.get("track_id"),
            "reason": "real Salad reallocation is outside this offline iteration",
        }


def _policy_hash(policy: HashGuardPolicy) -> str:
    encoded = json.dumps(asdict(policy), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    parsed = value.astimezone(timezone.utc)
    return parsed.isoformat(timespec="microseconds" if parsed.microsecond else "seconds").replace("+00:00", "Z")


def _elapsed(start: str, current: str) -> float:
    return (_parse_utc(current) - _parse_utc(start)).total_seconds()


class ContinuousMonitor:
    """Consume normalized events and repeatedly evaluate existing Guard V1 rules."""

    TERMINAL_STATES = {"stopped", "preempted", "lost", "terminated", "reallocated", "allocation_terminated"}

    def __init__(self, store: GuardStore, policy: HashGuardPolicy):
        self.store = store
        self.policy = policy
        self.policy_hash = _policy_hash(policy)

    def ingest(self, events: Iterable[Mapping[str, Any]], *, evaluate: bool = True) -> dict[str, Any]:
        ordered = sorted(
            (dict(event) for event in events),
            key=lambda item: (
                str(item.get("occurred_at_utc") or item.get("observed_at_utc") or ""),
                0 if item.get("event_type") in {"provider_lifecycle_observation", "readiness_observation", "allocation_lifecycle", "gpu_device_mapping_ambiguous"} else 1,
                str(item.get("event_id") or ""),
            ),
        )
        inserted_samples = 0
        duplicate_samples = 0
        lifecycle_count = 0
        identity_invalidations = 0
        evaluations: list[dict[str, Any]] = []
        terminated: list[str] = []
        for event in ordered:
            event_type = event.get("event_type")
            if event_type in {"gpu_sample", "device_hashrate_sample"}:
                outcome = self.store.ingest_observation(event)
                if outcome["inserted"]:
                    inserted_samples += 1
                    if outcome.get("replaced_track_id"):
                        terminated.append(outcome["replaced_track_id"])
                    if evaluate:
                        current_track = self.store.get_track(outcome["track_id"])
                        evaluation = self.evaluate_track(outcome["track_id"], current_track["latest_sample_utc"])
                        if evaluation is not None:
                            evaluations.append(evaluation)
                else:
                    duplicate_samples += 1
            elif event_type in {"provider_lifecycle_observation", "readiness_observation", "allocation_lifecycle"}:
                lifecycle = self.store.ingest_lifecycle(event)
                lifecycle_count += int(lifecycle["inserted"])
                state = str(event.get("reported_state") or "").casefold()
                if lifecycle["inserted"] and state in self.TERMINAL_STATES:
                    terminated.extend(
                        track["track_id"] for track in self.store.track_rows()
                        if track["closed_at_utc"] == canonical_utc(event.get("occurred_at_utc"))
                        and track["terminal_reason"] == f"provider_lifecycle:{state}"
                    )
            elif event_type == "gpu_device_mapping_ambiguous":
                identity_invalidations += self.store.invalidate_assignment_gpu_identity(event)
            elif event_type == "reallocation_confirmed":
                timestamp = canonical_utc(event.get("occurred_at_utc"))
                track_id = event.get("track_id")
                if not isinstance(track_id, str) or not track_id:
                    raise ValueError("reallocation_confirmed event requires the exact affected track_id")
                self.store.confirm_reallocation(track_id, timestamp, event)
            else:
                raise ValueError(f"unsupported continuous-monitor event_type: {event_type!r}")
        return {
            "inserted_sample_count": inserted_samples,
            "duplicate_sample_count": duplicate_samples,
            "lifecycle_event_count": lifecycle_count,
            "identity_invalidated_track_count": identity_invalidations,
            "terminated_track_ids": sorted(set(terminated)),
            "evaluations": evaluations,
            "actions_performed": False,
        }

    def evaluate_track(self, track_id: str, at_utc: Any) -> dict[str, Any] | None:
        timestamp = canonical_utc(at_utc)
        track = self.store.get_track(track_id)
        if track is None or track["closed_at_utc"] is not None:
            return None
        start = track["started_at_utc"]
        elapsed_now = _elapsed(start, timestamp)
        if elapsed_now < 0:
            raise ValueError("evaluation time precedes the assignment start")

        first_eval = (self.policy.warmup_seconds or 0) + (self.policy.hash_window_seconds or 0)
        interval = self.policy.reevaluation_interval_seconds or self.policy.hash_window_seconds or 1
        last_elapsed = track.get("last_evaluation_elapsed")
        due = elapsed_now >= first_eval if last_elapsed is None else elapsed_now - float(last_elapsed) >= interval
        if not due:
            return None

        identity = json.loads(track["gpu_identity_json"])
        normalized = normalize_gpu_identity(
            identity.get("raw_model"),
            identity_source=identity.get("identity_source"),
            identity_verified=identity.get("identity_verified"),
            reported_form_factor=identity.get("form_factor"),
        )
        evaluation_policy = self.policy
        window_offset = 0.0
        guard_now_elapsed = elapsed_now
        if all(value is not None for value in (
            self.policy.warmup_seconds,
            self.policy.hash_window_seconds,
            self.policy.expected_sample_interval_seconds,
            self.policy.maximum_sample_gap_seconds,
            self.policy.consecutive_bad_windows,
        )):
            stride = self.policy.reevaluation_interval_seconds or self.policy.hash_window_seconds
            first_end = self.policy.warmup_seconds + self.policy.hash_window_seconds
            slot = max(0, math.floor((elapsed_now - first_end) / stride))
            latest_window_start = self.policy.warmup_seconds + slot * stride
            required_history = max(1, self.policy.consecutive_bad_windows)
            window_offset = max(
                float(self.policy.warmup_seconds),
                float(latest_window_start - (required_history - 1) * stride),
            )
            sample_floor = max(0.0, window_offset - self.policy.maximum_sample_gap_seconds)
            samples = [
                {**sample, "elapsed_seconds": float(sample["elapsed_seconds"]) - window_offset}
                for sample in self.store.samples_for_track(track_id, since_elapsed_seconds=sample_floor)
            ]
            evaluation_policy = replace(self.policy, warmup_seconds=0)
            guard_now_elapsed = elapsed_now - window_offset
        else:
            samples = self.store.samples_for_track(track_id)
        previous_health = track.get("hash_health") or "UNKNOWN"
        if not track["start_anchor_verified"]:
            result = {
                "decision": "INSUFFICIENT_DATA",
                "reason": "verified allocation or worker-start anchor is required to evaluate warmup and lifetime windows",
                "details": {"hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA", "gpu_floor_ths": None},
            }
        else:
            elapsed_since_reallocation = None
            if track.get("last_reallocation_utc"):
                elapsed_since_reallocation = _elapsed(track["last_reallocation_utc"], timestamp)
            guard = evaluate_hash_floor(
                identity.get("raw_model") or "UNKNOWN",
                samples,
                evaluation_policy,
                reallocations_per_run=track.get("reallocation_count") if track.get("reallocation_history_known") else None,
                gpu_identity=identity,
                seconds_since_last_reallocation=elapsed_since_reallocation,
                now_elapsed_seconds=guard_now_elapsed,
            )
            result = guard.to_dict()

        details = result.get("details", {})
        if window_offset:
            for window in details.get("windows", []):
                if isinstance(window.get("start_seconds"), (int, float)):
                    window["start_seconds"] += window_offset
                if isinstance(window.get("end_seconds"), (int, float)):
                    window["end_seconds"] += window_offset
            details["evaluation_window_offset_seconds"] = window_offset
        details["machine_id"] = track.get("machine_id")
        details["instance_id"] = track.get("instance_id")
        details["allocation_id"] = track.get("allocation_id")
        details["assignment_id"] = track.get("assignment_id")
        details["track_id"] = track_id
        details["verified_gpu_identity"] = normalized
        details["reallocation_history"] = {
            "known": bool(track.get("reallocation_history_known")),
            "count": track.get("reallocation_count"),
            "last_reallocation_utc": track.get("last_reallocation_utc"),
        }
        details["policy"] = {
            "policy_hash": self.policy_hash,
            "warmup_seconds": self.policy.warmup_seconds,
            "hash_window_seconds": self.policy.hash_window_seconds,
            "reevaluation_interval_seconds": self.policy.reevaluation_interval_seconds,
            "expected_sample_interval_seconds": self.policy.expected_sample_interval_seconds,
            "maximum_sample_gap_seconds": self.policy.maximum_sample_gap_seconds,
            "minimum_window_coverage_ratio": self.policy.minimum_window_coverage_ratio,
            "consecutive_bad_windows": self.policy.consecutive_bad_windows,
            "reallocation_cooldown_seconds": self.policy.reallocation_cooldown_seconds,
            "max_reallocations_per_run": self.policy.max_reallocations_per_run,
        }
        details["actions_performed"] = False

        windows = details.get("windows") if isinstance(details.get("windows"), list) else []
        last_window = windows[-1] if windows else {}
        health = details.get("hash_health", "UNKNOWN")
        below = health == "BELOW_CONFIGURED_FLOOR"
        if below and not track.get("deterioration_start_utc"):
            bad_windows = [window for window in windows if window.get("valid") and window.get("below_floor") is True]
            first_bad = bad_windows[-int(details.get("consecutive_bad_windows_observed") or 1)] if bad_windows else last_window
            offset = first_bad.get("start_seconds")
            deterioration_start = _utc_text(_parse_utc(start) + timedelta(seconds=float(offset))) if isinstance(offset, (int, float)) else timestamp
            self.store.update_track_deterioration(track_id, deterioration_start)
            details["deterioration_start_utc"] = deterioration_start
            self.store.append_audit(
                track_id, "FLOOR_BREACH_DETECTED", timestamp,
                self._audit_payload(track, details, result, timestamp),
                dedupe_key=f"floor-breach:{track_id}:{deterioration_start}",
            )
        else:
            details["deterioration_start_utc"] = track.get("deterioration_start_utc")

        deterioration_start = details.get("deterioration_start_utc")
        if below and details.get("consecutive_bad_windows_observed", 0) >= (self.policy.consecutive_bad_windows or 1):
            self.store.append_audit(
                track_id, "SUSTAINED_LOW_HASHRATE", timestamp,
                self._audit_payload(track, details, result, timestamp),
                dedupe_key=f"sustained-low:{track_id}:{deterioration_start}",
            )
        if previous_health == "BELOW_CONFIGURED_FLOOR" and health == "MEETS_CONFIGURED_FLOOR":
            self.store.append_audit(
                track_id, "HASHRATE_RECOVERED", timestamp,
                self._audit_payload(track, details, result, timestamp),
                dedupe_key=f"hashrate-recovered:{track_id}:{timestamp}",
            )
            self.store.update_track_deterioration(track_id, None)
        if result.get("decision") == "WOULD_REALLOCATE":
            reallocation_generation = track.get("reallocation_count") if track.get("reallocation_history_known") else "unknown"
            recommendation_key = f"reallocation-recommended:{track_id}:{deterioration_start}:{reallocation_generation}:{self.policy_hash}"
            if self.store.has_audit(recommendation_key):
                result["decision"] = "WOULD_WAIT"
                result["reason"] = "the same deterioration already has a dry-run recommendation; waiting for recovery or confirmed assignment change"
                details["recommended_action"] = "WAIT"
                details["recommendation_deduplicated"] = True
            else:
                self.store.append_audit(
                    track_id, "REALLOCATION_RECOMMENDED", timestamp,
                    self._audit_payload(track, details, result, timestamp),
                    dedupe_key=recommendation_key,
                )

        result["details"] = details
        inserted = self.store.add_evaluation(track_id, timestamp, elapsed_now, self.policy_hash, result)
        if not inserted:
            return None
        return {
            "track_id": track_id,
            "evaluated_at_utc": timestamp,
            "decision": result.get("decision"),
            "hash_health": health,
            "machine_id": track.get("machine_id"),
            "instance_id": track.get("instance_id"),
            "gpu_identity": normalized,
            "gpu_floor_ths": details.get("gpu_floor_ths"),
            "observed_window_hashrate_ths": last_window.get("mean_hashrate_ths"),
            "deterioration_start_utc": details.get("deterioration_start_utc"),
            "deterioration_duration_seconds": max(0.0, _elapsed(details["deterioration_start_utc"], timestamp)) if details.get("deterioration_start_utc") else None,
            "sample_quality": {
                "coverage_ratio": last_window.get("coverage_ratio"),
                "sample_count": last_window.get("sample_count"),
                "maximum_observed_gap_seconds": last_window.get("maximum_observed_gap_seconds"),
            },
            "reallocation_history": details["reallocation_history"],
            "reason": result.get("reason"),
            "provenance": json.loads(track["provenance_json"]),
            "actions_performed": False,
        }

    def evaluate_all(self, at_utc: Any | None = None) -> list[dict[str, Any]]:
        timestamp = canonical_utc(at_utc) if at_utc is not None else self.store.latest_sample_timestamp()
        if timestamp is None:
            return []
        results: list[dict[str, Any]] = []
        for track in self.store.track_rows(active_only=True):
            evaluation = self.evaluate_track(track["track_id"], timestamp)
            if evaluation is not None:
                results.append(evaluation)
        return results

    @staticmethod
    def _audit_payload(track: Mapping[str, Any], details: Mapping[str, Any], result: Mapping[str, Any], timestamp: str) -> dict[str, Any]:
        windows = details.get("windows") if isinstance(details.get("windows"), list) else []
        last_window = windows[-1] if windows else {}
        deterioration_start = details.get("deterioration_start_utc")
        duration = _elapsed(deterioration_start, timestamp) if isinstance(deterioration_start, str) else None
        return {
            "machine_id": track.get("machine_id"),
            "instance_id": track.get("instance_id"),
            "allocation_id": track.get("allocation_id"),
            "assignment_id": track.get("assignment_id"),
            "verified_gpu_identity": details.get("verified_gpu_identity"),
            "gpu_floor_ths": details.get("gpu_floor_ths"),
            "observed_average_ths": last_window.get("mean_hashrate_ths"),
            "window_start_seconds": last_window.get("start_seconds"),
            "window_end_seconds": last_window.get("end_seconds"),
            "deterioration_start_utc": deterioration_start,
            "deterioration_duration_seconds": duration,
            "sample_quality": {
                "coverage_ratio": last_window.get("coverage_ratio"),
                "sample_count": last_window.get("sample_count"),
                "maximum_observed_gap_seconds": last_window.get("maximum_observed_gap_seconds"),
            },
            "reallocation_history": details.get("reallocation_history"),
            "decision": result.get("decision"),
            "reason": result.get("reason"),
            "provenance": json.loads(track["provenance_json"]),
            "actions_performed": False,
        }


_PROJECTION_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROJECTION_POLICY_HASH_RE = re.compile(r"^[a-f0-9]{64}$")


def _projection_number(value: Any, *, minimum: float | None = None, maximum: float | None = None) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(number) or (minimum is not None and number < minimum) or (maximum is not None and number > maximum):
        return None
    return value


def _projection_id(value: Any) -> str | None:
    if not isinstance(value, str) or not _PROJECTION_IDENTIFIER_RE.fullmatch(value):
        return None
    return value


def _projection_time(value: Any) -> str | None:
    try:
        return canonical_utc(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _projection_ref(kind: str, value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 1024:
        return None
    digest = hashlib.sha256((kind + "\0" + value).encode("utf-8", "replace")).hexdigest()[:32]
    return f"{kind}_{digest}"


def _projection_gpu_identity(raw: Any) -> tuple[str | None, str]:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 4096:
        return None, "UNKNOWN"
    try:
        identity = json.loads(raw)
    except (TypeError, ValueError):
        return None, "UNKNOWN"
    if not isinstance(identity, Mapping):
        return None, "UNKNOWN"
    normalized = normalize_gpu_identity(
        identity.get("raw_model"),
        identity_source=identity.get("identity_source"),
        identity_verified=identity.get("identity_verified"),
        reported_form_factor=identity.get("form_factor"),
    )
    if normalized.get("identity_verified") is not True:
        return None, "UNKNOWN"
    model = normalized.get("model")
    form = normalized.get("form_factor")
    if not isinstance(model, str) or form not in {"laptop", "desktop"}:
        return None, "UNKNOWN"
    model_key = re.sub(r"[^A-Z0-9]+", "_", model.upper()).strip("_")
    return (f"{model_key}_{form.upper()}", "EXACT_LOCAL_IDENTITY") if model_key else (None, "UNKNOWN")


def _track_identity_projection(
    row: Mapping[str, Any], binding_by_track: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    track_id = row.get("track_id")
    track_ref = _projection_ref("track", track_id)
    result = {
        "track_ref": track_ref,
        "generation_ref": track_ref,
        "generation_scope": "LOCAL_MONITOR_TRACK" if track_ref else "UNKNOWN",
        "identity_status": "UNKNOWN",
        "identity_source": "NONE",
        "machine_id": None,
        "instance_id": None,
        "container_group_id": None,
    }
    binding = binding_by_track.get(track_id) if isinstance(track_id, str) else None
    if not isinstance(binding, Mapping):
        return result
    status = binding.get("binding_status")
    if status == "CONFLICTING":
        result["identity_status"] = "CONFLICTING"
        return result
    if status != "VERIFIED":
        if status == "SYNTHETIC/UNVERIFIED":
            result["identity_status"] = "SYNTHETIC_UNVERIFIED"
        return result
    provider = binding.get("provider") if isinstance(binding.get("provider"), Mapping) else {}
    assignment = binding.get("assignment") if isinstance(binding.get("assignment"), Mapping) else {}
    machine_id = _projection_id(row.get("machine_id"))
    instance_id = _projection_id(row.get("instance_id"))
    assignment_id = _projection_id(row.get("assignment_id"))
    provider_group = _projection_id(provider.get("container_group_id"))
    assignment_group = _projection_id(assignment.get("container_group_id"))
    exact = bool(machine_id and instance_id and assignment_id) and all((
        provider.get("machine_id") == machine_id,
        assignment.get("machine_id") == machine_id,
        provider.get("instance_id") == instance_id,
        assignment.get("instance_id") == instance_id,
        provider.get("assignment_id") == assignment_id,
        assignment.get("assignment_id") == assignment_id,
        provider_group is not None,
        assignment_group == provider_group,
    ))
    if not exact:
        result["identity_status"] = "CONFLICTING"
        return result
    result.update({
        "identity_status": "VERIFIED",
        "identity_source": "INDEPENDENT_PROVIDER_ASSIGNMENT_BINDING",
        "machine_id": machine_id,
        "instance_id": instance_id,
        "container_group_id": provider_group,
    })
    return result


def _provider_label_identity(row: Mapping[str, Any]) -> dict[str, Any]:
    if row.get("provider_label_source_valid") is not True:
        return {
            "identity_status": "UNKNOWN",
            "identity_source": "NONE",
            "machine_id": None,
            "instance_id": None,
            "container_group_name": None,
        }
    labels = row.get("provider_identity_labels")
    labels = labels if isinstance(labels, Mapping) else {}
    raw_machine_label = labels.get("Resource labels machine id")
    raw_instance_label = labels.get("Resource labels instance id")
    machine_label = _projection_id(raw_machine_label)
    instance_label = _projection_id(raw_instance_label)
    stored_machine = _projection_id(row.get("machine_id"))
    stored_instance = _projection_id(row.get("instance_id"))
    group_name = _projection_id(labels.get("Resource labels container group name"))
    if (raw_machine_label is not None and machine_label is None) or (raw_instance_label is not None and instance_label is None):
        return {
            "identity_status": "CONFLICTING",
            "identity_source": "NONE",
            "machine_id": None,
            "instance_id": None,
            "container_group_name": None,
        }
    if machine_label and instance_label:
        if machine_label != stored_machine or instance_label != stored_instance:
            status = "CONFLICTING"
            machine_id = instance_id = None
        else:
            status = "PROVIDER_LABELS_PRESENT_UNVERIFIED_SEMANTICS"
            machine_id, instance_id = machine_label, instance_label
    elif machine_label or instance_label or stored_machine or stored_instance:
        status = "UNKNOWN"
        machine_id = instance_id = None
    else:
        status = "UNKNOWN"
        machine_id = instance_id = None
    return {
        "identity_status": status,
        "identity_source": "PROVIDER_RESOURCE_LABELS" if status == "PROVIDER_LABELS_PRESENT_UNVERIFIED_SEMANTICS" else "NONE",
        "machine_id": machine_id,
        "instance_id": instance_id,
        "container_group_name": group_name if machine_id is not None else None,
    }


def fleet_monitor_event_feed(
    store: GuardStore,
    *,
    limit: int = 100,
    binding_by_track: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Project a bounded, sanitized, restart-stable local monitor event feed."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise ValueError("monitor event feed limit must be between 1 and 100")
    bindings = binding_by_track if isinstance(binding_by_track, Mapping) else {}
    rows = store.monitor_projection_rows(limit=limit)
    events: list[dict[str, Any]] = []

    def base_event(
        *, kind: str, source_id: Any, occurred_at: Any, track_row: Mapping[str, Any] | None,
        event_type: str, state: str, severity: str, reason_code: str,
        source_classification: str,
    ) -> dict[str, Any]:
        row = track_row if isinstance(track_row, Mapping) else {}
        track_identity = _track_identity_projection(row, bindings) if row.get("track_id") else {
            "track_ref": None, "generation_ref": None, "generation_scope": "UNKNOWN",
            "identity_status": "UNKNOWN", "identity_source": "NONE",
            "machine_id": None, "instance_id": None, "container_group_id": None,
        }
        gpu_key, gpu_identity_status = _projection_gpu_identity(row.get("gpu_identity_json")) if row else (None, "UNKNOWN")
        event_id = _projection_ref(kind, source_id)
        return {
            "event_id": event_id,
            "event_type": event_type,
            "state": state,
            "severity": severity,
            "reason_code": reason_code,
            "occurred_at_utc": _projection_time(occurred_at),
            **track_identity,
            "gpu_key": gpu_key,
            "gpu_identity_status": gpu_identity_status,
            "evidence_classification": source_classification,
            "actions_performed": False,
        }

    decision_states = {
        "PASS": ("HEALTHY", "INFO", "AT_OR_ABOVE_CONFIGURED_FLOOR"),
        "WOULD_WAIT": ("DEGRADED", "WARNING", "BELOW_FLOOR_WINDOW_THRESHOLD_PENDING"),
        "WOULD_REALLOCATE": ("DEGRADED", "ALERT", "SUSTAINED_BELOW_CONFIGURED_FLOOR"),
        "WOULD_STOP": ("DEGRADED", "ALERT", "REALLOCATION_LIMIT_REACHED"),
        "TELEMETRY_STALE": ("STALE", "WARNING", "MAXIMUM_SAMPLE_GAP_EXCEEDED"),
        "NO_FLOOR_CONFIGURED": ("NO_FLOOR_CONFIGURED", "WARNING", "EXACT_GPU_FLOOR_MISSING"),
        "INSUFFICIENT_DATA": ("UNKNOWN", "INFO", "INSUFFICIENT_OR_INVALID_WINDOW_EVIDENCE"),
    }
    latest_evaluation_by_track: set[str] = set()
    for row in rows["evaluations"]:
        track_id = row.get("track_id")
        if not isinstance(track_id, str) or track_id in latest_evaluation_by_track:
            continue
        latest_evaluation_by_track.add(track_id)
        decision = row.get("decision")
        mapped = decision_states.get(decision)
        if mapped is None:
            continue
        state, severity, reason = mapped
        event = base_event(
            kind="evaluation", source_id=row.get("evaluation_id"), occurred_at=row.get("evaluated_at_utc"),
            track_row=row, event_type="MONITOR_EVALUATION", state=state, severity=severity,
            reason_code=reason, source_classification="LOCAL_CONTINUOUS_MONITOR_EVALUATION",
        )
        details = row.get("details") if isinstance(row.get("details"), Mapping) else {}
        last_window = details.get("last_window") if isinstance(details.get("last_window"), Mapping) else {}
        event.update({
            "policy_hash": row.get("policy_hash") if isinstance(row.get("policy_hash"), str) and _PROJECTION_POLICY_HASH_RE.fullmatch(row["policy_hash"]) else None,
            "decision_code": decision,
            "hash_health": row.get("hash_health") if row.get("hash_health") in {"MEETS_CONFIGURED_FLOOR", "BELOW_CONFIGURED_FLOOR", "UNKNOWN", "UNCONFIGURED"} else "UNKNOWN",
            "floor_ths": _projection_number(details.get("gpu_floor_ths"), minimum=0.000001),
            "observed_window_hashrate_ths": _projection_number(last_window.get("mean_hashrate_ths"), minimum=0),
            "sample_count": last_window.get("sample_count") if type(last_window.get("sample_count")) is int and last_window["sample_count"] >= 0 else None,
            "coverage_ratio": _projection_number(last_window.get("coverage_ratio"), minimum=0, maximum=1),
            "maximum_observed_gap_seconds": _projection_number(last_window.get("maximum_observed_gap_seconds"), minimum=0),
            "bad_windows": details.get("consecutive_bad_windows_observed") if type(details.get("consecutive_bad_windows_observed")) is int and details["consecutive_bad_windows_observed"] >= 0 else None,
        })
        if event["event_id"] is not None and event["occurred_at_utc"] is not None:
            events.append(event)

    audit_projection = {
        "FLOOR_BREACH_DETECTED": ("DEGRADATION_STARTED", "WARNING", "FIRST_BELOW_FLOOR_WINDOW"),
        "SUSTAINED_LOW_HASHRATE": ("SUSTAINED_DEGRADATION", "ALERT", "CONSECUTIVE_WINDOWS_BELOW_FLOOR"),
        "HASHRATE_RECOVERED": ("RECOVERY_OBSERVED", "INFO", "HASHRATE_RETURNED_TO_FLOOR"),
        "REALLOCATION_RECOMMENDED": ("REALLOCATION_RECOMMENDED", "ALERT", "DRY_RUN_RECOMMENDATION"),
        "REALLOCATION_CONFIRMED": ("REALLOCATION_OBSERVATION_RECORDED", "INFO", "EXTERNAL_CONFIRMATION_RECORDED"),
        "ALLOCATION_TERMINATED": ("LOCAL_TRACK_CLOSED", "INFO", "TRACK_GENERATION_CLOSED"),
        "GPU_IDENTITY_CONFLICT": ("GPU_IDENTITY_CONFLICT", "WARNING", "CONFLICTING_GPU_IDENTITY_EVIDENCE"),
        "AMBIGUOUS_ASSIGNMENT_CONTINUITY": ("ASSIGNMENT_CONTINUITY_AMBIGUOUS", "WARNING", "MULTIPLE_TRACK_CANDIDATES"),
        "UNSCOPED_TERMINAL_LIFECYCLE": ("LIFECYCLE_IDENTITY_UNSCOPED", "WARNING", "PROVIDER_ASSIGNMENT_NOT_UNIQUE"),
        "GPU_DEVICE_MAPPING_AMBIGUOUS": ("GPU_DEVICE_MAPPING_AMBIGUOUS", "WARNING", "PROVIDER_GPU_MAPPING_NOT_UNIQUE"),
    }
    for row in rows["audits"]:
        mapped = audit_projection.get(row.get("event_type"))
        if mapped is None:
            continue
        event_type, severity, reason = mapped
        event = base_event(
            kind="audit", source_id=row.get("audit_id"), occurred_at=row.get("occurred_at_utc"),
            track_row=row, event_type=event_type, state=event_type, severity=severity,
            reason_code=reason, source_classification="LOCAL_MONITOR_AUDIT",
        )
        if event["event_id"] is not None and event["occurred_at_utc"] is not None:
            events.append(event)

    lifecycle_projection = {
        "allocated": ("START_REPORTED", "INFO", "ALLOCATION_REPORTED"),
        "allocating": ("START_REPORTED", "INFO", "ALLOCATION_REPORTED"),
        "downloading": ("START_REPORTED", "INFO", "IMAGE_DOWNLOAD_REPORTED"),
        "creating": ("START_REPORTED", "INFO", "INSTANCE_CREATION_REPORTED"),
        "starting": ("START_REPORTED", "INFO", "INSTANCE_START_REPORTED"),
        "running": ("RUNNING_REPORTED", "INFO", "PROVIDER_RUNNING_REPORTED"),
        "ready": ("READY_REPORTED", "INFO", "PROVIDER_READY_REPORTED"),
        "startup_probe_passed": ("STARTUP_PROBE_PASSED", "INFO", "STARTUP_PROBE_PASSED_REPORTED"),
        "startup_probe_failed": ("STARTUP_PROBE_FAILED", "WARNING", "STARTUP_PROBE_FAILED_REPORTED"),
        "readiness_failed": ("READINESS_FAILURE_REPORTED", "WARNING", "READINESS_FAILURE_REPORTED"),
        "probe_failed": ("READINESS_FAILURE_REPORTED", "WARNING", "READINESS_PROBE_FAILED"),
        "stopping": ("TERMINATION_IN_PROGRESS_REPORTED", "INFO", "PROVIDER_STOPPING_REPORTED"),
        "stopped": ("TERMINATION_REPORTED", "INFO", "PROVIDER_STOPPED_REPORTED"),
        "terminated": ("TERMINATION_REPORTED", "INFO", "PROVIDER_TERMINATED_REPORTED"),
        "allocation_terminated": ("TERMINATION_REPORTED", "INFO", "ALLOCATION_TERMINATION_REPORTED"),
        "preempted": ("PREEMPTION_OR_LOSS_REPORTED", "WARNING", "PREEMPTION_REPORTED"),
        "lost": ("PREEMPTION_OR_LOSS_REPORTED", "WARNING", "RESOURCE_LOSS_REPORTED"),
        "reallocated": ("REALLOCATION_OBSERVED", "INFO", "REALLOCATION_REPORTED"),
    }
    for row in rows["lifecycle"]:
        mapped = lifecycle_projection.get(row.get("reported_state"))
        if mapped is None:
            continue
        event_type, severity, reason = mapped
        event = base_event(
            kind="lifecycle", source_id=row.get("event_id"), occurred_at=row.get("occurred_at_utc"),
            track_row=None, event_type=event_type, state=event_type, severity=severity,
            reason_code=reason, source_classification="PROVIDER_LOG_OBSERVATION_UNVERIFIED_SEMANTICS",
        )
        event.update(_provider_label_identity(row))
        event["generation_scope"] = "PROVIDER_GENERATION_UNKNOWN"
        event["container_group_name"] = event.pop("container_group_name", None)
        if event["event_id"] is not None and event["occurred_at_utc"] is not None:
            events.append(event)

    latest_observation_by_track: set[str] = set()
    for row in rows["observations"]:
        track_id = row.get("track_id")
        if not isinstance(track_id, str) or track_id in latest_observation_by_track:
            continue
        latest_observation_by_track.add(track_id)
        rate = _projection_number(row.get("hashrate_ths"), minimum=0.000001)
        if rate is None or row.get("hashrate_semantics") not in {"fl4shminer_device_reported", "krig_device_reported"}:
            continue
        event = base_event(
            kind="sample", source_id=row.get("event_id"), occurred_at=row.get("occurred_at_utc"),
            track_row=row, event_type="ACTIVE_MINING_SAMPLE", state="ACTIVE_MINING_OBSERVED",
            severity="INFO", reason_code="POSITIVE_DEVICE_REPORTED_HASHRATE",
            source_classification="LOCAL_DEVICE_REPORTED_HASHRATE",
        )
        event["observed_hashrate_ths"] = rate
        event["hashrate_semantics"] = row["hashrate_semantics"]
        if event["event_id"] is not None and event["occurred_at_utc"] is not None:
            events.append(event)

    events.sort(key=lambda item: (item["occurred_at_utc"], item["event_id"]), reverse=True)
    truncated = rows.get("source_truncated") is True or len(events) > limit
    return {
        "schema_version": "1.0",
        "status": "OK",
        "events": events[:limit],
        "limit": limit,
        "truncated": truncated,
        "source": "DURABLE_LOCAL_GUARD_STORE",
        "provider_lifecycle_semantics": "UNVERIFIED_OBSERVATIONS",
        "pool_failures_source": "EXISTING_CENTRAL_LOG_ALERT_PIPELINE",
        "actions_performed": False,
    }


def fleet_monitor_status(
    store: GuardStore,
    policy: HashGuardPolicy | None = None,
    *,
    binding_by_track: Mapping[str, Mapping[str, Any]] | None = None,
    event_limit: int = 100,
) -> dict[str, Any]:
    tracks: list[dict[str, Any]] = []
    for track in store.track_rows():
        latest = store.last_evaluation(track["track_id"])
        cooldown_until = None
        result_details = latest.get("result", {}).get("details", {}) if latest else {}
        stored_policy = result_details.get("policy", {}) if isinstance(result_details, Mapping) else {}
        cooldown_seconds = (
            policy.reallocation_cooldown_seconds if policy is not None
            else stored_policy.get("reallocation_cooldown_seconds")
        )
        if track.get("last_reallocation_utc") and isinstance(cooldown_seconds, int) and cooldown_seconds >= 0:
            cooldown_until = _utc_text(_parse_utc(track["last_reallocation_utc"]) + timedelta(seconds=cooldown_seconds))
        tracks.append({
            "track_id": track["track_id"],
            "fleet_id": track["fleet_id"],
            "worker_id": track["worker_id"],
            "allocation_id": track["allocation_id"],
            "assignment_id": track["assignment_id"],
            "machine_id": track["machine_id"],
            "instance_id": track["instance_id"],
            "device_namespace": track["device_namespace"],
            "device_id": track["device_id"],
            "gpu_identity": json.loads(track["gpu_identity_json"]),
            "started_at_utc": track["started_at_utc"],
            "latest_sample_utc": track["latest_sample_utc"],
            "hash_health": track["hash_health"],
            "last_decision": track["last_decision"],
            "last_evaluation": latest,
            "reallocation_count": track["reallocation_count"],
            "reallocation_history_known": bool(track["reallocation_history_known"]),
            "cooldown_until_utc": cooldown_until,
            "closed_at_utc": track["closed_at_utc"],
            "terminal_reason": track["terminal_reason"],
        })
    return {
        "schema_version": "1.0",
        "mode": "offline_dry_run",
        "tracks": tracks,
        "source_cursors": store.source_cursor_rows(),
        "events": fleet_monitor_event_feed(store, limit=event_limit, binding_by_track=binding_by_track),
        "actions_performed": False,
        "live_salad_adapter": "NOT_IMPLEMENTED",
        "economic_reconciliation_status": "UNKNOWN",
    }
