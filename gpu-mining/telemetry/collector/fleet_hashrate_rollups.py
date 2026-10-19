"""Coverage-aware, read-only GPU and fleet hashrate rollups.

Only explicitly device-reported observations with complete assignment/device
identity participate. Missing intervals are never filled with zero or carried
forward; trapezoidal interpolation is limited to adjacent samples within the
configured maximum gap.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any


WINDOWS_SECONDS: dict[str, int] = {
    "10m": 600,
    "30m": 1800,
    "60m": 3600,
    "24h": 86400,
}
ALLOWED_HASHRATE_SEMANTICS = frozenset({
    "fl4shminer_device_reported",
    "krig_device_reported",
})
MAXIMUM_SAMPLE_RECORDS_PER_TRACK = 100_000


def _parse_utc(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds" if value.microsecond else "seconds").replace("+00:00", "Z")


def _nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and len(value.encode("utf-8")) <= 65536:
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _scope(track: Mapping[str, Any]) -> tuple[str, str, str] | None:
    provenance = _json_object(track.get("provenance_json") or track.get("provenance"))
    raw_scope = provenance.get("provider_scope")
    if not isinstance(raw_scope, Mapping):
        raw_scope = track.get("provider_scope")
    if not isinstance(raw_scope, Mapping):
        return None
    organization_claims = {
        value.strip() for value in (raw_scope.get("organization_id"), raw_scope.get("organization_name"))
        if _nonempty_text(value)
    }
    project_claims = {
        value.strip() for value in (raw_scope.get("project_id"), raw_scope.get("project_name"))
        if _nonempty_text(value)
    }
    if len(organization_claims) > 1 or len(project_claims) > 1:
        return None
    organization = next(iter(organization_claims), None)
    project = next(iter(project_claims), None)
    if raw_scope.get("scope_status") != "VERIFIED" or not _nonempty_text(organization) or not _nonempty_text(project):
        return None
    organization = organization.strip()
    project = project.strip()
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", organization)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", project)
    ):
        return None
    digest = hashlib.sha256(f"{organization}\0{project}".encode("utf-8")).hexdigest()[:16]
    return organization, project, digest


def _track_identity(track: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    fields = (
        "track_id", "fleet_id", "worker_id", "allocation_id", "assignment_id",
        "run_id", "machine_id", "instance_id", "device_namespace", "device_id",
    )
    if any(not _nonempty_text(track.get(key)) for key in fields):
        return {}, "INCOMPLETE_TRACK_OR_DEVICE_IDENTITY"
    anchor = track.get("start_anchor_verified")
    if anchor is not True and not (type(anchor) is int and anchor == 1):
        return {}, "UNVERIFIED_ASSIGNMENT_START"
    started = _parse_utc(track.get("started_at_utc"))
    if started is None:
        return {}, "INVALID_TRACK_START"
    closed_value = track.get("closed_at_utc")
    closed = _parse_utc(closed_value) if closed_value is not None else None
    if closed_value is not None and closed is None:
        return {}, "INVALID_TRACK_END"
    if closed is not None and closed < started:
        return {}, "TRACK_END_PRECEDES_START"
    gpu_identity = _json_object(track.get("gpu_identity_json") or track.get("gpu_identity"))
    identity_status = str(gpu_identity.get("identity_status") or "").strip().casefold()
    if identity_status in {"conflicting_identity_observations", "gpu_identity_conflict", "conflicting"}:
        return {}, "CONFLICTING_GPU_IDENTITY"
    return {
        "track_id": track["track_id"],
        "fleet_id": track["fleet_id"],
        "worker_id": track["worker_id"],
        "allocation_id": track["allocation_id"],
        "assignment_id": track["assignment_id"],
        "run_id": track["run_id"],
        "machine_id": track["machine_id"],
        "instance_id": track["instance_id"],
        "device_namespace": track["device_namespace"],
        "device_id": track["device_id"],
        "started_at": started,
        "closed_at": closed,
        "track_active": closed is None,
        "gpu_identity": gpu_identity,
    }, None


def _valid_samples(
    samples: Sequence[Mapping[str, Any]],
    identity: Mapping[str, Any],
    *,
    as_of: datetime,
) -> tuple[list[tuple[datetime, float]], set[datetime], int]:
    by_time: dict[datetime, set[float]] = defaultdict(set)
    rejected = 0
    start = identity["started_at"]
    end = identity["closed_at"]
    for sample in samples:
        if not isinstance(sample, Mapping):
            rejected += 1
            continue
        if sample.get("hashrate_semantics") not in ALLOWED_HASHRATE_SEMANTICS:
            rejected += 1
            continue
        if not _nonempty_text(sample.get("hashrate_source")):
            rejected += 1
            continue
        timestamp = _parse_utc(sample.get("occurred_at_utc"))
        rate = sample.get("hashrate_ths")
        if timestamp is None or isinstance(rate, bool) or not isinstance(rate, (int, float)):
            rejected += 1
            continue
        try:
            numeric_rate = float(rate)
        except (OverflowError, TypeError, ValueError):
            rejected += 1
            continue
        if (
            not math.isfinite(numeric_rate)
            or numeric_rate < 0
            or timestamp < start
            or timestamp > as_of
            or (end is not None and timestamp > end)
        ):
            rejected += 1
            continue
        by_time[timestamp].add(numeric_rate)

    conflicts = {timestamp for timestamp, rates in by_time.items() if len(rates) > 1}
    points = [
        (timestamp, next(iter(rates)))
        for timestamp, rates in sorted(by_time.items())
        if len(rates) == 1
    ]
    return points, conflicts, rejected


def _interpolate(left: tuple[datetime, float], right: tuple[datetime, float], at: datetime) -> float:
    span = (right[0] - left[0]).total_seconds()
    offset = (at - left[0]).total_seconds()
    return left[1] + (right[1] - left[1]) * (offset / span)


def _window_data(
    identity: Mapping[str, Any],
    points: Sequence[tuple[datetime, float]],
    conflicts: set[datetime],
    *,
    end: datetime,
    duration_seconds: int,
    maximum_gap_seconds: float,
    minimum_coverage_ratio: float,
) -> dict[str, Any]:
    start = end - timedelta(seconds=duration_seconds)
    eligible_start = max(start, identity["started_at"])
    eligible_end = min(end, identity["closed_at"] or end)
    eligible_seconds = max(0.0, (eligible_end - eligible_start).total_seconds())
    segments: list[tuple[datetime, datetime, float, float]] = []
    integrated_th_seconds = 0.0
    covered_seconds = 0.0
    for left, right in zip(points, points[1:]):
        gap = (right[0] - left[0]).total_seconds()
        if gap <= 0 or gap > maximum_gap_seconds or left[0] in conflicts or right[0] in conflicts:
            continue
        segment_start = max(start, eligible_start, left[0])
        segment_end = min(end, eligible_end, right[0])
        if segment_end <= segment_start:
            continue
        start_rate = _interpolate(left, right, segment_start)
        end_rate = _interpolate(left, right, segment_end)
        segment_seconds = (segment_end - segment_start).total_seconds()
        if segment_seconds <= 0:
            continue
        segments.append((segment_start, segment_end, start_rate, end_rate))
        covered_seconds += segment_seconds
        integrated_th_seconds += ((start_rate + end_rate) / 2.0) * segment_seconds

    window_coverage = min(1.0, covered_seconds / duration_seconds)
    eligible_coverage = min(1.0, covered_seconds / eligible_seconds) if eligible_seconds > 0 else 0.0
    if eligible_seconds <= 0 or covered_seconds <= 0:
        status = "UNKNOWN"
    elif (
        window_coverage < minimum_coverage_ratio
        or eligible_coverage < minimum_coverage_ratio
        or eligible_seconds < duration_seconds
        or any(start <= timestamp <= end for timestamp in conflicts)
    ):
        status = "PARTIAL"
    else:
        status = "COMPLETE"
    return {
        "window_seconds": duration_seconds,
        "window_start_utc": _utc_text(start),
        "window_end_utc": _utc_text(end),
        "mean_hashrate_ths": integrated_th_seconds / covered_seconds if covered_seconds > 0 else None,
        "integrated_th_hours": integrated_th_seconds / 3600.0 if covered_seconds > 0 else None,
        "covered_seconds": round(covered_seconds, 6),
        "window_coverage_ratio": round(window_coverage, 6),
        "eligible_lifetime_seconds": round(eligible_seconds, 6),
        "eligible_lifetime_coverage_ratio": round(eligible_coverage, 6),
        "sample_count": sum(start <= timestamp <= end for timestamp, _ in points),
        "timestamp_conflict_count": sum(start <= timestamp <= end for timestamp in conflicts),
        "rejected_sample_count": None,
        "status": status,
        "method": "BOUNDED_LINEAR_TRAPEZOID_OVER_OBSERVED_INTERVALS",
        "_segments": segments,
        "_active_start": eligible_start if eligible_seconds > 0 else None,
        "_active_end": eligible_end if eligible_seconds > 0 else None,
    }


def _unknown_window(name: str, duration: int, end: datetime, reason: str) -> dict[str, Any]:
    return {
        "window_seconds": duration,
        "window_start_utc": _utc_text(end - timedelta(seconds=duration)),
        "window_end_utc": _utc_text(end),
        "mean_hashrate_ths": None,
        "fleet_time_weighted_average_hashrate_ths": None,
        "integrated_th_hours": None,
        "integrated_observed_th_hours": None,
        "covered_seconds": 0.0,
        "window_coverage_ratio": 0.0,
        "eligible_lifetime_seconds": 0.0,
        "eligible_lifetime_coverage_ratio": 0.0,
        "known_active_seconds": 0.0,
        "known_active_coverage_ratio": 0.0,
        "active_device_seconds": 0.0,
        "observed_device_seconds": 0.0,
        "missing_device_seconds": 0.0,
        "ambiguous_device_seconds": 0.0,
        "device_coverage_ratio": 0.0,
        "observed_contribution_status": "UNKNOWN",
        "device_coverage_status": "UNKNOWN",
        "fleet_completeness_status": "UNKNOWN_PROVIDER_GPU_INVENTORY_UNAVAILABLE",
        "sample_count": 0,
        "timestamp_conflict_count": 0,
        "rejected_sample_count": None,
        "status": "UNKNOWN",
        "reason": reason,
        "method": "BOUNDED_LINEAR_TRAPEZOID_OVER_OBSERVED_INTERVALS",
    }


def _public_window(value: Mapping[str, Any], *, rejected_sample_count: int) -> dict[str, Any]:
    return {
        key: item for key, item in value.items()
        if not key.startswith("_") and key != "rejected_sample_count"
    } | {"rejected_sample_count": rejected_sample_count}


def _physical_key(identity: Mapping[str, Any]) -> tuple[str, str, str]:
    return (str(identity["machine_id"]), str(identity["device_namespace"]), str(identity["device_id"]))


def _fleet_window(
    entries: Sequence[Mapping[str, Any]],
    *,
    as_of: datetime,
    duration: int,
    maximum_gap_seconds: float,
    minimum_coverage_ratio: float,
) -> dict[str, Any]:
    start = as_of - timedelta(seconds=duration)
    boundaries: set[datetime] = {start, as_of}
    intervals: list[tuple[datetime, datetime, Mapping[str, Any]]] = []
    for entry in entries:
        window = entry["windows"][str(duration)]
        left, right = window.get("_active_start"), window.get("_active_end")
        if isinstance(left, datetime) and isinstance(right, datetime) and right > left:
            intervals.append((left, right, entry))
            boundaries.update((left, right))
        for segment in window.get("_segments", []):
            boundaries.update((segment[0], segment[1]))

    ordered = sorted(boundaries)
    covered = 0.0
    integrated = 0.0
    eligible_intervals = sorted((left, right) for left, right, _ in intervals)
    eligible_union = 0.0
    union_end: datetime | None = None
    for left, right in eligible_intervals:
        if union_end is None or left > union_end:
            eligible_union += (right - left).total_seconds()
            union_end = right
        elif right > union_end:
            eligible_union += (right - union_end).total_seconds()
            union_end = right

    ambiguous_overlap_seconds = 0.0
    missing_coverage_seconds = 0.0
    active_device_seconds = 0.0
    observed_device_seconds = 0.0
    missing_device_seconds = 0.0
    ambiguous_device_seconds = 0.0
    for left, right in zip(ordered, ordered[1:]):
        seconds = (right - left).total_seconds()
        if seconds <= 0:
            continue
        active = [entry for active_start, active_end, entry in intervals if active_start <= left and active_end >= right]
        if not active:
            continue
        by_physical: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
        for entry in active:
            by_physical[_physical_key(entry["identity"])].append(entry)
        active_device_seconds += seconds * len(by_physical)
        conflicted_physical = {key for key, candidates in by_physical.items() if len(candidates) != 1}
        if conflicted_physical:
            ambiguous_overlap_seconds += seconds
            ambiguous_device_seconds += seconds * len(conflicted_physical)
        aggregate_start = 0.0
        aggregate_end = 0.0
        contributing_devices = 0
        for physical_key, candidates in by_physical.items():
            if physical_key in conflicted_physical:
                continue
            entry = candidates[0]
            segments = entry["windows"][str(duration)].get("_segments", [])
            segment = next((item for item in segments if item[0] <= left and item[1] >= right), None)
            if segment is None:
                missing_device_seconds += seconds
                continue
            segment_start, segment_end, rate_start, rate_end = segment
            segment_seconds = (segment_end - segment_start).total_seconds()
            if segment_seconds <= 0:
                missing_device_seconds += seconds
                continue
            aggregate_start += rate_start + (rate_end - rate_start) * ((left - segment_start).total_seconds() / segment_seconds)
            aggregate_end += rate_start + (rate_end - rate_start) * ((right - segment_start).total_seconds() / segment_seconds)
            contributing_devices += 1
        if contributing_devices <= 0:
            missing_coverage_seconds += seconds
            continue
        covered += seconds
        observed_device_seconds += seconds * contributing_devices
        integrated += ((aggregate_start + aggregate_end) / 2.0) * seconds

    coverage = min(1.0, covered / duration)
    eligible_coverage = min(1.0, covered / eligible_union) if eligible_union > 0 else 0.0
    device_coverage = min(1.0, observed_device_seconds / active_device_seconds) if active_device_seconds > 0 else 0.0
    if covered <= 0:
        status = "UNKNOWN"
    elif coverage < minimum_coverage_ratio or eligible_coverage < minimum_coverage_ratio or ambiguous_overlap_seconds > 0:
        status = "PARTIAL"
    else:
        # The sample ledger cannot attest that it includes every requested or
        # allocating GPU. Never label a track-only sum as a complete fleet.
        status = "PARTIAL"
    return {
        "window_seconds": duration,
        "window_start_utc": _utc_text(start),
        "window_end_utc": _utc_text(as_of),
        "fleet_time_weighted_average_hashrate_ths": integrated / covered if covered > 0 else None,
        "integrated_observed_th_hours": integrated / 3600.0 if covered > 0 else None,
        "covered_seconds": round(covered, 6),
        "window_coverage_ratio": round(coverage, 6),
        "known_active_seconds": round(eligible_union, 6),
        "known_active_coverage_ratio": round(eligible_coverage, 6),
        "active_device_seconds": round(active_device_seconds, 6),
        "observed_device_seconds": round(observed_device_seconds, 6),
        "missing_device_seconds": round(missing_device_seconds, 6),
        "ambiguous_device_seconds": round(ambiguous_device_seconds, 6),
        "device_coverage_ratio": round(device_coverage, 6),
        "observed_contribution_status": "OBSERVED" if observed_device_seconds > 0 else "UNKNOWN",
        "device_coverage_status": (
            "COMPLETE_TRACK_COVERAGE"
            if active_device_seconds > 0 and missing_device_seconds == 0 and ambiguous_device_seconds == 0
            else ("PARTIAL_TRACK_COVERAGE" if active_device_seconds > 0 else "UNKNOWN")
        ),
        # Track coverage cannot prove complete provider inventory. Keep this
        # explicitly unknown even when every known track contributed.
        "fleet_completeness_status": "UNKNOWN_PROVIDER_GPU_INVENTORY_UNAVAILABLE",
        "ambiguous_overlap_seconds": round(ambiguous_overlap_seconds, 6),
        "missing_coverage_seconds": round(missing_coverage_seconds, 6),
        "status": status,
        "method": "TIME_SLICED_SUM_OF_VERIFIED_TRACK_SEGMENTS",
    }


def build_hashrate_rollups(
    tracks: Iterable[Mapping[str, Any]],
    samples_by_track: Mapping[str, Sequence[Mapping[str, Any]] | Mapping[str, Any]],
    *,
    as_of_utc: str | datetime,
    maximum_sample_gap_seconds: float,
    minimum_window_coverage_ratio: float,
) -> dict[str, Any]:
    """Build per-track and provider-scope-isolated fleet rollups.

    Fleet aggregation requires explicitly verified organization/project scope
    in each track's trusted ``provider_scope`` provenance. If that evidence is
    absent, only per-device rollups are returned and fleet values stay UNKNOWN.
    """
    as_of = _parse_utc(as_of_utc)
    if as_of is None:
        raise ValueError("rollup time must be a timezone-aware UTC-compatible value")
    if isinstance(maximum_sample_gap_seconds, bool) or not isinstance(maximum_sample_gap_seconds, (int, float)) or not math.isfinite(float(maximum_sample_gap_seconds)) or maximum_sample_gap_seconds <= 0:
        raise ValueError("maximum sample gap must be finite and positive")
    if isinstance(minimum_window_coverage_ratio, bool) or not isinstance(minimum_window_coverage_ratio, (int, float)) or not math.isfinite(float(minimum_window_coverage_ratio)) or not 0 < minimum_window_coverage_ratio <= 1:
        raise ValueError("minimum coverage ratio must be within (0, 1]")

    prepared: list[dict[str, Any]] = []
    device_rows: list[dict[str, Any]] = []
    for track in tracks:
        if not isinstance(track, Mapping):
            continue
        identity, identity_error = _track_identity(track)
        track_id = track.get("track_id") if _nonempty_text(track.get("track_id")) else None
        raw_value = samples_by_track.get(track_id, ()) if track_id else ()
        history_truncated = False
        if isinstance(raw_value, Mapping):
            raw_samples = raw_value.get("samples", ())
            history_truncated = raw_value.get("truncated") is True
        else:
            raw_samples = raw_value
        if not isinstance(raw_samples, Sequence) or isinstance(raw_samples, (str, bytes, bytearray)):
            raw_samples = ()
            identity_error = identity_error or "INVALID_SAMPLE_HISTORY"
        if len(raw_samples) > MAXIMUM_SAMPLE_RECORDS_PER_TRACK:
            identity_error = identity_error or "SAMPLE_HISTORY_LIMIT_EXCEEDED"
            raw_samples = ()
        if identity_error:
            device_rows.append({
                "track_id": track_id,
                "fleet_id": track.get("fleet_id") if _nonempty_text(track.get("fleet_id")) else None,
                "worker_id": track.get("worker_id") if _nonempty_text(track.get("worker_id")) else None,
                "identity_status": "UNKNOWN",
                "reason": identity_error,
                "current": {"status": "UNKNOWN", "last_observed_hashrate_ths": None, "hashrate_ths": None, "observed_at_utc": None},
                "windows": {name: _unknown_window(name, seconds, as_of, identity_error) for name, seconds in WINDOWS_SECONDS.items()},
                "actions_performed": False,
            })
            continue

        identity["track_active"] = identity["closed_at"] is None or identity["closed_at"] > as_of
        samples, conflicts, rejected = _valid_samples(raw_samples, identity, as_of=as_of)
        scope = _scope(track)
        current_point = samples[-1] if samples else None
        current_age = (as_of - current_point[0]).total_seconds() if current_point else None
        current_fresh = identity["track_active"] and current_point is not None and 0 <= current_age <= maximum_sample_gap_seconds
        gpu_identity = identity["gpu_identity"]
        device_windows: dict[str, dict[str, Any]] = {}
        internal_windows: dict[str, dict[str, Any]] = {}
        for name, duration in WINDOWS_SECONDS.items():
            if history_truncated and name == "24h":
                data = _unknown_window(name, duration, as_of, "SAMPLE_HISTORY_LIMIT_EXCEEDED")
                active_start = max(as_of - timedelta(seconds=duration), identity["started_at"])
                active_end = min(as_of, identity["closed_at"] or as_of)
                data["_active_start"] = active_start if active_end > active_start else None
                data["_active_end"] = active_end if active_end > active_start else None
                data["sample_count"] = len(samples)
            else:
                data = _window_data(
                    identity, samples, conflicts, end=as_of, duration_seconds=duration,
                    maximum_gap_seconds=float(maximum_sample_gap_seconds),
                    minimum_coverage_ratio=float(minimum_window_coverage_ratio),
                )
            data["rejected_sample_count"] = rejected
            internal_windows[str(duration)] = data
            device_windows[name] = _public_window(data, rejected_sample_count=rejected)
        row = {
            "track_id": identity["track_id"],
            "fleet_id": identity["fleet_id"],
            "worker_id": identity["worker_id"],
            "allocation_id": identity["allocation_id"],
            "assignment_id": identity["assignment_id"],
            "run_id": identity["run_id"],
            "machine_id": identity["machine_id"],
            "instance_id": identity["instance_id"],
            "device_namespace": identity["device_namespace"],
            "device_id": identity["device_id"],
            "gpu_model": gpu_identity.get("model") if gpu_identity.get("identity_verified") is True else None,
            "gpu_identity_status": "VERIFIED" if gpu_identity.get("identity_verified") is True else "UNKNOWN",
            "provider_scope_status": "VERIFIED" if scope else "UNKNOWN",
            "provider_scope_fingerprint": scope[2] if scope else None,
            "track_status": "ACTIVE" if identity["track_active"] else "CLOSED",
            "identity_status": "VERIFIED",
            "current": {
                "status": "FRESH" if current_fresh else ("STALE" if identity["track_active"] and current_point else ("INACTIVE" if not identity["track_active"] else "UNKNOWN")),
                "last_observed_hashrate_ths": current_point[1] if current_point else None,
                "hashrate_ths": current_point[1] if current_fresh else None,
                "observed_at_utc": _utc_text(current_point[0]) if current_point else None,
                "age_seconds": round(current_age, 6) if current_age is not None else None,
                "semantics": "DEVICE_REPORTED" if current_point else "UNKNOWN",
            },
            "windows": device_windows,
            "actions_performed": False,
        }
        device_rows.append(row)
        prepared.append({"identity": identity, "scope": scope, "windows": internal_windows, "public": row})

    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    unknown_groups: set[tuple[str, str]] = set()
    for entry in prepared:
        identity = entry["identity"]
        scope = entry["scope"]
        if scope is None:
            unknown_groups.add((str(identity["fleet_id"]), str(identity["worker_id"])))
        else:
            groups[(scope[0], scope[1], str(identity["fleet_id"]), str(identity["worker_id"]))].append(entry)

    fleet_rows: list[dict[str, Any]] = []
    for (organization, project, fleet_id, worker_id), entries in sorted(groups.items()):
        fingerprint = hashlib.sha256(f"{organization}\0{project}".encode("utf-8")).hexdigest()[:16]
        windows = {
            name: _fleet_window(
                entries, as_of=as_of, duration=duration,
                maximum_gap_seconds=float(maximum_sample_gap_seconds),
                minimum_coverage_ratio=float(minimum_window_coverage_ratio),
            )
            for name, duration in WINDOWS_SECONDS.items()
        }
        fresh_keys = {
            (entry["identity"]["machine_id"], entry["identity"]["device_namespace"], entry["identity"]["device_id"])
            for entry in entries if entry["public"]["current"]["status"] == "FRESH"
        }
        fleet_rows.append({
            "fleet_id": fleet_id,
            "worker_id": worker_id,
            "provider_scope_status": "VERIFIED",
            "provider_scope_fingerprint": fingerprint,
            "provider_inventory_status": "UNKNOWN",
            "requested_gpu_count": None,
            "allocating_gpu_count": None,
            "observed_online_gpu_count": len(fresh_keys),
            "online_gpu_count_status": "OBSERVED_TRACKS_ONLY",
            "windows": windows,
            "scope_completeness_status": "UNKNOWN_PROVIDER_GPU_INVENTORY_UNAVAILABLE",
            "actions_performed": False,
        })

    for fleet_id, worker_id in sorted(unknown_groups):
        fleet_rows.append({
            "fleet_id": fleet_id,
            "worker_id": worker_id,
            "provider_scope_status": "UNKNOWN",
            "provider_scope_fingerprint": None,
            "provider_inventory_status": "UNKNOWN",
            "requested_gpu_count": None,
            "allocating_gpu_count": None,
            "observed_online_gpu_count": None,
            "online_gpu_count_status": "UNKNOWN_SCOPE_NOT_AGGREGATED",
            "windows": {
                name: _unknown_window(name, duration, as_of, "VERIFIED_ORGANIZATION_PROJECT_SCOPE_REQUIRED")
                for name, duration in WINDOWS_SECONDS.items()
            },
            "scope_completeness_status": "UNKNOWN",
            "actions_performed": False,
        })
    fleet_rows.sort(key=lambda item: (item["fleet_id"], item["worker_id"], item["provider_scope_fingerprint"] or ""))
    return {
        "schema_version": "1.0",
        "as_of_utc": _utc_text(as_of),
        "windows_seconds": dict(WINDOWS_SECONDS),
        "maximum_sample_gap_seconds": float(maximum_sample_gap_seconds),
        "minimum_window_coverage_ratio": float(minimum_window_coverage_ratio),
        "devices": sorted(device_rows, key=lambda item: (str(item.get("fleet_id") or ""), str(item.get("track_id") or ""))),
        "fleets": fleet_rows,
        "actions_performed": False,
        "data_classification": "LOCAL_DEVICE_REPORTED_OBSERVATIONS",
        "billing_status": "UNKNOWN",
    }
