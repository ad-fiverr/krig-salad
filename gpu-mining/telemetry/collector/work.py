"""Offline, provenance-aware mining work summaries for V2 event snapshots."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any


def _utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return parsed if parsed.is_finite() else None


def _counter_reset_analysis(sources: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compare counters only within a complete, source-local assignment segment."""
    resets: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    unique_sources = {source.source_file_sha256: source for source in sources}
    for source_hash in sorted(unique_sources):
        source = unique_sources[source_hash]
        grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
        for event in source.events:
            if event.get("event_type") not in {"gpu_sample", "total_sample"}:
                continue
            timestamp = _utc(event.get("occurred_at_utc"))
            if timestamp is None:
                continue
            payload = event.get("payload", {})
            device: Any = (
                {"namespace": payload.get("device_namespace", "krig_gpu_index"), "id": payload.get("gpu_index")}
                if event.get("event_type") == "gpu_sample" else "TOTAL"
            )
            identity_fields = (
                event.get("container_group_name"),
                event.get("container_group_version"),
                event.get("instance_id"),
                event.get("machine_id"),
                event.get("run_id"),
                event.get("segment_id"),
            )
            identity_complete = event.get("segment_identity_complete") is True and all(
                isinstance(value, str) and value and value != "UNKNOWN" for value in identity_fields
            )
            for counter in ("accepted_total", "stale_total", "rejected_total"):
                value = event.get("payload", {}).get(counter)
                if isinstance(value, int) and not isinstance(value, bool):
                    entry = {"time": timestamp, "value": value, "event": event}
                    if not identity_complete:
                        unresolved.append({
                            "source_file_sha256": source_hash,
                            "source_row": event.get("source_row"),
                            "device": device,
                            "counter": counter,
                            "value": value,
                            "occurred_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
                            "status": "counter_comparison_unresolved_missing_assignment_identity",
                        })
                        continue
                    grouped[(identity_fields, counter, json.dumps(device, sort_keys=True))].append(entry)
        for (identity_fields, counter, device_json), entries in sorted(grouped.items(), key=lambda item: str(item[0])):
            device = json.loads(device_json) if device_json.startswith("{") else device_json
            entries.sort(key=lambda item: (item["time"], item["event"].get("source_row", 0)))
            for previous, current in zip(entries, entries[1:]):
                if current["value"] < previous["value"]:
                    resets.append({
                        "source_file_sha256": source.source_file_sha256,
                        "container_group_name": identity_fields[0],
                        "container_group_version": identity_fields[1],
                        "instance_id": identity_fields[2],
                        "machine_id": identity_fields[3],
                        "run_id": identity_fields[4],
                        "segment_id": identity_fields[5],
                        "device": device,
                        "counter": counter,
                        "previous_value": previous["value"],
                        "new_value": current["value"],
                        "previous_source_row": previous["event"].get("source_row"),
                        "new_source_row": current["event"].get("source_row"),
                        "occurred_at_utc": current["time"].isoformat().replace("+00:00", "Z"),
                        "status": "counter_decrease_candidate_reset_not_proven",
                    })
    resets.sort(key=lambda item: (
        item["source_file_sha256"], item["run_id"], item["segment_id"],
        str(item["device"]), item["counter"], item["occurred_at_utc"],
    ))
    unresolved.sort(key=lambda item: (
        item["source_file_sha256"], item["source_row"] or 0, str(item["device"]), item["counter"],
    ))
    return resets, unresolved


def detect_counter_resets(sources: list[Any]) -> list[dict[str, Any]]:
    """Flag only decreases with complete source-local assignment identity."""
    return _counter_reset_analysis(sources)[0]


def build_work_accounting(events: list[dict[str, Any]], sources: list[Any] | None = None) -> dict[str, Any]:
    """Summarize explicit shares and bracketed GPU samples without inventing uptime."""
    by_segment_gpu: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    by_segment: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        segment_id = event.get("segment_id")
        if not isinstance(segment_id, str):
            continue
        by_segment[segment_id].append(event)
        if event.get("event_type") == "gpu_sample":
            gpu_index = event.get("payload", {}).get("gpu_index")
            if isinstance(gpu_index, int) and not isinstance(gpu_index, bool):
                namespace = event.get("payload", {}).get("device_namespace", "krig_gpu_index")
                if isinstance(namespace, str) and namespace:
                    by_segment_gpu[(segment_id, namespace, gpu_index)].append(event)

    results: list[dict[str, Any]] = []
    for segment_id, segment_events in sorted(by_segment.items()):
        explicit_share_accepted = [event for event in segment_events if event.get("event_type") == "share_accepted"]
        explicit_solution_accepted = [event for event in segment_events if event.get("event_type") == "solution_accepted"]
        stale = [event for event in segment_events if event.get("event_type") == "share_stale"]
        explicit_share_rejected = [event for event in segment_events if event.get("event_type") == "share_rejected"]
        explicit_solution_rejected = [event for event in segment_events if event.get("event_type") == "solution_rejected"]
        starts = [event for event in segment_events if event.get("event_type") == "worker_start"]
        share_times = sorted(
            parsed for event in explicit_share_accepted
            if (parsed := _utc(event.get("occurred_at_utc"))) is not None
        )
        intervals = [(right - left).total_seconds() for left, right in zip(share_times, share_times[1:])]
        hash_work_values: list[Decimal] = []
        difficulty_work_values: list[Decimal] = []
        hash_work_provenance: set[str] = set()
        hash_work_contexts: set[str] = set()
        difficulty_provenance: set[str] = set()
        difficulty_units: set[str] = set()
        difficulty_contexts: set[str] = set()
        every_hash_work_verified = bool(explicit_share_accepted)
        every_difficulty_verified = bool(explicit_share_accepted)
        for event in explicit_share_accepted:
            payload = event.get("payload", {})
            hash_amount = _decimal(payload.get("share_work_hashes"))
            hash_unit = payload.get("share_work_unit")
            hash_source = payload.get("share_work_provenance")
            hash_context = payload.get("share_work_context")
            hash_verified = payload.get("share_work_verified") is True
            if (hash_amount is None or hash_amount < 0 or hash_unit != "H" or not hash_verified
                    or not isinstance(hash_source, str) or not hash_source.strip()
                    or not isinstance(hash_context, str) or not hash_context.strip()):
                every_hash_work_verified = False
            else:
                hash_work_values.append(hash_amount)
                hash_work_provenance.add(hash_source.strip())
                hash_work_contexts.add(hash_context.strip())
            difficulty = _decimal(payload.get("share_difficulty_value"))
            difficulty_unit = payload.get("share_difficulty_unit")
            difficulty_source = payload.get("share_difficulty_provenance")
            difficulty_context = payload.get("share_difficulty_context")
            difficulty_verified = payload.get("share_difficulty_verified") is True
            if (difficulty is None or difficulty < 0 or not isinstance(difficulty_unit, str) or not difficulty_unit.strip()
                    or not isinstance(difficulty_source, str) or not difficulty_source.strip()
                    or not isinstance(difficulty_context, str) or not difficulty_context.strip() or not difficulty_verified):
                every_difficulty_verified = False
            else:
                difficulty_work_values.append(difficulty)
                difficulty_units.add(difficulty_unit.strip())
                difficulty_contexts.add(difficulty_context.strip())
                difficulty_provenance.add(difficulty_source.strip())

        gpu_results: list[dict[str, Any]] = []
        for (this_segment, device_namespace, gpu_index), samples in sorted(by_segment_gpu.items()):
            if this_segment != segment_id:
                continue
            points: list[tuple[datetime, Decimal, dict[str, Any]]] = []
            for event in samples:
                timestamp = _utc(event.get("occurred_at_utc"))
                rate = _decimal(event.get("payload", {}).get("hashrate_ths"))
                if timestamp is not None and rate is not None and rate >= 0:
                    points.append((timestamp, rate, event))
            points.sort(key=lambda item: (item[0], item[2].get("event_id", "")))
            intervals_out: list[dict[str, Any]] = []
            integrated_th_seconds = Decimal(0)
            bracketed_seconds = Decimal(0)
            invalid_intervals = 0
            for (left_time, left_rate, left_event), (right_time, right_rate, right_event) in zip(points, points[1:]):
                seconds = Decimal(str((right_time - left_time).total_seconds()))
                if seconds <= 0:
                    invalid_intervals += 1
                    continue
                integrated = (left_rate + right_rate) * seconds / Decimal(2)
                integrated_th_seconds += integrated
                bracketed_seconds += seconds
                intervals_out.append({
                    "start_utc": left_time.isoformat().replace("+00:00", "Z"),
                    "end_utc": right_time.isoformat().replace("+00:00", "Z"),
                    "duration_seconds": str(seconds),
                    "start_hashrate_ths": str(left_rate),
                    "end_hashrate_ths": str(right_rate),
                    "integrated_th_seconds_estimate": str(integrated),
                    "interpolation": "linear_trapezoid_between_observed_endpoints",
                    "left_event_id": left_event.get("event_id"),
                    "right_event_id": right_event.get("event_id"),
                    "source_references": [left_event.get("raw_reference"), right_event.get("raw_reference")],
                })
            gpu_results.append({
                "gpu_index": gpu_index,
                "device_namespace": device_namespace,
                "observed_sample_count": len(samples),
                "timestamped_rate_sample_count": len(points),
                "first_sample_utc": points[0][0].isoformat().replace("+00:00", "Z") if points else None,
                "last_sample_utc": points[-1][0].isoformat().replace("+00:00", "Z") if points else None,
                "bracketed_sample_span_seconds": str(bracketed_seconds),
                "integrated_th_seconds_estimate": str(integrated_th_seconds),
                "integrated_th_hours_estimate": str(integrated_th_seconds / Decimal(3600)),
                "unobserved_gap_threshold": None,
                "gap_intervals_reported_without_classification_threshold": len(intervals_out),
                "nonpositive_intervals_skipped": invalid_intervals,
                "intervals": intervals_out,
            })

        if explicit_share_accepted and every_hash_work_verified and len(hash_work_contexts) == 1:
            accepted_work = sum(hash_work_values, Decimal(0))
            work_unit = "H"
            work_basis = "explicit_verified_share_work"
            work_provenance = sorted(hash_work_provenance)
            work_context = next(iter(hash_work_contexts))
        elif explicit_share_accepted and every_difficulty_verified and len(difficulty_units) == 1 and len(difficulty_contexts) == 1:
            accepted_work = sum(difficulty_work_values, Decimal(0))
            work_unit = next(iter(difficulty_units))
            work_basis = "explicit_verified_compatible_share_difficulty"
            work_provenance = sorted(difficulty_provenance)
            work_context = next(iter(difficulty_contexts))
        else:
            accepted_work = None
            work_unit = None
            work_basis = None
            work_provenance = []
            work_context = None
        results.append({
            "schema_version": "2.0",
            "segment_id": segment_id,
            "accepted_share_count": len(explicit_share_accepted),
            "explicit_share_accepted_count": len(explicit_share_accepted),
            "explicit_solution_accepted_count": len(explicit_solution_accepted),
            "accepted_log_event_count": len(explicit_share_accepted) + len(explicit_solution_accepted),
            "stale_share_count": len(stale),
            "rejected_share_count": len(explicit_share_rejected),
            "explicit_solution_rejected_count": len(explicit_solution_rejected),
            "worker_start_count": len(starts),
            "worker_start_timestamps_utc": sorted(
                parsed.isoformat().replace("+00:00", "Z")
                for event in starts
                if (parsed := _utc(event.get("occurred_at_utc"))) is not None
            ),
            "accepted_share_timestamps_utc": [value.isoformat().replace("+00:00", "Z") for value in share_times],
            "accepted_share_timestamp_count": len(share_times),
            "accepted_share_interarrival_seconds": [str(value) for value in intervals],
            "accepted_work_amount": str(accepted_work) if accepted_work is not None else None,
            "accepted_work_unit": work_unit,
            "accepted_work_basis": work_basis,
            "accepted_work_context": work_context,
            "accepted_work_status": "verified" if accepted_work is not None else ("no_accepted_shares_observed_work_unknown" if not explicit_share_accepted else "unknown_missing_or_incompatible_verified_share_work"),
            "accepted_work_provenance": work_provenance,
            "gpu_hashrate_work_estimates": gpu_results,
            "billed_seconds": None,
            "productive_seconds": None,
            "nonproductive_billed_seconds": None,
            "unknowns": ["GPU rate integration estimates only bracketed intervals", "no gap threshold was calibrated", "billed and productive time are not established by miner telemetry"],
        })
    reset_candidates, unresolved_reset_samples = _counter_reset_analysis(sources or [])
    return {
        "schema_version": "2.0",
        "counter_reset_candidates": reset_candidates,
        "counter_reset_identity_unknown_samples": unresolved_reset_samples,
        "segments": results,
    }
