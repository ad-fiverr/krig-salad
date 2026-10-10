"""Deterministic segment reports and source-clock minute buckets."""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .krig_csv import ParsedKrigCsv
from .models import SCHEMA_VERSION, SOURCE_CLASS, SOURCE_NAME


def _clock(event: dict[str, Any]) -> datetime | None:
    value = event.get("occurred_at_source_clock")
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _mean(values: Iterable[float]) -> float | None:
    values = list(values)
    return statistics.fmean(values) if values else None


def _round(value: float | None, digits: int = 6) -> float | None:
    return None if value is None else round(value, digits)


def _source_time(event: dict[str, Any]) -> str | None:
    return event.get("occurred_at_source_clock")


def _utc_time(event: dict[str, Any]) -> str | None:
    return event.get("occurred_at_utc")


def _nearest_rank(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def _trapezoid_time_weighted(samples: list[tuple[datetime, float]]) -> tuple[float | None, float | None]:
    intervals: list[tuple[float, float]] = []
    for (left_time, left_rate), (right_time, right_rate) in zip(samples, samples[1:]):
        seconds = (right_time - left_time).total_seconds()
        if seconds > 0:
            intervals.append(((left_rate + right_rate) / 2.0, seconds))
    duration = sum(seconds for _, seconds in intervals)
    if duration <= 0:
        return None, None
    return sum(rate * seconds for rate, seconds in intervals) / duration, duration


def build_ledger(parsed: ParsedKrigCsv) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Return runs, segment summaries, minute stats, and an import report."""
    by_segment: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_run: dict[str, set[str]] = defaultdict(set)
    for event in parsed.events:
        by_segment[event["segment_id"]].append(event)
        by_run[event["run_id"]].add(event["segment_id"])

    segments: list[dict[str, Any]] = []
    for segment_id, events in sorted(by_segment.items()):
        events.sort(key=lambda event: (_clock(event) is None, _clock(event) or datetime.max, event["source_row"]))
        gpu_samples = [event for event in events if event["event_type"] == "gpu_sample"]
        total_samples = [event for event in events if event["event_type"] == "total_sample"]
        accepted_events = [event for event in events if event["event_type"] == "share_accepted"]
        stale_events = [event for event in events if event["event_type"] == "share_stale"]
        rejected_events = [event for event in events if event["event_type"] == "share_rejected"]
        errors = [event for event in events if event["event_type"] == "miner_error"]

        hash_values = [float(event["payload"]["hashrate_ths"]) for event in gpu_samples if event["payload"].get("hashrate_ths") is not None]
        power_values = [float(event["payload"]["power_w"]) for event in gpu_samples if event["payload"].get("power_w") is not None]
        temperature_values = [float(event["payload"]["temperature_c"]) for event in gpu_samples if event["payload"].get("temperature_c") is not None]
        sample_points = [(_clock(event), float(event["payload"]["hashrate_ths"])) for event in gpu_samples if _clock(event) is not None and event["payload"].get("hashrate_ths") is not None]
        sample_points.sort(key=lambda item: item[0])
        sample_gaps = [(right[0] - left[0]).total_seconds() for left, right in zip(sample_points, sample_points[1:])]
        sample_gaps = [gap for gap in sample_gaps if gap >= 0]
        weighted_hashrate, weighted_span = _trapezoid_time_weighted(sample_points)

        starts = [event for event in events if event["event_type"] == "worker_start"]
        first_hash = gpu_samples[0] if gpu_samples else None
        last_hash = gpu_samples[-1] if gpu_samples else None
        first_share = accepted_events[0] if accepted_events else None
        all_times = [(event, _clock(event)) for event in events if _clock(event) is not None]
        first_observed = all_times[0][0] if all_times else None
        last_observed = all_times[-1][0] if all_times else None
        first_start = starts[0] if starts else None

        counters_source = (gpu_samples + total_samples)
        counters_source = [event for event in counters_source if any(event["payload"].get(key) is not None for key in ("accepted_total", "stale_total", "rejected_total"))]
        counters_source.sort(key=lambda event: (_clock(event) is None, _clock(event) or datetime.max, event["source_row"]))
        final_counters = counters_source[-1]["payload"] if counters_source else {}

        interarrival_times = sorted(_clock(event) for event in accepted_events if _clock(event) is not None)
        interarrivals = [(right - left).total_seconds() for left, right in zip(interarrival_times, interarrival_times[1:])]
        interarrivals = [value for value in interarrivals if value >= 0]
        interval_median = statistics.median(interarrivals) if interarrivals else None
        interval_mean = statistics.fmean(interarrivals) if interarrivals else None
        interval_max = max(interarrivals) if interarrivals else None
        interval_p95 = _nearest_rank(interarrivals, 0.95)

        models = [event["payload"].get("gpu_model") for event in gpu_samples if event["payload"].get("gpu_model")]
        model_counts = Counter(models)
        gpu_model = model_counts.most_common(1)[0][0] if model_counts else None
        start_payload = first_start["payload"] if first_start else {}
        error_categories = dict(sorted(Counter(event["payload"].get("error_category", "unclassified_error") for event in errors).items()))

        active_start = _clock(first_start) if first_start else None
        first_hash_clock = _clock(first_hash) if first_hash else None
        last_hash_clock = _clock(last_hash) if last_hash else None
        observed_active_span = (last_hash_clock - active_start).total_seconds() if active_start is not None and last_hash_clock is not None else None
        hash_sample_span = (last_hash_clock - first_hash_clock).total_seconds() if first_hash_clock is not None and last_hash_clock is not None else None
        median_gap = statistics.median(sample_gaps) if sample_gaps else None
        expected_by_median = (int((hash_sample_span / median_gap) + 1.000000001) if median_gap and hash_sample_span is not None else None)
        inferred_coverage = min(1.0, len(sample_points) / expected_by_median) if expected_by_median else None

        event = events[0]
        segments.append(
            {
                "schema_version": SCHEMA_VERSION,
                "run_id": event["run_id"],
                "segment_id": segment_id,
                "container_group_name": event["container_group_name"],
                "container_group_version": event["container_group_version"],
                "instance_id": event["instance_id"],
                "machine_id": event["machine_id"],
                "segment_identity_complete": all(item.get("segment_identity_complete", False) for item in events),
                "gpu_model": gpu_model,
                "miner": start_payload.get("miner"),
                "miner_version": start_payload.get("miner_version"),
                "coin": start_payload.get("coin"),
                "pool_host": start_payload.get("pool_host"),
                "pool_port": start_payload.get("pool_port"),
                "first_observed_at_source_clock": _source_time(first_observed) if first_observed else None,
                "last_observed_at_source_clock": _source_time(last_observed) if last_observed else None,
                "first_observed_at_utc": _utc_time(first_observed) if first_observed else None,
                "last_observed_at_utc": _utc_time(last_observed) if last_observed else None,
                "worker_start_source_clock": _source_time(first_start) if first_start else None,
                "first_gpu_sample_source_clock": _source_time(first_hash) if first_hash else None,
                "first_gpu_sample_utc": _utc_time(first_hash) if first_hash else None,
                "first_accepted_share_source_clock": _source_time(first_share) if first_share else None,
                "first_accepted_share_utc": _utc_time(first_share) if first_share else None,
                "last_gpu_sample_source_clock": _source_time(last_hash) if last_hash else None,
                "last_gpu_sample_utc": _utc_time(last_hash) if last_hash else None,
                "gpu_sample_count": len(gpu_samples),
                "accepted_share_event_count": len(accepted_events),
                "stale_share_event_count": len(stale_events),
                "rejected_share_event_count": len(rejected_events),
                "final_accepted_counter": final_counters.get("accepted_total"),
                "final_stale_counter": final_counters.get("stale_total"),
                "final_rejected_counter": final_counters.get("rejected_total"),
                "mean_hashrate_ths": _round(_mean(hash_values)),
                "duration_weighted_hashrate_ths": _round(weighted_hashrate),
                "duration_weighted_hashrate_method": "trapezoidal estimate between timestamped GPU samples; not billed time" if weighted_hashrate is not None else None,
                "duration_weighted_span_seconds": weighted_span,
                "min_hashrate_ths": min(hash_values) if hash_values else None,
                "max_hashrate_ths": max(hash_values) if hash_values else None,
                "mean_power_w": _round(_mean(power_values)),
                "mean_temperature_c": _round(_mean(temperature_values)),
                "miner_observed_active_span_seconds": observed_active_span,
                "first_hash_to_last_hash_sample_seconds": hash_sample_span,
                "share_interarrival_timestamp_count": len(interarrival_times),
                "share_interarrival_timestamps_complete": len(interarrival_times) == len(accepted_events),
                "share_interarrival_interval_count": len(interarrivals),
                "share_interarrival_mean_seconds": _round(interval_mean),
                "share_interarrival_median_seconds": _round(interval_median),
                "share_interarrival_p95_seconds_nearest_rank": _round(interval_p95),
                "share_interarrival_max_seconds": _round(interval_max),
                "maximum_gpu_sample_gap_seconds": max(sample_gaps) if sample_gaps else None,
                "median_gpu_sample_interval_seconds": median_gap,
                "estimated_sample_coverage_ratio_from_median_interval": round(inferred_coverage, 6) if inferred_coverage is not None else None,
                "sample_coverage_method": "diagnostic estimate: expected count inferred from median observed interval; no billing or activity continuity implied",
                "error_count": len(errors),
                "error_categories": error_categories,
                "billed_running_seconds": None,
                "productive_seconds": None,
                "nonproductive_billed_seconds": None,
                "observed_productive_ratio": None,
                "billing_status": "UNKNOWN",
                "billing_unknown_reason": "KRig CSV logs do not establish Salad billed time",
            }
        )

    runs: list[dict[str, Any]] = []
    for run_id, segment_ids in sorted(by_run.items()):
        run_events = [event for event in parsed.events if event["run_id"] == run_id]
        runs.append(
            {
                "run_id": run_id,
                "container_group_name": run_events[0]["container_group_name"] if run_events else None,
                "segment_ids": sorted(segment_ids),
                "segment_count": len(segment_ids),
                "event_count": len(run_events),
                "billing_status": "UNKNOWN",
            }
        )

    minute_buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in parsed.events:
        timestamp = _clock(event)
        if timestamp is None:
            continue
        bucket = timestamp.strftime("%Y-%m-%dT%H:%M")
        minute_buckets[(event["run_id"], event["segment_id"], bucket)].append(event)

    minute_stats: list[dict[str, Any]] = []
    for (run_id, segment_id, minute), events in sorted(minute_buckets.items()):
        samples = [event for event in events if event["event_type"] == "gpu_sample"]
        hashrates = [float(event["payload"]["hashrate_ths"]) for event in samples if event["payload"].get("hashrate_ths") is not None]
        powers = [float(event["payload"]["power_w"]) for event in samples if event["payload"].get("power_w") is not None]
        temperatures = [float(event["payload"]["temperature_c"]) for event in samples if event["payload"].get("temperature_c") is not None]
        minute_stats.append(
            {
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "segment_id": segment_id,
                "minute_source_clock_bucket": minute,
                "minute_start_utc": _utc_minute(events[0], minute),
                "sample_count": len(samples),
                "hashrate_mean_ths": _round(_mean(hashrates)),
                "hashrate_min_ths": min(hashrates) if hashrates else None,
                "hashrate_max_ths": max(hashrates) if hashrates else None,
                "power_mean_w": _round(_mean(powers)),
                "temperature_mean_c": _round(_mean(temperatures)),
                "accepted_share_events": sum(event["event_type"] == "share_accepted" for event in events),
                "stale_events": sum(event["event_type"] == "share_stale" for event in events),
                "rejected_events": sum(event["event_type"] == "share_rejected" for event in events),
            }
        )

    event_counts = dict(sorted(Counter(event["event_type"] for event in parsed.events).items()))
    report = {
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE_NAME,
        "source_class": SOURCE_CLASS,
        "source_file_sha256": parsed.source_file_sha256,
        "source_file_name": parsed.source_file_name,
        "source_timezone_option": parsed.source_timezone,
        "recorded_at_utc": parsed.recorded_at_utc,
        "data_rows": parsed.data_rows,
        "recognized_event_count": len(parsed.events),
        "event_counts": event_counts,
        "empty_log_rows_ignored": parsed.empty_log_rows_ignored,
        "unrecognized_nonempty_rows": parsed.unrecognized_nonempty_rows,
        "run_count": len(runs),
        "segment_count": len(segments),
        "billed_running_seconds": None,
        "observed_productive_ratio": None,
        "billing_status": "UNKNOWN",
        "billing_unknown_reason": "No explicit Salad lifecycle/billing evidence was supplied",
        "runs": runs,
        "segments": segments,
    }
    return runs, segments, minute_stats, report


def _utc_minute(event: dict[str, Any], minute: str) -> str | None:
    value = event.get("occurred_at_utc")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(second=0, microsecond=0).isoformat(timespec="minutes").replace("+00:00", "Z")


def _json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def write_import_outputs(parsed: ParsedKrigCsv, output_dir: str | Path) -> dict[str, Any]:
    """Write four requested artifacts; the event ledger only appends unseen IDs."""
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    runs, segments, minute_stats, report = build_ledger(parsed)
    events_path = destination / "events.jsonl"
    report_path = destination / "report.json"
    existing_ids: set[str] = set()
    existing_source_hashes: set[str] = set()

    if events_path.exists() and events_path.stat().st_size > 0 and not report_path.exists():
        raise ValueError("existing events.jsonl has no report.json provenance; refusing to reinterpret timestamps")

    if report_path.exists():
        try:
            existing_report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("existing report.json is invalid; refusing to overwrite an unverifiable import") from exc
        if not isinstance(existing_report, dict):
            raise ValueError("existing report.json is not an object; refusing to overwrite an unverifiable import")
        report_source_hash = existing_report.get("source_file_sha256")
        if not isinstance(report_source_hash, str):
            raise ValueError("existing report.json has no source hash; refusing to overwrite an unverifiable import")
        if existing_report.get("source_timezone_option") != parsed.source_timezone:
            raise ValueError("output directory already contains this CSV with a different source timezone option")
        existing_source_hashes.add(report_source_hash)

    if events_path.exists():
        with events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    existing_event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError("existing events.jsonl contains invalid JSON; refusing to rewrite the ledger") from exc
                if not isinstance(existing_event, dict):
                    raise ValueError("existing events.jsonl contains a non-object event; refusing to rewrite the ledger")
                event_id = existing_event.get("event_id")
                reference = existing_event.get("raw_reference")
                source_hash = reference.get("source_file_sha256") if isinstance(reference, dict) else None
                if not isinstance(event_id, str) or not isinstance(source_hash, str):
                    raise ValueError("existing events.jsonl lacks event or source identity; refusing to mix imports")
                existing_ids.add(event_id)
                existing_source_hashes.add(source_hash)

    if any(source_hash != parsed.source_file_sha256 for source_hash in existing_source_hashes):
        raise ValueError("output directory already contains a different source CSV; choose a new output directory")
    new_events = [event for event in parsed.events if event["event_id"] not in existing_ids]
    if new_events:
        with events_path.open("a", encoding="utf-8", newline="\n") as handle:
            for event in new_events:
                handle.write(_json_line(event) + "\n")
    elif not events_path.exists():
        events_path.write_text("", encoding="utf-8")

    (destination / "segments.json").write_text(
        json.dumps({"schema_version": SCHEMA_VERSION, "runs": runs, "segments": segments}, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    (destination / "minute_stats.jsonl").write_text(
        "".join(_json_line(record) + "\n" for record in minute_stats),
        encoding="utf-8",
    )
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return {
        "output_dir": str(destination),
        "events_appended": len(new_events),
        "events_in_import": len(parsed.events),
        "run_count": len(runs),
        "segment_count": len(segments),
        "minute_buckets": len(minute_stats),
    }
