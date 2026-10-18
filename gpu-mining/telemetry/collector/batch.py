"""All-or-nothing V2 batch import from original KRig CSV exports."""

from __future__ import annotations

import json
import os
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .identity import build_v2_event_snapshot
from .krig_csv import ParsedKrigCsv
from .models import V2_SCHEMA_VERSION
from .work import build_work_accounting


def _time(event: dict[str, Any]) -> datetime | None:
    value = event.get("occurred_at_utc")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def build_v2_batch(sources: list[ParsedKrigCsv]) -> dict[str, Any]:
    snapshot = build_v2_event_snapshot(sources)
    events = snapshot["events"]
    by_segment: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_run: dict[str, set[str]] = defaultdict(set)
    for event in events:
        by_segment[event["segment_id"]].append(event)
        by_run[event["run_id"]].add(event["segment_id"])

    segments: list[dict[str, Any]] = []
    for segment_id, segment_events in sorted(by_segment.items()):
        segment_events.sort(key=lambda event: (_time(event) is None, _time(event) or datetime.max.replace(tzinfo=timezone.utc), event.get("event_id", "")))
        samples = [event for event in segment_events if event.get("event_type") == "gpu_sample"]
        rates = [float(event["payload"]["hashrate_ths"]) for event in samples if isinstance(event.get("payload", {}).get("hashrate_ths"), (int, float))]
        models = sorted({
            value.strip()
            for event in samples
            if isinstance((value := event.get("payload", {}).get("gpu_model")), str) and value.strip()
        })
        identity_candidates = {
            _json_line(event.get("payload", {}).get("gpu_identity"))
            for event in samples
            if isinstance(event.get("payload", {}).get("gpu_identity"), dict)
        }
        gpu_identity = json.loads(next(iter(identity_candidates))) if len(identity_candidates) == 1 else {
            "raw_model": None,
            "model": None,
            "form_factor": "unknown",
            "identity_source": None,
            "identity_verified": False,
            "identity_status": "missing_or_conflicting_identity_evidence",
        }
        shares = Counter(event.get("event_type") for event in segment_events)
        representative = segment_events[0]
        timestamped = [value for event in segment_events if (value := _time(event)) is not None]
        segments.append({
            "schema_version": V2_SCHEMA_VERSION,
            "run_id": representative["run_id"],
            "segment_id": segment_id,
            "allocation_id": representative.get("allocation_id"),
            "identity_status": representative.get("identity_status"),
            "container_group_name": representative.get("container_group_name"),
            "container_group_version": representative.get("container_group_version"),
            "instance_id": representative.get("instance_id"),
            "machine_id": representative.get("machine_id"),
            "gpu_model": models[0] if len(models) == 1 else None,
            "gpu_models": models,
            "gpu_identity": gpu_identity,
            "gpu_sample_count": len(samples),
            "mean_observed_hashrate_ths": sum(rates) / len(rates) if rates else None,
            "accepted_share_count": shares["share_accepted"],
            "stale_share_count": shares["share_stale"],
            "rejected_share_count": shares["share_rejected"],
            "first_event_utc": min(timestamped).isoformat().replace("+00:00", "Z") if timestamped else None,
            "last_event_utc": max(timestamped).isoformat().replace("+00:00", "Z") if timestamped else None,
            "billed_seconds": None,
            "productive_seconds": None,
            "billing_status": "UNKNOWN",
        })

    runs = [
        {"run_id": run_id, "segment_ids": sorted(segment_ids), "segment_count": len(segment_ids),
         "event_count": sum(event.get("run_id") == run_id for event in events), "billing_status": "UNKNOWN"}
        for run_id, segment_ids in sorted(by_run.items())
    ]
    minute_buckets: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        timestamp = _time(event)
        if timestamp is not None:
            minute_buckets[(event["run_id"], event["segment_id"], timestamp.strftime("%Y-%m-%dT%H:%M"))].append(event)
    minute_stats: list[dict[str, Any]] = []
    for (run_id, segment_id, minute), bucket in sorted(minute_buckets.items()):
        samples = [event for event in bucket if event.get("event_type") == "gpu_sample"]
        rates = [float(event["payload"]["hashrate_ths"]) for event in samples if event.get("payload", {}).get("hashrate_ths") is not None]
        minute_stats.append({
            "schema_version": V2_SCHEMA_VERSION,
            "run_id": run_id, "segment_id": segment_id,
            "minute_utc_bucket": minute + ":00Z",
            "sample_count": len(samples),
            "hashrate_mean_ths": sum(rates) / len(rates) if rates else None,
            "accepted_share_events": sum(e.get("event_type") == "share_accepted" for e in bucket),
            "stale_events": sum(e.get("event_type") == "share_stale" for e in bucket),
            "rejected_events": sum(e.get("event_type") == "share_rejected" for e in bucket),
        })

    work = build_work_accounting(events, sources)
    report = {
        "schema_version": V2_SCHEMA_VERSION,
        "source": "salad_exported_krig_csv_batch",
        "source_bundle_sha256": snapshot["source_bundle_sha256"],
        "source_timezone_option": snapshot["source_timezone"],
        "recorded_at_utc": snapshot["recorded_at_utc"],
        "source_manifest": snapshot["source_manifest"],
        "source_event_count": snapshot["source_event_count"],
        "deduplicated_event_count": snapshot["deduplicated_event_count"],
        "event_count": len(events),
        "event_counts": dict(sorted(Counter(e.get("event_type") for e in events).items())),
        "ambiguous_event_count": snapshot["ambiguous_event_count"],
        "unresolved_event_count": snapshot["unresolved_event_count"],
        "run_count": len(runs),
        "segment_count": len(segments),
        "billed_seconds": None,
        "productive_seconds": None,
        "billing_status": "UNKNOWN",
        "billing_unknown_reason": "KRig telemetry cannot establish Salad billing or productive time",
        "income_stages": ["estimated", "pool_observed", "paid", "converted", "realized"],
        "income_stages_are_non_additive": True,
        "runs": runs,
        "segments": segments,
    }
    return {"snapshot": snapshot, "runs": runs, "segments": segments, "minute_stats": minute_stats, "work": work, "report": report}


def write_v2_batch(sources: list[ParsedKrigCsv], output_dir: str | Path) -> dict[str, Any]:
    """Write a coherent new V2 output directory; never merge with existing ledgers."""
    destination = Path(output_dir)
    if destination.exists():
        raise ValueError("V2 batch output directory must be new and empty of prior artifacts")
    batch = build_v2_batch(sources)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (temporary / "events.jsonl").write_text("".join(_json_line(event) + "\n" for event in batch["snapshot"]["events"]), encoding="utf-8")
        (temporary / "segments.json").write_text(json.dumps({"schema_version": V2_SCHEMA_VERSION, "runs": batch["runs"], "segments": batch["segments"]}, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (temporary / "minute_stats.jsonl").write_text("".join(_json_line(record) + "\n" for record in batch["minute_stats"]), encoding="utf-8")
        (temporary / "work.json").write_text(json.dumps(batch["work"], ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (temporary / "report.json").write_text(json.dumps(batch["report"], ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
    except Exception:
        import shutil
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {"output_dir": str(destination), "schema_version": V2_SCHEMA_VERSION, "source_count": len(batch["snapshot"]["source_manifest"]), "source_event_count": batch["snapshot"]["source_event_count"], "events_written": len(batch["snapshot"]["events"]), "deduplicated_event_count": batch["snapshot"]["deduplicated_event_count"], "run_count": len(batch["runs"]), "segment_count": len(batch["segments"])}
