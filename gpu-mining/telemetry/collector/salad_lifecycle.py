"""Offline parser for provider lifecycle observations in Salad CSV exports."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import V2_SCHEMA_VERSION, utc_now_text


_LOG_COLUMNS = ("Text Log", "Json Log message")
_IDENTITY_COLUMNS = (
    "Resource labels container group name",
    "Resource labels container group version",
    "Resource labels instance id",
    "Resource labels machine id",
)


@dataclass(frozen=True)
class ParsedSaladLifecycleCsv:
    events: list[dict[str, Any]]
    source_file_sha256: str
    source_file_name: str
    recorded_at_utc: str
    data_rows: int
    empty_log_rows: int
    recognized_observations: int
    unrecognized_nonempty_cells: int
    duplicate_observation_groups: int
    source_conflict_groups: list[dict[str, Any]]


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:32]}"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _timestamp(row: dict[str, Any]) -> tuple[str | None, str | None, str]:
    original = _text(row.get("Time")) or _text(row.get("Receive Time"))
    if not original:
        return None, None, "unknown"
    candidate = original[:-1] + "+00:00" if original.endswith("Z") else original
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        parsed = None
    if parsed is None:
        for fmt in (
            "%Y/%m/%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S.%f",
            "%m/%d/%Y, %I:%M:%S %p",
            "%m/%d/%Y, %I:%M:%S.%f %p",
            "%m/%d/%Y %I:%M:%S %p",
        ):
            try:
                parsed = datetime.strptime(original, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return original, None, "unparsed_source_timestamp"
    precision = "millisecond" if parsed.microsecond else "second"
    if parsed.tzinfo is None:
        return original, None, precision
    return original, parsed.astimezone(timezone.utc).isoformat(timespec="microseconds" if parsed.microsecond else "seconds").replace("+00:00", "Z"), precision


def _classify(message: str, source_column: str) -> dict[str, Any] | None:
    value = " ".join(message.strip().split())
    if not value:
        return None
    folded = value.casefold()
    provider_prefix = folded.startswith("instance ")
    phrase = folded.removeprefix("instance ").strip()
    generic_json_state = source_column == "Json Log message" and not provider_prefix

    readiness = {
        "instance startup probe passed": ("startup", "passed"),
        "instance startup probe failed": ("startup", "failed"),
        "instance ready (readiness probe passed)": ("readiness", "passed"),
        "instance ready (readiness probe failed)": ("readiness", "failed"),
        "readiness probe passed": ("readiness", "passed"),
        "readiness probe failed": ("readiness", "failed"),
        "startup probe passed": ("startup", "passed"),
        "startup probe failed": ("startup", "failed"),
    }
    readiness_value = readiness.get(folded)
    if readiness_value is not None:
        probe, outcome = readiness_value
        return {
            "reported_state": (
                "startup_probe_passed" if probe == "startup" and outcome == "passed"
                else "startup_probe_failed" if probe == "startup"
                else "ready" if outcome == "passed"
                else "readiness_failed"
            ),
            "observation_kind": "readiness_probe",
            "readiness_probe": probe,
            "readiness_outcome": outcome,
        }

    state_map = {
        "allocating": "allocating",
        "allocated": "allocated",
        "downloading": "downloading",
        "creating": "creating",
        "starting": "starting",
        "running": "running",
        "stopping": "stopping",
        "stopped": "stopped",
        "preempted": "preempted",
        "lost": "lost",
        "terminated": "terminated",
        "reallocated": "reallocated",
        "ready": "ready",
    }
    state = state_map.get(phrase)
    if state is None or not (provider_prefix or generic_json_state):
        return None
    return {
        "reported_state": state,
        "observation_kind": "provider_lifecycle_log_observation",
        "readiness_probe": None,
        "readiness_outcome": None,
    }


def import_salad_lifecycle_csv(
    input_path: str | Path,
    *,
    recorded_at_utc: str | None = None,
) -> ParsedSaladLifecycleCsv:
    """Read named lifecycle columns independently and preserve their provenance."""
    path = Path(input_path)
    raw = path.read_bytes()
    source_hash = hashlib.sha256(raw).hexdigest()
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"CSV is not valid UTF-8: {path.name}") from exc
    reader = csv.DictReader(io.StringIO(decoded, newline=""))
    fields = set(reader.fieldnames or [])
    missing = sorted(set(_LOG_COLUMNS) - fields)
    if missing:
        raise ValueError(f"CSV is missing required log columns: {', '.join(missing)}")

    events: list[dict[str, Any]] = []
    source_conflicts: list[dict[str, Any]] = []
    duplicate_groups = 0
    data_rows = 0
    empty_rows = 0
    unrecognized = 0
    for source_row, row in enumerate(reader, start=2):
        data_rows += 1
        nonempty_cells = 0
        row_events: list[dict[str, Any]] = []
        source_timestamp_text, occurred_at_utc, precision = _timestamp(row)
        assignment = {column: (_text(row.get(column)) or None) for column in _IDENTITY_COLUMNS if column in fields}
        for source_column in _LOG_COLUMNS:
            message = _text(row.get(source_column))
            if not message:
                continue
            nonempty_cells += 1
            classified = _classify(message, source_column)
            if classified is None:
                unrecognized += 1
                continue
            event_type = "readiness_observation" if classified["observation_kind"] == "readiness_probe" else "provider_lifecycle_observation"
            event_id = _stable_id("salad-lifecycle-source", [source_hash, source_row, source_column, event_type, classified])
            event = {
                "schema_version": V2_SCHEMA_VERSION,
                "event_id": event_id,
                "event_type": event_type,
                "source": "salad_exported_lifecycle_csv",
                "source_class": "provider_log_observation",
                "source_file_name": path.name,
                "source_file_sha256": source_hash,
                "source_row": source_row,
                "event_source": source_column,
                "event_message": message,
                "source_timestamp_text": source_timestamp_text or None,
                "occurred_at_utc": occurred_at_utc,
                "occurred_at_precision": precision,
                "provider_identity": assignment,
                **classified,
                "billing_status": "UNKNOWN",
                "billing_evidence_present": False,
                "billing_inferred_from_event": False,
            }
            row_events.append(event)

        if nonempty_cells == 0:
            empty_rows += 1
        if len(row_events) > 1:
            signatures = {
                (event["event_type"], event["reported_state"], event["readiness_probe"], event["readiness_outcome"])
                for event in row_events
            }
            duplicate_group_id = _stable_id("salad-lifecycle-row-observation", [source_hash, source_row, sorted(signatures)])
            if len(signatures) == 1:
                duplicate_groups += 1
                for event in row_events:
                    event["cross_source_observation_group_id"] = duplicate_group_id
                    event["cross_source_observation_status"] = "equivalent_observation_in_both_log_columns"
            else:
                source_conflicts.append({
                    "source_row": source_row,
                    "group_id": duplicate_group_id,
                    "event_ids": [event["event_id"] for event in row_events],
                    "event_sources": [event["event_source"] for event in row_events],
                    "reported_states": [event["reported_state"] for event in row_events],
                    "status": "conflicting_observations_in_log_columns",
                })
                for event in row_events:
                    event["cross_source_observation_group_id"] = duplicate_group_id
                    event["cross_source_observation_status"] = "conflicting_observation_in_same_csv_row"
        else:
            for event in row_events:
                event["cross_source_observation_group_id"] = None
                event["cross_source_observation_status"] = "single_source_observation"
        events.extend(row_events)

    return ParsedSaladLifecycleCsv(
        events=events,
        source_file_sha256=source_hash,
        source_file_name=path.name,
        recorded_at_utc=recorded_at_utc or utc_now_text(),
        data_rows=data_rows,
        empty_log_rows=empty_rows,
        recognized_observations=len(events),
        unrecognized_nonempty_cells=unrecognized,
        duplicate_observation_groups=duplicate_groups,
        source_conflict_groups=source_conflicts,
    )


def build_salad_lifecycle_report(sources: list[ParsedSaladLifecycleCsv]) -> dict[str, Any]:
    events = [event for source in sources for event in source.events]
    return {
        "schema_version": V2_SCHEMA_VERSION,
        "source": "salad_exported_lifecycle_csv",
        "source_count": len(sources),
        "source_manifest": [
            {"source_file_name": source.source_file_name, "source_file_sha256": source.source_file_sha256, "data_rows": source.data_rows}
            for source in sources
        ],
        "data_rows": sum(source.data_rows for source in sources),
        "event_count": len(events),
        "event_counts": {key: sum(event["event_type"] == key for event in events) for key in sorted({event["event_type"] for event in events})},
        "duplicate_observation_groups": sum(source.duplicate_observation_groups for source in sources),
        "source_conflict_groups": [conflict for source in sources for conflict in source.source_conflict_groups],
        "billing_status": "UNKNOWN",
        "billing_evidence_present": False,
        "billing_inferred_from_provider_events": False,
        "actions_performed": False,
        "recorded_at_utc": max((source.recorded_at_utc for source in sources), default=utc_now_text()),
    }


def write_salad_lifecycle_outputs(sources: list[ParsedSaladLifecycleCsv], output_dir: str | Path) -> dict[str, Any]:
    destination = Path(output_dir)
    if destination.exists():
        raise ValueError("lifecycle output directory must be new")
    report = build_salad_lifecycle_report(sources)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        events = [event for source in sources for event in source.events]
        (temporary / "events.jsonl").write_text("".join(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n" for event in events), encoding="utf-8")
        (temporary / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
    except Exception:
        import shutil
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {"output_dir": str(destination), "event_count": report["event_count"], "source_count": report["source_count"], "billing_status": "UNKNOWN"}
