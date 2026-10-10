"""Read-only parser for Salad-exported KRig CSV logs."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import SCHEMA_VERSION, SOURCE_CLASS, SOURCE_NAME, utc_now_text

_LOG_CLOCK_RE = re.compile(r"^\s*(\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\s+")
_START_RE = re.compile(
    r"starting\s+(?P<miner>[A-Za-z0-9_-]+)\s+v(?P<version>[A-Za-z0-9._+-]+):\s*"
    r"coin=(?P<coin>[^\s]+)\s+pool=(?P<pool>[^\s]+)\s+device=(?P<device>[^\s]+)",
    re.IGNORECASE,
)
_GPU_RE = re.compile(
    r"GPU(?P<gpu_index>\d+)\s+(?:(?:[0-9A-Fa-f:.]+)\s+)?(?P<gpu_model>[^:]+):\s*"
    r"(?P<hashrate>[\d.]+)\s*TH/s\s+"
    r"(?P<accepted>\d+)\s*/\s*(?P<stale>\d+)\s*/\s*(?P<rejected>\d+)"
    r"(?:\s+(?P<efficiency>[\d.]+)\s*GH/W)?"
    r"(?:\s+(?P<power>[\d.]+)\s*W)?"
    r"(?:\s+(?P<temperature>-?[\d.]+)\s*C)?"
    r"(?:\s+(?P<tail>.*))?$",
    re.IGNORECASE,
)
_TOTAL_RE = re.compile(
    r"Total:\s*(?P<hashrate>[\d.]+)\s*TH/s\s+shares:\s*"
    r"(?P<accepted>\d+)\s+accepted\s+(?P<stale>\d+)\s+stale\s+"
    r"(?P<rejected>\d+)\s+rejected",
    re.IGNORECASE,
)
_ACCEPTED_RE = re.compile(
    r"share\s+accepted:\s*GPU(?P<gpu_index>\d+)\s+(?P<latency>[\d.]+)\s*ms",
    re.IGNORECASE,
)
_REJECTED_RE = re.compile(r"share\s+rejected(?::\s*GPU(?P<gpu_index>\d+))?", re.IGNORECASE)
_STALE_RE = re.compile(r"share\s+stale(?::\s*GPU(?P<gpu_index>\d+))?", re.IGNORECASE)
_STRATUM_RE = re.compile(r"stratum:\s*new\s+job", re.IGNORECASE)
_PERCENT_RE = re.compile(r"(?P<utilization>[\d.]+)%")
_CLOCKS_RE = re.compile(r"(?P<core>\d+)\s*\(\+[-\d]+\)\s+(?P<memory>\d+)\s*\(\+[-\d]+\)")

_REQUIRED_COLUMNS = {
    "Time",
    "Text Log",
    "Resource labels container group name",
    "Resource labels container group version",
    "Resource labels instance id",
    "Resource labels machine id",
}


@dataclass(frozen=True)
class ParsedKrigCsv:
    events: list[dict[str, Any]]
    source_file_sha256: str
    source_file_name: str
    source_timezone: str | None
    recorded_at_utc: str
    data_rows: int
    empty_log_rows_ignored: int
    unrecognized_nonempty_rows: int


def _clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _parse_datetime(value: str) -> datetime | None:
    value = value.strip()
    if not value:
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        pass
    for fmt in (
        "%m/%d/%Y, %I:%M:%S %p",
        "%m/%d/%Y %I:%M:%S %p",
        "%m/%d/%Y, %I:%M:%S.%f %p",
        "%m/%d/%Y %I:%M:%S.%f %p",
    ):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _parse_log_clock(value: str) -> time | None:
    try:
        parsed = time.fromisoformat(value)
        return parsed.replace(tzinfo=None)
    except ValueError:
        return None


def _source_datetime(
    row_timestamp: str,
    receive_timestamp: str,
    text_log: str,
    source_zone: ZoneInfo | None,
) -> tuple[datetime | None, str, str]:
    original = row_timestamp or receive_timestamp
    parsed = _parse_datetime(original)
    precision = "second" if parsed is not None else "unknown"

    clock_match = _LOG_CLOCK_RE.match(text_log)
    if parsed is not None and clock_match:
        log_clock_text = clock_match.group(1)
        log_clock = _parse_log_clock(log_clock_text)
        if log_clock is not None:
            existing_zone = parsed.tzinfo
            clock_zone = existing_zone if existing_zone is not None else source_zone
            anchor = parsed if existing_zone is not None else parsed.replace(tzinfo=clock_zone)
            candidate_times = [
                datetime.combine(parsed.date() + timedelta(days=day_offset), log_clock, tzinfo=clock_zone)
                for day_offset in (-1, 0, 1)
            ]

            def distance_from_row(candidate: datetime) -> float:
                if candidate.tzinfo is not None and anchor.tzinfo is not None:
                    return abs((candidate.astimezone(timezone.utc) - anchor.astimezone(timezone.utc)).total_seconds())
                return abs((candidate.replace(tzinfo=None) - anchor.replace(tzinfo=None)).total_seconds())

            parsed = min(candidate_times, key=distance_from_row)
            precision = "millisecond" if "." in log_clock_text else "second"
    elif parsed is not None and parsed.microsecond:
        precision = "millisecond"

    if parsed is not None and parsed.tzinfo is None and source_zone is not None:
        parsed = parsed.replace(tzinfo=source_zone)

    if parsed is None:
        return None, original, precision
    source_clock = parsed.replace(tzinfo=None).isoformat(timespec="microseconds" if parsed.microsecond else "seconds")
    return parsed, original, precision


def _utc_text(timestamp: datetime | None) -> str | None:
    if timestamp is None or timestamp.tzinfo is None:
        return None
    return timestamp.astimezone(timezone.utc).isoformat(timespec="microseconds" if timestamp.microsecond else "seconds").replace("+00:00", "Z")


def _number(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _tail_metrics(tail: str | None) -> dict[str, float | int]:
    result: dict[str, float | int] = {}
    if not tail:
        return result
    percent = _PERCENT_RE.search(tail)
    clocks = _CLOCKS_RE.search(tail)
    if percent:
        result["utilization_percent"] = float(percent.group("utilization"))
    if clocks:
        result["core_clock_mhz"] = int(clocks.group("core"))
        result["memory_clock_mhz"] = int(clocks.group("memory"))
    return result


def _classify_log(text_log: str, severity: str) -> tuple[str, dict[str, Any]] | None:
    text = text_log.strip()
    if not text:
        return None

    start = _START_RE.search(text)
    if start:
        pool = start.group("pool")
        pool_match = re.match(r"(?P<host>\[[^\]]+\]|[^:]+):(?P<port>\d+)$", pool)
        payload: dict[str, Any] = {
            "miner": start.group("miner"),
            "miner_version": start.group("version"),
            "coin": start.group("coin"),
            "pool_host": pool_match.group("host").strip("[]") if pool_match else None,
            "pool_port": int(pool_match.group("port")) if pool_match else None,
            "device": start.group("device"),
        }
        return "worker_start", payload

    gpu = _GPU_RE.search(text)
    if gpu:
        payload = {
            "gpu_index": int(gpu.group("gpu_index")),
            "gpu_model": gpu.group("gpu_model").strip(),
            "gpu_identity": {
                "raw_model": gpu.group("gpu_model").strip(),
                "model": None,
                "form_factor": "unknown",
                "identity_source": "krig_text_log_gpu_model",
                "identity_verified": False,
                "identity_status": "model_label_without_verified_form_factor",
            },
            "hashrate_ths": float(gpu.group("hashrate")),
            "hashrate_semantics": "krig_device_reported",
            "hashrate_source": "krig_text_log_gpu_sample",
            "accepted_total": int(gpu.group("accepted")),
            "stale_total": int(gpu.group("stale")),
            "rejected_total": int(gpu.group("rejected")),
            "efficiency_gh_w": _number(gpu.group("efficiency")),
            "power_w": _number(gpu.group("power")),
            "temperature_c": _number(gpu.group("temperature")),
        }
        payload.update(_tail_metrics(gpu.group("tail")))
        return "gpu_sample", payload

    total = _TOTAL_RE.search(text)
    if total:
        return "total_sample", {
            "hashrate_ths": float(total.group("hashrate")),
            "accepted_total": int(total.group("accepted")),
            "stale_total": int(total.group("stale")),
            "rejected_total": int(total.group("rejected")),
        }

    accepted = _ACCEPTED_RE.search(text)
    if accepted:
        return "share_accepted", {
            "gpu_index": int(accepted.group("gpu_index")),
            "response_latency_ms": float(accepted.group("latency")),
        }

    rejected = _REJECTED_RE.search(text)
    if rejected:
        payload = {"gpu_index": int(rejected.group("gpu_index"))} if rejected.group("gpu_index") else {}
        return "share_rejected", payload

    stale = _STALE_RE.search(text)
    if stale:
        payload = {"gpu_index": int(stale.group("gpu_index"))} if stale.group("gpu_index") else {}
        return "share_stale", payload

    if _STRATUM_RE.search(text):
        return "stratum_job", {}

    lowered = text.lower()
    severity_error = severity.strip().lower() in {"error", "critical", "fatal", "alert", "emergency"}
    looks_like_error = severity_error or any(
        marker in lowered
        for marker in (" error", "error:", "failed", "failure", "exception", "fatal", "not exposed")
    )
    if looks_like_error:
        if "nvidia runtime is not exposed" in lowered and "/dev/nvidiactl is missing" in lowered:
            category = "legacy_nvidia_runtime_not_exposed"
            source_class = "legacy_runtime_preflight_failure"
        elif "cuda" in lowered and any(word in lowered for word in ("init", "initial", "error", "failed")):
            category = "cuda_initialization_error"
            source_class = "miner_runtime_error"
        elif "stratum" in lowered or "pool" in lowered:
            category = "pool_or_stratum_error"
            source_class = "miner_runtime_error"
        elif "krig-entrypoint" in lowered or "runtime" in lowered:
            category = "runtime_error"
            source_class = "miner_runtime_error"
        else:
            category = "unclassified_error"
            source_class = "miner_runtime_error"
        return "miner_error", {"error_category": category, "error_source_class": source_class}

    return None


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}_{digest}"


def import_krig_csv(
    input_path: str | Path,
    *,
    source_timezone: str | None = None,
    recorded_at_utc: str | None = None,
) -> ParsedKrigCsv:
    """Parse a CSV without modifying it; timestamps remain non-UTC unless known."""
    path = Path(input_path)
    raw_bytes = path.read_bytes()
    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    try:
        decoded = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"CSV is not valid UTF-8: {path.name}") from exc

    source_zone = None
    if source_timezone:
        try:
            source_zone = ZoneInfo(source_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Unknown IANA timezone: {source_timezone}") from exc

    reader = csv.DictReader(io.StringIO(decoded, newline=""))
    fields = set(reader.fieldnames or [])
    missing = sorted(_REQUIRED_COLUMNS - fields)
    if missing:
        raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")

    import_time = recorded_at_utc or utc_now_text()
    event_rows: list[tuple[datetime | None, int, dict[str, Any]]] = []
    empty_rows = 0
    unrecognized_rows = 0
    data_rows = 0

    for source_row, row in enumerate(reader, start=2):
        data_rows += 1
        text_log = _clean(row.get("Text Log"))
        if not text_log:
            empty_rows += 1
            continue

        severity = _clean(row.get("Severity"))
        classified = _classify_log(text_log, severity)
        if classified is None:
            unrecognized_rows += 1
            continue
        event_type, payload = classified

        group_name = _clean(row.get("Resource labels container group name")) or "UNKNOWN"
        group_version = _clean(row.get("Resource labels container group version")) or "UNKNOWN"
        instance_id = _clean(row.get("Resource labels instance id")) or "UNKNOWN"
        machine_id = _clean(row.get("Resource labels machine id")) or "UNKNOWN"
        identity_complete = all(value != "UNKNOWN" for value in (group_name, group_version, instance_id, machine_id))

        run_id = _stable_id("run", source_sha256, group_name)
        identity_parts = [group_name, group_version, instance_id, machine_id]
        if not identity_complete:
            # Missing provider identity is never used to merge otherwise unrelated rows.
            identity_parts.append(f"unresolved-source-row-{source_row}")
        segment_id = _stable_id("segment", run_id, *identity_parts)

        timestamp, source_timestamp_text, precision = _source_datetime(
            _clean(row.get("Time")),
            _clean(row.get("Receive Time")),
            text_log,
            source_zone,
        )
        source_clock_text = None
        if timestamp is not None:
            source_clock = timestamp.replace(tzinfo=None)
            source_clock_text = source_clock.isoformat(
                timespec="microseconds" if source_clock.microsecond else "seconds"
            )

        event_id = _stable_id("event", source_sha256, str(source_row), event_type)
        event = {
            "schema_version": SCHEMA_VERSION,
            "event_id": event_id,
            "run_id": run_id,
            "segment_id": segment_id,
            "event_type": event_type,
            "source": SOURCE_NAME,
            "source_class": SOURCE_CLASS,
            "source_row": source_row,
            "source_timestamp_text": source_timestamp_text or None,
            "occurred_at_source_clock": source_clock_text,
            "occurred_at_utc": _utc_text(timestamp),
            "occurred_at_precision": precision,
            "recorded_at_utc": import_time,
            "raw_reference": {
                "source_file_sha256": source_sha256,
                "source_file_name": path.name,
                "source_row": source_row,
            },
            "container_group_name": group_name,
            "container_group_version": group_version,
            "instance_id": instance_id,
            "machine_id": machine_id,
            "segment_identity_complete": identity_complete,
            "payload": payload,
        }
        sort_value = timestamp
        if sort_value is not None and sort_value.tzinfo is not None:
            sort_value = sort_value.astimezone(timezone.utc).replace(tzinfo=None)
        event_rows.append((sort_value, source_row, event))

    # Source exports may be reverse chronological. Missing source times remain stable by row.
    event_rows.sort(key=lambda item: (item[0] is None, item[0] or datetime.max, item[1]))
    events = [event for _, _, event in event_rows]
    return ParsedKrigCsv(
        events=events,
        source_file_sha256=source_sha256,
        source_file_name=path.name,
        source_timezone=source_timezone,
        recorded_at_utc=import_time,
        data_rows=data_rows,
        empty_log_rows_ignored=empty_rows,
        unrecognized_nonempty_rows=unrecognized_rows,
    )
