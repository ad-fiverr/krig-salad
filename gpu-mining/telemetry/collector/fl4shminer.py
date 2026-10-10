"""Offline Fl4shMiner parser with namespaced device observations."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import re
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .gpu_identity import normalize_gpu_identity
from .models import V2_SCHEMA_VERSION, utc_now_text
from .work import build_work_accounting


_TEXT_COLUMN = "Text Log"
_IDENTITY_COLUMNS = (
    "Resource labels container group name",
    "Resource labels container group version",
    "Resource labels instance id",
    "Resource labels machine id",
)
_START_RE = re.compile(
    r"starting\s+Fl4shMiner\s+v(?P<version>[\w.+-]+):\s*coin=(?P<coin>[^,\s]+)\s+"
    r"pool=(?P<pool>[^,\s]+)\s+device=(?P<device>[^,\s]+)", re.IGNORECASE
)
_DEVICE_RATE_RE = re.compile(
    r"Device\s*\[(?P<device>\d+)\]\s+hashRate:\s*(?P<rate>[\d.]+)\s*(?P<unit>TH/s|GH/s|MH/s)"
    r"\s*,\s*stale:\s*(?P<stale>\d+)\s*/\s*(?P<total>\d+)\s*\((?P<percent>[\d.]+)%\)"
    r"(?:\s*,\s*warm:\s*(?P<warm>\d+))?", re.IGNORECASE,
)
_POOL_EQ_RE = re.compile(
    r"Device\s*\[(?P<device>\d+)\]\s+CUDA\s+autotune:\s*(?P<rate>[\d.]+)\s*(?P<unit>TH/s|GH/s|MH/s)\s*"
    r"\(measured\s+pool-equivalent\)", re.IGNORECASE,
)
_AUTOTUNE_RE = re.compile(
    r"GPU=(?P<model>.+?)\s+Pearl\s+autotune\s+hashrate\s*=\s*(?P<rate>[\d.]+)\s*(?P<unit>TH/s|GH/s|MH/s)", re.IGNORECASE,
)
_SOLUTION_RE = re.compile(
    r"Solutions\s+(?P<status>accepted|rejected):\s*(?P<device>\d+)-(?P<model>[^,]+),\s*"
    r"(?P<solution_hex>0x[0-9a-fA-F]+)\s*,\s*pool=(?P<pool>[^,]+)(?P<tail>.*)$", re.IGNORECASE,
)
_POOL_CONNECTED_RE = re.compile(r"Pool\s+connected:\s*(?P<pool>\S+)\s*\(latency\s+(?P<latency>[\d.]+)\s*ms\)", re.IGNORECASE)
_TIMESTAMP_PREFIX_RE = re.compile(r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+")


@dataclass(frozen=True)
class ParsedFl4shMinerCsv:
    events: list[dict[str, Any]]
    source_file_sha256: str
    source_file_name: str
    recorded_at_utc: str
    data_rows: int
    empty_log_rows: int
    recognized_events: int
    unrecognized_nonempty_rows: int


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}_{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:32]}"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _rate_ths(value: str, unit: str) -> float:
    scale = {"TH/S": 1.0, "GH/S": 0.001, "MH/S": 0.000001}[unit.upper()]
    return float(value) * scale


def _pool_parts(value: str) -> dict[str, Any]:
    try:
        parsed = urlsplit(value)
        return {"pool_scheme": parsed.scheme or None, "pool_host": parsed.hostname, "pool_port": parsed.port}
    except ValueError:
        return {"pool_scheme": None, "pool_host": None, "pool_port": None}


def _timestamp(row: dict[str, Any], message: str) -> tuple[str | None, str | None, str]:
    original = _text(row.get("Time")) or _text(row.get("Receive Time"))
    prefix = _TIMESTAMP_PREFIX_RE.match(message)
    if prefix is not None:
        original = original or prefix.group("timestamp")
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


def _source_clock(timestamp_text: str | None, message: str) -> str | None:
    """Parse a local/source wall clock for within-export ordering only.

    Salad's historical ``Time`` field is commonly naive and must not be promoted
    to UTC. A local clock is still useful to group records in one export around
    their own worker-start observation; it is never used to merge exports.
    """
    original = timestamp_text or ""
    parsed: datetime | None = None
    candidate = original[:-1] + "+00:00" if original.endswith("Z") else original
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
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
        prefix = _TIMESTAMP_PREFIX_RE.match(message)
        if prefix is not None:
            for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M:%S.%f"):
                try:
                    parsed = datetime.strptime(prefix.group("timestamp"), fmt)
                    break
                except ValueError:
                    continue
    if parsed is None:
        return None
    # Preserve the source wall clock. This value is deliberately not UTC.
    return parsed.replace(tzinfo=None).isoformat(timespec="microseconds" if parsed.microsecond else "seconds")


def _classify(message: str) -> tuple[str, dict[str, Any]] | None:
    start = _START_RE.search(message)
    if start:
        return "worker_start", {
            "miner": "Fl4shMiner",
            "miner_version": start.group("version"),
            "coin": start.group("coin"),
            "wrapper_device_id": start.group("device"),
            "wrapper_device_namespace": "salad_wrapper_device",
            "worker_hashrate_status": "not_reported_by_start_record",
            **_pool_parts(start.group("pool")),
        }

    match = _DEVICE_RATE_RE.search(message)
    if match:
        return "gpu_sample", {
            "gpu_index": int(match.group("device")),
            "device_id": str(match.group("device")),
            "device_namespace": "fl4shminer_device",
            "hashrate_ths": _rate_ths(match.group("rate"), match.group("unit")),
            "hashrate_reported_value": float(match.group("rate")),
            "hashrate_reported_unit": match.group("unit").upper(),
            "hashrate_semantics": "fl4shminer_device_reported",
            "hashrate_source": "Text Log:Device hashRate",
            "stale_counter_numerator": int(match.group("stale")),
            "stale_counter_denominator": int(match.group("total")),
            "stale_counter_reported_percent": float(match.group("percent")),
            "stale_counter_semantics": "cumulative_stale_over_reported_solution_counter",
            "stale_counter_is_paid_share_count": False,
            "warm_counter": int(match.group("warm")) if match.group("warm") else None,
        }

    match = _POOL_EQ_RE.search(message)
    if match:
        return "hashrate_estimate", {
            "device_id": str(match.group("device")),
            "device_namespace": "fl4shminer_device",
            "estimate_kind": "cuda_autotune_measured_pool_equivalent",
            "hashrate_reported_value": float(match.group("rate")),
            "hashrate_reported_unit": match.group("unit").upper(),
            "hashrate_ths": _rate_ths(match.group("rate"), match.group("unit")),
            "hashrate_semantics": "fl4shminer_cuda_autotune_pool_equivalent_estimate",
            "hashrate_source": "Text Log:CUDA autotune pool-equivalent",
            "worker_hashrate": False,
        }

    match = _AUTOTUNE_RE.search(message)
    if match:
        return "hashrate_estimate", {
            "reported_gpu_model_label": match.group("model").strip(),
            "estimate_kind": "pearl_autotune_reported_estimate",
            "hashrate_reported_value": float(match.group("rate")),
            "hashrate_reported_unit": match.group("unit").upper(),
            "hashrate_ths": _rate_ths(match.group("rate"), match.group("unit")),
            "hashrate_semantics": "pearl_autotune_estimate",
            "hashrate_source": "Text Log:Pearl autotune",
            "worker_hashrate": False,
        }

    match = _SOLUTION_RE.search(message)
    if match:
        tail = match.group("tail")
        status_match = re.search(r"(?:^|,)\s*status=([^,]+)", tail, re.IGNORECASE)
        reason_match = re.search(r"(?:^|,)\s*reason=([^,]+)", tail, re.IGNORECASE)
        proof_match = re.search(r"(?:^|,)\s*proof=([0-9a-fA-Fx]+)", tail, re.IGNORECASE)
        reported_status = match.group("status").casefold()
        event_type = "solution_accepted" if reported_status == "accepted" else "solution_rejected"
        payload: dict[str, Any] = {
            "device_id": str(match.group("device")),
            "device_namespace": "fl4shminer_solution_device",
            "reported_gpu_model_label": match.group("model").strip(),
            "solution_status": reported_status,
            "reported_solution_hex": match.group("solution_hex"),
            "solution_hex_interpretation": "unverified_solution_field_not_difficulty",
            "share_difficulty_value": None,
            "share_difficulty_verified": False,
            "reported_solution_proof_present": proof_match is not None,
            "reported_solution_proof_sha256": hashlib.sha256(proof_match.group(1).encode("ascii")).hexdigest() if proof_match else None,
            **_pool_parts(match.group("pool")),
        }
        if status_match:
            payload["reported_rejection_status"] = status_match.group(1).strip().casefold()
        if reason_match:
            payload["reported_rejection_reason"] = reason_match.group(1).strip()
        return event_type, payload

    match = _POOL_CONNECTED_RE.search(message)
    if match:
        return "worker_connection", {
            "connection_state": "connected",
            "latency_ms": float(match.group("latency")),
            "worker_hashrate": None,
            "worker_hashrate_status": "not_observed_in_supported_record",
            **_pool_parts(match.group("pool")),
        }
    return None


def _parse_source(path: Path, recorded_at_utc: str | None = None) -> ParsedFl4shMinerCsv:
    raw = path.read_bytes()
    source_hash = hashlib.sha256(raw).hexdigest()
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"CSV is not valid UTF-8: {path.name}") from exc
    reader = csv.DictReader(io.StringIO(decoded, newline=""))
    fields = set(reader.fieldnames or [])
    missing = sorted({"Time", "Text Log"} - fields)
    if missing:
        raise ValueError(f"CSV is missing required Fl4shMiner columns: {', '.join(missing)}")

    rows: list[tuple[int, dict[str, Any], str, tuple[str, ...], dict[str, Any]]] = []
    provider_gpu_labels_by_assignment: dict[tuple[str, ...], set[str]] = defaultdict(set)
    empty_rows = 0
    unrecognized = 0
    for source_row, row in enumerate(reader, start=2):
        message = _text(row.get(_TEXT_COLUMN))
        provider_values = tuple(_text(row.get(column)) for column in _IDENTITY_COLUMNS)
        provider_complete = len(provider_values) == len(_IDENTITY_COLUMNS) and all(provider_values)
        if "Json Log gpu class name" in fields and provider_complete:
            provider_gpu_label = _text(row.get("Json Log gpu class name"))
            if provider_gpu_label:
                provider_gpu_labels_by_assignment[provider_values].add(provider_gpu_label)
        if not message:
            empty_rows += 1
            continue
        classified = _classify(message)
        if classified is None:
            unrecognized += 1
            continue
        event_type, payload = classified
        source_timestamp_text, occurred_at_utc, precision = _timestamp(row, message)
        identity = {column: value or None for column, value in zip(_IDENTITY_COLUMNS, provider_values)}
        rows.append((source_row, row, event_type, provider_values, {
            "payload": payload,
            "source_timestamp_text": source_timestamp_text,
            "occurred_at_utc": occurred_at_utc,
            "occurred_at_precision": precision,
            "occurred_at_source_clock": _source_clock(source_timestamp_text, message),
            "provider_identity": identity,
            "provider_identity_complete": bool(provider_complete),
        }))

    provider_gpu_identity_by_assignment: dict[tuple[str, ...], dict[str, Any]] = {}
    for assignment, labels_seen in provider_gpu_labels_by_assignment.items():
        provider_gpu_labels = sorted(labels_seen)
        provider_gpu_identity_by_assignment[assignment] = (
            normalize_gpu_identity(
                provider_gpu_labels[0],
                identity_source="salad_json_log_gpu_class_name",
                identity_verified=True,
            )
            if len(provider_gpu_labels) == 1 else {
            "raw_model": None,
            "model": None,
            "form_factor": "unknown",
            "identity_source": "salad_json_log_gpu_class_name" if provider_gpu_labels else None,
            "identity_verified": False,
            "identity_status": "missing_or_conflicting_provider_gpu_class_names",
        }
        )

    utc_anchors: dict[tuple[str, ...], set[str]] = defaultdict(set)
    source_clock_anchors: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for _, _, event_type, provider_values, info in rows:
        if event_type != "worker_start":
            continue
        if info["provider_identity_complete"] and info["occurred_at_utc"]:
            utc_anchors[provider_values].add(info["occurred_at_utc"])
        if info["occurred_at_source_clock"]:
            source_clock_anchors[provider_values].add(info["occurred_at_source_clock"])

    events: list[dict[str, Any]] = []
    for source_row, row, event_type, provider_values, info in rows:
        identity_complete = info["provider_identity_complete"]
        occurred_at_utc = info["occurred_at_utc"]
        source_clock = info["occurred_at_source_clock"]
        provider_gpu_identity = provider_gpu_identity_by_assignment.get(provider_values, {
            "raw_model": None,
            "model": None,
            "form_factor": "unknown",
            "identity_source": None,
            "identity_verified": False,
            "identity_status": "provider_assignment_incomplete_or_gpu_class_label_missing",
        })
        verified_anchors = sorted(anchor for anchor in utc_anchors.get(provider_values, set()) if occurred_at_utc and anchor <= occurred_at_utc)
        run_verified = identity_complete and occurred_at_utc and len(verified_anchors) > 0
        if run_verified:
            anchor = verified_anchors[-1]
            run_id = _stable_id("fl4sh-run-v2", [list(provider_values), anchor])
            segment_id = _stable_id("fl4sh-segment-v2", [run_id, list(provider_values)])
            run_identity_status = "verified_provider_assignment_and_worker_start_anchor"
        else:
            if not identity_complete:
                # Without a complete provider assignment, isolate each event. A
                # matching partial label, worker clock, or miner device index is
                # not enough evidence to merge possibly different machines.
                run_id = _stable_id("fl4sh-run-incomplete-assignment-event", [source_hash, source_row, event_type])
                segment_id = _stable_id("fl4sh-segment-incomplete-assignment-event", [run_id, source_hash, source_row])
                run_identity_status = "incomplete_provider_assignment_event_isolated"
            else:
                local_anchors = sorted(anchor for anchor in source_clock_anchors.get(provider_values, set()) if source_clock and anchor <= source_clock)
                local_anchor = local_anchors[-1] if local_anchors else None
                local_run_key = local_anchor or "unanchored-assignment-in-this-export"
                run_id = _stable_id("fl4sh-run-source-local", [source_hash, list(provider_values), local_run_key])
                segment_id = _stable_id("fl4sh-segment-source-local", [run_id, source_hash, list(provider_values)])
                run_identity_status = (
                    "source_local_assignment_and_wall_clock_anchor_timezone_unverified"
                    if local_anchor
                    else "source_local_assignment_without_proven_run_anchor"
                )

        source_event_id = _stable_id("fl4sh-source-event", [source_hash, source_row, event_type])
        payload = dict(info["payload"])
        # Salad's GPU-class label describes the whole provider assignment. It
        # is not an explicit mapping from that GPU to each Fl4shMiner device.
        # Keep it visible at assignment scope; the guard may use it for a
        # single-device segment, but must not copy it to multiple miner devices.
        payload["assignment_gpu_identity"] = provider_gpu_identity
        payload["gpu_identity_scope"] = "provider_assignment"
        event = {
            "schema_version": V2_SCHEMA_VERSION,
            "event_id": source_event_id,
            "source_event_id": source_event_id,
            "logical_event_id": None,
            "run_id": run_id,
            "segment_id": segment_id,
            "run_identity_status": run_identity_status,
            "identity_status": "candidate_verified" if run_verified else run_identity_status,
            "event_type": event_type,
            "source": "salad_exported_fl4shminer_csv",
            "source_class": "exported_miner_log",
            "event_source": _TEXT_COLUMN,
            "source_file_name": path.name,
            "source_file_sha256": source_hash,
            "source_row": source_row,
            "raw_reference": {
                "source_file_name": path.name,
                "source_file_sha256": source_hash,
                "source_row": source_row,
                "source_column": _TEXT_COLUMN,
            },
            "source_timestamp_text": info["source_timestamp_text"],
            "occurred_at_source_clock": source_clock,
            "occurred_at_utc": occurred_at_utc,
            "occurred_at_precision": info["occurred_at_precision"],
            "container_group_name": provider_values[0] or "UNKNOWN",
            "container_group_version": provider_values[1] or "UNKNOWN",
            "instance_id": provider_values[2] or "UNKNOWN",
            "machine_id": provider_values[3] or "UNKNOWN",
            "segment_identity_complete": bool(identity_complete),
            "billing_status": "UNKNOWN",
            "payload": payload,
        }
        if event_type == "gpu_sample":
            payload["assignment_gpu_model"] = provider_gpu_identity.get("raw_model")
        events.append(event)

    return ParsedFl4shMinerCsv(
        events=events,
        source_file_sha256=source_hash,
        source_file_name=path.name,
        recorded_at_utc=recorded_at_utc or utc_now_text(),
        data_rows=sum(1 for _ in csv.DictReader(io.StringIO(decoded, newline=""))),
        empty_log_rows=empty_rows,
        recognized_events=len(events),
        unrecognized_nonempty_rows=unrecognized,
    )


def import_fl4shminer_csv(input_path: str | Path, *, recorded_at_utc: str | None = None) -> ParsedFl4shMinerCsv:
    return _parse_source(Path(input_path), recorded_at_utc=recorded_at_utc)


def build_fl4shminer_snapshot(sources: list[ParsedFl4shMinerCsv]) -> dict[str, Any]:
    all_events = [dict(event) for source in sources for event in source.events]
    fingerprint_counts: Counter[tuple[str, str]] = Counter()
    fingerprint_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in all_events:
        if event.get("identity_status") != "candidate_verified" or not event.get("occurred_at_utc"):
            continue
        semantic_payload = dict(event.get("payload", {}))
        fingerprint = _stable_id("fl4sh-logical-fingerprint", [
            event.get("run_id"), event.get("occurred_at_utc"), event.get("event_type"), semantic_payload,
        ])
        event["logical_event_id"] = _stable_id("fl4sh-logical-event", fingerprint)
        event["_logical_fingerprint"] = fingerprint
        source_hash = event.get("source_file_sha256")
        fingerprint_counts[(source_hash, fingerprint)] += 1
        fingerprint_groups[fingerprint].append(event)

    ambiguous = {
        fingerprint
        for (source_hash, fingerprint), count in fingerprint_counts.items()
        if count > 1
    }
    # Preserve repeated events in one export; deduplicate only a unique match
    # across different exports with a verified run anchor and UTC timestamp.
    deduplicated: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()
    for event in all_events:
        fingerprint = event.get("_logical_fingerprint")
        if not isinstance(fingerprint, str) or fingerprint in ambiguous or fingerprint in seen_fingerprints:
            if isinstance(fingerprint, str) and fingerprint in ambiguous:
                event["logical_event_id"] = None
                event["identity_status"] = "ambiguous_repeated_fingerprint_preserved"
            if fingerprint not in seen_fingerprints or fingerprint in ambiguous:
                deduplicated.append(event)
            continue
        seen_fingerprints.add(fingerprint)
        equivalents = fingerprint_groups[fingerprint]
        unique_source_hashes = {item.get("source_file_sha256") for item in equivalents}
        if len(unique_source_hashes) > 1:
            event["source_references"] = [item.get("raw_reference") for item in equivalents]
            event["source_event_ids"] = [item.get("source_event_id") for item in equivalents]
            event["deduplication_status"] = "verified_equivalent_observation_across_exports"
        else:
            event["source_references"] = [event.get("raw_reference")]
            event["source_event_ids"] = [event.get("source_event_id")]
            event["deduplication_status"] = "source_local_observation"
        deduplicated.append(event)

    by_segment: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in deduplicated:
        by_segment[event["segment_id"]].append(event)
    segments: list[dict[str, Any]] = []
    for segment_id, events in sorted(by_segment.items()):
        samples = [event for event in events if event.get("event_type") == "gpu_sample"]
        rates = [float(event["payload"]["hashrate_ths"]) for event in samples if isinstance(event.get("payload", {}).get("hashrate_ths"), (int, float)) and math.isfinite(float(event["payload"]["hashrate_ths"]))]
        accepted = [event for event in events if event.get("event_type") == "solution_accepted"]
        rejected = [event for event in events if event.get("event_type") == "solution_rejected"]
        representative = events[0]
        identities = {
            json.dumps(
                event.get("payload", {}).get("assignment_gpu_identity")
                if isinstance(event.get("payload", {}).get("assignment_gpu_identity"), dict)
                else event.get("payload", {}).get("gpu_identity", {}),
                sort_keys=True,
            )
            for event in events
            if isinstance(event.get("payload", {}).get("assignment_gpu_identity"), dict)
            or isinstance(event.get("payload", {}).get("gpu_identity"), dict)
        }
        gpu_identity = json.loads(next(iter(identities))) if len(identities) == 1 else {
            "raw_model": None, "model": None, "form_factor": "unknown", "identity_source": None,
            "identity_verified": False, "identity_status": "missing_or_conflicting_provider_gpu_class_names",
        }
        device_observations: dict[tuple[str, str], set[str]] = defaultdict(set)
        for event in events:
            payload = event.get("payload", {})
            if isinstance(payload.get("wrapper_device_id"), str):
                namespace = payload.get("wrapper_device_namespace")
                device_id = payload["wrapper_device_id"]
            elif isinstance(payload.get("device_id"), str):
                namespace = payload.get("device_namespace")
                device_id = payload["device_id"]
            else:
                continue
            if isinstance(namespace, str) and namespace:
                device_observations[(namespace, device_id)].add(event.get("source_event_id", ""))
        unique_devices = [
            {
                "namespace": namespace,
                "id": device_id,
                "source_event_ids": sorted(event_ids - {""}),
            }
            for (namespace, device_id), event_ids in sorted(device_observations.items())
        ]
        segments.append({
            "schema_version": V2_SCHEMA_VERSION,
            "run_id": representative["run_id"],
            "segment_id": segment_id,
            "identity_status": representative.get("identity_status"),
            "run_identity_status": representative.get("run_identity_status"),
            "container_group_name": representative.get("container_group_name"),
            "container_group_version": representative.get("container_group_version"),
            "instance_id": representative.get("instance_id"),
            "machine_id": representative.get("machine_id"),
            "gpu_model": gpu_identity.get("raw_model"),
            "gpu_identity": gpu_identity,
            "gpu_identity_scope": "provider_assignment",
            "gpu_sample_count": len(samples),
            "mean_observed_hashrate_ths": sum(rates) / len(rates) if rates else None,
            "hashrate_semantics": "fl4shminer_device_reported" if samples else None,
            "hashrate_source": "Text Log:Device hashRate" if samples else None,
            "explicit_accepted_solution_count": len(accepted),
            "explicit_rejected_solution_count": len(rejected),
            "cumulative_stale_counter_observations": [
                {"source_row": event.get("source_row"), "device_id": event["payload"].get("device_id"), "device_namespace": event["payload"].get("device_namespace"), "stale": event["payload"].get("stale_counter_numerator"), "total": event["payload"].get("stale_counter_denominator"), "semantics": event["payload"].get("stale_counter_semantics"), "is_paid_share_count": False}
                for event in samples if event["payload"].get("stale_counter_numerator") is not None
            ],
            "device_id_observations": unique_devices,
            "actual_kryptex_worker_hashrate_ths": None,
            "actual_kryptex_worker_hashrate_status": "not_observed_in_supported_records",
            "billed_seconds": None,
            "productive_seconds": None,
            "billing_status": "UNKNOWN",
        })

    report = {
        "schema_version": V2_SCHEMA_VERSION,
        "source": "salad_exported_fl4shminer_csv",
        "source_count": len(sources),
        "source_manifest": [{"source_file_name": source.source_file_name, "source_file_sha256": source.source_file_sha256, "data_rows": source.data_rows} for source in sources],
        "data_rows": sum(source.data_rows for source in sources),
        "recognized_source_event_count": sum(source.recognized_events for source in sources),
        "event_count": len(deduplicated),
        "deduplicated_event_count": sum(event.get("deduplication_status") == "verified_equivalent_observation_across_exports" for event in deduplicated),
        "event_counts": dict(sorted(Counter(event.get("event_type") for event in deduplicated).items())),
        "run_count": len({event.get("run_id") for event in deduplicated}),
        "segment_count": len(segments),
        "worker_hashrate_status": "UNKNOWN_NOT_REPORTED_IN_SUPPORTED_RECORDS",
        "billing_status": "UNKNOWN",
        "billing_evidence_present": False,
        "actions_performed": False,
        "recorded_at_utc": max((source.recorded_at_utc for source in sources), default=utc_now_text()),
        "segments": segments,
    }
    return {"events": deduplicated, "segments": segments, "report": report, "work": build_work_accounting(deduplicated)}


def write_fl4shminer_outputs(sources: list[ParsedFl4shMinerCsv], output_dir: str | Path) -> dict[str, Any]:
    destination = Path(output_dir)
    if destination.exists():
        raise ValueError("Fl4shMiner output directory must be new")
    snapshot = build_fl4shminer_snapshot(sources)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent))
    try:
        (temporary / "events.jsonl").write_text("".join(json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n" for event in snapshot["events"]), encoding="utf-8")
        (temporary / "segments.json").write_text(json.dumps({"schema_version": V2_SCHEMA_VERSION, "segments": snapshot["segments"]}, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (temporary / "work.json").write_text(json.dumps(snapshot["work"], ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (temporary / "report.json").write_text(json.dumps(snapshot["report"], ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
    except Exception:
        import shutil
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return {"output_dir": str(destination), "event_count": snapshot["report"]["event_count"], "source_count": snapshot["report"]["source_count"], "segment_count": snapshot["report"]["segment_count"], "billing_status": "UNKNOWN"}
