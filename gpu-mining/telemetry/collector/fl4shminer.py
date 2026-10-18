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
from .fl4sh_early_autotune import (
    EarlyEvaluationContext,
    EarlyObservation,
    MonitorPolicyEvidence,
    ObservationReference,
    _policy_evidence_sha256,
    evaluate_early_autotune,
)
from .models import V2_SCHEMA_VERSION, utc_now_text
from .work import build_work_accounting
from log_alerts.normalize import CUDA_DRIVER_FAILURE_REASON, _cuda_signal_from_text


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
    r"(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?"
    r"Device\s*\[(?P<device>[0-9]{1,3})\]\s+CUDA\s+autotune:\s*"
    r"(?P<rate>[0-9]{1,5}(?:\.[0-9]{1,6})?)\s*(?P<unit>TH/s|GH/s|MH/s)\s*"
    r"\(measured pool-equivalent\)", re.IGNORECASE,
)
_GPU_INIT_RE = re.compile(
    r"(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?"
    r"Device\s*\[(?P<device>[0-9]{1,3})\]\s+"
    r"(?P<model>[^:\r\n=]{1,256}?)\s*:\s*Initialized\s*", re.IGNORECASE,
)
_AUTOTUNE_RE = re.compile(
    r"(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?"
    r"(?:Device\s*\[(?P<device>[0-9]{1,3})\]\s*)?"
    r"GPU=(?P<model>[^\r\n=]{1,256}?)\s+Pearl\s+autotune\s+hashrate\s*=\s*"
    r"(?P<rate>[0-9]{1,5}(?:\.[0-9]{1,6})?)\s*(?P<unit>TH/s|GH/s|MH/s)", re.IGNORECASE,
)
_SOLUTION_RE = re.compile(
    r"Solutions\s+(?P<status>accepted|rejected):\s*(?P<device>\d+)-(?P<model>[^,]+),\s*"
    r"(?P<solution_hex>0x[0-9a-fA-F]+)\s*,\s*pool=(?P<pool>[^,]+)(?P<tail>.*)$", re.IGNORECASE,
)
_POOL_CONNECTED_RE = re.compile(r"Pool\s+connected:\s*(?P<pool>\S+)\s*\(latency\s+(?P<latency>[\d.]+)\s*ms\)", re.IGNORECASE)
_TIMESTAMP_PREFIX_RE = re.compile(r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+")
_MONITOR_CONFIG_PREFIX = "FL4SH_MONITOR state=CONFIG"
_MONITOR_POLICY_FIELD_RE = re.compile(r"(?:^|\s)policy_hash=(?P<value>[^\s]*)")
_MONITOR_POLICY_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")


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


def _parse_gpu_initialization(message: str) -> dict[str, Any] | None:
    """Read an explicit Fl4shMiner device/model announcement for correlation only."""
    if not isinstance(message, str) or len(message) > 2048:
        return None
    match = _GPU_INIT_RE.fullmatch(message.strip())
    if match is None:
        return None
    raw_model = match.group("model").strip()
    identity = normalize_gpu_identity(
        raw_model,
        identity_source="fl4shminer_device_initialized",
        identity_verified=False,
    )
    model = identity.get("model")
    form_factor = identity.get("form_factor")
    gpu_key = (
        f"{str(model).replace(' ', '_').upper()}_{str(form_factor).upper()}"
        if isinstance(model, str) and form_factor in {"laptop", "desktop"}
        else None
    )
    return {
        "device_index": int(match.group("device")),
        "gpu_key": gpu_key,
        "identity_status": "EXPLICIT_MODEL_AND_FORM_FACTOR" if gpu_key else "GPU_IDENTITY_UNKNOWN",
    }


def _parse_monitor_config_policy(message: str) -> tuple[str, str | None] | None:
    """Parse only the bounded policy hash declaration emitted by the monitor."""
    if not isinstance(message, str) or not message.startswith(_MONITOR_CONFIG_PREFIX):
        return None
    if len(message) > 4096 or not message.isascii():
        return ("MALFORMED", None)
    if len(message) == len(_MONITOR_CONFIG_PREFIX) or message[len(_MONITOR_CONFIG_PREFIX)] != " ":
        return ("MALFORMED", None)
    fields = _MONITOR_POLICY_FIELD_RE.findall(message)
    if len(fields) != 1 or _MONITOR_POLICY_HASH_RE.fullmatch(fields[0]) is None:
        return ("MALFORMED", None)
    return ("PARSED", fields[0])


def _aware_datetime(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def _resolve_initialized_gpu(
    observations: list[dict[str, Any]],
    *,
    device_index: int,
    event_time_utc: datetime | None,
    run_anchor_utc: datetime | None,
) -> tuple[str | None, str | None]:
    if event_time_utc is None or run_anchor_utc is None:
        return None, None
    eligible = [
        item for item in observations
        if item["device_index"] == device_index
        and item["occurred_at_utc"] is not None
        and run_anchor_utc <= item["occurred_at_utc"] <= event_time_utc
    ]
    if not eligible:
        return None, None
    latest_time = max(item["occurred_at_utc"] for item in eligible)
    latest = [item for item in eligible if item["occurred_at_utc"] == latest_time]
    if len(latest) != 1 or latest[0]["gpu_key"] is None:
        return None, None
    return latest[0]["gpu_key"], latest[0]["source_event_id"]


def _early_decision_for_event(
    *,
    event_type: str,
    payload: dict[str, Any],
    source_event_id: str,
    source_file_sha256: str,
    source_row: int,
    provider_values: tuple[str, ...],
    organization: str | None,
    project: str | None,
    occurred_at_utc: str | None,
    device_init_events: list[dict[str, Any]],
    monitor_config_events: list[dict[str, Any]],
    run_anchor_utc: datetime | None,
    run_anchor_source_event_id: str | None,
    context: EarlyEvaluationContext | None,
    default_now_utc: datetime,
) -> dict[str, Any] | None:
    signal_type = payload.get("early_signal_type")
    startup_failure_reason = payload.get("startup_failure_reason")
    if signal_type not in {"CUDA_POOL_EQUIVALENT", "PEARL_AUTOTUNE"} and startup_failure_reason is None:
        return None

    event_time = _aware_datetime(occurred_at_utc)
    device_value = payload.get("device_id")
    device_index = int(device_value) if isinstance(device_value, str) and device_value.isdigit() else None
    gpu_key: str | None = None
    gpu_init_event_id: str | None = None
    if device_index is not None and payload.get("device_namespace") == "fl4shminer_device":
        gpu_key, gpu_init_event_id = _resolve_initialized_gpu(
            device_init_events,
            device_index=device_index,
            event_time_utc=event_time,
            run_anchor_utc=run_anchor_utc,
        )

    if signal_type == "PEARL_AUTOTUNE" and isinstance(payload.get("reported_gpu_model_label"), str):
        reported = normalize_gpu_identity(
            payload["reported_gpu_model_label"],
            identity_source="pearl_autotune_corroboration",
            identity_verified=False,
        )
        reported_model = reported.get("model")
        reported_factor = reported.get("form_factor")
        reported_key = (
            f"{str(reported_model).replace(' ', '_').upper()}_{str(reported_factor).upper()}"
            if isinstance(reported_model, str) and reported_factor in {"laptop", "desktop"}
            else None
        )
        if gpu_key is not None and reported_key is not None and gpu_key != reported_key:
            contradictory_evidence = True
        else:
            contradictory_evidence = False
    else:
        contradictory_evidence = False

    policy_evidence: MonitorPolicyEvidence | None = None
    policy_evidence_status = "MISSING"
    if startup_failure_reason is None:
        policy_evidence, policy_evidence_status = _resolve_monitor_policy_evidence(
            monitor_config_events,
            provider_values=provider_values,
            organization=organization,
            project=project,
            event_time_utc=event_time,
            run_anchor_utc=run_anchor_utc,
            run_anchor_source_event_id=run_anchor_source_event_id,
        )

    reference = None
    if all((organization, project, *provider_values)) and device_index is not None and gpu_key and gpu_init_event_id:
        reference = ObservationReference(
            source_event_id=source_event_id,
            source_file_sha256=source_file_sha256,
            source_row=source_row,
            organization=organization or "",
            project=project or "",
            container_group=provider_values[0],
            container_group_version=provider_values[1],
            instance_id=provider_values[2],
            machine_id=provider_values[3],
            device_namespace="fl4shminer_device",
            device_index=device_index,
            gpu_key=gpu_key,
            gpu_identity_source_event_id=gpu_init_event_id,
            startup_anchor_source_event_id=run_anchor_source_event_id,
            startup_anchor_time_utc=(
                run_anchor_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                if run_anchor_utc is not None else None
            ),
            policy_evidence_sha256=_policy_evidence_sha256(policy_evidence),
        )

    active_context = context or EarlyEvaluationContext()
    observation = EarlyObservation(
        signal_type=signal_type if signal_type in {"CUDA_POOL_EQUIVALENT", "PEARL_AUTOTUNE"} else None,
        device_index=device_index,
        gpu_key=gpu_key,
        estimate_ths=payload.get("hashrate_ths") if signal_type else None,
        event_time_utc=event_time,
        policy_hash=(policy_evidence.policy_hash if policy_evidence is not None else None),
        source="FL4SHMINER_STARTUP_LOG" if startup_failure_reason else "FL4SHMINER_AUTOTUNE_LOG",
        startup_failure_reason=startup_failure_reason,
        source_reference=reference,
        policy_evidence=policy_evidence,
        policy_evidence_status=policy_evidence_status,
    )

    matching_bindings = [
        item for item in active_context.bindings
        if item.device_index == observation.device_index and item.gpu_key == observation.gpu_key
    ]
    binding = matching_bindings[0] if len(matching_bindings) == 1 else None
    matching_calibrations = [
        item for item in active_context.calibrations
        if item.signal_type == observation.signal_type and item.gpu_key == observation.gpu_key
    ]
    calibration = matching_calibrations[0] if len(matching_calibrations) == 1 else None
    now_utc = active_context.now_utc or default_now_utc
    decision = evaluate_early_autotune(
        observation,
        binding,
        calibration,
        active_context.policy,
        now_utc=now_utc,
        contradictory_evidence=contradictory_evidence,
        allow_synthetic_calibration_for_test=active_context.allow_synthetic_calibration_for_test,
        association_records=active_context.association_records,
        allow_synthetic_binding_evidence_for_test=active_context.allow_synthetic_binding_evidence_for_test,
    )
    return decision.to_dict()


def _resolve_monitor_policy_evidence(
    config_events: list[dict[str, Any]],
    *,
    provider_values: tuple[str, ...],
    organization: str | None,
    project: str | None,
    event_time_utc: datetime | None,
    run_anchor_utc: datetime | None,
    run_anchor_source_event_id: str | None,
) -> tuple[MonitorPolicyEvidence | None, str]:
    if (
        event_time_utc is None or run_anchor_utc is None or run_anchor_source_event_id is None
        or organization is None or project is None
    ):
        return None, "MISSING"
    if any(item["provider_values"] == provider_values and item["occurred_at_utc"] is None for item in config_events):
        return None, "AMBIGUOUS"
    applicable = [
        item for item in config_events
        if item["provider_values"] == provider_values
        and item["organization"] == organization
        and item["project"] == project
        and item["occurred_at_utc"] is not None
        and run_anchor_utc <= item["occurred_at_utc"] <= event_time_utc
    ]
    if len(applicable) != 1:
        return None, "AMBIGUOUS" if len(applicable) > 1 else "MISSING"
    item = applicable[0]
    return MonitorPolicyEvidence(
        source_event_id=item["source_event_id"],
        source_file_sha256=item["source_file_sha256"],
        source_row=item["source_row"],
        organization=organization,
        project=project,
        container_group=provider_values[0],
        container_group_version=provider_values[1],
        machine_id=provider_values[3],
        instance_id=provider_values[2],
        startup_anchor_source_event_id=run_anchor_source_event_id,
        startup_anchor_time_utc=run_anchor_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        occurred_at_utc=item["occurred_at_utc"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        policy_hash=item["policy_hash"],
        status=item["status"],
    ), item["status"]


def _classify(message: str) -> tuple[str, dict[str, Any]] | None:
    if len(message) <= 65536 and _cuda_signal_from_text(message.strip()) == "CUDA_DRIVER_INCOMPATIBLE":
        return "startup_failure", {
            "startup_failure_reason": CUDA_DRIVER_FAILURE_REASON,
            "startup_failure_source": "exact_supported_cuda_fatal_log",
            "actions_performed": False,
        }

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

    match = _POOL_EQ_RE.fullmatch(message.strip()) if len(message) <= 65536 else None
    if match and 0 < _rate_ths(match.group("rate"), match.group("unit")) <= 10000:
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
            "early_signal_type": "CUDA_POOL_EQUIVALENT",
            "estimate_stage": "EARLY_STARTUP",
        }

    match = _AUTOTUNE_RE.fullmatch(message.strip()) if len(message) <= 65536 else None
    if match and 0 < _rate_ths(match.group("rate"), match.group("unit")) <= 10000:
        return "hashrate_estimate", {
            "reported_gpu_model_label": match.group("model").strip(),
            "device_id": match.group("device"),
            "device_namespace": "fl4shminer_device" if match.group("device") is not None else "unknown",
            "estimate_kind": "pearl_autotune_reported_estimate",
            "hashrate_reported_value": float(match.group("rate")),
            "hashrate_reported_unit": match.group("unit").upper(),
            "hashrate_ths": _rate_ths(match.group("rate"), match.group("unit")),
            "hashrate_semantics": "pearl_autotune_estimate",
            "hashrate_source": "Text Log:Pearl autotune",
            "worker_hashrate": False,
            "early_signal_type": "PEARL_AUTOTUNE",
            "estimate_stage": "EARLY_STARTUP",
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


def _parse_source(
    path: Path,
    recorded_at_utc: str | None = None,
    *,
    early_context: EarlyEvaluationContext | None = None,
) -> ParsedFl4shMinerCsv:
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
    gpu_init_events: list[dict[str, Any]] = []
    monitor_config_events: list[dict[str, Any]] = []
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
        gpu_init = _parse_gpu_initialization(message)
        if gpu_init is not None:
            _, gpu_init_time_utc, _ = _timestamp(row, message)
            gpu_init_events.append({
                **gpu_init,
                "provider_values": provider_values,
                "occurred_at_utc": _aware_datetime(gpu_init_time_utc),
                "source_event_id": _stable_id("fl4sh-source-event", [source_hash, source_row, "gpu_initialized"]),
            })
        config_parse = _parse_monitor_config_policy(message)
        if config_parse is not None:
            config_status, config_policy_hash = config_parse
            _, config_time_utc, _ = _timestamp(row, message)
            monitor_config_events.append({
                "provider_values": provider_values,
                "organization": _text(row.get("Resource labels organization name")) or None,
                "project": _text(row.get("Resource labels project name")) or None,
                "occurred_at_utc": _aware_datetime(config_time_utc),
                "source_event_id": _stable_id("fl4sh-source-event", [source_hash, source_row, "monitor_config"]),
                "source_file_sha256": source_hash,
                "source_row": source_row,
                "status": config_status,
                "policy_hash": config_policy_hash,
            })
        classified = _classify(message)
        if classified is None:
            if gpu_init is not None:
                continue
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
            "source_row": source_row,
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
    utc_anchor_events: dict[tuple[str, ...], list[tuple[datetime, str]]] = defaultdict(list)
    for anchor_source_row, _, event_type, provider_values, info in rows:
        if event_type != "worker_start":
            continue
        if info["provider_identity_complete"] and info["occurred_at_utc"]:
            utc_anchors[provider_values].add(info["occurred_at_utc"])
            anchor_time = _aware_datetime(info["occurred_at_utc"])
            if anchor_time is not None:
                utc_anchor_events[provider_values].append((
                    anchor_time,
                    _stable_id("fl4sh-source-event", [source_hash, anchor_source_row, "worker_start"]),
                ))
        if info["occurred_at_source_clock"]:
            source_clock_anchors[provider_values].add(info["occurred_at_source_clock"])

    events: list[dict[str, Any]] = []
    recorded_now_utc = _aware_datetime(recorded_at_utc) or datetime.now(timezone.utc)
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
        run_anchor_source_event_id: str | None = None
        if run_verified:
            anchor = verified_anchors[-1]
            parsed_anchor_time = _aware_datetime(anchor)
            matching_anchor_events = [
                item for item in utc_anchor_events.get(provider_values, [])
                if item[0] == parsed_anchor_time
            ]
            if len(matching_anchor_events) == 1:
                run_anchor_source_event_id = matching_anchor_events[0][1]
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
        organization = _text(row.get("Resource labels organization name")) or None
        project = _text(row.get("Resource labels project name")) or None
        run_anchor_utc = _aware_datetime(anchor) if run_verified else None
        event["early_decision"] = _early_decision_for_event(
            event_type=event_type,
            payload=payload,
            source_event_id=source_event_id,
            source_file_sha256=source_hash,
            source_row=source_row,
            provider_values=provider_values,
            organization=organization,
            project=project,
            occurred_at_utc=occurred_at_utc,
            device_init_events=[item for item in gpu_init_events if item["provider_values"] == provider_values],
            monitor_config_events=monitor_config_events,
            run_anchor_utc=run_anchor_utc,
            run_anchor_source_event_id=run_anchor_source_event_id,
            context=early_context,
            default_now_utc=recorded_now_utc,
        )
        if event["early_decision"] is None:
            del event["early_decision"]
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


def import_fl4shminer_csv(
    input_path: str | Path,
    *,
    recorded_at_utc: str | None = None,
    early_context: EarlyEvaluationContext | None = None,
) -> ParsedFl4shMinerCsv:
    return _parse_source(Path(input_path), recorded_at_utc=recorded_at_utc, early_context=early_context)


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
