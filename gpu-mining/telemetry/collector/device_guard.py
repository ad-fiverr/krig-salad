"""Normalize local device samples for the existing physical hash guard."""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict
import csv
from pathlib import Path
from typing import Any, Iterable, Mapping

from .fl4shminer import ParsedFl4shMinerCsv, import_fl4shminer_csv
from .gpu_identity import normalize_gpu_identity
from .salad_lifecycle import import_salad_lifecycle_csv


def _stable_id(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "device-observation_" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32]


def _source_path_key(path: str | Path) -> str:
    resolved = str(Path(path).resolve())
    return os.path.normcase(resolved).replace("\\", "/")


def detect_monitor_format(path: str | Path, input_format: str = "auto") -> str:
    source = Path(path)
    if input_format != "auto":
        return input_format
    if source.suffix.casefold() in {".jsonl", ".ndjson"}:
        return "normalized-jsonl"
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        columns = set(next(csv.reader(handle), []))
    if "Json Log gpu class name" in columns and "Text Log" in columns:
        return "fl4shminer-csv"
    if "Json Log message" in columns and "Text Log" in columns:
        return "salad-lifecycle-csv"
    raise ValueError(f"cannot identify offline monitor input format from columns in {source.name}")


def inspect_monitor_source(path: str | Path, input_format: str = "auto") -> dict[str, Any]:
    """Fingerprint logical records so incremental ingestion can verify append-only prefixes."""
    source = Path(path)
    kind = detect_monitor_format(source, input_format)
    row_hashes: list[str] = []
    header_hash: str | None = None
    if kind in {"fl4shminer-csv", "salad-lifecycle-csv"}:
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, [])
            header_hash = hashlib.sha256(json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
            for row in reader:
                row_hashes.append(hashlib.sha256(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest())
    elif kind == "normalized-jsonl":
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            for line in handle:
                row_hashes.append(hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).hexdigest())
    else:
        raise ValueError(f"unsupported offline monitor input format: {kind}")
    path_key = _source_path_key(source)
    source_id = hashlib.sha256(path_key.encode("utf-8")).hexdigest()[:32]
    return {
        "source_id": source_id,
        "source_path_key": path_key,
        "source_format": kind,
        "row_count": len(row_hashes),
        "header_sha256": header_hash,
        "row_sha256": row_hashes,
    }


def _present(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned if cleaned and cleaned.casefold() not in {"unknown", "none", "null", "n/a"} else None


def normalize_fl4shminer_events(
    sources: Iterable[ParsedFl4shMinerCsv],
    *,
    fleet_id: str | None = None,
    worker_id: str | None = None,
    reallocation_history_known: bool = False,
    reallocation_count: int = 0,
) -> list[dict[str, Any]]:
    """Create device-only observations; assignment GPU labels map only to one device."""
    all_events = [dict(event) for source in sources for event in source.events]
    grouped: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in all_events:
        key = (
            str(event.get("run_id") or ""),
            _present(event.get("container_group_name")) or "",
            _present(event.get("container_group_version")) or "",
            _present(event.get("machine_id")) or "",
            _present(event.get("instance_id")) or "",
        )
        grouped[key].append(event)

    normalized: list[dict[str, Any]] = []
    for key, events in grouped.items():
        run_id, group_name, group_version, machine_id, instance_id = key
        lineage_events = [
            event for event in events
            if event.get("_monitor_source_id") and event.get("_monitor_source_generation")
        ]
        source_id = lineage_events[0].get("_monitor_source_id") if lineage_events else None
        source_generation = lineage_events[0].get("_monitor_source_generation") if lineage_events else None
        if source_id and source_generation and any(event.get("identity_status") != "candidate_verified" for event in events):
            assignment_complete = all((group_name, group_version, machine_id, instance_id))
            stable_run = ["monitor-source-run", source_id, source_generation]
            if assignment_complete:
                stable_run.extend([group_name, group_version, machine_id, instance_id])
            else:
                # Partial labels cannot establish assignment continuity. Keep
                # each log event in its own source/generation/row lineage.
                stable_run.extend(["isolated-row", min(int(event.get("source_row") or 0) for event in events)])
            run_id = _stable_id(stable_run)
        gpu_events = [
            event for event in events
            if event.get("event_type") == "gpu_sample" and isinstance(event.get("payload"), Mapping)
            and event["payload"].get("hashrate_semantics") == "fl4shminer_device_reported"
        ]
        device_keys = {
            (str(event["payload"].get("device_namespace") or ""), str(event["payload"].get("device_id") or ""))
            for event in gpu_events
        }
        starts = [
            event.get("occurred_at_utc") for event in events
            if event.get("event_type") == "worker_start" and isinstance(event.get("occurred_at_utc"), str)
        ]
        run_started_at = min(starts) if starts else None
        assignment_id = f"{group_name}|{group_version}" if group_name and group_version else None
        for event in gpu_events:
            payload = event["payload"]
            device_namespace = _present(payload.get("device_namespace"))
            device_id = str(payload.get("device_id")) if payload.get("device_id") is not None else None
            assignment_identity = payload.get("assignment_gpu_identity")
            one_device_mapping = len(device_keys) == 1 and bool(device_namespace and device_id)
            if one_device_mapping and isinstance(assignment_identity, Mapping):
                gpu_identity = normalize_gpu_identity(
                    assignment_identity.get("raw_model"),
                    identity_source=assignment_identity.get("identity_source"),
                    identity_verified=assignment_identity.get("identity_verified"),
                    reported_form_factor=assignment_identity.get("form_factor"),
                )
            else:
                raw_identity = dict(assignment_identity) if isinstance(assignment_identity, Mapping) else {}
                gpu_identity = {
                    **raw_identity,
                    "identity_verified": False,
                    "identity_status": "provider_assignment_identity_not_mapped_to_single_device",
                    "identity_scope": "provider_assignment",
                }
            semantic_key = [
                run_id if event.get("identity_status") == "candidate_verified" else None,
                event.get("occurred_at_utc"),
                event.get("event_type"),
                device_namespace,
                device_id,
                payload.get("hashrate_ths"),
                payload.get("hashrate_semantics"),
            ]
            # Monitor IDs are stable across append-only updates and distinct
            # across reset generations, even when the parser can identify the
            # worker-start anchor. Direct importer use without a persistent
            # cursor keeps its prior cross-export behavior for verified runs.
            if event.get("_monitor_source_id") and event.get("_monitor_source_generation"):
                semantic_key.extend([
                    event.get("_monitor_source_id"),
                    event.get("_monitor_source_generation"),
                    event.get("source_row"),
                ])
            elif not run_id or event.get("identity_status") != "candidate_verified":
                # Without a persisted cursor, incomplete run identities stay
                # isolated to their source file and row.
                semantic_key.extend([event.get("source_file_sha256"), event.get("source_row")])
            normalized.append({
                "event_type": "gpu_sample",
                "event_id": _stable_id(semantic_key),
                "fleet_id": _present(fleet_id),
                "worker_id": _present(worker_id),
                "allocation_id": assignment_id,
                "assignment_id": assignment_id,
                "run_id": _present(run_id),
                "machine_id": _present(machine_id),
                "instance_id": _present(instance_id),
                "device_namespace": device_namespace,
                "device_id": device_id,
                "occurred_at_utc": event.get("occurred_at_utc"),
                "assignment_started_at_utc": run_started_at,
                "start_anchor_verified": bool(run_started_at and event.get("identity_status") == "candidate_verified"),
                "hashrate_ths": payload.get("hashrate_ths"),
                "hashrate_semantics": payload.get("hashrate_semantics"),
                "hashrate_source": payload.get("hashrate_source"),
                "gpu_identity": gpu_identity,
                "gpu_identity_mapping_status": "single_device_in_provider_assignment" if one_device_mapping else "assignment_identity_not_device_mapped",
                "reallocation_history_known": reallocation_history_known,
                "reallocation_count": reallocation_count if reallocation_history_known else None,
                "provenance": {
                    "source": event.get("source"),
                    "event_source": event.get("event_source"),
                    "source_file_name": event.get("source_file_name"),
                    "source_file_sha256": event.get("source_file_sha256"),
                    "source_row": event.get("source_row"),
                    "raw_reference": event.get("raw_reference"),
                    "source_event_id": event.get("source_event_id"),
                    "monitor_source_id": event.get("_monitor_source_id"),
                    "monitor_source_generation": event.get("_monitor_source_generation"),
                    "monitor_source_row": event.get("source_row"),
                    "source_run_id": event.get("source_run_id"),
                    "run_identity_status": event.get("run_identity_status"),
                    "gpu_identity_scope": payload.get("gpu_identity_scope"),
                },
            })
    return sorted(normalized, key=lambda item: (str(item.get("occurred_at_utc") or ""), str(item["event_id"])))


def load_fl4shminer_observations(
    paths: Iterable[str | Path],
    *,
    fleet_id: str | None = None,
    worker_id: str | None = None,
    reallocation_history_known: bool = False,
    reallocation_count: int = 0,
) -> list[dict[str, Any]]:
    sources = [import_fl4shminer_csv(path) for path in paths]
    return normalize_fl4shminer_events(
        sources,
        fleet_id=fleet_id,
        worker_id=worker_id,
        reallocation_history_known=reallocation_history_known,
        reallocation_count=reallocation_count,
    )


def load_normalized_jsonl(path: str | Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL in {Path(path).name} line {line_number}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"JSONL record on line {line_number} must be an object")
            item["_monitor_source_row"] = line_number
            values.append(item)
    return values


def load_monitor_events(
    paths: Iterable[str | Path],
    *,
    input_format: str = "auto",
    fleet_id: str | None = None,
    worker_id: str | None = None,
    source_contexts: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Load local evidence, preserving append-only source generations and cursors."""
    events: list[dict[str, Any]] = []
    fl4sh_sources: list[ParsedFl4shMinerCsv] = []
    contexts = source_contexts or {}
    starts: dict[tuple[str, int], int] = {}
    for raw_path in paths:
        path = Path(raw_path)
        path_key = _source_path_key(path)
        kind = detect_monitor_format(path, input_format)
        context = contexts.get(path_key)
        if not isinstance(context, Mapping):
            fallback_id = hashlib.sha256(path_key.encode("utf-8")).hexdigest()[:32]
            context = {"source_id": fallback_id, "generation": 1, "start_row_count": 0, "source_format": kind}
        source_id = context.get("source_id")
        generation = context.get("generation")
        start_row_count = context.get("start_row_count")
        if not isinstance(source_id, str) or isinstance(generation, bool) or not isinstance(generation, int) or isinstance(start_row_count, bool) or not isinstance(start_row_count, int):
            raise ValueError("monitor source context is missing its source id, generation, or cursor")
        starts[(source_id, generation)] = start_row_count
        if kind == "normalized-jsonl":
            for event in load_normalized_jsonl(path):
                source_row = int(event.pop("_monitor_source_row"))
                if source_row <= start_row_count:
                    continue
                source_event_id = event.get("source_event_id") or event.get("event_id")
                event["source_event_id"] = source_event_id
                event["event_id"] = _stable_id(["monitor-jsonl-event", source_id, generation, source_row, source_event_id])
                event["monitor_source_id"] = source_id
                event["monitor_source_generation"] = generation
                event["monitor_source_row"] = source_row
                prior_provenance = event.get("provenance") if isinstance(event.get("provenance"), Mapping) else {}
                event["provenance"] = {
                    **dict(prior_provenance),
                    "monitor_source_id": source_id,
                    "monitor_source_generation": generation,
                    "monitor_source_row": source_row,
                }
                events.append(event)
        elif kind == "fl4shminer-csv":
            parsed = import_fl4shminer_csv(path)
            for event in parsed.events:
                event["_monitor_source_id"] = source_id
                event["_monitor_source_generation"] = generation
                source_run_id = event.get("run_id")
                if event.get("identity_status") != "candidate_verified":
                    provider_complete = all(_present(event.get(key)) for key in (
                        "container_group_name", "container_group_version", "machine_id", "instance_id",
                    ))
                    if provider_complete:
                        run_key = [
                            "monitor-source-assignment", source_id, generation,
                            _present(event.get("container_group_name")),
                            _present(event.get("container_group_version")),
                            _present(event.get("machine_id")), _present(event.get("instance_id")),
                        ]
                    else:
                        run_key = ["monitor-source-isolated-row", source_id, generation, event.get("source_row")]
                    source_run_id = _stable_id(run_key)
                event["source_run_id"] = source_run_id
                event["run_id"] = _stable_id([
                    "monitor-fl4sh-run", source_id, generation, source_run_id,
                ])
                event["source_event_id"] = event.get("source_event_id") or event.get("event_id")
                event["event_id"] = _stable_id([
                    "monitor-fl4sh-event", source_id, generation,
                    event.get("source_row"), event.get("event_type"),
                ])
            fl4sh_sources.append(parsed)
        elif kind == "salad-lifecycle-csv":
            parsed = import_salad_lifecycle_csv(path)
            for event in parsed.events:
                source_row = int(event.get("source_row") or 0)
                if source_row <= start_row_count + 1:
                    continue
                identity = event.get("provider_identity") if isinstance(event.get("provider_identity"), Mapping) else {}
                group = _present(identity.get("Resource labels container group name"))
                version = _present(identity.get("Resource labels container group version"))
                allocation_id = f"{group}|{version}" if group and version else None
                source_event_id = event.get("source_event_id") or event.get("event_id")
                events.append({
                    **event,
                    "source_event_id": source_event_id,
                    "event_id": _stable_id([
                        "monitor-lifecycle-event", source_id, generation, source_row,
                        event.get("event_source"), event.get("event_type"), event.get("reported_state"),
                        event.get("readiness_probe"), event.get("readiness_outcome"),
                    ]),
                    "event_type": event.get("event_type"),
                    "fleet_id": _present(fleet_id),
                    "worker_id": _present(worker_id),
                    "allocation_id": allocation_id,
                    "assignment_id": allocation_id,
                    "machine_id": _present(identity.get("Resource labels machine id")),
                    "instance_id": _present(identity.get("Resource labels instance id")),
                    "source": event.get("source"),
                    "event_source": event.get("event_source"),
                    "monitor_source_id": source_id,
                    "monitor_source_generation": generation,
                    "monitor_source_row": source_row,
                })
        else:
            raise ValueError(f"unsupported monitor input format: {kind}")
    if fl4sh_sources:
        normalized_events = normalize_fl4shminer_events(fl4sh_sources, fleet_id=fleet_id, worker_id=worker_id)
        mapping_groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        for event in normalized_events:
            provenance = event.get("provenance") if isinstance(event.get("provenance"), Mapping) else {}
            source_key = (provenance.get("monitor_source_id"), provenance.get("monitor_source_generation"))
            start_row_count = starts.get(source_key, 0)
            row_number = int(provenance.get("monitor_source_row") or 0)
            source_id, generation = source_key
            assignment_id = event.get("assignment_id")
            assignment_fields = (
                source_id, generation, event.get("fleet_id"), event.get("worker_id"),
                event.get("allocation_id"), assignment_id, event.get("machine_id"), event.get("instance_id"),
            )
            if all(isinstance(value, str) and value.strip() for value in (source_id, assignment_id, event.get("allocation_id"), event.get("machine_id"), event.get("instance_id"))):
                group = mapping_groups.setdefault(assignment_fields, {
                    "device_keys": set(), "latest_new_event": None, "source_event": event,
                })
                group["device_keys"].add(f"{event.get('device_namespace')}:{event.get('device_id')}")
                if row_number > start_row_count + 1:
                    previous = group.get("latest_new_event")
                    current_time = str(event.get("occurred_at_utc") or "")
                    previous_time = str(previous.get("occurred_at_utc") or "") if isinstance(previous, Mapping) else ""
                    if previous is None or current_time > previous_time:
                        group["latest_new_event"] = event
            if int(provenance.get("monitor_source_row") or 0) > start_row_count + 1:
                events.append(event)
        for key, group in mapping_groups.items():
            source_id, generation, event_fleet_id, event_worker_id, allocation_id, assignment_id, machine_id, instance_id = key
            device_keys = sorted(group["device_keys"])
            latest_new_event = group.get("latest_new_event")
            if len(device_keys) < 2 or not isinstance(latest_new_event, Mapping):
                continue
            latest_provenance = latest_new_event.get("provenance") if isinstance(latest_new_event.get("provenance"), Mapping) else {}
            events.append({
                "event_type": "gpu_device_mapping_ambiguous",
                "event_id": _stable_id([
                    "monitor-fl4sh-device-mapping-ambiguous", source_id, generation,
                    event_fleet_id, event_worker_id, allocation_id, assignment_id,
                    machine_id, instance_id, device_keys,
                ]),
                "fleet_id": event_fleet_id,
                "worker_id": event_worker_id,
                "allocation_id": allocation_id,
                "assignment_id": assignment_id,
                "machine_id": machine_id,
                "instance_id": instance_id,
                "device_keys": device_keys,
                "occurred_at_utc": latest_new_event.get("occurred_at_utc"),
                "monitor_source_id": source_id,
                "monitor_source_generation": generation,
                "monitor_source_row": latest_provenance.get("monitor_source_row"),
                "provenance": {
                    "source": "salad_exported_fl4shminer_csv",
                    "event_source": "provider_assignment_gpu_mapping",
                    "source_file_name": latest_provenance.get("source_file_name"),
                    "source_file_sha256": latest_provenance.get("source_file_sha256"),
                    "monitor_source_id": source_id,
                    "monitor_source_generation": generation,
                    "monitor_source_row": latest_provenance.get("monitor_source_row"),
                },
                "actions_performed": False,
            })
    return sorted(events, key=lambda item: (str(item.get("occurred_at_utc") or item.get("observed_at_utc") or ""), str(item.get("event_id") or "")))
