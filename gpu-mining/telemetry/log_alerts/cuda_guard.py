"""Exact CUDA fatal correlation and safe offline alert formatting."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from typing import Any

from .contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED, canonical_utc
from .normalize import (
    CUDA_DRIVER_FAILURE_REASON,
    MonitorAlert,
    NormalizedLogEntry,
)


MAX_EXIT_CORRELATION_SECONDS = 60
MAX_CUDA_EXIT_AUDIT_HASHES = 100
MAX_CUDA_FATAL_CANDIDATE_HASHES = 100


def _bounded_hashes(values: Iterable[str], maximum: int) -> tuple[list[str], bool]:
    ordered = sorted(set(values))
    return ordered[:maximum], len(ordered) > maximum


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(canonical_utc(value).replace("Z", "+00:00"))


def _complete_resource_key(entry: NormalizedLogEntry) -> tuple[str, ...] | None:
    identity = entry.identity.public_fields()
    names = (
        "organization_name", "project_name", "container_group_name",
        "machine_id", "instance_id",
    )
    if (
        identity.get("identity_status") not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}
        or identity.get("identity_source") != "resource.labels"
        or any(not isinstance(identity.get(name), str) or not identity[name] for name in names)
    ):
        return None
    return (entry.resource_type, *(str(identity[name]) for name in names))


def correlate_cuda_exit_status(
    entries: Sequence[NormalizedLogEntry],
) -> tuple[tuple[NormalizedLogEntry, ...], tuple[dict[str, Any], ...]]:
    """Attach only same-resource, strictly-later exit status evidence.

    A fatal alert remains valid with unknown identity or without exit evidence.
    Exit evidence is exported separately only when its complete provider label
    identity is trustworthy enough to enrich a previously prepared alert.
    """
    exits_by_resource: dict[tuple[str, ...], list[NormalizedLogEntry]] = {}
    fatals_by_resource: dict[tuple[str, ...], list[NormalizedLogEntry]] = {}
    durable_exit_evidence: list[dict[str, Any]] = []
    for entry in entries:
        key = _complete_resource_key(entry)
        if key is None:
            continue
        if entry.cuda_signal == "MINER_EXIT_STATUS_1":
            exits_by_resource.setdefault(key, []).append(entry)
            identity = entry.identity.public_fields()
            durable_exit_evidence.append({
                "resource_type": entry.resource_type,
                "organization_name": identity["organization_name"],
                "project_name": identity["project_name"],
                "container_group_name": identity["container_group_name"],
                "machine_id": identity["machine_id"],
                "instance_id": identity["instance_id"],
                "event_time_utc": entry.event_time_utc,
                "evidence_sha256": entry.evidence_sha256,
            })
        elif entry.alert is not None and entry.alert.event_type == "CUDA_DRIVER_INCOMPATIBLE":
            fatals_by_resource.setdefault(key, []).append(entry)

    fatal_candidates_by_exit: dict[str, set[str]] = {}
    exits_by_fatal: dict[str, list[NormalizedLogEntry]] = {}
    for key, exits in exits_by_resource.items():
        for fatal in fatals_by_resource.get(key, ()):
            fatal_time = _utc(fatal.event_time_utc)
            matching_exits: list[NormalizedLogEntry] = []
            for exit_entry in exits:
                delta = (_utc(exit_entry.event_time_utc) - fatal_time).total_seconds()
                if 0 < delta <= MAX_EXIT_CORRELATION_SECONDS:
                    matching_exits.append(exit_entry)
                    fatal_candidates_by_exit.setdefault(exit_entry.evidence_sha256, set()).add(
                        fatal.evidence_sha256
                    )
            if matching_exits:
                exits_by_fatal[fatal.evidence_sha256] = matching_exits

    enriched: list[NormalizedLogEntry] = []
    for entry in entries:
        alert = entry.alert
        if alert is None or alert.event_type != "CUDA_DRIVER_INCOMPATIBLE":
            enriched.append(entry)
            continue
        fields = dict(alert.fields)
        matches = exits_by_fatal.get(entry.evidence_sha256, [])
        already_ambiguous = fields.get("exit_correlation_status") == "AMBIGUOUS"
        audit_was_truncated = fields.get("exit_correlation_audit_truncated") is True
        if (
            len(matches) == 1
            and len(fatal_candidates_by_exit.get(matches[0].evidence_sha256, ())) == 1
            and not already_ambiguous
            and not audit_was_truncated
        ):
            exit_entry = matches[0]
            fields.update({
                "miner_exit_status": 1,
                "exit_status_confirmed": True,
                "exit_status_event_time_utc": exit_entry.event_time_utc,
                "exit_evidence_sha256": exit_entry.evidence_sha256,
                "exit_correlation_status": "CONFIRMED",
            })
        elif matches:
            candidate_exit_hashes = {
                candidate.evidence_sha256 for candidate in matches
            }
            candidate_fatal_hashes: set[str] = set()
            for candidate in matches:
                candidate_fatal_hashes.update(
                    fatal_candidates_by_exit.get(candidate.evidence_sha256, set())
                )
            exit_hashes, exits_truncated = _bounded_hashes(
                [
                    *fields.get("exit_evidence_audit_sha256", []),
                    *candidate_exit_hashes,
                    *([fields["exit_evidence_sha256"]]
                      if isinstance(fields.get("exit_evidence_sha256"), str) else []),
                ],
                MAX_CUDA_EXIT_AUDIT_HASHES,
            )
            fatal_hashes, fatals_truncated = _bounded_hashes(
                [
                    *fields.get("exit_candidate_fatal_sha256", []),
                    *candidate_fatal_hashes,
                ],
                MAX_CUDA_FATAL_CANDIDATE_HASHES,
            )
            fields["exit_correlation_status"] = "AMBIGUOUS"
            fields["miner_exit_status"] = "UNKNOWN"
            fields["exit_status_confirmed"] = False
            fields["exit_status_event_time_utc"] = None
            fields["exit_evidence_sha256"] = None
            fields["exit_evidence_audit_sha256"] = exit_hashes
            fields["exit_candidate_fatal_sha256"] = fatal_hashes
            if audit_was_truncated or exits_truncated or fatals_truncated:
                fields["exit_correlation_audit_truncated"] = True
        elif already_ambiguous or audit_was_truncated:
            fields.update({
                "exit_correlation_status": "AMBIGUOUS",
                "miner_exit_status": "UNKNOWN",
                "exit_status_confirmed": False,
                "exit_status_event_time_utc": None,
                "exit_evidence_sha256": None,
            })
        enriched.append(replace(entry, alert=replace(alert, fields=fields)))
    return tuple(enriched), tuple(durable_exit_evidence)


def render_cuda_message(payload: Mapping[str, Any]) -> str:
    """Render the fixed CUDA alert without raw miner text or arbitrary labels."""
    identity = payload.get("identity")
    fields = payload.get("event_fields")
    if not isinstance(identity, Mapping) or not isinstance(fields, Mapping):
        raise ValueError("CUDA alert payload is malformed")

    def safe(value: Any) -> str:
        if not isinstance(value, str):
            return "UNKNOWN"
        value = "".join(char for char in value if ord(char) >= 32 and ord(char) != 127)
        return value[:128] or "UNKNOWN"

    reason = fields.get("reason")
    if reason != CUDA_DRIVER_FAILURE_REASON:
        raise ValueError("CUDA alert reason is invalid")
    if fields.get("gpu_initialized") is not False:
        raise ValueError("CUDA alert GPU initialization state is invalid")
    if fields.get("actions_performed") is not False:
        raise ValueError("CUDA alert action state is invalid")
    if fields.get("recommendation") != "REALLOCATE":
        raise ValueError("CUDA alert recommendation is invalid")
    exit_status = fields.get("miner_exit_status")
    confirmed = fields.get("exit_status_confirmed")
    if not ((exit_status == 1 and confirmed is True) or (exit_status == "UNKNOWN" and confirmed is False)):
        raise ValueError("CUDA alert exit evidence is inconsistent")

    lines = [
        f"Organization: {safe(identity.get('organization_name') or payload.get('query_organization'))}",
        f"Project: {safe(identity.get('project_name'))}",
        f"Container Group: {safe(identity.get('container_group_name'))}",
        f"Machine ID: {safe(identity.get('machine_id'))}",
        f"Instance ID: {safe(identity.get('instance_id'))}",
        f"Identity source: {safe(identity.get('identity_source'))}",
        "🚨 CUDA_DRIVER_INCOMPATIBLE",
        f"Identity status: {safe(identity.get('identity_status'))}",
        f"Error: {CUDA_DRIVER_FAILURE_REASON}",
        "GPU initialized: false",
        f"Miner exit: {exit_status if confirmed else 'UNKNOWN'}",
        "Recommendation: REALLOCATE",
        "Actions performed: false",
    ]
    message = "\n".join(lines)
    if len(message) > 8_192:
        raise ValueError("CUDA alert message exceeds the local bound")
    return message
