"""Compatibility adapters for public and persisted GPU Profit Guard V2 records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


def normalize_v2_track(track: Mapping[str, Any]) -> dict[str, Any]:
    """Expose stable V2 track fields without discarding the stored record."""
    result = dict(track)
    identity = result.get("gpu_identity")
    if not isinstance(identity, Mapping):
        raw_identity = result.get("gpu_identity_json")
        try:
            identity = json.loads(raw_identity) if isinstance(raw_identity, str) else {}
        except (TypeError, ValueError):
            identity = {}
    result["gpu_identity"] = dict(identity) if isinstance(identity, Mapping) else {}
    if "track_active" not in result:
        if "closed_at_utc" in result:
            result["track_active"] = result.get("closed_at_utc") is None and not result.get("terminal_reason")
        else:
            result["track_active"] = False
    return result


def normalize_v2_evaluation(evaluation: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize ContinuousMonitor output or GuardStore.evaluations_for_track rows.

    Stored V2 rows keep the evaluator result nested under ``result``. Public
    monitor results are already flat. This adapter preserves source fields and
    adds a common flat view used by the dashboard and dry-run controller.
    """
    result = dict(evaluation)
    nested = result.get("result")
    if not isinstance(nested, Mapping):
        return result

    details = nested.get("details") if isinstance(nested.get("details"), Mapping) else {}
    policy_details = details.get("policy") if isinstance(details.get("policy"), Mapping) else {}
    windows = details.get("windows") if isinstance(details.get("windows"), list) else []
    last_window = windows[-1] if windows and isinstance(windows[-1], Mapping) else {}
    identity = details.get("verified_gpu_identity")
    if not isinstance(identity, Mapping):
        identity = details.get("gpu_identity")
    identity = dict(identity) if isinstance(identity, Mapping) else {}
    quality = {
        "coverage_ratio": last_window.get("coverage_ratio"),
        "sample_count": last_window.get("sample_count"),
        "maximum_observed_gap_seconds": last_window.get("maximum_observed_gap_seconds"),
    }

    result.update({
        "evaluation_id": result.get("evaluation_id") or result.get("evaluated_at_utc"),
        "track_id": result.get("track_id") or details.get("track_id"),
        "evaluated_at_utc": result.get("evaluated_at_utc"),
        "policy_hash": result.get("policy_hash") or policy_details.get("policy_hash"),
        "decision": result.get("decision") or nested.get("decision"),
        "hash_health": result.get("hash_health") or details.get("hash_health"),
        "machine_id": details.get("machine_id"),
        "instance_id": details.get("instance_id"),
        "allocation_id": details.get("allocation_id"),
        "assignment_id": details.get("assignment_id"),
        "device_namespace": details.get("device_namespace"),
        "device_id": details.get("device_id"),
        "track_active": details.get("track_active") is True,
        "gpu_identity": identity,
        "gpu_floor_ths": details.get("gpu_floor_ths"),
        "observed_window_hashrate_ths": last_window.get("mean_hashrate_ths"),
        "deterioration_start_utc": details.get("deterioration_start_utc"),
        "sample_quality": quality,
        "reallocation_history": details.get("reallocation_history"),
        "reason": nested.get("reason"),
        "provenance": result.get("provenance") or {},
        "actions_performed": details.get("actions_performed") is True,
        "v2_source": "guard_store_evaluation_record",
    })
    return result
