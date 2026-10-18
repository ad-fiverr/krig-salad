"""Versioned, fail-closed contracts for offline/live GPU telemetry boundaries.

This module deliberately contains no provider transport or credential handling.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any

from .guard_store import canonical_utc


LIVE_SCHEMA_VERSION = "1.0"
OBSERVED_DEVICE_HASHRATES = frozenset({"krig_device_reported", "fl4shminer_device_reported"})
PROVIDER_EVENT_TYPES = frozenset({"provider_lifecycle_observation", "readiness_observation", "allocation_lifecycle"})


class ContractValidationError(ValueError):
    """An event cannot safely cross the live telemetry boundary."""


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{field} must be a non-empty string")
    return value.strip()


def stable_event_id(kind: str, payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    digest = hashlib.sha256(f"{kind}\0{canonical}".encode("utf-8")).hexdigest()[:32]
    return f"{kind}_{digest}"


def validate_provider_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a provider observation; provider state never becomes billing proof."""
    if not isinstance(event, Mapping):
        raise ContractValidationError("provider event must be an object")
    result = dict(event)
    event_type = _required_text(result.get("event_type"), "event_type")
    if event_type not in PROVIDER_EVENT_TYPES:
        raise ContractValidationError(f"unsupported provider event_type: {event_type}")
    result["event_type"] = event_type
    result["reported_state"] = _required_text(result.get("reported_state"), "reported_state").casefold()
    result["occurred_at_utc"] = canonical_utc(result.get("occurred_at_utc"))
    result["event_source"] = _required_text(result.get("event_source") or result.get("source"), "event_source")
    event_id = result.get("event_id")
    if event_id is None:
        stable_fields = {
            key: result.get(key)
            for key in (
                "occurred_at_utc", "reported_state", "organization_id", "project_id",
                "container_group_id", "container_group_name", "instance_id", "machine_id",
                "event_source",
            )
        }
        event_id = stable_event_id("provider", stable_fields)
    result["event_id"] = _required_text(event_id, "event_id")
    # Lifecycle/readiness observations do not establish billing.
    result["billing_status"] = "UNKNOWN"
    result["schema_version"] = LIVE_SCHEMA_VERSION
    provenance = result.get("provenance")
    result["provenance"] = dict(provenance) if isinstance(provenance, Mapping) else {}
    result["provenance"].setdefault("event_source", result["event_source"])
    return result


def validate_miner_sample(event: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a local device-rate sample without substituting pool estimates."""
    if not isinstance(event, Mapping):
        raise ContractValidationError("miner sample must be an object")
    result = dict(event)
    if result.get("event_type") not in {"gpu_sample", "device_hashrate_sample"}:
        raise ContractValidationError("miner sample must use gpu_sample or device_hashrate_sample")
    result["event_id"] = _required_text(result.get("event_id") or result.get("observation_id"), "event_id")
    result["occurred_at_utc"] = canonical_utc(result.get("occurred_at_utc") or result.get("observed_at_utc"))
    semantics = _required_text(result.get("hashrate_semantics"), "hashrate_semantics")
    if semantics not in OBSERVED_DEVICE_HASHRATES:
        raise ContractValidationError("only local KRig/Fl4shMiner device-reported hashrate is guard-comparable")
    rate = result.get("hashrate_ths")
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(float(rate)) or rate < 0:
        raise ContractValidationError("hashrate_ths must be a finite non-negative number")
    result["hashrate_ths"] = float(rate)
    result["hashrate_semantics"] = semantics
    result["hashrate_source"] = _required_text(result.get("hashrate_source"), "hashrate_source")
    provenance = result.get("provenance")
    result["provenance"] = dict(provenance) if isinstance(provenance, Mapping) else {}
    source = result.get("event_source") or result["provenance"].get("event_source") or result["provenance"].get("source")
    if isinstance(source, str) and source.strip():
        result["event_source"] = source.strip()
        result["provenance"].setdefault("event_source", source.strip())
    result["schema_version"] = LIVE_SCHEMA_VERSION
    # Keep identity and allocation identifiers as supplied. Missing/ambiguous
    # values remain unknown; this module never derives them from device IDs.
    return result


def validate_live_event(event: Mapping[str, Any]) -> dict[str, Any]:
    event_type = event.get("event_type") if isinstance(event, Mapping) else None
    if event_type in PROVIDER_EVENT_TYPES:
        return validate_provider_event(event)
    return validate_miner_sample(event)
