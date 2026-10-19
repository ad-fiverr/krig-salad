"""Sanitize synthetic instance-list fixtures without making identity claims."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from pilot_scope import request_for_group

SYNTHETIC_CLASSIFICATION = "SYNTHETIC/UNVERIFIED"
MAX_INSTANCES_PER_RESPONSE = 1000
LIST_COMPLETENESS_UNKNOWN = "provider pagination/completeness is not verified"
LIST_COMPLETENESS_AT_CAP = "response reached 1000 items; pagination is not verified"

_PROVIDER_FIELDS = frozenset(
    {"id", "instance_id", "machine_id", "state", "update_time", "version", "ready", "started"}
)
_SECRET_KEY_PARTS = ("token", "secret", "credential", "password", "apikey", "privatekey")
_SECRET_VALUE = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[:=]\s*\S+|"
    r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"
)


class EvidenceError(ValueError):
    """Fixture content cannot be safely represented as provider evidence."""


def _sensitive_path(value: Any, path: str = "root") -> str | None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = "".join(char for char in str(key).casefold() if char.isalnum())
            if any(part in normalized for part in _SECRET_KEY_PARTS):
                return f"{path}.{key}"
            nested = _sensitive_path(item, f"{path}.{key}")
            if nested:
                return nested
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            nested = _sensitive_path(item, f"{path}[{index}]")
            if nested:
                return nested
    elif isinstance(value, str):
        if _SECRET_VALUE.search(value):
            return path
    return None


def _safe_scalar_id(value: Any, label: str) -> str | int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise EvidenceError(f"{label} must be a string, integer, or null")
    if isinstance(value, str) and not value.strip():
        raise EvidenceError(f"{label} cannot be an empty string")
    return value


def _safe_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EvidenceError(f"{label} must be a string or null")
    return value


def _safe_version(value: Any) -> str | int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise EvidenceError("version must be a string, integer, or null")
    return value


def _safe_bool(value: Any, label: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise EvidenceError(f"{label} must be a boolean or null")
    return value


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sanitize_instance_list(container_group: str, payload: Any) -> dict[str, Any]:
    """Return a minimized, explicitly synthetic list observation.

    Unknown fields, including SSH-related fields, are omitted. Credential-like
    keys or values reject the whole fixture before any sanitized result escapes.
    ``id`` and ``instance_id`` remain distinct fields and are never aliased.
    """
    request = request_for_group(container_group)
    sensitive = _sensitive_path(payload)
    if sensitive:
        raise EvidenceError(f"credential-like fixture content is forbidden at {sensitive}")
    if not isinstance(payload, Mapping) or set(payload) != {"instances"}:
        raise EvidenceError("fixture payload must contain only an instances array")
    rows = payload["instances"]
    if not isinstance(rows, list):
        raise EvidenceError("instances must be an array")
    if len(rows) > MAX_INSTANCES_PER_RESPONSE:
        raise EvidenceError("response exceeds the 1000-item schema cap")

    sanitized_rows: list[dict[str, Any]] = []
    dropped_fields = 0
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise EvidenceError(f"instances[{index}] must be an object")
        normalized: dict[str, Any] = {}
        for name in ("id", "instance_id", "machine_id"):
            if name in row:
                normalized[name] = _safe_scalar_id(row[name], f"instances[{index}].{name}")
        for name in ("state", "update_time"):
            if name in row:
                normalized[name] = _safe_string(row[name], f"instances[{index}].{name}")
        if "version" in row:
            normalized["version"] = _safe_version(row["version"])
        for name in ("ready", "started"):
            if name in row:
                normalized[name] = _safe_bool(row[name], f"instances[{index}].{name}")
        dropped_fields += len(set(row) - _PROVIDER_FIELDS)

        provider_id = normalized.get("id")
        instance_id = normalized.get("instance_id")
        if provider_id is not None and instance_id is not None and provider_id != instance_id:
            identity_status = "CONFLICTING"
        elif provider_id is not None or instance_id is not None:
            identity_status = "UNVERIFIED"
        else:
            identity_status = "UNKNOWN"
        normalized.update(
            {
                "provider_identity_status": identity_status,
                "gpu_binding_status": "UNKNOWN",
                "billing_status": "UNKNOWN",
            }
        )
        sanitized_rows.append(normalized)

    payload_out = {
        "instances": sanitized_rows,
        "instance_count_observed": len(sanitized_rows),
        "list_completeness": "INCOMPLETE" if len(sanitized_rows) == MAX_INSTANCES_PER_RESPONSE else "UNKNOWN",
        "list_completeness_reason": (
            LIST_COMPLETENESS_AT_CAP
            if len(sanitized_rows) == MAX_INSTANCES_PER_RESPONSE
            else LIST_COMPLETENESS_UNKNOWN
        ),
        "dropped_uncontracted_field_count": dropped_fields,
    }
    evidence = {
        "schema_version": "1.0",
        "data_classification": SYNTHETIC_CLASSIFICATION,
        "source_provenance": {
            "system": "local_fixture",
            "capture_mode": "synthetic_fixture",
            "provider_observation_verified": False,
        },
        "evidence_status": "UNVERIFIED",
        "operation": request.operation,
        "http_method": "GET",
        "organization": request.organization,
        "project": request.project,
        "container_group": container_group,
        "scope_source": "operator_approved_offline_scope",
        "request_path": request.path,
        "payload": payload_out,
        "binding_status": "UNKNOWN",
        "billing_status": "UNKNOWN",
        "live_calls_performed": False,
        "actions_performed": False,
        "reallocation_enabled": False,
    }
    evidence["sanitized_fixture_sha256"] = _canonical_hash(evidence)
    return evidence


def sanitize_live_instance_list(
    container_group: str,
    payload: Any,
    *,
    observed_at_utc: str,
) -> dict[str, Any]:
    """Minimize a successful fixed Salad GET without claiming GPU binding.

    Provider payload fields receive transport/source provenance, while machine
    to device/GPU attribution, billing, and list completeness remain UNKNOWN.
    This function must only be called after the fixed HTTPS transport returned
    a successful response.
    """
    if not isinstance(observed_at_utc, str) or not observed_at_utc.strip():
        raise EvidenceError("live observation timestamp is required")
    from datetime import datetime

    try:
        parsed = datetime.fromisoformat(observed_at_utc.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError("live observation timestamp is invalid") from None
    if parsed.tzinfo is None:
        raise EvidenceError("live observation timestamp must be timezone-aware")
    evidence = sanitize_instance_list(container_group, payload)
    evidence.pop("sanitized_fixture_sha256", None)
    evidence["data_classification"] = "PROVIDER_OBSERVED"
    evidence["evidence_status"] = "OBSERVED_UNVERIFIED_BINDING"
    evidence["source_provenance"] = {
        "system": "salad_api",
        "host": "api.salad.com",
        "capture_mode": "fixed_authenticated_https_get",
        "provider_response_observed": True,
        "transport_tls_hostname_verified": True,
        "observed_at_utc": observed_at_utc,
    }
    evidence["live_calls_performed"] = True
    evidence["actions_performed"] = False
    evidence["reallocation_enabled"] = False
    evidence["sanitized_observation_sha256"] = _canonical_hash(evidence)
    return evidence
