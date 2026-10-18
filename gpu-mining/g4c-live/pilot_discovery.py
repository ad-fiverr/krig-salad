"""Deterministic replay of synthetic four-group Salad response fixtures.

No socket, HTTP, Firebase, credential, or action adapter is exposed here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pilot_evidence import EvidenceError, sanitize_instance_list
from pilot_scope import (
    CONTAINER_GROUPS,
    MAX_RESPONSE_BYTES_PER_GROUP,
    MAX_RESPONSE_BYTES_TOTAL,
    REQUEST_PLAN,
    RequestSpec,
)


SYNTHETIC_CLASSIFICATION = "SYNTHETIC/UNVERIFIED"


@dataclass(frozen=True)
class OfflineFixtureResponse:
    """A local test fixture standing in for one HTTP response."""

    container_group: str
    status_code: int | None
    body: Any = None
    timed_out: bool = False
    transport_error: str | None = None


def _serialized_body(body: Any) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("fixture body must be JSON-compatible, text, or bytes") from exc


def _parse_body(body: Any) -> Any:
    if isinstance(body, Mapping):
        return body
    raw = _serialized_body(body)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("fixture body is not valid UTF-8 JSON") from exc


def _fixture_status(response: OfflineFixtureResponse) -> tuple[str, str]:
    if not isinstance(response.timed_out, bool):
        return "INVALID_FIXTURE", "timed_out must be a boolean fixture field"
    if response.timed_out:
        return "TIMEOUT", "synthetic response represents a request timeout; no retry is allowed"
    if response.transport_error is not None:
        if not isinstance(response.transport_error, str) or not response.transport_error:
            return "INVALID_FIXTURE", "transport_error must be a non-empty synthetic label"
        return "TRANSPORT_ERROR", "synthetic transport error; remaining groups are not queried"
    status = response.status_code
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return "INVALID_FIXTURE", "status_code must be an HTTP status integer"
    if status == 200:
        return "OK", "synthetic HTTP 200 fixture"
    if 300 <= status < 400:
        return "REDIRECT_BLOCKED", "redirects are not followed"
    if status in {401, 403}:
        return "AUTH_BLOCKED", "provider rejected the synthetic request; no credential diagnosis is persisted"
    if status == 404:
        return "NOT_FOUND_OR_SCOPE_UNKNOWN", "resource or scope is unverified"
    if status == 429:
        return "RATE_LIMITED", "no retry or polling is performed"
    if status >= 500:
        return "PROVIDER_ERROR", "provider error; remaining groups are not queried"
    return "CONTRACT_CONFLICT", f"HTTP {status} is outside the approved 200-only list response contract"


def _empty_group(spec: RequestSpec, state: str) -> dict[str, Any]:
    return {
        "container_group": spec.container_group,
        "ordinal": spec.ordinal,
        "request_path": spec.path,
        "method": spec.method,
        "state": state,
        "http_status_code": None,
        "evidence": None,
        "error": None,
        "response_bytes": 0,
    }


def _blocked_result(reason: str, state: str = "SCOPE_BLOCKED") -> dict[str, Any]:
    groups = [_empty_group(spec, "NOT_QUERIED") for spec in REQUEST_PLAN]
    return {
        "schema_version": "1.0",
        "data_classification": SYNTHETIC_CLASSIFICATION,
        "execution_mode": "OFFLINE_FIXTURE_REPLAY",
        "state": state,
        "reason": reason,
        "groups": groups,
        "fixtures_consumed": 0,
        "response_bytes_total": 0,
        "live_calls_performed": False,
        "actions_performed": False,
        "reallocation_enabled": False,
    }


def _cross_group_collisions(groups: list[dict[str, Any]]) -> None:
    seen: dict[tuple[str, type, str | int], list[tuple[dict[str, Any], int]]] = {}
    for group in groups:
        evidence = group.get("evidence")
        if not isinstance(evidence, dict):
            continue
        for row_index, row in enumerate(evidence["payload"]["instances"]):
            for field in ("id", "instance_id", "machine_id"):
                value = row.get(field)
                if value is None:
                    continue
                key = (field, type(value), value)
                seen.setdefault(key, []).append((group, row_index))
    for (field, _value_type, value), occurrences in seen.items():
        distinct_groups = {group["container_group"] for group, _ in occurrences}
        if len(distinct_groups) < 2:
            continue
        for group, row_index in occurrences:
            group.setdefault("cross_group_collisions", []).append(
                {
                    "row_index": row_index,
                    "field": field,
                    "value": value,
                    "other_groups": sorted(distinct_groups - {group["container_group"]}),
                }
            )


def replay_discovery_fixtures(
    fixtures: Sequence[OfflineFixtureResponse],
) -> dict[str, Any]:
    """Replay zero or more synthetic group responses, strictly in fixed order.

    A scope error is rejected before consuming any fixture. The first malformed
    or unsuccessful response stops the sequence; later groups remain
    ``NOT_QUERIED``. This models the future fail-closed request policy only.
    """
    if not isinstance(fixtures, Sequence) or isinstance(fixtures, (str, bytes, bytearray)):
        return _blocked_result("fixtures must be an ordered sequence of offline response objects")
    if len(fixtures) > len(REQUEST_PLAN):
        return _blocked_result("more than four responses are outside the approved request budget")

    fixture_groups: list[str] = []
    for fixture in fixtures:
        if not isinstance(fixture, OfflineFixtureResponse):
            return _blocked_result("every fixture must be an OfflineFixtureResponse")
        if not isinstance(fixture.container_group, str):
            return _blocked_result("every fixture container group must be a string")
        fixture_groups.append(fixture.container_group)
    if len(fixture_groups) != len(set(fixture_groups)):
        return _blocked_result("repeated container groups are forbidden")
    if any(group not in CONTAINER_GROUPS for group in fixture_groups):
        return _blocked_result("fixture contains a container group outside the approved allowlist")
    if fixture_groups != list(CONTAINER_GROUPS[: len(fixture_groups)]):
        return _blocked_result("fixtures must follow the approved group order without skipping ahead")

    groups = [_empty_group(spec, "NOT_QUERIED") for spec in REQUEST_PLAN]
    fixtures_consumed = 0
    total_bytes = 0
    stopped_reason: str | None = None

    for index, spec in enumerate(REQUEST_PLAN):
        if index >= len(fixtures):
            stopped_reason = "MISSING_FIXTURE"
            break
        fixture = fixtures[index]
        fixtures_consumed += 1
        group_result = groups[index]
        if fixture.container_group != spec.container_group:
            group_result["state"] = "SCOPE_BLOCKED"
            group_result["error"] = "fixture group does not match the next fixed request"
            stopped_reason = "SCOPE_BLOCKED"
            break

        state, detail = _fixture_status(fixture)
        group_result["state"] = state
        if (
            not fixture.timed_out
            and fixture.transport_error is None
            and isinstance(fixture.status_code, int)
            and not isinstance(fixture.status_code, bool)
            and 100 <= fixture.status_code <= 599
            and state != "INVALID_FIXTURE"
        ):
            group_result["http_status_code"] = fixture.status_code
        if state != "OK":
            group_result["error"] = detail
            stopped_reason = state
            break

        try:
            raw = _serialized_body(fixture.body)
        except ValueError as exc:
            group_result["state"] = "INVALID_FIXTURE"
            group_result["error"] = str(exc)
            stopped_reason = "INVALID_FIXTURE"
            break
        byte_count = len(raw)
        group_result["response_bytes"] = byte_count
        if byte_count > MAX_RESPONSE_BYTES_PER_GROUP:
            group_result["state"] = "RESPONSE_TOO_LARGE"
            group_result["error"] = "synthetic body exceeds the per-group byte cap"
            stopped_reason = "RESPONSE_TOO_LARGE"
            break
        if total_bytes + byte_count > MAX_RESPONSE_BYTES_TOTAL:
            group_result["state"] = "TOTAL_RESPONSE_BUDGET_EXCEEDED"
            group_result["error"] = "synthetic bodies exceed the total byte cap"
            stopped_reason = "TOTAL_RESPONSE_BUDGET_EXCEEDED"
            break
        total_bytes += byte_count
        try:
            payload = _parse_body(raw)
            evidence = sanitize_instance_list(spec.container_group, payload)
        except (EvidenceError, ValueError) as exc:
            group_result["state"] = "INVALID_OR_UNSAFE_PAYLOAD"
            group_result["error"] = str(exc)
            stopped_reason = "INVALID_OR_UNSAFE_PAYLOAD"
            break
        group_result["state"] = "OBSERVED_SYNTHETIC_UNVERIFIED"
        group_result["evidence"] = evidence

    _cross_group_collisions(groups)
    all_observed = all(group["state"] == "OBSERVED_SYNTHETIC_UNVERIFIED" for group in groups)
    return {
        "schema_version": "1.0",
        "data_classification": SYNTHETIC_CLASSIFICATION,
        "execution_mode": "OFFLINE_FIXTURE_REPLAY",
        "source_provenance": {
            "system": "local_fixture",
            "capture_mode": "synthetic_fixture",
            "provider_observation_verified": False,
        },
        "state": "ALL_FIXTURES_REPLAYED" if all_observed else "PARTIAL_OR_BLOCKED",
        "stopped_reason": stopped_reason,
        "groups": groups,
        "fixtures_consumed": fixtures_consumed,
        "response_bytes_total": total_bytes,
        "request_limit": {
            "max_requests_total": 4,
            "max_requests_per_group": 1,
            "retries": 0,
            "redirects_followed": False,
        },
        "live_calls_performed": False,
        "actions_performed": False,
        "reallocation_enabled": False,
    }

