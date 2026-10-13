"""Fixture-only G4-A client for the two approved Salad GET contracts.

There is deliberately no HTTP implementation in this module. The reviewed
point-instance and workload-error endpoints remain blocked until their
contracts and read-only permissions are independently resolved.
"""

from __future__ import annotations

import json
import re
import time
from collections import deque
from collections.abc import Mapping
from urllib.parse import quote
from typing import Any, Callable


BASE_URL = "https://api.salad.com/api/public"
ALLOWED_OPERATIONS = frozenset({"get_container_group", "list_container_group_instances"})
MAX_INSTANCES = 1000
_SECRET_PATTERNS = (
    re.compile(r"(?i)(salad[_-]?api[_-]?key|authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|token)(\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]+=*"),
)
_SENSITIVE_KEY_SUFFIXES = ("token", "apikey", "secret", "credential", "password")
_SENSITIVE_KEY_NAMES = frozenset({"authorization", "proxyauthorization", "cookie", "setcookie"})


class G4ASaladError(RuntimeError):
    pass


class G4ABlockedOperation(G4ASaladError):
    pass


class G4ASaladReadError(G4ASaladError):
    def __init__(self, operation: str, status: int | None, message: str):
        self.operation = operation
        self.status_code = status
        self.message = redact_secrets(message)
        super().__init__(f"{operation} failed ({status if status is not None else 'transport'}): {self.message}")


def redact_secrets(value: Any) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]" if match.lastindex and match.lastindex >= 2 else "Bearer [REDACTED]", text)
    return text[:500]


def _is_sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
    return normalized in _SENSITIVE_KEY_NAMES or any(token in normalized for token in _SENSITIVE_KEY_SUFFIXES)


def _sanitize_payload(value: Any) -> Any:
    """Drop credential-like keys recursively before provider fixtures escape."""
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_payload(item)
            for key, item in value.items()
            if isinstance(key, str) and not _is_sensitive_key(key)
        }
    if isinstance(value, list):
        return [_sanitize_payload(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_payload(item) for item in value]
    return value


def _check_response_scope(
    body: Mapping[str, Any],
    operation: str,
    *,
    organization_name: str,
    project_name: str,
    container_group_name: str,
    organization_id: str | None,
    project_id: str | None,
    container_group_id: str | None,
    include_group_name_alias: bool = False,
) -> None:
    checks = [
        (organization_name, ("organization_name", "organization"), "organization name"),
        (organization_id, ("organization_id", "organizationId"), "organization id"),
        (project_name, ("project_name", "project"), "project name"),
        (project_id, ("project_id", "projectId"), "project id"),
        (container_group_id, ("container_group_id", "containerGroupId"), "container group id"),
    ]
    group_name_fields = ("container_group_name", "containerGroupName", "container_name")
    if include_group_name_alias:
        group_name_fields += ("name",)
    checks.append((container_group_name, group_name_fields, "container group name"))
    for expected, fields, description in checks:
        if expected is None:
            continue
        for field in fields:
            actual = body.get(field)
            if actual is not None and actual != expected:
                raise G4ASaladReadError(operation, 200, f"response {description} conflicts with requested scope")


def _optional_id(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 180:
        raise ValueError(f"{field} must be a non-empty bounded identifier when supplied")
    return value.strip()


def normalize_instance_list_response(
    body: Mapping[str, Any], *, organization_name: str,
    project_name: str, container_group_name: str,
    organization_id: str | None = None, project_id: str | None = None,
    container_group_id: str | None = None,
) -> dict[str, Any]:
    """Validate and sanitize the exact List Instances response schema.

    This pure validator is shared by the original fixture client and the
    central log-alert fallback. It never promotes a binding by itself.
    """
    if not isinstance(body, Mapping):
        raise G4ASaladReadError("list_container_group_instances", 200, "response body must be an object")
    org = organization_name.strip()
    project = project_name.strip()
    group = container_group_name.strip()
    _check_response_scope(
        body, "list_container_group_instances", organization_name=org,
        project_name=project, container_group_name=group,
        organization_id=organization_id, project_id=project_id,
        container_group_id=container_group_id,
    )
    instances = body.get("instances")
    if not isinstance(instances, list):
        raise G4ASaladReadError("list_container_group_instances", 200, "documented instances array is missing; aliases are not accepted")
    if any(not isinstance(item, Mapping) for item in instances):
        raise G4ASaladReadError("list_container_group_instances", 200, "instances contains a non-object item")
    observed: list[dict[str, Any]] = []
    for item in instances[:MAX_INSTANCES]:
        _check_response_scope(
            item, "list_container_group_instances", organization_name=org,
            project_name=project, container_group_name=group,
            organization_id=organization_id, project_id=project_id,
            container_group_id=container_group_id,
        )
        value = _sanitize_payload(item)
        instance_id = value.get("instance_id")
        alias_id = value.get("id")
        machine_id = value.get("machine_id")
        if alias_id is not None and instance_id is not None and alias_id != instance_id:
            identity_status = "CONFLICTING"
        elif isinstance(instance_id, str) and instance_id.strip() and isinstance(machine_id, str) and machine_id.strip():
            identity_status = "OBSERVED_PROVIDER_FIELDS"
        else:
            identity_status = "UNKNOWN"
        observed.append({**value, "identity_status": identity_status, "binding_status": "UNKNOWN"})
    limit_reached = len(instances) >= MAX_INSTANCES
    return {
        "operation": "list_container_group_instances",
        "method": "GET",
        "path": f"/organizations/{G4ASaladGetClient._name(org, 'organization_name')}"
                f"/projects/{G4ASaladGetClient._name(project, 'project_name')}"
                f"/containers/{G4ASaladGetClient._name(group, 'container_group_name')}/instances",
        "instances": observed,
        "returned_count": len(observed),
        "complete": not limit_reached,
        "status": "INCOMPLETE" if limit_reached else "COMPLETE",
        "incomplete_reason": "documented 1000-item maximum reached; cursor contract is UNKNOWN" if limit_reached else None,
        "binding_status": "UNKNOWN",
    }


class FixtureSaladTransport:
    """Exact registered fixture transport; it cannot open sockets or use credentials."""

    offline_fixture = True

    def __init__(self, responses: Mapping[str, Any]):
        self._responses = dict(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, operation: str, path: str, *, timeout_seconds: float, max_response_bytes: int) -> Mapping[str, Any]:
        if method != "GET" or operation not in ALLOWED_OPERATIONS:
            raise G4ABlockedOperation("only fixture-backed allowlisted GET operations are available")
        if not path.startswith(BASE_URL + "/"):
            raise G4ABlockedOperation("fixture transport rejects a non-Salad API base URL")
        self.calls.append({"method": method, "operation": operation, "path": path, "timeout_seconds": timeout_seconds, "credentials_sent": False})
        value = self._responses.get(operation)
        if isinstance(value, BaseException):
            raise value
        if not isinstance(value, Mapping):
            raise G4ASaladReadError(operation, None, "fixture response is missing")
        response = dict(value)
        size = len(json.dumps(response.get("body"), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        if size > max_response_bytes:
            raise G4ASaladReadError(operation, response.get("status_code"), "response exceeds configured size limit")
        return response


class G4ASaladGetClient:
    """Validated fixture reader; no production HTTP/authentication path exists."""

    def __init__(
        self,
        transport: FixtureSaladTransport,
        *,
        timeout_seconds: float = 5,
        max_response_bytes: int = 1_048_576,
        max_requests_per_minute: int = 30,
        clock: Callable[[], float] = time.monotonic,
    ):
        if type(transport) is not FixtureSaladTransport:
            raise ValueError("G4-A requires the registered fixture-only Salad transport")
        if not 0 < timeout_seconds <= 10 or max_response_bytes < 1 or max_requests_per_minute < 1:
            raise ValueError("timeout, response, and request-rate limits must be positive and bounded")
        self._transport = transport
        self._timeout = float(timeout_seconds)
        self._max_bytes = int(max_response_bytes)
        self._rate = int(max_requests_per_minute)
        self._clock = clock
        self._call_times: deque[float] = deque()

    @staticmethod
    def _name(value: str, field: str) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 180:
            raise ValueError(f"{field} must be a non-empty bounded name")
        return quote(value.strip(), safe="-_.~")

    def _request(self, operation: str, path: str) -> Mapping[str, Any]:
        now = self._clock()
        while self._call_times and now - self._call_times[0] >= 60:
            self._call_times.popleft()
        if len(self._call_times) >= self._rate:
            raise G4ASaladReadError(operation, 429, "local fixture request budget exhausted")
        self._call_times.append(now)
        try:
            response = self._transport.request("GET", operation, BASE_URL + path, timeout_seconds=self._timeout, max_response_bytes=self._max_bytes)
        except G4ASaladError:
            raise
        except TimeoutError as exc:
            raise G4ASaladReadError(operation, None, "fixture timeout") from exc
        except Exception as exc:
            raise G4ASaladReadError(operation, None, redact_secrets(exc)) from exc
        status = response.get("status_code")
        if isinstance(status, bool) or not isinstance(status, int) or status < 100 or status > 599:
            raise G4ASaladReadError(operation, None, "invalid fixture HTTP status")
        if status != 200:
            raise G4ASaladReadError(operation, status, "non-success status; no retry or fallback performed")
        body = response.get("body")
        if not isinstance(body, Mapping):
            raise G4ASaladReadError(operation, status, "response body must be an object")
        return dict(body)

    def get_container_group(
        self,
        *,
        organization_name: str,
        project_name: str,
        container_group_name: str,
        organization_id: str | None = None,
        project_id: str | None = None,
        container_group_id: str | None = None,
    ) -> dict[str, Any]:
        org = self._name(organization_name, "organization_name")
        project = self._name(project_name, "project_name")
        group = self._name(container_group_name, "container_group_name")
        organization_raw = organization_name.strip()
        project_raw = project_name.strip()
        group_raw = container_group_name.strip()
        organization_id = _optional_id(organization_id, "organization_id")
        project_id = _optional_id(project_id, "project_id")
        container_group_id = _optional_id(container_group_id, "container_group_id")
        path = f"/organizations/{org}/projects/{project}/containers/{group}"
        body = self._request("get_container_group", path)
        _check_response_scope(
            body,
            "get_container_group",
            organization_name=organization_raw,
            project_name=project_raw,
            container_group_name=group_raw,
            organization_id=organization_id,
            project_id=project_id,
            container_group_id=container_group_id,
            include_group_name_alias=True,
        )
        safe_body = _sanitize_payload(body)
        return {
            "operation": "get_container_group",
            "method": "GET",
            "path": path,
            "source": "SaladCloud GET fixture; no provider request was made",
            "reported_state": safe_body.get("state") if isinstance(safe_body.get("state"), str) else None,
            "body": safe_body,
            "billing_status": "UNKNOWN",
            "binding_status": "UNKNOWN",
            "credentials_sent": False,
        }

    def list_container_group_instances(
        self,
        *,
        organization_name: str,
        project_name: str,
        container_group_name: str,
        organization_id: str | None = None,
        project_id: str | None = None,
        container_group_id: str | None = None,
    ) -> dict[str, Any]:
        org = self._name(organization_name, "organization_name")
        project = self._name(project_name, "project_name")
        group = self._name(container_group_name, "container_group_name")
        organization_raw = organization_name.strip()
        project_raw = project_name.strip()
        group_raw = container_group_name.strip()
        organization_id = _optional_id(organization_id, "organization_id")
        project_id = _optional_id(project_id, "project_id")
        container_group_id = _optional_id(container_group_id, "container_group_id")
        path = f"/organizations/{org}/projects/{project}/containers/{group}/instances"
        body = self._request("list_container_group_instances", path)
        result = normalize_instance_list_response(
            body, organization_name=organization_raw,
            project_name=project_raw, container_group_name=group_raw,
            organization_id=organization_id, project_id=project_id,
            container_group_id=container_group_id,
        )
        result.update({
            "source": "SaladCloud GET fixture; no provider request was made",
            "billing_status": "UNKNOWN",
            "credentials_sent": False,
        })
        return result

    def get_container_group_instance(self, **_kwargs: Any) -> None:
        raise G4ABlockedOperation("point-instance GET is blocked: id/instance_id and 200/202 contracts remain conflicting")

    def get_container_group_errors(self, **_kwargs: Any) -> None:
        raise G4ABlockedOperation("workload-errors GET is blocked: detail/details schema conflict; it is not a log export API")
