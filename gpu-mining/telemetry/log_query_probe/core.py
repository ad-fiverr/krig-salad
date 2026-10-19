"""Bounded, sanitized, offline-first probe for Salad organization log queries.

The only live operation represented here is the fixed organization log-query
POST. Constructing or importing this module opens no sockets and reads no
credentials. Provider semantics remain unknown until a separately authorized
manual invocation is reviewed and run by the operator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import http.client
import json
import math
import re
import ssl
import sys
import time
from typing import Any, Callable, Mapping


SALAD_HOST = "api.salad.com"
SALAD_PORT = 443
SALAD_ROUTE_PREFIX = "/api/public/organizations/"
MAX_PAGE_SIZE = 100
MAX_WINDOW_NS = 3_600 * 1_000_000_000
MAX_EXPERIMENT_REQUESTS = 6
MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS = 3
MAX_PAGE_MIN_BEFORE_CAPTURE_ATTEMPTS = 10
MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS = 30
PAGE_MIN_BEFORE_CAPTURE_WINDOW_SECONDS = 135
PAGE_MIN_BEFORE_CAPTURE_CADENCE_SECONDS = 15
MAX_SATURATED_TRACE_DEPTH = 5
MAX_SATURATED_TRACE_REQUESTS = 11
MAX_PRODUCTION_RECURSION_TRACE_DEPTH = 7
MAX_PRODUCTION_RECURSION_TRACE_REQUESTS = 23
MAX_RESPONSE_BYTES = 5_000_000
MAX_TOTAL_RESPONSE_BYTES = 5_000_000
MAX_PROVIDER_ERROR_BODY_BYTES = 4_096
_PROVIDER_ERROR_BODY_STATUSES = frozenset({400, 401, 403, 404, 429})
_PROVIDER_ERROR_CODES = frozenset({"invalid_time_range"})
MAX_REQUEST_BYTES = 24_000
MAX_TOTAL_ITEMS = MAX_SATURATED_TRACE_REQUESTS * MAX_PAGE_SIZE
MAX_PRODUCTION_RECURSION_TRACE_ITEMS = (
    MAX_PRODUCTION_RECURSION_TRACE_REQUESTS * MAX_PAGE_SIZE
)
CONNECT_TIMEOUT_SECONDS = 8.0
READ_TIMEOUT_SECONDS = 12.0
MAX_DELTA_SECONDS = 86_400

_NS_PER_SECOND = 1_000_000_000
_NS_PER_MICROSECOND = 1_000
_NS_PER_MILLISECOND = 1_000_000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ORG_RE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
_RFC3339_RE = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[Tt]"
    r"(?P<clock>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<zone>[Zz]|[+-]\d{2}:\d{2})"
)
_CREDENTIAL_LIKE_RE = re.compile(
    r"(?i)(?:salad[ _-]*api[ _-]*key|bearer\s+\S{8,}|"
    r"(?:token|password|secret|api[_-]?key)\s*[:=])"
)
_PAGINATION_KEYS = frozenset({
    "next_page_token", "page_token", "next_page", "nextPageToken",
    "pageToken", "next_cursor", "nextCursor", "pagination", "cursors",
})
_ERROR_CODES = frozenset({
    "CONFIGURATION_INVALID", "LIVE_AUTHORIZATION_REQUIRED",
    "INTERACTIVE_TTY_REQUIRED", "SECRET_PROVIDER_UNAVAILABLE",
    "SECRET_INPUT_EMPTY_OR_INVALID", "SECRET_ACQUISITION_FAILED",
    "SECRET_MATERIAL_INVALID", "SECRET_PROVIDER_IDENTITY_INVALID",
    "SECRET_SOURCE_INVALID", "SECRET_HEADER_ENCODING_INVALID",
    "LIVE_TRANSPORT_FAILED", "LIVE_TIMEOUT", "HTTP_STATUS_REJECTED",
    "RESPONSE_TOO_LARGE", "RESPONSE_JSON_INVALID", "RESPONSE_SCHEMA_INVALID",
    "PAGINATION_METADATA_UNSUPPORTED", "PAGE_BOUNDS_MISSING",
    "PAGE_BOUNDS_INVALID", "PAGE_BOUNDS_REVERSED", "ITEM_TIME_MISSING",
    "ITEM_TIME_INVALID", "RECEIVE_TIME_INVALID", "PAGE_SIZE_EXCEEDED",
    "BYTE_BUDGET_EXCEEDED", "ENTRY_BUDGET_EXCEEDED",
    "REQUEST_BUDGET_EXCEEDED", "MIDPOINT_INVALID", "DIRECT_CHILD_INVALID",
    "TRANSPORT_RESPONSE_INVALID", "SECRET_BOUNDARY_VIOLATION",
})
_ROLE_PAGE_SIZES = {
    "PARENT_100": 100,
    "CONTROL_99": 99,
    "REPEAT_PARENT_100": 100,
    "LEFT_CHILD_100": 100,
    "RIGHT_CHILD_100": 100,
    "DIRECT_CHILD_100": 100,
    "TRACE_PARENT_0_100": 100,
    "PAGE_MIN_PROBE_PARENT_100": 100,
    "PAGE_MIN_PROBE_LEFT_100": 100,
    "PAGE_MIN_PROBE_RIGHT_100": 100,
}
for _trace_depth in range(1, MAX_SATURATED_TRACE_DEPTH + 1):
    for _trace_side in ("LEFT", "RIGHT"):
        _ROLE_PAGE_SIZES[f"TRACE_DEPTH_{_trace_depth}_{_trace_side}_100"] = 100
for _trace_depth in range(MAX_PRODUCTION_RECURSION_TRACE_DEPTH + 1):
    _first_node = 1 << _trace_depth
    _last_node = (1 << (_trace_depth + 1)) - 1
    for _trace_node in range(_first_node, _last_node + 1):
        _ROLE_PAGE_SIZES[
            f"PRODUCTION_TRACE_D{_trace_depth}_N{_trace_node}_100"
        ] = 100


class ProbeError(RuntimeError):
    """A fixed, non-sensitive diagnostic failure."""

    __slots__ = (
        "code", "http_status", "provider_error_code", "provider_error_category",
    )

    def __init__(
        self, code: str, *, http_status: int | None = None,
        provider_error_code: str | None = None,
        provider_error_category: str | None = None,
    ):
        self.code = code if type(code) is str and code in _ERROR_CODES else "CONFIGURATION_INVALID"
        self.http_status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None
        self.provider_error_code = (
            provider_error_code
            if type(provider_error_code) is str
            and provider_error_code in _PROVIDER_ERROR_CODES
            else None
        )
        self.provider_error_category = (
            provider_error_category
            if provider_error_category == "PROVIDER_ERROR_UNCLASSIFIED"
            else None
        )
        super().__init__(self.code)

    def __repr__(self) -> str:
        return (
            f"ProbeError(code={self.code!r}, http_status={self.http_status!r}, "
            f"provider_error_code={self.provider_error_code!r}, "
            f"provider_error_category={self.provider_error_category!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ExactInstant:
    """UTC instant with nanosecond integer precision and fixed format classes."""

    epoch_ns: int = field(repr=False)
    precision_class: str
    timezone_class: str

    def __post_init__(self) -> None:
        if (
            type(self.epoch_ns) is not int
            or type(self.precision_class) is not str
            or self.precision_class not in {
                "SECONDS", "MILLISECOND", "MICROSECOND", "SUBMICROSECOND",
            }
            or type(self.timezone_class) is not str
            or self.timezone_class not in {"Z", "UTC_OFFSET", "NONUTC_OFFSET"}
        ):
            raise ProbeError("CONFIGURATION_INVALID")

    def __repr__(self) -> str:
        return "ExactInstant([TIME REDACTED])"


def parse_rfc3339(value: str) -> ExactInstant:
    """Parse a timezone-qualified RFC3339 timestamp without float rounding."""
    if type(value) is not str or len(value) > 64:
        raise ProbeError("CONFIGURATION_INVALID")
    match = _RFC3339_RE.fullmatch(value)
    if match is None:
        raise ProbeError("CONFIGURATION_INVALID")
    zone = match.group("zone")
    if zone == "-00:00":
        # RFC3339 uses -00:00 to mean that the local offset is unknown.
        raise ProbeError("CONFIGURATION_INVALID")
    normalized_zone = "+00:00" if zone in {"Z", "z"} else zone
    try:
        base = datetime.fromisoformat(
            f"{match.group('date')}T{match.group('clock')}{normalized_zone}"
        )
        utc_base = base.astimezone(timezone.utc).replace(microsecond=0)
    except (ValueError, OverflowError):
        raise ProbeError("CONFIGURATION_INVALID") from None
    delta = utc_base - _EPOCH
    epoch_seconds = delta.days * 86_400 + delta.seconds
    fraction = match.group("fraction") or ""
    fractional_ns = int(fraction.ljust(9, "0")) if fraction else 0
    epoch_ns = epoch_seconds * _NS_PER_SECOND + fractional_ns
    if not fraction:
        precision = "SECONDS"
    elif len(fraction) <= 3:
        precision = "MILLISECOND"
    elif len(fraction) <= 6:
        precision = "MICROSECOND"
    else:
        precision = "SUBMICROSECOND"
    if zone in {"Z", "z"}:
        timezone_class = "Z"
    elif zone == "+00:00":
        timezone_class = "UTC_OFFSET"
    else:
        timezone_class = "NONUTC_OFFSET"
    return ExactInstant(epoch_ns, precision, timezone_class)


def _format_utc_ns(epoch_ns: int, *, millisecond_only: bool = False) -> str:
    seconds, fractional_ns = divmod(epoch_ns, _NS_PER_SECOND)
    try:
        moment = _EPOCH + timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        raise ProbeError("CONFIGURATION_INVALID") from None
    result = (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
    )
    if millisecond_only:
        if fractional_ns % _NS_PER_MILLISECOND:
            raise ProbeError("CONFIGURATION_INVALID")
        result += f".{fractional_ns // _NS_PER_MILLISECOND:03d}Z"
    elif fractional_ns:
        result += "." + f"{fractional_ns:09d}".rstrip("0") + "Z"
    else:
        result += "Z"
    return result


def _exact_instant_from_datetime(value: datetime) -> ExactInstant:
    """Convert an aware datetime to an exact UTC instant without float math."""
    if type(value) is not datetime or value.tzinfo is None:
        raise ProbeError("CONFIGURATION_INVALID")
    try:
        utc_value = value.astimezone(timezone.utc)
        delta = utc_value - _EPOCH
    except (OverflowError, ValueError):
        raise ProbeError("CONFIGURATION_INVALID") from None
    epoch_seconds = delta.days * 86_400 + delta.seconds
    epoch_ns = epoch_seconds * _NS_PER_SECOND + delta.microseconds * _NS_PER_MICROSECOND
    precision = "MICROSECOND" if delta.microseconds else "SECONDS"
    return ExactInstant(epoch_ns, precision, "Z")


@dataclass(frozen=True, slots=True, repr=False)
class ProbeRequest:
    """Operator request; repr deliberately hides organization and query."""

    organization_name: str = field(repr=False)
    start_time: ExactInstant
    end_time: ExactInstant
    query: str = field(repr=False)
    page_size: int = 100
    sort_order: str = "asc"

    def __post_init__(self) -> None:
        if type(self.organization_name) is not str or not _ORG_RE.fullmatch(self.organization_name):
            raise ProbeError("CONFIGURATION_INVALID")
        if not isinstance(self.start_time, ExactInstant) or not isinstance(self.end_time, ExactInstant):
            raise ProbeError("CONFIGURATION_INVALID")
        if type(self.query) is not str or not self.query.strip() or len(self.query) > 20_000:
            raise ProbeError("CONFIGURATION_INVALID")
        if any(ord(char) < 32 or ord(char) == 127 for char in self.query):
            raise ProbeError("CONFIGURATION_INVALID")
        if _CREDENTIAL_LIKE_RE.search(self.query):
            raise ProbeError("CONFIGURATION_INVALID")
        if type(self.page_size) is not int or not 1 <= self.page_size <= MAX_PAGE_SIZE:
            raise ProbeError("CONFIGURATION_INVALID")
        if type(self.sort_order) is not str or self.sort_order not in {"asc", "desc"}:
            raise ProbeError("CONFIGURATION_INVALID")
        duration = self.end_time.epoch_ns - self.start_time.epoch_ns
        if duration <= 0 or duration > MAX_WINDOW_NS:
            raise ProbeError("CONFIGURATION_INVALID")

    @classmethod
    def from_values(
        cls, *, organization_name: str, start_time: str, end_time: str,
        query: str, page_size: int = 100, sort_order: str = "asc",
    ) -> "ProbeRequest":
        return cls(
            organization_name=organization_name,
            start_time=parse_rfc3339(start_time),
            end_time=parse_rfc3339(end_time),
            query=query,
            page_size=page_size,
            sort_order=sort_order,
        )

    def __repr__(self) -> str:
        return "ProbeRequest(organization=[REDACTED], query=[REDACTED], timestamps=[REDACTED])"


@dataclass(frozen=True, slots=True, repr=False)
class WireRequest:
    """Fixed-route request; body/path may contain operator values and are hidden."""

    role: str
    method: str
    host: str
    port: int
    path: str = field(repr=False)
    body: bytes = field(repr=False)
    logical_start: ExactInstant
    logical_end: ExactInstant
    wire_start: ExactInstant
    wire_end: ExactInstant
    page_size: int
    sort_order: str

    def __repr__(self) -> str:
        return f"WireRequest(role={self.role!r}, method={self.method!r}, host={self.host!r}, path=[REDACTED], body=[REDACTED])"


def _wire_request(
    request: ProbeRequest, *, role: str, start: ExactInstant,
    end: ExactInstant, page_size: int,
) -> WireRequest:
    if role not in {"SINGLE_REQUEST", *_ROLE_PAGE_SIZES}:
        raise ProbeError("CONFIGURATION_INVALID")
    if type(page_size) is not int or not 1 <= page_size <= MAX_PAGE_SIZE:
        raise ProbeError("CONFIGURATION_INVALID")
    if role in _ROLE_PAGE_SIZES and page_size != _ROLE_PAGE_SIZES[role]:
        raise ProbeError("CONFIGURATION_INVALID")
    logical_duration = end.epoch_ns - start.epoch_ns
    if logical_duration <= 0 or logical_duration > MAX_WINDOW_NS:
        raise ProbeError("CONFIGURATION_INVALID")
    wire_start_ns = (start.epoch_ns // _NS_PER_MILLISECOND) * _NS_PER_MILLISECOND
    wire_end_ns = (
        (end.epoch_ns + _NS_PER_MILLISECOND - 1) // _NS_PER_MILLISECOND
    ) * _NS_PER_MILLISECOND
    if wire_start_ns >= wire_end_ns:
        raise ProbeError("CONFIGURATION_INVALID")
    wire_start = ExactInstant(wire_start_ns, "MILLISECOND", "Z")
    wire_end = ExactInstant(wire_end_ns, "MILLISECOND", "Z")
    path = f"{SALAD_ROUTE_PREFIX}{request.organization_name}/log-entries"
    payload = {
        "start_time": _format_utc_ns(wire_start_ns, millisecond_only=True),
        "end_time": _format_utc_ns(wire_end_ns, millisecond_only=True),
        "query": request.query,
        "page_size": page_size,
        "sort_order": request.sort_order,
    }
    try:
        body = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ProbeError("CONFIGURATION_INVALID") from None
    if len(body) > MAX_REQUEST_BYTES:
        raise ProbeError("CONFIGURATION_INVALID")
    return WireRequest(
        role, "POST", SALAD_HOST, SALAD_PORT, path, body,
        start, end, wire_start, wire_end, page_size, request.sort_order,
    )


def _production_split_midpoint(
    start: ExactInstant, end: ExactInstant,
) -> ExactInstant:
    """Mirror live_adapter's datetime/timedelta midpoint and second truncation.

    Production parses timestamps into Python datetimes, divides the timedelta
    by two (rounding to microseconds, ties to even), then drops the fractional
    second. Recreate those steps without floating-point timestamp math.
    """
    if (
        type(start) is not ExactInstant
        or type(end) is not ExactInstant
        or start.epoch_ns >= end.epoch_ns
    ):
        raise ProbeError("MIDPOINT_INVALID")
    try:
        start_dt = _EPOCH + timedelta(
            microseconds=start.epoch_ns // _NS_PER_MICROSECOND
        )
        end_dt = _EPOCH + timedelta(
            microseconds=end.epoch_ns // _NS_PER_MICROSECOND
        )
        midpoint_dt = (start_dt + (end_dt - start_dt) / 2).replace(microsecond=0)
        delta = midpoint_dt - _EPOCH
    except (OverflowError, ValueError):
        raise ProbeError("MIDPOINT_INVALID") from None
    midpoint_us = (
        (delta.days * 86_400 + delta.seconds) * 1_000_000
        + delta.microseconds
    )
    midpoint_ns = midpoint_us * _NS_PER_MICROSECOND
    if midpoint_ns <= start.epoch_ns or midpoint_ns >= end.epoch_ns:
        raise ProbeError("MIDPOINT_INVALID")
    return ExactInstant(midpoint_ns, "SECONDS", "Z")


@dataclass(frozen=True, slots=True, repr=False)
class ProbeHttpResponse:
    status_code: int
    body: bytes = field(repr=False)

    def __repr__(self) -> str:
        return f"ProbeHttpResponse(status_code={self.status_code}, body=[REDACTED])"


def _provider_error_classification(body: bytes) -> tuple[str | None, str | None]:
    """Return only a known Salad error code or a fixed unclassified category."""
    category = (None, "PROVIDER_ERROR_UNCLASSIFIED")
    if type(body) is not bytes or not body or len(body) > MAX_PROVIDER_ERROR_BODY_BYTES:
        return category

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def reject_nonfinite(_value: str) -> None:
        raise ValueError

    try:
        decoded = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except Exception:
        return category
    if type(decoded) is not dict:
        return category

    # The real Salad 400 sample uses the top-level RFC 7807-style `type` field.
    # Accept only the observed safe machine code; never echo arbitrary provider data.
    provider_type = decoded.get("type")
    if (
        type(provider_type) is str
        and len(provider_type) <= 32
        and provider_type.isascii()
        and provider_type in _PROVIDER_ERROR_CODES
    ):
        return provider_type, None
    return category


class OfflineSyntheticTransport:
    """In-memory exchange with no sockets, DNS, filesystem or credentials."""

    __slots__ = ("_responder", "request_count", "roles_seen", "request_budget")

    def __init__(
        self, responder: Callable[[WireRequest], ProbeHttpResponse], *,
        request_budget: int = MAX_EXPERIMENT_REQUESTS,
    ):
        if (
            not callable(responder)
            or type(request_budget) is not int
            or request_budget not in {
                MAX_EXPERIMENT_REQUESTS, MAX_SATURATED_TRACE_REQUESTS,
                MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
                MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
                MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS,
            }
        ):
            raise ProbeError("CONFIGURATION_INVALID")
        self._responder = responder
        self.request_count = 0
        self.roles_seen: list[str] = []
        self.request_budget = request_budget

    def post(self, request: WireRequest) -> ProbeHttpResponse:
        if type(request) is not WireRequest or self.request_count >= self.request_budget:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        self.request_count += 1
        self.roles_seen.append(request.role)
        try:
            response = self._responder(request)
        except ProbeError:
            raise
        except Exception:
            raise ProbeError("TRANSPORT_RESPONSE_INVALID") from None
        if type(response) is not ProbeHttpResponse or type(response.body) is not bytes:
            raise ProbeError("TRANSPORT_RESPONSE_INVALID")
        return response

    def __repr__(self) -> str:
        return f"OfflineSyntheticTransport(request_count={self.request_count}, classification='SYNTHETIC/UNVERIFIED')"


class LiveManualTransport:
    """Fixed-host, one-POST HTTPS transport, requiring two explicit live gates."""

    __slots__ = (
        "_capability", "_secret_provider", "request_count", "_material",
        "request_budget",
    )

    def __init__(
        self, *, capability: Any, secret_provider: Any,
        request_budget: int = MAX_EXPERIMENT_REQUESTS,
    ):
        if (
            type(request_budget) is not int
            or request_budget not in {
                MAX_EXPERIMENT_REQUESTS, MAX_SATURATED_TRACE_REQUESTS,
                MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
                MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
                MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS,
            }
        ):
            raise ProbeError("CONFIGURATION_INVALID")
        try:
            from log_alerts.live_capability import LiveRuntimeCapability
        except Exception:
            raise ProbeError("LIVE_AUTHORIZATION_REQUIRED") from None
        try:
            from log_alerts.live_transport import secret_boundary_types
        except Exception:
            raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID") from None

        try:
            interactive_provider, _, _ = secret_boundary_types()
        except Exception:
            raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID") from None
        if (
            type(capability) is not LiveRuntimeCapability
            or capability.mode != "probe"
            or capability.allows_salad_read is not True
        ):
            raise ProbeError("LIVE_AUTHORIZATION_REQUIRED")
        if type(secret_provider) is not interactive_provider:
            raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID")
        self._capability = capability
        self._secret_provider = secret_provider
        self.request_count = 0
        self._material: Any = None
        self.request_budget = request_budget

    def post(self, request: WireRequest) -> ProbeHttpResponse:
        try:
            from log_alerts.live_transport import secret_boundary_types
        except Exception:
            raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID") from None
        try:
            from log_alerts.live_capability import capability_allows
        except Exception:
            raise ProbeError("LIVE_AUTHORIZATION_REQUIRED") from None

        valid_route = False
        if type(request) is WireRequest and request.path.startswith(SALAD_ROUTE_PREFIX):
            suffix = request.path[len(SALAD_ROUTE_PREFIX):]
            route_marker = "/log-entries"
            if suffix.endswith(route_marker):
                organization_name = suffix[:-len(route_marker)]
                valid_route = (
                    bool(_ORG_RE.fullmatch(organization_name))
                    and request.path == f"{SALAD_ROUTE_PREFIX}{organization_name}/log-entries"
                )
        valid_body = False
        if type(request) is WireRequest and type(request.body) is bytes:
            try:
                payload = json.loads(request.body.decode("utf-8"))
                valid_body = (
                    type(payload) is dict
                    and set(payload) == {"start_time", "end_time", "query", "page_size", "sort_order"}
                    and payload["start_time"] == _format_utc_ns(request.wire_start.epoch_ns, millisecond_only=True)
                    and payload["end_time"] == _format_utc_ns(request.wire_end.epoch_ns, millisecond_only=True)
                    and type(payload["query"]) is str
                    and payload["query"].strip()
                    and len(payload["query"]) <= 20_000
                    and not any(
                        ord(char) < 32 or ord(char) == 127
                        for char in payload["query"]
                    )
                    and type(payload["page_size"]) is int
                    and type(payload["sort_order"]) is str
                    and payload["page_size"] == request.page_size
                    and payload["sort_order"] == request.sort_order
                    and type(request.page_size) is int
                    and 1 <= request.page_size <= MAX_PAGE_SIZE
                    and (
                        request.role == "SINGLE_REQUEST"
                        or _ROLE_PAGE_SIZES.get(request.role) == request.page_size
                    )
                    and request.sort_order in {"asc", "desc"}
                    and not _CREDENTIAL_LIKE_RE.search(payload["query"])
                    and len(request.body) <= MAX_REQUEST_BYTES
                    and request.body == json.dumps(
                        payload, ensure_ascii=False, sort_keys=True,
                        separators=(",", ":"), allow_nan=False,
                    ).encode("utf-8")
                )
            except Exception:
                valid_body = False
        if (
            type(request) is not WireRequest
            or request.method != "POST"
            or request.host != SALAD_HOST
            or request.port != SALAD_PORT
            or not valid_route
            or not valid_body
            or capability_allows(self._capability, "salad_read") is not True
        ):
            raise ProbeError("LIVE_AUTHORIZATION_REQUIRED")
        if self.request_count >= self.request_budget:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        self.request_count += 1
        if not sys.stdin.isatty():
            raise ProbeError("INTERACTIVE_TTY_REQUIRED")
        try:
            interactive_provider, _, secret_material = secret_boundary_types()
        except Exception:
            raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID") from None
        if type(self._secret_provider) is not interactive_provider:
            raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID")
        if self._material is None:
            try:
                reads_before = self._secret_provider.read_count
            except Exception:
                raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID") from None
            if type(reads_before) is not int or reads_before < 0:
                raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID")
            try:
                self._material = self._secret_provider.acquire()
            except Exception:
                # The approved provider increments read_count only after hidden
                # TTY input returns. A changed count means input reached
                # SecretMaterial validation; never inspect exception text or
                # input contents to distinguish the failure.
                try:
                    reads_after = self._secret_provider.read_count
                except Exception:
                    raise ProbeError("SECRET_ACQUISITION_FAILED") from None
                code = (
                    "SECRET_INPUT_EMPTY_OR_INVALID"
                    if type(reads_after) is int and reads_after == reads_before + 1
                    else "SECRET_ACQUISITION_FAILED"
                )
                raise ProbeError(code) from None
        material = self._material
        if type(material) is not secret_material:
            raise ProbeError("SECRET_MATERIAL_INVALID")
        try:
            source_label = material.source_label
        except Exception:
            raise ProbeError("SECRET_SOURCE_INVALID") from None
        if source_label != "interactive_tty_session":
            raise ProbeError("SECRET_SOURCE_INVALID")
        try:
            header_value = material._header_value()
            if type(header_value) is not str:
                raise TypeError
            secret = header_value.encode("ascii")
        except Exception:
            raise ProbeError("SECRET_HEADER_ENCODING_INVALID") from None
        if secret and (secret in request.body or secret in request.path.encode("utf-8")):
            raise ProbeError("SECRET_BOUNDARY_VIOLATION")
        connection: http.client.HTTPSConnection | None = None
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            connection = http.client.HTTPSConnection(
                SALAD_HOST, SALAD_PORT, timeout=CONNECT_TIMEOUT_SECONDS,
                context=context,
            )
            connection.connect()
            if connection.sock is not None:
                connection.sock.settimeout(READ_TIMEOUT_SECONDS)
            connection.putrequest(
                "POST", request.path, skip_host=True, skip_accept_encoding=True,
            )
            connection.putheader("Host", SALAD_HOST)
            connection.putheader("Accept", "application/json")
            connection.putheader("Accept-Encoding", "identity")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Salad-Api-Key", secret.decode("ascii"))
            connection.putheader("Content-Length", str(len(request.body)))
            connection.endheaders(request.body)
            response = connection.getresponse()
            # Redirects remain status-only. Read only a small bounded body for
            # selected provider error statuses so a known safe code can be
            # classified without exposing arbitrary response text.
            if response.status != 200:
                body = b""
                if response.status in _PROVIDER_ERROR_BODY_STATUSES:
                    try:
                        candidate = response.read(MAX_PROVIDER_ERROR_BODY_BYTES + 1)
                        if type(candidate) is bytes:
                            body = candidate
                    except Exception:
                        # Keep the HTTP status useful even when its optional
                        # diagnostic body cannot be read.
                        body = b""
                return ProbeHttpResponse(response.status, body)
            body = response.read(MAX_RESPONSE_BYTES + 1)
            return ProbeHttpResponse(response.status, body)
        except TimeoutError:
            raise ProbeError("LIVE_TIMEOUT") from None
        except ProbeError:
            raise
        except Exception:
            raise ProbeError("LIVE_TRANSPORT_FAILED") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    def __repr__(self) -> str:
        return f"LiveManualTransport(host='{SALAD_HOST}', port=443, route='READ_LOG_QUERY only', credential=[REDACTED], enabled_by_explicit_capability={self._capability.allows_salad_read})"


@dataclass(frozen=True, slots=True)
class _ParsedPage:
    page_min: ExactInstant | None
    page_max: ExactInstant | None
    items: tuple[ExactInstant, ...]
    receive_times: tuple[ExactInstant, ...]
    monotonic: bool | None


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _parse_page(body: bytes, *, page_size: int, sort_order: str) -> _ParsedPage:
    if type(body) is not bytes or len(body) > MAX_RESPONSE_BYTES:
        raise ProbeError("RESPONSE_TOO_LARGE")
    try:
        data = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ProbeError("RESPONSE_JSON_INVALID") from None
    if type(data) is not dict:
        raise ProbeError("RESPONSE_SCHEMA_INVALID")
    if _PAGINATION_KEYS.intersection(data):
        raise ProbeError("PAGINATION_METADATA_UNSUPPORTED")
    items = data.get("items")
    if type(items) is not list:
        raise ProbeError("RESPONSE_SCHEMA_INVALID")
    if len(items) > page_size:
        raise ProbeError("PAGE_SIZE_EXCEEDED")

    min_value = data.get("page_min_time")
    max_value = data.get("page_max_time")
    if items and (not isinstance(min_value, str) or not isinstance(max_value, str)):
        raise ProbeError("PAGE_BOUNDS_MISSING")
    if (min_value is None) != (max_value is None):
        raise ProbeError("PAGE_BOUNDS_INVALID")
    page_min: ExactInstant | None = None
    page_max: ExactInstant | None = None
    if min_value is not None:
        try:
            page_min = parse_rfc3339(min_value)
            page_max = parse_rfc3339(max_value)
        except ProbeError:
            raise ProbeError("PAGE_BOUNDS_INVALID") from None
        if page_min.epoch_ns > page_max.epoch_ns:
            raise ProbeError("PAGE_BOUNDS_REVERSED")

    event_times: list[ExactInstant] = []
    receive_times: list[ExactInstant] = []
    for item in items:
        if type(item) is not dict:
            raise ProbeError("RESPONSE_SCHEMA_INVALID")
        raw_time = item.get("time")
        if not isinstance(raw_time, str):
            raise ProbeError("ITEM_TIME_MISSING")
        try:
            event_times.append(parse_rfc3339(raw_time))
        except ProbeError:
            raise ProbeError("ITEM_TIME_INVALID") from None
        raw_receive_time = item.get("receive_time")
        if raw_receive_time is not None:
            if not isinstance(raw_receive_time, str):
                raise ProbeError("RECEIVE_TIME_INVALID")
            try:
                receive_times.append(parse_rfc3339(raw_receive_time))
            except ProbeError:
                raise ProbeError("RECEIVE_TIME_INVALID") from None

    monotonic: bool | None
    if len(event_times) < 2:
        monotonic = True
    elif sort_order == "asc":
        monotonic = all(
            left.epoch_ns <= right.epoch_ns
            for left, right in zip(event_times, event_times[1:])
        )
    else:
        monotonic = all(
            left.epoch_ns >= right.epoch_ns
            for left, right in zip(event_times, event_times[1:])
        )
    # Drop the decoded response object immediately. The result retains only
    # validated timestamps and fixed format classes.
    del data
    return _ParsedPage(page_min, page_max, tuple(event_times), tuple(receive_times), monotonic)


def _position(value: ExactInstant | None, boundary: ExactInstant) -> str:
    if value is None:
        return "ABSENT"
    if value.epoch_ns < boundary.epoch_ns:
        return "BEFORE"
    if value.epoch_ns > boundary.epoch_ns:
        return "AFTER"
    return "EQUAL"


def _range_relation(
    low: ExactInstant | None, high: ExactInstant | None,
    start: ExactInstant, end: ExactInstant,
) -> str:
    if low is None or high is None:
        return "ABSENT"
    if high.epoch_ns < start.epoch_ns:
        return "BEFORE_WINDOW"
    if low.epoch_ns > end.epoch_ns:
        return "AFTER_WINDOW"
    before = low.epoch_ns < start.epoch_ns
    after = high.epoch_ns > end.epoch_ns
    if before and after:
        return "SPANS_WINDOW"
    if before:
        return "EXTENDS_BEFORE"
    if after:
        return "EXTENDS_AFTER"
    return "WITHIN_WINDOW"


def _format_classes(values: tuple[ExactInstant, ...]) -> dict[str, list[str]]:
    precision_order = ("SECONDS", "MILLISECOND", "MICROSECOND", "SUBMICROSECOND")
    timezone_order = ("Z", "UTC_OFFSET", "NONUTC_OFFSET")
    precision_set = {item.precision_class for item in values}
    timezone_set = {item.timezone_class for item in values}
    return {
        "precision": [name for name in precision_order if name in precision_set],
        "timezone": [name for name in timezone_order if name in timezone_set],
    }


def _delta_summary(value: ExactInstant | None, reference: ExactInstant) -> dict[str, Any] | None:
    if value is None:
        return None
    delta_ns = value.epoch_ns - reference.epoch_ns
    magnitude = abs(delta_ns)
    whole, remainder = divmod(magnitude, _NS_PER_SECOND)
    rounded = whole + (1 if remainder * 2 >= _NS_PER_SECOND else 0)
    signed = rounded if delta_ns >= 0 else -rounded
    capped = magnitude > MAX_DELTA_SECONDS * _NS_PER_SECOND
    if capped:
        signed = MAX_DELTA_SECONDS if signed > 0 else -MAX_DELTA_SECONDS
    return {
        "seconds_rounded_nearest": signed,
        "subsecond": magnitude < _NS_PER_SECOND,
        "capped": capped,
    }


def _unique_count(values: tuple[ExactInstant, ...]) -> int:
    return len({item.epoch_ns for item in values})


def _ties_at(values: tuple[ExactInstant, ...], boundary: ExactInstant) -> int:
    return sum(item.epoch_ns == boundary.epoch_ns for item in values)


def _extreme_ties(values: tuple[ExactInstant, ...], *, low: bool) -> int:
    if not values:
        return 0
    target = min(item.epoch_ns for item in values) if low else max(item.epoch_ns for item in values)
    return sum(item.epoch_ns == target for item in values)


@dataclass(frozen=True, slots=True, repr=False)
class _Observation:
    report: Mapping[str, Any]
    page: _ParsedPage = field(repr=False)

    def __repr__(self) -> str:
        return "_Observation([SANITIZED REPORT], [TEMPORAL DATA])"


def _observation_report(
    request: WireRequest, page: _ParsedPage, *, classification: str,
    http_status: int,
) -> dict[str, Any]:
    item_values = page.items
    receive_values = page.receive_times
    item_min = min(item_values, key=lambda item: item.epoch_ns) if item_values else None
    item_max = max(item_values, key=lambda item: item.epoch_ns) if item_values else None
    logical_start = request.logical_start
    logical_end = request.logical_end
    wire_start = request.wire_start
    wire_end = request.wire_end
    page_min, page_max = page.page_min, page.page_max
    receive_min = min(receive_values, key=lambda item: item.epoch_ns) if receive_values else None
    receive_max = max(receive_values, key=lambda item: item.epoch_ns) if receive_values else None
    return {
        "classification": classification,
        "request_role": request.role,
        "logical_window_utc": {
            "start": _format_utc_ns(logical_start.epoch_ns),
            "end": _format_utc_ns(logical_end.epoch_ns),
        },
        "wire_window_utc": {
            "start": _format_utc_ns(wire_start.epoch_ns, millisecond_only=True),
            "end": _format_utc_ns(wire_end.epoch_ns, millisecond_only=True),
        },
        "requested_page_size": request.page_size,
        "sort_order": request.sort_order,
        "organization_and_query_values_emitted": False,
        "http_status": http_status,
        "item_count": len(item_values),
        "page_bounds_present": page_min is not None and page_max is not None,
        "page_bounds_vs_wire_window": _range_relation(page_min, page_max, wire_start, wire_end),
        "page_min_vs_wire_start": _position(page_min, wire_start),
        "page_max_vs_wire_end": _position(page_max, wire_end),
        "page_bounds_vs_logical_window": _range_relation(page_min, page_max, logical_start, logical_end),
        "page_min_vs_logical_start": _position(page_min, logical_start),
        "page_max_vs_logical_end": _position(page_max, logical_end),
        "items_vs_wire_window": _range_relation(item_min, item_max, wire_start, wire_end),
        "item_min_vs_wire_start": _position(item_min, wire_start),
        "item_max_vs_wire_end": _position(item_max, wire_end),
        "items_vs_logical_window": _range_relation(item_min, item_max, logical_start, logical_end),
        "item_min_vs_logical_start": _position(item_min, logical_start),
        "item_max_vs_logical_end": _position(item_max, logical_end),
        "receive_times_vs_wire_window": _range_relation(receive_min, receive_max, wire_start, wire_end),
        "receive_time_count": len(receive_values),
        "receive_time_distinct_count": _unique_count(receive_values),
        "receive_time_min_vs_wire_start": _position(receive_min, wire_start),
        "receive_time_max_vs_wire_end": _position(receive_max, wire_end),
        "sort_order_monotonic": page.monotonic,
        "distinct_item_timestamp_count": _unique_count(item_values),
        "item_minimum_timestamp_tie_count": _extreme_ties(item_values, low=True),
        "item_maximum_timestamp_tie_count": _extreme_ties(item_values, low=False),
        "item_wire_start_boundary_tie_count": _ties_at(item_values, wire_start),
        "item_wire_end_boundary_tie_count": _ties_at(item_values, wire_end),
        "item_logical_start_boundary_tie_count": _ties_at(item_values, logical_start),
        "item_logical_end_boundary_tie_count": _ties_at(item_values, logical_end),
        "page_min_format": (
            _format_classes((page_min,)) if page_min is not None else {"precision": [], "timezone": []}
        ),
        "page_max_format": (
            _format_classes((page_max,)) if page_max is not None else {"precision": [], "timezone": []}
        ),
        "item_time_formats": _format_classes(item_values),
        "receive_time_formats": _format_classes(receive_values),
        "bounded_deltas": {
            "page_min_to_wire_start": _delta_summary(page_min, wire_start),
            "page_max_to_wire_end": _delta_summary(page_max, wire_end),
            "page_min_to_logical_start": _delta_summary(page_min, logical_start),
            "page_max_to_logical_end": _delta_summary(page_max, logical_end),
            "item_min_to_wire_start": _delta_summary(item_min, wire_start),
            "item_max_to_wire_end": _delta_summary(item_max, wire_end),
            "item_min_to_logical_start": _delta_summary(item_min, logical_start),
            "item_max_to_logical_end": _delta_summary(item_max, logical_end),
        },
        "delta_policy": "nearest_whole_second_capped_at_86400",
    }


class ProbeRunner:
    """Single-use bounded request runner; it has no cursor or delivery state."""

    __slots__ = (
        "transport", "request_count", "response_bytes", "item_count", "_started",
        "_request_budget", "_item_budget", "_total_item_limit",
    )

    def __init__(self, transport: OfflineSyntheticTransport | LiveManualTransport):
        if type(transport) not in {OfflineSyntheticTransport, LiveManualTransport}:
            raise ProbeError("CONFIGURATION_INVALID")
        self.transport = transport
        self.request_count = 0
        self.response_bytes = 0
        self.item_count = 0
        self._started = False
        self._request_budget = transport.request_budget
        self._item_budget = self._request_budget * MAX_PAGE_SIZE
        self._total_item_limit = MAX_TOTAL_ITEMS

    def _observe(
        self, request: ProbeRequest, *, role: str, start: ExactInstant,
        end: ExactInstant, page_size: int,
    ) -> _Observation:
        if self.request_count >= self._request_budget:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        wire_request = _wire_request(
            request, role=role, start=start, end=end, page_size=page_size,
        )
        self.request_count += 1
        response = self.transport.post(wire_request)
        if type(response) is not ProbeHttpResponse:
            raise ProbeError("TRANSPORT_RESPONSE_INVALID")
        if type(response.status_code) is not int or not 100 <= response.status_code <= 599:
            raise ProbeError("TRANSPORT_RESPONSE_INVALID")
        if response.status_code != 200:
            status = response.status_code
            body = response.body if type(response.body) is bytes else b""
            if status in _PROVIDER_ERROR_BODY_STATUSES:
                provider_code, provider_category = _provider_error_classification(body)
            else:
                provider_code, provider_category = None, None
            # Do not retain the raw provider body in the raised error/traceback.
            del response, body
            raise ProbeError(
                "HTTP_STATUS_REJECTED",
                http_status=status,
                provider_error_code=provider_code,
                provider_error_category=provider_category,
            )
        if type(response.body) is not bytes or len(response.body) > MAX_RESPONSE_BYTES:
            raise ProbeError("RESPONSE_TOO_LARGE")
        self.response_bytes += len(response.body)
        if self.response_bytes > MAX_TOTAL_RESPONSE_BYTES:
            raise ProbeError("BYTE_BUDGET_EXCEEDED")
        classification = (
            "SYNTHETIC/UNVERIFIED"
            if type(self.transport) is OfflineSyntheticTransport
            else "PROVIDER_OBSERVED"
        )
        try:
            page = _parse_page(
                response.body, page_size=page_size, sort_order=request.sort_order,
            )
        finally:
            # Do not retain raw provider bytes between query pages.
            del response
        self.item_count += len(page.items)
        if self.item_count > min(self._item_budget, self._total_item_limit):
            raise ProbeError("ENTRY_BUDGET_EXCEEDED")
        report = _observation_report(
            wire_request, page, classification=classification, http_status=200,
        )
        return _Observation(report, page)

    def run_single(self, request: ProbeRequest) -> dict[str, Any]:
        if self._started:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        if type(request) is not ProbeRequest:
            raise ProbeError("CONFIGURATION_INVALID")
        self._started = True
        observation = self._observe(
            request, role="SINGLE_REQUEST", start=request.start_time,
            end=request.end_time, page_size=request.page_size,
        )
        return _result_document(
            [observation], comparisons=None, request_budget=self._request_budget,
        )

    def run_experiment(
        self, request: ProbeRequest, *, repeat_parent: bool = False,
        direct_child: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        """Run parent100/control99, optional repeat, and at most one split level."""
        if self._started:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        if type(request) is not ProbeRequest or type(repeat_parent) is not bool:
            raise ProbeError("CONFIGURATION_INVALID")
        if request.page_size != 100:
            raise ProbeError("CONFIGURATION_INVALID")
        start, end = request.start_time, request.end_time
        child_window: tuple[ExactInstant, ExactInstant] | None = None
        split_midpoint: ExactInstant | None = None
        if direct_child is not None:
            if type(direct_child) is not tuple or len(direct_child) != 2:
                raise ProbeError("DIRECT_CHILD_INVALID")
            try:
                child_start, child_end = parse_rfc3339(direct_child[0]), parse_rfc3339(direct_child[1])
            except ProbeError:
                raise ProbeError("DIRECT_CHILD_INVALID") from None
            try:
                split_midpoint = _production_split_midpoint(start, end)
            except ProbeError:
                raise ProbeError("DIRECT_CHILD_INVALID") from None
            expected_children = {
                (start.epoch_ns, split_midpoint.epoch_ns),
                (split_midpoint.epoch_ns, end.epoch_ns),
            }
            if (child_start.epoch_ns, child_end.epoch_ns) not in expected_children:
                raise ProbeError("DIRECT_CHILD_INVALID")
            child_window = (child_start, child_end)
        self._started = True
        observations: list[_Observation] = []
        parent = self._observe(
            request, role="PARENT_100", start=start, end=end, page_size=100,
        )
        observations.append(parent)
        control = self._observe(
            request, role="CONTROL_99", start=start, end=end, page_size=99,
        )
        observations.append(control)
        comparison: dict[str, Any] = {
            "parent_vs_control": {
                "parent_count": len(parent.page.items),
                "control_count": len(control.page.items),
                "count_equal": len(parent.page.items) == len(control.page.items),
                "item_min_timestamp_equal": _same_extreme(parent.page, control.page, low=True),
                "item_max_timestamp_equal": _same_extreme(parent.page, control.page, low=False),
                "page_min_position_equal": _same_position(parent.page.page_min, control.page.page_min, start),
                "page_max_position_equal": _same_position(parent.page.page_max, control.page.page_max, end),
                "timestamp_equality_proves_same_event": False,
            },
            "repeat_parent": None,
            "split_children": None,
            "direct_child": None,
        }
        if repeat_parent:
            repeated = self._observe(
                request, role="REPEAT_PARENT_100", start=start, end=end, page_size=100,
            )
            observations.append(repeated)
            comparison["repeat_parent"] = {
                "count_equal_to_first_parent": len(repeated.page.items) == len(parent.page.items),
                "item_min_timestamp_equal": _same_extreme(parent.page, repeated.page, low=True),
                "item_max_timestamp_equal": _same_extreme(parent.page, repeated.page, low=False),
                "timestamp_equality_proves_same_event": False,
            }
        if len(parent.page.items) == 100:
            if split_midpoint is None:
                split_midpoint = _production_split_midpoint(start, end)
            midpoint = split_midpoint
            left = self._observe(
                request, role="LEFT_CHILD_100", start=start, end=midpoint,
                page_size=100,
            )
            observations.append(left)
            right = self._observe(
                request, role="RIGHT_CHILD_100", start=midpoint, end=end,
                page_size=100,
            )
            observations.append(right)
            left_times = {item.epoch_ns for item in left.page.items}
            right_times = {item.epoch_ns for item in right.page.items}
            comparison["split_children"] = {
                "left_count": len(left.page.items),
                "right_count": len(right.page.items),
                "sum_of_child_counts": len(left.page.items) + len(right.page.items),
                "count_sum_equals_parent_count": (
                    len(left.page.items) + len(right.page.items) == len(parent.page.items)
                ),
                "left_items_at_split_boundary": _ties_at(left.page.items, midpoint),
                "right_items_at_split_boundary": _ties_at(right.page.items, midpoint),
                "shared_event_timestamps_between_children": len(left_times.intersection(right_times)),
                "shared_timestamp_proves_same_event": False,
            }
            comparison["split_midpoint_policy"] = "MIDPOINT_FLOORED_TO_WHOLE_SECOND_SHARED_BY_CHILDREN"
        if child_window is not None:
            child = self._observe(
                request, role="DIRECT_CHILD_100", start=child_window[0],
                end=child_window[1], page_size=100,
            )
            observations.append(child)
            comparison["direct_child"] = {
                "count": len(child.page.items),
                "parent_saturated": len(parent.page.items) == 100,
                "role": "USER_SELECTED_DIRECT_CHILD",
                "recursive_descendants_requested": False,
            }
        if self.request_count > MAX_EXPERIMENT_REQUESTS:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        return _result_document(
            observations, comparisons=comparison,
            request_budget=MAX_EXPERIMENT_REQUESTS,
        )

    def run_saturated_branch_trace(self, request: ProbeRequest) -> dict[str, Any]:
        """Follow one uniquely saturated child branch with fixed depth/budgets."""
        if self._started:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        if (
            type(request) is not ProbeRequest
            or request.page_size != MAX_PAGE_SIZE
            or request.sort_order != "asc"
            or self.transport.request_budget != MAX_SATURATED_TRACE_REQUESTS
        ):
            raise ProbeError("CONFIGURATION_INVALID")

        self._started = True
        self._request_budget = MAX_SATURATED_TRACE_REQUESTS
        self._item_budget = MAX_SATURATED_TRACE_REQUESTS * MAX_PAGE_SIZE
        observations: list[_Observation] = []
        root = self._observe(
            request, role="TRACE_PARENT_0_100", start=request.start_time,
            end=request.end_time, page_size=MAX_PAGE_SIZE,
        )
        observations.append(root)

        trace_depth = 0
        saturated_nodes_seen = 1 if len(root.page.items) == MAX_PAGE_SIZE else 0
        first_nonempty_unsaturated_depth: int | None = None
        if len(root.page.items) != MAX_PAGE_SIZE:
            stop_reason = "TRACE_STOPPED_PARENT_NOT_AT_LIMIT"
        else:
            current = root
            current_start = request.start_time
            current_end = request.end_time
            current_depth = 0
            stop_reason: str | None = None
            while len(current.page.items) == MAX_PAGE_SIZE:
                if current_depth >= MAX_SATURATED_TRACE_DEPTH:
                    stop_reason = "TRACE_STOPPED_DEPTH_LIMIT"
                    break
                if self.request_count + 2 > self._request_budget:
                    stop_reason = "TRACE_STOPPED_REQUEST_BUDGET"
                    break
                midpoint = _production_split_midpoint(current_start, current_end)
                child_depth = current_depth + 1
                left = self._observe(
                    request,
                    role=f"TRACE_DEPTH_{child_depth}_LEFT_100",
                    start=current_start, end=midpoint, page_size=MAX_PAGE_SIZE,
                )
                right = self._observe(
                    request,
                    role=f"TRACE_DEPTH_{child_depth}_RIGHT_100",
                    start=midpoint, end=current_end, page_size=MAX_PAGE_SIZE,
                )
                observations.extend((left, right))
                trace_depth = child_depth
                saturated_children = [
                    child for child in (left, right)
                    if len(child.page.items) == MAX_PAGE_SIZE
                ]
                saturated_nodes_seen += len(saturated_children)
                if first_nonempty_unsaturated_depth is None and any(
                    0 < len(child.page.items) < MAX_PAGE_SIZE
                    for child in (left, right)
                ):
                    first_nonempty_unsaturated_depth = child_depth

                if len(saturated_children) == 0:
                    stop_reason = "TRACE_STOPPED_NO_SATURATED_CHILDREN"
                    break
                if len(saturated_children) > 1:
                    stop_reason = "TRACE_STOPPED_MULTIPLE_SATURATED_CHILDREN"
                    break
                current = saturated_children[0]
                current_start, current_end = (
                    (current_start, midpoint)
                    if current is left else (midpoint, current_end)
                )
                current_depth = child_depth
                if current_depth >= MAX_SATURATED_TRACE_DEPTH:
                    stop_reason = "TRACE_STOPPED_DEPTH_LIMIT"
                    break

        if stop_reason is None:
            raise ProbeError("TRANSPORT_RESPONSE_INVALID")
        report = _result_document(
            observations, comparisons=None,
            request_budget=MAX_SATURATED_TRACE_REQUESTS,
        )
        report.update({
            "trace_depth": trace_depth,
            "trace_stop_reason": stop_reason,
            "saturated_nodes_seen": saturated_nodes_seen,
            "first_nonempty_unsaturated_depth": first_nonempty_unsaturated_depth,
        })
        return report

    def run_page_min_before_probe(self, request: ProbeRequest) -> dict[str, Any]:
        """Observe one page and, if saturated, only its two immediate children.

        This diagnostic records provider page metadata and validated item-time
        relationships without changing the production adapter's acceptance
        policy or claiming pagination completeness.
        """
        if self._started:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        if (
            type(request) is not ProbeRequest
            or request.page_size != MAX_PAGE_SIZE
            or request.sort_order != "asc"
            or self.transport.request_budget != MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS
        ):
            raise ProbeError("CONFIGURATION_INVALID")

        self._started = True
        self._request_budget = MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS
        self._item_budget = MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS * MAX_PAGE_SIZE
        self._total_item_limit = self._item_budget
        observations: list[_Observation] = []
        parent = self._observe(
            request, role="PAGE_MIN_PROBE_PARENT_100",
            start=request.start_time, end=request.end_time,
            page_size=MAX_PAGE_SIZE,
        )
        observations.append(parent)

        parent_saturated = len(parent.page.items) == MAX_PAGE_SIZE
        if parent_saturated:
            midpoint = _production_split_midpoint(
                request.start_time, request.end_time,
            )
            left = self._observe(
                request, role="PAGE_MIN_PROBE_LEFT_100",
                start=request.start_time, end=midpoint,
                page_size=MAX_PAGE_SIZE,
            )
            right = self._observe(
                request, role="PAGE_MIN_PROBE_RIGHT_100",
                start=midpoint, end=request.end_time,
                page_size=MAX_PAGE_SIZE,
            )
            observations.extend((left, right))

        signature_roles = [
            str(observation.report["request_role"])
            for observation in observations
            if observation.report["item_count"] == MAX_PAGE_SIZE
            and (
                observation.report["page_min_vs_logical_start"] == "BEFORE"
                or observation.report["page_min_vs_wire_start"] == "BEFORE"
            )
        ]
        report = _result_document(
            observations, comparisons=None,
            request_budget=MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
        )
        report.update({
            "trace_depth": 1 if parent_saturated else 0,
            "trace_stop_reason": (
                "TRACE_STOPPED_ONE_LEVEL_CHILDREN_OBSERVED"
                if parent_saturated else "TRACE_STOPPED_PARENT_NOT_AT_LIMIT"
            ),
            "page_min_before_slice_signature_observed": bool(signature_roles),
            "page_min_before_slice_signature_roles": signature_roles,
            "saturated_page_count": sum(
                1 for observation in observations
                if observation.report["item_count"] == MAX_PAGE_SIZE
            ),
            "nonempty_unsaturated_page_count": sum(
                1 for observation in observations
                if 0 < observation.report["item_count"] < MAX_PAGE_SIZE
            ),
            "recursive_descendants_requested": False,
        })
        return report

    def run_page_min_before_capture(
        self, request: ProbeRequest, *,
        utc_now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
        wait: Callable[[float], None] | None = None,
    ) -> dict[str, Any]:
        """Repeatedly observe a rolling 135-second window with hard bounds.

        Each attempt observes the parent and, only when saturated and no target
        signature has appeared, its two immediate children. The first matching
        page stops requests immediately. No provider semantics are inferred.
        Clock and wait functions are injectable so tests never sleep or use
        wall-clock timing.
        """
        request_budget = self.transport.request_budget
        if (
            self._started
            or type(request) is not ProbeRequest
            or request.page_size != MAX_PAGE_SIZE
            or request.sort_order != "asc"
            or type(request_budget) is not int
            or not 1 <= request_budget <= MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS
            or (utc_now is not None and not callable(utc_now))
            or (monotonic is not None and not callable(monotonic))
            or (wait is not None and not callable(wait))
        ):
            raise ProbeError("CONFIGURATION_INVALID")

        clock = utc_now or (lambda: datetime.now(timezone.utc))
        monotonic_clock = monotonic or time.monotonic
        wait_fn = wait or time.sleep

        def read_monotonic() -> float:
            try:
                value = monotonic_clock()
            except Exception:
                raise ProbeError("CONFIGURATION_INVALID") from None
            if (
                type(value) not in {int, float}
                or not math.isfinite(value)
            ):
                raise ProbeError("CONFIGURATION_INVALID")
            return float(value)

        try:
            schedule_started = read_monotonic()
        except ProbeError:
            raise

        self._started = True
        self._request_budget = request_budget
        self._item_budget = request_budget * MAX_PAGE_SIZE
        self._total_item_limit = request_budget * MAX_PAGE_SIZE

        attempts: list[dict[str, Any]] = []
        attempts_completed = 0
        signature_attempt: int | None = None
        signature_role: str | None = None
        signature_details: dict[str, Any] | None = None
        stop_reason: str | None = None
        next_due = schedule_started + PAGE_MIN_BEFORE_CAPTURE_CADENCE_SECONDS

        def page_class(item_count: int) -> str:
            if item_count == 0:
                return "EMPTY"
            if item_count == MAX_PAGE_SIZE:
                return "NONEMPTY_SATURATED"
            return "NONEMPTY_UNSATURATED"

        def matches_signature(report: Mapping[str, Any]) -> bool:
            return (
                report.get("page_min_vs_logical_start") == "BEFORE"
                or report.get("page_min_vs_wire_start") == "BEFORE"
            )

        detail_fields = (
            "item_count", "page_class", "page_min_vs_logical_start",
            "page_min_vs_wire_start", "items_vs_logical_window",
            "items_vs_wire_window", "item_min_vs_logical_start",
            "item_min_vs_wire_start", "receive_times_vs_wire_window",
        )

        for attempt_number in range(1, MAX_PAGE_MIN_BEFORE_CAPTURE_ATTEMPTS + 1):
            # A saturated parent may need three requests. Do not begin an
            # observation that cannot finish its bounded one-level sample.
            if request_budget - self.request_count < 3:
                stop_reason = "REQUEST_BUDGET"
                break

            try:
                window_end = _exact_instant_from_datetime(clock())
                window_start = ExactInstant(
                    window_end.epoch_ns
                    - PAGE_MIN_BEFORE_CAPTURE_WINDOW_SECONDS * _NS_PER_SECOND,
                    window_end.precision_class,
                    "Z",
                )
                attempt_request = ProbeRequest(
                    organization_name=request.organization_name,
                    start_time=window_start,
                    end_time=window_end,
                    query=request.query,
                    page_size=MAX_PAGE_SIZE,
                    sort_order="asc",
                )
            except ProbeError:
                raise
            except Exception:
                raise ProbeError("CONFIGURATION_INVALID") from None

            attempt_observations: list[_Observation] = []
            midpoint = _production_split_midpoint(window_start, window_end)
            first_match: _Observation | None = None

            def observe_page(
                role: str, start: ExactInstant, end: ExactInstant,
            ) -> _Observation:
                nonlocal first_match
                observation = self._observe(
                    attempt_request, role=role, start=start, end=end,
                    page_size=MAX_PAGE_SIZE,
                )
                attempt_observations.append(observation)
                if first_match is None and matches_signature(observation.report):
                    first_match = observation
                return observation

            parent = observe_page(
                "PAGE_MIN_PROBE_PARENT_100", window_start, window_end,
            )
            if first_match is None and len(parent.page.items) == MAX_PAGE_SIZE:
                observe_page(
                    "PAGE_MIN_PROBE_LEFT_100", window_start, midpoint,
                )
                if first_match is None:
                    observe_page(
                        "PAGE_MIN_PROBE_RIGHT_100", midpoint, window_end,
                    )

            page_reports: list[dict[str, Any]] = []
            for observation in attempt_observations:
                page_report = dict(observation.report)
                page_report["page_class"] = page_class(
                    int(page_report["item_count"]),
                )
                page_reports.append(page_report)

            attempts.append({
                "attempt_number": attempt_number,
                "window_seconds": PAGE_MIN_BEFORE_CAPTURE_WINDOW_SECONDS,
                "request_count": len(attempt_observations),
                "pages": page_reports,
            })
            attempts_completed += 1

            if first_match is not None:
                matched = dict(first_match.report)
                signature_attempt = attempt_number
                signature_role = str(matched["request_role"])
                details = dict(matched)
                details["page_class"] = page_class(int(details["item_count"]))
                signature_details = {
                    field_name: details.get(field_name)
                    for field_name in detail_fields
                }
                stop_reason = "SIGNATURE"
                break

            if attempt_number == MAX_PAGE_MIN_BEFORE_CAPTURE_ATTEMPTS:
                stop_reason = "MAX_ATTEMPTS"
                break
            if request_budget - self.request_count < 3:
                stop_reason = "REQUEST_BUDGET"
                break

            current_mono = read_monotonic()
            if current_mono < next_due:
                delay = next_due - current_mono
                try:
                    wait_fn(delay)
                except Exception:
                    raise ProbeError("CONFIGURATION_INVALID") from None
                next_due += PAGE_MIN_BEFORE_CAPTURE_CADENCE_SECONDS
            else:
                # One late attempt may start immediately; re-anchor afterward
                # so missed ticks never trigger a catch-up burst.
                next_due = current_mono + PAGE_MIN_BEFORE_CAPTURE_CADENCE_SECONDS

        if stop_reason is None:
            stop_reason = "REQUEST_BUDGET"

        classification = (
            "SYNTHETIC/UNVERIFIED"
            if type(self.transport) is OfflineSyntheticTransport
            else "PROVIDER_OBSERVED"
        )
        return {
            "schema_version": 1,
            "status": "OBSERVATION_COMPLETED" if attempts_completed else "CAPTURE_NOT_STARTED",
            "operation": "page-min-before-capture",
            "classification": classification,
            "production_cause": "PRODUCTION_CAUSE_UNKNOWN",
            "provider_semantics": "UNKNOWN",
            "pagination_completeness": "UNKNOWN",
            "capture_attempts_completed": attempts_completed,
            "capture_signature_observed": signature_attempt is not None,
            "capture_signature_attempt": signature_attempt,
            "capture_signature_role": signature_role,
            "capture_signature_details": signature_details,
            "capture_stop_reason": stop_reason,
            "total_request_count": self.request_count,
            "request_budget": request_budget,
            "attempts": attempts,
            "count_at_limit_proves_truncation": False,
            "count_below_limit_proves_completeness": False,
            "synthetic_response_proves_provider_contract": False,
            "durable_cursor_written": False,
            "alert_or_delivery_state_written": False,
        }

    def run_production_recursion_trace(self, request: ProbeRequest) -> dict[str, Any]:
        """Mirror production's bounded left-first, depth-first page subdivision."""
        if self._started:
            raise ProbeError("REQUEST_BUDGET_EXCEEDED")
        if (
            type(request) is not ProbeRequest
            or request.page_size != MAX_PAGE_SIZE
            or request.sort_order != "asc"
            or self.transport.request_budget
            != MAX_PRODUCTION_RECURSION_TRACE_REQUESTS
        ):
            raise ProbeError("CONFIGURATION_INVALID")

        self._started = True
        self._request_budget = MAX_PRODUCTION_RECURSION_TRACE_REQUESTS
        self._item_budget = MAX_PRODUCTION_RECURSION_TRACE_ITEMS
        self._total_item_limit = MAX_PRODUCTION_RECURSION_TRACE_ITEMS
        observations: list[_Observation] = []
        counters = {
            "visited_node_count": 0,
            "saturated_node_count": 0,
            "nonempty_unsaturated_node_count": 0,
            "deepest_depth_seen": 0,
        }
        target_signature: dict[str, Any] = {
            "target_signature_observed": False,
            "target_signature_depth": None,
            "target_signature_role": None,
        }
        stop_state: dict[str, str | None] = {"reason": None}

        def visit(
            start: ExactInstant, end: ExactInstant, depth: int, node_number: int,
        ) -> None:
            if stop_state["reason"] is not None:
                return
            if self.request_count >= self._request_budget:
                stop_state["reason"] = "TRACE_STOPPED_REQUEST_BUDGET"
                return

            role = f"PRODUCTION_TRACE_D{depth}_N{node_number}_100"
            observation = self._observe(
                request, role=role, start=start, end=end,
                page_size=MAX_PAGE_SIZE,
            )
            observations.append(observation)
            count = len(observation.page.items)
            counters["visited_node_count"] += 1
            counters["deepest_depth_seen"] = max(
                counters["deepest_depth_seen"], depth,
            )
            if count == MAX_PAGE_SIZE:
                counters["saturated_node_count"] += 1
            elif count > 0:
                counters["nonempty_unsaturated_node_count"] += 1

            report = observation.report
            page_max_after = (
                report.get("page_max_vs_logical_end") == "AFTER"
                or report.get("page_max_vs_wire_end") == "AFTER"
            )
            if (
                0 < count < MAX_PAGE_SIZE
                and page_max_after
                and report.get("items_vs_logical_window") == "WITHIN_WINDOW"
                and report.get("items_vs_wire_window") == "WITHIN_WINDOW"
            ):
                target_signature.update({
                    "target_signature_observed": True,
                    "target_signature_depth": depth,
                    "target_signature_role": role,
                })
                stop_state["reason"] = "TRACE_STOPPED_TARGET_SIGNATURE"
                return

            if count != MAX_PAGE_SIZE:
                return
            if depth >= MAX_PRODUCTION_RECURSION_TRACE_DEPTH:
                stop_state["reason"] = "TRACE_STOPPED_DEPTH_LIMIT"
                return

            midpoint = _production_split_midpoint(start, end)
            child_depth = depth + 1
            visit(start, midpoint, child_depth, node_number * 2)
            visit(midpoint, end, child_depth, node_number * 2 + 1)

        visit(request.start_time, request.end_time, 0, 1)
        stop_reason = stop_state["reason"]
        if stop_reason is None:
            stop_reason = "TRACE_STOPPED_TRAVERSAL_COMPLETE"
        report = _result_document(
            observations, comparisons=None,
            request_budget=MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
        )
        report.update(counters)
        report.update(target_signature)
        report["trace_stop_reason"] = stop_reason
        return report


def _same_extreme(left: _ParsedPage, right: _ParsedPage, *, low: bool) -> bool | None:
    if not left.items or not right.items:
        return None
    left_value = min(x.epoch_ns for x in left.items) if low else max(x.epoch_ns for x in left.items)
    right_value = min(x.epoch_ns for x in right.items) if low else max(x.epoch_ns for x in right.items)
    return left_value == right_value


def _same_position(
    left: ExactInstant | None, right: ExactInstant | None, boundary: ExactInstant,
) -> bool | None:
    if left is None or right is None:
        return None
    return _position(left, boundary) == _position(right, boundary)


def _result_document(
    observations: list[_Observation], *, comparisons: Mapping[str, Any] | None,
    request_budget: int = MAX_EXPERIMENT_REQUESTS,
) -> dict[str, Any]:
    classifications = {item.report["classification"] for item in observations}
    if len(classifications) != 1:
        raise ProbeError("TRANSPORT_RESPONSE_INVALID")
    interpretations: set[str] = {
        "TEMPORAL_RELATION_OBSERVED",
        "PAGINATION_COMPLETENESS_UNKNOWN",
        "PROVIDER_SEMANTICS_UNKNOWN",
    }
    for observation in observations:
        if observation.report["item_count"] == observation.report["requested_page_size"]:
            interpretations.add("OBSERVED_COUNT_AT_LIMIT")
        else:
            interpretations.add("OBSERVED_COUNT_BELOW_LIMIT")
    return {
        "schema_version": 1,
        "status": "OBSERVATION_COMPLETED",
        "classification": next(iter(classifications)),
        "production_cause": "PRODUCTION_CAUSE_UNKNOWN",
        "provider_semantics": "UNKNOWN",
        "pagination_completeness": "UNKNOWN",
        "request_count": len(observations),
        "request_budget": request_budget,
        "requests": [dict(item.report) for item in observations],
        "comparisons": dict(comparisons) if comparisons is not None else None,
        "interpretations": sorted(interpretations),
        "count_at_limit_proves_truncation": False,
        "count_below_limit_proves_completeness": False,
        "child_count_sum_proves_completeness": False,
        "observed_order_proves_provider_order_contract": False,
        "synthetic_response_proves_provider_contract": False,
        "durable_cursor_written": False,
        "alert_or_delivery_state_written": False,
    }


def authorize_live_probe(*, enabled: bool, confirmation: str | None) -> Any:
    """Return the existing exact one-invocation probe capability or fail closed."""
    if enabled is not True:
        raise ProbeError("LIVE_AUTHORIZATION_REQUIRED")
    try:
        from log_alerts.live_capability import authorize_live_invocation
        return authorize_live_invocation(
            mode="probe", enable_live_read=True,
            enable_central_telegram=False, confirmation=confirmation,
        )
    except Exception:
        raise ProbeError("LIVE_AUTHORIZATION_REQUIRED") from None


def load_interactive_secret_provider() -> Any:
    """Create the already-approved hidden-TTY provider without reading it."""
    try:
        from log_alerts.live_transport import secret_boundary_types
        provider_type, _, _ = secret_boundary_types()
    except Exception:
        raise ProbeError("SECRET_PROVIDER_IDENTITY_INVALID") from None
    try:
        return provider_type(enabled=True)
    except Exception:
        raise ProbeError("SECRET_ACQUISITION_FAILED") from None


def make_synthetic_saturated_responder() -> Callable[[WireRequest], ProbeHttpResponse]:
    """Create a deterministic fixture with 100 samples and non-extremal bounds."""
    root_window: tuple[int, int] | None = None

    def respond(request: WireRequest) -> ProbeHttpResponse:
        nonlocal root_window
        try:
            payload = json.loads(request.body.decode("utf-8"))
            request_start = parse_rfc3339(payload["start_time"]).epoch_ns
            request_end = parse_rfc3339(payload["end_time"]).epoch_ns
            if root_window is None:
                root_window = (request_start, request_end)
            root_start, root_end = root_window
            total = 100
            span = root_end - root_start
            timeline = tuple(
                root_start + (span * index // (total - 1))
                for index in range(total)
            )
            selected = [
                timestamp for timestamp in timeline
                if request_start <= timestamp <= request_end
            ][:payload["page_size"]]
            entries = []
            for timestamp in selected:
                time_value = _format_utc_ns(timestamp)
                receive_value = _format_utc_ns(timestamp + 5_000_000)
                entries.append({
                    "time": time_value,
                    "receive_time": receive_value,
                    "text_log": "SYNTHETIC_PRIVATE_LOG_MARKER",
                    "json_log": {"synthetic_private": "SYNTHETIC_PRIVATE_JSON_MARKER"},
                    "resource": {"labels": {
                        "machine_id": "SYNTHETIC_PRIVATE_MACHINE_ID",
                        "instance_id": "SYNTHETIC_PRIVATE_INSTANCE_ID",
                    }},
                })
            body: dict[str, Any] = {"items": entries}
            if selected:
                body["page_min_time"] = _format_utc_ns(request_start - 2 * _NS_PER_SECOND)
                body["page_max_time"] = _format_utc_ns(request_end + 3 * _NS_PER_SECOND)
            encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            return ProbeHttpResponse(200, encoded)
        except ProbeError:
            raise
        except Exception:
            raise ProbeError("TRANSPORT_RESPONSE_INVALID") from None
    return respond
