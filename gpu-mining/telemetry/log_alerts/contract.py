"""Offline fixtures and the exact disabled Salad organization-log contract.

The official API reference documents the exact POST operation and page-size
ceiling. Query-language, provider-label, and full pagination semantics remain
UNKNOWN. HTTP is implemented separately and hard-disabled by default.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
import copy
import re


READ_LOG_QUERY = "READ_LOG_QUERY"
DENIED = "DENIED"
DATA_CLASSIFICATION = "SYNTHETIC/UNVERIFIED"
PROVIDER_OBSERVED = "PROVIDER_OBSERVED"
CONTRACT_STATUS = "PARTIALLY_VERIFIED"
SALAD_HOST = "api.salad.com"
SALAD_PORT = 443
MAX_LOCAL_PAGE_SIZE = 100
MAX_LOCAL_PAGE_TOKEN_LENGTH = 256
_ORG_RE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
_SECRET_QUERY_RE = re.compile(
    r"(?i)(?:salad[ _-]*api[ _-]*key|bearer\s+\S{8,}|(?:token|password|secret|api[_-]?key)\s*[:=])"
)


class QueryPolicyError(ValueError):
    """The request does not match the one closed log-query policy."""


class LiveQueryPolicyError(QueryPolicyError):
    """The request does not match the one disabled-by-default live route."""


class IncompleteFixtureQuery(RuntimeError):
    """The offline fixture cannot prove that all expected pages were read."""


def canonical_utc(value: str | datetime) -> str:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise QueryPolicyError("timestamp is invalid") from exc
    else:
        raise QueryPolicyError("timestamp must be ISO-8601")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise QueryPolicyError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ReadLogQueryRequest:
    organization_name: str
    method: str
    host: str
    port: int
    path: str
    operation: str
    start_time_utc: str
    end_time_utc: str
    page_size: int
    page_token: str | None
    real_network_enabled: bool = False


@dataclass(frozen=True, slots=True)
class QueryLimits:
    """Finite local fixture limits; these are not Salad provider limits."""

    page_size: int = 100
    maximum_pages: int = 20
    maximum_entries: int = 2_000
    maximum_response_bytes: int = 2_000_000
    maximum_window_seconds: int = 3_600
    overlap_seconds: int = 120
    correlation_seconds: int = 60

    def __post_init__(self) -> None:
        positive_ints = (
            self.page_size,
            self.maximum_pages,
            self.maximum_entries,
            self.maximum_response_bytes,
            self.maximum_window_seconds,
        )
        if any(type(value) is not int or value <= 0 for value in positive_ints):
            raise ValueError("local query limits must be positive integers")
        if self.page_size > MAX_LOCAL_PAGE_SIZE:
            raise ValueError("fixture page size exceeds the local cap")
        if self.maximum_pages > 100 or self.maximum_entries > 10_000:
            raise ValueError("local query page or entry limits exceed the hard cap")
        if self.maximum_response_bytes > 20_000_000 or self.maximum_window_seconds > 86_400:
            raise ValueError("local query byte or time window exceeds the hard cap")
        if type(self.overlap_seconds) is not int or self.overlap_seconds < 0:
            raise ValueError("overlap must be a non-negative integer")
        if self.overlap_seconds >= self.maximum_window_seconds:
            raise ValueError("overlap must be shorter than the query window")
        if type(self.correlation_seconds) is not int or not 0 <= self.correlation_seconds <= 300:
            raise ValueError("correlation window is outside the local bound")


class FixturePage(Protocol):
    entries: Sequence[Mapping[str, Any]]
    next_page_token: str | None
    data_classification: str


@dataclass(frozen=True, slots=True)
class LogQueryPage:
    entries: tuple[Mapping[str, Any], ...]
    next_page_token: str | None = None
    data_classification: str = DATA_CLASSIFICATION

    def __post_init__(self) -> None:
        if self.data_classification != DATA_CLASSIFICATION:
            raise ValueError("fixture page must be marked SYNTHETIC/UNVERIFIED")
        if not isinstance(self.entries, tuple):
            raise ValueError("fixture entries must be an immutable tuple")
        if self.next_page_token is not None and (
            not isinstance(self.next_page_token, str)
            or not self.next_page_token
            or len(self.next_page_token) > MAX_LOCAL_PAGE_TOKEN_LENGTH
        ):
            raise ValueError("fixture page token is invalid")


@dataclass(frozen=True, slots=True)
class LogQueryPolicy:
    """Exact route classifier. It intentionally has no HTTP client."""

    approved_organization: str

    def __post_init__(self) -> None:
        if not isinstance(self.approved_organization, str) or not _ORG_RE.fullmatch(
            self.approved_organization
        ):
            raise ValueError("approved organization name is invalid")

    @property
    def path(self) -> str:
        return f"/organizations/{self.approved_organization}/log-entries"

    def build_request(
        self,
        *,
        start_time_utc: str | datetime,
        end_time_utc: str | datetime,
        page_size: int,
        page_token: str | None = None,
    ) -> ReadLogQueryRequest:
        start = canonical_utc(start_time_utc)
        end = canonical_utc(end_time_utc)
        if datetime.fromisoformat(start.replace("Z", "+00:00")) >= datetime.fromisoformat(
            end.replace("Z", "+00:00")
        ):
            raise QueryPolicyError("query window must have positive duration")
        if type(page_size) is not int or not 1 <= page_size <= MAX_LOCAL_PAGE_SIZE:
            raise QueryPolicyError("page size exceeds the local fixture cap")
        if page_token is not None and (
            not isinstance(page_token, str)
            or not page_token
            or len(page_token) > MAX_LOCAL_PAGE_TOKEN_LENGTH
        ):
            raise QueryPolicyError("page token is invalid")
        request = ReadLogQueryRequest(
            organization_name=self.approved_organization,
            method="POST",
            host=SALAD_HOST,
            port=SALAD_PORT,
            path=self.path,
            operation=READ_LOG_QUERY,
            start_time_utc=start,
            end_time_utc=end,
            page_size=page_size,
            page_token=page_token,
            real_network_enabled=False,
        )
        self.validate(request)
        return request

    def validate(self, request: ReadLogQueryRequest) -> ReadLogQueryRequest:
        if type(request) is not ReadLogQueryRequest:
            raise QueryPolicyError("request is not a fixed log-query request")
        expected_path = f"/organizations/{self.approved_organization}/log-entries"
        if (
            request.organization_name != self.approved_organization
            or request.method != "POST"
            or request.host != SALAD_HOST
            or request.port != SALAD_PORT
            or request.path != expected_path
            or request.operation != READ_LOG_QUERY
            or request.real_network_enabled is not False
        ):
            raise QueryPolicyError("request is outside the exact offline log-query policy")
        if type(request.page_size) is not int or request.page_size < 1 or request.page_size > MAX_LOCAL_PAGE_SIZE:
            raise QueryPolicyError("page size exceeds the local fixture cap")
        if request.page_token is not None and (
            not isinstance(request.page_token, str)
            or not request.page_token
            or len(request.page_token) > MAX_LOCAL_PAGE_TOKEN_LENGTH
        ):
            raise QueryPolicyError("page token is invalid")
        if request.start_time_utc != canonical_utc(request.start_time_utc) or (
            request.end_time_utc != canonical_utc(request.end_time_utc)
        ):
            raise QueryPolicyError("query timestamps are not canonical UTC")
        if datetime.fromisoformat(request.start_time_utc.replace("Z", "+00:00")) >= datetime.fromisoformat(
            request.end_time_utc.replace("Z", "+00:00")
        ):
            raise QueryPolicyError("query window must have positive duration")
        return request

    def classify(self, *, method: str, host: str, port: int, path: str) -> str:
        return (
            READ_LOG_QUERY
            if (method, host, port, path)
            == ("POST", SALAD_HOST, SALAD_PORT, self.path)
            else DENIED
        )


@dataclass(frozen=True, slots=True)
class LiveReadLogQueryRequest:
    """Typed request for the one Salad organization log-query operation.

    This represents READ_LOG_QUERY only. It is deliberately distinct from the
    offline fixture request and does not carry credentials or a network-enable
    switch.
    """

    organization_name: str
    method: str
    host: str
    port: int
    path: str
    operation: str
    start_time_utc: str
    end_time_utc: str
    query: str
    page_size: int = 100
    sort_order: str = "asc"


class LiveLogQueryPolicy:
    """Exact classifier/builder for POST /organizations/{org}/log-entries."""

    def __init__(self, approved_organization: str):
        if not isinstance(approved_organization, str) or not _ORG_RE.fullmatch(approved_organization):
            raise LiveQueryPolicyError("approved organization name is invalid")
        self.approved_organization = approved_organization

    @property
    def path(self) -> str:
        return f"/api/public/organizations/{self.approved_organization}/log-entries"

    def build_request(
        self,
        *,
        start_time_utc: str | datetime,
        end_time_utc: str | datetime,
        query: str,
        page_size: int = MAX_LOCAL_PAGE_SIZE,
        sort_order: str = "asc",
    ) -> LiveReadLogQueryRequest:
        start = canonical_utc(start_time_utc)
        end = canonical_utc(end_time_utc)
        if datetime.fromisoformat(start.replace("Z", "+00:00")) >= datetime.fromisoformat(end.replace("Z", "+00:00")):
            raise LiveQueryPolicyError("query window must have positive duration")
        if not isinstance(query, str) or not query.strip() or len(query) > 20_000:
            raise LiveQueryPolicyError("an explicit bounded query is required")
        if any(ord(char) < 32 or ord(char) == 127 for char in query) or _SECRET_QUERY_RE.search(query):
            raise LiveQueryPolicyError("query contains a control character")
        if type(page_size) is not int or not 1 <= page_size <= MAX_LOCAL_PAGE_SIZE:
            raise LiveQueryPolicyError("page size exceeds the local cap")
        if sort_order != "asc":
            raise LiveQueryPolicyError("only ascending query order is allowed")
        request = LiveReadLogQueryRequest(
            organization_name=self.approved_organization,
            method="POST",
            host=SALAD_HOST,
            port=SALAD_PORT,
            path=self.path,
            operation=READ_LOG_QUERY,
            start_time_utc=start,
            end_time_utc=end,
            query=query,
            page_size=page_size,
            sort_order="asc",
        )
        return self.validate(request)

    def validate(self, request: LiveReadLogQueryRequest) -> LiveReadLogQueryRequest:
        if type(request) is not LiveReadLogQueryRequest:
            raise LiveQueryPolicyError("request is not a fixed log-query request")
        if (
            request.organization_name != self.approved_organization
            or request.method != "POST"
            or request.host != SALAD_HOST
            or request.port != SALAD_PORT
            or request.path != self.path
            or request.operation != READ_LOG_QUERY
            or request.sort_order != "asc"
            or type(request.page_size) is not int
            or not 1 <= request.page_size <= MAX_LOCAL_PAGE_SIZE
        ):
            raise LiveQueryPolicyError("request is outside the exact Salad log-query route")
        if request.start_time_utc != canonical_utc(request.start_time_utc) or request.end_time_utc != canonical_utc(request.end_time_utc):
            raise LiveQueryPolicyError("query timestamps are not canonical UTC")
        if datetime.fromisoformat(request.start_time_utc.replace("Z", "+00:00")) >= datetime.fromisoformat(request.end_time_utc.replace("Z", "+00:00")):
            raise LiveQueryPolicyError("query window must have positive duration")
        if (
            not isinstance(request.query, str) or not request.query.strip()
            or len(request.query) > 20_000
            or any(ord(char) < 32 or ord(char) == 127 for char in request.query)
            or _SECRET_QUERY_RE.search(request.query)
        ):
            raise LiveQueryPolicyError("query is invalid")
        return request

    def classify(self, *, method: str, host: str, port: int, path: str) -> str:
        return READ_LOG_QUERY if (method, host, port, path) == (
            "POST", SALAD_HOST, SALAD_PORT, self.path
        ) else DENIED


class FixtureLogQueryTransport:
    """An in-memory transport with no DNS, sockets, credentials, or retries."""

    def __init__(
        self,
        pages: Mapping[str | None, LogQueryPage] | Sequence[LogQueryPage],
        *,
        policy: LogQueryPolicy,
    ) -> None:
        self.policy = policy
        if isinstance(pages, Mapping):
            page_map = dict(pages)
        else:
            sequence = tuple(pages)
            page_map: dict[str | None, LogQueryPage] = {}
            token: str | None = None
            for page in sequence:
                if token in page_map:
                    raise ValueError("fixture page sequence has a repeated token")
                page_map[token] = page
                token = page.next_page_token
        if None not in page_map or not page_map:
            raise ValueError("fixture must include its first page")
        if any(type(page) is not LogQueryPage for page in page_map.values()):
            raise ValueError("fixture transport accepts only LogQueryPage values")
        self._pages = copy.deepcopy(page_map)
        self.page_requests: list[ReadLogQueryRequest] = []

    @property
    def organization_query_count(self) -> int:
        return sum(request.page_token is None for request in self.page_requests)

    def fetch_page(self, request: ReadLogQueryRequest) -> LogQueryPage:
        self.policy.validate(request)
        if request.real_network_enabled is not False:
            raise QueryPolicyError("real network access is disabled")
        self.page_requests.append(request)
        try:
            return copy.deepcopy(self._pages[request.page_token])
        except KeyError as exc:
            raise IncompleteFixtureQuery("fixture page token is unavailable") from exc
