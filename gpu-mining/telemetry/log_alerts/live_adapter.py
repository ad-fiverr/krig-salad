"""Bounded organization-query adapter with fail-closed time-window splitting."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import hashlib
import re
from typing import Any

from .contract import LiveLogQueryPolicy, LiveReadLogQueryRequest, canonical_utc
from .live_transport import (
    MAX_RESPONSE_BYTES,
    PRODUCTION_NETWORK_ALLOWED,
    LiveSaladReadTransport,
    LiveTransportBlocked,
    ProviderResponseEvidence,
    SaladTransportResponse,
    secret_boundary_types,
)
from .normalize import (
    LogRecordError,
    NormalizedLogEntry,
    normalize_provider_log_entry,
    provider_organization_label_values,
)


MAX_SUBQUERIES = 64
MAX_LOG_ENTRIES = 5_000
MAX_TOTAL_RESPONSE_BYTES = 5_000_000
MAX_SPLIT_DEPTH = 16
MINIMUM_SLICE_SECONDS = 1
_SECRET_LIKE_QUERY = re.compile(
    r"(?i)(?:salad[ _-]*api[ _-]*key|bearer\s+\S{8,}|(?:token|password|secret|api[_-]?key)\s*[:=])"
)
_PAGINATION_KEYS = frozenset({"next_page_token", "page_token", "next_page", "nextPageToken"})


class LiveAdapterError(RuntimeError):
    """The response could not be proven complete and safe to process."""


@dataclass(frozen=True, slots=True)
class LiveQueryLimits:
    page_size: int = 100
    maximum_subqueries: int = MAX_SUBQUERIES
    maximum_entries: int = MAX_LOG_ENTRIES
    maximum_response_bytes: int = MAX_TOTAL_RESPONSE_BYTES
    maximum_split_depth: int = MAX_SPLIT_DEPTH
    minimum_slice_seconds: int = MINIMUM_SLICE_SECONDS
    maximum_window_seconds: int = 3_600
    overlap_seconds: int = 120
    correlation_seconds: int = 60

    def __post_init__(self) -> None:
        if type(self.page_size) is not int or not 1 <= self.page_size <= 100:
            raise ValueError("live page size must be between 1 and 100")
        if type(self.maximum_subqueries) is not int or not 1 <= self.maximum_subqueries <= MAX_SUBQUERIES:
            raise ValueError("live subquery limit exceeds its hard cap")
        if type(self.maximum_entries) is not int or not 1 <= self.maximum_entries <= MAX_LOG_ENTRIES:
            raise ValueError("live entry limit exceeds its hard cap")
        if type(self.maximum_response_bytes) is not int or not 1 <= self.maximum_response_bytes <= MAX_TOTAL_RESPONSE_BYTES:
            raise ValueError("live byte limit exceeds its hard cap")
        if type(self.maximum_split_depth) is not int or not 1 <= self.maximum_split_depth <= MAX_SPLIT_DEPTH:
            raise ValueError("live split depth exceeds its hard cap")
        if type(self.minimum_slice_seconds) is not int or not 1 <= self.minimum_slice_seconds <= 60:
            raise ValueError("live minimum slice is outside bounds")
        if type(self.maximum_window_seconds) is not int or not 1 <= self.maximum_window_seconds <= 86_400:
            raise ValueError("live query window exceeds its hard cap")
        if type(self.overlap_seconds) is not int or not 0 <= self.overlap_seconds < self.maximum_window_seconds:
            raise ValueError("live query overlap is invalid")
        if type(self.correlation_seconds) is not int or not 0 <= self.correlation_seconds <= 300:
            raise ValueError("live correlation window exceeds its hard cap")


@dataclass(frozen=True, slots=True)
class LiveQueryResult:
    query_start_utc: str
    query_end_utc: str
    subqueries_seen: int
    response_items_seen: int
    entries: tuple[NormalizedLogEntry, ...]
    data_classification: str
    response_evidence: tuple[ProviderResponseEvidence, ...] = ()
    window_completeness: str = "COMPLETE"


def _utc(value: str) -> datetime:
    return datetime.fromisoformat(canonical_utc(value).replace("Z", "+00:00"))


def _bounded_body(response: SaladTransportResponse, limits: LiveQueryLimits) -> Mapping[str, Any]:
    if type(response) is not SaladTransportResponse or response.status_code != 200:
        status = getattr(response, "status_code", None)
        if type(status) is int and 400 <= status <= 599:
            raise LiveAdapterError(f"Salad query failed with HTTP {status}")
        raise LiveAdapterError("Salad query response is not an accepted HTTP 200")
    body = response.body
    if not isinstance(body, bytes) or len(body) > min(MAX_RESPONSE_BYTES, limits.maximum_response_bytes):
        raise LiveAdapterError("Salad response exceeds the local byte limit")
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LiveAdapterError("Salad response is not bounded JSON") from None
    if not isinstance(parsed, Mapping) or _PAGINATION_KEYS.intersection(parsed):
        raise LiveAdapterError("Salad response shape or pagination semantics are unsupported")
    items = parsed.get("items")
    if not isinstance(items, list):
        raise LiveAdapterError("Salad response items are missing")
    return parsed


def _validate_page_bounds(
    data: Mapping[str, Any], raw_items: list[Any], *,
    slice_start: datetime, slice_end: datetime,
) -> tuple[datetime | None, datetime | None]:
    page_min = data.get("page_min_time")
    page_max = data.get("page_max_time")
    if raw_items:
        if not isinstance(page_min, str) or not isinstance(page_max, str):
            raise LiveAdapterError("Salad page time bounds are missing")
        try:
            parsed_min, parsed_max = _utc(page_min), _utc(page_max)
        except Exception:
            raise LiveAdapterError("Salad page time bounds are invalid") from None
        if not (slice_start <= parsed_min <= parsed_max <= slice_end):
            raise LiveAdapterError("Salad page time bounds are outside the requested window")
        return parsed_min, parsed_max
    if page_min is not None or page_max is not None:
        try:
            if page_min is not None and not (slice_start <= _utc(page_min) <= slice_end):
                raise LiveAdapterError("empty Salad page minimum is outside the query window")
            if page_max is not None and not (slice_start <= _utc(page_max) <= slice_end):
                raise LiveAdapterError("empty Salad page maximum is outside the query window")
        except LiveAdapterError:
            raise
        except Exception:
            raise LiveAdapterError("empty Salad page bounds are invalid") from None
    return None, None


def _normalize_page_items(
    raw_items: list[Any], *,
    evidence: ProviderResponseEvidence,
    policy: LiveLogQueryPolicy,
    slice_start: datetime,
    slice_end: datetime,
    page_min: datetime | None,
    page_max: datetime | None,
) -> tuple[NormalizedLogEntry, ...]:
    normalized: list[NormalizedLogEntry] = []
    for item in raw_items:
        envelope = _allowlisted_envelope(item)
        organization_values = provider_organization_label_values(envelope["resource"]["labels"])
        if any(value != policy.approved_organization for value in organization_values):
            raise LiveAdapterError("Salad log organization label is outside the approved scope")
        if len(organization_values) > 1:
            raise LiveAdapterError("Salad log organization labels conflict")
        try:
            record = normalize_provider_log_entry(envelope, evidence)
        except (LogRecordError, ValueError):
            raise LiveAdapterError("Salad log entry failed local validation") from None
        event_time = _utc(record.event_time_utc)
        if event_time < slice_start or event_time > slice_end:
            raise LiveAdapterError("Salad log entry time is outside its query slice")
        if (
            record.identity.organization_name is not None
            and record.identity.organization_name != policy.approved_organization
        ):
            raise LiveAdapterError("Salad log organization label is outside the approved scope")
        normalized.append(record)
    if normalized:
        times = [_utc(record.event_time_utc) for record in normalized]
        if page_min != min(times) or page_max != max(times):
            raise LiveAdapterError("Salad page bounds do not match returned item times")
    return tuple(normalized)


class LiveLogQueryAdapter:
    """Fetch one explicit time range using only the fixed log-query route."""

    def __init__(
        self,
        *,
        approved_organization: str,
        transport: LiveSaladReadTransport,
        secret_provider: Any,
        limits: LiveQueryLimits | None = None,
    ) -> None:
        if type(transport) is not LiveSaladReadTransport:
            raise TypeError("exact LiveSaladReadTransport is required")
        interactive_provider, synthetic_provider, _ = secret_boundary_types()
        if transport._offline_exchange is not None:
            if type(secret_provider) is not synthetic_provider:
                raise TypeError("offline adapter requires the exact SyntheticSecretProvider")
        elif type(secret_provider) is not interactive_provider:
            raise TypeError("live adapter requires the exact InteractiveSecretProvider")
        self.policy = LiveLogQueryPolicy(approved_organization)
        if transport.policy.approved_organization != approved_organization:
            raise ValueError("transport organization scope does not match adapter")
        if transport._offline_exchange is None and transport._secret_provider is not secret_provider:
            raise ValueError("live transport and adapter must share the exact secret provider")
        self.transport = transport
        self.secret_provider = secret_provider
        self.limits = limits or LiveQueryLimits()

    def fetch_complete_window(
        self, *, start_time_utc: str, end_time_utc: str, query: str,
    ) -> LiveQueryResult:
        start, end, query = self._validate_query(start_time_utc, end_time_utc, query)
        secret = self._acquire_secret()

        responses = 0
        items_seen = 0
        cumulative_bytes = 0
        normalized_by_hash: dict[str, NormalizedLogEntry] = {}
        classification: str | None = None
        response_evidence: list[ProviderResponseEvidence] = []

        def fetch_slice(slice_start: datetime, slice_end: datetime, depth: int) -> None:
            nonlocal responses, items_seen, cumulative_bytes, classification
            if responses >= self.limits.maximum_subqueries:
                raise LiveAdapterError("Salad query exceeded the bounded subquery count")
            if depth > self.limits.maximum_split_depth:
                raise LiveAdapterError("Salad response remained saturated past the split depth")
            request = self.policy.build_request(
                start_time_utc=slice_start,
                end_time_utc=slice_end,
                query=query,
                page_size=self.limits.page_size,
                sort_order="asc",
            )
            try:
                response = self.transport.fetch_query(request, secret=secret)
            except LiveTransportBlocked:
                raise
            except Exception:
                raise LiveAdapterError("Salad query transport failed; details redacted") from None
            responses += 1
            cumulative_bytes += len(response.body) if isinstance(response, SaladTransportResponse) else 0
            if cumulative_bytes > self.limits.maximum_response_bytes:
                raise LiveAdapterError("Salad query exceeded the cumulative byte limit")
            data = _bounded_body(response, self.limits)
            evidence = response.evidence
            if (
                type(evidence) is not ProviderResponseEvidence
                or evidence.status_code != response.status_code
                or evidence.classification not in {"SYNTHETIC/UNVERIFIED", "PROVIDER_OBSERVED"}
                or evidence.response_sha256 != hashlib.sha256(response.body).hexdigest()
            ):
                raise LiveAdapterError("Salad response provenance is unavailable")
            response_evidence.append(evidence)
            if classification is None:
                classification = evidence.classification
            elif classification != evidence.classification:
                raise LiveAdapterError("query mixed synthetic and provider-observed records")

            raw_items = data["items"]
            if len(raw_items) > request.page_size:
                raise LiveAdapterError("Salad response contains more items than requested page_size")
            items_seen += len(raw_items)
            if items_seen > self.limits.maximum_entries:
                raise LiveAdapterError("Salad query exceeded the cumulative entry limit")
            page_min, page_max = _validate_page_bounds(
                data, raw_items, slice_start=slice_start, slice_end=slice_end,
            )

            if len(raw_items) == self.limits.page_size:
                duration = (slice_end - slice_start).total_seconds()
                if duration <= self.limits.minimum_slice_seconds:
                    raise LiveAdapterError("minimum time slice remains saturated; query is incomplete")
                midpoint = slice_start + (slice_end - slice_start) / 2
                midpoint = midpoint.replace(microsecond=0)
                if midpoint <= slice_start or midpoint >= slice_end:
                    raise LiveAdapterError("time slice cannot be split safely")
                # Both child windows include the boundary. Stable evidence
                # deduplication removes boundary duplicates without assuming
                # the provider's endpoint-inclusion convention.
                fetch_slice(slice_start, midpoint, depth + 1)
                fetch_slice(midpoint, slice_end, depth + 1)
                return

            normalized_slice = _normalize_page_items(
                raw_items, evidence=evidence, policy=self.policy,
                slice_start=slice_start, slice_end=slice_end,
                page_min=page_min, page_max=page_max,
            )
            for record in normalized_slice:
                normalized_by_hash.setdefault(record.evidence_sha256, record)

        fetch_slice(_utc(start), _utc(end), 0)
        ordered = tuple(sorted(normalized_by_hash.values(), key=lambda item: (
            item.event_time_utc, item.evidence_sha256,
        )))
        return LiveQueryResult(
            query_start_utc=start,
            query_end_utc=end,
            subqueries_seen=responses,
            response_items_seen=items_seen,
            entries=ordered,
            data_classification=classification or "SYNTHETIC/UNVERIFIED",
            response_evidence=tuple(response_evidence),
        )

    def probe_single_request(
        self, *, start_time_utc: str, end_time_utc: str, query: str,
    ) -> LiveQueryResult:
        """Make exactly one bounded query request; never split a saturated page."""
        start, end, query = self._validate_query(start_time_utc, end_time_utc, query)
        duration = (_utc(end) - _utc(start)).total_seconds()
        if duration > self.limits.maximum_window_seconds:
            raise LiveAdapterError("contract probe window exceeds the configured maximum")
        secret = self._acquire_secret()
        request = self.policy.build_request(
            start_time_utc=start,
            end_time_utc=end,
            query=query,
            page_size=self.limits.page_size,
            sort_order="asc",
        )
        try:
            response = self.transport.fetch_query(request, secret=secret)
        except LiveTransportBlocked:
            raise
        except Exception:
            raise LiveAdapterError("Salad query transport failed; details redacted") from None
        if not isinstance(response, SaladTransportResponse):
            raise LiveAdapterError("Salad query response is not an accepted transport result")
        data = _bounded_body(response, self.limits)
        evidence = response.evidence
        if (
            type(evidence) is not ProviderResponseEvidence
            or evidence.status_code != response.status_code
            or evidence.classification not in {"SYNTHETIC/UNVERIFIED", "PROVIDER_OBSERVED"}
            or evidence.response_sha256 != hashlib.sha256(response.body).hexdigest()
        ):
            raise LiveAdapterError("Salad response provenance is unavailable")
        raw_items = data["items"]
        if len(raw_items) > request.page_size:
            raise LiveAdapterError("Salad response contains more items than requested page_size")
        if len(raw_items) > self.limits.maximum_entries:
            raise LiveAdapterError("Salad query exceeded the cumulative entry limit")
        slice_start, slice_end = _utc(start), _utc(end)
        page_min, page_max = _validate_page_bounds(
            data, raw_items, slice_start=slice_start, slice_end=slice_end,
        )
        entries = _normalize_page_items(
            raw_items, evidence=evidence, policy=self.policy,
            slice_start=slice_start, slice_end=slice_end,
            page_min=page_min, page_max=page_max,
        )
        completeness = "UNKNOWN_SATURATED" if len(raw_items) == request.page_size else "COMPLETE"
        return LiveQueryResult(
            query_start_utc=start,
            query_end_utc=end,
            subqueries_seen=1,
            response_items_seen=len(raw_items),
            entries=entries,
            data_classification=evidence.classification,
            response_evidence=(evidence,),
            window_completeness=completeness,
        )

    def _validate_query(self, start_time_utc: str, end_time_utc: str, query: str) -> tuple[str, str, str]:
        start = canonical_utc(start_time_utc)
        end = canonical_utc(end_time_utc)
        if _utc(start) >= _utc(end):
            raise LiveAdapterError("query window must have positive duration")
        if (_utc(end) - _utc(start)).total_seconds() > self.limits.maximum_window_seconds:
            raise LiveAdapterError("query window exceeds the configured maximum")
        if not isinstance(query, str) or not query.strip() or len(query) > 20_000:
            raise LiveAdapterError("an explicit bounded operator query is required")
        if any(ord(char) < 32 or ord(char) == 127 for char in query) or _SECRET_LIKE_QUERY.search(query):
            raise LiveAdapterError("query contains unsupported or credential-like content")
        return start, end, query

    def _acquire_secret(self) -> Any:
        offline = self.transport._offline_exchange is not None
        if not offline and PRODUCTION_NETWORK_ALLOWED is not True:
            raise LiveTransportBlocked("Salad production network access is disabled")
        interactive_provider, synthetic_provider, secret_material = secret_boundary_types()
        expected_provider = synthetic_provider if offline else interactive_provider
        expected_source = "synthetic_test_provider" if offline else "interactive_tty_session"
        if type(self.secret_provider) is not expected_provider:
            raise LiveTransportBlocked("approved Salad credential provider is unavailable")
        try:
            secret = self.secret_provider.acquire()
        except Exception:
            raise LiveTransportBlocked("Salad credential acquisition is unavailable") from None
        if type(secret) is not secret_material or secret.source_label != expected_source:
            raise LiveTransportBlocked("approved Salad credential material is unavailable")
        return secret


def _allowlisted_envelope(item: Any) -> Mapping[str, Any]:
    if not isinstance(item, Mapping):
        raise LiveAdapterError("Salad log item is malformed")
    # Copy only fields needed by the existing normalizer. Provider-specific
    # opaque fields, including unknown IDs, are neither retained nor persisted.
    event_time = item.get("time")
    resource = item.get("resource")
    if not isinstance(resource, Mapping):
        raise LiveAdapterError("Salad log resource is missing")
    resource_type = resource.get("type")
    labels = resource.get("labels")
    if not isinstance(resource_type, str) or not isinstance(labels, Mapping):
        raise LiveAdapterError("Salad resource type or labels are malformed")
    text_log = item.get("text_log")
    json_log = item.get("json_log")
    if json_log is not None and isinstance(json_log, str):
        if len(json_log.encode("utf-8")) > 32_000:
            raise LiveAdapterError("Salad structured log exceeds the local limit")
        try:
            json_log = json.loads(json_log)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Preserve a bounded string as a structured message; the parser
            # will ignore it unless it matches an allowlisted structured shape.
            pass
    return {
        "event_time_utc": event_time,
        "resource": {"type": resource_type, "labels": dict(labels)},
        "text_log": text_log,
        "structured_message": json_log,
        "log_id": None,
    }
