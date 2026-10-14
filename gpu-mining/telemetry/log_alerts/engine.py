"""Deterministic organization log polling with fixture and gated-live inputs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable
import hashlib
import json
import math
import re

from .contract import (
    DATA_CLASSIFICATION,
    PROVIDER_OBSERVED,
    FixtureLogQueryTransport,
    IncompleteFixtureQuery,
    LogQueryPage,
    LogQueryPolicy,
    QueryPolicyError,
    QueryLimits,
    canonical_utc,
)
from .live_adapter import LiveLogQueryAdapter, LiveQueryLimits
from .live_transport import LiveSaladReadTransport
from .ledger import SQLiteAlertLedger
from .cuda_guard import correlate_cuda_exit_status, render_cuda_message
from .normalize import (
    AlertMarker,
    LogRecordError,
    MonitorAlert,
    NormalizedLogEntry,
    normalize_log_entry,
)
from .startup_guard import StartupGuard


MAX_TELEGRAM_MESSAGE_CHARS = 8_192


class UnsafeQueryCycle(RuntimeError):
    """A bounded fixture cycle could not establish a complete safe page set."""


@dataclass(frozen=True, slots=True)
class CycleResult:
    query_start_utc: str
    query_end_utc: str
    pages_seen: int
    records_seen: int
    recognized_alerts: int
    prepared_count: int
    duplicate_count: int
    cursor_time_utc: str
    data_classification: str
    evidence: tuple[NormalizedLogEntry, ...]
    prepared_notifications: tuple[Mapping[str, Any], ...]


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(canonical_utc(value).replace("Z", "+00:00"))


def _entry_order_key(entry: NormalizedLogEntry) -> tuple[str, int, str]:
    """Keep equal-time lifecycle transitions deterministic by event meaning.

    Evidence hashes remain a stable tie-breaker only within one semantic
    class; they never decide whether Ready precedes Running.
    """
    priority = {
        "INSTANCE_RUNNING": 0,
        "INSTANCE_READY": 1,
        "CUDA_DRIVER_INCOMPATIBLE": 2,
        "MINER_EXIT_STATUS_1": 3,
    }.get(entry.startup_signal or entry.cuda_signal, 4)
    return (entry.event_time_utc, priority, entry.evidence_sha256)


def _json_bytes(value: Any) -> int:
    try:
        return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                              allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise UnsafeQueryCycle("fixture page is not bounded JSON data") from exc


def _safe_field_text(value: Any, *, maximum: int = 256) -> str:
    if not isinstance(value, str):
        return "unknown"
    clean = "".join(char for char in value if ord(char) >= 32 and ord(char) != 127).strip()
    return clean[:maximum] or "unknown"


def _format_number(value: Any) -> str:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)):
        return "unknown"
    return f"{float(value):.3f}".rstrip("0").rstrip(".")


def _format_stale(stale: Any) -> str:
    if not isinstance(stale, Mapping):
        return "unknown"
    numerator = stale.get("numerator")
    denominator = stale.get("denominator")
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        return "unknown"
    percent = stale.get("reported_percent")
    if isinstance(percent, (int, float)) and not isinstance(percent, bool) and math.isfinite(float(percent)):
        return f"{numerator}/{denominator} ({_format_number(percent)}%)"
    return f"{numerator}/{denominator} (unknown)"


def _resource_context(entry: NormalizedLogEntry) -> str:
    parts = (
        entry.resource_type,
        entry.identity.resource_key(),
        entry.identity.organization_name or "",
        entry.identity.project_name or "",
        entry.identity.container_group_name or "",
    )
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _correlate_markers(
    entries: tuple[NormalizedLogEntry, ...],
    *,
    maximum_seconds: int,
) -> tuple[NormalizedLogEntry, ...]:
    markers = [entry for entry in entries if entry.marker is not None]
    result: list[NormalizedLogEntry] = []
    for candidate in entries:
        alert = candidate.alert
        if alert is None or alert.alert_id is not None:
            result.append(candidate)
            continue
        possible: dict[str, AlertMarker] = {}
        candidate_time = _parse_utc(candidate.event_time_utc)
        candidate_context = _resource_context(candidate)
        for marker_entry in markers:
            marker = marker_entry.marker
            if marker is None or marker.event_type != alert.event_type:
                continue
            alert_episode = alert.fields.get("degradation_episode_id")
            alert_sequence = alert.fields.get("alert_sequence")
            if alert_episode is not None and marker.episode_id != alert_episode:
                continue
            if alert_sequence is not None and marker.alert_sequence != alert_sequence:
                continue
            if alert_episode is None and marker.episode_id is not None:
                continue
            if alert_sequence is None and marker.alert_sequence is not None:
                continue
            if alert.event_type.startswith("POOL_CONNECTION_"):
                if (
                    marker.pool_episode_id != alert.fields.get("pool_episode_id")
                    or marker.monitor_session_id != alert.fields.get("monitor_session_id")
                    or marker.pool_alert_sequence != alert.fields.get("pool_alert_sequence")
                ):
                    continue
            if _resource_context(marker_entry) != candidate_context:
                continue
            delta = abs((_parse_utc(marker_entry.event_time_utc) - candidate_time).total_seconds())
            if delta <= maximum_seconds:
                possible[marker.alert_id] = marker
        # A single unique marker is required. Multiple possible IDs remain unknown.
        if len(possible) == 1:
            alert = replace(alert, alert_id=next(iter(possible)))
            result.append(replace(candidate, alert=alert))
        elif len(possible) == 0:
            result.append(candidate)
        else:
            result.append(candidate)
    return tuple(result)


def _has_bounded_pool_recovery_evidence(
    entry: NormalizedLogEntry,
    entries: tuple[NormalizedLogEntry, ...],
    *,
    maximum_seconds: int,
) -> bool:
    alert = entry.alert
    if alert is None or alert.event_type != "POOL_CONNECTION_RECOVERED":
        return True
    identity = entry.identity
    if (
        identity.status in {"UNKNOWN", "CONFLICTING"}
        or not identity.machine_id
        or not identity.instance_id
        or not identity.container_group_name
    ):
        return False
    fields = alert.fields
    failure_time = _parse_utc(fields["latest_failure_utc"])
    recovered_at = _parse_utc(fields["recovered_at_utc"])
    recovery_event_time = _parse_utc(entry.event_time_utc)
    evidence_hash = fields.get("solutions_evidence_sha256")
    if abs((recovery_event_time - recovered_at).total_seconds()) > maximum_seconds:
        return False
    resource = _resource_context(entry)
    for marker_entry in entries:
        if marker_entry is entry:
            continue
        marker = marker_entry.pool_recovery_marker
        if marker is None or _resource_context(marker_entry) != resource:
            continue
        if (
            marker.monitor_session_id != fields.get("monitor_session_id")
            or marker.pool_episode_id != fields.get("pool_episode_id")
            or marker.pool_alert_sequence != fields.get("pool_alert_sequence")
            or marker.recovery_signal != "SOLUTIONS_ACCEPTED"
            or marker.solutions_evidence_sha256 != evidence_hash
        ):
            continue
        marker_event_time = _parse_utc(marker_entry.event_time_utc)
        marker_record_time = _parse_utc(marker.timestamp_utc)
        if abs((marker_record_time - marker_event_time).total_seconds()) > maximum_seconds:
            continue
        # The monitor emits the internal evidence marker immediately before the
        # recovery audit, with the exact same internal timestamp. Salad records
        # those lines in provider time; preserve their actual marker -> recovery
        # -> accepted-solution order, allowing equal timestamps at provider
        # precision boundaries while requiring each record to stay bounded.
        if marker.timestamp_utc != fields.get("recovered_at_utc"):
            continue
        if marker_event_time > recovery_event_time:
            continue
        if (recovery_event_time - marker_event_time).total_seconds() > maximum_seconds:
            continue
        if marker_record_time > recovered_at or (recovered_at - marker_record_time).total_seconds() > maximum_seconds:
            continue
        for evidence in entries:
            if (
                evidence is marker_entry
                or evidence is entry
                or not evidence.pool_recovery_signal
                or evidence.pool_recovery_signal_sha256 != marker.solutions_evidence_sha256
                or _resource_context(evidence) != resource
            ):
                continue
            signal_time = _parse_utc(evidence.event_time_utc)
            if signal_time <= failure_time or signal_time < recovery_event_time:
                continue
            if (signal_time - recovery_event_time).total_seconds() > maximum_seconds:
                continue
            if abs((signal_time - recovered_at).total_seconds()) > maximum_seconds:
                continue
            return True
    return False


def _render_message(payload: Mapping[str, Any]) -> str:
    event_type = payload["event_type"]
    identity = payload["identity"]
    if not isinstance(identity, Mapping):
        raise UnsafeQueryCycle("prepared identity is malformed")
    if event_type == "CUDA_DRIVER_INCOMPATIBLE":
        cuda_lines = render_cuda_message(payload).splitlines()
        # CUDA uses the same six-line provider identity prefix as every other
        # central alert; the dedicated renderer supplies its bounded details.
        title = cuda_lines[6]
        body = cuda_lines[8:]
    else:
        body = []
        title = (
            f"🚨 {event_type}"
            if event_type in {
                "RUNNING_READY_BUT_MINER_NOT_STARTED", "MINER_STARTUP_HASHRATE_TIMEOUT",
            }
            else f"ALERT: {event_type}"
        )
    lines = [
        f"Organization: {_safe_field_text(payload.get('query_organization') or 'UNKNOWN')}",
        f"Project: {_safe_field_text(identity.get('project_name') or 'UNKNOWN')}",
        f"Container Group: {_safe_field_text(identity.get('container_group_name') or 'UNKNOWN')}",
        f"Machine ID: {_safe_field_text(identity.get('machine_id') or 'UNKNOWN')}",
        f"Instance ID: {_safe_field_text(identity.get('instance_id') or 'UNKNOWN')}",
        f"Identity source: {_safe_field_text(identity.get('identity_source') or 'UNKNOWN')}",
        title,
        f"Identity status: {_safe_field_text(identity.get('identity_status') or 'UNKNOWN')}",
    ]
    lines.extend(body)
    if event_type == "CUDA_DRIVER_INCOMPATIBLE":
        lines.extend([
            f"Event time: {payload['event_time_utc']}",
            f"Alert ID: {payload.get('alert_id') or 'unknown'}",
            f"Evidence: {payload.get('data_classification', DATA_CLASSIFICATION)}",
        ])
        message = "\n".join(lines)
        if len(message) > MAX_TELEGRAM_MESSAGE_CHARS:
            raise UnsafeQueryCycle("prepared alert exceeds the local message limit")
        return message
    if event_type == "REALLOCATE_RECOMMENDED":
        fields = payload["event_fields"]
        lines.extend([
            f"GPU: {_safe_field_text(fields.get('gpu_key'))}",
            f"Device: {_safe_field_text(fields.get('device'))}",
            f"Hashrate mean: {_format_number(fields.get('observed_window_mean_ths'))} TH/s",
            f"Floor: {_format_number(fields.get('floor_ths'))} TH/s",
            "Bad windows: "
            f"{fields.get('bad_windows', 'unknown')}/{fields.get('bad_windows_required', 'unknown')}",
            f"Stale: {_format_stale(fields.get('stale'))}",
            f"Policy hash: {_safe_field_text(fields.get('policy_hash'))}",
        ])
        if fields.get("floor_tolerance_ths") is not None:
            lines.append(f"Tolerance: {_format_number(fields.get('floor_tolerance_ths'))} TH/s")
            lines.append(f"Decision threshold: {_format_number(fields.get('decision_threshold_ths'))} TH/s")
        lines.append("Recommendation: REALLOCATE")
        if fields.get("degradation_episode_id"):
            lines.extend([
                f"Degradation episode: {_safe_field_text(fields.get('degradation_episode_id'))}",
                f"Alert sequence: {fields.get('alert_sequence', 'unknown')}",
                f"Notification reason: {_safe_field_text(fields.get('notification_reason'))}",
            ])
            if fields.get("previous_alert_mean_ths") is not None:
                lines.append(f"Previous alert mean: {_format_number(fields.get('previous_alert_mean_ths'))} TH/s")
                lines.append(
                    "Deterioration since previous alert: "
                    f"{_format_number(fields.get('deterioration_since_previous_alert_ths'))} TH/s"
                )
    elif event_type == "POOL_CONNECTION_FAILED":
        fields = payload["event_fields"]
        lines.extend([
            "Reason: MINING_AUTHORIZE_RESPONSE_TIMEOUT",
            f"Retry: {fields['retry_seconds']}s",
        ])
        if fields.get("pool_episode_id"):
            lines.extend([
                f"Monitor session: {_safe_field_text(fields.get('monitor_session_id'))}",
                f"Pool episode: {_safe_field_text(fields.get('pool_episode_id'))}",
                f"Pool alert sequence: {fields.get('pool_alert_sequence', 'unknown')}",
                f"Failure count: {fields.get('failure_count', 'unknown')}",
                f"First failure: {fields.get('first_failure_utc', 'unknown')}",
                f"Latest failure: {fields.get('latest_failure_utc', 'unknown')}",
                f"GPU: {_safe_field_text(fields.get('gpu_key'))}",
                f"Device: {_safe_field_text(fields.get('device'))}",
            ])
    elif event_type == "POOL_CONNECTION_UNSTABLE":
        fields = payload["event_fields"]
        lines.append("Reason: MINING_AUTHORIZE_RESPONSE_TIMEOUT")
        if fields.get("pool_episode_id"):
            lines.extend([
                f"Monitor session: {_safe_field_text(fields.get('monitor_session_id'))}",
                f"Pool episode: {_safe_field_text(fields.get('pool_episode_id'))}",
                f"Pool alert sequence: {fields.get('pool_alert_sequence', 'unknown')}",
                f"Notification reason: {_safe_field_text(fields.get('notification_reason'))}",
                f"Failure count: {fields.get('failure_count', 'unknown')}",
                f"Recent failures: {fields.get('recent_failure_count', 'unknown')} in 90s",
                f"First failure: {fields.get('first_failure_utc', 'unknown')}",
                f"Latest failure: {fields.get('latest_failure_utc', 'unknown')}",
                f"Retry reported by miner: {fields.get('retry_seconds', 'unknown')}s",
                f"Unstable duration: {fields.get('unstable_duration_seconds', 'unknown')}s",
                f"GPU: {_safe_field_text(fields.get('gpu_key'))}",
                f"Device: {_safe_field_text(fields.get('device'))}",
                "Recommendation: CHECK_POOL_OR_NETWORK",
            ])
        else:
            lines.extend([
                f"Failures: {fields['failure_count']} in {fields['window_seconds']}s",
                f"First failure: {fields['first_failure_utc']}",
                f"Latest failure: {fields['latest_failure_utc']}",
                f"GPU: {_safe_field_text(fields.get('gpu_key'))}",
                f"Device: {_safe_field_text(fields.get('device'))}",
            ])
    elif event_type == "POOL_CONNECTION_RECOVERED":
        fields = payload["event_fields"]
        lines.extend([
            f"Monitor session: {_safe_field_text(fields.get('monitor_session_id'))}",
            f"Pool episode: {_safe_field_text(fields.get('pool_episode_id'))}",
            f"Pool alert sequence: {fields.get('pool_alert_sequence', 'unknown')}",
            f"Failures: {fields.get('failure_count', 'unknown')}",
            f"Retry reported by miner: {fields.get('retry_seconds', 'unknown')}s",
            f"Prior failures: {fields.get('prior_failure_count', 'unknown')}",
            "Recovery signal: SOLUTIONS_ACCEPTED",
            f"Timestamp: {fields.get('timestamp_utc', 'unknown')}",
            f"Recovered at: {fields.get('recovered_at_utc', 'unknown')}",
            f"GPU: {_safe_field_text(fields.get('gpu_key'))}",
            f"Device: {_safe_field_text(fields.get('device'))}",
        ])
    elif event_type == "RUNNING_READY_BUT_MINER_NOT_STARTED":
        fields = payload["event_fields"]
        lines.extend([
            f"Provider state: {fields.get('provider_state', 'Running / Ready')}",
            f"Miner started: {str(fields.get('miner_started', False)).lower()}",
            f"GPU detected: {str(fields.get('gpu_detected', False)).lower()}",
            f"Hashrate samples: {fields.get('hashrate_samples', 0)}",
            f"Elapsed since Ready: {fields.get('elapsed_since_ready_seconds', 'unknown')}s",
            f"Recommendation: {fields.get('recommendation', 'REALLOCATE')}",
            "Generation: local fingerprint only",
        ])
    elif event_type == "MINER_STARTUP_RECOVERED":
        fields = payload["event_fields"]
        lines.extend([
            f"Progress recovered: {_safe_field_text(fields.get('progress_signal'))}",
            f"Progress event time: {fields.get('progress_event_time_utc') or 'unknown'}",
            "Generation: local fingerprint only",
        ])
    elif event_type == "MINER_STARTUP_HASHRATE_TIMEOUT":
        fields = payload["event_fields"]
        lines.extend([
            f"Reason: {_safe_field_text(fields.get('reason'))}",
            f"Startup timeout: {fields.get('startup_timeout_seconds', 'unknown')}s",
            f"Policy hash: {_safe_field_text(fields.get('policy_hash'))}",
            "Observed positive device hashrate: false",
            "Actions performed: false",
        ])
    elif event_type == "MONITOR_CONFIGURATION_INVALID":
        fields = payload["event_fields"]
        lines.extend([
            f"Reason: {_safe_field_text(fields.get('reason'))}",
            "Suggestion: CHECK_CONFIGURATION",
        ])
    elif event_type == "NO_FLOOR_CONFIGURED":
        fields = payload["event_fields"]
        lines.extend([
            f"GPU: {_safe_field_text(fields.get('gpu_key'))}",
            f"Device: {_safe_field_text(fields.get('device'))}",
            f"Observed: {_format_number(fields.get('observed_window_mean_ths'))} TH/s",
            "Floor: UNKNOWN",
            "Suggestion: CHECK_GPU_FLOOR_CONFIG",
        ])
    lines.extend([
        f"Event time: {payload['event_time_utc']}",
        f"Alert ID: {payload.get('alert_id') or 'unknown'}",
        f"Evidence: {payload.get('data_classification', DATA_CLASSIFICATION)}",
        "Actions performed: false",
    ])
    message = "\n".join(lines)
    if len(message) > MAX_TELEGRAM_MESSAGE_CHARS:
        raise UnsafeQueryCycle("prepared alert exceeds the local message limit")
    return message


class LogAlertEnricher:
    """Reuse one alert pipeline with either fixtures or the exact live transport."""

    def __init__(
        self,
        *,
        approved_organization: str,
        transport: FixtureLogQueryTransport | LiveSaladReadTransport,
        ledger: SQLiteAlertLedger,
        limits: QueryLimits | LiveQueryLimits | None = None,
        secret_provider: Any = None,
        allowed_projects: Iterable[str] | None = None,
        identity_resolver: Callable[[NormalizedLogEntry], NormalizedLogEntry] | None = None,
    ) -> None:
        if type(ledger) is not SQLiteAlertLedger:
            raise TypeError("a local SQLiteAlertLedger is required")
        self.approved_organization = approved_organization
        projects = None if allowed_projects is None else tuple(sorted(set(allowed_projects)))
        if projects is not None and (
            not projects or any(not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]", value) for value in projects)
        ):
            raise ValueError("allowed project names are invalid")
        if identity_resolver is not None and not callable(identity_resolver):
            raise TypeError("identity resolver must be callable")
        if identity_resolver is not None and type(transport) is not LiveSaladReadTransport:
            raise TypeError("provider identity fallback requires the live Salad adapter")
        self.allowed_projects = projects
        self.identity_resolver = identity_resolver
        self.transport = transport
        self.ledger = ledger
        if type(transport) is FixtureLogQueryTransport:
            if limits is not None and type(limits) is not QueryLimits:
                raise TypeError("fixture transport requires QueryLimits")
            self.limits = limits or QueryLimits()
            self.policy = LogQueryPolicy(approved_organization)
            if transport.policy != self.policy:
                raise ValueError("fixture transport policy does not match the approved organization")
            self.live_adapter = None
        elif type(transport) is LiveSaladReadTransport:
            if limits is not None and type(limits) is not LiveQueryLimits:
                raise TypeError("live transport requires LiveQueryLimits")
            self.limits = limits or LiveQueryLimits()
            if transport.policy.approved_organization != approved_organization:
                raise ValueError("live transport organization does not match the approved organization")
            if secret_provider is None:
                raise ValueError("live transport requires an explicit secret provider")
            self.policy = transport.policy
            self.live_adapter = LiveLogQueryAdapter(
                approved_organization=approved_organization,
                transport=transport,
                secret_provider=secret_provider,
                limits=self.limits,
            )
        else:
            raise TypeError("only FixtureLogQueryTransport or exact LiveSaladReadTransport is supported")

    def _window(self, end_time_utc: str | datetime) -> tuple[str, str]:
        requested_end = _parse_utc(canonical_utc(end_time_utc))
        previous = self.ledger.get_cursor()
        if previous is None:
            end = requested_end
            start = end - timedelta(seconds=self.limits.maximum_window_seconds)
        else:
            cursor = _parse_utc(previous)
            if requested_end < cursor:
                raise UnsafeQueryCycle("query end time precedes the durable cursor")
            # Catch up from the oldest unprocessed time. A delayed caller may
            # request an end several hours ahead, but this cycle may advance at
            # most one bounded window minus its overlap from the durable cursor.
            # Repeated calls therefore walk the interval without skipping it.
            end = min(
                requested_end,
                cursor + timedelta(seconds=(
                    self.limits.maximum_window_seconds - self.limits.overlap_seconds
                )),
            )
            start = cursor - timedelta(seconds=self.limits.overlap_seconds)
            if end <= start:
                raise UnsafeQueryCycle("catch-up window has no positive duration")
        if end - start > timedelta(seconds=self.limits.maximum_window_seconds):
            raise UnsafeQueryCycle("query window exceeds the local bound")
        return canonical_utc(start), canonical_utc(end)

    def run_once(
        self,
        *,
        end_time_utc: str | datetime,
        query: str | None = None,
        enable_provider_delivery: bool = False,
    ) -> CycleResult:
        """Fetch one bounded cycle and pass it through the existing alert pipeline."""
        start, end = self._window(end_time_utc)
        query_count = 0
        normalized: list[NormalizedLogEntry] = []
        classification = DATA_CLASSIFICATION
        live_scope = None
        provider_response_evidence: tuple[Any, ...] = ()
        if type(self.transport) is FixtureLogQueryTransport:
            if query is not None or enable_provider_delivery:
                raise UnsafeQueryCycle("fixture cycles cannot accept live query or delivery controls")
            page_token: str | None = None
            seen_tokens: set[str] = set()
            pages: list[LogQueryPage] = []
            entries: list[Mapping[str, Any]] = []
            total_bytes = 0
            for _page_number in range(1, self.limits.maximum_pages + 1):
                request = self.policy.build_request(
                    start_time_utc=start,
                    end_time_utc=end,
                    page_size=self.limits.page_size,
                    page_token=page_token,
                )
                page = self.transport.fetch_page(request)
                if type(page) is not LogQueryPage or page.data_classification != DATA_CLASSIFICATION:
                    raise UnsafeQueryCycle("fixture response is not marked SYNTHETIC/UNVERIFIED")
                if len(page.entries) > self.limits.page_size:
                    raise IncompleteFixtureQuery("fixture page exceeds the requested local size")
                total_bytes += _json_bytes(page.entries)
                if total_bytes > self.limits.maximum_response_bytes:
                    raise IncompleteFixtureQuery("fixture response exceeds the local byte limit")
                entries.extend(page.entries)
                if len(entries) > self.limits.maximum_entries:
                    raise IncompleteFixtureQuery("fixture response exceeds the local entry limit")
                pages.append(page)
                next_token = page.next_page_token
                if next_token is None:
                    break
                if next_token in seen_tokens or next_token == page_token:
                    raise IncompleteFixtureQuery("fixture pagination token repeated")
                seen_tokens.add(next_token)
                page_token = next_token
            else:
                raise IncompleteFixtureQuery("fixture pagination exceeded the local page limit")
            if not pages or pages[-1].next_page_token is not None:
                raise IncompleteFixtureQuery("fixture response ended before pagination completed")
            query_count = len(pages)
            try:
                for raw_entry in entries:
                    record = normalize_log_entry(raw_entry)
                    if record.identity.organization_name is not None and record.identity.organization_name != self.approved_organization:
                        raise UnsafeQueryCycle("provider organization label is outside the fixed query scope")
                    event_time = _parse_utc(record.event_time_utc)
                    if event_time < _parse_utc(start) or event_time > _parse_utc(end):
                        raise UnsafeQueryCycle("fixture log time is outside the bounded query window")
                    normalized.append(record)
            except (LogRecordError, QueryPolicyError) as exc:
                raise UnsafeQueryCycle(str(exc)) from None
        else:
            if not isinstance(query, str) or not query.strip():
                raise UnsafeQueryCycle("live cycles require an explicit operator query")
            if self.transport._offline_exchange is None:
                live_scope = self._scope_for_query(query)
                # Check the database before any future request so a fixture or
                # incompatible query can never share the live cursor.
                self.ledger.assert_live_scope(live_scope)
            live_result = self.live_adapter.fetch_complete_window(
                start_time_utc=start,
                end_time_utc=end,
                query=query,
            )
            normalized.extend(live_result.entries)
            if self.allowed_projects is not None:
                normalized = [
                    entry for entry in normalized
                    if entry.identity.project_name in self.allowed_projects
                ]
            if self.identity_resolver is not None:
                resolved: list[NormalizedLogEntry] = []
                for entry in normalized:
                    updated = self.identity_resolver(entry)
                    if (
                        type(updated) is not NormalizedLogEntry
                        or updated.data_classification != entry.data_classification
                        or updated.event_time_utc != entry.event_time_utc
                        or updated.evidence_sha256 != entry.evidence_sha256
                        or updated.resource_labels != entry.resource_labels
                        or updated.alert != entry.alert
                    ):
                        raise UnsafeQueryCycle("identity resolver changed non-identity evidence")
                    resolved.append(updated)
                normalized = resolved
            classification = live_result.data_classification
            query_count = live_result.subqueries_seen
            provider_response_evidence = live_result.response_evidence
            if classification == PROVIDER_OBSERVED:
                live_scope = self._scope_for_query(query)
            elif enable_provider_delivery:
                raise UnsafeQueryCycle("synthetic live-transport test records cannot be delivered")

        ordered = tuple(sorted(normalized, key=_entry_order_key))
        ordered, cuda_exit_evidence = correlate_cuda_exit_status(ordered)
        correlated = _correlate_markers(
            ordered,
            maximum_seconds=self.limits.correlation_seconds,
        )
        candidates: list[NormalizedLogEntry] = []
        for entry in correlated:
            alert = entry.alert
            if alert is None:
                continue
            fields = alert.fields
            if (
                classification == PROVIDER_OBSERVED
                and alert.event_type in {
                    "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
                    "POOL_CONNECTION_RECOVERED",
                }
                and not fields.get("pool_episode_id")
            ):
                # Raw legacy retry lines remain parseable for historical/offline
                # analysis, but live delivery needs a bounded episode event so
                # each retry cannot become a separate notification.
                continue
            if alert.event_type == "POOL_CONNECTION_RECOVERED" and not _has_bounded_pool_recovery_evidence(
                entry, ordered, maximum_seconds=self.limits.correlation_seconds
            ):
                continue
            candidates.append(entry)
        if classification == DATA_CLASSIFICATION:
            startup_events, startup_states = StartupGuard().process(
                ordered,
                prior_states=self.ledger.get_startup_states(),
                end_time_utc=end,
            )
        else:
            # Salad Running/Ready lifecycle semantics remain unverified. Live
            # records may produce miner alerts but cannot enter StartupGuard.
            startup_events, startup_states = [], None
        notifications = [
            self._prepare_notification(entry)
            for entry in candidates
        ]
        notifications.extend(self._prepare_startup_notification(event) for event in startup_events)
        prepared = self.ledger.commit_cycle(
            notifications,
            cursor_time_utc=end,
            committed_at_utc=end,
            startup_states=startup_states,
            cuda_exit_evidence=cuda_exit_evidence,
            data_classification=classification,
            live_scope=live_scope,
            allow_provider_delivery=enable_provider_delivery,
            provider_response_evidence=provider_response_evidence,
        )
        return CycleResult(
            query_start_utc=start,
            query_end_utc=end,
            pages_seen=query_count,
            records_seen=len(normalized),
            recognized_alerts=len(candidates) + len(startup_events),
            prepared_count=len(prepared),
            duplicate_count=len(notifications) - len(prepared),
            cursor_time_utc=self.ledger.get_cursor() or end,
            data_classification=classification,
            evidence=ordered,
            prepared_notifications=tuple(prepared),
        )

    def _scope_for_query(self, query: str) -> dict[str, str]:
        scope_material = json.dumps(
            {"query": query, "allowed_projects": self.allowed_projects},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        )
        return {
            "organization_name": self.approved_organization,
            "operation": "READ_LOG_QUERY",
            "query_sha256": hashlib.sha256(scope_material.encode("ascii")).hexdigest(),
            "data_classification": PROVIDER_OBSERVED,
        }

    def _prepare_notification(self, entry: NormalizedLogEntry) -> dict[str, Any]:
        alert = entry.alert
        assert alert is not None
        identity = entry.identity.public_fields()
        # Dedupe identity is fixed to the raw provider-label source record;
        # optional List Instances enrichment changes only the presentation.
        identity_key = entry.identity.source_identity_key()
        fields = dict(alert.fields)
        if alert.event_type == "NO_FLOOR_CONFIGURED":
            dedupe_evidence = json.dumps(
                {
                    "gpu_key": fields.get("gpu_key", "unknown"),
                    "device": fields.get("device", "unknown"),
                    "policy_hash": fields.get("policy_hash"),
                }, sort_keys=True,
                separators=(",", ":"),
            )
        elif alert.event_type == "MONITOR_CONFIGURATION_INVALID":
            # Distinct source records remain durable evidence; the ledger
            # applies the allocation-scoped cooldown transactionally.
            dedupe_evidence = entry.evidence_sha256
        elif alert.event_type == "REALLOCATE_RECOMMENDED" and alert.fields.get("degradation_episode_id"):
            dedupe_evidence = (
                f"{alert.fields['degradation_episode_id']}:{alert.fields.get('alert_sequence')}"
            )
        elif alert.event_type.startswith("POOL_CONNECTION_") and alert.fields.get("pool_episode_id"):
            dedupe_evidence = ":".join(str(alert.fields.get(key, "")) for key in (
                "monitor_session_id", "pool_episode_id", "pool_alert_sequence",
                "notification_reason",
            )) + f":{alert.event_type}"
        else:
            dedupe_evidence = entry.evidence_sha256
        material = {
            "query_organization": self.approved_organization,
            "resource_type": entry.resource_type,
            "identity_key": identity_key,
            "event_type": alert.event_type,
            "dedupe_evidence": dedupe_evidence,
        }
        dedupe_key = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        payload: dict[str, Any] = {
            "data_classification": entry.data_classification,
            "query_organization": self.approved_organization,
            "event_type": alert.event_type,
            "alert_id": alert.alert_id,
            "event_time_utc": entry.event_time_utc,
            "resource_type": entry.resource_type,
            "identity": identity,
            "event_source": entry.alert_source,
            "event_fields": fields,
            "source_evidence_sha256": entry.evidence_sha256,
            "source_log_reference": entry.log_id,
            "actions_performed": False,
        }
        message = _render_message(payload)
        if "\r" in message:
            raise UnsafeQueryCycle("prepared message contains a line-control character")
        return {
            "dedupe_key": dedupe_key,
            "event_type": alert.event_type,
            "event_time_utc": entry.event_time_utc,
            "identity_key": identity_key,
            "identity_status": identity["identity_status"],
            "machine_id": identity.get("machine_id"),
            "instance_id": identity.get("instance_id"),
            "container_group_name": identity.get("container_group_name"),
            "alert_id": alert.alert_id,
            "source_evidence_sha256": entry.evidence_sha256,
            "source_log_ref": entry.log_id,
            "payload": payload,
            "message_text": message,
        }

    def _prepare_startup_notification(self, event: Mapping[str, Any]) -> dict[str, Any]:
        payload = {
            "data_classification": DATA_CLASSIFICATION,
            "query_organization": self.approved_organization,
            "event_type": event["event_type"],
            "alert_id": None,
            "event_time_utc": event["event_time_utc"],
            "resource_type": event["resource_type"],
            "identity": dict(event["identity"]),
            "event_source": "provider_resource_and_container_progress_logs",
            "event_fields": dict(event["event_fields"]),
            "source_evidence_sha256": event["source_evidence_sha256"],
            "source_log_reference": None,
            "generation_id": event["generation_id"],
            "actions_performed": False,
        }
        identity_key = str(event["resource_key"])
        material = {
            "query_organization": self.approved_organization,
            "resource_type": event["resource_type"],
            "identity_key": identity_key,
            "event_type": event["event_type"],
            "generation_id": event["generation_id"],
        }
        dedupe_key = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        message = _render_message(payload)
        return {
            "dedupe_key": dedupe_key,
            "event_type": event["event_type"],
            "event_time_utc": event["event_time_utc"],
            "identity_key": identity_key,
            "identity_status": payload["identity"]["identity_status"],
            "machine_id": payload["identity"].get("machine_id"),
            "instance_id": payload["identity"].get("instance_id"),
            "container_group_name": payload["identity"].get("container_group_name"),
            "alert_id": None,
            "source_evidence_sha256": event["source_evidence_sha256"],
            "source_log_ref": None,
            "payload": payload,
            "message_text": message,
        }
