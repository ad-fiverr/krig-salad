"""Sequential multi-organization Salad log watcher with isolated state."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from pathlib import Path
import threading
import time
from typing import Any, Callable, Iterable, Mapping

from .central_telegram import CentralTelegramSender
from .contract import LiveLogQueryPolicy, canonical_utc
from .delivery import DeliveryCoordinator
from .engine import LogAlertEnricher
from .fleet_targets import FleetTarget, targets_by_organization, validate_targets
from .ledger import SQLiteAlertLedger
from .live_adapter import QUERY_FAILURE_CODES, LiveAdapterError, LiveQueryLimits
from .live_capability import LiveRuntimeCapability
from .live_transport import LiveSaladReadTransport, LiveTransportBlocked
from .list_instances_lookup import ListInstancesLookup


MIN_POLL_SECONDS = 15
MAX_POLL_SECONDS = 300
DEFAULT_POLL_SECONDS = 30
MAX_QUERY_CHARS = 20_000
_SECRET_QUERY_RE = re.compile(r"(?i)(?:salad[ _-]*api[ _-]*key|bearer\s+\S{8,}|(?:token|password|secret|api[_-]?key)\s*[:=])")


@dataclass(frozen=True, slots=True)
class OrganizationCycleResult:
    organization_name: str
    status: str
    projects: tuple[str, ...]
    records_seen: int = 0
    alerts_prepared: int = 0
    duplicates: int = 0
    group_lookups: int = 0
    lookup_cache_hits: int = 0
    lookup_failures: int = 0
    identity_lookup_status: str = "NOT_NEEDED"
    identity_lookup_http_status: int | None = None
    delivery_states: tuple[str, ...] = ()
    query_failure_code: str | None = None


class CentralFleetWatcher:
    """One sequential process; one scoped log query and SQLite ledger per org."""

    def __init__(
        self,
        *,
        targets: Iterable[FleetTarget],
        query: str,
        state_dir: str | Path,
        secret_provider: Any,
        sender: CentralTelegramSender,
        capability: LiveRuntimeCapability,
        poll_seconds: int = DEFAULT_POLL_SECONDS,
        transport_factory: Callable[[str, Any, LiveRuntimeCapability], LiveSaladReadTransport] | None = None,
        ledger_factory: Callable[[str | Path], SQLiteAlertLedger] = SQLiteAlertLedger,
        clock_utc: Callable[[], str] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.targets = validate_targets(targets)
        self.by_organization = targets_by_organization(self.targets)
        if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARS:
            raise ValueError("one explicit bounded Salad query is required")
        if any(ord(char) < 32 or ord(char) == 127 for char in query) or _SECRET_QUERY_RE.search(query):
            raise ValueError("Salad query contains unsupported control or credential-like content")
        if not MIN_POLL_SECONDS <= poll_seconds <= MAX_POLL_SECONDS:
            raise ValueError("poll interval must be between 15 and 300 seconds")
        if type(capability) is not LiveRuntimeCapability or not (
            capability.allows_salad_read and capability.allows_central_telegram
        ):
            raise ValueError("watcher requires explicit per-invocation Salad and Telegram capability")
        if type(sender) is not CentralTelegramSender:
            raise TypeError("one centralized Telegram sender is required")
        if not callable(ledger_factory) or not callable(monotonic):
            raise TypeError("watcher support functions are invalid")
        self.query = query.strip()
        state_path = Path(state_dir).expanduser()
        if state_path.is_symlink():
            raise ValueError("state directory must not be a symbolic link")
        self.state_dir = state_path.resolve()
        self.secret_provider = secret_provider
        self.sender = sender
        self.capability = capability
        self.poll_seconds = poll_seconds
        self.transport_factory = transport_factory or self._default_transport
        self.ledger_factory = ledger_factory
        self.clock_utc = clock_utc or (lambda: canonical_utc(datetime.now(timezone.utc)))
        self.monotonic = monotonic
        self._ledgers: dict[str, SQLiteAlertLedger] = {}
        # Keep the per-organization transport and scoped List Instances cache
        # for the lifetime of the watcher. Recreating the lookup each cycle
        # would silently disable its bounded TTL cache.
        self._transports: dict[str, LiveSaladReadTransport] = {}
        self._lookups: dict[str, ListInstancesLookup] = {}
        self._closed = False

    def __repr__(self) -> str:
        return (
            f"CentralFleetWatcher(organizations={len(self.by_organization)}, "
            f"query=[REDACTED], credentials=[REDACTED], enabled=False)"
        )

    def run_cycle(self, *, end_time_utc: str | None = None) -> tuple[OrganizationCycleResult, ...]:
        if self._closed:
            raise RuntimeError("watcher is closed")
        end = canonical_utc(end_time_utc or self.clock_utc())
        results: list[OrganizationCycleResult] = []
        # Sequential, fixed order prevents overlapping requests and makes one
        # organization's failure independent from the remaining organizations.
        for organization, projects in self.by_organization.items():
            results.append(self._run_organization(organization, projects, end))
        return tuple(results)

    def _run_organization(
        self, organization: str, projects: tuple[str, ...], end_time_utc: str,
    ) -> OrganizationCycleResult:
        ledger: SQLiteAlertLedger | None = None
        lookup: ListInstancesLookup | None = None
        try:
            ledger = self._ledger_for(organization)
            transport = self._transports.get(organization)
            if transport is None:
                transport = self.transport_factory(organization, self.secret_provider, self.capability)
            if type(transport) is not LiveSaladReadTransport or transport.policy.approved_organization != organization:
                raise RuntimeError("fixed organization transport unavailable")
            self._transports[organization] = transport
            offline = transport._offline_exchange is not None
            lookup = self._lookups.get(organization)
            if lookup is None:
                lookup = ListInstancesLookup(
                    organization_name=organization,
                    transport=transport,
                    secret_provider=self.secret_provider,
                    allowed_projects=projects,
                    clock=self.monotonic,
                )
                self._lookups[organization] = lookup
            lookup.begin_cycle()
            # Saturated pages are subdivided by the existing bounded adapter.
            # The default cap (64) permits safe time slicing without retries.
            limits = LiveQueryLimits()
            enricher = LogAlertEnricher(
                approved_organization=organization,
                transport=transport,
                ledger=ledger,
                limits=limits,
                secret_provider=self.secret_provider,
                allowed_projects=projects,
                identity_resolver=lookup.resolve_entry,
            )
            cycle = enricher.run_once(
                end_time_utc=end_time_utc,
                query=self.query,
                enable_provider_delivery=not offline,
            )
            delivery_states: tuple[str, ...] = ()
            if cycle.data_classification == "PROVIDER_OBSERVED":
                coordinator = DeliveryCoordinator(ledger, self.sender)
                attempts = coordinator.dispatch_new(
                    # A later overlapping provider page may have completed an
                    # exact identity lookup for an older pending alert. The
                    # ledger returns only a bounded batch with all five IDs.
                    ledger.list_pending_delivery_keys(),
                    now_utc=end_time_utc,
                )
                delivery_states = tuple(item.state for item in attempts)
            elif cycle.prepared_notifications:
                # Synthetic transport output is inspectable in local tests,
                # but it is never eligible for a Telegram send.
                delivery_states = tuple("NOT_SENT_SYNTHETIC" for _ in cycle.prepared_notifications)
            identity_lookup_status = _identity_lookup_status(lookup)
            organization_status = (
                "ACCESS_DENIED"
                if lookup.access_denied_status in {401, 403}
                else "SYNTHETIC_ONLY" if offline else "OK"
            )
            return OrganizationCycleResult(
                organization_name=organization,
                status=organization_status,
                projects=projects,
                records_seen=cycle.records_seen,
                alerts_prepared=cycle.prepared_count,
                duplicates=cycle.duplicate_count,
                group_lookups=lookup.lookups,
                lookup_cache_hits=lookup.cache_hits,
                lookup_failures=lookup.lookup_failures,
                identity_lookup_status=identity_lookup_status,
                identity_lookup_http_status=lookup.access_denied_status,
                delivery_states=delivery_states,
            )
        except Exception as exc:
            status = _safe_failure_state(exc)
            lookup_denied = lookup is not None and lookup.access_denied_status in {401, 403}
            return OrganizationCycleResult(
                organization_name=organization,
                status=status,
                projects=projects,
                group_lookups=0 if lookup is None else lookup.lookups,
                lookup_cache_hits=0 if lookup is None else lookup.cache_hits,
                lookup_failures=0 if lookup is None else lookup.lookup_failures,
                identity_lookup_status="ACCESS_DENIED" if lookup_denied else "NOT_AVAILABLE",
                identity_lookup_http_status=lookup.access_denied_status if lookup_denied else None,
                query_failure_code=_safe_query_failure_code(exc),
            )

    def _ledger_for(self, organization: str) -> SQLiteAlertLedger:
        existing = self._ledgers.get(organization)
        if existing is not None:
            return existing
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if self.state_dir.is_symlink():
            raise RuntimeError("state directory must not be a symbolic link")
        digest = hashlib.sha256(organization.encode("ascii")).hexdigest()
        path = self.state_dir / f"{digest}.sqlite3"
        if path.exists() and path.is_symlink():
            raise RuntimeError("state ledger must not be a symbolic link")
        ledger = self.ledger_factory(path)
        if type(ledger) is not SQLiteAlertLedger:
            raise TypeError("ledger factory must return the existing SQLite ledger")
        self._ledgers[organization] = ledger
        return ledger

    def _default_transport(
        self, organization: str, secret_provider: Any,
        capability: LiveRuntimeCapability,
    ) -> LiveSaladReadTransport:
        return LiveSaladReadTransport(
            policy=LiveLogQueryPolicy(organization),
            secret_provider=secret_provider,
            capability=capability,
        )

    def watch(
        self, *, stop_event: threading.Event | None = None,
        maximum_cycles: int | None = None,
        wait: Callable[[float], Any] | None = None,
        on_cycle: Callable[[tuple[OrganizationCycleResult, ...]], Any] | None = None,
    ) -> tuple[OrganizationCycleResult, ...]:
        """Poll until Ctrl+C/stop event; cycles never overlap or retry inline."""
        if maximum_cycles is not None and (isinstance(maximum_cycles, bool) or maximum_cycles < 1):
            raise ValueError("maximum_cycles must be positive when supplied")
        event = stop_event or threading.Event()
        wait_for = wait or event.wait
        cycle_number = 0
        last: tuple[OrganizationCycleResult, ...] = ()
        while not event.is_set():
            cycle_started = self.monotonic()
            last = self.run_cycle()
            if on_cycle is not None:
                on_cycle(last)
            cycle_number += 1
            if maximum_cycles is not None and cycle_number >= maximum_cycles:
                break
            elapsed = max(0.0, self.monotonic() - cycle_started)
            # Delay after the complete sequential cycle. No per-org immediate
            # retry, no overlapping cycle, and no busy loop on failures.
            wait_for(max(0.0, self.poll_seconds - elapsed))
        return last

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for ledger in self._ledgers.values():
            ledger.close()
        self._ledgers.clear()
        self._lookups.clear()
        self._transports.clear()

    def __enter__(self) -> "CentralFleetWatcher":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


def _safe_query_failure_code(exc: Exception) -> str:
    if type(exc) is LiveAdapterError:
        code = exc.failure_code
        if isinstance(code, str) and code in QUERY_FAILURE_CODES:
            return code
    if isinstance(exc, LiveTransportBlocked):
        return "TRANSPORT_FAILED"
    return "UNKNOWN"


def _safe_failure_state(exc: Exception) -> str:
    # Only sanitized status/exception classes escape; provider text never does.
    text = str(exc)
    if re.search(r"HTTP (?:401|403)\b", text):
        return "ACCESS_DENIED"
    if (
        isinstance(exc, TimeoutError)
        or "timeout" in type(exc).__name__.casefold()
        or (isinstance(exc, LiveTransportBlocked) and "timeout" in text.casefold())
    ):
        return "TIMEOUT"
    if "saturated" in text.casefold() or "incomplete" in text.casefold():
        return "INCOMPLETE_RESPONSE"
    if "429" in text:
        return "RATE_LIMITED"
    return "QUERY_FAILED"


def _identity_lookup_status(lookup: ListInstancesLookup) -> str:
    if lookup.access_denied_status in {401, 403}:
        return "ACCESS_DENIED"
    if lookup.lookup_failures:
        return "UNRESOLVED"
    if lookup.lookups or lookup.cache_hits:
        return "OK"
    return "NOT_NEEDED"
