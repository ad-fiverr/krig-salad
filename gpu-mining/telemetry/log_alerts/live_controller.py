"""Explicit one-shot orchestration for future centralized live log alerts."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import re

from .central_telegram import CentralTelegramSender, PRODUCTION_TELEGRAM_ALLOWED
from .contract import PROVIDER_OBSERVED
from .delivery import DeliveryAttempt, DeliveryCoordinator
from .engine import CycleResult, LogAlertEnricher
from .contract import canonical_utc
from .live_transport import PRODUCTION_NETWORK_ALLOWED, LiveSaladReadTransport
from .ledger import SQLiteAlertLedger
from .normalize import NormalizedLogEntry


class LiveControllerBlocked(RuntimeError):
    """The one-shot run does not satisfy every explicit local gate."""


@dataclass(frozen=True, slots=True)
class ContractProbeSummary:
    data_classification: str
    query_start_utc: str
    query_end_utc: str
    subqueries_seen: int
    records_seen: int
    completeness: str
    resource_type_counts: dict[str, int]
    resource_label_key_names: tuple[str, ...]
    identity_status_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class LiveAlertRunSummary:
    cycle: CycleResult
    delivery_attempts: tuple[DeliveryAttempt, ...]


_SAFE_LABEL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SECRET_NAME = re.compile(r"(?i)(secret|token|password|credential|api.?key|authorization|private.?key)")


def summarize_probe(entries: tuple[NormalizedLogEntry, ...], *, classification: str,
                    start: str, end: str, subqueries: int,
                    completeness: str) -> ContractProbeSummary:
    """Return metadata only; never include IDs, values, messages or labels."""
    resource_types: Counter[str] = Counter()
    identities: Counter[str] = Counter()
    label_names: set[str] = set()
    for entry in entries:
        resource_types[entry.resource_type] += 1
        identities[entry.identity.status] += 1
        for name in entry.resource_labels:
            if isinstance(name, str) and _SAFE_LABEL_NAME.fullmatch(name) and not _SECRET_NAME.search(name):
                label_names.add(name)
    return ContractProbeSummary(
        data_classification=classification,
        query_start_utc=start,
        query_end_utc=end,
        subqueries_seen=subqueries,
        records_seen=len(entries),
        completeness=completeness,
        resource_type_counts=dict(sorted(resource_types.items())),
        resource_label_key_names=tuple(sorted(label_names)),
        identity_status_counts=dict(sorted(identities.items())),
    )


class LiveLogAlertController:
    """Coordinates a single read cycle and optionally a single delivery pass."""

    def __init__(
        self,
        *,
        enricher: LogAlertEnricher,
        ledger: SQLiteAlertLedger,
        sender: CentralTelegramSender | None = None,
    ):
        if type(enricher) is not LogAlertEnricher or type(ledger) is not SQLiteAlertLedger:
            raise TypeError("exact existing enricher and SQLite ledger are required")
        if enricher.ledger is not ledger:
            raise ValueError("enricher and controller must share one ledger")
        if sender is not None and type(sender) is not CentralTelegramSender:
            raise TypeError("exact central Telegram sender is required")
        if type(enricher.transport) is not LiveSaladReadTransport:
            raise TypeError("live controller requires the fixed Salad read transport")
        self.enricher = enricher
        self.ledger = ledger
        self.sender = sender

    def probe_once(
        self, *, start_time_utc: str, end_time_utc: str, query: str,
        enable_live_read: bool,
    ) -> ContractProbeSummary:
        if enable_live_read is not True:
            raise LiveControllerBlocked("explicit live-read gate is required")
        if self.enricher.transport._offline_exchange is None and not self.enricher.transport._live_read_enabled():
            raise LiveControllerBlocked("production Salad probe requires explicit live capability")
        result = self.enricher.live_adapter.probe_single_request(
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
            query=query,
        )
        return summarize_probe(
            result.entries,
            classification=result.data_classification,
            start=result.query_start_utc,
            end=result.query_end_utc,
            subqueries=result.subqueries_seen,
            completeness=result.window_completeness,
        )

    def live_alert_once(
        self, *, end_time_utc: str, query: str,
        enable_live_read: bool, enable_telegram_delivery: bool,
    ) -> LiveAlertRunSummary:
        if enable_live_read is not True:
            raise LiveControllerBlocked("explicit live-read gate is required")
        if enable_telegram_delivery is not True:
            raise LiveControllerBlocked("explicit central Telegram gate is required")
        if self.sender is None:
            raise LiveControllerBlocked("central Telegram sender is unavailable")
        if self.enricher.transport._offline_exchange is not None:
            raise LiveControllerBlocked("synthetic offline transport is never eligible for Telegram delivery")
        if self.enricher.transport._offline_exchange is None and not self.enricher.transport._live_read_enabled():
            raise LiveControllerBlocked("production Salad reads require explicit live capability")
        if self.sender._offline_responder is None:
            from .live_capability import capability_allows
            if PRODUCTION_TELEGRAM_ALLOWED is not True and not capability_allows(self.sender._capability, "central_telegram"):
                raise LiveControllerBlocked("production Telegram delivery requires explicit live capability")
        cycle = self.enricher.run_once(
            end_time_utc=end_time_utc,
            query=query,
            enable_provider_delivery=True,
        )
        if cycle.data_classification != PROVIDER_OBSERVED:
            raise LiveControllerBlocked("synthetic transport output is never deliverable")
        coordinator = DeliveryCoordinator(self.ledger, self.sender)
        attempts = coordinator.dispatch_new(
            [str(item["dedupe_key"]) for item in cycle.prepared_notifications],
            now_utc=canonical_utc(datetime.now(timezone.utc)),
        )
        return LiveAlertRunSummary(cycle=cycle, delivery_attempts=attempts)
