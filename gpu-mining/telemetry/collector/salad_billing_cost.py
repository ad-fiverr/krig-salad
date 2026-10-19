"""Offline, evidence-scoped Salad cost exposure and billing reconciliation.

Lifecycle observations, scoped rates, and independent billing records remain
separate evidence layers. This module performs no provider or payment I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import re
from typing import Any, Mapping


MAX_RECORDS = 10_000
MAX_IDENTIFIER_LENGTH = 256
MAX_REFERENCE_LENGTH = 512
ACTIVE_STATES = frozenset({
    "ALLOCATING", "ALLOCATED", "DOWNLOADING", "CREATING", "STARTING",
    "RUNNING", "READY", "STOPPING",
})
TERMINAL_STATES = frozenset({
    "STOPPED", "PREEMPTED", "LOST", "TERMINATED", "REALLOCATED",
    "ALLOCATION_TERMINATED",
})
KNOWN_STATES = ACTIVE_STATES | TERMINAL_STATES
RATE_CLASSIFICATIONS = frozenset({"QUOTED", "ESTIMATED_OPERATOR_RATE"})
BILLING_SOURCE_KINDS = frozenset({
    "PROVIDER_BILLING_STATEMENT", "PROVIDER_INVOICE_EXPORT",
    "PROVIDER_BILLING_API_VERIFIED",
})
GPU_CHARGE_TYPES = frozenset({"GPU_CONSUMPTION_CHARGE"})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


def _identifier(value: Any, field: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    result = value.strip()
    if not result or len(result) > MAX_IDENTIFIER_LENGTH or not _SAFE_ID.fullmatch(result):
        raise ValueError(f"{field} is invalid")
    return result


def _reference(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    result = value.strip()
    if not result or len(result) > MAX_REFERENCE_LENGTH or not _SAFE_ID.fullmatch(result):
        raise ValueError(f"{field} is invalid")
    return result


def _timestamp(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        except ValueError:
            raise ValueError(f"{field} is invalid") from None
    else:
        raise ValueError(f"{field} is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _decimal(value: Any, field: str, *, positive: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ValueError(f"{field} is invalid")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError(f"{field} is invalid") from None
    if not result.is_finite() or result < 0 or (positive and result <= 0) or result > Decimal("1000000000000"):
        raise ValueError(f"{field} is outside safe bounds")
    return result


def _seconds(start: datetime, end: datetime) -> Decimal:
    delta = end - start
    micros = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    return Decimal(micros) / Decimal(1_000_000)


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _money_text(value: Decimal) -> str:
    return format(value.normalize(), "f")


def _reference_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ScopedRate:
    quote_id: str
    organization: str
    project: str
    fleet_id: str
    billing_account_id: str
    usd_per_hour: Decimal
    effective_from_utc: datetime
    effective_until_utc: datetime | None
    rate_classification: str
    source_reference: str
    source_timestamp_utc: datetime
    gpu_model: str | None = None
    priority: str | None = None
    plan_identity: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ScopedRate":
        if not isinstance(raw, Mapping):
            raise ValueError("rate record is invalid")
        gpu_model = _identifier(raw.get("gpu_model"), "gpu_model", optional=True)
        priority = _identifier(raw.get("priority"), "priority", optional=True)
        plan = _identifier(raw.get("plan_identity"), "plan_identity", optional=True)
        if gpu_model is None and priority is None and plan is None:
            raise ValueError("rate record needs an explicit GPU, priority, or plan scope")
        classification = raw.get("rate_classification", "QUOTED")
        if classification not in RATE_CLASSIFICATIONS:
            raise ValueError("rate classification is invalid")
        start = _timestamp(raw.get("effective_from_utc"), "effective_from_utc")
        end_raw = raw.get("effective_until_utc")
        end = _timestamp(end_raw, "effective_until_utc") if end_raw is not None else None
        if end is not None and end <= start:
            raise ValueError("rate effective interval is invalid")
        return cls(
            quote_id=_identifier(raw.get("quote_id"), "quote_id"),
            organization=_identifier(raw.get("organization"), "organization"),
            project=_identifier(raw.get("project"), "project"),
            fleet_id=_identifier(raw.get("fleet_id"), "fleet_id"),
            billing_account_id=_identifier(raw.get("billing_account_id"), "billing_account_id"),
            usd_per_hour=_decimal(raw.get("usd_per_hour"), "usd_per_hour", positive=True),
            effective_from_utc=start,
            effective_until_utc=end,
            rate_classification=classification,
            source_reference=_reference(raw.get("source_reference"), "source_reference"),
            source_timestamp_utc=_timestamp(raw.get("source_timestamp_utc"), "source_timestamp_utc"),
            gpu_model=gpu_model,
            priority=priority,
            plan_identity=plan,
        )

    def applies_to(self, event: "LifecycleEvent", scope: tuple[str, str, str, str | None]) -> bool:
        organization, project, fleet_id, account_id = scope
        if (self.organization, self.project, self.fleet_id, self.billing_account_id) != (organization, project, fleet_id, account_id):
            return False
        for field in ("gpu_model", "priority", "plan_identity"):
            selected = getattr(self, field)
            if selected is not None and getattr(event, field) != selected:
                return False
        return True


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    event_id: str
    organization: str
    project: str
    fleet_id: str
    billing_account_id: str | None
    assignment_id: str
    instance_id: str
    machine_id: str
    allocation_id: str | None
    state: str
    occurred_at_utc: datetime
    source: str
    source_reference: str
    gpu_model: str | None = None
    priority: str | None = None
    plan_identity: str | None = None
    duplicate_group_id: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any], default_scope: Mapping[str, Any]) -> "LifecycleEvent":
        if not isinstance(raw, Mapping):
            raise ValueError("lifecycle event is invalid")
        labels = raw.get("provider_identity") if isinstance(raw.get("provider_identity"), Mapping) else {}
        machine = raw.get("machine_id") or labels.get("Resource labels machine id")
        instance = raw.get("instance_id") or labels.get("Resource labels instance id")
        state_raw = raw.get("state", raw.get("reported_state"))
        state = state_raw.upper() if isinstance(state_raw, str) else ""
        source = raw.get("source")
        if source not in {"salad_exported_lifecycle_csv", "provider_lifecycle", "synthetic"}:
            raise ValueError("lifecycle source is invalid")
        assignment = _identifier(raw.get("assignment_id"), "assignment_id")
        machine_id = _identifier(machine, "machine_id")
        instance_id = _identifier(instance, "instance_id")
        event_id = _identifier(raw.get("event_id"), "event_id")
        source_ref = raw.get("source_reference") or raw.get("source_file_sha256") or event_id
        reference = _reference(source_ref, "source_reference")
        return cls(
            event_id=event_id,
            organization=_identifier(raw.get("organization", default_scope.get("organization")), "organization"),
            project=_identifier(raw.get("project", default_scope.get("project")), "project"),
            fleet_id=_identifier(raw.get("fleet_id", default_scope.get("fleet_id")), "fleet_id"),
            billing_account_id=_identifier(raw.get("billing_account_id", default_scope.get("billing_account_id")), "billing_account_id", optional=True),
            assignment_id=assignment,
            instance_id=instance_id,
            machine_id=machine_id,
            allocation_id=_identifier(raw.get("allocation_id"), "allocation_id", optional=True),
            state=state,
            occurred_at_utc=_timestamp(raw.get("occurred_at_utc"), "occurred_at_utc"),
            source=source,
            source_reference=reference,
            gpu_model=_identifier(raw.get("gpu_model"), "gpu_model", optional=True),
            priority=_identifier(raw.get("priority"), "priority", optional=True),
            plan_identity=_identifier(raw.get("plan_identity"), "plan_identity", optional=True),
            duplicate_group_id=_identifier(raw.get("cross_source_observation_group_id"), "duplicate_group_id", optional=True),
        )


@dataclass(frozen=True, slots=True)
class IndependentBillingRecord:
    evidence_id: str
    organization: str
    project: str
    fleet_id: str
    billing_account_id: str
    window_start_utc: datetime
    window_end_utc: datetime
    amount: Decimal
    currency: str
    record_type: str
    source_kind: str
    source_reference: str
    verified_at_utc: datetime

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "IndependentBillingRecord":
        if not isinstance(raw, Mapping):
            raise ValueError("billing evidence is invalid")
        return cls(
            evidence_id=_identifier(raw.get("evidence_id"), "evidence_id"),
            organization=_identifier(raw.get("organization"), "organization"),
            project=_identifier(raw.get("project"), "project"),
            fleet_id=_identifier(raw.get("fleet_id"), "fleet_id"),
            billing_account_id=_identifier(raw.get("billing_account_id"), "billing_account_id"),
            window_start_utc=_timestamp(raw.get("window_start_utc"), "window_start_utc"),
            window_end_utc=_timestamp(raw.get("window_end_utc"), "window_end_utc"),
            amount=_decimal(raw.get("amount"), "amount"),
            currency=raw.get("currency") if isinstance(raw.get("currency"), str) else "",
            record_type=raw.get("record_type") if isinstance(raw.get("record_type"), str) else "",
            source_kind=raw.get("source_kind") if isinstance(raw.get("source_kind"), str) else "",
            source_reference=_reference(raw.get("source_reference"), "source_reference"),
            verified_at_utc=_timestamp(raw.get("verified_at_utc"), "verified_at_utc"),
        )


def unknown_cost_reconciliation(reason: str = "NO_COST_ACCOUNTING_INPUT") -> dict[str, Any]:
    safe_reason = reason if reason in {
        "NO_COST_ACCOUNTING_INPUT", "COST_INPUT_INVALID", "COST_INPUT_LIMIT_EXCEEDED",
        "LIFECYCLE_EVIDENCE_INVALID", "LIFECYCLE_SCOPE_CONFLICT", "LIFECYCLE_IDENTITY_CONFLICT",
        "NO_COMPLETE_LIFECYCLE_INTERVAL", "BILLING_ACCOUNT_SCOPE_UNKNOWN",
    } else "COST_INPUT_INVALID"
    return {
        "schema_version": "1.0",
        "status": "UNKNOWN",
        "reason": safe_reason,
        "quoted_rate_usd_per_hour": None,
        "quoted_24h_cost_usd": None,
        "rate_classification": "UNKNOWN",
        "estimated_exposure_seconds": None,
        "estimated_coverage_seconds": None,
        "estimated_coverage_status": "UNKNOWN",
        "estimated_accumulated_cost_usd": None,
        "estimated_cost_status": "UNKNOWN",
        "estimated_classification": "ESTIMATED",
        "chargeability_status": "PROVISIONAL_PROVIDER_CHARGEABILITY_UNVERIFIED",
        "verified_billed_cost_usd": None,
        "verified_billing_status": "UNKNOWN",
        "reconciliation_delta_usd": None,
        "reconciliation_status": "UNKNOWN",
        "assignments": [],
        "provenance": {"lifecycle_evidence_count": 0, "rate_evidence_count": 0, "billing_evidence_count": 0},
        "actions_performed": False,
    }


def _event_signature(event: LifecycleEvent) -> tuple[Any, ...]:
    return (
        event.organization, event.project, event.fleet_id, event.billing_account_id,
        event.assignment_id, event.instance_id, event.machine_id, event.allocation_id,
        event.state, event.occurred_at_utc, event.gpu_model, event.priority, event.plan_identity,
    )


def _rate_cost(start: datetime, end: datetime, event: LifecycleEvent, rates: list[ScopedRate], scope: tuple[str, str, str, str | None]) -> tuple[Decimal, Decimal, bool, list[ScopedRate]]:
    candidates = [rate for rate in rates if rate.applies_to(event, scope)]
    boundaries = {start, end}
    for rate in candidates:
        if start < rate.effective_from_utc < end:
            boundaries.add(rate.effective_from_utc)
        if rate.effective_until_utc is not None and start < rate.effective_until_utc < end:
            boundaries.add(rate.effective_until_utc)
    ordered = sorted(boundaries)
    amount = Decimal("0")
    covered = Decimal("0")
    conflict = False
    used: dict[str, ScopedRate] = {}
    for left, right in zip(ordered, ordered[1:]):
        matching = [rate for rate in candidates if rate.effective_from_utc <= left and (rate.effective_until_utc is None or right <= rate.effective_until_utc)]
        if len(matching) > 1:
            conflict = True
            continue
        if not matching:
            continue
        selected = matching[0]
        seconds = _seconds(left, right)
        covered += seconds
        amount += selected.usd_per_hour * seconds / Decimal(3600)
        used[selected.quote_id] = selected
    return amount, covered, conflict, list(used.values())


def _billing_total(
    rows: list[Any], *, organization: str, project: str, fleet_id: str,
    billing_account_id: str | None, window_start: datetime, window_end: datetime,
) -> tuple[Decimal | None, str, list[str], list[str]]:
    if not rows:
        return None, "UNKNOWN", [], []
    if billing_account_id is None:
        return None, "UNKNOWN_ACCOUNT_SCOPE", [], []
    if len(rows) > MAX_RECORDS:
        return None, "UNKNOWN_INPUT_LIMIT", [], []
    parsed: list[IndependentBillingRecord] = []
    excluded_cashflow = False
    try:
        for row in rows:
            item = IndependentBillingRecord.from_mapping(row)
            if item.record_type not in GPU_CHARGE_TYPES:
                excluded_cashflow = True
                continue
            if item.source_kind not in BILLING_SOURCE_KINDS:
                return None, "UNKNOWN_SOURCE", [], []
            if item.currency != "USD":
                return None, "UNKNOWN_CURRENCY_MISMATCH", [], []
            if (item.organization, item.project, item.fleet_id, item.billing_account_id) != (organization, project, fleet_id, billing_account_id):
                return None, "UNKNOWN_SCOPE_CONFLICT", [], []
            if (item.window_start_utc, item.window_end_utc) != (window_start, window_end):
                return None, "UNKNOWN_PERIOD_MISMATCH", [], []
            if item.window_end_utc <= item.window_start_utc:
                return None, "UNKNOWN_PERIOD_INVALID", [], []
            if row.get("verification_status") != "VERIFIED" or row.get("independent_source") is not True:
                return None, "UNKNOWN_NOT_INDEPENDENTLY_VERIFIED", [], []
            parsed.append(item)
    except (TypeError, ValueError):
        return None, "UNKNOWN_EVIDENCE_INVALID", [], []
    if not parsed:
        return None, "UNKNOWN_NON_CONSUMPTION_ONLY" if excluded_cashflow else "UNKNOWN", [], []
    by_id: dict[str, IndependentBillingRecord] = {}
    for item in parsed:
        prior = by_id.get(item.evidence_id)
        if prior is not None and prior != item:
            return None, "UNKNOWN_EVIDENCE_CONFLICT", [], []
        by_id[item.evidence_id] = item
    records = list(by_id.values())
    total = sum((item.amount for item in records), Decimal("0"))
    refs = sorted({_reference_hash(item.source_reference) for item in records})
    ids = sorted(item.evidence_id for item in records)
    return total, "BILLED_VERIFIED", ids, refs


def build_cost_reconciliation(record: Mapping[str, Any] | None) -> dict[str, Any]:
    """Build a deterministic, offline estimate and evidence-gated reconciliation."""
    if not isinstance(record, Mapping):
        return unknown_cost_reconciliation("COST_INPUT_INVALID")
    scope_values = (
        record.get("organization"), record.get("project"), record.get("fleet_id"),
    )
    try:
        organization, project, fleet_id = (
            _identifier(scope_values[0], "organization"),
            _identifier(scope_values[1], "project"),
            _identifier(scope_values[2], "fleet_id"),
        )
        billing_account_id = _identifier(record.get("billing_account_id"), "billing_account_id", optional=True)
        window_start = _timestamp(record.get("window_start_utc"), "window_start_utc")
        window_end = _timestamp(record.get("window_end_utc"), "window_end_utc")
        if window_end <= window_start:
            return unknown_cost_reconciliation("COST_INPUT_INVALID")
    except (TypeError, ValueError):
        return unknown_cost_reconciliation("COST_INPUT_INVALID")

    event_rows = record.get("lifecycle_events", [])
    rate_rows = record.get("quoted_rates", [])
    billing_rows = record.get("billing_evidence", [])
    if any(not isinstance(rows, list) or len(rows) > MAX_RECORDS for rows in (event_rows, rate_rows, billing_rows)):
        return unknown_cost_reconciliation("COST_INPUT_LIMIT_EXCEEDED")

    scope = (organization, project, fleet_id, billing_account_id)
    errors: set[str] = set()
    events_by_id: dict[str, LifecycleEvent] = {}
    events_by_unique_key: dict[str, LifecycleEvent] = {}
    conflicted_event_keys: set[str] = set()
    try:
        for raw in event_rows:
            event = LifecycleEvent.from_mapping(raw, record)
            if event.state not in KNOWN_STATES:
                errors.add("LIFECYCLE_EVIDENCE_INVALID")
                continue
            if (event.organization, event.project, event.fleet_id) != (organization, project, fleet_id):
                errors.add("LIFECYCLE_SCOPE_CONFLICT")
                continue
            if event.billing_account_id is not None and event.billing_account_id != billing_account_id:
                errors.add("LIFECYCLE_SCOPE_CONFLICT")
                continue
            previous = events_by_id.get(event.event_id)
            if previous is not None:
                if _event_signature(previous) != _event_signature(event):
                    errors.add("LIFECYCLE_IDENTITY_CONFLICT")
                    conflicted_event_keys.add(previous.duplicate_group_id or previous.event_id)
                continue
            events_by_id[event.event_id] = event
            unique_key = event.duplicate_group_id or event.event_id
            prior_duplicate = events_by_unique_key.get(unique_key)
            if prior_duplicate is not None:
                if _event_signature(prior_duplicate) != _event_signature(event):
                    errors.add("LIFECYCLE_IDENTITY_CONFLICT")
                    conflicted_event_keys.add(unique_key)
                continue
            events_by_unique_key[unique_key] = event
    except (TypeError, ValueError):
        errors.add("LIFECYCLE_EVIDENCE_INVALID")

    events = [event for key, event in events_by_unique_key.items() if key not in conflicted_event_keys]
    rates: list[ScopedRate] = []
    seen_rates: dict[str, ScopedRate] = {}
    try:
        for raw in rate_rows:
            rate = ScopedRate.from_mapping(raw)
            if (rate.organization, rate.project, rate.fleet_id, rate.billing_account_id) != (organization, project, fleet_id, billing_account_id):
                errors.add("RATE_SCOPE_CONFLICT")
                continue
            prior = seen_rates.get(rate.quote_id)
            if prior is not None and prior != rate:
                errors.add("RATE_EVIDENCE_CONFLICT")
                continue
            seen_rates[rate.quote_id] = rate
        rates = list(seen_rates.values())
    except (TypeError, ValueError):
        errors.add("RATE_EVIDENCE_INVALID")

    groups: dict[str, list[LifecycleEvent]] = {}
    for event in events:
        groups.setdefault(event.assignment_id, []).append(event)
    assignment_rows: list[dict[str, Any]] = []
    known_seconds = Decimal("0")
    all_rate_cost = Decimal("0")
    total_rate_covered = Decimal("0")
    any_open_tail = False
    any_assignment_conflict = False
    relevant_rates: dict[str, ScopedRate] = {}
    for assignment_id, rows in sorted(groups.items()):
        identities = {(row.machine_id, row.instance_id, row.allocation_id) for row in rows}
        if len(identities) != 1:
            errors.add("LIFECYCLE_IDENTITY_CONFLICT")
            any_assignment_conflict = True
            assignment_rows.append({
                "assignment_id": assignment_id,
                "status": "UNKNOWN_IDENTITY_CONFLICT",
                "measured_lifecycle_seconds": None,
                "candidate_billable_seconds": None,
                "estimated_accumulated_cost_usd": None,
                "estimated_cost_status": "UNKNOWN",
            })
            continue
        rows.sort(key=lambda item: (item.occurred_at_utc, item.event_id))
        same_time_states: dict[datetime, set[str]] = {}
        for row in rows:
            same_time_states.setdefault(row.occurred_at_utc, set()).add(row.state)
        if any(len(states) > 1 for states in same_time_states.values()):
            errors.add("LIFECYCLE_IDENTITY_CONFLICT")
            any_assignment_conflict = True
            assignment_rows.append({
                "assignment_id": assignment_id,
                "status": "UNKNOWN_AMBIGUOUS_TRANSITION",
                "measured_lifecycle_seconds": None,
                "candidate_billable_seconds": None,
                "estimated_accumulated_cost_usd": None,
                "estimated_cost_status": "UNKNOWN",
            })
            continue
        # Repeated same-state provider observations at an identical timestamp
        # do not add duration; retain one boundary deterministically.
        collapsed: list[LifecycleEvent] = []
        seen_boundaries: set[tuple[datetime, str]] = set()
        for row in rows:
            key = (row.occurred_at_utc, row.state)
            if key not in seen_boundaries:
                collapsed.append(row)
                seen_boundaries.add(key)
        if len(collapsed) < 2:
            if collapsed and collapsed[-1].state in ACTIVE_STATES:
                any_open_tail = True
            assignment_rows.append({
                "assignment_id": assignment_id,
                "instance_id": rows[0].instance_id,
                "machine_id": rows[0].machine_id,
                "status": "PARTIAL_OPEN_LIFECYCLE" if collapsed and collapsed[-1].state in ACTIVE_STATES else "UNKNOWN_NO_INTERVAL",
                "measured_lifecycle_seconds": None,
                "candidate_billable_seconds": None,
                "rate_covered_seconds": None,
                "estimated_accumulated_cost_usd": None,
                "estimated_cost_status": "UNKNOWN",
                "chargeability_status": "PROVISIONAL_PROVIDER_CHARGEABILITY_UNVERIFIED",
            })
            continue
        intervals: list[tuple[datetime, datetime, LifecycleEvent]] = []
        open_tail = collapsed[-1].state in ACTIVE_STATES
        any_open_tail = any_open_tail or open_tail
        measured = Decimal("0")
        cost = Decimal("0")
        rate_covered = Decimal("0")
        rate_conflict = False
        used_rates: dict[str, ScopedRate] = {}
        for left_event, right_event in zip(collapsed, collapsed[1:]):
            if left_event.state not in ACTIVE_STATES:
                continue
            start = max(window_start, left_event.occurred_at_utc)
            end = min(window_end, right_event.occurred_at_utc)
            if end <= start:
                continue
            intervals.append((start, end, left_event))
            duration = _seconds(start, end)
            measured += duration
            if billing_account_id is None:
                continue
            interval_cost, covered, conflict, interval_rates = _rate_cost(start, end, left_event, rates, scope)
            cost += interval_cost
            rate_covered += covered
            rate_conflict = rate_conflict or conflict
            for rate in interval_rates:
                used_rates[rate.quote_id] = rate
        known_seconds += measured
        total_rate_covered += rate_covered
        for rate in used_rates.values():
            relevant_rates[rate.quote_id] = rate
        if measured == 0:
            estimate_status = "UNKNOWN"
            est_cost = None
            assignment_status = "UNKNOWN_NO_IN_WINDOW_INTERVAL"
        elif rate_conflict:
            estimate_status = "UNKNOWN_RATE_CONFLICT"
            est_cost = None
            assignment_status = "PARTIAL_RATE_CONFLICT"
        elif rate_covered != measured:
            estimate_status = "PARTIAL_RATE_COVERAGE" if rate_covered > 0 else ("UNKNOWN_ACCOUNT_SCOPE" if billing_account_id is None else "UNKNOWN_RATE")
            est_cost = None
            assignment_status = "PARTIAL_RATE_COVERAGE" if rate_covered > 0 else "UNKNOWN_RATE"
        else:
            estimate_status = "PROVISIONAL_COMPLETE"
            est_cost = cost
            assignment_status = "PROVISIONAL"
            all_rate_cost += cost
        assignment_rows.append({
            "assignment_id": assignment_id,
            "instance_id": rows[0].instance_id,
            "machine_id": rows[0].machine_id,
            "status": assignment_status,
            "window_start_utc": _time_text(min((start for start, _, _ in intervals), default=window_start)),
            "window_end_utc": _time_text(max((end for _, end, _ in intervals), default=window_start)),
            "measured_lifecycle_seconds": _money_text(measured),
            "candidate_billable_seconds": _money_text(measured),
            "rate_covered_seconds": _money_text(rate_covered),
            "estimated_accumulated_cost_usd": _money_text(est_cost) if est_cost is not None else None,
            "estimated_cost_status": estimate_status,
            "open_lifecycle_tail": open_tail,
            "chargeability_status": "PROVISIONAL_PROVIDER_CHARGEABILITY_UNVERIFIED",
            "lifecycle_evidence_ids": sorted({item.event_id for item in rows}),
            "rate_source_classifications": sorted({rate.rate_classification for rate in used_rates.values()}),
            "rate_source_reference_sha256": sorted({_reference_hash(rate.source_reference) for rate in used_rates.values()}),
        })

    lifecycle_count = len(events)
    measured_present = known_seconds > 0
    if not measured_present:
        overall_estimated_status = "UNKNOWN"
        estimated_cost: Decimal | None = None
        overall_coverage = "UNKNOWN"
    elif errors or any_open_tail or any_assignment_conflict:
        overall_estimated_status = "PARTIAL"
        estimated_cost = None
        overall_coverage = "PARTIAL"
    elif all(row.get("estimated_cost_status") == "PROVISIONAL_COMPLETE" for row in assignment_rows):
        overall_estimated_status = "PROVISIONAL_COMPLETE"
        estimated_cost = all_rate_cost
        overall_coverage = "COMPLETE_OBSERVED_INTERVALS"
    elif assignment_rows and all(str(row.get("estimated_cost_status", "")).startswith("UNKNOWN") for row in assignment_rows):
        overall_estimated_status = "UNKNOWN"
        estimated_cost = None
        overall_coverage = "UNKNOWN"
    else:
        overall_estimated_status = "PARTIAL"
        estimated_cost = None
        overall_coverage = "PARTIAL_RATE_OR_IDENTITY_COVERAGE"

    quoted_rate_values = sorted({_money_text(rate.usd_per_hour) for rate in relevant_rates.values()})
    quoted_rate = Decimal(quoted_rate_values[0]) if len(quoted_rate_values) == 1 else None
    quoted_24h = quoted_rate * Decimal(24) if quoted_rate is not None else None
    billed_total, billing_status, billing_ids, billing_refs = _billing_total(
        billing_rows,
        organization=organization,
        project=project,
        fleet_id=fleet_id,
        billing_account_id=billing_account_id,
        window_start=window_start,
        window_end=window_end,
    )
    delta = billed_total - estimated_cost if billed_total is not None and estimated_cost is not None else None
    if delta is not None:
        reconciliation_status = "COMPARED_ESTIMATE_TO_VERIFIED_BILLING"
    elif billing_status == "BILLED_VERIFIED":
        reconciliation_status = "UNKNOWN_ESTIMATE_NOT_COMPLETE"
    else:
        reconciliation_status = billing_status

    reason_codes = sorted(errors)
    if not reason_codes and overall_estimated_status == "UNKNOWN" and assignment_rows:
        assignment_statuses = {row.get("estimated_cost_status") for row in assignment_rows}
        if assignment_statuses == {"UNKNOWN_ACCOUNT_SCOPE"}:
            reason_codes = ["BILLING_ACCOUNT_SCOPE_UNKNOWN"]
        elif assignment_statuses == {"UNKNOWN_RATE"}:
            reason_codes = ["RATE_COVERAGE_UNKNOWN"]
        elif assignment_statuses == {"UNKNOWN_RATE_CONFLICT"}:
            reason_codes = ["RATE_EVIDENCE_CONFLICT"]
    return {
        "schema_version": "1.0",
        "status": "PROVISIONAL" if measured_present else "UNKNOWN",
        "reason": reason_codes[0] if reason_codes else ("NO_COMPLETE_LIFECYCLE_INTERVAL" if not measured_present else None),
        "organization": organization,
        "project": project,
        "fleet_id": fleet_id,
        "billing_account_id": billing_account_id,
        "window_start_utc": _time_text(window_start),
        "window_end_utc": _time_text(window_end),
        "quoted_rate_usd_per_hour": _money_text(quoted_rate) if quoted_rate is not None else None,
        "quoted_24h_cost_usd": _money_text(quoted_24h) if quoted_24h is not None else None,
        "rate_classification": next(iter({rate.rate_classification for rate in relevant_rates.values()})) if len({rate.rate_classification for rate in relevant_rates.values()}) == 1 else ("MIXED" if relevant_rates else "UNKNOWN"),
        "estimated_exposure_seconds": _money_text(known_seconds) if measured_present else None,
        "estimated_coverage_seconds": _money_text(total_rate_covered) if total_rate_covered > 0 else None,
        "estimated_coverage_status": overall_coverage,
        "estimated_accumulated_cost_usd": _money_text(estimated_cost) if estimated_cost is not None else None,
        "estimated_cost_status": overall_estimated_status,
        "estimated_classification": "ESTIMATED",
        "chargeability_status": "PROVISIONAL_PROVIDER_CHARGEABILITY_UNVERIFIED",
        "verified_billed_cost_usd": _money_text(billed_total) if billed_total is not None else None,
        "verified_billing_status": billing_status,
        "verified_billing_evidence_ids": billing_ids,
        "verified_billing_source_reference_sha256": billing_refs,
        "reconciliation_delta_usd": _money_text(delta) if delta is not None else None,
        "reconciliation_status": reconciliation_status,
        "lifecycle_error_codes": reason_codes,
        "assignments": assignment_rows,
        "assumptions": [
            "candidate exposure is limited to observed adjacent lifecycle intervals inside the requested window",
            "missing lifecycle endpoints are not extrapolated",
            "provider chargeability semantics are not verified; estimated cost is provisional",
            "hashrate is not used to infer lifecycle duration or billing",
        ],
        "provenance": {
            "lifecycle_evidence_count": lifecycle_count,
            "rate_evidence_count": len(relevant_rates),
            "billing_evidence_count": len(billing_ids),
            "lifecycle_sources": sorted({event.source for event in events}),
            "lifecycle_source_reference_sha256": sorted({_reference_hash(event.source_reference) for event in events}),
        },
        "actions_performed": False,
    }


def operator_reaction_cost_scenarios() -> dict[str, Any]:
    """Return the supplied 198-placement sensitivity case, never billing data."""
    placements = 198
    rate = Decimal("0.417")
    scenarios: dict[str, dict[str, Any]] = {}
    for label, seconds in (("180_seconds", 180), ("30_seconds", 30), ("15_seconds", 15)):
        exposure = placements * seconds
        hours = Decimal(exposure) / Decimal(3600)
        amount = hours * rate
        scenarios[label] = {
            "placement_count": placements,
            "reaction_seconds_per_placement": seconds,
            "estimated_exposure_seconds": exposure,
            "estimated_exposure_minutes": _money_text(Decimal(exposure) / Decimal(60)),
            "estimated_exposure_hours": _money_text(hours),
            "operator_rate_usd_per_hour": _money_text(rate),
            "estimated_cost_usd": _money_text(amount),
            "classification": "ESTIMATED_OPERATOR_RATE",
            "billing_verified": False,
            "spend_authorized": False,
        }
    baseline = Decimal(scenarios["180_seconds"]["estimated_cost_usd"])
    savings = {}
    for label in ("30_seconds", "15_seconds"):
        current = Decimal(scenarios[label]["estimated_cost_usd"])
        savings[label] = {
            "estimated_savings_usd": _money_text(baseline - current),
            "classification": "ESTIMATED_SCENARIO_SAVINGS",
            "billing_verified": False,
            "spend_authorized": False,
        }
    return {
        "scenarios": scenarios,
        "savings_vs_180_seconds": savings,
        "rate_scope": "OPERATOR_SUPPLIED_ILLUSTRATIVE_ONLY",
        "classification": "ESTIMATED_OPERATOR_RATE",
        "billing_verified": False,
        "spend_authorized": False,
    }
