"""Offline monetary evidence ledger with non-additive stages and conservative deltas."""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .models import REVENUE_EVIDENCE_STAGES, V2_SCHEMA_VERSION


def _amount(value: Any, field: str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{field} is required as a decimal string")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field} must be a decimal") from exc
    if not result.is_finite():
        raise ValueError(f"{field} must be finite")
    return result


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not re.search(r"T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$", value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _has_reference(value: Any) -> bool:
    return (isinstance(value, str) and bool(value.strip())) or (isinstance(value, dict) and bool(value))


def _validate_observation_time(item: dict[str, Any], stage: str) -> str:
    if stage == "estimated":
        start = _time(item.get("window_start"))
        end = _time(item.get("window_end"))
        if start is None or end is None or end <= start:
            raise ValueError("estimated evidence requires a positive timezone-aware window_start/window_end")
        return "bounded_estimate_window"
    if _time(item.get("observed_at")) is None:
        raise ValueError("monetary evidence requires a timezone-aware observed_at timestamp")
    if item.get("observed_at_precision") not in {"second", "millisecond"}:
        raise ValueError("monetary evidence observed_at_precision must be second or millisecond")
    return "observed_at"


def _validate_conversion(item: dict[str, Any]) -> dict[str, Any]:
    conversion = item.get("conversion")
    if not isinstance(conversion, dict):
        raise ValueError("converted evidence requires explicit conversion metadata")
    from_amount = _amount(conversion.get("from_amount"), "conversion.from_amount")
    rate = _amount(conversion.get("rate"), "conversion.rate")
    if from_amount < 0 or rate <= 0:
        raise ValueError("conversion source amount must be nonnegative and conversion rate positive")
    from_currency = conversion.get("from_currency")
    to_currency = conversion.get("to_currency")
    if not isinstance(from_currency, str) or not from_currency or to_currency != item.get("currency"):
        raise ValueError("conversion currencies must identify source and match the converted evidence currency")
    if from_currency == to_currency:
        raise ValueError("conversion must identify two different currencies")
    if _time(conversion.get("observed_at")) is None:
        raise ValueError("conversion rate requires a timezone-aware observed_at timestamp")
    reference = conversion.get("source_reference")
    if not _has_reference(reference):
        raise ValueError("conversion rate requires a source_reference")
    amount = _amount(item.get("amount"), "amount")
    quantum = Decimal(1).scaleb(amount.as_tuple().exponent)
    expected = from_amount * rate
    expected_rounded = expected.quantize(quantum)
    if expected_rounded == amount:
        return {
            "status": "RECONCILED_RATE_AMOUNT",
            "expected_amount": str(expected_rounded),
            "reported_amount": str(amount),
        }

    adjustment = conversion.get("documented_adjustment")
    if isinstance(adjustment, dict):
        adjustment_amount = _amount(adjustment.get("amount"), "conversion.documented_adjustment.amount")
        adjustment_reference = adjustment.get("source_reference")
        adjustment_time = _time(adjustment.get("observed_at"))
        if _has_reference(adjustment_reference) and adjustment_time is not None:
            adjusted = (expected + adjustment_amount).quantize(quantum)
            if adjusted == amount:
                return {
                    "status": "RECONCILED_WITH_DOCUMENTED_ADJUSTMENT",
                    "expected_amount": str(expected_rounded),
                    "documented_adjustment_amount": str(adjustment_amount),
                    "reported_amount": str(amount),
                }
    return {
        "status": "UNRECONCILED",
        "expected_amount": str(expected_rounded),
        "reported_amount": str(amount),
        "reason": "reported converted amount does not match the timestamped rate or a documented adjustment",
    }


def _normalize_billing_evidence(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("each Salad billing evidence record must be an object")
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            raise ValueError("Salad billing evidence requires a nonempty evidence_id")
        amount = _amount(item.get("amount"), "billing_evidence.amount")
        if amount < 0 or item.get("currency") != "USD":
            raise ValueError("Salad billing evidence amount must be nonnegative USD")
        attribution_id = item.get("attribution_id")
        if not isinstance(attribution_id, str) or not attribution_id.strip():
            raise ValueError("Salad billing evidence requires an attribution_id")
        if _time(item.get("observed_at")) is None or item.get("observed_at_precision") not in {"second", "millisecond"}:
            raise ValueError("Salad billing evidence requires a timezone-aware observed_at with second or millisecond precision")
        reference = item.get("source_reference", item.get("raw_reference"))
        if not _has_reference(reference):
            raise ValueError("Salad billing evidence requires a source_reference or raw_reference")
        clean = {**item, "amount": str(amount), "currency": "USD"}
        previous = normalized.get(evidence_id)
        if previous is not None and previous != clean:
            raise ValueError("conflicting Salad billing evidence records share one evidence_id")
        normalized[evidence_id] = clean
    return [normalized[key] for key in sorted(normalized)]


def reconcile_money(
    evidence: list[dict[str, Any]], snapshots: list[dict[str, Any]], *,
    active_worker_count_by_interval: dict[str, int] | None = None,
    billing_evidence: list[dict[str, Any]] | None = None,
    salad_billed_cost_usd: Any = None, salad_billing_evidence_id: str | None = None,
    salad_billing_attribution_id: str | None = None,
) -> dict[str, Any]:
    clean_evidence: list[dict[str, Any]] = []
    evidence_by_id: dict[str, dict[str, Any]] = {}
    totals: dict[str, dict[str, Decimal]] = {stage: {} for stage in REVENUE_EVIDENCE_STAGES}
    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError("each monetary evidence record must be an object")
        evidence_id = item.get("evidence_id")
        stage = item.get("evidence_stage")
        amount = _amount(item.get("amount"), "amount")
        currency = item.get("currency")
        if not isinstance(evidence_id, str) or not evidence_id.strip() or not isinstance(currency, str) or not currency.strip():
            raise ValueError("evidence_id and currency are required")
        reference = item.get("source_reference", item.get("raw_reference"))
        if not ((isinstance(reference, str) and reference.strip()) or (isinstance(reference, dict) and reference)):
            raise ValueError("each monetary evidence record requires a source_reference or raw_reference")
        if stage not in REVENUE_EVIDENCE_STAGES:
            raise ValueError("evidence_stage must be one of the five frozen revenue stages")
        if stage == "converted" or "conversion" in item:
            conversion_status = _validate_conversion(item)
        else:
            conversion_status = None
        time_basis = _validate_observation_time(item, stage)
        fee_state = item.get("fee_inclusion_state")
        if fee_state is not None and fee_state not in {"included", "excluded", "partial", "unknown"}:
            raise ValueError("fee_inclusion_state is invalid")
        clean = {**item, "amount": str(amount), "evidence_stage": stage, "time_evidence_basis": time_basis}
        if conversion_status is not None:
            clean["conversion_reconciliation"] = conversion_status
        previous = evidence_by_id.get(evidence_id)
        if previous is not None:
            if previous != clean:
                raise ValueError("conflicting monetary evidence records share one evidence_id")
            continue
        evidence_by_id[evidence_id] = clean
        clean_evidence.append(clean)
        stage_totals = totals[stage]
        if conversion_status is not None and conversion_status["status"] == "UNRECONCILED":
            continue
        stage_totals[currency] = stage_totals.get(currency, Decimal(0)) + amount

    snapshots_by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    snapshot_by_id: dict[str, dict[str, Any]] = {}
    for item in snapshots:
        if not isinstance(item, dict):
            raise ValueError("each balance snapshot must be an object")
        amount = _amount(item.get("amount"), "snapshot.amount")
        if amount < 0:
            raise ValueError("balance snapshot amount must be nonnegative")
        observed = _time(item.get("observed_at"))
        required = (item.get("snapshot_id"), item.get("account_id"), item.get("currency"), item.get("evidence_stage"))
        if any(not isinstance(value, str) or not value for value in required) or observed is None:
            raise ValueError("balance snapshots require id, account, currency, stage, and timezone-aware observed_at")
        reference = item.get("source_reference", item.get("raw_reference"))
        if not ((isinstance(reference, str) and reference.strip()) or (isinstance(reference, dict) and reference)):
            raise ValueError("each balance snapshot requires a source_reference or raw_reference")
        if item["evidence_stage"] not in {"pool_observed", "paid", "converted", "realized"}:
            raise ValueError("balance snapshot stage must represent observed balance evidence")
        scope = item.get("scope", "account")
        if scope not in {"account", "worker"}:
            raise ValueError("snapshot scope must be account or worker")
        if scope == "worker" and (not isinstance(item.get("worker_id"), str) or not item["worker_id"]):
            raise ValueError("worker-scoped snapshot requires worker_id")
        key = (item["account_id"], item.get("worker_id") if scope == "worker" else None, item["currency"], item["evidence_stage"], scope)
        normalized = {**item, "amount": str(amount), "_time": observed, "scope": scope}
        prior_snapshot = snapshot_by_id.get(item["snapshot_id"])
        if prior_snapshot is not None:
            comparable_prior = {name: value for name, value in prior_snapshot.items() if name != "_time"}
            comparable_current = {name: value for name, value in normalized.items() if name != "_time"}
            if comparable_prior != comparable_current:
                raise ValueError("conflicting balance snapshots share one snapshot_id")
            continue
        snapshot_by_id[item["snapshot_id"]] = normalized
        snapshots_by_key.setdefault(key, []).append(normalized)

    deltas: list[dict[str, Any]] = []
    worker_counts = active_worker_count_by_interval or {}
    for key, items in sorted(snapshots_by_key.items(), key=lambda pair: str(pair[0])):
        items.sort(key=lambda item: (item["_time"], item["snapshot_id"]))
        for previous, current in zip(items, items[1:]):
            delta = Decimal(current["amount"]) - Decimal(previous["amount"])
            start = previous["_time"]
            end = current["_time"]
            interval_key = f"{previous['observed_at']}..{current['observed_at']}"
            worker_count = worker_counts.get(interval_key)
            identity_matches = all(
                previous.get(name) == current.get(name) and isinstance(current.get(name), str) and bool(current.get(name))
                for name in ("run_id", "segment_id")
            )
            if delta < 0:
                attribution_status = "unresolved_balance_decrease_or_adjustment"
                attributed = None
            elif end <= start:
                attribution_status = "unresolved_nonpositive_balance_interval"
                attributed = None
            elif not identity_matches:
                attribution_status = "unresolved_missing_or_changed_session_identity"
                attributed = None
            elif key[-1] == "account" and (not isinstance(worker_count, int) or isinstance(worker_count, bool) or worker_count != 1):
                attribution_status = "unresolved_account_scope_multiple_or_unknown_workers"
                attributed = None
            elif key[-1] == "worker" and not current.get("worker_id"):
                attribution_status = "unresolved_missing_worker_identity"
                attributed = None
            else:
                attribution_status = "attributed_to_bounded_session_interval"
                attributed = str(delta)
            deltas.append({
                "account_id": current["account_id"],
                "worker_id": current.get("worker_id"),
                "currency": current["currency"],
                "evidence_stage": current["evidence_stage"],
                "from_snapshot_id": previous["snapshot_id"],
                "to_snapshot_id": current["snapshot_id"],
                "interval_start": previous["observed_at"],
                "interval_end": current["observed_at"],
                "delta_amount": str(delta),
                "attributed_amount": attributed,
                "attribution_status": attribution_status,
                "run_id": current.get("run_id"),
                "segment_id": current.get("segment_id"),
            })

    stage_summaries = {
        stage: {currency: str(amount) for currency, amount in sorted(values.items())}
        for stage, values in totals.items()
    }
    billing_cost_candidate = None if salad_billed_cost_usd is None else _amount(salad_billed_cost_usd, "salad_billed_cost_usd")
    if billing_cost_candidate is not None and billing_cost_candidate < 0:
        raise ValueError("salad_billed_cost_usd must be nonnegative")
    clean_billing_evidence = _normalize_billing_evidence(billing_evidence or [])
    billing_by_id = {item["evidence_id"]: item for item in clean_billing_evidence}
    billing_record = billing_by_id.get(salad_billing_evidence_id) if salad_billing_evidence_id else None
    billing_status = "UNKNOWN_BILLING_EVIDENCE_NOT_PROVIDED"
    billing_cost = None
    if salad_billing_evidence_id and billing_record is None:
        billing_status = "UNKNOWN_BILLING_EVIDENCE_ID_NOT_FOUND"
    elif billing_record is not None:
        if not isinstance(salad_billing_attribution_id, str) or not salad_billing_attribution_id:
            billing_status = "UNKNOWN_BILLING_ATTRIBUTION_NOT_PROVIDED"
        elif billing_record["attribution_id"] != salad_billing_attribution_id:
            billing_status = "UNRECONCILED_BILLING_ATTRIBUTION_MISMATCH"
        elif billing_cost_candidate is not None and billing_cost_candidate != _amount(billing_record["amount"], "billing_evidence.amount"):
            billing_status = "UNRECONCILED_BILLING_AMOUNT_MISMATCH"
        else:
            billing_status = "MATCHED_BILLING_RECORD_AND_ATTRIBUTION"
            billing_cost = _amount(billing_record["amount"], "billing_evidence.amount")
    elif billing_cost_candidate is not None:
        billing_status = "UNKNOWN_COST_WITHOUT_BILLING_RECORD"

    realized_matches = [
        item for item in clean_evidence
        if item["evidence_stage"] == "realized"
        and item["currency"] == "USD"
        and item.get("attribution_id") == salad_billing_attribution_id
        and salad_billing_attribution_id
        and item.get("fee_inclusion_state") == "included"
        and item.get("conversion_reconciliation", {}).get("status") != "UNRECONCILED"
    ]
    realized_usd = sum((_amount(item["amount"], "realized.amount") for item in realized_matches), Decimal(0))
    pnl_known = billing_cost is not None and billing_status == "MATCHED_BILLING_RECORD_AND_ATTRIBUTION" and bool(realized_matches)
    clean_evidence.sort(key=lambda item: (item["evidence_stage"], item["currency"], item["evidence_id"]))
    normalized_snapshots = [
        {name: value for name, value in item.items() if name != "_time"}
        for group in snapshots_by_key.values()
        for item in group
    ]
    normalized_snapshots.sort(key=lambda item: (
        item["account_id"], item.get("scope", "account"), item.get("worker_id") or "",
        item["currency"], item["evidence_stage"], item["observed_at"], item["snapshot_id"],
    ))
    return {
        "schema_version": V2_SCHEMA_VERSION,
        "money_evidence": clean_evidence,
        "stage_totals_non_additive": stage_summaries,
        "balance_snapshots": normalized_snapshots,
        "balance_deltas": deltas,
        "salad_billed_cost_usd": str(billing_cost) if billing_cost is not None else None,
        "salad_billed_cost_candidate_usd": str(billing_cost_candidate) if billing_cost_candidate is not None else None,
        "salad_billing_evidence_id": salad_billing_evidence_id,
        "salad_billing_evidence": clean_billing_evidence,
        "salad_billing_evidence_status": billing_status,
        "unreconciled_conversion_evidence_ids": sorted(
            item["evidence_id"] for item in clean_evidence
            if item.get("conversion_reconciliation", {}).get("status") == "UNRECONCILED"
        ),
        "realized_usd_for_billing_attribution": str(realized_usd) if realized_matches else None,
        "actual_profit_loss_usd": str(realized_usd - billing_cost) if pnl_known and billing_cost is not None else None,
        "actual_profit_loss_status": "COMPUTABLE_FROM_MATCHED_BILLING_AND_REALIZED_EVIDENCE" if pnl_known else "UNKNOWN_REQUIRES_MATCHED_BILLING_RECORD_AND_REALIZED_PAYMENT_EVIDENCE",
        "fee_subtractions_performed": False,
        "money_stages_added_together": False,
    }
