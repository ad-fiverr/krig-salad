"""Evidence-gated dry-run rankings for observed work and economic profit."""

from __future__ import annotations

import math
from decimal import Decimal, InvalidOperation
from collections import defaultdict
from datetime import datetime
from typing import Any, Mapping

from .guards import evaluate_economics


_NUMERIC_FIELDS = (
    "observed_hashrate_ths",
    "rental_usd_per_hour",
    "target_profit_over_rental_cost_fraction",
    "observed_productive_ratio",
    "net_revenue_usd_per_ths_hour",
)
_EVIDENCE_KINDS = ("salad_billing", "rental_price", "productive_ratio", "pool_revenue")
_REVENUE_STAGES = {"estimated", "pool_observed", "paid", "converted", "realized"}
_OBSERVED_DEVICE_SEMANTICS = {"krig_device_reported", "fl4shminer_device_reported"}


def _evidence_provenance(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        return {}
    return {
        kind: {
            key: evidence[kind].get(key)
            for key in ("evidence_id", "attribution_id", "observed_at", "freshness", "source_reference")
            if isinstance(evidence.get(kind), Mapping) and evidence[kind].get(key) is not None
        }
        for kind in _EVIDENCE_KINDS
        if isinstance(evidence.get(kind), Mapping)
    }


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _same_number(left: Any, right: Any, *, tolerance: float = 1e-9) -> bool:
    a = _finite(left)
    b = _finite(right)
    return a is not None and b is not None and math.isclose(a, b, rel_tol=tolerance, abs_tol=tolerance)


def _aware_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _evidence_issue(record: Any, *, kind: str, attribution_id: str) -> str | None:
    if not isinstance(record, Mapping):
        return f"{kind}_evidence_missing"
    evidence_id = record.get("evidence_id")
    source_reference = record.get("source_reference")
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        return f"{kind}_evidence_id_missing"
    if record.get("status") != "verified":
        return f"{kind}_evidence_not_verified"
    if record.get("attribution_id") != attribution_id:
        return f"{kind}_attribution_missing_or_mismatched"
    if not ((isinstance(source_reference, str) and source_reference.strip()) or (isinstance(source_reference, Mapping) and source_reference)):
        return f"{kind}_source_reference_missing"
    if not _aware_timestamp(record.get("observed_at")):
        return f"{kind}_timestamp_missing_or_untrusted"
    freshness = record.get("freshness")
    if freshness not in {"fresh", "historical"}:
        return f"{kind}_freshness_unknown"
    return None


def evaluate_economic_profit(machine: Mapping[str, Any]) -> dict[str, Any]:
    attribution_id = machine.get("attribution_id")
    evidence = machine.get("economic_evidence")
    issues: list[str] = []
    if not isinstance(attribution_id, str) or not attribution_id.strip():
        issues.append("attribution_id_missing")
        attribution_id = ""
    if not isinstance(evidence, Mapping):
        evidence = {}
    for kind in _EVIDENCE_KINDS:
        issue = _evidence_issue(evidence.get(kind), kind=kind, attribution_id=attribution_id)
        if issue:
            issues.append(issue)

    values = {name: _finite(machine.get(name)) for name in _NUMERIC_FIELDS}
    issues.extend(f"{name}_missing_or_invalid" for name, value in values.items() if value is None)
    if values["observed_productive_ratio"] is not None and not 0 <= values["observed_productive_ratio"] <= 1:
        issues.append("observed_productive_ratio_out_of_range")
    if values["rental_usd_per_hour"] is not None and values["rental_usd_per_hour"] < 0:
        issues.append("rental_usd_per_hour_out_of_range")
    if values["observed_hashrate_ths"] is not None and values["observed_hashrate_ths"] < 0:
        issues.append("observed_hashrate_ths_out_of_range")
    if values["net_revenue_usd_per_ths_hour"] is not None and values["net_revenue_usd_per_ths_hour"] < 0:
        issues.append("net_revenue_usd_per_ths_hour_out_of_range")

    billing = evidence.get("salad_billing")
    price = evidence.get("rental_price")
    productive = evidence.get("productive_ratio")
    pool = evidence.get("pool_revenue")
    if all(isinstance(item, Mapping) for item in (billing, price, productive, pool)):
        billing_seconds = _finite(billing.get("billed_seconds"))
        billing_amount = _finite(billing.get("amount_usd"))
        price_rate = _finite(price.get("rental_usd_per_hour"))
        productive_seconds = _finite(productive.get("productive_seconds"))
        productive_billed_seconds = _finite(productive.get("billed_seconds"))
        productive_value = _finite(productive.get("value"))
        pool_rate = _finite(pool.get("net_revenue_usd_per_ths_hour"))
        if billing_seconds is None or billing_seconds <= 0 or billing_amount is None or billing_amount < 0:
            issues.append("salad_billing_amount_or_duration_invalid")
        if price_rate is None or price_rate < 0:
            issues.append("rental_price_value_invalid")
        if productive_seconds is None or productive_billed_seconds is None or productive_billed_seconds <= 0 or productive_seconds < 0:
            issues.append("productive_ratio_duration_invalid")
        elif productive_value is None or not _same_number(productive_seconds / productive_billed_seconds, productive_value):
            issues.append("productive_ratio_not_reconciled_to_durations")
        if billing_seconds is not None and productive_billed_seconds is not None and not _same_number(billing_seconds, productive_billed_seconds):
            issues.append("productive_ratio_billing_duration_mismatch")
        if pool_rate is None or pool_rate < 0:
            issues.append("pool_revenue_rate_invalid")
        elif not _same_number(pool_rate, values["net_revenue_usd_per_ths_hour"]):
            issues.append("pool_revenue_rate_does_not_match_machine_input")
        if price_rate is not None and billing_seconds is not None and billing_amount is not None:
            expected_cost = price_rate * billing_seconds / 3600
            # Provider invoices may round to cents; the tolerance is explicit.
            if abs(expected_cost - billing_amount) > 0.0100001:
                issues.append("salad_billing_cost_not_reconciled_to_price")
        for kind, expected_field, expected_value in (
            ("rental_price", "rental_usd_per_hour", values["rental_usd_per_hour"]),
            ("productive_ratio", "value", values["observed_productive_ratio"]),
        ):
            record = evidence.get(kind)
            if isinstance(record, Mapping) and not _same_number(record.get(expected_field), expected_value):
                issues.append(f"{kind}_value_does_not_match_machine_input")
        if isinstance(pool, Mapping):
            if pool.get("evidence_stage") not in _REVENUE_STAGES:
                issues.append("pool_revenue_stage_missing_or_invalid")
            if pool.get("fee_inclusion_state") not in {"included", "not_applicable"}:
                issues.append("pool_revenue_fee_inclusion_unknown")

    if issues:
        return {
            "profit_status": "UNKNOWN",
            "economic_guard": {"decision": "ECONOMICS_UNKNOWN", "reason": "required economic evidence is missing, unverified, or unreconciled", "details": {"unknown_reasons": sorted(set(issues))}},
            "net_profit_usd_per_billed_hour": None,
            "profit_basis_stage": None,
            "economic_evidence_provenance": _evidence_provenance(evidence),
        }

    margin = values["target_profit_over_rental_cost_fraction"]
    if margin is None or margin < 0:
        return {
            "profit_status": "UNKNOWN",
            "economic_guard": {"decision": "ECONOMICS_UNKNOWN", "reason": "target profit-over-cost policy is missing or invalid", "details": {"unknown_reasons": ["target_profit_over_rental_cost_fraction_missing_or_invalid"]}},
            "net_profit_usd_per_billed_hour": None,
            "profit_basis_stage": None,
            "economic_evidence_provenance": _evidence_provenance(evidence),
        }

    calculation = evaluate_economics(
        rental_usd_per_hour=values["rental_usd_per_hour"],
        target_profit_over_rental_cost_fraction=margin,
        observed_productive_ratio=values["observed_productive_ratio"],
        net_revenue_usd_per_ths_hour=values["net_revenue_usd_per_ths_hour"],
        observed_hashrate_ths=values["observed_hashrate_ths"],
    )
    revenue_rate = values["net_revenue_usd_per_ths_hour"] * values["observed_hashrate_ths"] * values["observed_productive_ratio"]
    profit_rate = revenue_rate - values["rental_usd_per_hour"]
    pool_stage = pool.get("evidence_stage")
    return {
        "profit_status": "ECONOMICS_VERIFIED",
        "economic_guard": calculation.to_dict(),
        "net_profit_usd_per_billed_hour": profit_rate,
        "profit_basis_stage": pool_stage,
        "economic_evidence_provenance": {
            kind: {
                "evidence_id": evidence[kind].get("evidence_id"),
                "attribution_id": evidence[kind].get("attribution_id"),
                "observed_at": evidence[kind].get("observed_at"),
                "freshness": evidence[kind].get("freshness"),
                "source_reference": evidence[kind].get("source_reference"),
            }
            for kind in _EVIDENCE_KINDS
        },
    }


def build_fleet_rankings(machines: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Rank comparable observed work separately from evidence-complete profit."""
    work_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    work_unranked: list[dict[str, Any]] = []
    economic_ranked: list[dict[str, Any]] = []
    economic_unknown: list[dict[str, Any]] = []

    for index, machine in enumerate(machines):
        machine_id = machine.get("machine_id") or f"unidentified-machine-{index + 1}"
        coin = machine.get("coin") if isinstance(machine.get("coin"), str) and machine.get("coin") else "UNKNOWN"
        algorithm = machine.get("algorithm") if isinstance(machine.get("algorithm"), str) and machine.get("algorithm") else "UNKNOWN"
        semantics = machine.get("hashrate_semantics")
        source = machine.get("hashrate_source")
        rate = _finite(machine.get("observed_hashrate_ths"))
        comparable_workload = (
            isinstance(machine.get("coin"), str) and bool(machine.get("coin").strip())
            and isinstance(machine.get("algorithm"), str) and bool(machine.get("algorithm").strip())
        )
        if (
            rate is not None and rate >= 0 and semantics in _OBSERVED_DEVICE_SEMANTICS
            and isinstance(source, str) and source.strip() and comparable_workload
        ):
            work_groups[(coin, algorithm)].append({
                "machine_id": machine_id,
                "observed_hashrate_ths": rate,
                "hashrate_semantics": semantics,
                "hashrate_source": source,
                "accepted_solution_count": machine.get("explicit_accepted_solution_count"),
                "rejected_solution_count": machine.get("explicit_rejected_solution_count"),
                "cumulative_stale_counters": machine.get("cumulative_stale_counter_observations", []),
                "provenance": machine.get("work_provenance", {}),
                "gpu_identity": machine.get("gpu_identity", {}),
                "hash_health": machine.get("hash_health", "UNKNOWN"),
            })
        else:
            reason = "coin_or_algorithm_missing_for_comparison" if rate is not None and semantics in _OBSERVED_DEVICE_SEMANTICS else "no compatible observed device-hashrate sample"
            work_unranked.append({"machine_id": machine_id, "status": "UNKNOWN", "reason": reason, "observed_hashrate_ths": rate, "hashrate_semantics": semantics, "hashrate_source": source})

        evaluation = evaluate_economic_profit(machine)
        item = {"machine_id": machine_id, "economic_guard": evaluation["economic_guard"], "actions_performed": False}
        item["economic_evidence_provenance"] = evaluation["economic_evidence_provenance"]
        if evaluation["profit_status"] == "ECONOMICS_VERIFIED":
            item.update({
                "profit_status": evaluation["profit_status"],
                "profit_basis_stage": evaluation["profit_basis_stage"],
                "net_profit_usd_per_billed_hour": evaluation["net_profit_usd_per_billed_hour"],
                "economic_evidence_provenance": evaluation["economic_evidence_provenance"],
            })
            economic_ranked.append(item)
        else:
            item.update({"profit_status": "UNKNOWN", "rank_exclusion_reason": evaluation["economic_guard"]["details"].get("unknown_reasons", [])})
            economic_unknown.append(item)

    observed_rankings: list[dict[str, Any]] = []
    for (coin, algorithm), entries in sorted(work_groups.items()):
        ordered = sorted(entries, key=lambda item: (-item["observed_hashrate_ths"], str(item["machine_id"])))
        observed_rankings.append({
            "coin": coin,
            "algorithm": algorithm,
            "unit": "TH/s",
            "machines": [{"rank": rank, **item} for rank, item in enumerate(ordered, start=1)],
        })
    economic_ranked.sort(key=lambda item: (-item["net_profit_usd_per_billed_hour"], str(item["machine_id"])))
    for rank, item in enumerate(economic_ranked, start=1):
        item["rank"] = rank

    return {
        "schema_version": "2.0",
        "mode": "dry_run_only",
        "observed_work_rankings": observed_rankings,
        "observed_work_unranked": work_unranked,
        "economic_profit_rankings": economic_ranked,
        "economic_profit_unknown": economic_unknown,
        "actions_performed": False,
    }


def _decimal_amount(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        return None
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        return None
    return amount if amount.is_finite() and amount >= 0 else None


def summarize_fleet(record: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize a shared worker and its Salad assignments without per-GPU revenue fiction."""
    fleet_id = record.get("fleet_id")
    worker_id = record.get("worker_id")
    if not isinstance(fleet_id, str) or not fleet_id.strip():
        raise ValueError("fleet summary requires fleet_id")
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ValueError("fleet summary requires worker_id")

    assignments = record.get("assignments", [])
    if not isinstance(assignments, list) or any(not isinstance(item, Mapping) for item in assignments):
        raise ValueError("assignments must be an array of objects")
    assignment_history = []
    failed_costs: list[Decimal] = []
    failed_cost_unknown: list[str] = []
    for index, assignment in enumerate(assignments, start=1):
        assignment_id = assignment.get("assignment_id")
        if not isinstance(assignment_id, str) or not assignment_id.strip():
            assignment_id = f"unidentified-assignment-{index}"
        status = str(assignment.get("status") or "UNKNOWN").casefold()
        is_failed = status in {"failed", "startup_failed", "preempted", "lost"}
        evidence = assignment.get("billing_evidence")
        cost_amount: Decimal | None = None
        if isinstance(evidence, Mapping):
            candidate = _decimal_amount(evidence.get("amount_usd"))
            compatible = (
                evidence.get("status") == "verified"
                and evidence.get("assignment_id") == assignment_id
                and evidence.get("currency") == "USD"
                and isinstance(evidence.get("evidence_id"), str) and bool(evidence.get("evidence_id"))
                and isinstance(evidence.get("source_reference"), str) and bool(evidence.get("source_reference"))
            )
            if compatible:
                cost_amount = candidate
        if is_failed:
            if cost_amount is None:
                failed_cost_unknown.append(assignment_id)
            else:
                failed_costs.append(cost_amount)
        assignment_history.append({
            "assignment_id": assignment_id,
            "allocation_id": assignment.get("allocation_id"),
            "machine_id": assignment.get("machine_id"),
            "instance_id": assignment.get("instance_id"),
            "status": status,
            "started_at_utc": assignment.get("started_at_utc"),
            "ended_at_utc": assignment.get("ended_at_utc"),
            "replaces_assignment_id": assignment.get("replaces_assignment_id"),
            "failed_assignment_cost_usd": str(cost_amount) if is_failed and cost_amount is not None else None,
            "failed_assignment_cost_status": "VERIFIED" if is_failed and cost_amount is not None else ("UNKNOWN" if is_failed else "NOT_APPLICABLE"),
            "billing_status": "VERIFIED" if cost_amount is not None else "UNKNOWN",
        })

    if failed_cost_unknown:
        failed_cost_total: str | None = None
        failed_cost_status = "UNKNOWN"
    else:
        failed_cost_total = str(sum(failed_costs, Decimal("0")))
        failed_cost_status = "VERIFIED" if failed_costs else "NO_FAILED_ASSIGNMENTS"

    rate_rows = record.get("device_hashrate_observations", [])
    if not isinstance(rate_rows, list) or any(not isinstance(item, Mapping) for item in rate_rows):
        raise ValueError("device_hashrate_observations must be an array of objects")
    work_groups: dict[tuple[str, str, str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    work_unresolved: list[dict[str, Any]] = []
    seen_devices: set[tuple[Any, ...]] = set()
    for item in rate_rows:
        coin = item.get("coin")
        algorithm = item.get("algorithm")
        semantics = item.get("hashrate_semantics")
        source = item.get("hashrate_source")
        rate = _finite(item.get("hashrate_ths"))
        machine_id = item.get("machine_id")
        device_ns = item.get("device_namespace")
        device_id = item.get("device_id")
        start = item.get("window_start_utc")
        end = item.get("window_end_utc")
        valid = (
            isinstance(coin, str) and bool(coin.strip())
            and isinstance(algorithm, str) and bool(algorithm.strip())
            and semantics in _OBSERVED_DEVICE_SEMANTICS
            and isinstance(source, str) and bool(source.strip())
            and rate is not None and rate >= 0
            and isinstance(machine_id, str) and bool(machine_id.strip())
            and isinstance(device_ns, str) and bool(device_ns.strip())
            and isinstance(device_id, (str, int)) and not isinstance(device_id, bool)
            and isinstance(start, str) and isinstance(end, str) and start < end
        )
        if not valid:
            work_unresolved.append({"machine_id": machine_id, "status": "UNKNOWN", "reason": "device_work_missing_comparable_window_or_provenance"})
            continue
        device_key = (machine_id, device_ns, str(device_id), start, end, coin, algorithm)
        if device_key in seen_devices:
            work_unresolved.append({"machine_id": machine_id, "status": "UNKNOWN", "reason": "duplicate_device_window_observation_not_summed"})
            continue
        seen_devices.add(device_key)
        work_groups[(coin.strip(), algorithm.strip(), semantics, start, end)].append(item)
    combined_work = []
    for (coin, algorithm, semantics, start, end), rows in sorted(work_groups.items()):
        combined_work.append({
            "coin": coin,
            "algorithm": algorithm,
            "hashrate_semantics": semantics,
            "window_start_utc": start,
            "window_end_utc": end,
            "observed_hashrate_ths": math.fsum(float(row["hashrate_ths"]) for row in rows),
            "device_count": len(rows),
            "machine_ids": sorted({str(row["machine_id"]) for row in rows}),
            "hashrate_sources": sorted({str(row["hashrate_source"]) for row in rows}),
            "status": "OBSERVED_WORK_ONLY",
        })

    revenue_rows = record.get("worker_btc_evidence", [])
    if not isinstance(revenue_rows, list) or any(not isinstance(item, Mapping) for item in revenue_rows):
        raise ValueError("worker_btc_evidence must be an array of objects")
    btc_totals = {"pool_observed": Decimal("0"), "paid": Decimal("0")}
    btc_evidence_ids: dict[str, list[str]] = {"pool_observed": [], "paid": []}
    btc_unknown_stages: set[str] = set()
    for item in revenue_rows:
        amount = _decimal_amount(item.get("amount"))
        stage = item.get("evidence_stage")
        valid = (
            amount is not None
            and item.get("worker_id") == worker_id
            and item.get("currency") == "BTC"
            and item.get("status") == "verified"
            and stage in {"pool_observed", "paid"}
            and isinstance(item.get("evidence_id"), str) and bool(item.get("evidence_id"))
            and isinstance(item.get("source_reference"), str) and bool(item.get("source_reference"))
            and _aware_timestamp(item.get("observed_at"))
        )
        if valid:
            btc_totals[stage] += amount
            btc_evidence_ids[stage].append(item["evidence_id"])
        else:
            if stage in btc_unknown_stages or stage not in btc_totals:
                btc_unknown_stages.add("unknown")
            else:
                btc_unknown_stages.add(stage)

    revenue_usd: dict[tuple[str, str], Decimal] = {}
    for item in record.get("worker_usd_revenue_evidence", []) if isinstance(record.get("worker_usd_revenue_evidence", []), list) else []:
        if not isinstance(item, Mapping):
            continue
        amount = _decimal_amount(item.get("amount_usd"))
        if (
            amount is not None and item.get("worker_id") == worker_id and item.get("status") == "verified"
            and item.get("evidence_stage") == "realized"
            and isinstance(item.get("evidence_id"), str) and isinstance(item.get("source_reference"), str)
            and _aware_timestamp(item.get("window_start_utc")) and _aware_timestamp(item.get("window_end_utc"))
        ):
            revenue_usd[(item["window_start_utc"], item["window_end_utc"])] = revenue_usd.get((item["window_start_utc"], item["window_end_utc"]), Decimal("0")) + amount

    billing_usd: dict[tuple[str, str], Decimal] = {}
    for item in record.get("fleet_billing_evidence", []) if isinstance(record.get("fleet_billing_evidence", []), list) else []:
        if not isinstance(item, Mapping):
            continue
        amount = _decimal_amount(item.get("amount_usd"))
        if (
            amount is not None and item.get("fleet_id") == fleet_id and item.get("status") == "verified"
            and isinstance(item.get("evidence_id"), str) and isinstance(item.get("source_reference"), str)
            and _aware_timestamp(item.get("window_start_utc")) and _aware_timestamp(item.get("window_end_utc"))
        ):
            key = (item["window_start_utc"], item["window_end_utc"])
            billing_usd[key] = billing_usd.get(key, Decimal("0")) + amount

    net_results = []
    for window in sorted(set(revenue_usd) & set(billing_usd)):
        net_results.append({
            "window_start_utc": window[0],
            "window_end_utc": window[1],
            "revenue_usd": str(revenue_usd[window]),
            "billing_cost_usd": str(billing_usd[window]),
            "net_profit_usd": str(revenue_usd[window] - billing_usd[window]),
            "status": "RECONCILED",
        })
    economic_status = "RECONCILED" if net_results else "UNKNOWN"

    return {
        "schema_version": "2.0",
        "mode": "offline_dry_run",
        "fleet_id": fleet_id,
        "worker_id": worker_id,
        "assignments": assignment_history,
        "failed_assignment_costs": {
            "amount_usd": failed_cost_total,
            "status": failed_cost_status,
            "unknown_assignment_ids": failed_cost_unknown,
        },
        "observed_hashrate_by_coin_algorithm_window": combined_work,
        "observed_hashrate_unresolved": work_unresolved,
        "worker_btc_revenue": {
            "amount_btc_by_stage": {
                stage: str(btc_totals[stage]) if btc_evidence_ids[stage] and stage not in btc_unknown_stages else None
                for stage in ("pool_observed", "paid")
            },
            "evidence_ids_by_stage": {stage: sorted(ids) for stage, ids in btc_evidence_ids.items()},
            "status_by_stage": {
                stage: "VERIFIED" if btc_evidence_ids[stage] and stage not in btc_unknown_stages else "UNKNOWN"
                for stage in ("pool_observed", "paid")
            },
            "status": "VERIFIED" if any(btc_evidence_ids[stage] for stage in btc_evidence_ids) and not btc_unknown_stages else "UNKNOWN",
            "attribution_scope": "fleet_worker",
            "machine_level_distribution": "NOT_DISTRIBUTED",
        },
        "net_profit_by_compatible_window": net_results,
        "economic_reconciliation_status": economic_status,
        "actions_performed": False,
    }
