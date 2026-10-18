"""Read-only dashboard projections built on the existing fleet ledger rules."""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

from .fleet import summarize_fleet
from .v2_adapters import normalize_v2_evaluation, normalize_v2_track


def project_device(
    track: Mapping[str, Any],
    evaluation: Mapping[str, Any] | None = None,
    *,
    provider_observation: Mapping[str, Any] | None = None,
    binding: Mapping[str, Any] | None = None,
    action_context: Mapping[str, Any] | None = None,
    economic_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_track = normalize_v2_track(track)
    selected_evaluation = evaluation if isinstance(evaluation, Mapping) else normalized_track.get("last_evaluation")
    evaluation = normalize_v2_evaluation(selected_evaluation) if isinstance(selected_evaluation, Mapping) else {}
    health = normalized_track.get("hash_health") or evaluation.get("hash_health") or "UNKNOWN"
    performance = {
        "MEETS_CONFIGURED_FLOOR": "HEALTHY",
        "BELOW_CONFIGURED_FLOOR": "UNDERPERFORMING",
    }.get(str(health), "UNKNOWN")
    raw_decision = str(evaluation.get("decision") or track.get("last_decision") or "").upper()
    evaluation_matches_track = all(
        evaluation.get(key) == normalized_track.get(key)
        for key in ("track_id", "assignment_id", "allocation_id", "machine_id", "instance_id", "device_namespace", "device_id")
    )
    if normalized_track.get("track_active") is not True:
        action_state = "NOT_ELIGIBLE"
    elif raw_decision == "WOULD_REALLOCATE" and evaluation_matches_track and evaluation.get("track_active") is True:
        action_state = "CANDIDATE"
    elif raw_decision in {"WOULD_REALLOCATE", "WOULD_WAIT", "WOULD_STOP"}:
        action_state = "BLOCKED" if not evaluation_matches_track else "NOT_ELIGIBLE"
    else:
        action_state = "DISABLED"
    hardware = "UNKNOWN"
    diagnostic = normalized_track.get("hardware_diagnostic")
    if isinstance(diagnostic, Mapping) and diagnostic.get("status") in {"SUSPECTED_FAULT", "CONFIRMED_FAULT"}:
        # An independently supplied diagnostic must carry its own provenance;
        # hash performance alone never changes hardware condition.
        if isinstance(diagnostic.get("evidence_id"), str) and diagnostic["evidence_id"].strip() and isinstance(diagnostic.get("source"), str) and diagnostic["source"].strip():
            hardware = diagnostic["status"]
    quality = evaluation.get("sample_quality")
    provider = dict(provider_observation) if isinstance(provider_observation, Mapping) else {}
    binding_record = dict(binding) if isinstance(binding, Mapping) else {}
    action_record = dict(action_context) if isinstance(action_context, Mapping) else {}
    economics = dict(economic_summary) if isinstance(economic_summary, Mapping) else {}
    return {
        "schema_version": "1.0",
        "track_id": normalized_track.get("track_id"),
        "fleet_id": normalized_track.get("fleet_id"),
        "worker_id": normalized_track.get("worker_id"),
        "allocation_id": normalized_track.get("allocation_id"),
        "assignment_id": normalized_track.get("assignment_id"),
        "machine_id": normalized_track.get("machine_id"),
        "instance_id": normalized_track.get("instance_id"),
        "device_namespace": normalized_track.get("device_namespace"),
        "device_id": normalized_track.get("device_id"),
        "track_active": normalized_track.get("track_active"),
        "closed_at_utc": normalized_track.get("closed_at_utc"),
        "terminal_reason": normalized_track.get("terminal_reason"),
        "gpu_identity": normalized_track.get("gpu_identity") or evaluation.get("gpu_identity") or {},
        "performance_status": performance,
        "hardware_status": hardware,
        "action_status": action_state,
        "action_execution": "DISABLED",
        "hash_health": health,
        "gpu_floor_ths": evaluation.get("gpu_floor_ths"),
        "observed_window_hashrate_ths": evaluation.get("observed_window_hashrate_ths"),
        "sample_quality": dict(quality) if isinstance(quality, Mapping) else {},
        "billing_status": "UNKNOWN",
        "profit_status": "UNKNOWN",
        "provider_observation": {
            "container_group": provider.get("container_group"),
            "instance_id": provider.get("instance_id"),
            "machine_id": provider.get("machine_id"),
            "reported_state": provider.get("state"),
            "observed_at_utc": provider.get("observed_at_utc"),
            "freshness": provider.get("freshness", "UNKNOWN"),
            "data_classification": provider.get("data_classification", "UNKNOWN"),
            "attribution_to_track": "UNKNOWN",
        },
        "binding": {
            "binding_status": binding_record.get("binding_status", "UNKNOWN"),
            "reason": binding_record.get("reason", "no independent binding evidence"),
            "actions_authorized_by_binding": binding_record.get("actions_authorized_by_binding") is True,
        },
        "cooldown": action_record.get("cooldown", "UNKNOWN"),
        "budget": {
            "status": economics.get("budget_status", "UNKNOWN"),
            "hard_budget_cap_usd": economics.get("hard_budget_cap_usd"),
            "verified_spend_usd": economics.get("verified_spend_usd"),
            "next_action_cost_usd": economics.get("next_action_cost_usd"),
        },
        "action_gate": {
            "status": action_record.get("status", "DISABLED"),
            "blockers": list(action_record.get("blockers", [])) if isinstance(action_record.get("blockers", []), (list, tuple)) else [],
        },
        "last_evaluation": dict(evaluation) if evaluation else None,
        "actions_performed": False,
    }


def project_fleet(record: Mapping[str, Any], *, device_projections: list[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Use V1/V2 fleet accounting; BTC remains at shared-worker scope."""
    accounting = summarize_fleet(record)
    stages = accounting["worker_btc_revenue"]
    devices = [dict(item) for item in (device_projections or [])]
    net_windows = []
    for window in accounting["net_profit_by_compatible_window"]:
        projected_window = dict(window)
        try:
            profit = Decimal(str(window["net_profit_usd"]))
            billed_cost = Decimal(str(window["billing_cost_usd"]))
            fraction = profit / billed_cost if billed_cost > 0 else None
            if fraction is not None and not fraction.is_finite():
                fraction = None
        except (InvalidOperation, KeyError, TypeError, ValueError, ZeroDivisionError):
            fraction = None
        projected_window["observed_net_profit_over_billed_cost_fraction"] = str(fraction) if fraction is not None else None
        projected_window["observed_net_profit_over_billed_cost_status"] = "VERIFIED" if fraction is not None else "UNKNOWN"
        net_windows.append(projected_window)
    return {
        "schema_version": "1.0",
        "fleet_id": accounting["fleet_id"],
        "worker_id": accounting["worker_id"],
        "assignments": accounting["assignments"],
        "devices": devices,
        "observed_hashrate_by_coin_algorithm_window": accounting["observed_hashrate_by_coin_algorithm_window"],
        "observed_hashrate_unresolved": accounting["observed_hashrate_unresolved"],
        "worker_revenue": {
            "pool_observed_btc": stages["amount_btc_by_stage"]["pool_observed"],
            "pool_observed_status": stages["status_by_stage"]["pool_observed"],
            "paid_btc": stages["amount_btc_by_stage"]["paid"],
            "paid_status": stages["status_by_stage"]["paid"],
            "converted": {"amount": None, "currency": None, "status": "UNKNOWN"},
            "realized": {
                "status": "RECONCILED" if accounting["economic_reconciliation_status"] == "RECONCILED" else "UNKNOWN",
                "windows": net_windows,
            },
            "attribution_scope": "fleet_worker",
            "machine_level_distribution": "NOT_DISTRIBUTED",
        },
        "failed_assignment_costs": accounting["failed_assignment_costs"],
        "net_profit_by_compatible_window": net_windows,
        "economic_reconciliation_status": accounting["economic_reconciliation_status"],
        "profit_status": "VERIFIED" if accounting["economic_reconciliation_status"] == "RECONCILED" else "UNKNOWN",
        "actions_performed": False,
    }
