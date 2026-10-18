"""Fail-closed eligibility controller; G2 has no real action capability."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import math
from typing import Any

from .action_ledger import ActionLedger
from .gpu_identity import normalize_gpu_identity
from .guard_store import canonical_utc
from .live_contracts import OBSERVED_DEVICE_HASHRATES
from .v2_adapters import normalize_v2_evaluation


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(canonical_utc(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return None
    return float(value)


def _duration_seconds(start: Any, end: datetime) -> float | None:
    parsed = _time(start)
    return max(0.0, (end - parsed).total_seconds()) if parsed is not None else None


@dataclass(frozen=True)
class ReallocationPolicy:
    allowed_targets: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    gpu_floors_ths: Mapping[str, float] = field(default_factory=dict)
    policy_version: str = "1.0"
    maximum_telemetry_age_seconds: int = 30
    minimum_window_coverage_ratio: float = 0.8
    maximum_sample_gap_seconds: int = 30
    evaluation_max_age_seconds: int = 90
    cooldown_seconds: int | None = None
    maximum_per_assignment: int | None = None
    maximum_per_fleet: int | None = None
    budget_limit_usd: float | None = None
    action_enabled: bool = False
    g5_authorized: bool = False

    def __post_init__(self) -> None:
        if self.action_enabled or self.g5_authorized:
            raise ValueError("G2 does not implement or accept real reallocation authorization")
        if isinstance(self.maximum_telemetry_age_seconds, bool) or not isinstance(self.maximum_telemetry_age_seconds, int) or self.maximum_telemetry_age_seconds <= 0 or isinstance(self.evaluation_max_age_seconds, bool) or not isinstance(self.evaluation_max_age_seconds, int) or self.evaluation_max_age_seconds <= 0:
            raise ValueError("telemetry freshness windows must be positive")
        if isinstance(self.minimum_window_coverage_ratio, bool) or _number(self.minimum_window_coverage_ratio) is None or not 0 < self.minimum_window_coverage_ratio <= 1:
            raise ValueError("minimum coverage must be within (0, 1]")
        if isinstance(self.maximum_sample_gap_seconds, bool) or not isinstance(self.maximum_sample_gap_seconds, int) or self.maximum_sample_gap_seconds <= 0:
            raise ValueError("maximum sample gap must be positive")
        if self.cooldown_seconds is not None and (isinstance(self.cooldown_seconds, bool) or not isinstance(self.cooldown_seconds, int) or self.cooldown_seconds < 0):
            raise ValueError("cooldown must be a non-negative integer when configured")
        for name in ("maximum_per_assignment", "maximum_per_fleet"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise ValueError(f"{name} must be a non-negative integer when configured")
        if self.budget_limit_usd is not None and (_number(self.budget_limit_usd) is None or float(self.budget_limit_usd) <= 0):
            raise ValueError("budget_limit_usd must be positive when configured")
        if not isinstance(self.gpu_floors_ths, Mapping):
            raise ValueError("gpu_floors_ths must be the existing Guard V1/V2 floor map")


class ReallocationController:
    """Pure eligibility assessment plus atomic dry-run deduplication."""

    REQUIRED_TARGET_FIELDS = (
        "organization_id", "project_id", "container_group_id", "instance_id", "machine_id",
        "allocation_id", "assignment_id",
    )
    REQUIRED_EVIDENCE_FIELDS = (
        "track_id", "allocation_id", "assignment_id", "device_namespace", "device_id",
    )

    def __init__(self, policy: ReallocationPolicy, ledger: ActionLedger, *, guard_policy_hash: str):
        if not isinstance(guard_policy_hash, str) or not guard_policy_hash.strip():
            raise ValueError("the active ContinuousMonitor policy hash is required")
        self.policy = policy
        self.ledger = ledger
        self.guard_policy_hash = guard_policy_hash.strip()

    def assess(
        self,
        *,
        candidate: Mapping[str, Any],
        evaluations: list[Mapping[str, Any]],
        provider_revalidation: Mapping[str, Any],
        revalidated_sample: Mapping[str, Any],
        allocation_history: Mapping[str, Any],
        budget: Mapping[str, Any],
        now_utc: str,
        reserve_action: bool = True,
    ) -> dict[str, Any]:
        now = _time(now_utc)
        if now is None:
            raise ValueError("now_utc must be timezone-aware RFC3339")
        blockers: list[str] = []
        identity = candidate.get("gpu_identity") if isinstance(candidate.get("gpu_identity"), Mapping) else {}
        normalized = normalize_gpu_identity(
            identity.get("raw_model"),
            identity_source=identity.get("identity_source"),
            identity_verified=identity.get("identity_verified"),
            reported_form_factor=identity.get("form_factor"),
        )
        target = {key: candidate.get(key) for key in self.REQUIRED_TARGET_FIELDS}
        floor_key = "|".join((str(normalized.get("model") or ""), str(normalized.get("form_factor") or ""), str(normalized.get("identity_source") or "")))
        configured_floor = _number(self.policy.gpu_floors_ths.get(floor_key))
        candidate_floor = _number(candidate.get("gpu_floor_ths"))
        if configured_floor is None or candidate_floor is None or candidate_floor != configured_floor:
            blockers.append("candidate_floor_does_not_match_exact_policy")
        if not normalized["identity_verified"]:
            blockers.append("gpu_identity_not_verified")
        if any(
            not isinstance(candidate.get(key), str) or not candidate.get(key).strip()
            for key in ("track_id", "allocation_id", "assignment_id", "device_namespace")
        ) or candidate.get("device_id") is None or isinstance(candidate.get("device_id"), bool):
            blockers.append("candidate_device_assignment_identity_incomplete")
        if candidate.get("track_active") is not True:
            blockers.append("candidate_track_closed_or_not_verified_active")
        if candidate.get("guard_policy_hash") != self.guard_policy_hash:
            blockers.append("candidate_guard_policy_hash_mismatch")
        if any(not isinstance(value, str) or not value.strip() for value in target.values()):
            blockers.append("provider_target_identity_incomplete")
        allowlisted = any(
            all(item.get(key) == value for key, value in target.items())
            and item.get("gpu_model") == normalized.get("model")
            and item.get("form_factor") == normalized.get("form_factor")
            and item.get("identity_source") == normalized.get("identity_source")
            for item in self.policy.allowed_targets
            if isinstance(item, Mapping)
        )
        if not allowlisted:
            blockers.append("target_not_on_explicit_gpu_allowlist")

        sample_at = _time(revalidated_sample.get("occurred_at_utc") or revalidated_sample.get("observed_at_utc"))
        if sample_at is None or (now - sample_at).total_seconds() < 0 or (now - sample_at).total_seconds() > self.policy.maximum_telemetry_age_seconds:
            blockers.append("revalidated_miner_telemetry_missing_or_stale")
        sample_rate = _number(revalidated_sample.get("hashrate_ths"))
        sample_source = revalidated_sample.get("hashrate_source")
        if revalidated_sample.get("hashrate_semantics") not in OBSERVED_DEVICE_HASHRATES or sample_rate is None or not isinstance(sample_source, str) or not sample_source.strip():
            blockers.append("revalidated_hashrate_is_not_comparable_local_device_data")
        elif configured_floor is not None and sample_rate >= configured_floor:
            blockers.append("hashrate_recovered_during_immediate_revalidation")
        if revalidated_sample.get("machine_id") != target.get("machine_id") or revalidated_sample.get("instance_id") != target.get("instance_id"):
            blockers.append("revalidated_sample_assignment_identity_mismatch")
        if revalidated_sample.get("device_namespace") != candidate.get("device_namespace") or str(revalidated_sample.get("device_id")) != str(candidate.get("device_id")):
            blockers.append("revalidated_sample_device_identity_mismatch")
        sample_identity = revalidated_sample.get("gpu_identity") if isinstance(revalidated_sample.get("gpu_identity"), Mapping) else {}
        if (
            sample_identity.get("identity_verified") is not True
            or sample_identity.get("model") != normalized.get("model")
            or sample_identity.get("form_factor") != normalized.get("form_factor")
            or sample_identity.get("identity_source") != normalized.get("identity_source")
        ):
            blockers.append("revalidated_sample_gpu_identity_mismatch")
        if revalidated_sample.get("monitor_policy_hash") != self.guard_policy_hash:
            blockers.append("revalidated_sample_policy_hash_mismatch")
        for key in self.REQUIRED_EVIDENCE_FIELDS:
            expected = candidate.get(key)
            observed = revalidated_sample.get(key)
            if key == "device_id":
                matches = observed is not None and str(observed) == str(expected)
            else:
                matches = isinstance(expected, str) and expected and observed == expected
            if not matches:
                blockers.append(f"revalidated_sample_{key}_mismatch")
        provider_at = _time(provider_revalidation.get("occurred_at_utc"))
        if provider_at is None or (now - provider_at).total_seconds() < 0 or (now - provider_at).total_seconds() > self.policy.maximum_telemetry_age_seconds:
            blockers.append("provider_revalidation_missing_or_stale")
        reported_state = provider_revalidation.get("reported_state")
        if not isinstance(reported_state, str) or reported_state.casefold() != "running":
            blockers.append("provider_instance_not_confirmed_running")
        for key in self.REQUIRED_TARGET_FIELDS:
            snapshot_key = "container_group_id" if key == "container_group_id" else key
            if target.get(key) != provider_revalidation.get(snapshot_key):
                blockers.append(f"provider_revalidation_{key}_mismatch")
        if not isinstance(provider_revalidation.get("machine_id"), str) or not provider_revalidation.get("machine_id"):
            blockers.append("provider_machine_id_unverified")

        binding = provider_revalidation.get("target_binding") if isinstance(provider_revalidation.get("target_binding"), Mapping) else {}
        for key in self.REQUIRED_TARGET_FIELDS:
            if binding.get(key) != target.get(key):
                blockers.append(f"provider_target_binding_{key}_mismatch")
        for key in self.REQUIRED_EVIDENCE_FIELDS:
            expected = candidate.get(key)
            observed = binding.get(key)
            if key == "device_id":
                matches = observed is not None and str(observed) == str(expected)
            else:
                matches = isinstance(expected, str) and expected and observed == expected
            if not matches:
                blockers.append(f"provider_target_binding_{key}_mismatch")
        binding_identity = binding.get("gpu_identity") if isinstance(binding.get("gpu_identity"), Mapping) else {}
        if any(binding_identity.get(key) != normalized.get(key) for key in ("model", "form_factor", "identity_source", "identity_verified")):
            blockers.append("provider_target_binding_gpu_identity_mismatch")
        if binding.get("guard_policy_hash") != self.guard_policy_hash:
            blockers.append("provider_target_binding_policy_hash_mismatch")

        ordered = sorted(
            (normalize_v2_evaluation(item) for item in evaluations if isinstance(item, Mapping)),
            key=lambda item: str(item.get("evaluated_at_utc") or ""),
        )
        last_two = ordered[-2:]
        if len(last_two) != 2:
            blockers.append("two_consecutive_low_evaluations_required")
        else:
            timestamps = [_time(item.get("evaluated_at_utc")) for item in last_two]
            if any(value is None for value in timestamps) or timestamps[0] == timestamps[1]:
                blockers.append("evaluation_timestamps_invalid_or_duplicated")
            elif any((now - value).total_seconds() < 0 or (now - value).total_seconds() > self.policy.evaluation_max_age_seconds for value in timestamps if value is not None):
                blockers.append("low_evaluations_stale")
            for item in last_two:
                if item.get("policy_hash") != self.guard_policy_hash:
                    blockers.append("low_evaluations_policy_hash_missing_or_mismatched")
                if item.get("track_active") is not True:
                    blockers.append("evaluation_track_closed_or_not_verified_active")
                if item.get("deterioration_start_utc") != candidate.get("deterioration_start_utc"):
                    blockers.append("low_evaluations_do_not_share_current_deterioration")
                if item.get("hash_health") != "BELOW_CONFIGURED_FLOOR" or item.get("decision") not in {"WOULD_REALLOCATE", "WOULD_WAIT"}:
                    blockers.append("two_consecutive_low_evaluations_required")
                floor = _number(item.get("gpu_floor_ths"))
                observed = _number(item.get("observed_window_hashrate_ths"))
                quality = item.get("sample_quality") if isinstance(item.get("sample_quality"), Mapping) else {}
                coverage = _number(quality.get("coverage_ratio"))
                max_gap = _number(quality.get("maximum_observed_gap_seconds"))
                if floor is None or observed is None or observed >= floor:
                    blockers.append("evaluation_does_not_prove_below_floor")
                if coverage is None or coverage < self.policy.minimum_window_coverage_ratio:
                    blockers.append("evaluation_sample_coverage_insufficient")
                if max_gap is None or max_gap > self.policy.maximum_sample_gap_seconds:
                    blockers.append("evaluation_sample_gap_exceeds_policy")
                evaluated_identity = item.get("gpu_identity") if isinstance(item.get("gpu_identity"), Mapping) else {}
                if any(evaluated_identity.get(key) != normalized.get(key) for key in ("identity_verified", "model", "form_factor", "identity_source")):
                    blockers.append("evaluation_gpu_identity_mismatch")
                if item.get("machine_id") != target.get("machine_id") or item.get("instance_id") != target.get("instance_id"):
                    blockers.append("evaluation_assignment_identity_mismatch")
                if item.get("gpu_floor_ths") != configured_floor:
                    blockers.append("evaluation_floor_does_not_match_current_policy")
                for key in self.REQUIRED_EVIDENCE_FIELDS:
                    expected = candidate.get(key)
                    observed = item.get(key)
                    if key == "device_id":
                        matches = observed is not None and str(observed) == str(expected)
                    else:
                        matches = isinstance(expected, str) and expected and observed == expected
                    if not matches:
                        blockers.append(f"evaluation_{key}_mismatch")
            if len(timestamps) == 2 and all(value is not None for value in timestamps) and sample_at is not None and timestamps[-1] is not None and sample_at < timestamps[-1]:
                blockers.append("revalidated_sample_precedes_latest_low_evaluation")

        history_known = allocation_history.get("history_known") is True
        allocation_count = allocation_history.get("allocation_reallocation_count")
        fleet_count = allocation_history.get("fleet_reallocation_count")
        if not history_known or isinstance(allocation_count, bool) or not isinstance(allocation_count, int) or allocation_count < 0 or isinstance(fleet_count, bool) or not isinstance(fleet_count, int) or fleet_count < 0:
            blockers.append("reallocation_history_unknown")
        else:
            if self.policy.maximum_per_assignment is None or allocation_count >= self.policy.maximum_per_assignment:
                blockers.append("assignment_reallocation_limit_missing_or_reached")
            if self.policy.maximum_per_fleet is None or fleet_count >= self.policy.maximum_per_fleet:
                blockers.append("fleet_reallocation_limit_missing_or_reached")
        last_action = _time(allocation_history.get("last_reallocation_at_utc"))
        if self.policy.cooldown_seconds is None or self.policy.cooldown_seconds < 0:
            blockers.append("cooldown_policy_missing_or_invalid")
        if allocation_count and allocation_count > 0:
            if self.policy.cooldown_seconds is None or last_action is None:
                blockers.append("cooldown_cannot_be_verified")
            elif (now - last_action).total_seconds() < self.policy.cooldown_seconds:
                blockers.append("reallocation_cooldown_active")

        budget_limit = _number(self.policy.budget_limit_usd)
        spent = _number(budget.get("verified_spend_usd"))
        estimated_cost = _number(budget.get("verified_next_action_cost_usd"))
        pending_exposure = _number(budget.get("pending_exposure_usd"))
        maximum_exposure = _number(budget.get("maximum_exposure_usd"))
        spend_at = _time(budget.get("spend_observed_at_utc"))
        cost_at = _time(budget.get("next_action_cost_observed_at_utc"))
        valid_until = _time(budget.get("valid_until_utc"))
        budget_sources_valid = all(
            isinstance(budget.get(key), str) and bool(budget.get(key).strip())
            for key in (
                "spend_evidence_id", "spend_source_reference",
                "next_action_cost_evidence_id", "next_action_cost_source_reference",
                "pending_exposure_evidence_id", "maximum_exposure_evidence_id",
            )
        )
        budget_time_valid = all(value is not None and value <= now for value in (spend_at, cost_at)) and valid_until is not None and valid_until >= now
        exposure_status_valid = (
            budget.get("pending_exposure_status") == "VERIFIED"
            and budget.get("maximum_exposure_status") == "VERIFIED"
        )
        exposure_consistent = False
        if all(value is not None and value >= 0 for value in (spent, estimated_cost, pending_exposure, maximum_exposure)):
            try:
                expected_maximum = sum(Decimal(str(value)) for value in (spent, estimated_cost, pending_exposure))
                reported_maximum = Decimal(str(maximum_exposure))
                exposure_consistent = reported_maximum >= expected_maximum
            except (InvalidOperation, ValueError):
                exposure_consistent = False
        if (
            budget.get("status") != "VERIFIED"
            or budget.get("currency") != "USD"
            or budget_limit is None or budget_limit <= 0
            or spent is None or spent < 0
            or estimated_cost is None or estimated_cost < 0
            or pending_exposure is None or pending_exposure < 0
            or maximum_exposure is None or maximum_exposure < 0
            or not budget_sources_valid or not budget_time_valid
            or not exposure_status_valid or not exposure_consistent
        ):
            blockers.append("hard_budget_or_verified_spend_missing")
        elif spent + pending_exposure + estimated_cost > budget_limit or maximum_exposure > budget_limit:
            blockers.append("hard_budget_limit_reached")

        blockers = sorted(set(blockers))
        recommendation = {
            "target": target,
            "gpu_identity": normalized,
            "gpu_floor_ths": configured_floor,
            "deterioration_start_utc": candidate.get("deterioration_start_utc"),
            "evaluation_ids": [item.get("evaluation_id") or item.get("evaluated_at_utc") for item in last_two],
            "policy_version": self.policy.policy_version,
            "guard_policy_hash": self.guard_policy_hash,
            "actions_performed": False,
        }
        action_key = None
        if not blockers:
            allocation_generation = candidate.get("assignment_id")
            deterioration = candidate.get("deterioration_start_utc")
            if not isinstance(allocation_generation, str) or not allocation_generation or not isinstance(deterioration, str) or not deterioration:
                blockers.append("idempotency_generation_or_deterioration_missing")
            else:
                action_key = ActionLedger.key_for(
                    organization_id=target["organization_id"], project_id=target["project_id"],
                    container_group_id=target["container_group_id"], instance_id=target["instance_id"],
                    generation=allocation_generation, deterioration_id=deterioration,
                    policy_version=self.policy.policy_version,
                )
                if reserve_action:
                    try:
                        ledger_result = self.ledger.reserve(action_key, recommendation, now_utc)
                    except ValueError:
                        previous = self.ledger.get(action_key)
                        if previous is None:
                            raise
                        ledger_result = {**previous, "inserted": False}
                    recommendation["ledger_state"] = ledger_result["state"]
                    recommendation["deduplicated"] = not ledger_result["inserted"]
                    recommendation["reservation_status"] = ledger_result["state"] if ledger_result["inserted"] else (
                        "RECONCILIATION_REQUIRED" if ledger_result["state"] == "RECONCILIATION_REQUIRED" else "ALREADY_RESERVED"
                    )
                    if not ledger_result["inserted"]:
                        blockers.append("action_reservation_already_exists")
                        if ledger_result["state"] == "RECONCILIATION_REQUIRED":
                            blockers.append("action_reconciliation_required")
                else:
                    recommendation["ledger_state"] = "NOT_RESERVED_PREVIEW"
                    recommendation["deduplicated"] = False
                    recommendation["reservation_status"] = "NOT_RESERVED_PREVIEW"
        eligible = not blockers
        latest_evaluation = last_two[-1] if last_two else {}
        latest_quality = latest_evaluation.get("sample_quality") if isinstance(latest_evaluation.get("sample_quality"), Mapping) else {}
        sample_provenance = revalidated_sample.get("provenance") if isinstance(revalidated_sample.get("provenance"), Mapping) else {}
        provider_provenance = provider_revalidation.get("provenance") if isinstance(provider_revalidation.get("provenance"), Mapping) else {}
        return {
            "schema_version": "1.0",
            "eligibility": "CANDIDATE" if eligible else "BLOCKED",
            "action_status": "DISABLED",
            "action_execution": "DISABLED",
            "reservation_status": recommendation.get("reservation_status"),
            "action_key": action_key,
            "machine_id": target.get("machine_id"),
            "instance_id": target.get("instance_id"),
            "verified_gpu_identity": normalized,
            "guard_policy_hash": self.guard_policy_hash,
            "gpu_floor_ths": configured_floor,
            "observed_average_ths": latest_evaluation.get("observed_window_hashrate_ths"),
            "immediate_revalidated_hashrate_ths": sample_rate,
            "deterioration_start_utc": candidate.get("deterioration_start_utc"),
            "deterioration_duration_seconds": _duration_seconds(candidate.get("deterioration_start_utc"), now),
            "sample_quality": dict(latest_quality),
            "reallocation_history": dict(allocation_history),
            "provenance": {
                "candidate": dict(candidate.get("provenance")) if isinstance(candidate.get("provenance"), Mapping) else {},
                "provider_revalidation": dict(provider_provenance),
                "miner_revalidation": dict(sample_provenance),
            },
            "blockers": blockers,
            "reason": "all offline eligibility gates passed; real action remains disabled" if eligible else "one or more fail-closed gates are unresolved",
            "recommendation": recommendation,
            "actions_performed": False,
        }

    def preview(self, **kwargs: Any) -> dict[str, Any]:
        """Evaluate all eligibility gates without consuming an action key."""
        if "reserve_action" in kwargs:
            raise TypeError("preview never reserves an action")
        return self.assess(**kwargs, reserve_action=False)

    def reserve_for_execution(self, **kwargs: Any) -> dict[str, Any]:
        """Explicitly perform the local atomic dry-run reservation after preview."""
        if "reserve_action" in kwargs:
            raise TypeError("reserve_for_execution controls reservation itself")
        return self.assess(**kwargs, reserve_action=True)
