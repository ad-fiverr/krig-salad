"""Offline-only admission model for the SCRUM-101 early and steady-state paths.

This module can reserve a local simulation record. It cannot construct a provider
request, create an action dossier, or change the existing provider-action ledger.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import json
import math
import re
from typing import Any

from .action_ledger import ActionLedger, _reject_secrets
from .guard_store import canonical_utc
from .salad_action_policy import APPROVED_GROUPS, APPROVED_ORGANIZATION, APPROVED_PROJECT, HARD_BUDGET_CAP_USD


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GPU_KEY_RE = re.compile(r"^[A-Z0-9]+(?:_[A-Z0-9]+)*$")
_EARLY_FIELDS = frozenset({
    "decision_version", "state", "reason", "signal_type", "device_index", "gpu_key",
    "estimate_ths", "predicted_lower_ths", "predicted_upper_ths", "floor_ths", "policy_hash",
    "assignment_id", "assignment_generation", "actions_performed", "action_eligible",
    "evaluated_at_utc", "source_reference_sha256", "calibration_status",
    "calibration_evidence_sha256",
})
_APPROVED_CALIBRATION = "APPLIED_APPROVED_MEASURED_PAIRS"
_SYNTHETIC_FIXTURE = "G5-SYNTHETIC-ACTION-PATH"
_MAX_HARD_BUDGET = Decimal("30.00")


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(canonical_utc(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _digest(*parts: Any) -> str:
    encoded = json.dumps(parts, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _canonical_gpu_key(identity: Mapping[str, Any]) -> str | None:
    if identity.get("identity_verified") is not True:
        return None
    existing = identity.get("gpu_key")
    if isinstance(existing, str) and _GPU_KEY_RE.fullmatch(existing):
        return existing
    model = identity.get("model")
    form = identity.get("form_factor")
    if not isinstance(model, str) or not model.strip():
        return None
    tokens = re.findall(r"[A-Za-z0-9]+", model)
    if not tokens:
        return None
    key = "_".join(tokens).upper()
    if form in {"laptop", "desktop"}:
        key += "_" + form.upper()
    elif form not in {"neutral", "unknown", None}:
        return None
    return key if _GPU_KEY_RE.fullmatch(key) else None


@dataclass(frozen=True, slots=True)
class AutoReallocationLimits:
    """Limits required for a positive simulation; omitted values fail closed."""

    max_per_minute: int | None = None
    max_per_day: int | None = None
    cooldown_seconds: int | None = None
    max_per_assignment: int | None = None
    max_per_fleet: int | None = None

    def __post_init__(self) -> None:
        for name in ("max_per_minute", "max_per_day", "max_per_assignment", "max_per_fleet"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
                raise ValueError(f"{name} must be a positive integer when configured")
        value = self.cooldown_seconds
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ValueError("cooldown_seconds must be a non-negative integer when configured")

    def complete(self) -> bool:
        return all(getattr(self, name) is not None for name in (
            "max_per_minute", "max_per_day", "cooldown_seconds", "max_per_assignment", "max_per_fleet",
        ))

    def as_ledger_limits(self) -> dict[str, int]:
        if not self.complete():
            raise ValueError("all simulation quotas and cooldown must be configured")
        return {
            "max_per_minute": int(self.max_per_minute),
            "max_per_day": int(self.max_per_day),
            "cooldown_seconds": int(self.cooldown_seconds),
            "max_per_assignment": int(self.max_per_assignment),
            "max_per_fleet": int(self.max_per_fleet),
        }


class AutoReallocationGate:
    """Validate a typed trigger and reserve a bounded, non-executing simulation."""

    def __init__(
        self,
        ledger: ActionLedger,
        *,
        policy_hash: str,
        gpu_floors_ths: Mapping[str, Any],
        limits: AutoReallocationLimits | None = None,
        hard_budget_cap_usd: Any = HARD_BUDGET_CAP_USD,
        maximum_evidence_age_seconds: int = 90,
        simulation_enabled: bool = False,
    ):
        if type(ledger) is not ActionLedger:
            raise TypeError("auto reallocation gate requires the local ActionLedger")
        if not isinstance(policy_hash, str) or not _HASH_RE.fullmatch(policy_hash):
            raise ValueError("active policy hash is required")
        if not isinstance(gpu_floors_ths, Mapping):
            raise ValueError("active floor registry is required")
        floors: dict[str, float] = {}
        for key, raw in gpu_floors_ths.items():
            value = _finite_number(raw)
            if not isinstance(key, str) or not _GPU_KEY_RE.fullmatch(key) or value is None or value <= 0:
                raise ValueError("active floor registry is invalid")
            floors[key] = value
        try:
            hard_cap = Decimal(str(hard_budget_cap_usd))
        except (InvalidOperation, ValueError):
            raise ValueError("hard budget cap is invalid") from None
        if not hard_cap.is_finite() or hard_cap <= 0 or hard_cap > _MAX_HARD_BUDGET:
            raise ValueError("hard budget cap must be within USD 30.00")
        if isinstance(maximum_evidence_age_seconds, bool) or not isinstance(maximum_evidence_age_seconds, int) or maximum_evidence_age_seconds <= 0:
            raise ValueError("maximum evidence age must be positive")
        if type(simulation_enabled) is not bool:
            raise ValueError("simulation_enabled must be boolean")
        if limits is not None and type(limits) is not AutoReallocationLimits:
            raise TypeError("limits must be AutoReallocationLimits")
        self.ledger = ledger
        self.policy_hash = policy_hash
        self.gpu_floors_ths = floors
        self.limits = limits or AutoReallocationLimits()
        self.hard_budget_cap_usd = hard_cap
        self.maximum_evidence_age_seconds = maximum_evidence_age_seconds
        self.simulation_enabled = simulation_enabled

    def assess_early(
        self,
        decision: Mapping[str, Any],
        *,
        source_evidence: Mapping[str, Any],
        policy_evidence: Mapping[str, Any],
        generation_evidence: Mapping[str, Any],
        provider_binding: Mapping[str, Any],
        provider_revalidation: Mapping[str, Any],
        budget_evidence: Mapping[str, Any],
        allocation_history: Mapping[str, Any],
        fleet_id: str,
        now_utc: str,
        kill_switch_engaged: bool,
        auto_armed: bool,
        live_actions_enabled: bool = False,
        g5_authorized: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(decision, Mapping) or set(decision) != _EARLY_FIELDS:
            return self._blocked("EARLY", ["EARLY_DECISION_SCHEMA_INVALID"])
        try:
            _reject_secrets(decision)
        except ValueError:
            return self._blocked("EARLY", ["SECRET_LIKE_FIELDS_REJECTED"])
        if decision.get("decision_version") != 1 or isinstance(decision.get("decision_version"), bool):
            return self._blocked("EARLY", ["EARLY_DECISION_VERSION_UNSUPPORTED"])
        if decision.get("state") != "EARLY_UNDER_FLOOR" or decision.get("reason") != "UPPER_BOUND_BELOW_THRESHOLD":
            return self._blocked("EARLY", ["EARLY_DECISION_NOT_ACTION_CANDIDATE"])
        if not isinstance(decision.get("signal_type"), str) or decision.get("signal_type") not in {"CUDA_POOL_EQUIVALENT", "PEARL_AUTOTUNE"}:
            return self._blocked("EARLY", ["EARLY_SIGNAL_TYPE_UNSUPPORTED"])
        if type(decision.get("device_index")) is not int or decision["device_index"] < 0:
            return self._blocked("EARLY", ["EARLY_DEVICE_IDENTITY_INVALID"])
        gpu_key = decision.get("gpu_key")
        if not isinstance(gpu_key, str) or not _GPU_KEY_RE.fullmatch(gpu_key):
            return self._blocked("EARLY", ["EARLY_GPU_IDENTITY_INVALID"])
        estimate = _finite_number(decision.get("estimate_ths"))
        lower = _finite_number(decision.get("predicted_lower_ths"))
        upper = _finite_number(decision.get("predicted_upper_ths"))
        floor = _finite_number(decision.get("floor_ths"))
        if estimate is None or lower is None or upper is None or floor is None or min(estimate, lower, upper, floor) <= 0 or lower > estimate or estimate > upper or upper >= floor:
            return self._blocked("EARLY", ["EARLY_PREDICTION_INVALID_OR_NOT_BELOW_FLOOR"])
        if decision.get("actions_performed") is not False or decision.get("action_eligible") is not False:
            return self._blocked("EARLY", ["EARLY_DECISION_CANNOT_AUTHORIZE_ACTION"])
        source_hash = decision.get("source_reference_sha256")
        calibration_hash = decision.get("calibration_evidence_sha256")
        if not isinstance(source_hash, str) or not _HASH_RE.fullmatch(source_hash) or not isinstance(calibration_hash, str) or not _HASH_RE.fullmatch(calibration_hash):
            return self._blocked("EARLY", ["EARLY_PROVENANCE_HASH_INVALID"])
        calibration_status = decision.get("calibration_status")
        if not isinstance(calibration_status, str) or calibration_status not in {_APPROVED_CALIBRATION, "APPLIED_SYNTHETIC_TEST_ONLY"}:
            return self._blocked("EARLY", ["EARLY_CALIBRATION_NOT_APPROVED"])
        if calibration_status == "APPLIED_SYNTHETIC_TEST_ONLY" and not (
            isinstance(source_evidence, Mapping)
            and source_evidence.get("data_classification") == "SYNTHETIC/UNVERIFIED"
            and source_evidence.get("synthetic_fixture_id") == _SYNTHETIC_FIXTURE
        ):
            return self._blocked("EARLY", ["SYNTHETIC_CALIBRATION_NOT_ACTIONABLE"])
        if not self._text_id(decision.get("assignment_id")) or not self._text_id(decision.get("assignment_generation")):
            return self._blocked("EARLY", ["EARLY_ASSIGNMENT_GENERATION_MISSING"])
        evaluated = _utc(decision.get("evaluated_at_utc"))
        now = _utc(now_utc)
        if evaluated is None or now is None:
            return self._blocked("EARLY", ["EARLY_DECISION_TIME_INVALID"])
        if (now - evaluated).total_seconds() < 0 or (now - evaluated).total_seconds() > self.maximum_evidence_age_seconds:
            return self._blocked("EARLY", ["EARLY_DECISION_STALE_OR_FUTURE"])
        return self._assess_common(
            trigger_kind="EARLY",
            trigger_facts={
                "decision_state": decision["state"], "reason": decision["reason"],
                "signal_type": decision["signal_type"], "device_index": decision["device_index"],
                "gpu_key": gpu_key, "floor_ths": floor, "policy_hash": decision.get("policy_hash"),
                "assignment_id": decision["assignment_id"], "assignment_generation": decision["assignment_generation"],
                "source_reference_sha256": source_hash, "calibration_evidence_sha256": calibration_hash,
            },
            gpu_key=gpu_key,
            floor=floor,
            assignment_id=decision["assignment_id"],
            assignment_generation=decision["assignment_generation"],
            decision_policy_hash=decision.get("policy_hash"),
            source_reference_sha256=source_hash,
            evaluated_at=evaluated,
            source_evidence=source_evidence,
            policy_evidence=policy_evidence,
            generation_evidence=generation_evidence,
            provider_binding=provider_binding,
            provider_revalidation=provider_revalidation,
            budget_evidence=budget_evidence,
            allocation_history=allocation_history,
            fleet_id=fleet_id,
            now=now,
            device_index=decision["device_index"],
            kill_switch_engaged=kill_switch_engaged,
            auto_armed=auto_armed,
            live_actions_enabled=live_actions_enabled,
            g5_authorized=g5_authorized,
        )

    def assess_steady_state(
        self,
        controller_assessment: Mapping[str, Any],
        *,
        source_evidence: Mapping[str, Any],
        policy_evidence: Mapping[str, Any],
        generation_evidence: Mapping[str, Any],
        provider_binding: Mapping[str, Any],
        provider_revalidation: Mapping[str, Any],
        budget_evidence: Mapping[str, Any],
        allocation_history: Mapping[str, Any],
        fleet_id: str,
        now_utc: str,
        kill_switch_engaged: bool,
        auto_armed: bool,
        live_actions_enabled: bool = False,
        g5_authorized: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(controller_assessment, Mapping):
            return self._blocked("STEADY_STATE", ["CONTROLLER_ASSESSMENT_INVALID"])
        try:
            _reject_secrets(controller_assessment)
        except ValueError:
            return self._blocked("STEADY_STATE", ["SECRET_LIKE_FIELDS_REJECTED"])
        recommendation = controller_assessment.get("recommendation")
        target = recommendation.get("target") if isinstance(recommendation, Mapping) else None
        gpu_identity = recommendation.get("gpu_identity") if isinstance(recommendation, Mapping) else None
        if not isinstance(target, Mapping) or not isinstance(gpu_identity, Mapping):
            return self._blocked("STEADY_STATE", ["CONTROLLER_ASSESSMENT_INCOMPLETE"])
        if (
            controller_assessment.get("eligibility") != "CANDIDATE"
            or controller_assessment.get("schema_version") != "1.0"
            or controller_assessment.get("action_status") != "DISABLED"
            or controller_assessment.get("action_execution") != "DISABLED"
            or controller_assessment.get("actions_performed") is not False
            or controller_assessment.get("blockers") not in ([], ())
            or controller_assessment.get("guard_policy_hash") != self.policy_hash
            or recommendation.get("guard_policy_hash") != self.policy_hash
            or recommendation.get("actions_performed") is not False
            or not self._text_id(recommendation.get("action_key"))
        ):
            return self._blocked("STEADY_STATE", ["TWO_WINDOW_CONTROLLER_CANDIDATE_REQUIRED"])
        eval_ids = recommendation.get("evaluation_ids")
        if not isinstance(eval_ids, list) or len(eval_ids) != 2 or any(not self._text_id(item) for item in eval_ids):
            return self._blocked("STEADY_STATE", ["TWO_CURRENT_LOW_WINDOWS_REQUIRED"])
        gpu_key = _canonical_gpu_key(gpu_identity)
        floor = _finite_number(controller_assessment.get("gpu_floor_ths"))
        assignment_id = target.get("assignment_id")
        generation_e = generation_evidence.get("assignment_generation") if isinstance(generation_evidence, Mapping) else None
        now = _utc(now_utc)
        evaluated = _utc(source_evidence.get("observed_at_utc")) if isinstance(source_evidence, Mapping) else None
        if not isinstance(assignment_id, str) or not assignment_id or not isinstance(generation_e, str) or not generation_e:
            return self._blocked("STEADY_STATE", ["STEADY_ASSIGNMENT_GENERATION_MISSING"])
        binding_provider = provider_binding.get("provider") if isinstance(provider_binding, Mapping) else None
        if not isinstance(binding_provider, Mapping) or any(
            binding_provider.get(name) != target.get(name)
            for name in ("organization_id", "project_id", "container_group_id", "instance_id", "machine_id", "assignment_id")
        ):
            return self._blocked("STEADY_STATE", ["CONTROLLER_TARGET_BINDING_MISMATCH"])
        if gpu_key is None or floor is None:
            return self._blocked("STEADY_STATE", ["STEADY_GPU_FLOOR_INVALID"])
        if now is None or evaluated is None or (now - evaluated).total_seconds() < 0 or (now - evaluated).total_seconds() > self.maximum_evidence_age_seconds:
            return self._blocked("STEADY_STATE", ["STEADY_ASSESSMENT_STALE_OR_UNTIMED"])
        source_hash = source_evidence.get("source_reference_sha256") if isinstance(source_evidence, Mapping) else None
        if not isinstance(source_hash, str) or not _HASH_RE.fullmatch(source_hash):
            return self._blocked("STEADY_STATE", ["STEADY_SOURCE_PROVENANCE_INVALID"])
        return self._assess_common(
            trigger_kind="STEADY_STATE",
            trigger_facts={
                "action_key": recommendation.get("action_key") or controller_assessment.get("action_key"),
                "evaluation_ids": eval_ids, "gpu_key": gpu_key, "floor_ths": floor,
                "policy_hash": controller_assessment.get("guard_policy_hash"),
                "assignment_id": assignment_id, "assignment_generation": generation_e,
                "source_reference_sha256": source_hash,
            },
            gpu_key=gpu_key,
            floor=floor,
            assignment_id=assignment_id,
            assignment_generation=generation_e,
            decision_policy_hash=controller_assessment.get("guard_policy_hash"),
            source_reference_sha256=source_hash,
            evaluated_at=evaluated,
            source_evidence=source_evidence,
            policy_evidence=policy_evidence,
            generation_evidence=generation_evidence,
            provider_binding=provider_binding,
            provider_revalidation=provider_revalidation,
            budget_evidence=budget_evidence,
            allocation_history=allocation_history,
            fleet_id=fleet_id,
            now=now,
            device_index=None,
            kill_switch_engaged=kill_switch_engaged,
            auto_armed=auto_armed,
            live_actions_enabled=live_actions_enabled,
            g5_authorized=g5_authorized,
        )

    @staticmethod
    def _text_id(value: Any) -> bool:
        return isinstance(value, str) and bool(_ID_RE.fullmatch(value))

    def _assess_common(self, *, trigger_kind: str, trigger_facts: Mapping[str, Any], gpu_key: str,
                       floor: float, assignment_id: str, assignment_generation: str,
                       decision_policy_hash: Any, source_reference_sha256: str, evaluated_at: datetime,
                       source_evidence: Mapping[str, Any], policy_evidence: Mapping[str, Any],
                       generation_evidence: Mapping[str, Any], provider_binding: Mapping[str, Any],
                       provider_revalidation: Mapping[str, Any], budget_evidence: Mapping[str, Any],
                       allocation_history: Mapping[str, Any], fleet_id: str, now: datetime,
                       device_index: int | None, kill_switch_engaged: bool, auto_armed: bool, live_actions_enabled: bool,
                       g5_authorized: bool) -> dict[str, Any]:
        blockers: list[str] = []
        evidence_values = (source_evidence, policy_evidence, generation_evidence, provider_binding,
                           provider_revalidation, budget_evidence, allocation_history)
        if any(not isinstance(value, Mapping) for value in evidence_values):
            return self._blocked(trigger_kind, ["REQUIRED_EVIDENCE_MISSING"], gpu_key=gpu_key,
                                 policy_hash=self.policy_hash)
        try:
            for value in evidence_values:
                _reject_secrets(value)
        except ValueError:
            return self._blocked(trigger_kind, ["SECRET_LIKE_FIELDS_REJECTED"], gpu_key=gpu_key,
                                 policy_hash=self.policy_hash)

        policy_hash = decision_policy_hash
        if policy_hash != self.policy_hash or policy_evidence.get("policy_hash") != self.policy_hash:
            blockers.append("POLICY_HASH_MISMATCH")
        floors_evidence = policy_evidence.get("gpu_floors_ths")
        if not isinstance(floors_evidence, Mapping) or dict(floors_evidence) != self.gpu_floors_ths:
            blockers.append("POLICY_FLOOR_REGISTRY_MISMATCH")
        expected_floor = self.gpu_floors_ths.get(gpu_key)
        if expected_floor is None or floor != expected_floor:
            blockers.append("GPU_FLOOR_MISMATCH")

        source_class = source_evidence.get("data_classification")
        policy_class = policy_evidence.get("data_classification")
        generation_class = generation_evidence.get("data_classification")
        binding_class = provider_binding.get("data_classification")
        provider_class = provider_revalidation.get("data_classification")
        raw_classes = (source_class, policy_class, generation_class, binding_class, provider_class)
        classes = set(raw_classes) if all(isinstance(value, str) for value in raw_classes) else set()
        is_synthetic = classes == {"SYNTHETIC/UNVERIFIED"}
        raw_synthetic_ids = tuple(
            value.get("synthetic_fixture_id")
            for value in (source_evidence, policy_evidence, generation_evidence, provider_binding, provider_revalidation)
        )
        synthetic_ids = set(raw_synthetic_ids) if all(value is None or isinstance(value, str) for value in raw_synthetic_ids) else set()
        if is_synthetic:
            if synthetic_ids != {_SYNTHETIC_FIXTURE}:
                blockers.append("SYNTHETIC_PROVENANCE_INVALID")
        elif classes != {
            "INDEPENDENT_WORKLOAD_EVIDENCE", "APPROVED_POLICY",
            "INDEPENDENT_GENERATION_EVIDENCE", "INDEPENDENT_BINDING_ATTESTATION",
            "PROVIDER_OBSERVED",
        }:
            blockers.append("EVIDENCE_PROVENANCE_INCOMPLETE_OR_MIXED")

        if source_evidence.get("source_reference_sha256") != source_reference_sha256:
            blockers.append("SOURCE_REFERENCE_MISMATCH")
        if trigger_kind == "EARLY" and source_evidence.get("source") != "FL4SHMINER_AUTOTUNE_LOG":
            blockers.append("EARLY_SOURCE_NOT_APPROVED")
        source_time = _utc(source_evidence.get("observed_at_utc"))
        if source_time is None or self._stale_or_future(source_time, now):
            blockers.append("SOURCE_EVIDENCE_STALE_OR_UNTIMED")
        if self._stale_or_future(evaluated_at, now):
            blockers.append("TRIGGER_EVIDENCE_STALE_OR_FUTURE")

        provider = provider_binding.get("provider") if isinstance(provider_binding.get("provider"), Mapping) else {}
        assignment = provider_binding.get("assignment") if isinstance(provider_binding.get("assignment"), Mapping) else {}
        if device_index is not None and (
            provider.get("device_index") != device_index
            or provider.get("gpu_key") != gpu_key
            or assignment.get("device_index") != device_index
            or assignment.get("gpu_key") != gpu_key
        ):
            blockers.append("EARLY_DEVICE_BINDING_MISMATCH")
        required_identity = (
            ("organization_id", APPROVED_ORGANIZATION),
            ("project_id", APPROVED_PROJECT),
            ("container_group_id", None),
            ("instance_id", None),
            ("machine_id", None),
            ("assignment_id", assignment_id),
        )
        for key, expected in required_identity:
            left = provider.get(key)
            right = assignment.get(key)
            if key == "container_group_id":
                if left not in APPROVED_GROUPS or right != left:
                    blockers.append("PROVIDER_GROUP_SCOPE_INVALID")
                continue
            if expected is not None:
                if left != expected or right != expected:
                    blockers.append("PROVIDER_BINDING_IDENTITY_MISMATCH")
            elif not self._text_id(left) or right != left:
                blockers.append("PROVIDER_BINDING_IDENTITY_INCOMPLETE")
        binding_status = provider_binding.get("binding_status")
        if not isinstance(binding_status, str) or binding_status not in {"VERIFIED", "SYNTHETIC/UNVERIFIED"}:
            blockers.append("PROVIDER_BINDING_NOT_VERIFIED")
        if provider_binding.get("policy_hash") != self.policy_hash:
            blockers.append("BINDING_POLICY_HASH_MISMATCH")
        if is_synthetic:
            if provider_binding.get("actions_authorized_by_binding") is not False:
                blockers.append("SYNTHETIC_BINDING_CANNOT_AUTHORIZE_ACTION")
        elif (
            provider_binding.get("binding_status") != "VERIFIED"
            or provider_binding.get("actions_authorized_by_binding") is not True
            or not self._text_id(provider_binding.get("attestation_evidence_id"))
            or not isinstance(provider_binding.get("evidence_sha256"), str)
            or not _HASH_RE.fullmatch(provider_binding["evidence_sha256"])
        ):
            blockers.append("INDEPENDENT_BINDING_ATTESTATION_INVALID")

        provider_observed_at = _utc(provider_revalidation.get("observed_at_utc") or provider_revalidation.get("occurred_at_utc"))
        provenance = provider_revalidation.get("source_provenance")
        if is_synthetic:
            provider_ok = (
                isinstance(provenance, Mapping)
                and provenance.get("system") == "synthetic_test_fixture"
                and provenance.get("host") == "loopback"
                and provenance.get("transport_tls_hostname_verified") is False
                and provider_revalidation.get("synthetic_fixture_id") == _SYNTHETIC_FIXTURE
            )
        else:
            provider_ok = (
                isinstance(provenance, Mapping)
                and provenance.get("system") == "salad_api"
                and provenance.get("host") == "api.salad.com"
                and provenance.get("transport_tls_hostname_verified") is True
            )
        reported_state = provider_revalidation.get("reported_state")
        if not provider_ok or not isinstance(reported_state, str) or reported_state.casefold() != "running":
            blockers.append("PROVIDER_REVALIDATION_INVALID")
        if provider_observed_at is None or self._stale_or_future(provider_observed_at, now):
            blockers.append("PROVIDER_REVALIDATION_STALE_OR_UNTIMED")
        binding_valid_from = _utc(provider_binding.get("valid_from_utc"))
        binding_revalidated = _utc(provider_binding.get("revalidated_at_utc"))
        binding_valid_until = _utc(provider_binding.get("valid_until_utc"))
        if (
            binding_valid_from is None or binding_revalidated is None or binding_valid_until is None
            or not (binding_valid_from <= binding_revalidated <= now <= binding_valid_until)
            or self._stale_or_future(binding_revalidated, now)
        ):
            blockers.append("PROVIDER_BINDING_STALE_OR_OUTSIDE_VALIDITY")
        for key in ("organization_id", "project_id", "container_group_id", "instance_id", "machine_id", "assignment_id", "assignment_generation"):
            if provider_revalidation.get(key) != provider.get(key):
                blockers.append("PROVIDER_REVALIDATION_IDENTITY_MISMATCH")
                break

        generation_observed = _utc(generation_evidence.get("observed_at_utc"))
        if (
            generation_evidence.get("status") != "CURRENT"
            or generation_evidence.get("policy_hash") != self.policy_hash
            or generation_evidence.get("assignment_id") != assignment_id
            or generation_evidence.get("assignment_generation") != assignment_generation
            or assignment.get("assignment_generation") != assignment_generation
            or generation_observed is None
            or self._stale_or_future(generation_observed, now)
        ):
            blockers.append("ASSIGNMENT_GENERATION_NOT_CURRENT")
        valid_until = _utc(generation_evidence.get("valid_until_utc"))
        valid_from = _utc(generation_evidence.get("valid_from_utc"))
        if valid_until is None or valid_from is None or valid_from > now or valid_until < now:
            blockers.append("ASSIGNMENT_GENERATION_EXPIRED")

        budget_class = budget_evidence.get("data_classification")
        expected_budget_class = "SYNTHETIC/UNVERIFIED" if is_synthetic else "INDEPENDENT_FINANCIAL_EVIDENCE"
        if budget_class != expected_budget_class or not self._verified_budget(budget_evidence, now):
            blockers.append("VERIFIED_BUDGET_REQUIRED")
        if isinstance(fleet_id, str) is False or not self._text_id(fleet_id):
            blockers.append("FLEET_ID_INVALID")
        if not isinstance(allocation_history, Mapping) or allocation_history.get("history_known") is not True:
            blockers.append("REALLOCATION_HISTORY_UNKNOWN")
        else:
            for field in ("allocation_reallocation_count", "fleet_reallocation_count"):
                value = allocation_history.get(field)
                if type(value) is not int or value < 0:
                    blockers.append("REALLOCATION_HISTORY_UNKNOWN")
                    break
            history_at = _utc(allocation_history.get("observed_at_utc"))
            if history_at is None or self._stale_or_future(history_at, now):
                blockers.append("REALLOCATION_HISTORY_STALE_OR_UNTIMED")
            if self.limits.complete():
                assignment_count = allocation_history.get("allocation_reallocation_count")
                fleet_count = allocation_history.get("fleet_reallocation_count")
                if type(assignment_count) is int and assignment_count >= int(self.limits.max_per_assignment):
                    blockers.append("ASSIGNMENT_DAILY_QUOTA")
                if type(fleet_count) is int and fleet_count >= int(self.limits.max_per_fleet):
                    blockers.append("FLEET_DAILY_QUOTA")
                prior_action = _utc(allocation_history.get("last_reallocation_at_utc"))
                if type(assignment_count) is int and assignment_count > 0 and prior_action is None:
                    blockers.append("COOLDOWN_CANNOT_BE_VERIFIED")
                elif prior_action is not None and (now - prior_action).total_seconds() < int(self.limits.cooldown_seconds):
                    blockers.append("ASSIGNMENT_COOLDOWN_ACTIVE")
        if not self.limits.complete():
            blockers.append("SIMULATION_QUOTAS_OR_COOLDOWN_UNCONFIGURED")
        if self.simulation_enabled is not True:
            blockers.append("SIMULATION_GATE_DISABLED")
        if type(kill_switch_engaged) is not bool or kill_switch_engaged:
            blockers.append("KILL_SWITCH_ACTIVE_OR_UNKNOWN")
        if type(auto_armed) is not bool or not auto_armed:
            blockers.append("AUTO_REALLOCATE_NOT_ARMED_FOR_SIMULATION")
        if live_actions_enabled is not False or g5_authorized is not False:
            blockers.append("LIVE_ACTION_PATH_MUST_REMAIN_DISABLED")

        blockers = sorted(set(blockers))
        if blockers:
            return self._blocked(trigger_kind, blockers, gpu_key=gpu_key, policy_hash=self.policy_hash,
                                 data_classification="SYNTHETIC/UNVERIFIED" if is_synthetic else "UNKNOWN")

        identity = {key: provider[key] for key in ("organization_id", "project_id", "container_group_id", "instance_id", "machine_id")}
        trigger_digest = _digest(trigger_kind, trigger_facts, identity, fleet_id)
        simulation_key = trigger_digest
        scopes = {
            "organization": _digest(identity["organization_id"]),
            "fleet": _digest(identity["organization_id"], identity["project_id"], fleet_id),
            "assignment": _digest(identity["organization_id"], identity["project_id"], assignment_id),
            "target": _digest(identity["organization_id"], identity["project_id"], identity["container_group_id"], identity["instance_id"], identity["machine_id"]),
        }
        payload = {
            "trigger_kind": trigger_kind,
            "decision_reason": trigger_facts.get("reason") if trigger_kind == "EARLY" else "TWO_WINDOW_CONTROLLER_CANDIDATE",
            "gpu_key": gpu_key,
            "policy_hash": self.policy_hash,
            "data_classification": "SYNTHETIC/UNVERIFIED" if is_synthetic else "PROVIDER_EVIDENCE_PRESENT_SIMULATION_ONLY",
            "synthetic_fixture_id": _SYNTHETIC_FIXTURE if is_synthetic else None,
            "simulation_only": True,
            "actions_performed": False,
            "request_submitted": False,
            "dossier_created": False,
            "live_action_eligible": False,
            "reservation_identity": {
                "assignment_scope": scopes["assignment"],
                "target_scope": scopes["target"],
                "original_instance_fingerprint": _digest(identity["instance_id"]),
                "original_generation_fingerprint": _digest(assignment_generation),
            },
        }
        reserved = self.ledger.reserve_auto_reallocation_simulation(
            simulation_key=simulation_key,
            trigger_key=trigger_digest,
            scopes=scopes,
            at_utc=now.isoformat().replace("+00:00", "Z"),
            at_epoch=now.timestamp(),
            limits=self.limits.as_ledger_limits(),
            payload=payload,
        )
        return self._result(
            trigger_kind,
            reserved["status"],
            blockers=[reserved["blocker"]] if reserved.get("blocker") else [],
            simulation_key=reserved.get("simulation_key"),
            gpu_key=gpu_key,
            policy_hash=self.policy_hash,
            data_classification=payload["data_classification"],
        )

    def _stale_or_future(self, value: datetime, now: datetime) -> bool:
        age = (now - value).total_seconds()
        return age < 0 or age > self.maximum_evidence_age_seconds

    def _verified_budget(self, evidence: Mapping[str, Any], now: datetime) -> bool:
        if evidence.get("status") != "VERIFIED" or evidence.get("currency") != "USD":
            return False
        numbers = [_finite_number(evidence.get(key)) for key in (
            "verified_spend_usd", "verified_next_action_cost_usd", "pending_exposure_usd", "maximum_exposure_usd",
        )]
        if any(value is None or value < 0 for value in numbers):
            return False
        spend, next_cost, pending, maximum = (Decimal(str(value)) for value in numbers)
        spend_at = _utc(evidence.get("spend_observed_at_utc"))
        cost_at = _utc(evidence.get("next_action_cost_observed_at_utc"))
        valid_until = _utc(evidence.get("valid_until_utc"))
        time_valid = (
            spend_at is not None and cost_at is not None and valid_until is not None
            and not self._stale_or_future(spend_at, now)
            and not self._stale_or_future(cost_at, now)
            and valid_until >= now
        )
        return (
            maximum >= spend + next_cost + pending
            and maximum <= min(self.hard_budget_cap_usd, _MAX_HARD_BUDGET)
            and time_valid
            and all(isinstance(evidence.get(key), str) and evidence[key].strip() for key in (
                "spend_evidence_id", "next_action_cost_evidence_id", "pending_exposure_evidence_id",
                "maximum_exposure_evidence_id",
            ))
        )

    @staticmethod
    def _result(trigger_kind: str, status: str, *, blockers: list[str] | None = None,
                simulation_key: str | None = None, gpu_key: str | None = None,
                policy_hash: str | None = None, data_classification: str = "UNKNOWN") -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "trigger_kind": trigger_kind,
            "status": status,
            "blockers": list(blockers or []),
            "simulation_id": simulation_key,
            "gpu_key": gpu_key,
            "policy_hash": policy_hash,
            "evidence_classification": data_classification,
            "simulation_only": True,
            "actions_performed": False,
            "request_submitted": False,
            "dossier_created": False,
            "live_action_eligible": False,
        }

    def _blocked(self, trigger_kind: str, blockers: list[str], *, gpu_key: str | None = None,
                 policy_hash: str | None = None, data_classification: str = "UNKNOWN") -> dict[str, Any]:
        return self._result(trigger_kind, "BLOCKED", blockers=sorted(set(blockers)), gpu_key=gpu_key,
                            policy_hash=policy_hash or self.policy_hash, data_classification=data_classification)
