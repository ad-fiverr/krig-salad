"""Shared fail-closed policy gates for manual and automatic Salad actions."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from enum import Enum
import hashlib
import hmac
import json
import math
import re
import secrets
from typing import Any
import uuid


HARD_BUDGET_CAP_USD = Decimal("30.00")
APPROVED_ORGANIZATION = "adrianfiverr"
APPROVED_PROJECT = "miners"
APPROVED_GROUPS = ("fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4")


class SaladAction(str, Enum):
    START_GROUP = "START_GROUP"
    STOP_GROUP = "STOP_GROUP"
    REALLOCATE_INSTANCE = "REALLOCATE_INSTANCE"


@dataclass(frozen=True, slots=True)
class SignedActionCapability:
    """Externally signed, one-action grant; payload and signature stay opaque."""

    payload: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes) or not 1 <= len(self.payload) <= 4096:
            raise ValueError("signed action capability payload is invalid")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("signed action capability signature is invalid")

    def __repr__(self) -> str:
        return "SignedActionCapability([REDACTED])"


class ActionCapabilityVerifier:
    """Verify an operator-signed capability bound to one exact Salad route."""

    __slots__ = ("_public_key",)

    def __init__(self, public_key: bytes):
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("trusted action key is invalid")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            self._public_key = Ed25519PublicKey.from_public_bytes(public_key)
        except Exception:
            raise ValueError("trusted action key is unavailable") from None

    def verify(
        self,
        capability: SignedActionCapability | None,
        *,
        action: SaladAction,
        target: Mapping[str, Any],
        route: str,
        now_epoch: float,
    ) -> bool:
        return self.verified_nonce(
            capability, action=action, target=target, route=route, now_epoch=now_epoch,
        ) is not None

    def verified_nonce(
        self,
        capability: SignedActionCapability | None,
        *,
        action: SaladAction,
        target: Mapping[str, Any],
        route: str,
        now_epoch: float,
    ) -> str | None:
        """Return the signed nonce only when every capability claim is valid.

        The caller must atomically consume this value in the durable action
        ledger before dispatch. Verification alone never makes a grant one-use.
        """
        if type(capability) is not SignedActionCapability or type(action) is not SaladAction:
            return None
        if not isinstance(target, Mapping) or not isinstance(route, str) or not route.startswith("/"):
            return None
        if isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float)) or not math.isfinite(float(now_epoch)):
            return None
        try:
            self._public_key.verify(capability.signature, capability.payload)
            claims = json.loads(capability.payload.decode("utf-8"))
            issued = float(claims["issued_at_epoch"])
            expires = float(claims["expires_at_epoch"])
            nonce = str(uuid.UUID(claims["nonce"]))
        except Exception:
            return None
        expected = {
            "schema_version", "audience", "host", "organization", "project",
            "container_group", "action", "path", "issued_at_epoch",
            "expires_at_epoch", "nonce", "max_requests",
        }
        target_generation = target.get("assignment_generation")
        generation_bound = target_generation is not None
        if generation_bound:
            expected.add("assignment_generation")
        valid = (
            isinstance(claims, dict)
            and set(claims) == expected
            and claims.get("schema_version") == (2 if generation_bound else 1)
            and claims.get("audience") == "salad-g5-control-plane"
            and claims.get("host") == "api.salad.com"
            and claims.get("organization") == APPROVED_ORGANIZATION
            and claims.get("project") == APPROVED_PROJECT
            and claims.get("container_group") == target.get("container_group")
            and claims.get("action") == action.value
            and claims.get("path") == route
            and (
                not generation_bound
                or (
                    isinstance(target_generation, str)
                    and bool(target_generation.strip())
                    and claims.get("assignment_generation") == target_generation
                )
            )
            and claims.get("max_requests") == 1
            and nonce == claims.get("nonce")
            and issued <= float(now_epoch) < expires
            and expires - issued <= 300
        )
        return nonce if valid else None


class DossierRejected(ValueError):
    """Backend evidence was incomplete, stale, inconsistent, or over budget."""


@dataclass(frozen=True, slots=True)
class VerifiedActionDossier:
    """Opaque short-lived backend authorization proof, sealed in process memory."""

    payload: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes) or not 1 <= len(self.payload) <= 16_384:
            raise DossierRejected("decision dossier is invalid")
        if not isinstance(self.signature, bytes) or len(self.signature) != 32:
            raise DossierRejected("decision dossier is invalid")

    def __repr__(self) -> str:
        return "VerifiedActionDossier([SEALED])"


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        raise DossierRejected("decision evidence is not canonical JSON") from None


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _epoch(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


class DecisionDossierAuthority:
    """Issue and verify short-lived evidence dossiers inside the backend.

    The HMAC key is generated in memory and never persisted or exposed through
    the control API. The only issuer entry point requires the complete
    ReallocationController assessment and matching evidence records; UI fields
    and booleans are not accepted as authorization material.
    """

    __slots__ = ("__key", "__evidence_verifier")

    def __init__(self, *, action_evidence_verifier: Any = None):
        if action_evidence_verifier is not None and any(
            not callable(getattr(action_evidence_verifier, method, None))
            for method in (
                "verify_controller_assessment", "verify_binding", "verify_provider",
                "verify_telemetry", "verify_low_evaluations", "verify_allocation_history", "verify_budget",
            )
        ):
            raise TypeError("action evidence verifier is incomplete")
        self.__key = secrets.token_bytes(32)
        self.__evidence_verifier = action_evidence_verifier

    def issue_reallocation(
        self,
        *,
        action: SaladAction,
        target: Mapping[str, Any],
        controller_assessment: Mapping[str, Any],
        binding_evidence: Mapping[str, Any],
        provider_revalidation: Mapping[str, Any],
        telemetry_sample: Mapping[str, Any],
        low_evaluations: list[Mapping[str, Any]],
        allocation_history: Mapping[str, Any],
        budget_evidence: Mapping[str, Any],
        reservation_snapshot: list[Mapping[str, Any]],
        hard_budget_usd: Any,
        now_epoch: float,
    ) -> VerifiedActionDossier:
        if action is not SaladAction.REALLOCATE_INSTANCE:
            raise DossierRejected("only reallocation can use a controller dossier")
        verifier = self.__evidence_verifier
        if verifier is None:
            raise DossierRejected("INDEPENDENT_ACTION_EVIDENCE_VERIFIER_NOT_CONFIGURED")
        if not all(isinstance(item, Mapping) for item in (
            target, controller_assessment, binding_evidence, provider_revalidation,
            telemetry_sample, allocation_history, budget_evidence,
        )) or not isinstance(low_evaluations, list) or not isinstance(reservation_snapshot, list):
            raise DossierRejected("backend evidence is incomplete")
        verifier_inputs = (
            ("verify_controller_assessment", controller_assessment),
            ("verify_binding", binding_evidence),
            ("verify_provider", provider_revalidation),
            ("verify_telemetry", telemetry_sample),
            ("verify_low_evaluations", low_evaluations),
            ("verify_allocation_history", allocation_history),
            ("verify_budget", budget_evidence),
        )
        try:
            independently_verified = all(getattr(verifier, method)(evidence) is True for method, evidence in verifier_inputs)
        except Exception:
            independently_verified = False
        if not independently_verified:
            raise DossierRejected("independent action evidence verification failed")
        synthetic_test_authority = getattr(verifier, "synthetic_test_only", False) is True
        now = _epoch(now_epoch)
        hard_cap = _money(hard_budget_usd)
        if now is None or hard_cap is None or hard_cap <= 0 or hard_cap > HARD_BUDGET_CAP_USD:
            raise DossierRejected("BUDGET_UNVERIFIABLE")

        required_target = {
            "organization": APPROVED_ORGANIZATION,
            "project": APPROVED_PROJECT,
            "container_group": target.get("container_group"),
            "instance_id": target.get("instance_id"),
            "assignment_id": target.get("assignment_id"),
            "deterioration_id": target.get("deterioration_id"),
        }
        if (
            target.get("organization") != APPROVED_ORGANIZATION
            or target.get("project") != APPROVED_PROJECT
            or target.get("container_group") not in APPROVED_GROUPS
            or not all(isinstance(required_target[key], str) and required_target[key].strip() for key in (
                "instance_id", "assignment_id", "deterioration_id"
            ))
        ):
            raise DossierRejected("controller target is outside verified scope")
        assessment_target = controller_assessment.get("recommendation", {}).get("target") if isinstance(controller_assessment.get("recommendation"), Mapping) else None
        aliases = {
            "organization": "organization_id", "project": "project_id",
            "container_group": "container_group_id", "instance_id": "instance_id",
            "assignment_id": "assignment_id",
        }
        if (
            controller_assessment.get("eligibility") != "CANDIDATE"
            or controller_assessment.get("action_status") != "DISABLED"
            or controller_assessment.get("actions_performed") is not False
            or not isinstance(assessment_target, Mapping)
            or any(assessment_target.get(source) != required_target[target_key] for target_key, source in aliases.items())
            or controller_assessment.get("guard_policy_hash") != controller_assessment.get("recommendation", {}).get("guard_policy_hash")
            or controller_assessment.get("deterioration_start_utc") != required_target["deterioration_id"]
        ):
            raise DossierRejected("ReallocationController assessment does not authorize this target")

        binding_provider = binding_evidence.get("provider") if isinstance(binding_evidence.get("provider"), Mapping) else {}
        binding_assignment = binding_evidence.get("assignment") if isinstance(binding_evidence.get("assignment"), Mapping) else {}
        binding_miner = binding_evidence.get("miner") if isinstance(binding_evidence.get("miner"), Mapping) else {}
        attestation_id = binding_evidence.get("attestation_evidence_id")
        verified_binding = (
            binding_evidence.get("binding_status") == "VERIFIED"
            and binding_evidence.get("actions_authorized_by_binding") is True
            and binding_evidence.get("data_classification") in {"INDEPENDENT_BINDING_ATTESTATION", "INDEPENDENT_ATTESTATION_VERIFIED"}
        )
        synthetic_binding = (
            synthetic_test_authority
            and binding_evidence.get("binding_status") == "SYNTHETIC/UNVERIFIED"
            and binding_evidence.get("actions_authorized_by_binding") is False
            and binding_evidence.get("data_classification") == "SYNTHETIC/UNVERIFIED"
            and binding_evidence.get("synthetic_fixture_id") == "G5-SYNTHETIC-ACTION-PATH"
        )
        if (
            not (verified_binding or synthetic_binding)
            or not isinstance(attestation_id, str) or not attestation_id.strip()
        ):
            raise DossierRejected("independent binding attestation is not verified")

        provider_provenance = provider_revalidation.get("source_provenance")
        provider_observed = (
            provider_revalidation.get("data_classification") == "PROVIDER_OBSERVED"
            and isinstance(provider_provenance, Mapping)
            and provider_provenance.get("system") == "salad_api"
            and provider_provenance.get("host") == "api.salad.com"
            and provider_provenance.get("transport_tls_hostname_verified") is True
        )
        synthetic_provider = (
            synthetic_test_authority
            and provider_revalidation.get("data_classification") == "SYNTHETIC/UNVERIFIED"
            and isinstance(provider_provenance, Mapping)
            and provider_provenance.get("system") == "synthetic_test_fixture"
            and provider_provenance.get("host") == "loopback"
            and provider_provenance.get("transport_tls_hostname_verified") is False
            and provider_revalidation.get("synthetic_fixture_id") == "G5-SYNTHETIC-ACTION-PATH"
        )
        if not (provider_observed or synthetic_provider) or str(provider_revalidation.get("reported_state", "")).casefold() != "running":
            raise DossierRejected("provider state was not independently revalidated")
        exact_identity = (
            ("organization_id", "organization", APPROVED_ORGANIZATION),
            ("project_id", "project", APPROVED_PROJECT),
            ("container_group_id", "container_group", target.get("container_group")),
            ("instance_id", "instance_id", target.get("instance_id")),
            ("assignment_id", "assignment_id", target.get("assignment_id")),
        )
        for field_name, target_key, expected in exact_identity:
            if provider_revalidation.get(field_name) != expected:
                raise DossierRejected("provider revalidation identity mismatch")
            if binding_provider.get(field_name) != expected:
                raise DossierRejected("independent binding provider identity mismatch")
            if binding_assignment.get(field_name) != expected:
                raise DossierRejected("independent binding assignment identity mismatch")

        if (
            binding_miner.get("track_id") != telemetry_sample.get("track_id")
            or binding_miner.get("device_namespace") != telemetry_sample.get("device_namespace")
            or str(binding_miner.get("device_id")) != str(telemetry_sample.get("device_id"))
            or not (
                telemetry_sample.get("data_classification") == "INDEPENDENT_WORKLOAD_EVIDENCE"
                or (
                    synthetic_test_authority
                    and telemetry_sample.get("data_classification") == "SYNTHETIC/UNVERIFIED"
                    and telemetry_sample.get("synthetic_fixture_id") == "G5-SYNTHETIC-ACTION-PATH"
                )
            )
            or telemetry_sample.get("instance_id") != target.get("instance_id")
            or telemetry_sample.get("assignment_id") != target.get("assignment_id")
            or telemetry_sample.get("hashrate_semantics") != "fl4shminer_device_reported"
        ):
            raise DossierRejected("independent device telemetry does not match the bound assignment")

        if len(low_evaluations) != 2:
            raise DossierRejected("two current low evaluations are required")
        evaluation_ids: list[str] = []
        floor_values: set[float] = set()
        for evaluation in low_evaluations:
            if not isinstance(evaluation, Mapping):
                raise DossierRejected("low-window evaluation is invalid")
            evaluated_at = _epoch(evaluation.get("evaluated_at_epoch"))
            floor = _money(evaluation.get("gpu_floor_ths"))
            observed = _money(evaluation.get("observed_window_hashrate_ths"))
            if (
                evaluation.get("decision") not in {"WOULD_REALLOCATE", "WOULD_WAIT"}
                or evaluation.get("hash_health") != "BELOW_CONFIGURED_FLOOR"
                or evaluation.get("guard_policy_hash") != controller_assessment.get("guard_policy_hash")
                or evaluation.get("instance_id") != target.get("instance_id")
                or evaluation.get("assignment_id") != target.get("assignment_id")
                or evaluated_at is None or evaluated_at > now or now - evaluated_at > 90
                or floor is None or observed is None or observed >= floor
            ):
                raise DossierRejected("low-window evidence is stale or inconsistent")
            evaluation_id = evaluation.get("evaluation_id")
            if not isinstance(evaluation_id, str) or not evaluation_id.strip():
                raise DossierRejected("low-window evaluation identifier is missing")
            evaluation_ids.append(evaluation_id)
            floor_values.add(float(floor))
        if len(set(evaluation_ids)) != 2 or len(floor_values) != 1:
            raise DossierRejected("low-window evaluations are duplicated or use different floors")

        if allocation_history.get("history_known") is not True:
            raise DossierRejected("reallocation history is unknown")
        allocation_count = allocation_history.get("allocation_reallocation_count")
        fleet_count = allocation_history.get("fleet_reallocation_count")
        cooldown_seconds = allocation_history.get("cooldown_seconds")
        last_action_epoch = allocation_history.get("last_reallocation_epoch")
        if (
            isinstance(allocation_count, bool) or not isinstance(allocation_count, int) or allocation_count < 0
            or isinstance(fleet_count, bool) or not isinstance(fleet_count, int) or fleet_count < 0
            or isinstance(cooldown_seconds, bool) or not isinstance(cooldown_seconds, int) or cooldown_seconds < 0
            or (allocation_count > 0 and (_epoch(last_action_epoch) is None or now - float(last_action_epoch) < cooldown_seconds))
        ):
            raise DossierRejected("cooldown or reallocation limits are not verifiable")

        financial = budget_evidence
        spent = _money(financial.get("verified_spend_usd"))
        next_cost = _money(financial.get("verified_next_action_cost_usd"))
        pending = _money(financial.get("pending_exposure_usd"))
        maximum = _money(financial.get("maximum_exposure_usd"))
        valid_until = _epoch(financial.get("valid_until_epoch"))
        if (
            financial.get("status") != "VERIFIED"
            or financial.get("currency") != "USD"
            or financial.get("pending_exposure_status") != "VERIFIED"
            or financial.get("maximum_exposure_status") != "VERIFIED"
            or not all(isinstance(financial.get(key), str) and financial[key].strip() for key in (
                "spend_evidence_id", "action_cost_evidence_id", "pending_exposure_evidence_id", "maximum_exposure_evidence_id"
            ))
            or spent is None or next_cost is None or pending is None or maximum is None
            or min(spent, next_cost, pending, maximum) < 0
            or valid_until is None or valid_until <= now
            or maximum != spent + pending + next_cost
        ):
            raise DossierRejected("BUDGET_UNVERIFIABLE")
        if maximum > hard_cap:
            raise DossierRejected("HARD_BUDGET_USD_30_EXCEEDED")

        unresolved = {"RESERVED", "SEND_STARTED", "ACCEPTED_PENDING", "RECONCILIATION_REQUIRED"}
        if any(
            not isinstance(item, Mapping) or item.get("state") in unresolved
            for item in reservation_snapshot
        ):
            raise DossierRejected("ACTION_RESERVATION_OR_RECONCILIATION_UNCLEAR")

        claims = {
            "schema_version": 1,
            "action": action.value,
            "target_sha256": _sha256(required_target),
            "controller_assessment_sha256": _sha256(dict(controller_assessment)),
            "binding_evidence_sha256": _sha256(dict(binding_evidence)),
            "provider_revalidation_sha256": _sha256(dict(provider_revalidation)),
            "telemetry_sample_sha256": _sha256(dict(telemetry_sample)),
            "low_evaluation_ids": evaluation_ids,
            "assignment_generation": target.get("assignment_id"),
            "guard_policy_hash": controller_assessment.get("guard_policy_hash"),
            "allocation_history_sha256": _sha256(dict(allocation_history)),
            "reservation_snapshot_sha256": _sha256(reservation_snapshot),
            "verified_total_exposure_usd": format(maximum, "f"),
            "hard_budget_usd": format(hard_cap, "f"),
            "action_cost_evidence_id": financial.get("action_cost_evidence_id"),
            "action_cost_source_reference": financial.get("action_cost_source_reference"),
            "action_cost_usd": format(next_cost, "f"),
            "binding_attestation_id": attestation_id,
            "issued_at_epoch": now,
            "expires_at_epoch": now + 30,
        }
        payload = _canonical_bytes(claims)
        signature = hmac.digest(self.__key, payload, "sha256")
        return VerifiedActionDossier(payload, signature)

    def issue_early_reallocation(
        self,
        *,
        action: SaladAction,
        target: Mapping[str, Any],
        decision: Mapping[str, Any],
        live_admission: Mapping[str, Any],
        source_evidence: Mapping[str, Any],
        policy_evidence: Mapping[str, Any],
        generation_evidence: Mapping[str, Any],
        binding_evidence: Mapping[str, Any],
        provider_revalidation: Mapping[str, Any],
        budget_evidence: Mapping[str, Any],
        allocation_history: Mapping[str, Any],
        proof_binding: Mapping[str, Any],
        reservation_snapshot: list[Mapping[str, Any]],
        hard_budget_usd: Any,
        now_epoch: float,
    ) -> VerifiedActionDossier:
        """Seal one short-lived EARLY admission without inventing two hash windows."""
        if action is not SaladAction.REALLOCATE_INSTANCE:
            raise DossierRejected("EARLY dossier is restricted to instance reallocation")
        verifier = self.__evidence_verifier
        early_methods = (
            "verify_early_decision", "verify_early_calibration", "verify_early_generation",
            "verify_early_revalidation",
        )
        if verifier is None or any(not callable(getattr(verifier, name, None)) for name in early_methods):
            raise DossierRejected("INDEPENDENT_EARLY_ACTION_EVIDENCE_VERIFIER_NOT_CONFIGURED")
        mappings = (
            target, decision, live_admission, source_evidence, policy_evidence,
            generation_evidence, binding_evidence, provider_revalidation,
            budget_evidence, allocation_history, proof_binding,
        )
        if any(not isinstance(value, Mapping) for value in mappings) or not isinstance(reservation_snapshot, list):
            raise DossierRejected("EARLY action evidence is incomplete")
        try:
            from .action_ledger import _reject_secrets
            for value in (*mappings, reservation_snapshot):
                _reject_secrets(value)
        except ValueError:
            raise DossierRejected("SECRET_LIKE_FIELDS_REJECTED") from None

        try:
            verified = (
                verifier.verify_early_decision(decision) is True
                and verifier.verify_early_calibration(decision) is True
                and verifier.verify_early_generation(generation_evidence) is True
                and verifier.verify_early_revalidation(proof_binding) is True
                and verifier.verify_binding(binding_evidence) is True
                and verifier.verify_provider(provider_revalidation) is True
                and verifier.verify_telemetry(source_evidence) is True
                and verifier.verify_budget(budget_evidence) is True
                and verifier.verify_allocation_history(allocation_history) is True
            )
        except Exception:
            verified = False
        if not verified:
            raise DossierRejected("independent EARLY action evidence verification failed")

        now = _epoch(now_epoch)
        hard_cap = _money(hard_budget_usd)
        if now is None or hard_cap is None or hard_cap <= 0 or hard_cap > HARD_BUDGET_CAP_USD:
            raise DossierRejected("BUDGET_UNVERIFIABLE")
        required_target = (
            "organization", "project", "container_group", "machine_id", "instance_id",
            "assignment_id", "assignment_generation", "deterioration_id",
        )
        if (
            target.get("organization") != APPROVED_ORGANIZATION
            or target.get("project") != APPROVED_PROJECT
            or target.get("container_group") not in APPROVED_GROUPS
            or any(not isinstance(target.get(name), str) or not target[name].strip() for name in required_target)
            or action is not SaladAction.REALLOCATE_INSTANCE
        ):
            raise DossierRejected("EARLY target is outside the fixed verified scope")
        if (
            decision.get("state") != "EARLY_UNDER_FLOOR"
            or decision.get("reason") != "UPPER_BOUND_BELOW_THRESHOLD"
            or decision.get("actions_performed") is not False
            or decision.get("action_eligible") is not False
            or decision.get("calibration_status") != "APPLIED_APPROVED_MEASURED_PAIRS"
            or decision.get("assignment_id") != target.get("assignment_id")
            or decision.get("assignment_generation") != target.get("assignment_generation")
            or decision.get("policy_hash") != policy_evidence.get("policy_hash")
            or source_evidence.get("source") != "FL4SHMINER_AUTOTUNE_LOG"
            or source_evidence.get("source_reference_sha256") != decision.get("source_reference_sha256")
            or policy_evidence.get("policy_hash") != decision.get("policy_hash")
            or policy_evidence.get("gpu_floors_ths", {}).get(decision.get("gpu_key")) != decision.get("floor_ths")
            or generation_evidence.get("status") != "CURRENT"
            or generation_evidence.get("assignment_id") != target.get("assignment_id")
            or generation_evidence.get("assignment_generation") != target.get("assignment_generation")
        ):
            raise DossierRejected("EARLY decision, calibration, policy, or generation mismatch")

        provider = binding_evidence.get("provider") if isinstance(binding_evidence.get("provider"), Mapping) else {}
        assignment = binding_evidence.get("assignment") if isinstance(binding_evidence.get("assignment"), Mapping) else {}
        expected_identity = {
            "organization_id": APPROVED_ORGANIZATION,
            "project_id": APPROVED_PROJECT,
            "container_group_id": target.get("container_group"),
            "instance_id": target.get("instance_id"),
            "machine_id": target.get("machine_id"),
            "assignment_id": target.get("assignment_id"),
            "assignment_generation": target.get("assignment_generation"),
        }
        if any(provider.get(key) != value or assignment.get(key) != value for key, value in expected_identity.items()):
            raise DossierRejected("EARLY binding identity does not match the exact target generation")
        if (
            provider_revalidation.get("organization_id") != APPROVED_ORGANIZATION
            or provider_revalidation.get("project_id") != APPROVED_PROJECT
            or provider_revalidation.get("container_group_id") != target.get("container_group")
            or provider_revalidation.get("instance_id") != target.get("instance_id")
            or provider_revalidation.get("assignment_id") != target.get("assignment_id")
            or provider_revalidation.get("assignment_generation") != target.get("assignment_generation")
            or provider_revalidation.get("machine_id") != provider.get("machine_id")
        ):
            raise DossierRejected("EARLY provider revalidation identity mismatch")
        if (
            live_admission.get("status") != "LIVE_ADMISSION_ELIGIBLE"
            or live_admission.get("admission_only") is not True
            or live_admission.get("live_action_eligible") is not True
            or live_admission.get("actions_performed") is not False
            or live_admission.get("request_submitted") is not False
            or live_admission.get("dossier_created") is not False
            or live_admission.get("policy_hash") != decision.get("policy_hash")
        ):
            raise DossierRejected("fresh LIVE admission is not eligible")
        if (
            proof_binding.get("assignment_id") != target.get("assignment_id")
            or proof_binding.get("assignment_generation") != target.get("assignment_generation")
            or proof_binding.get("instance_id") != target.get("instance_id")
            or proof_binding.get("machine_id") != provider.get("machine_id")
            or proof_binding.get("policy_hash") != decision.get("policy_hash")
            or not isinstance(proof_binding.get("evidence_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", proof_binding["evidence_sha256"]) is None
        ):
            raise DossierRejected("EARLY signed generation proof does not match the target")
        synthetic_test_authority = getattr(verifier, "synthetic_test_only", False) is True
        if synthetic_test_authority:
            if proof_binding.get("data_classification") != "SYNTHETIC/UNVERIFIED":
                raise DossierRejected("synthetic EARLY authority requires explicit synthetic proof provenance")
        elif proof_binding.get("data_classification") != "PROVIDER_OBSERVED":
            raise DossierRejected("provider-observed generation proof is required")

        spend = _money(budget_evidence.get("verified_spend_usd"))
        action_cost = _money(budget_evidence.get("verified_next_action_cost_usd"))
        pending = _money(budget_evidence.get("pending_exposure_usd"))
        maximum = _money(budget_evidence.get("maximum_exposure_usd"))
        if (
            budget_evidence.get("status") != "VERIFIED"
            or budget_evidence.get("currency") != "USD"
            or any(value is None or value < 0 for value in (spend, action_cost, pending, maximum))
            or maximum is None or maximum > hard_cap
            or maximum < spend + action_cost + pending  # type: ignore[operator]
            or not all(isinstance(budget_evidence.get(name), str) and budget_evidence[name].strip() for name in (
                "spend_evidence_id", "next_action_cost_evidence_id", "pending_exposure_evidence_id",
                "maximum_exposure_evidence_id", "action_cost_source_reference",
            ))
        ):
            raise DossierRejected("BUDGET_UNVERIFIABLE")
        if allocation_history.get("history_known") is not True:
            raise DossierRejected("REALLOCATION_HISTORY_UNKNOWN")
        if any(
            type(allocation_history.get(name)) is not int or allocation_history[name] < 0
            for name in ("allocation_reallocation_count", "fleet_reallocation_count")
        ):
            raise DossierRejected("REALLOCATION_HISTORY_UNKNOWN")
        if any(isinstance(row, Mapping) and row.get("state") in {
            "RESERVED", "SEND_STARTED", "ACCEPTED_PENDING", "RECONCILIATION_REQUIRED",
        } for row in reservation_snapshot):
            raise DossierRejected("ACTION_RESERVATION_OR_RECONCILIATION_UNCLEAR")

        claims = {
            "schema_version": 2,
            "dispatch_kind": "EARLY",
            "action": action.value,
            "target_sha256": _sha256(dict(target)),
            "assignment_generation": target["assignment_generation"],
            "decision_sha256": _sha256(dict(decision)),
            "live_admission_sha256": _sha256(dict(live_admission)),
            "source_evidence_sha256": _sha256(dict(source_evidence)),
            "policy_evidence_sha256": _sha256(dict(policy_evidence)),
            "generation_evidence_sha256": _sha256(dict(generation_evidence)),
            "binding_evidence_sha256": _sha256(dict(binding_evidence)),
            "provider_revalidation_sha256": _sha256(dict(provider_revalidation)),
            "proof_evidence_sha256": proof_binding["evidence_sha256"],
            "proof_binding_sha256": _sha256(dict(proof_binding)),
            "allocation_history_sha256": _sha256(dict(allocation_history)),
            "reservation_snapshot_sha256": _sha256(reservation_snapshot),
            "verified_total_exposure_usd": format(maximum, "f"),
            "hard_budget_usd": format(hard_cap, "f"),
            "action_cost_evidence_id": budget_evidence.get("next_action_cost_evidence_id"),
            "action_cost_source_reference": budget_evidence.get("action_cost_source_reference"),
            "action_cost_usd": format(action_cost, "f"),
            "data_classification": "SYNTHETIC/UNVERIFIED" if synthetic_test_authority else "PROVIDER_OBSERVED",
            "synthetic_fixture_id": "G5-SYNTHETIC-ACTION-PATH" if synthetic_test_authority else None,
            "issued_at_epoch": now,
            "expires_at_epoch": now + 30,
        }
        payload = _canonical_bytes(claims)
        signature = hmac.digest(self.__key, payload, "sha256")
        return VerifiedActionDossier(payload, signature)

    def verify_for(
        self,
        dossier: VerifiedActionDossier | None,
        *,
        action: SaladAction,
        target: Mapping[str, Any],
        now_epoch: float,
    ) -> bool:
        if type(dossier) is not VerifiedActionDossier or not isinstance(target, Mapping):
            return False
        try:
            expected = hmac.digest(self.__key, dossier.payload, "sha256")
            if not hmac.compare_digest(expected, dossier.signature):
                return False
            claims = json.loads(dossier.payload.decode("utf-8"))
            now = _epoch(now_epoch)
            schema_version = claims.get("schema_version")
            canonical_target = (
                dict(target) if schema_version == 2 else {
                    "organization": target.get("organization"), "project": target.get("project"),
                    "container_group": target.get("container_group"), "instance_id": target.get("instance_id"),
                    "assignment_id": target.get("assignment_id"), "deterioration_id": target.get("deterioration_id"),
                }
            )
            maximum = _money(claims.get("verified_total_exposure_usd"))
            hard_cap = _money(claims.get("hard_budget_usd"))
            return bool(
                type(action) is SaladAction
                and schema_version in {1, 2}
                and (schema_version != 2 or claims.get("dispatch_kind") == "EARLY")
                and claims.get("action") == action.value
                and claims.get("target_sha256") == _sha256(canonical_target)
                and now is not None
                and _epoch(claims.get("issued_at_epoch")) is not None
                and _epoch(claims.get("expires_at_epoch")) is not None
                and float(claims["issued_at_epoch"]) <= now < float(claims["expires_at_epoch"])
                and maximum is not None and hard_cap is not None
                and maximum <= hard_cap <= HARD_BUDGET_CAP_USD
                and claims.get("assignment_generation") == (
                    canonical_target.get("assignment_generation")
                    if schema_version == 2 else canonical_target.get("assignment_id")
                )
            )
        except Exception:
            return False

    def verified_claims(self, dossier: VerifiedActionDossier, *, now_epoch: float) -> Mapping[str, Any] | None:
        """Read sealed claims only after verifying the internal HMAC and TTL."""
        if type(dossier) is not VerifiedActionDossier:
            return None
        try:
            expected = hmac.digest(self.__key, dossier.payload, "sha256")
            if not hmac.compare_digest(expected, dossier.signature):
                return None
            claims = json.loads(dossier.payload.decode("utf-8"))
        except Exception:
            return None
        now = _epoch(now_epoch)
        if now is None or _epoch(claims.get("issued_at_epoch")) is None or _epoch(claims.get("expires_at_epoch")) is None:
            return None
        if not float(claims["issued_at_epoch"]) <= now < float(claims["expires_at_epoch"]):
            return None
        return claims

    def verify_reservation_snapshot(
        self,
        dossier: VerifiedActionDossier,
        *,
        current_snapshot: list[Mapping[str, Any]],
        now_epoch: float,
    ) -> bool:
        claims = self.verified_claims(dossier, now_epoch=now_epoch)
        return bool(
            claims is not None
            and isinstance(current_snapshot, list)
            and claims.get("reservation_snapshot_sha256") == _sha256(current_snapshot)
            and not any(
                not isinstance(row, Mapping)
                or row.get("state") in {"RESERVED", "SEND_STARTED", "ACCEPTED_PENDING", "RECONCILIATION_REQUIRED"}
                for row in current_snapshot
            )
        )


@dataclass(frozen=True)
class ActionDecision:
    action: SaladAction
    allowed: bool
    blockers: tuple[str, ...]
    actions_performed: bool = False


@dataclass(frozen=True)
class SaladActionPolicy:
    allowed_groups: tuple[str, ...] = APPROVED_GROUPS
    hard_budget_usd: Decimal = HARD_BUDGET_CAP_USD
    live_actions_enabled: bool = False
    live_spend_authorized: bool = False
    auto_reallocate: bool = False
    g5_reviewed: bool = False

    def __post_init__(self) -> None:
        try:
            value = Decimal(str(self.hard_budget_usd))
        except (InvalidOperation, ValueError):
            raise ValueError("hard budget must be a valid USD amount") from None
        if not value.is_finite() or value <= 0 or value > HARD_BUDGET_CAP_USD:
            raise ValueError("hard budget must be greater than zero and no more than USD 30.00")
        object.__setattr__(self, "hard_budget_usd", value)
        if tuple(self.allowed_groups) != APPROVED_GROUPS:
            raise ValueError("action group scope must exactly match the four approved groups")
        if self.auto_reallocate and not self.live_actions_enabled:
            raise ValueError("automatic reallocation cannot be armed while live actions are disabled")

    def evaluate(
        self,
        action: SaladAction,
        *,
        target: dict[str, Any],
        decision_dossier: VerifiedActionDossier | None,
        dossier_authority: DecisionDossierAuthority,
        kill_switch_clear: bool,
        auto_armed: bool = False,
        now_epoch: float | None = None,
    ) -> ActionDecision:
        if type(action) is not SaladAction:
            raise TypeError("action must be one of the fixed SaladAction values")
        blockers: list[str] = []
        if not self.g5_reviewed:
            blockers.append("G5_REVIEW_REQUIRED")
        if not self.live_actions_enabled:
            blockers.append("LIVE_ACTIONS_DISABLED")
        if not self.live_spend_authorized:
            blockers.append("LIVE_SPEND_NOT_AUTHORIZED")
        if not kill_switch_clear:
            blockers.append("KILL_SWITCH_ACTIVE")
        if target.get("organization") != APPROVED_ORGANIZATION or target.get("project") != APPROVED_PROJECT:
            blockers.append("TARGET_ORGANIZATION_OR_PROJECT_NOT_ALLOWLISTED")
        group = target.get("container_group")
        if group not in self.allowed_groups:
            blockers.append("TARGET_GROUP_NOT_ALLOWLISTED")
        if not isinstance(now_epoch, (int, float)) or isinstance(now_epoch, bool) or not math.isfinite(float(now_epoch)):
            blockers.append("DECISION_TIME_INVALID")
        dossier_valid = bool(
            type(dossier_authority) is DecisionDossierAuthority
            and dossier_authority.verify_for(
                decision_dossier,
                action=action,
                target=target,
                now_epoch=now_epoch if isinstance(now_epoch, (int, float)) else float("nan"),
            )
        )
        if not dossier_valid:
            blockers.extend(("BACKEND_DECISION_DOSSIER_REQUIRED", "BUDGET_UNVERIFIABLE"))
        if action is SaladAction.REALLOCATE_INSTANCE:
            try:
                uuid.UUID(target.get("instance_id"))
            except (ValueError, TypeError, AttributeError):
                blockers.append("INSTANCE_ID_UNKNOWN")
            for field in ("assignment_id", "deterioration_id"):
                if not isinstance(target.get(field), str) or not target[field].strip():
                    blockers.append(f"{field.upper()}_UNKNOWN")
        elif action in {SaladAction.START_GROUP, SaladAction.STOP_GROUP}:
            # G3 contract review did not verify these mutation routes. The UI
            # may expose the control with a reason, but the sender remains NO-GO.
            blockers.append("SALAD_GROUP_ACTION_CONTRACT_UNVERIFIED")
        if action in {SaladAction.START_GROUP, SaladAction.STOP_GROUP} and target.get("instance_id") is not None:
            blockers.append("GROUP_ACTION_MUST_NOT_TARGET_AN_INSTANCE")
        if decision_dossier is not None and dossier_valid:
            try:
                claims = json.loads(decision_dossier.payload.decode("utf-8"))
                exposure = _money(claims.get("verified_total_exposure_usd"))
                if exposure is None:
                    blockers.append("BUDGET_UNVERIFIABLE")
                elif exposure > min(self.hard_budget_usd, HARD_BUDGET_CAP_USD):
                    blockers.append("HARD_BUDGET_USD_30_EXCEEDED")
            except Exception:
                blockers.append("BUDGET_UNVERIFIABLE")
        if auto_armed and (action is not SaladAction.REALLOCATE_INSTANCE or not self.auto_reallocate):
            blockers.append("AUTO_REALLOCATION_NOT_ARMED")
        unique = tuple(sorted(set(blockers)))
        return ActionDecision(action=action, allowed=not unique, blockers=unique)


def _money(value: Any) -> Decimal | None:
    try:
        if isinstance(value, bool):
            return None
        result = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return result if result.is_finite() else None
