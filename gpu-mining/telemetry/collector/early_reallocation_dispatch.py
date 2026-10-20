"""Generation-bound dispatch bridge for calibrated EARLY startup decisions.

The bridge is disabled by default. It composes existing admission, proof,
binding-revalidation, dossier, ledger, and Salad action transport boundaries;
it does not create another HTTP client or provider route.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any

from .action_ledger import ActionLedger, _reject_secrets
from .auto_reallocation_gate import AutoReallocationGate
from .salad_action_policy import (
    APPROVED_GROUPS,
    APPROVED_ORGANIZATION,
    APPROVED_PROJECT,
    DecisionDossierAuthority,
    DossierRejected,
    SaladAction,
)
from .salad_action_transport import (
    ActionReceipt,
    RestrictedSaladActionHTTPTransport,
    SaladActionExecutor,
    fixed_action_path,
)
from .fl4sh_early_autotune import EarlyDecision
from log_alerts.provider_binding_revalidation import (
    ProviderBindingPreDispatchResult,
    ProviderBindingRevalidator,
)
from log_alerts.startup_v2_attestation import (
    StartupV2ProofHandle,
    _is_startup_v2_proof_handle,
)


_SAFE_REASON = re.compile(r"^[A-Z0-9_,.-]{1,160}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SYNTHETIC_FIXTURE = "G5-SYNTHETIC-ACTION-PATH"


@dataclass(frozen=True, slots=True)
class EarlyDispatchResult:
    status: str
    action_key: str | None = None
    reason_code: str | None = None
    http_status_code: int | None = None
    request_submitted: bool = False
    actions_performed: bool = False
    data_classification: str | None = None

    def __repr__(self) -> str:
        return (
            "EarlyDispatchResult("
            f"status={self.status!r}, reason_code={self.reason_code!r}, "
            f"http_status_code={self.http_status_code!r}, "
            f"request_submitted={self.request_submitted!r}, "
            f"actions_performed={self.actions_performed!r})"
        )


class EarlyReallocationDispatcher:
    """Connect one eligible LIVE EARLY decision to one reserved action attempt."""

    def __init__(
        self,
        *,
        gate: AutoReallocationGate,
        revalidator: ProviderBindingRevalidator,
        executor: SaladActionExecutor,
        dossier_authority: DecisionDossierAuthority,
        enabled: bool = False,
        epoch_clock: Callable[[], float] | None = None,
    ) -> None:
        if type(gate) is not AutoReallocationGate:
            raise TypeError("dispatcher requires the existing AutoReallocationGate")
        if type(revalidator) is not ProviderBindingRevalidator:
            raise TypeError("dispatcher requires the existing provider binding revalidator")
        if type(executor) is not SaladActionExecutor:
            raise TypeError("dispatcher requires the existing SaladActionExecutor")
        if type(dossier_authority) is not DecisionDossierAuthority:
            raise TypeError("dispatcher requires the backend decision dossier authority")
        if type(enabled) is not bool:
            raise TypeError("EARLY dispatch enable flag must be boolean")
        self.gate = gate
        self.revalidator = revalidator
        self.executor = executor
        self.dossier_authority = dossier_authority
        self.enabled = enabled
        self.epoch_clock = epoch_clock

    def dispatch(
        self,
        decision: EarlyDecision | Mapping[str, Any],
        *,
        proof_handle: StartupV2ProofHandle,
        source_evidence: Mapping[str, Any],
        policy_evidence: Mapping[str, Any],
        generation_evidence: Mapping[str, Any],
        budget_evidence: Mapping[str, Any],
        allocation_history: Mapping[str, Any],
        fleet_id: str,
        now_utc: datetime | Callable[[], datetime],
    ) -> EarlyDispatchResult:
        """Evaluate the LIVE gate, reserve, revalidate again, then dispatch once."""
        if not self.enabled:
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_DISPATCH_DISABLED")
        if (
            self.gate.admission_mode != "LIVE"
            or self.gate.live_transport_disabled is not True
            or self.gate.simulation_enabled is not False
        ):
            return EarlyDispatchResult("BLOCKED", reason_code="LIVE_ADMISSION_CONFIGURATION_INVALID")
        if not self._effective_transport_is_disabled():
            return EarlyDispatchResult("BLOCKED", reason_code="LIVE_TRANSPORT_EFFECTIVE_STATE_INVALID")
        if type(proof_handle) is not StartupV2ProofHandle or not _is_startup_v2_proof_handle(proof_handle):
            return EarlyDispatchResult("BLOCKED", reason_code="STARTUP_V2_PROOF_REQUIRED")
        if not isinstance(now_utc, datetime) and not callable(now_utc):
            return EarlyDispatchResult("BLOCKED", reason_code="DISPATCH_TIME_INVALID")
        try:
            decision_map = decision.to_dict() if type(decision) is EarlyDecision else dict(decision)
            _reject_secrets(decision_map)
            _reject_secrets(source_evidence)
            _reject_secrets(policy_evidence)
            _reject_secrets(generation_evidence)
            _reject_secrets(budget_evidence)
            _reject_secrets(allocation_history)
        except (TypeError, ValueError):
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_EVIDENCE_INVALID")

        binding = proof_handle.binding
        record = proof_handle.record
        reference = record.observation_reference
        classification = getattr(reference, "data_classification", None)
        if classification not in {"PROVIDER_OBSERVED", "SYNTHETIC/UNVERIFIED"}:
            return EarlyDispatchResult("BLOCKED", reason_code="PROOF_PROVENANCE_INVALID")
        if (
            getattr(reference, "organization", None) != APPROVED_ORGANIZATION
            or getattr(reference, "project", None) != APPROVED_PROJECT
            or getattr(reference, "container_group", None) not in APPROVED_GROUPS
            or binding.organization != APPROVED_ORGANIZATION
            or binding.project != APPROVED_PROJECT
            or binding.container_group != reference.container_group
            or binding.instance_id != reference.instance_id
            or binding.machine_id != reference.machine_id
            or binding.assignment_id != record.assignment_id
            or binding.assignment_generation != record.assignment_generation
            or binding.policy_hash != record.policy_hash
            or decision_map.get("state") != "EARLY_UNDER_FLOOR"
            or decision_map.get("reason") != "UPPER_BOUND_BELOW_THRESHOLD"
            or decision_map.get("calibration_status") != "APPLIED_APPROVED_MEASURED_PAIRS"
            or decision_map.get("assignment_id") != record.assignment_id
            or decision_map.get("assignment_generation") != record.assignment_generation
            or decision_map.get("policy_hash") != record.policy_hash
            or decision_map.get("source_reference_sha256") != source_evidence.get("source_reference_sha256")
            or not isinstance(decision_map.get("source_reference_sha256"), str)
            or _SHA256.fullmatch(decision_map["source_reference_sha256"]) is None
        ):
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_PROOF_OR_DECISION_MISMATCH")

        target = {
            "organization": reference.organization,
            "project": reference.project,
            "container_group": reference.container_group,
            "machine_id": binding.machine_id,
            "instance_id": binding.instance_id,
            "assignment_id": record.assignment_id,
            "assignment_generation": record.assignment_generation,
            "deterioration_id": decision_map["source_reference_sha256"],
        }
        try:
            fixed_action_path(SaladAction.REALLOCATE_INSTANCE, target)
        except (TypeError, ValueError):
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_FIXED_TARGET_INVALID")

        try:
            first_revalidation = self._revalidate(proof_handle, now_utc)
        except Exception:
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_PROVIDER_REVALIDATION_FAILED")
        if not self._valid_revalidation(first_revalidation, proof_handle):
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_PROVIDER_REVALIDATION_FAILED")
        typed_evidence = self._typed_binding_evidence(proof_handle, classification)
        provider_revalidation = self._typed_revalidation_evidence(
            proof_handle, first_revalidation, classification,
        )
        current_time = self._read_now(now_utc)
        if current_time is None:
            return EarlyDispatchResult("BLOCKED", reason_code="DISPATCH_TIME_INVALID")
        try:
            admission = self.gate.assess_early(
                decision_map,
                source_evidence=source_evidence,
                policy_evidence=policy_evidence,
                generation_evidence=generation_evidence,
                provider_binding=typed_evidence,
                provider_revalidation=provider_revalidation,
                budget_evidence=budget_evidence,
                allocation_history=allocation_history,
                fleet_id=fleet_id,
                now_utc=current_time.isoformat().replace("+00:00", "Z"),
                kill_switch_engaged=not bool(getattr(self.executor.kill_switch, "enabled", False)),
                auto_armed=False,
                live_actions_enabled=False,
                g5_authorized=False,
            )
        except Exception:
            return EarlyDispatchResult("BLOCKED", reason_code="LIVE_ADMISSION_FAILED_CLOSED")
        if not isinstance(admission, Mapping) or admission.get("status") != "LIVE_ADMISSION_ELIGIBLE":
            return EarlyDispatchResult("BLOCKED", reason_code="LIVE_ADMISSION_NOT_ELIGIBLE")
        if (
            admission.get("admission_only") is not True
            or admission.get("live_action_eligible") is not True
            or admission.get("actions_performed") is not False
            or admission.get("request_submitted") is not False
            or admission.get("dossier_created") is not False
            or admission.get("policy_hash") != decision_map.get("policy_hash")
        ):
            return EarlyDispatchResult("BLOCKED", reason_code="LIVE_ADMISSION_RESULT_INVALID")
        # Re-read the executor's actual transport after gate evaluation. The
        # constructor-time gate flag is not authoritative if the transport
        # was changed while this admission was in flight.
        if not self._effective_transport_is_disabled():
            return EarlyDispatchResult("BLOCKED", reason_code="LIVE_TRANSPORT_EFFECTIVE_STATE_INVALID")

        try:
            dossier = self.dossier_authority.issue_early_reallocation(
                action=SaladAction.REALLOCATE_INSTANCE,
                target=target,
                decision=decision_map,
                live_admission=admission,
                source_evidence=source_evidence,
                policy_evidence=policy_evidence,
                generation_evidence=generation_evidence,
                binding_evidence=typed_evidence,
                provider_revalidation=provider_revalidation,
                budget_evidence=budget_evidence,
                allocation_history=allocation_history,
                proof_binding=self._proof_binding(proof_handle, classification),
                reservation_snapshot=self.executor.ledger.snapshot(),
                hard_budget_usd=self.gate.hard_budget_cap_usd,
                now_epoch=self._read_epoch(),
            )
        except (DossierRejected, TypeError, ValueError):
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_DOSSIER_REJECTED")

        def revalidate_after_reservation() -> bool:
            if not self._effective_transport_is_disabled():
                return False
            result = self._revalidate(proof_handle, now_utc)
            return self._valid_revalidation(result, proof_handle)

        try:
            receipt = self.executor.execute(
                SaladAction.REALLOCATE_INSTANCE,
                target,
                decision_dossier=dossier,
                auto_armed=True,
                before_send_validation=revalidate_after_reservation,
            )
        except Exception:
            return EarlyDispatchResult("BLOCKED", reason_code="EARLY_EXECUTOR_FAILED_CLOSED")
        return self._public_result(receipt)

    def _effective_transport_is_disabled(self) -> bool:
        """Check current transport state, distinguishing the existing offline fake."""
        transport = self.executor.transport
        if type(transport) is RestrictedSaladActionHTTPTransport:
            return type(transport.enabled) is bool and transport.enabled is False
        if getattr(transport, "synthetic_test_only", None) is True:
            enabled = getattr(transport, "enabled", False)
            return type(enabled) is bool and enabled is False
        return False

    def _read_now(self, source: datetime | Callable[[], datetime]) -> datetime | None:
        try:
            current = source() if callable(source) else source
            if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
                return None
            return current.astimezone(timezone.utc)
        except Exception:
            return None

    def _read_epoch(self) -> float:
        if self.epoch_clock is None:
            return float(self.executor.clock())
        value = self.epoch_clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("invalid dispatch clock")
        return float(value)

    def _revalidate(
        self, proof_handle: StartupV2ProofHandle,
        now_utc: datetime | Callable[[], datetime],
    ) -> ProviderBindingPreDispatchResult:
        return self.revalidator.revalidate_pre_dispatch(proof_handle, now_utc=now_utc)

    @staticmethod
    def _valid_revalidation(
        result: ProviderBindingPreDispatchResult,
        proof_handle: StartupV2ProofHandle,
    ) -> bool:
        expected_classification = proof_handle.record.observation_reference.data_classification
        return bool(
            type(result) is ProviderBindingPreDispatchResult
            and result.binding_status == "BOUND_EXACT"
            and result.revalidation_status in {"REVALIDATED_MATCH_TEST_ONLY", "REVALIDATED_MATCH"}
            and result.reason in {"MATCH_TEST_ONLY", "MATCH"}
            and result.event_evidence_ref_sha256 == proof_handle.record.evidence_sha256
            and result.policy_hash == proof_handle.record.policy_hash
            and result.evidence_classification == expected_classification
        )

    @staticmethod
    def _typed_binding_evidence(
        proof_handle: StartupV2ProofHandle,
        classification: str,
    ) -> dict[str, Any]:
        binding = proof_handle.binding
        record = proof_handle.record
        reference = record.observation_reference
        identity = {
            "organization_id": reference.organization,
            "project_id": reference.project,
            "container_group_id": reference.container_group,
            "instance_id": binding.instance_id,
            "machine_id": binding.machine_id,
            "assignment_id": record.assignment_id,
            "assignment_generation": record.assignment_generation,
        }
        value = {
            "provider": dict(identity),
            "assignment": dict(identity),
            "binding_status": "VERIFIED" if classification == "PROVIDER_OBSERVED" else "SYNTHETIC/UNVERIFIED",
            "policy_hash": record.policy_hash,
            "actions_authorized_by_binding": classification == "PROVIDER_OBSERVED",
            "attestation_evidence_id": record.evidence_id,
            "evidence_sha256": record.evidence_sha256,
            "valid_from_utc": record.valid_from_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "revalidated_at_utc": record.revalidated_at_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "valid_until_utc": record.valid_until_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "data_classification": classification,
        }
        if classification == "SYNTHETIC/UNVERIFIED":
            value["synthetic_fixture_id"] = _SYNTHETIC_FIXTURE
        return value

    @staticmethod
    def _typed_revalidation_evidence(
        proof_handle: StartupV2ProofHandle,
        result: ProviderBindingPreDispatchResult,
        classification: str,
    ) -> dict[str, Any]:
        binding = proof_handle.binding
        reference = proof_handle.record.observation_reference
        provenance = (
            {"system": "salad_api", "host": "api.salad.com", "transport_tls_hostname_verified": True}
            if classification == "PROVIDER_OBSERVED"
            else {"system": "synthetic_test_fixture", "host": "loopback", "transport_tls_hostname_verified": False}
        )
        value = {
            "organization_id": reference.organization,
            "project_id": reference.project,
            "container_group_id": reference.container_group,
            "instance_id": binding.instance_id,
            "machine_id": binding.machine_id,
            "assignment_id": binding.assignment_id,
            "assignment_generation": binding.assignment_generation,
            "reported_state": "running",
            "observed_at_utc": result.revalidated_at_utc,
            "source_provenance": provenance,
            "data_classification": classification,
        }
        if classification == "SYNTHETIC/UNVERIFIED":
            value["synthetic_fixture_id"] = _SYNTHETIC_FIXTURE
        return value

    @staticmethod
    def _proof_binding(proof_handle: StartupV2ProofHandle, classification: str) -> dict[str, Any]:
        binding = proof_handle.binding
        record = proof_handle.record
        value = {
            "instance_id": binding.instance_id,
            "machine_id": binding.machine_id,
            "assignment_id": record.assignment_id,
            "assignment_generation": record.assignment_generation,
            "policy_hash": record.policy_hash,
            "evidence_sha256": record.evidence_sha256,
            "data_classification": classification,
        }
        if classification == "SYNTHETIC/UNVERIFIED":
            value["synthetic_fixture_id"] = _SYNTHETIC_FIXTURE
        return value

    @staticmethod
    def _public_result(receipt: ActionReceipt) -> EarlyDispatchResult:
        reason = receipt.reason
        reason_code = reason if isinstance(reason, str) and _SAFE_REASON.fullmatch(reason) else None
        return EarlyDispatchResult(
            status=receipt.status,
            action_key=receipt.action_key,
            reason_code=reason_code,
            http_status_code=receipt.http_status_code,
            request_submitted=receipt.request_submitted is True,
            actions_performed=receipt.actions_performed is True,
            data_classification=receipt.data_classification,
        )
