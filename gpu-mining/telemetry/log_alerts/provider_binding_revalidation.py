"""Offline-only fresh binding checks for the startup pre-dispatch boundary.

This module deliberately has no Salad transport. The only source implemented
here is a signed, in-memory synthetic fixture source used by offline tests.
Missing, stale or mismatched evidence is always UNKNOWN and never an action
permit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import time
from types import MappingProxyType
from typing import Any, Protocol

from collector.fl4sh_early_autotune import (
    AssociationEvidenceRecord,
    BindingAttestation,
    _gpu_key,
    ProviderBinding,
    ProviderLogObservationReference,
    association_evidence_sha256,
)
from .live_transport import ProviderResponseEvidence
from .startup_v2_attestation import StartupV2ProofHandle, _is_startup_v2_proof_handle


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z", re.ASCII)
_SAFE_NAME = re.compile(r"[a-z][a-z0-9-]{0,61}[a-z0-9]\Z", re.ASCII)
_SHA256 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_SAFE_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z", re.ASCII)
MAX_PROVIDER_READ_DURATION_SECONDS = 5.0
_ALLOWED_REASONS = frozenset({
    "ATTESTATION_GENERATION_MISMATCH",
    "ATTESTATION_STALE",
    "ATTESTATION_TIME_INVALID",
    "ASSIGNMENT_GENERATION_MISMATCH",
    "ASSIGNMENT_IDENTITY_MISMATCH",
    "ASSIGNMENT_NOT_RUNNING",
    "ASSIGNMENT_STATE_FUTURE",
    "ASSIGNMENT_STATE_STALE",
    "DEVICE_IDENTITY_UNVERIFIED",
    "EVENT_NOT_ELIGIBLE",
    "MATCH_TEST_ONLY",
    "NO_VERIFIED_V2_PROOF",
    "POLICY_HASH_MISMATCH",
    "SCOPE_NOT_ALLOWLISTED",
    "SOURCE_DUPLICATE_ASSIGNMENT",
    "SOURCE_READ_FAILED",
    "SOURCE_RESPONSE_INVALID",
    "SOURCE_READ_CLOCK_INVALID",
    "SOURCE_READ_TIMEOUT",
    "SOURCE_SCOPE_MISMATCH",
    "SOURCE_SIGNATURE_INVALID",
    "SOURCE_UNAVAILABLE",
    "SOURCE_WALL_CLOCK_ROLLBACK",
})
_ALLOWED_STATES = frozenset({"RUNNING", "STARTING", "STOPPED", "FAILED", "UNKNOWN"})


def _safe_id(value: object) -> bool:
    return isinstance(value, str) and _SAFE_ID.fullmatch(value) is not None and value != "*"


def _safe_name(value: object) -> bool:
    return isinstance(value, str) and _SAFE_NAME.fullmatch(value) is not None and value != "*"


def _utc(value: object) -> datetime | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    return value.astimezone(timezone.utc)


def _time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ExactSaladAssignmentTarget:
    """Exact organization/project/group name and provider-ID mapping."""

    organization_name: str
    project_name: str
    container_group_name: str
    organization_id: str
    project_id: str
    container_group_id: str
    tenant_id: str | None = None
    account_id: str | None = None

    def __post_init__(self) -> None:
        if not all(_safe_name(value) for value in (
            self.organization_name, self.project_name, self.container_group_name,
        )) or not all(_safe_id(value) for value in (
            self.organization_id, self.project_id, self.container_group_id,
        )):
            raise ValueError("INVALID_EXACT_PROVIDER_TARGET")
        if self.tenant_id is not None and not _safe_id(self.tenant_id):
            raise ValueError("INVALID_EXACT_PROVIDER_TARGET")
        if self.account_id is not None and not _safe_id(self.account_id):
            raise ValueError("INVALID_EXACT_PROVIDER_TARGET")

    def __repr__(self) -> str:
        return "ExactSaladAssignmentTarget(scope=[REDACTED])"


@dataclass(frozen=True, slots=True)
class ExplicitBindingAllowlist:
    """Immutable, unique explicit scope; wildcard and duplicate aliases fail."""

    targets: tuple[ExactSaladAssignmentTarget, ...]

    def __post_init__(self) -> None:
        if type(self.targets) is not tuple or not self.targets or any(
            type(item) is not ExactSaladAssignmentTarget for item in self.targets
        ):
            raise ValueError("INVALID_BINDING_ALLOWLIST")
        names = tuple((item.organization_name, item.project_name, item.container_group_name) for item in self.targets)
        ids = tuple((item.organization_id, item.project_id, item.container_group_id) for item in self.targets)
        if len(set(names)) != len(names) or len(set(ids)) != len(ids):
            raise ValueError("DUPLICATE_BINDING_ALLOWLIST_TARGET")

    def find(self, reference: ProviderLogObservationReference) -> ExactSaladAssignmentTarget | None:
        matches = tuple(
            target for target in self.targets
            if (target.organization_name, target.project_name, target.container_group_name)
            == (reference.organization, reference.project, reference.container_group)
        )
        return matches[0] if len(matches) == 1 else None

    def for_organization(self, organization_name: str) -> "ExplicitBindingAllowlist":
        selected = tuple(item for item in self.targets if item.organization_name == organization_name)
        if not selected:
            raise ValueError("BINDING_ALLOWLIST_ORGANIZATION_MISSING")
        return ExplicitBindingAllowlist(selected)

    def __repr__(self) -> str:
        return f"ExplicitBindingAllowlist(targets={len(self.targets)}, values=[REDACTED])"


@dataclass(frozen=True, slots=True, repr=False)
class SignedSyntheticProviderSnapshot:
    """One signed test fixture representing a current List Instances response."""

    target: ExactSaladAssignmentTarget
    instance_id: str
    machine_id: str
    assignment_id: str
    assignment_generation: str
    state: str
    observed_at_utc: datetime
    policy_hash: str
    tenant_id: str | None
    account_id: str | None
    request_method: str
    request_path: str
    response_evidence: ProviderResponseEvidence
    authority_id: str
    key_id: str
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.target) is not ExactSaladAssignmentTarget:
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if not all(_safe_id(value) for value in (
            self.instance_id, self.machine_id, self.assignment_id, self.assignment_generation,
            self.authority_id, self.key_id,
        )):
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if self.state not in _ALLOWED_STATES or _utc(self.observed_at_utc) is None:
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if not _SHA256.fullmatch(self.policy_hash if isinstance(self.policy_hash, str) else ""):
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if self.tenant_id is not None and not _safe_id(self.tenant_id):
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if self.account_id is not None and not _safe_id(self.account_id):
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if self.request_method != "GET" or type(self.request_path) is not str:
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if type(self.response_evidence) is not ProviderResponseEvidence:
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if not _safe_id(self.authority_id) or not _safe_id(self.key_id):
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SNAPSHOT")

    def __repr__(self) -> str:
        return "SignedSyntheticProviderSnapshot(identity=[REDACTED], signature=[REDACTED])"


def synthetic_snapshot_signature_payload(snapshot: SignedSyntheticProviderSnapshot) -> bytes:
    """Canonical signed bytes exposed for synthetic test-fixture construction."""
    if type(snapshot) is not SignedSyntheticProviderSnapshot:
        raise TypeError("exact synthetic provider snapshot required")
    target = snapshot.target
    payload = {
        "schema_version": 1,
        "target": {
            "organization_name": target.organization_name,
            "project_name": target.project_name,
            "container_group_name": target.container_group_name,
            "organization_id": target.organization_id,
            "project_id": target.project_id,
            "container_group_id": target.container_group_id,
            "tenant_id": target.tenant_id,
            "account_id": target.account_id,
        },
        "assignment": {
            "instance_id": snapshot.instance_id,
            "machine_id": snapshot.machine_id,
            "assignment_id": snapshot.assignment_id,
            "assignment_generation": snapshot.assignment_generation,
            "state": snapshot.state,
            "observed_at_utc": _time_text(snapshot.observed_at_utc),
            "policy_hash": snapshot.policy_hash,
            "tenant_id": snapshot.tenant_id,
            "account_id": snapshot.account_id,
        },
        "request": {"method": snapshot.request_method, "path": snapshot.request_path},
        "response_sha256": snapshot.response_evidence.response_sha256,
        "authority_id": snapshot.authority_id,
        "key_id": snapshot.key_id,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


class ReadOnlyFreshProviderSource(Protocol):
    """Synchronous cache-bypassing source contract; no live implementation here."""

    offline_test_only: bool

    def read_current_assignments(
        self, target: ExactSaladAssignmentTarget, *, bypass_cache: bool,
        timeout_seconds: float,
    ) -> tuple[SignedSyntheticProviderSnapshot, ...]: ...


class SyntheticFreshProviderSource:
    """In-memory, signed, one-response-per-call source used only by offline tests."""

    __slots__ = (
        "_target", "_authorities", "_responses", "_read_index", "_calls",
        "_last_timeout_seconds", "offline_test_only",
    )

    def __init__(
        self,
        *,
        target: ExactSaladAssignmentTarget,
        trusted_authorities: Mapping[str, tuple[str, bytes]],
        responses: Sequence[Sequence[SignedSyntheticProviderSnapshot]],
    ) -> None:
        if type(target) is not ExactSaladAssignmentTarget:
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_SOURCE")
        if not isinstance(trusted_authorities, Mapping) or not trusted_authorities:
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_TRUST_STORE")
        clean: dict[str, tuple[str, bytes]] = {}
        for key_id, value in trusted_authorities.items():
            if (
                not _safe_id(key_id) or type(value) is not tuple or len(value) != 2
                or not _safe_id(value[0]) or not isinstance(value[1], bytes) or len(value[1]) != 32
            ):
                raise ValueError("INVALID_SYNTHETIC_PROVIDER_TRUST_STORE")
            clean[key_id] = (value[0], bytes(value[1]))
        if not isinstance(responses, Sequence) or isinstance(responses, (str, bytes)) or len(responses) > 32:
            raise ValueError("SYNTHETIC_PROVIDER_RESPONSE_LIMIT")
        clean_responses: list[tuple[SignedSyntheticProviderSnapshot, ...]] = []
        for response in responses:
            if not isinstance(response, Sequence) or isinstance(response, (str, bytes)) or len(response) > 100:
                raise ValueError("SYNTHETIC_PROVIDER_ENTRY_LIMIT")
            if any(type(item) is not SignedSyntheticProviderSnapshot for item in response):
                raise ValueError("INVALID_SYNTHETIC_PROVIDER_RESPONSE")
            clean_responses.append(tuple(response))
        self._target = target
        self._authorities = MappingProxyType(clean)
        self._responses = tuple(clean_responses)
        self._read_index = 0
        self._calls = 0
        self._last_timeout_seconds: float | None = None
        self.offline_test_only = True

    @property
    def read_calls(self) -> int:
        return self._calls

    @property
    def last_timeout_seconds(self) -> float | None:
        return self._last_timeout_seconds

    @property
    def trusted_authorities(self) -> Mapping[str, tuple[str, bytes]]:
        return self._authorities

    def read_current_assignments(
        self, target: ExactSaladAssignmentTarget, *, bypass_cache: bool,
        timeout_seconds: float,
    ) -> tuple[SignedSyntheticProviderSnapshot, ...]:
        if (
            type(target) is not ExactSaladAssignmentTarget or bypass_cache is not True
            or target != self._target or type(timeout_seconds) not in (int, float)
            or not math.isfinite(float(timeout_seconds))
            or not 0 < float(timeout_seconds) <= MAX_PROVIDER_READ_DURATION_SECONDS
        ):
            raise ValueError("INVALID_SYNTHETIC_PROVIDER_READ")
        self._calls += 1
        self._last_timeout_seconds = float(timeout_seconds)
        if self._read_index >= len(self._responses):
            return ()
        response = self._responses[self._read_index]
        self._read_index += 1
        return response

    def __repr__(self) -> str:
        return f"SyntheticFreshProviderSource(responses={len(self._responses)}, values=[REDACTED])"


@dataclass(frozen=True, slots=True)
class ProviderBindingPreDispatchResult:
    binding_status: str
    revalidation_status: str
    reason: str
    evidence_classification: str
    event_evidence_ref_sha256: str | None = None
    assignment_evidence_ref_sha256: str | None = None
    device_evidence_ref_sha256: str | None = None
    policy_hash: str | None = None
    observed_at_utc: str | None = None
    revalidated_at_utc: str | None = None

    def __post_init__(self) -> None:
        if self.binding_status not in {"BOUND_EXACT", "UNKNOWN"}:
            raise ValueError("INVALID_BINDING_RESULT")
        if self.revalidation_status not in {"REVALIDATED_MATCH_TEST_ONLY", "REVALIDATION_BLOCKED"}:
            raise ValueError("INVALID_BINDING_RESULT")
        if self.reason not in _ALLOWED_REASONS or not _SAFE_REASON.fullmatch(self.reason):
            raise ValueError("INVALID_BINDING_RESULT")
        if self.evidence_classification not in {"SYNTHETIC/UNVERIFIED", "UNKNOWN"}:
            raise ValueError("INVALID_BINDING_RESULT")
        for value in (self.event_evidence_ref_sha256, self.assignment_evidence_ref_sha256, self.device_evidence_ref_sha256, self.policy_hash):
            if value is not None and not _SHA256.fullmatch(value):
                raise ValueError("INVALID_BINDING_RESULT")

    @property
    def action_eligible(self) -> bool:
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_status": self.binding_status,
            "revalidation_status": self.revalidation_status,
            "reason": self.reason,
            "evidence_classification": self.evidence_classification,
            "event_evidence_ref_sha256": self.event_evidence_ref_sha256,
            "assignment_evidence_ref_sha256": self.assignment_evidence_ref_sha256,
            "device_evidence_ref_sha256": self.device_evidence_ref_sha256,
            "policy_hash": self.policy_hash,
            "observed_at_utc": self.observed_at_utc,
            "revalidated_at_utc": self.revalidated_at_utc,
            "action_eligible": False,
            "actions_performed": False,
            "request_submitted": False,
        }

    def __repr__(self) -> str:
        return f"ProviderBindingPreDispatchResult({self.binding_status}, {self.revalidation_status}, reason={self.reason})"


class ProviderBindingRevalidator:
    """Single bounded synchronous uncached test-only check; it never returns authority."""

    __slots__ = ("_allowlist", "_source", "_maximum_age_seconds")

    def __init__(
        self,
        *,
        allowlist: ExplicitBindingAllowlist,
        source: ReadOnlyFreshProviderSource | None,
        maximum_age_seconds: int | float = 15,
    ) -> None:
        if type(allowlist) is not ExplicitBindingAllowlist:
            raise ValueError("INVALID_BINDING_ALLOWLIST")
        if source is not None and type(source) is not SyntheticFreshProviderSource:
            raise ValueError("ONLY_SYNTHETIC_OFFLINE_SOURCE_IS_IMPLEMENTED")
        if source is not None and source._target not in allowlist.targets:
            raise ValueError("SOURCE_TARGET_NOT_ALLOWLISTED")
        if (
            isinstance(maximum_age_seconds, bool)
            or not isinstance(maximum_age_seconds, (int, float))
            or not math.isfinite(float(maximum_age_seconds))
            or not 1 <= maximum_age_seconds <= 15
        ):
            raise ValueError("INVALID_PROVIDER_REVALIDATION_AGE")
        self._allowlist = allowlist
        self._source = source
        self._maximum_age_seconds = float(maximum_age_seconds)

    @property
    def offline_test_only(self) -> bool:
        return True

    @property
    def organization_names(self) -> frozenset[str]:
        return frozenset(item.organization_name for item in self._allowlist.targets)

    @property
    def allowed_targets(self) -> tuple[ExactSaladAssignmentTarget, ...]:
        return self._allowlist.targets

    def revalidate_pre_dispatch(
        self,
        proof_handle: StartupV2ProofHandle | None,
        *,
        now_utc: datetime | Callable[[], datetime],
    ) -> ProviderBindingPreDispatchResult:
        if isinstance(now_utc, datetime):
            now_reader = lambda: now_utc
        elif callable(now_utc):
            now_reader = now_utc
        else:
            return self._blocked("SOURCE_RESPONSE_INVALID")
        try:
            initial_now = _utc(now_reader())
        except Exception:
            initial_now = None
        if initial_now is None:
            return self._blocked("SOURCE_RESPONSE_INVALID")
        if not _is_startup_v2_proof_handle(proof_handle):
            return self._blocked("NO_VERIFIED_V2_PROOF")
        assert proof_handle is not None
        binding, record = proof_handle.binding, proof_handle.record
        if not self._valid_signed_binding(binding, record):
            return self._blocked("NO_VERIFIED_V2_PROOF")
        proof_time_reason = self._proof_time_reason(proof_handle, initial_now)
        if proof_time_reason is not None:
            return self._blocked(proof_time_reason, proof_handle=proof_handle)
        reference = record.observation_reference
        if type(reference) is not ProviderLogObservationReference:
            return self._blocked("NO_VERIFIED_V2_PROOF")
        target = self._allowlist.find(reference)
        if target is None:
            return self._blocked("SCOPE_NOT_ALLOWLISTED", proof_handle=proof_handle)
        if self._source is None:
            return self._blocked("SOURCE_UNAVAILABLE", proof_handle=proof_handle)
        if self._source._target != target:
            return self._blocked("SOURCE_SCOPE_MISMATCH", proof_handle=proof_handle)
        try:
            read_started = time.monotonic()
        except Exception:
            return self._blocked("SOURCE_READ_CLOCK_INVALID", proof_handle=proof_handle)
        if isinstance(read_started, bool) or not isinstance(read_started, (int, float)) or not math.isfinite(read_started):
            return self._blocked("SOURCE_READ_CLOCK_INVALID", proof_handle=proof_handle)
        try:
            snapshots = self._source.read_current_assignments(
                target,
                bypass_cache=True,
                timeout_seconds=MAX_PROVIDER_READ_DURATION_SECONDS,
            )
        except Exception:
            return self._blocked("SOURCE_READ_FAILED", proof_handle=proof_handle)
        try:
            read_finished = time.monotonic()
        except Exception:
            return self._blocked("SOURCE_READ_CLOCK_INVALID", proof_handle=proof_handle)
        if (
            isinstance(read_finished, bool) or not isinstance(read_finished, (int, float))
            or not math.isfinite(read_finished) or read_finished < read_started
        ):
            return self._blocked("SOURCE_READ_CLOCK_INVALID", proof_handle=proof_handle)
        if read_finished - read_started > MAX_PROVIDER_READ_DURATION_SECONDS:
            return self._blocked("SOURCE_READ_TIMEOUT", proof_handle=proof_handle)
        # Re-read the clock after the synchronous provider read. The proof and
        # response must still be fresh at the point this check completes.
        try:
            now = _utc(now_reader())
        except Exception:
            now = None
        if now is None:
            return self._blocked("SOURCE_RESPONSE_INVALID", proof_handle=proof_handle)
        if now < initial_now:
            return self._blocked("SOURCE_WALL_CLOCK_ROLLBACK", proof_handle=proof_handle)
        proof_time_reason = self._proof_time_reason(proof_handle, now)
        if proof_time_reason is not None:
            return self._blocked(proof_time_reason, proof_handle=proof_handle)
        if type(snapshots) is not tuple or len(snapshots) != 1:
            return self._blocked(
                "SOURCE_DUPLICATE_ASSIGNMENT" if len(snapshots) > 1 else "SOURCE_RESPONSE_INVALID",
                proof_handle=proof_handle,
            )
        current = snapshots[0]
        if type(current) is not SignedSyntheticProviderSnapshot:
            return self._blocked("SOURCE_RESPONSE_INVALID", proof_handle=proof_handle)
        verified = self._verify_snapshot(current)
        if verified is None:
            return self._blocked("SOURCE_SIGNATURE_INVALID", proof_handle=proof_handle)
        _authority_id, _public_key = verified
        if (
            current.target != target
            or current.request_method != "GET"
            or current.request_path != self._instances_path(target)
            or current.response_evidence.status_code != 200
            or current.response_evidence.source != "offline_test_transport"
            or current.response_evidence.classification != "SYNTHETIC/UNVERIFIED"
        ):
            return self._blocked("SOURCE_RESPONSE_INVALID", proof_handle=proof_handle)
        if reference.data_classification != "SYNTHETIC/UNVERIFIED":
            return self._blocked("SOURCE_RESPONSE_INVALID", proof_handle=proof_handle)
        observed = _utc(current.observed_at_utc)
        if observed is None:
            return self._blocked("SOURCE_RESPONSE_INVALID", proof_handle=proof_handle)
        age = (now - observed).total_seconds()
        if age < 0:
            return self._blocked("ASSIGNMENT_STATE_FUTURE", proof_handle=proof_handle, current=current)
        if age > self._maximum_age_seconds:
            return self._blocked("ASSIGNMENT_STATE_STALE", proof_handle=proof_handle, current=current)
        if current.state != "RUNNING":
            return self._blocked("ASSIGNMENT_NOT_RUNNING", proof_handle=proof_handle, current=current)
        if target.tenant_id is not None and current.tenant_id != target.tenant_id:
            return self._blocked("SOURCE_SCOPE_MISMATCH", proof_handle=proof_handle, current=current)
        if target.account_id is not None and current.account_id != target.account_id:
            return self._blocked("SOURCE_SCOPE_MISMATCH", proof_handle=proof_handle, current=current)
        if (
            current.target.organization_id != target.organization_id
            or current.target.project_id != target.project_id
            or current.target.container_group_id != target.container_group_id
            or current.instance_id != binding.instance_id
            or current.machine_id != binding.machine_id
        ):
            return self._blocked("ASSIGNMENT_IDENTITY_MISMATCH", proof_handle=proof_handle, current=current)
        if (
            current.assignment_id != record.assignment_id
            or current.assignment_generation != record.assignment_generation
        ):
            return self._blocked("ASSIGNMENT_GENERATION_MISMATCH", proof_handle=proof_handle, current=current)
        if current.policy_hash != binding.policy_hash or current.policy_hash != record.policy_hash:
            return self._blocked("POLICY_HASH_MISMATCH", proof_handle=proof_handle, current=current)
        if (
            type(binding.device_index) is not int or not 0 <= binding.device_index <= 999
            or not _gpu_key(binding.gpu_key)
        ):
            return self._blocked("DEVICE_IDENTITY_UNVERIFIED", proof_handle=proof_handle, current=current)
        assignment_hash = hashlib.sha256(json.dumps([
            current.target.organization_id, current.target.project_id, current.target.container_group_id,
            current.instance_id, current.machine_id, current.assignment_id, current.assignment_generation,
        ], separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
        device_hash = hashlib.sha256(json.dumps([
            reference.device_namespace, binding.device_index, binding.gpu_key,
            reference.gpu_identity_source_sha256, binding.policy_hash,
        ], separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
        snapshot_hash = hashlib.sha256(synthetic_snapshot_signature_payload(current)).hexdigest()
        return ProviderBindingPreDispatchResult(
            "BOUND_EXACT", "REVALIDATED_MATCH_TEST_ONLY", "MATCH_TEST_ONLY",
            "SYNTHETIC/UNVERIFIED", record.evidence_sha256, snapshot_hash, device_hash,
            binding.policy_hash, _time_text(observed), _time_text(now),
        )

    @staticmethod
    def _valid_signed_binding(binding: ProviderBinding, record: AssociationEvidenceRecord) -> bool:
        reference = record.observation_reference
        attestation = binding.attestation
        return bool(
            type(binding) is ProviderBinding
            and type(record) is AssociationEvidenceRecord
            and type(reference) is ProviderLogObservationReference
            and type(attestation) is BindingAttestation
            and record.status == "VERIFIED"
            and association_evidence_sha256(record) == record.evidence_sha256
            and record.observation_reference == binding.observation_reference
            and attestation.evidence_id == record.evidence_id
            and attestation.evidence_sha256 == record.evidence_sha256
            and binding.status == "VERIFIED"
            and binding.source == record.source == "SYNTHETIC_TEST_ONLY"
            and binding.assignment_id == record.assignment_id
            and binding.assignment_generation == record.assignment_generation
            and binding.policy_hash == record.policy_hash
            and binding.valid_from_utc == record.valid_from_utc
            and binding.revalidated_at_utc == record.revalidated_at_utc
            and binding.valid_until_utc == record.valid_until_utc
            and binding.machine_id == reference.machine_id
            and binding.instance_id == reference.instance_id
            and reference.data_classification == "SYNTHETIC/UNVERIFIED"
        )

    @staticmethod
    def _proof_time_reason(proof_handle: StartupV2ProofHandle, now: datetime) -> str | None:
        record = proof_handle.record
        valid_from = _utc(record.valid_from_utc)
        valid_until = _utc(record.valid_until_utc)
        revalidated = _utc(record.revalidated_at_utc)
        if valid_from is None or valid_until is None or revalidated is None:
            return "ATTESTATION_TIME_INVALID"
        if not valid_from <= revalidated <= valid_until or now < revalidated:
            return "ATTESTATION_GENERATION_MISMATCH"
        if now > valid_until:
            return "ATTESTATION_STALE"
        if (now - revalidated).total_seconds() > proof_handle.max_binding_age_seconds:
            return "ATTESTATION_STALE"
        return None

    def _verify_snapshot(
        self, snapshot: SignedSyntheticProviderSnapshot,
    ) -> tuple[str, bytes] | None:
        trusted = self._source.trusted_authorities.get(snapshot.key_id) if self._source is not None else None
        if trusted is None or trusted[0] != snapshot.authority_id:
            return None
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(trusted[1]).verify(
                snapshot.signature, synthetic_snapshot_signature_payload(snapshot),
            )
        except Exception:
            return None
        return trusted

    @staticmethod
    def _instances_path(target: ExactSaladAssignmentTarget) -> str:
        return (
            f"/api/public/organizations/{target.organization_name}/projects/{target.project_name}/"
            f"containers/{target.container_group_name}/instances"
        )

    @staticmethod
    def _blocked(
        reason: str,
        *,
        proof_handle: StartupV2ProofHandle | None = None,
        current: SignedSyntheticProviderSnapshot | None = None,
    ) -> ProviderBindingPreDispatchResult:
        assert reason in _ALLOWED_REASONS
        record = proof_handle.record if _is_startup_v2_proof_handle(proof_handle) else None
        binding = proof_handle.binding if _is_startup_v2_proof_handle(proof_handle) else None
        event_hash = record.evidence_sha256 if record is not None and _SHA256.fullmatch(record.evidence_sha256) else None
        snapshot_hash = None
        observed = None
        if current is not None:
            try:
                snapshot_hash = hashlib.sha256(synthetic_snapshot_signature_payload(current)).hexdigest()
                observed = _time_text(current.observed_at_utc)
            except Exception:
                pass
        device_hash = None
        policy_hash = None
        if binding is not None:
            policy_hash = binding.policy_hash if _SHA256.fullmatch(binding.policy_hash) else None
            try:
                device_hash = hashlib.sha256(json.dumps([
                    binding.observation_reference.device_namespace, binding.device_index, binding.gpu_key,
                    binding.observation_reference.gpu_identity_source_sha256, binding.policy_hash,
                ], separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
            except Exception:
                device_hash = None
        return ProviderBindingPreDispatchResult(
            "UNKNOWN", "REVALIDATION_BLOCKED", reason,
            "SYNTHETIC/UNVERIFIED" if current is not None else "UNKNOWN",
            event_hash, snapshot_hash, device_hash, policy_hash,
            observed, None,
        )

    def __repr__(self) -> str:
        return (
            f"ProviderBindingRevalidator(targets={len(self._allowlist.targets)}, "
            f"source_configured={self._source is not None}, max_age={self._maximum_age_seconds:g}s)"
        )
