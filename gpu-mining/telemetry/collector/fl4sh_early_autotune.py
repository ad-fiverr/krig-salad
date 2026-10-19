"""Pure, fail-closed Pearl startup floor classifier; it never performs an action.

PEARL_AUTOTUNE is compared directly with the exact configured GPU floor after
the caller supplies independently verified provider binding. CUDA pool-equivalent
autotune remains diagnostic only, and neither estimate is Device hashRate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
import math
import re
from types import MappingProxyType
from typing import Mapping, Sequence


SIGNAL_TYPES = frozenset({"CUDA_POOL_EQUIVALENT", "PEARL_AUTOTUNE"})
STARTUP_FAILURES = frozenset({"CUDA_DRIVER_VERSION_INSUFFICIENT"})
GPU_KEY_RE = re.compile(r"[A-Z0-9]+(?:_[A-Z0-9]+)*\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def _utc(value: datetime) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


def _number(value: object, *, allow_zero: bool = False) -> bool:
    return type(value) in {float, int} and math.isfinite(value) and (value >= 0 if allow_zero else value > 0)


def _hash(value: object) -> bool:
    return isinstance(value, str) and HASH_RE.fullmatch(value) is not None


def _gpu_key(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 128 and GPU_KEY_RE.fullmatch(value) is not None


@dataclass(frozen=True)
class EarlyPolicy:
    policy_hash: str
    floors_ths: Mapping[str, float]
    margin_ths: float
    max_signal_age_seconds: int = 60
    max_binding_age_seconds: int = 30
    minimum_calibration_pairs: int = 30

    def __post_init__(self) -> None:
        if not _hash(self.policy_hash):
            raise ValueError("INVALID_POLICY_HASH")
        if not isinstance(self.floors_ths, Mapping) or not self.floors_ths:
            raise ValueError("INVALID_FLOORS")
        for key, floor in self.floors_ths.items():
            if not _gpu_key(key) or not _number(floor) or floor > 10000:
                raise ValueError("INVALID_FLOORS")
        object.__setattr__(self, "floors_ths", MappingProxyType(dict(self.floors_ths)))
        if not _number(self.margin_ths, allow_zero=True) or self.margin_ths > 10000:
            raise ValueError("INVALID_MARGIN")
        if any(type(value) is not int or value < 1 or value > 86400 for value in (
            self.max_signal_age_seconds, self.max_binding_age_seconds, self.minimum_calibration_pairs
        )):
            raise ValueError("INVALID_POLICY_LIMIT")


@dataclass(frozen=True)
class EarlyObservation:
    signal_type: str | None
    device_index: int | None
    gpu_key: str | None
    estimate_ths: float | None
    event_time_utc: datetime | None
    policy_hash: str | None
    source: str = "FL4SHMINER_AUTOTUNE_LOG"
    startup_failure_reason: str | None = None
    source_reference: "ObservationReference | None" = None
    policy_evidence: "MonitorPolicyEvidence | None" = None
    policy_evidence_status: str = "MISSING"


@dataclass(frozen=True)
class MonitorPolicyEvidence:
    """Bounded CONFIG-line declaration from the same imported startup episode."""

    source_event_id: str
    source_file_sha256: str
    source_row: int
    organization: str
    project: str
    container_group: str
    container_group_version: str
    machine_id: str
    instance_id: str
    startup_anchor_source_event_id: str
    startup_anchor_time_utc: str
    occurred_at_utc: str
    policy_hash: str | None
    status: str = "PARSED"
    source: str = "FL4SH_MONITOR_CONFIG_LOG_DECLARATION"


@dataclass(frozen=True)
class ObservationReference:
    """Stable, event-scoped reference to provider and workload evidence."""

    source_event_id: str
    source_file_sha256: str
    source_row: int
    organization: str
    project: str
    container_group: str
    container_group_version: str
    machine_id: str
    instance_id: str
    device_namespace: str
    device_index: int
    gpu_key: str
    gpu_identity_source_event_id: str
    startup_anchor_source_event_id: str | None = None
    startup_anchor_time_utc: str | None = None
    policy_evidence_sha256: str | None = None


@dataclass(frozen=True)
class BindingAttestation:
    """Pointer to an independently supplied, canonical association record."""

    format_version: int
    evidence_id: str
    evidence_sha256: str


@dataclass(frozen=True)
class AssociationEvidenceRecord:
    """Generation-scoped association record supplied by a separate trust boundary.

    A content digest detects mismatched or stale records; it is not a signature.
    Synthetic records are accepted only through an explicit test-only flag.
    """

    format_version: int
    evidence_id: str
    source: str
    status: str
    observation_reference: ObservationReference
    assignment_id: str
    assignment_generation: str
    valid_from_utc: datetime
    valid_until_utc: datetime
    revalidated_at_utc: datetime
    policy_hash: str
    verifier_id: str
    verifier_version: str
    evidence_sha256: str


@dataclass(frozen=True)
class ProviderBinding:
    device_index: int
    gpu_key: str
    organization: str
    project: str
    container_group: str
    machine_id: str
    instance_id: str
    assignment_id: str
    assignment_generation: str
    valid_from_utc: datetime
    revalidated_at_utc: datetime
    policy_hash: str
    source: str = "INDEPENDENT_PROVIDER_AND_WORKLOAD_EVIDENCE"
    status: str = "VERIFIED"
    observation_reference: ObservationReference | None = None
    attestation: BindingAttestation | None = None
    valid_until_utc: datetime | None = None


@dataclass(frozen=True)
class EarlyCalibration:
    signal_type: str
    gpu_key: str
    lower_multiplier: float
    upper_multiplier: float
    pair_count: int
    approved_at_utc: datetime
    expires_at_utc: datetime
    policy_hash: str
    evidence_sha256: str
    status: str = "APPROVED_MEASURED_PAIRS"


@dataclass(frozen=True)
class EarlyDecision:
    state: str
    reason: str
    signal_type: str | None
    device_index: int | None
    gpu_key: str | None
    estimate_ths: float | None
    predicted_lower_ths: float | None
    predicted_upper_ths: float | None
    floor_ths: float | None
    policy_hash: str | None
    assignment_id: str | None = None
    assignment_generation: str | None = None
    machine_id: str | None = None
    instance_id: str | None = None
    actions_performed: bool = False
    action_eligible: bool = False
    decision_version: int = 1
    evaluated_at_utc: str | None = None
    source_reference_sha256: str | None = None
    calibration_status: str = "NOT_APPLICABLE"
    calibration_evidence_sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe decision with only a one-way source reference."""
        return {
            "decision_version": self.decision_version,
            "state": self.state,
            "reason": self.reason,
            "signal_type": self.signal_type,
            "device_index": self.device_index,
            "gpu_key": self.gpu_key,
            "estimate_ths": self.estimate_ths,
            "predicted_lower_ths": self.predicted_lower_ths,
            "predicted_upper_ths": self.predicted_upper_ths,
            "floor_ths": self.floor_ths,
            "policy_hash": self.policy_hash,
            "assignment_id": self.assignment_id,
            "assignment_generation": self.assignment_generation,
            "actions_performed": False,
            "action_eligible": False,
            "evaluated_at_utc": self.evaluated_at_utc,
            "source_reference_sha256": self.source_reference_sha256,
            "calibration_status": self.calibration_status,
            "calibration_evidence_sha256": self.calibration_evidence_sha256,
        }


@dataclass(frozen=True)
class EarlyEvaluationContext:
    """Explicit offline inputs; no provider or calibration lookup is performed."""

    policy: EarlyPolicy | None = None
    bindings: Sequence[ProviderBinding] = ()
    association_records: Sequence[AssociationEvidenceRecord] = ()
    calibrations: Sequence[EarlyCalibration] = ()
    now_utc: datetime | None = None
    allow_synthetic_calibration_for_test: bool = False
    allow_synthetic_binding_evidence_for_test: bool = False

    def __post_init__(self) -> None:
        if type(self.allow_synthetic_calibration_for_test) is not bool:
            raise ValueError("INVALID_SYNTHETIC_CALIBRATION_TEST_FLAG")
        if type(self.allow_synthetic_binding_evidence_for_test) is not bool:
            raise ValueError("INVALID_SYNTHETIC_BINDING_TEST_FLAG")
        object.__setattr__(self, "bindings", tuple(self.bindings))
        object.__setattr__(self, "association_records", tuple(self.association_records))
        object.__setattr__(self, "calibrations", tuple(self.calibrations))


def evaluate_early_autotune(
    observation: EarlyObservation,
    binding: ProviderBinding | None,
    calibration: EarlyCalibration | None,
    policy: EarlyPolicy | None,
    *,
    now_utc: datetime,
    contradictory_evidence: bool = False,
    allow_synthetic_calibration_for_test: bool = False,
    association_records: Sequence[AssociationEvidenceRecord] = (),
    allow_synthetic_binding_evidence_for_test: bool = False,
) -> EarlyDecision:
    """Compare Pearl autotune directly to its exact GPU floor; never authorize action.

    ``calibration`` and its test flag remain in the signature for caller
    compatibility, but are intentionally irrelevant to the direct Pearl rule.
    """
    provenance_hash = _source_reference_hash(observation.source_reference)
    base = dict(
        signal_type=observation.signal_type if observation.signal_type in SIGNAL_TYPES else None,
        device_index=observation.device_index,
        gpu_key=observation.gpu_key if _gpu_key(observation.gpu_key) else None,
        estimate_ths=observation.estimate_ths if _number(observation.estimate_ths) else None,
        predicted_lower_ths=None,
        predicted_upper_ths=None,
        floor_ths=None,
        policy_hash=policy.policy_hash if policy is not None else None,
        evaluated_at_utc=now_utc.isoformat().replace("+00:00", "Z") if _utc(now_utc) else None,
        source_reference_sha256=provenance_hash,
        calibration_status="NOT_APPLICABLE",
        calibration_evidence_sha256=None,
    )

    def unknown(reason: str) -> EarlyDecision:
        return EarlyDecision("EARLY_UNKNOWN", reason, **base)

    if not _utc(now_utc) or not _utc(observation.event_time_utc):
        return unknown("TIME_UNVERIFIED")
    age = (now_utc - observation.event_time_utc).total_seconds()
    maximum_signal_age = policy.max_signal_age_seconds if policy is not None else 60
    if age < 0 or age > maximum_signal_age:
        return unknown("SIGNAL_STALE_OR_FUTURE")
    if observation.startup_failure_reason in STARTUP_FAILURES and observation.source == "FL4SHMINER_STARTUP_LOG":
        return EarlyDecision("STARTUP_UNQUALIFIED", observation.startup_failure_reason, **base)
    if observation.startup_failure_reason is not None:
        return unknown("STARTUP_FAILURE_UNRECOGNIZED")
    if policy is None:
        return unknown("POLICY_UNAVAILABLE")
    if not policy.floors_ths:
        return unknown("POLICY_UNAVAILABLE")
    if observation.policy_evidence_status == "AMBIGUOUS":
        return unknown("POLICY_EVIDENCE_AMBIGUOUS")
    if observation.policy_evidence_status != "PARSED" or not _valid_policy_evidence(
        observation.policy_evidence,
        observation.source_reference,
        observation.event_time_utc,
    ):
        return unknown("POLICY_EVIDENCE_UNVERIFIED")
    if observation.policy_hash != observation.policy_evidence.policy_hash:
        return unknown("POLICY_EVIDENCE_CONFLICT")
    if observation.policy_hash != policy.policy_hash:
        return unknown("POLICY_MISMATCH")
    if observation.source != "FL4SHMINER_AUTOTUNE_LOG" or observation.signal_type not in SIGNAL_TYPES:
        return unknown("SIGNAL_UNVERIFIED")
    if observation.device_index is None or type(observation.device_index) is not int or not 0 <= observation.device_index <= 999:
        return unknown("DEVICE_UNVERIFIED")
    if not _gpu_key(observation.gpu_key):
        return unknown("GPU_UNVERIFIED")
    if not _number(observation.estimate_ths) or observation.estimate_ths > 10000:
        return unknown("ESTIMATE_INVALID")
    if contradictory_evidence:
        return unknown("CONTRADICTORY_EVIDENCE")
    if binding is None or type(binding) is not ProviderBinding or binding.status != "VERIFIED":
        return unknown("BINDING_UNVERIFIED")
    if binding.source == "SYNTHETIC_TEST_ONLY" and not allow_synthetic_binding_evidence_for_test:
        return unknown("BINDING_NOT_AUTHORIZED_FOR_PRODUCTION")
    if binding.source not in {"INDEPENDENT_PROVIDER_AND_WORKLOAD_EVIDENCE", "SYNTHETIC_TEST_ONLY"}:
        return unknown("BINDING_UNVERIFIED")
    if (
        not _valid_observation_reference(observation.source_reference)
        or not _valid_observation_reference(binding.observation_reference)
    ):
        return unknown("PROVENANCE_UNVERIFIED")
    if binding.observation_reference != observation.source_reference:
        return unknown("BINDING_SOURCE_CONFLICT")
    source_reference = observation.source_reference
    if (
        binding.organization != source_reference.organization
        or binding.project != source_reference.project
        or binding.container_group != source_reference.container_group
        or binding.machine_id != source_reference.machine_id
        or binding.instance_id != source_reference.instance_id
    ):
        return unknown("BINDING_SOURCE_CONFLICT")
    if binding.device_index != observation.device_index or binding.gpu_key != observation.gpu_key:
        return unknown("BINDING_CONFLICT")
    if binding.policy_hash != policy.policy_hash or not all(
        isinstance(value, str) and ID_RE.fullmatch(value) for value in (
            binding.organization, binding.project, binding.container_group,
            binding.machine_id, binding.instance_id, binding.assignment_id,
            binding.assignment_generation,
        )
    ):
        return unknown("BINDING_UNVERIFIED")
    if not _utc(binding.valid_from_utc) or not _utc(binding.valid_until_utc) or not _utc(binding.revalidated_at_utc):
        return unknown("BINDING_TIME_UNVERIFIED")
    binding_age = (now_utc - binding.revalidated_at_utc).total_seconds()
    if not (
        binding.valid_from_utc <= observation.event_time_utc <= binding.valid_until_utc
        and binding.valid_from_utc <= binding.revalidated_at_utc <= binding.valid_until_utc
        and binding.revalidated_at_utc <= now_utc <= binding.valid_until_utc
    ):
        return unknown("BINDING_TIME_CONFLICT")
    if binding_age > policy.max_binding_age_seconds:
        return unknown("BINDING_STALE")
    attestation_result = _validate_binding_attestation(
        binding,
        observation.source_reference,
        association_records,
        allow_synthetic=allow_synthetic_binding_evidence_for_test,
    )
    if attestation_result != "VALID":
        return unknown(attestation_result)
    floor = policy.floors_ths.get(observation.gpu_key)
    if not _number(floor):
        return unknown("FLOOR_UNCONFIGURED")
    if observation.signal_type == "CUDA_POOL_EQUIVALENT":
        return unknown("CUDA_POOL_EQUIVALENT_DIAGNOSTIC_ONLY")
    if observation.signal_type != "PEARL_AUTOTUNE":
        return unknown("SIGNAL_UNVERIFIED")
    if observation.estimate_ths >= floor:
        state, reason = "EARLY_PASS", "PEARL_AT_OR_ABOVE_FLOOR"
    else:
        state, reason = "EARLY_UNDER_FLOOR", "PEARL_BELOW_FLOOR"
    return EarlyDecision(
        state, reason, observation.signal_type, observation.device_index,
        observation.gpu_key, observation.estimate_ths, None, None, floor,
        policy.policy_hash, binding.assignment_id, binding.assignment_generation,
        binding.machine_id, binding.instance_id,
        source_reference_sha256=provenance_hash,
        evaluated_at_utc=now_utc.isoformat().replace("+00:00", "Z"),
        calibration_status="NOT_APPLICABLE",
        calibration_evidence_sha256=None,
    )


def _valid_observation_reference(value: object) -> bool:
    if type(value) is not ObservationReference:
        return False
    if not _hash(value.source_file_sha256) or not _valid_id(value.source_event_id):
        return False
    if type(value.source_row) is not int or value.source_row < 2:
        return False
    if any(not _valid_id(item) for item in (
        value.organization, value.project, value.container_group,
        value.container_group_version, value.machine_id, value.instance_id,
    )):
        return False
    if value.device_namespace != "fl4shminer_device":
        return False
    if type(value.device_index) is not int or not 0 <= value.device_index <= 999:
        return False
    if not _gpu_key(value.gpu_key) or not _valid_id(value.gpu_identity_source_event_id):
        return False
    if value.startup_anchor_source_event_id is not None or value.startup_anchor_time_utc is not None:
        if not _valid_id(value.startup_anchor_source_event_id) or _aware_utc_text(value.startup_anchor_time_utc) is None:
            return False
    if value.policy_evidence_sha256 is not None and not _hash(value.policy_evidence_sha256):
        return False
    return True


def _aware_utc_text(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _canonical_hash(value: object) -> str | None:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _policy_evidence_payload(value: MonitorPolicyEvidence) -> dict[str, object]:
    return {
        "source_event_id": value.source_event_id,
        "source_file_sha256": value.source_file_sha256,
        "source_row": value.source_row,
        "organization": value.organization,
        "project": value.project,
        "container_group": value.container_group,
        "container_group_version": value.container_group_version,
        "machine_id": value.machine_id,
        "instance_id": value.instance_id,
        "startup_anchor_source_event_id": value.startup_anchor_source_event_id,
        "startup_anchor_time_utc": value.startup_anchor_time_utc,
        "occurred_at_utc": value.occurred_at_utc,
        "policy_hash": value.policy_hash,
        "status": value.status,
        "source": value.source,
    }


def _policy_evidence_sha256(value: MonitorPolicyEvidence | None) -> str | None:
    if type(value) is not MonitorPolicyEvidence:
        return None
    return _canonical_hash(_policy_evidence_payload(value))


def monitor_policy_evidence_sha256(value: MonitorPolicyEvidence | None) -> str | None:
    """Return a stable digest for the bounded CONFIG witness."""
    return _policy_evidence_sha256(value)


def _valid_policy_evidence(
    evidence: object,
    reference: ObservationReference | None,
    event_time_utc: datetime | None,
) -> bool:
    if type(evidence) is not MonitorPolicyEvidence or not _valid_observation_reference(reference):
        return False
    assert isinstance(reference, ObservationReference)
    if (
        evidence.status != "PARSED"
        or evidence.source != "FL4SH_MONITOR_CONFIG_LOG_DECLARATION"
        or not _hash(evidence.source_file_sha256)
        or not _hash(evidence.policy_hash)
        or not _valid_id(evidence.source_event_id)
        or type(evidence.source_row) is not int or evidence.source_row < 2
        or not all(_valid_id(item) for item in (
            evidence.organization, evidence.project, evidence.container_group,
            evidence.container_group_version, evidence.machine_id, evidence.instance_id,
            evidence.startup_anchor_source_event_id,
        ))
    ):
        return False
    anchor = _aware_utc_text(evidence.startup_anchor_time_utc)
    config_time = _aware_utc_text(evidence.occurred_at_utc)
    if anchor is None or config_time is None or not _utc(event_time_utc):
        return False
    if not (anchor <= config_time <= event_time_utc):
        return False
    return (
        evidence.source_file_sha256 == reference.source_file_sha256
        and evidence.organization == reference.organization
        and evidence.project == reference.project
        and evidence.container_group == reference.container_group
        and evidence.container_group_version == reference.container_group_version
        and evidence.machine_id == reference.machine_id
        and evidence.instance_id == reference.instance_id
        and evidence.startup_anchor_source_event_id == reference.startup_anchor_source_event_id
        and evidence.startup_anchor_time_utc == reference.startup_anchor_time_utc
        and _policy_evidence_sha256(evidence) == reference.policy_evidence_sha256
    )


def _association_evidence_payload(value: AssociationEvidenceRecord) -> dict[str, object] | None:
    if type(value) is not AssociationEvidenceRecord:
        return None
    reference_hash = _source_reference_hash(value.observation_reference)
    if reference_hash is None:
        return None
    return {
        "format_version": value.format_version,
        "evidence_id": value.evidence_id,
        "source": value.source,
        "status": value.status,
        "observation_reference_sha256": reference_hash,
        "assignment_id": value.assignment_id,
        "assignment_generation": value.assignment_generation,
        "valid_from_utc": value.valid_from_utc.astimezone(timezone.utc).isoformat() if _utc(value.valid_from_utc) else None,
        "valid_until_utc": value.valid_until_utc.astimezone(timezone.utc).isoformat() if _utc(value.valid_until_utc) else None,
        "revalidated_at_utc": value.revalidated_at_utc.astimezone(timezone.utc).isoformat() if _utc(value.revalidated_at_utc) else None,
        "policy_hash": value.policy_hash,
        "verifier_id": value.verifier_id,
        "verifier_version": value.verifier_version,
    }


def association_evidence_sha256(value: AssociationEvidenceRecord) -> str | None:
    """Return a canonical content digest for an independent evidence record.

    This digest detects accidental/stale mismatches. It does not establish
    authenticity; production records must come from the separately trusted
    association verifier. Synthetic records require an explicit test flag.
    """
    payload = _association_evidence_payload(value)
    return _canonical_hash(payload) if payload is not None else None


def _validate_binding_attestation(
    binding: ProviderBinding,
    observation_reference: ObservationReference,
    association_records: Sequence[AssociationEvidenceRecord],
    *,
    allow_synthetic: bool,
) -> str:
    attestation = binding.attestation
    if (
        type(attestation) is not BindingAttestation
        or type(attestation.format_version) is not int
        or attestation.format_version != 1
        or not _valid_id(attestation.evidence_id)
        or not _hash(attestation.evidence_sha256)
    ):
        return "PROVENANCE_UNVERIFIED"
    matches = [
        record for record in association_records
        if type(record) is AssociationEvidenceRecord
        and record.evidence_id == attestation.evidence_id
        and record.evidence_sha256 == attestation.evidence_sha256
    ]
    if len(matches) != 1:
        return "PROVENANCE_UNVERIFIED"
    record = matches[0]
    if (
        record.format_version != 1
        or record.status != "VERIFIED"
        or record.source not in {
            "INDEPENDENT_PROVIDER_AND_WORKLOAD_EVIDENCE",
            "SYNTHETIC_TEST_ONLY",
        }
        or not _valid_id(record.evidence_id)
        or not all(_valid_id(item) for item in (record.verifier_id, record.verifier_version))
        or not _hash(record.policy_hash)
        or not _hash(record.evidence_sha256)
        or not _utc(record.valid_from_utc)
        or not _utc(record.valid_until_utc)
        or not _utc(record.revalidated_at_utc)
        or not (record.valid_from_utc <= record.revalidated_at_utc <= record.valid_until_utc)
        or association_evidence_sha256(record) != record.evidence_sha256
    ):
        return "PROVENANCE_UNVERIFIED"
    if record.source == "SYNTHETIC_TEST_ONLY" and not allow_synthetic:
        return "BINDING_NOT_AUTHORIZED_FOR_PRODUCTION"
    if (
        record.observation_reference != observation_reference
        or record.observation_reference != binding.observation_reference
        or record.assignment_id != binding.assignment_id
        or record.assignment_generation != binding.assignment_generation
        or record.valid_from_utc != binding.valid_from_utc
        or record.valid_until_utc != binding.valid_until_utc
        or record.revalidated_at_utc != binding.revalidated_at_utc
        or record.policy_hash != binding.policy_hash
        or record.source != binding.source
    ):
        return "BINDING_ATTESTATION_CONFLICT"
    return "VALID"


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and ID_RE.fullmatch(value) is not None


def _source_reference_hash(value: ObservationReference | None) -> str | None:
    if not _valid_observation_reference(value):
        return None
    encoded = json.dumps(value.__dict__, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()
