"""Signed, event-scoped V2 binding evidence for the read-only startup path.

No trust authority or attestation source is configured by the watcher CLI.
Without an explicitly constructed resolver, startup decisions stay UNKNOWN.
Synthetic attestations are accepted only by a resolver explicitly marked for
offline tests and only alongside response evidence from the offline transport.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from types import MappingProxyType
from typing import Any

from collector.fl4sh_early_autotune import (
    AssociationEvidenceRecord,
    BindingAttestation,
    EarlyEvaluationContext,
    EarlyPolicy,
    ProviderBinding,
    ProviderLogObservationReference,
    association_evidence_sha256,
)


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_RESOLUTION_CODES = frozenset({
    "ATTESTATION_AMBIGUOUS",
    "ATTESTATION_AUTHORITY_UNTRUSTED",
    "ATTESTATION_GENERATION_MISMATCH",
    "ATTESTATION_INPUT_INCOMPLETE",
    "ATTESTATION_IDENTITY_MISMATCH",
    "ATTESTATION_POLICY_MISMATCH",
    "ATTESTATION_RECORD_INVALID",
    "ATTESTATION_RESPONSE_MISMATCH",
    "ATTESTATION_REFERENCE_MISMATCH",
    "ATTESTATION_SCHEMA_INVALID",
    "ATTESTATION_SIGNATURE_INVALID",
    "ATTESTATION_SOURCE_INVALID",
    "ATTESTATION_STALE",
    "ATTESTATION_TIME_INVALID",
    "NO_VERIFIED_ATTESTATION",
    "PROVIDER_RESPONSE_EVIDENCE_INVALID",
})


@dataclass(frozen=True, slots=True)
class StartupV2Attestation:
    """V2 signature over one association record and its exact response body."""

    schema_version: int
    authority_id: str
    key_id: str
    response_sha256: str
    record: AssociationEvidenceRecord
    signature: bytes

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 2:
            raise ValueError("INVALID_STARTUP_V2_SCHEMA")
        if not _safe_id(self.authority_id) or not _safe_id(self.key_id):
            raise ValueError("INVALID_STARTUP_V2_AUTHORITY")
        if not _SHA256.fullmatch(self.response_sha256 if isinstance(self.response_sha256, str) else ""):
            raise ValueError("INVALID_STARTUP_V2_RESPONSE_HASH")
        if type(self.record) is not AssociationEvidenceRecord:
            raise ValueError("INVALID_STARTUP_V2_RECORD")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("INVALID_STARTUP_V2_SIGNATURE")

    def __repr__(self) -> str:
        return "StartupV2Attestation(schema_version=2, claims=[REDACTED], signature=[REDACTED])"


@dataclass(frozen=True, slots=True)
class StartupV2Resolution:
    context: EarlyEvaluationContext | None
    reason: str

    def __post_init__(self) -> None:
        if self.reason not in _RESOLUTION_CODES and self.reason != "ATTESTATION_VERIFIED":
            raise ValueError("INVALID_STARTUP_V2_RESULT")
        if self.context is not None and type(self.context) is not EarlyEvaluationContext:
            raise ValueError("INVALID_STARTUP_V2_CONTEXT")


def _safe_id(value: object) -> bool:
    return isinstance(value, str) and _SAFE_ID.fullmatch(value) is not None


def _aware_utc(value: object) -> datetime | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    return value.astimezone(timezone.utc)


def startup_v2_signature_payload(attestation: StartupV2Attestation) -> bytes:
    """Canonical signed bytes; hashes bind every field in the association record."""
    if type(attestation) is not StartupV2Attestation:
        raise TypeError("exact V2 attestation required")
    record_hash = association_evidence_sha256(attestation.record)
    if record_hash is None:
        raise ValueError("INVALID_STARTUP_V2_RECORD")
    payload = {
        "schema_version": attestation.schema_version,
        "authority_id": attestation.authority_id,
        "key_id": attestation.key_id,
        "response_sha256": attestation.response_sha256,
        "association_evidence_sha256": record_hash,
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


class StartupV2AttestationResolver:
    """Resolve exactly one signed V2 record for an exact normalized event.

    ``trusted_authorities`` maps a key ID to ``(authority_id, Ed25519 public
    key bytes)``. The current runtime supplies no resolver or authority by
    default. ``offline_test_only`` cannot be used for provider-observed data.
    """

    __slots__ = ("_trusted_authorities", "_attestations", "_offline_test_only")

    def __init__(
        self,
        *,
        trusted_authorities: Mapping[str, tuple[str, bytes]],
        attestations: Sequence[StartupV2Attestation],
        offline_test_only: bool = False,
    ) -> None:
        if not isinstance(trusted_authorities, Mapping) or not trusted_authorities:
            raise ValueError("STARTUP_V2_TRUST_STORE_REQUIRED")
        if type(offline_test_only) is not bool:
            raise ValueError("INVALID_STARTUP_V2_MODE")
        if not isinstance(attestations, Sequence) or len(attestations) > 4096:
            raise ValueError("STARTUP_V2_ATTESTATION_LIMIT")
        clean_authorities: dict[str, tuple[str, bytes]] = {}
        for key_id, value in trusted_authorities.items():
            if (
                not _safe_id(key_id)
                or type(value) is not tuple or len(value) != 2
                or not _safe_id(value[0])
                or not isinstance(value[1], bytes) or len(value[1]) != 32
            ):
                raise ValueError("INVALID_STARTUP_V2_TRUST_STORE")
            clean_authorities[key_id] = (value[0], bytes(value[1]))
        if any(type(item) is not StartupV2Attestation for item in attestations):
            raise ValueError("INVALID_STARTUP_V2_ATTESTATION_SET")
        self._trusted_authorities = MappingProxyType(clean_authorities)
        self._attestations = tuple(attestations)
        self._offline_test_only = offline_test_only

    @property
    def offline_test_only(self) -> bool:
        return self._offline_test_only

    def __repr__(self) -> str:
        return (
            "StartupV2AttestationResolver(attestations=[REDACTED], "
            f"trusted_authorities={len(self._trusted_authorities)}, "
            f"offline_test_only={self._offline_test_only})"
        )

    def resolve(
        self,
        *,
        reference: ProviderLogObservationReference,
        response_evidence: Any,
        gpu_identity_response_evidence: Any,
        gpu_identity_data_classification: str,
        policy: EarlyPolicy,
        event_time_utc: datetime,
        gpu_identity_event_time_utc: datetime,
        now_utc: datetime,
    ) -> StartupV2Resolution:
        if type(reference) is not ProviderLogObservationReference or type(policy) is not EarlyPolicy:
            return StartupV2Resolution(None, "ATTESTATION_INPUT_INCOMPLETE")
        if not all(_aware_utc(value) is not None for value in (
            event_time_utc, gpu_identity_event_time_utc, now_utc,
        )):
            return StartupV2Resolution(None, "ATTESTATION_TIME_INVALID")
        response_status = self._response_status(response_evidence, reference.data_classification)
        if response_status is not None:
            return StartupV2Resolution(None, response_status)
        if gpu_identity_data_classification != reference.data_classification:
            return StartupV2Resolution(None, "PROVIDER_RESPONSE_EVIDENCE_INVALID")
        gpu_response_status = self._response_status(
            gpu_identity_response_evidence, gpu_identity_data_classification,
        )
        if gpu_response_status is not None:
            return StartupV2Resolution(None, gpu_response_status)
        matching = tuple(
            item for item in self._attestations
            if item.record.observation_reference == reference
        )
        if not matching:
            return StartupV2Resolution(None, "NO_VERIFIED_ATTESTATION")
        if len(matching) != 1:
            return StartupV2Resolution(None, "ATTESTATION_AMBIGUOUS")
        attestation = matching[0]
        record = attestation.record
        if attestation.response_sha256 != response_evidence.response_sha256:
            return StartupV2Resolution(None, "ATTESTATION_RESPONSE_MISMATCH")
        if attestation.schema_version != 2 or record.format_version != 1:
            return StartupV2Resolution(None, "ATTESTATION_SCHEMA_INVALID")
        if (
            record.status != "VERIFIED"
            or not _safe_id(record.evidence_id)
            or not _safe_id(record.verifier_id)
            or not _safe_id(record.verifier_version)
            or association_evidence_sha256(record) != record.evidence_sha256
        ):
            return StartupV2Resolution(None, "ATTESTATION_RECORD_INVALID")
        if record.observation_reference != reference:
            return StartupV2Resolution(None, "ATTESTATION_REFERENCE_MISMATCH")
        if record.policy_hash != policy.policy_hash:
            return StartupV2Resolution(None, "ATTESTATION_POLICY_MISMATCH")
        expected_source = (
            "SYNTHETIC_TEST_ONLY"
            if reference.data_classification == "SYNTHETIC/UNVERIFIED"
            else "INDEPENDENT_PROVIDER_AND_WORKLOAD_EVIDENCE"
        )
        if record.source != expected_source:
            return StartupV2Resolution(None, "ATTESTATION_SOURCE_INVALID")
        if self._offline_test_only != (expected_source == "SYNTHETIC_TEST_ONLY"):
            return StartupV2Resolution(None, "ATTESTATION_SOURCE_INVALID")
        identity = reference
        if not all(_safe_id(item) for item in (
            identity.organization, identity.project, identity.container_group,
            identity.machine_id, identity.instance_id, record.assignment_id,
            record.assignment_generation,
        )):
            return StartupV2Resolution(None, "ATTESTATION_IDENTITY_MISMATCH")
        event_time = _aware_utc(event_time_utc)
        gpu_time = _aware_utc(gpu_identity_event_time_utc)
        now = _aware_utc(now_utc)
        valid_from = _aware_utc(record.valid_from_utc)
        valid_until = _aware_utc(record.valid_until_utc)
        revalidated = _aware_utc(record.revalidated_at_utc)
        if None in (event_time, gpu_time, now, valid_from, valid_until, revalidated):
            return StartupV2Resolution(None, "ATTESTATION_TIME_INVALID")
        assert event_time is not None and gpu_time is not None and now is not None
        assert valid_from is not None and valid_until is not None and revalidated is not None
        if not (
            valid_from <= gpu_time <= event_time <= valid_until
            and valid_from <= revalidated <= valid_until
            and revalidated <= now <= valid_until
        ):
            return StartupV2Resolution(None, "ATTESTATION_GENERATION_MISMATCH")
        if (now - revalidated).total_seconds() > policy.max_binding_age_seconds:
            return StartupV2Resolution(None, "ATTESTATION_STALE")
        trusted = self._trusted_authorities.get(attestation.key_id)
        if trusted is None or trusted[0] != attestation.authority_id:
            return StartupV2Resolution(None, "ATTESTATION_AUTHORITY_UNTRUSTED")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(trusted[1]).verify(
                attestation.signature, startup_v2_signature_payload(attestation),
            )
        except Exception:
            return StartupV2Resolution(None, "ATTESTATION_SIGNATURE_INVALID")

        binding = ProviderBinding(
            device_index=reference.device_index,
            gpu_key=reference.gpu_key,
            organization=reference.organization,
            project=reference.project,
            container_group=reference.container_group,
            machine_id=reference.machine_id,
            instance_id=reference.instance_id,
            assignment_id=record.assignment_id,
            assignment_generation=record.assignment_generation,
            valid_from_utc=record.valid_from_utc,
            revalidated_at_utc=record.revalidated_at_utc,
            policy_hash=record.policy_hash,
            source=record.source,
            status="VERIFIED",
            observation_reference=reference,
            attestation=BindingAttestation(1, record.evidence_id, record.evidence_sha256),
            valid_until_utc=record.valid_until_utc,
        )
        synthetic = expected_source == "SYNTHETIC_TEST_ONLY"
        context = EarlyEvaluationContext(
            policy=policy,
            bindings=(binding,),
            association_records=(record,),
            now_utc=now,
            allow_synthetic_provider_log_evidence_for_test=synthetic,
            allow_synthetic_binding_evidence_for_test=synthetic,
        )
        return StartupV2Resolution(context, "ATTESTATION_VERIFIED")

    def _response_status(self, evidence: Any, classification: str) -> str | None:
        from .live_transport import ProviderResponseEvidence

        if type(evidence) is not ProviderResponseEvidence or evidence.status_code != 200:
            return "PROVIDER_RESPONSE_EVIDENCE_INVALID"
        if classification == "SYNTHETIC/UNVERIFIED":
            valid = (
                self._offline_test_only
                and evidence.source == "offline_test_transport"
                and evidence.classification == "SYNTHETIC/UNVERIFIED"
            )
        else:
            valid = (
                not self._offline_test_only
                and evidence.source == "salad_https_fixed_route"
                and evidence.classification == "PROVIDER_OBSERVED"
            )
        return None if valid and _SHA256.fullmatch(evidence.response_sha256) else "PROVIDER_RESPONSE_EVIDENCE_INVALID"
