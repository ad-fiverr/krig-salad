"""Offline tests for generation-scoped, signed V2 startup binding evidence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path
import unittest


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.fl4sh_early_autotune import (  # noqa: E402
    AssociationEvidenceRecord,
    EarlyPolicy,
    ProviderLogObservationReference,
    association_evidence_sha256,
)
from log_alerts.contract import LiveLogQueryPolicy  # noqa: E402
from log_alerts.live_transport import (  # noqa: E402
    LiveSaladReadTransport,
    OfflineSaladExchange,
    SaladTransportResponse,
)
from log_alerts.startup_v2_attestation import (  # noqa: E402
    StartupV2Attestation,
    StartupV2AttestationResolver,
    startup_v2_signature_payload,
)


ORG = "adrianfiverr"
PROJECT = "miners"
GROUP = "fl4shminer-2"
MACHINE = "machine-synthetic"
INSTANCE = "instance-synthetic"
GPU_TIME = datetime(2026, 10, 19, 12, 0, 1, tzinfo=timezone.utc)
PEARL_TIME = GPU_TIME + timedelta(seconds=1)
NOW = PEARL_TIME + timedelta(seconds=2)
POLICY = EarlyPolicy("a" * 64, {"RTX_5080_LAPTOP": 120.0}, margin_ths=0.0)


def _offline_response_evidence():
    policy = LiveLogQueryPolicy(ORG)
    transport = LiveSaladReadTransport.for_offline_test(
        policy=policy,
        exchange=OfflineSaladExchange(
            lambda *_args: SaladTransportResponse(
                200, b'{"items":[],"page_min_time":null,"page_max_time":null}',
            ),
        ),
    )
    request = policy.build_request(
        start_time_utc=GPU_TIME - timedelta(seconds=1),
        end_time_utc=NOW + timedelta(seconds=1),
        query='severity="ERROR"',
    )
    return transport.fetch_query(request).evidence


def _reference(*, event_time=PEARL_TIME, gpu_hash="b" * 64, instance=INSTANCE):
    return ProviderLogObservationReference(
        evidence_sha256="c" * 64,
        event_time_utc=event_time.isoformat().replace("+00:00", "Z"),
        data_classification="SYNTHETIC/UNVERIFIED",
        organization=ORG,
        project=PROJECT,
        container_group=GROUP,
        machine_id=MACHINE,
        instance_id=instance,
        device_namespace="fl4shminer_device",
        device_index=1,
        gpu_key="RTX_5080_LAPTOP",
        gpu_identity_source_sha256=gpu_hash,
    )


def _record(reference, *, valid_from=GPU_TIME, valid_until=NOW + timedelta(minutes=2),
            revalidated=PEARL_TIME, generation="generation-1"):
    record = AssociationEvidenceRecord(
        format_version=1,
        evidence_id="synthetic-evidence-1",
        source="SYNTHETIC_TEST_ONLY",
        status="VERIFIED",
        observation_reference=reference,
        assignment_id="assignment-1",
        assignment_generation=generation,
        valid_from_utc=valid_from,
        valid_until_utc=valid_until,
        revalidated_at_utc=revalidated,
        policy_hash=POLICY.policy_hash,
        verifier_id="offline-test-verifier",
        verifier_version="1",
        evidence_sha256="0" * 64,
    )
    return replace(record, evidence_sha256=association_evidence_sha256(record))


def _signed(reference, response_sha256, *, valid_from=GPU_TIME,
            valid_until=NOW + timedelta(minutes=2), revalidated=PEARL_TIME,
            generation="generation-1", signature_override=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    attestation = StartupV2Attestation(
        schema_version=2,
        authority_id="offline-test-authority",
        key_id="offline-test-key",
        response_sha256=response_sha256,
        record=_record(
            reference, valid_from=valid_from, valid_until=valid_until,
            revalidated=revalidated, generation=generation,
        ),
        signature=b"\0" * 64,
    )
    signature = signature_override or private.sign(startup_v2_signature_payload(attestation))
    attestation = replace(attestation, signature=signature)
    resolver = StartupV2AttestationResolver(
        trusted_authorities={"offline-test-key": ("offline-test-authority", public)},
        attestations=(attestation,),
        offline_test_only=True,
    )
    return resolver, attestation, private


def _resolve(resolver, reference, evidence, *, gpu_time=GPU_TIME, pearl_time=PEARL_TIME, now=NOW):
    return resolver.resolve(
        reference=reference,
        response_evidence=evidence,
        gpu_identity_response_evidence=evidence,
        gpu_identity_data_classification=reference.data_classification,
        policy=POLICY,
        event_time_utc=pearl_time,
        gpu_identity_event_time_utc=gpu_time,
        now_utc=now,
    )


class StartupV2AttestationTests(unittest.TestCase):
    def setUp(self):
        self.response_evidence = _offline_response_evidence()
        self.reference = _reference()
        self.resolver, self.attestation, _private = _signed(
            self.reference, self.response_evidence.response_sha256,
        )

    def test_exact_signed_response_and_generation_yield_one_scoped_context(self):
        result = _resolve(self.resolver, self.reference, self.response_evidence)
        self.assertEqual(result.reason, "ATTESTATION_VERIFIED")
        self.assertIsNotNone(result.context)
        self.assertEqual(len(result.context.bindings), 1)
        binding = result.context.bindings[0]
        self.assertEqual(binding.observation_reference, self.reference)
        self.assertEqual(binding.assignment_generation, "generation-1")
        self.assertEqual(result.context.association_records[0], self.attestation.record)
        self.assertTrue(result.context.allow_synthetic_binding_evidence_for_test)

    def test_missing_attestation_fails_closed_with_fixed_reason(self):
        resolver = StartupV2AttestationResolver(
            trusted_authorities={"offline-test-key": ("offline-test-authority", b"p" * 32)},
            attestations=(), offline_test_only=True,
        )
        result = _resolve(resolver, self.reference, self.response_evidence)
        self.assertIsNone(result.context)
        self.assertEqual(result.reason, "NO_VERIFIED_ATTESTATION")

    def test_response_body_hash_mismatch_fails_closed(self):
        resolver, _attestation, _private = _signed(self.reference, "f" * 64)
        result = _resolve(resolver, self.reference, self.response_evidence)
        self.assertIsNone(result.context)
        self.assertEqual(result.reason, "ATTESTATION_RESPONSE_MISMATCH")

    def test_different_instance_or_generation_time_cannot_reuse_old_binding(self):
        other_instance = _reference(instance="other-instance")
        result = _resolve(self.resolver, other_instance, self.response_evidence)
        self.assertEqual(result.reason, "NO_VERIFIED_ATTESTATION")

        resolver, _, _ = _signed(
            self.reference, self.response_evidence.response_sha256,
            valid_from=GPU_TIME + timedelta(seconds=2),
        )
        result = _resolve(resolver, self.reference, self.response_evidence)
        self.assertIsNone(result.context)
        self.assertEqual(result.reason, "ATTESTATION_GENERATION_MISMATCH")

    def test_stale_revalidation_fails_closed(self):
        old_revalidation = GPU_TIME
        resolver, _, _ = _signed(
            self.reference, self.response_evidence.response_sha256,
            revalidated=old_revalidation,
        )
        result = _resolve(
            resolver, self.reference, self.response_evidence,
            now=old_revalidation + timedelta(seconds=31),
        )
        self.assertEqual(result.reason, "ATTESTATION_STALE")

    def test_tampered_signature_and_provider_response_classification_fail_closed(self):
        bad_signature = bytes([self.attestation.signature[0] ^ 1]) + self.attestation.signature[1:]
        resolver, _, _ = _signed(
            self.reference, self.response_evidence.response_sha256,
            signature_override=bad_signature,
        )
        result = _resolve(resolver, self.reference, self.response_evidence)
        self.assertEqual(result.reason, "ATTESTATION_SIGNATURE_INVALID")

        result = self.resolver.resolve(
            reference=self.reference,
            response_evidence=self.response_evidence,
            gpu_identity_response_evidence=object(),
            gpu_identity_data_classification=self.reference.data_classification,
            policy=POLICY,
            event_time_utc=PEARL_TIME,
            gpu_identity_event_time_utc=GPU_TIME,
            now_utc=NOW,
        )
        self.assertEqual(result.reason, "PROVIDER_RESPONSE_EVIDENCE_INVALID")

    def test_production_mode_cannot_accept_synthetic_transport_evidence(self):
        resolver = StartupV2AttestationResolver(
            trusted_authorities={"offline-test-key": ("offline-test-authority", b"p" * 32)},
            attestations=(self.attestation,),
            offline_test_only=False,
        )
        result = _resolve(resolver, self.reference, self.response_evidence)
        self.assertIsNone(result.context)
        self.assertEqual(result.reason, "PROVIDER_RESPONSE_EVIDENCE_INVALID")

    def test_repr_and_failure_details_do_not_expose_assigned_identity(self):
        output = repr(self.attestation) + repr(self.resolver)
        for sensitive in (MACHINE, INSTANCE, "assignment-1", self.attestation.response_sha256):
            self.assertNotIn(sensitive, output)


if __name__ == "__main__":
    unittest.main()
