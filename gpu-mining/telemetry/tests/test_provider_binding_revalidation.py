"""Offline-only tests for signed, fresh, exact startup binding revalidation."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.fl4sh_early_autotune import (  # noqa: E402
    AssociationEvidenceRecord,
    EarlyPolicy,
    ProviderLogObservationReference,
    _gpu_key,
    association_evidence_sha256,
)
from log_alerts.contract import LiveLogQueryPolicy  # noqa: E402
from log_alerts.live_transport import (  # noqa: E402
    LiveSaladReadTransport,
    OfflineSaladExchange,
    SaladTransportResponse,
)
from log_alerts.provider_binding_revalidation import (  # noqa: E402
    ExactSaladAssignmentTarget,
    ExplicitBindingAllowlist,
    ProviderBindingRevalidator,
    SignedSyntheticProviderSnapshot,
    SyntheticFreshProviderSource,
    synthetic_snapshot_signature_payload,
)
from log_alerts.startup_v2_attestation import (  # noqa: E402
    StartupV2Attestation,
    StartupV2AttestationResolver,
    _startup_v2_proof_handle,
    startup_v2_signature_payload,
)


ORG = "adrianfiverr"
PROJECT = "miners"
GROUP = "fl4shminer-2"
TARGET = ExactSaladAssignmentTarget(
    ORG, PROJECT, GROUP, "org-id-synthetic", "project-id-synthetic", "group-id-synthetic",
    tenant_id="tenant-synthetic", account_id="account-synthetic",
)
MACHINE = "machine-synthetic"
INSTANCE = "instance-synthetic"
ASSIGNMENT = "assignment-synthetic"
GENERATION = "generation-synthetic-1"
GPU_TIME = datetime.now(timezone.utc) - timedelta(seconds=6)
PEARL_TIME = GPU_TIME + timedelta(seconds=1)
NOW = PEARL_TIME + timedelta(seconds=1)
POLICY = EarlyPolicy("a" * 64, {"RTX_5080_LAPTOP": 120.0}, margin_ths=0.0)


def _list_instances_evidence(target=TARGET, *, status=200):
    exchange = OfflineSaladExchange(
        lambda *_args: SaladTransportResponse(status, b'{"instances":[]}'),
    )
    transport = LiveSaladReadTransport.for_offline_test(
        policy=LiveLogQueryPolicy(target.organization_name), exchange=exchange,
    )
    response = transport.fetch_list_instances(
        organization_name=target.organization_name,
        project_name=target.project_name,
        container_group_name=target.container_group_name,
    )
    assert response.evidence is not None
    assert exchange.calls[0]["method"] == "GET"
    return response.evidence


def _resolution(*, gpu_key="RTX_5080_LAPTOP", valid_until_utc=None,
                revalidated_at_utc=None, policy=POLICY):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    reference = ProviderLogObservationReference(
        evidence_sha256="c" * 64,
        event_time_utc=PEARL_TIME.isoformat().replace("+00:00", "Z"),
        data_classification="SYNTHETIC/UNVERIFIED",
        organization=ORG,
        project=PROJECT,
        container_group=GROUP,
        machine_id=MACHINE,
        instance_id=INSTANCE,
        device_namespace="fl4shminer_device",
        device_index=1,
        gpu_key=gpu_key,
        gpu_identity_source_sha256="b" * 64,
    )
    record = AssociationEvidenceRecord(
        format_version=1,
        evidence_id="synthetic-evidence-1",
        source="SYNTHETIC_TEST_ONLY",
        status="VERIFIED",
        observation_reference=reference,
        assignment_id=ASSIGNMENT,
        assignment_generation=GENERATION,
        valid_from_utc=GPU_TIME,
        valid_until_utc=valid_until_utc or NOW + timedelta(minutes=2),
        revalidated_at_utc=revalidated_at_utc or PEARL_TIME,
        policy_hash=policy.policy_hash,
        verifier_id="offline-test-verifier",
        verifier_version="1",
        evidence_sha256="0" * 64,
    )
    record = replace(record, evidence_sha256=association_evidence_sha256(record))
    evidence = _list_instances_evidence()
    # V2 evidence signs a separate synthetic log response digest. The provider
    # response proof is a bounded synthetic GET evidence object for this fixture.
    from log_alerts.live_transport import ProviderResponseEvidence
    from log_alerts.live_transport import _PROVIDER_RESPONSE_AUTHORITY
    v2_evidence = ProviderResponseEvidence(
        source="offline_test_transport", classification="SYNTHETIC/UNVERIFIED",
        status_code=200, response_sha256="d" * 64, _authority=_PROVIDER_RESPONSE_AUTHORITY,
    )
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    unsigned = StartupV2Attestation(
        schema_version=2,
        authority_id="offline-test-authority",
        key_id="offline-test-key",
        response_sha256=v2_evidence.response_sha256,
        record=record,
        signature=b"\0" * 64,
    )
    attestation = replace(
        unsigned, signature=private.sign(startup_v2_signature_payload(unsigned)),
    )
    resolver = StartupV2AttestationResolver(
        trusted_authorities={"offline-test-key": ("offline-test-authority", public)},
        attestations=(attestation,),
        offline_test_only=True,
    )
    resolution = resolver.resolve(
        reference=reference,
        response_evidence=v2_evidence,
        gpu_identity_response_evidence=v2_evidence,
        gpu_identity_data_classification=reference.data_classification,
        policy=policy,
        event_time_utc=PEARL_TIME,
        gpu_identity_event_time_utc=GPU_TIME,
        now_utc=NOW,
    )
    return resolution, _startup_v2_proof_handle(resolution), evidence


def _snapshot(target=TARGET, **overrides):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    values = {
        "target": target,
        "instance_id": INSTANCE,
        "machine_id": MACHINE,
        "assignment_id": ASSIGNMENT,
        "assignment_generation": GENERATION,
        "state": "RUNNING",
        "observed_at_utc": NOW,
        "policy_hash": POLICY.policy_hash,
        "tenant_id": target.tenant_id,
        "account_id": target.account_id,
        "request_method": "GET",
        "request_path": (
            f"/api/public/organizations/{target.organization_name}/projects/{target.project_name}/"
            f"containers/{target.container_group_name}/instances"
        ),
        "response_evidence": _list_instances_evidence(target),
        "authority_id": "offline-provider-authority",
        "key_id": "offline-provider-key",
        "signature": b"\0" * 64,
    }
    values.update(overrides)
    unsigned = SignedSyntheticProviderSnapshot(**values)
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signed = replace(unsigned, signature=private.sign(synthetic_snapshot_signature_payload(unsigned)))
    trust = {"offline-provider-key": ("offline-provider-authority", public)}
    return signed, trust


def _source_with_snapshots(target, signed_snapshots):
    # Use snapshots signed by one shared test authority for the whole sequence.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from log_alerts.provider_binding_revalidation import synthetic_snapshot_signature_payload

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    authority = {"offline-provider-key": ("offline-provider-authority", public)}
    groups = []
    for response in signed_snapshots:
        signed_response = []
        for item in response:
            unsigned = replace(item, signature=b"\0" * 64)
            signed_response.append(replace(
                unsigned,
                signature=private.sign(synthetic_snapshot_signature_payload(unsigned)),
            ))
        groups.append(tuple(signed_response))
    return SyntheticFreshProviderSource(target=target, trusted_authorities=authority, responses=tuple(groups))


class ProviderBindingRevalidationTests(unittest.TestCase):
    def setUp(self):
        self.resolution, self.proof_handle, self.v2_evidence = _resolution()
        self.assertIsNotNone(self.proof_handle)
        self.snapshot, trust = _snapshot()
        self.source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((self.snapshot,),),
        )
        self.revalidator = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=self.source,
        )

    def test_exact_signed_match_is_test_only_sanitized_and_never_authorizes(self):
        with patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")):
            result = self.revalidator.revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual(result.binding_status, "BOUND_EXACT")
        self.assertEqual(result.revalidation_status, "REVALIDATED_MATCH_TEST_ONLY")
        self.assertEqual(result.reason, "MATCH_TEST_ONLY")
        self.assertFalse(result.action_eligible)
        public = result.to_dict()
        self.assertFalse(public["actions_performed"] or public["request_submitted"] or public["action_eligible"])
        encoded = json.dumps(public, sort_keys=True) + repr(result) + repr(self.snapshot)
        for value in (TARGET.organization_id, TARGET.project_id, TARGET.container_group_id,
                      INSTANCE, MACHINE, ASSIGNMENT, GENERATION):
            self.assertNotIn(value, encoded)
        self.assertEqual(self.source.read_calls, 1)

    def test_canonical_non_rtx_gpu_keys_match_exactly_and_invalid_keys_fail_validation(self):
        for gpu_key in ("A100_SXM4_80GB", "L40S", "H100_SXM"):
            with self.subTest(gpu_key=gpu_key):
                self.assertTrue(_gpu_key(gpu_key))
                _resolution_result, proof_handle, _evidence = _resolution(gpu_key=gpu_key)
                snapshot, trust = _snapshot()
                source = SyntheticFreshProviderSource(
                    target=TARGET, trusted_authorities=trust, responses=((snapshot,),),
                )
                revalidator = ProviderBindingRevalidator(
                    allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
                )
                result = revalidator.revalidate_pre_dispatch(proof_handle, now_utc=NOW)
                self.assertEqual(result.reason, "MATCH_TEST_ONLY")
                self.assertEqual(result.revalidation_status, "REVALIDATED_MATCH_TEST_ONLY")
        for gpu_key in ("a100_sxm4_80gb", "A100--SXM", "A100_SXM ", "A" * 129, "RTX_5080/LAPTOP"):
            with self.subTest(gpu_key=gpu_key):
                self.assertFalse(_gpu_key(gpu_key))

    def test_expired_v2_binding_blocks_even_when_provider_snapshot_is_fresh(self):
        expired_at = NOW + timedelta(seconds=30)
        _resolution_result, proof_handle, _evidence = _resolution(valid_until_utc=expired_at)
        fresh_after_expiry = expired_at + timedelta(seconds=1)
        signed, trust = _snapshot(observed_at_utc=fresh_after_expiry)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(proof_handle, now_utc=fresh_after_expiry)
        self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "ATTESTATION_STALE"))
        self.assertEqual(source.read_calls, 0)

    def test_original_binding_age_limit_is_rechecked_at_predispatch(self):
        short_policy = EarlyPolicy(
            "e" * 64, {"RTX_5080_LAPTOP": 120.0}, margin_ths=0.0,
            max_binding_age_seconds=5,
        )
        _resolution_result, proof_handle, _evidence = _resolution(policy=short_policy)
        predispatch = NOW + timedelta(seconds=5)
        signed, trust = _snapshot(observed_at_utc=predispatch)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(proof_handle, now_utc=predispatch)
        self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "ATTESTATION_STALE"))
        self.assertEqual(source.read_calls, 0)

    def test_proof_expiring_during_provider_read_is_rejected_after_read(self):
        expired_at = NOW + timedelta(seconds=30)
        _resolution_result, proof_handle, _evidence = _resolution(valid_until_utc=expired_at)
        after_expiry = expired_at + timedelta(seconds=1)
        signed, trust = _snapshot(observed_at_utc=after_expiry)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        clock_values = iter((NOW, after_expiry))
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(proof_handle, now_utc=lambda: next(clock_values))
        self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "ATTESTATION_STALE"))
        self.assertEqual(source.read_calls, 1)

    def test_provider_snapshot_freshness_is_measured_after_synchronous_read(self):
        signed, trust = _snapshot(observed_at_utc=NOW)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        clock_values = iter((NOW, NOW + timedelta(seconds=16)))
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(self.proof_handle, now_utc=lambda: next(clock_values))
        self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "ASSIGNMENT_STATE_STALE"))
        self.assertEqual(source.read_calls, 1)

    def test_provider_read_exceeding_total_duration_limit_is_blocked(self):
        signed, trust = _snapshot(observed_at_utc=NOW)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        with patch(
            "log_alerts.provider_binding_revalidation.time.monotonic",
            side_effect=(100.0, 105.001),
        ):
            result = ProviderBindingRevalidator(
                allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
            ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "SOURCE_READ_TIMEOUT"))
        self.assertEqual(source.read_calls, 1)
        self.assertEqual(source.last_timeout_seconds, 5.0)

    def test_provider_read_at_duration_limit_remains_valid(self):
        signed, trust = _snapshot(observed_at_utc=NOW)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        with patch(
            "log_alerts.provider_binding_revalidation.time.monotonic",
            side_effect=(100.0, 105.0),
        ):
            result = ProviderBindingRevalidator(
                allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
            ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual(result.revalidation_status, "REVALIDATED_MATCH_TEST_ONLY")
        self.assertEqual(source.last_timeout_seconds, 5.0)

    def test_monotonic_clock_rollback_blocks_provider_result(self):
        signed, trust = _snapshot(observed_at_utc=NOW)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        with patch(
            "log_alerts.provider_binding_revalidation.time.monotonic",
            side_effect=(100.0, 99.0),
        ):
            result = ProviderBindingRevalidator(
                allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
            ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "SOURCE_READ_CLOCK_INVALID"))
        self.assertFalse(result.action_eligible)

    def test_wall_clock_rollback_after_provider_read_blocks_result(self):
        signed, trust = _snapshot(observed_at_utc=NOW)
        source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=trust, responses=((signed,),),
        )
        clock_values = iter((NOW, NOW - timedelta(seconds=1)))
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(self.proof_handle, now_utc=lambda: next(clock_values))
        self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "SOURCE_WALL_CLOCK_ROLLBACK"))
        self.assertFalse(result.action_eligible)

    def test_all_seven_trusted_identifier_changes_block(self):
        changed_org = replace(TARGET, organization_id="other-org-id")
        changed_project = replace(TARGET, project_id="other-project-id")
        changed_group = replace(TARGET, container_group_id="other-group-id")
        cases = (
            (changed_org, {}, "SOURCE_RESPONSE_INVALID"),
            (changed_project, {}, "SOURCE_RESPONSE_INVALID"),
            (changed_group, {}, "SOURCE_RESPONSE_INVALID"),
            (TARGET, {"instance_id": "other-instance"}, "ASSIGNMENT_IDENTITY_MISMATCH"),
            (TARGET, {"machine_id": "other-machine"}, "ASSIGNMENT_IDENTITY_MISMATCH"),
            (TARGET, {"assignment_id": "other-assignment"}, "ASSIGNMENT_GENERATION_MISMATCH"),
            (TARGET, {"assignment_generation": "other-generation"}, "ASSIGNMENT_GENERATION_MISMATCH"),
        )
        for signed_target, changes, expected in cases:
            with self.subTest(changes=(signed_target.organization_id, signed_target.project_id,
                                       signed_target.container_group_id, *changes.keys())):
                signed, _trust = _snapshot(target=signed_target, **changes)
                source = _source_with_snapshots(TARGET, ((signed,),))
                result = ProviderBindingRevalidator(
                    allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
                ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
                self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", expected))

    def test_org_project_group_id_and_account_scope_changes_block(self):
        changed = ExactSaladAssignmentTarget(
            ORG, PROJECT, GROUP, "other-org-id", TARGET.project_id, TARGET.container_group_id,
            tenant_id=TARGET.tenant_id, account_id=TARGET.account_id,
        )
        signed, _ = _snapshot(target=changed)
        source = _source_with_snapshots(TARGET, ((signed,),))
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual(result.reason, "SOURCE_RESPONSE_INVALID")
        self.assertFalse(result.action_eligible)

        signed, _ = _snapshot(account_id="other-account")
        source = _source_with_snapshots(TARGET, ((signed,),))
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual(result.reason, "SOURCE_SCOPE_MISMATCH")

    def test_stale_future_and_not_running_are_unknown(self):
        for snapshot_time, state, expected in (
            (NOW - timedelta(seconds=16), "RUNNING", "ASSIGNMENT_STATE_STALE"),
            (NOW + timedelta(seconds=1), "RUNNING", "ASSIGNMENT_STATE_FUTURE"),
            (NOW, "STOPPED", "ASSIGNMENT_NOT_RUNNING"),
        ):
            with self.subTest(expected=expected):
                signed, _ = _snapshot(observed_at_utc=snapshot_time, state=state)
                source = _source_with_snapshots(TARGET, ((signed,),))
                result = ProviderBindingRevalidator(
                    allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
                ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
                self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", expected))

    def test_no_source_scope_miss_duplicates_and_bad_signature_fail_closed(self):
        allowlist = ExplicitBindingAllowlist((TARGET,))
        self.assertEqual(
            ProviderBindingRevalidator(allowlist=allowlist, source=None)
            .revalidate_pre_dispatch(self.proof_handle, now_utc=NOW).reason,
            "SOURCE_UNAVAILABLE",
        )
        other = ExactSaladAssignmentTarget("fleet-other", PROJECT, GROUP, "o2", "p2", "g2")
        self.assertEqual(
            ProviderBindingRevalidator(allowlist=ExplicitBindingAllowlist((other,)), source=None)
            .revalidate_pre_dispatch(self.proof_handle, now_utc=NOW).reason,
            "SCOPE_NOT_ALLOWLISTED",
        )
        duplicate_source = _source_with_snapshots(TARGET, ((self.snapshot, self.snapshot),))
        duplicate = ProviderBindingRevalidator(allowlist=allowlist, source=duplicate_source)
        self.assertEqual(duplicate.revalidate_pre_dispatch(self.proof_handle, now_utc=NOW).reason,
                         "SOURCE_DUPLICATE_ASSIGNMENT")

        bad = replace(self.snapshot, signature=b"x" * 64)
        bad_source = SyntheticFreshProviderSource(
            target=TARGET, trusted_authorities=self.source.trusted_authorities, responses=((bad,),),
        )
        result = ProviderBindingRevalidator(allowlist=allowlist, source=bad_source).revalidate_pre_dispatch(
            self.proof_handle, now_utc=NOW,
        )
        self.assertEqual(result.reason, "SOURCE_SIGNATURE_INVALID")

    def test_provider_http_failures_and_missing_ids_remain_unknown(self):
        for status in (401, 403, 429, 500, 503):
            with self.subTest(status=status):
                signed, _ = _snapshot(response_evidence=_list_instances_evidence(status=status))
                source = _source_with_snapshots(TARGET, ((signed,),))
                result = ProviderBindingRevalidator(
                    allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
                ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
                self.assertEqual((result.binding_status, result.reason), ("UNKNOWN", "SOURCE_RESPONSE_INVALID"))
        with self.assertRaisesRegex(ValueError, "INVALID_SYNTHETIC_PROVIDER_SNAPSHOT"):
            _snapshot(machine_id="")

    def test_wrong_route_and_policy_mismatch_block(self):
        signed, _ = _snapshot(request_path="/api/public/organizations/adrianfiverr/other")
        source = _source_with_snapshots(TARGET, ((signed,),))
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual(result.reason, "SOURCE_RESPONSE_INVALID")

        signed, _ = _snapshot(policy_hash="f" * 64)
        source = _source_with_snapshots(TARGET, ((signed,),))
        result = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        ).revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual(result.reason, "POLICY_HASH_MISMATCH")

    def test_pre_dispatch_always_consumes_a_fresh_uncached_snapshot(self):
        second, _ = _snapshot(assignment_generation="generation-synthetic-2")
        source = _source_with_snapshots(TARGET, ((self.snapshot,), (second,)))
        revalidator = ProviderBindingRevalidator(
            allowlist=ExplicitBindingAllowlist((TARGET,)), source=source,
        )
        first = revalidator.revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        after_race = revalidator.revalidate_pre_dispatch(self.proof_handle, now_utc=NOW)
        self.assertEqual(first.revalidation_status, "REVALIDATED_MATCH_TEST_ONLY")
        self.assertEqual(after_race.reason, "ASSIGNMENT_GENERATION_MISMATCH")
        self.assertEqual(source.read_calls, 2)
        self.assertFalse(first.action_eligible or after_race.action_eligible)

    def test_invalid_handle_and_ambiguous_allowlist_block(self):
        self.assertEqual(
            self.revalidator.revalidate_pre_dispatch(object(), now_utc=NOW).reason,
            "NO_VERIFIED_V2_PROOF",
        )
        with self.assertRaisesRegex(ValueError, "DUPLICATE_BINDING_ALLOWLIST_TARGET"):
            ExplicitBindingAllowlist((TARGET, TARGET))
        with self.assertRaisesRegex(ValueError, "INVALID_EXACT_PROVIDER_TARGET"):
            ExactSaladAssignmentTarget("*", PROJECT, GROUP, "org", "project", "group")
        with self.assertRaisesRegex(ValueError, "INVALID_PROVIDER_REVALIDATION_AGE"):
            ProviderBindingRevalidator(allowlist=ExplicitBindingAllowlist((TARGET,)), source=None,
                                       maximum_age_seconds=16)

    def test_multi_organization_allowlist_is_explicit_and_splits_without_aliasing(self):
        target_b = ExactSaladAssignmentTarget(
            "fleet-bravo", PROJECT, "fl4shminer", "org-b", "project-b", "group-b",
            tenant_id="tenant-b", account_id="account-b",
        )
        allowlist = ExplicitBindingAllowlist((TARGET, target_b))
        scoped_a = allowlist.for_organization(ORG)
        scoped_b = allowlist.for_organization("fleet-bravo")
        self.assertEqual(scoped_a.targets, (TARGET,))
        self.assertEqual(scoped_b.targets, (target_b,))
        self.assertIsNone(scoped_b.find(self.proof_handle.record.observation_reference))
        self.assertNotEqual(scoped_a.targets, scoped_b.targets)


if __name__ == "__main__":
    unittest.main()
