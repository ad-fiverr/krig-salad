"""Offline identity fallback tests for the central Salad fleet watcher."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from log_alerts.contract import DATA_CLASSIFICATION, LiveLogQueryPolicy  # noqa: E402
from log_alerts.live_transport import (  # noqa: E402
    LiveSaladReadTransport,
    OfflineSaladExchange,
    SaladTransportResponse,
    secret_boundary_types,
)
from log_alerts.list_instances_lookup import ListInstancesLookup  # noqa: E402
from log_alerts.normalize import (  # noqa: E402
    NormalizedLogEntry,
    ProviderIdentity,
    resolve_provider_identity,
)


ORG = "fleet-one"
PROJECT = "miners"
GROUP_A = "fl4shminer"
GROUP_B = "fl4shminer-2"
INSTANCE = "11111111-1111-4111-8111-111111111111"
MACHINE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
MACHINE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
InteractiveSecretProvider, SyntheticSecretProvider, _ = secret_boundary_types()


def _entry(*, org=ORG, project=PROJECT, group=GROUP_A, instance=INSTANCE,
           machine=None, status="UNKNOWN"):
    identity = ProviderIdentity(
        status=status,
        machine_id=machine,
        instance_id=instance,
        container_group_name=group,
        organization_name=org,
        project_name=project,
        source="resource.labels",
        labels_fingerprint=hashlib.sha256(
            json.dumps([org, project, group, instance, machine], separators=(",", ":")).encode()
        ).hexdigest(),
    )
    return NormalizedLogEntry(
        log_id="synthetic-entry",
        event_time_utc="2026-10-13T12:00:00.000000Z",
        resource_type="salad.container_group_instance",
        resource_labels={"instance_id": instance},
        text_log="synthetic text",
        structured_message=None,
        data_classification=DATA_CLASSIFICATION,
        identity=identity,
        alert=None,
        marker=None,
        alert_source=None,
        evidence_sha256="c" * 64,
        startup_signal=None,
        startup_signal_source=None,
        cuda_signal=None,
        cuda_signal_source=None,
    )


def _response(value, status=200):
    return SaladTransportResponse(status, json.dumps(value).encode("utf-8"))


class FleetIdentityFallbackTests(unittest.TestCase):
    def make_lookup(self, responder, *, clock=None, allowed=(PROJECT,)):
        exchange = OfflineSaladExchange(responder)
        transport = LiveSaladReadTransport.for_offline_test(
            policy=LiveLogQueryPolicy(ORG), exchange=exchange,
        )
        provider = SyntheticSecretProvider()
        lookup = ListInstancesLookup(
            organization_name=ORG,
            transport=transport,
            secret_provider=provider,
            allowed_projects=allowed,
            ttl_seconds=10,
            clock=clock or (lambda: 1.0),
        )
        return lookup, exchange, provider

    def test_partial_identity_is_preserved_but_conflicting_provider_labels_are_suppressed(self):
        partial = resolve_provider_identity({"instance_id": INSTANCE})
        self.assertEqual(partial.status, "UNKNOWN")
        self.assertIsNone(partial.machine_id)
        self.assertEqual(partial.instance_id, INSTANCE)
        self.assertEqual(partial.public_fields()["instance_id"], INSTANCE)

        conflicting = resolve_provider_identity({
            "machine_id": MACHINE_A,
            "machineId": MACHINE_B,
            "instance_id": INSTANCE,
        })
        self.assertEqual(conflicting.status, "CONFLICTING")
        self.assertIsNone(conflicting.public_fields()["machine_id"])
        self.assertIsNone(conflicting.public_fields()["instance_id"])

    def test_exact_group_scope_resolves_instance_to_provider_machine(self):
        calls = []

        def responder(_host, path, _headers, _body):
            calls.append(path)
            group = path.split("/containers/", 1)[1].split("/", 1)[0]
            machine = MACHINE_A if group == GROUP_A else MACHINE_B
            return _response({"instances": [{"id": INSTANCE, "instance_id": INSTANCE, "machine_id": machine}]})

        lookup, exchange, _provider = self.make_lookup(responder)
        original = _entry(group=GROUP_A)
        resolved_a = lookup.resolve_entry(original)
        resolved_b = lookup.resolve_entry(_entry(group=GROUP_B))
        self.assertEqual(resolved_a.identity.machine_id, MACHINE_A)
        self.assertEqual(resolved_b.identity.machine_id, MACHINE_B)
        self.assertEqual(resolved_a.identity.source, "list_container_group_instances")
        self.assertEqual(resolved_a.identity.status, DATA_CLASSIFICATION)
        self.assertEqual(resolved_a.identity.labels_fingerprint, original.identity.labels_fingerprint)
        self.assertEqual(resolved_a.identity.source_identity_key(), original.identity.source_identity_key())
        self.assertEqual(len(calls), 2)
        self.assertEqual([call["method"] for call in exchange.calls], ["GET", "GET"])
        self.assertTrue(all("/containers/" + group + "/instances" in path for path, group in zip(calls, (GROUP_A, GROUP_B))))
        self.assertTrue(all(call["headers"]["Salad-Api-Key"] == "[REDACTED]" for call in exchange.calls))

    def test_org_project_group_and_complete_instance_id_are_required_for_fallback(self):
        calls = []

        def responder(*args):
            calls.append(args[1])
            return _response({"instances": [{"instance_id": INSTANCE, "machine_id": MACHINE_A}]})

        lookup, _exchange, _provider = self.make_lookup(responder)
        cases = (
            _entry(org="another-org"),
            _entry(project="other-project"),
            _entry(group=None),
            _entry(instance="not-a-uuid"),
            _entry(status="CONFLICTING"),
            _entry(machine=MACHINE_A),
        )
        for entry in cases:
            with self.subTest(identity=entry.identity):
                self.assertEqual(lookup.resolve_entry(entry), entry)
        self.assertEqual(calls, [])

    def test_missing_duplicate_malformed_and_conflicting_list_rows_remain_unknown(self):
        variants = (
            {"instances": []},
            {"instances": [{"instance_id": INSTANCE}]},
            {"instances": [{"instance_id": INSTANCE, "machine_id": MACHINE_A},
                            {"instance_id": INSTANCE, "machine_id": MACHINE_B}]},
            {"instances": [{"id": INSTANCE, "instance_id": INSTANCE + "x", "machine_id": MACHINE_A}]},
            {"instances": [{"id": INSTANCE, "instance_id": INSTANCE, "machine_id": "not-a-uuid"}]},
            {"wrong_shape": []},
        )
        for body in variants:
            with self.subTest(body=body):
                lookup, _exchange, _provider = self.make_lookup(lambda *_args, body=body: _response(body))
                result = lookup.resolve_entry(_entry())
                self.assertEqual(result.identity.status, "UNKNOWN")
                self.assertIsNone(result.identity.machine_id)

    def test_scope_conflict_or_saturated_list_page_fails_closed(self):
        scoped_conflict = {
            "project_name": "other-project",
            "instances": [{"instance_id": INSTANCE, "machine_id": MACHINE_A}],
        }
        lookup, _exchange, _provider = self.make_lookup(lambda *_args: _response(scoped_conflict))
        entry = _entry()
        self.assertEqual(lookup.resolve_entry(entry), entry)

        saturated = {"instances": [
            {"instance_id": f"{index:08x}-1111-4111-8111-111111111111", "machine_id": MACHINE_A}
            for index in range(1000)
        ]}
        lookup, _exchange, _provider = self.make_lookup(lambda *_args: _response(saturated))
        result = lookup.resolve_entry(_entry())
        self.assertEqual(result.identity.status, "UNKNOWN")
        self.assertIsNone(result.identity.machine_id)

    def test_scope_cache_expires_and_cycle_deduplicates_group_lookup(self):
        now = [0.0]
        calls = []

        def responder(*_args):
            calls.append(1)
            return _response({"instances": [{"instance_id": INSTANCE, "machine_id": MACHINE_A}]})

        lookup, _exchange, _provider = self.make_lookup(responder, clock=lambda: now[0])
        first = _entry()
        second = replace(first, evidence_sha256="d" * 64)
        lookup.begin_cycle()
        self.assertEqual(lookup.resolve_entry(first).identity.machine_id, MACHINE_A)
        self.assertEqual(lookup.resolve_entry(second).identity.machine_id, MACHINE_A)
        self.assertEqual(len(calls), 1)
        self.assertEqual(lookup.lookups, 1)
        self.assertEqual(lookup.cache_hits, 1)
        now[0] = 11.0
        lookup.begin_cycle()
        self.assertEqual(lookup.resolve_entry(first).identity.machine_id, MACHINE_A)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
