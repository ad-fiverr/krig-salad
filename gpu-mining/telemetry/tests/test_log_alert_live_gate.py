"""Offline-only tests for the disabled Salad organization-log boundary."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from log_alerts.contract import (  # noqa: E402
    DATA_CLASSIFICATION,
    DENIED,
    PROVIDER_OBSERVED,
    READ_LOG_QUERY,
    LiveLogQueryPolicy,
)
from log_alerts.central_telegram import (  # noqa: E402
    CentralTelegramSender,
    SyntheticTelegramSecretProvider,
)
from log_alerts.engine import LogAlertEnricher  # noqa: E402
from log_alerts.ledger import SQLiteAlertLedger  # noqa: E402
from log_alerts.live_adapter import (  # noqa: E402
    LiveAdapterError,
    LiveLogQueryAdapter,
    LiveQueryLimits,
)
from log_alerts.live_controller import (  # noqa: E402
    LiveControllerBlocked,
    LiveLogAlertController,
    summarize_probe,
)
from log_alerts.live_transport import (  # noqa: E402
    LiveSaladReadTransport,
    LiveTransportBlocked,
    OfflineSaladExchange,
    ProviderResponseEvidence,
    SaladTransportResponse,
    secret_boundary_types,
)

InteractiveSecretProvider, SyntheticSecretProvider, SecretMaterial = secret_boundary_types()


ORG = "adrianfiverr"
START = "2026-10-13T12:00:00Z"
END = "2026-10-13T12:01:00Z"
POOL_LINE = (
    "2026/10/13 12:00:30 Pool connection failed: mining.authorize response timeout; "
    "reconnecting; retrying in 10s"
)


def _labels(**overrides):
    labels = {
        "machine_id": "machine-sensitive-test",
        "instance_id": "instance-sensitive-test",
        "container_group_name": "fl4shminer-2",
        "organization_name": ORG,
        "project_name": "miners",
        "opaque_private_label": "sensitive-label-value",
    }
    labels.update(overrides)
    return labels


def _item(event_time= "2026-10-13T12:00:30Z", *, labels=None, text=POOL_LINE):
    return {
        "time": event_time,
        "receive_time": event_time,
        "resource": {
            "type": "salad.container_group_instance",
            "labels": labels if labels is not None else _labels(),
        },
        "severity": "ERROR",
        "json_log": None,
        "text_log": text,
    }


def _response(items):
    times = [item["time"] for item in items]
    return SaladTransportResponse(
        200,
        json.dumps({
            "items": items,
            "page_min_time": min(times) if times else None,
            "page_max_time": max(times) if times else None,
        }).encode("utf-8"),
    )


def _build_offline(*, responder, limits=None, ledger=None):
    policy = LiveLogQueryPolicy(ORG)
    exchange = OfflineSaladExchange(responder)
    transport = LiveSaladReadTransport.for_offline_test(policy=policy, exchange=exchange)
    secret_provider = SyntheticSecretProvider()
    store = ledger or SQLiteAlertLedger()
    enricher = LogAlertEnricher(
        approved_organization=ORG,
        transport=transport,
        ledger=store,
        limits=limits or LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=0),
        secret_provider=secret_provider,
    )
    return enricher, exchange, secret_provider, store


class LiveRouteAndTransportTests(unittest.TestCase):
    def test_only_exact_organization_log_query_post_is_read_log_query(self):
        policy = LiveLogQueryPolicy(ORG)
        self.assertEqual(policy.classify(method="POST", host="api.salad.com", port=443, path=policy.path), READ_LOG_QUERY)
        self.assertEqual(policy.classify(method="GET", host="api.salad.com", port=443, path=policy.path), DENIED)
        self.assertEqual(policy.classify(method="POST", host="api.salad.com", port=443, path=policy.path + "/start"), DENIED)
        self.assertEqual(policy.classify(method="POST", host="salad.example", port=443, path=policy.path), DENIED)
        self.assertEqual(policy.classify(method="POST", host="api.salad.com", port=80, path=policy.path), DENIED)
        request = policy.build_request(start_time_utc=START, end_time_utc=END, query='severity="ERROR"')
        self.assertEqual(request.path, f"/api/public/organizations/{ORG}/log-entries")
        self.assertEqual(request.sort_order, "asc")
        self.assertLessEqual(request.page_size, 100)
        with self.assertRaises(ValueError):
            policy.validate(replace(request, path=policy.path + "/reallocate"))

    def test_request_requires_explicit_bounded_non_secret_query(self):
        policy = LiveLogQueryPolicy(ORG)
        for value in ("", "   ", "query\nnext", "token=do-not-echo"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.build_request(start_time_utc=START, end_time_utc=END, query=value)
        with self.assertRaises(ValueError):
            policy.build_request(start_time_utc=END, end_time_utc=START, query="valid")
        with self.assertRaises(ValueError):
            policy.build_request(start_time_utc=START, end_time_utc=END, query="valid", page_size=101)

    def test_real_transport_fails_before_network_or_secret_acquisition(self):
        policy = LiveLogQueryPolicy(ORG)
        transport = LiveSaladReadTransport(policy=policy)
        request = policy.build_request(start_time_utc=START, end_time_utc=END, query="severity=ERROR")
        with self.assertRaisesRegex(LiveTransportBlocked, "disabled"):
            transport.fetch_query(request)
        self.assertIn("credentials=[REDACTED]", repr(transport))

    def test_live_secret_boundaries_reject_arbitrary_provider_types(self):
        policy = LiveLogQueryPolicy(ORG)
        with self.assertRaisesRegex(TypeError, "InteractiveSecretProvider"):
            LiveSaladReadTransport(policy=policy, secret_provider=object())
        approved_provider = InteractiveSecretProvider(enabled=False)
        live_transport = LiveSaladReadTransport(policy=policy, secret_provider=approved_provider)
        with self.assertRaisesRegex(TypeError, "InteractiveSecretProvider"):
            LiveLogQueryAdapter(
                approved_organization=ORG,
                transport=live_transport,
                secret_provider=object(),
            )
        request = policy.build_request(start_time_utc=START, end_time_utc=END, query="severity=ERROR")
        with (
            patch("log_alerts.live_transport.PRODUCTION_NETWORK_ALLOWED", True),
            self.assertRaisesRegex(LiveTransportBlocked, "credential is unavailable"),
        ):
            live_transport.fetch_query(request, secret=object())
        offline = LiveSaladReadTransport.for_offline_test(
            policy=policy,
            exchange=OfflineSaladExchange(lambda *_args: _response([])),
        )
        with self.assertRaisesRegex(TypeError, "SyntheticSecretProvider"):
            LiveLogQueryAdapter(
                approved_organization=ORG,
                transport=offline,
                secret_provider=object(),
            )

    def test_fixed_salad_https_request_has_exactly_one_host_header(self):
        class FakeResponse:
            status = 200

            @staticmethod
            def read(_maximum):
                return b'{"items":[]}'

        class FakeConnection:
            last = None

            def __init__(self, host, port, **kwargs):
                self.host = host
                self.port = port
                self.kwargs = kwargs
                self.sock = None
                self.headers = []
                self.putrequest_args = None
                FakeConnection.last = self

            def connect(self):
                pass

            def putrequest(self, *args, **kwargs):
                self.putrequest_args = (args, kwargs)

            def putheader(self, name, value):
                self.headers.append((name, value))

            def endheaders(self, _body):
                pass

            @staticmethod
            def getresponse():
                return FakeResponse()

            @staticmethod
            def close():
                pass

        provider = InteractiveSecretProvider(enabled=False)
        secret = SecretMaterial(
            "SYNTHETIC_ONLY_NOT_A_CREDENTIAL",
            source_label="interactive_tty_session",
        )
        policy = LiveLogQueryPolicy(ORG)
        transport = LiveSaladReadTransport(policy=policy, secret_provider=provider)
        request = policy.build_request(start_time_utc=START, end_time_utc=END, query="severity=ERROR")
        with (
            patch.object(provider, "acquire", return_value=secret),
            patch("log_alerts.live_transport.PRODUCTION_NETWORK_ALLOWED", True),
            patch("log_alerts.live_transport.http.client.HTTPSConnection", FakeConnection),
        ):
            response = transport.fetch_query(request, secret=secret)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(FakeConnection.last.host, "api.salad.com")
        self.assertEqual(FakeConnection.last.port, 443)
        host_headers = [value for name, value in FakeConnection.last.headers if name.casefold() == "host"]
        self.assertEqual(host_headers, ["api.salad.com"])
        self.assertTrue(FakeConnection.last.putrequest_args[1]["skip_host"])

    def test_offline_exchange_is_redacted_and_never_provider_observed(self):
        seen = []

        def responder(host, path, headers, body):
            seen.append((host, path, dict(headers), json.loads(body)))
            return _response([_item()])

        enricher, exchange, provider, ledger = _build_offline(responder=responder)
        result = enricher.run_once(end_time_utc=END, query='severity="ERROR"')
        self.assertEqual(result.data_classification, DATA_CLASSIFICATION)
        self.assertEqual(result.records_seen, 1)
        self.assertEqual(result.evidence[0].identity.status, DATA_CLASSIFICATION)
        self.assertEqual(len(exchange.calls), 1)
        self.assertEqual(exchange.calls[0]["headers"]["Salad-Api-Key"], "[REDACTED]")
        self.assertEqual(seen[0][0:2], ("api.salad.com", f"/api/public/organizations/{ORG}/log-entries"))
        self.assertEqual(seen[0][2]["Salad-Api-Key"], "SYNTHETIC_ONLY_NOT_A_CREDENTIAL")
        self.assertEqual(set(seen[0][3]), {"start_time", "end_time", "query", "page_size", "sort_order"})
        self.assertNotIn("SYNTHETIC_ONLY_NOT_A_CREDENTIAL", repr(exchange.calls))
        self.assertNotIn("sensitive-label-value", repr(ledger.list_outbox()))
        self.assertEqual(provider.read_count, 1)
        ledger.close()

    def test_synthetic_response_evidence_cannot_be_promoted_by_fixture_fields(self):
        with self.assertRaises(TypeError):
            ProviderResponseEvidence(
                source="salad_https_fixed_route",
                classification=PROVIDER_OBSERVED,
                status_code=200,
                response_sha256="a" * 64,
            )

        def responder(_host, _path, _headers, _body):
            return _response([_item()])

        enricher, _, _, ledger = _build_offline(responder=responder)
        result = enricher.run_once(end_time_utc=END, query="severity=ERROR")
        self.assertNotEqual(result.data_classification, PROVIDER_OBSERVED)
        self.assertTrue(all(item["payload"]["data_classification"] == DATA_CLASSIFICATION for item in ledger.list_outbox()))
        ledger.close()


class LiveAdapterTests(unittest.TestCase):
    def test_probe_makes_one_request_and_reports_saturated_completeness_unknown(self):
        items = [
            _item(labels=_labels(machine_id="machine-one")),
            _item(labels=_labels(machine_id="machine-two", instance_id="instance-two")),
        ]
        enricher, exchange, _, ledger = _build_offline(
            responder=lambda *_args: _response(items),
            limits=LiveQueryLimits(page_size=2, maximum_window_seconds=60, overlap_seconds=0),
        )
        controller = LiveLogAlertController(enricher=enricher, ledger=ledger)
        summary = controller.probe_once(
            start_time_utc=START,
            end_time_utc=END,
            query="severity=ERROR",
            enable_live_read=True,
        )
        self.assertEqual(len(exchange.calls), 1)
        self.assertEqual(summary.subqueries_seen, 1)
        self.assertEqual(summary.completeness, "UNKNOWN_SATURATED")
        self.assertEqual(summary.records_seen, 2)
        self.assertIsNone(ledger.get_cursor())
        ledger.close()

    def test_probe_rejects_window_over_limit_before_any_request(self):
        enricher, exchange, provider, ledger = _build_offline(
            responder=lambda *_args: _response([]),
            limits=LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=0),
        )
        with self.assertRaisesRegex(LiveAdapterError, "window exceeds"):
            enricher.live_adapter.probe_single_request(
                start_time_utc=START,
                end_time_utc="2026-10-13T12:01:01Z",
                query="severity=ERROR",
            )
        self.assertEqual(exchange.calls, [])
        self.assertEqual(provider.read_count, 0)
        self.assertIsNone(ledger.get_cursor())
        ledger.close()

    def test_saturated_window_is_recursively_split_and_boundary_duplicates_deduped(self):
        start = datetime.fromisoformat(START.replace("Z", "+00:00"))
        observed = []

        def stamp(delta):
            return (start + delta).isoformat(timespec="seconds").replace("+00:00", "Z")

        def responder(_host, _path, _headers, body):
            request = json.loads(body)
            s = datetime.fromisoformat(request["start_time"].replace("Z", "+00:00"))
            e = datetime.fromisoformat(request["end_time"].replace("Z", "+00:00"))
            duration = (e - s).total_seconds()
            if duration > 2:
                items = [_item(stamp(timedelta(seconds=1))), _item(stamp(timedelta(seconds=3)), labels=_labels(machine_id="machine-two"))]
            elif s == start:
                items = [_item(stamp(timedelta(seconds=1)))]
            else:
                items = [_item(stamp(timedelta(seconds=3)), labels=_labels(machine_id="machine-two"))]
            observed.append((request["start_time"], request["end_time"], len(items)))
            return _response(items)

        policy = LiveLogQueryPolicy(ORG)
        exchange = OfflineSaladExchange(responder)
        transport = LiveSaladReadTransport.for_offline_test(policy=policy, exchange=exchange)
        adapter = LiveLogQueryAdapter(
            approved_organization=ORG,
            transport=transport,
            secret_provider=SyntheticSecretProvider(),
            limits=LiveQueryLimits(page_size=2, maximum_window_seconds=60, overlap_seconds=0),
        )
        result = adapter.fetch_complete_window(
            start_time_utc=START,
            end_time_utc="2026-10-13T12:00:04Z",
            query="severity=ERROR",
        )
        self.assertEqual(result.subqueries_seen, 3)
        self.assertEqual(result.response_items_seen, 4)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.data_classification, DATA_CLASSIFICATION)
        self.assertEqual([call[2] for call in observed], [2, 1, 1])

    def test_saturated_minimum_slice_fails_closed(self):
        def responder(_host, _path, _headers, body):
            request = json.loads(body)
            t = request["start_time"]
            return _response([_item(t)])

        policy = LiveLogQueryPolicy(ORG)
        transport = LiveSaladReadTransport.for_offline_test(
            policy=policy,
            exchange=OfflineSaladExchange(responder),
        )
        adapter = LiveLogQueryAdapter(
            approved_organization=ORG,
            transport=transport,
            secret_provider=SyntheticSecretProvider(),
            limits=LiveQueryLimits(page_size=1, maximum_window_seconds=60, overlap_seconds=0),
        )
        with self.assertRaisesRegex(LiveAdapterError, "saturated"):
            adapter.fetch_complete_window(
                start_time_utc=START,
                end_time_utc="2026-10-13T12:00:02Z",
                query="severity=ERROR",
            )

    def test_bad_org_or_bad_page_bounds_do_not_advance_enricher_cursor(self):
        scenarios = (
            [_item(labels=_labels(organization_name="other-org"))],
            [_item()],
        )
        for index, items in enumerate(scenarios):
            with self.subTest(index=index):
                def responder(_host, _path, _headers, _body, items=items, index=index):
                    result = _response(items)
                    if index == 1:
                        body = json.loads(result.body)
                        body["page_max_time"] = "2026-10-13T12:00:59Z"
                        return SaladTransportResponse(200, json.dumps(body).encode())
                    return result

                enricher, _, _, ledger = _build_offline(responder=responder)
                with self.assertRaises(LiveAdapterError):
                    enricher.run_once(end_time_utc=END, query="severity=ERROR")
                self.assertIsNone(ledger.get_cursor())
                self.assertEqual(ledger.alert_count(), 0)
                ledger.close()

    def test_oversized_provider_page_is_rejected_before_cursor_commit(self):
        oversized = [_item() for _ in range(101)]
        enricher, exchange, _, ledger = _build_offline(
            responder=lambda *_args: _response(oversized),
            limits=LiveQueryLimits(page_size=100, maximum_window_seconds=60, overlap_seconds=0),
        )
        with self.assertRaisesRegex(LiveAdapterError, "more items than requested page_size"):
            enricher.run_once(end_time_utc=END, query="severity=ERROR")
        self.assertEqual(len(exchange.calls), 1)
        self.assertIsNone(ledger.get_cursor())
        self.assertEqual(ledger.alert_count(), 0)
        ledger.close()

    def test_live_adapter_reuses_cursor_and_overlap_deduplicates_without_promotion(self):
        def responder(_host, _path, _headers, _body):
            return _response([_item(event_time="2026-10-13T12:01:00Z")])

        limits = LiveQueryLimits(
            maximum_window_seconds=60,
            overlap_seconds=10,
        )
        enricher, exchange, _, ledger = _build_offline(responder=responder, limits=limits)
        first = enricher.run_once(end_time_utc=END, query="severity=ERROR")
        second = enricher.run_once(
            end_time_utc="2026-10-13T12:01:30Z",
            query="severity=ERROR",
        )
        self.assertEqual(first.prepared_count, 1)
        self.assertEqual(second.prepared_count, 0)
        self.assertEqual(second.duplicate_count, 1)
        self.assertEqual(ledger.alert_count(), 1)
        self.assertEqual(len(exchange.calls), 2)
        self.assertEqual(second.data_classification, DATA_CLASSIFICATION)
        ledger.close()

    def test_missing_identity_stays_unknown_and_miner_text_cannot_supply_ids(self):
        labels = {"organization_name": ORG, "project_name": "miners", "container_group_name": "fl4shminer"}
        spoofed = "miner said machine_id=claimed instance_id=claimed"

        def responder(_host, _path, _headers, _body):
            return _response([_item(labels=labels, text=spoofed)])

        enricher, _, _, ledger = _build_offline(responder=responder)
        result = enricher.run_once(end_time_utc=END, query="severity=ERROR")
        self.assertEqual(result.evidence[0].identity.status, "UNKNOWN")
        outbox = ledger.list_outbox()
        self.assertEqual(len(outbox), 0)
        self.assertIsNone(result.evidence[0].identity.machine_id)
        self.assertIsNone(result.evidence[0].identity.instance_id)
        self.assertNotIn("claimed", repr(result.evidence[0].identity.public_fields()))
        ledger.close()

    def test_probe_summary_contains_label_names_but_not_values_or_raw_logs(self):
        def responder(_host, _path, _headers, _body):
            return _response([_item()])

        enricher, _, _, ledger = _build_offline(responder=responder)
        probe = enricher.live_adapter.probe_single_request(
            start_time_utc=START,
            end_time_utc=END,
            query="severity=ERROR",
        )
        summary = summarize_probe(
            probe.entries,
            classification=probe.data_classification,
            start=probe.query_start_utc,
            end=probe.query_end_utc,
            subqueries=probe.subqueries_seen,
            completeness=probe.window_completeness,
        )
        rendered = json.dumps(asdict(summary), sort_keys=True)
        self.assertIn("machine_id", rendered)
        self.assertIn("opaque_private_label", rendered)
        self.assertNotIn("machine-sensitive-test", rendered)
        self.assertNotIn("instance-sensitive-test", rendered)
        self.assertNotIn("sensitive-label-value", rendered)
        self.assertNotIn(POOL_LINE, rendered)
        self.assertEqual(summary.data_classification, DATA_CLASSIFICATION)
        ledger.close()

    def test_hard_disabled_probe_does_not_prompt_or_create_ledger(self):
        from log_alerts.live_cli import main

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "must-not-be-created.sqlite3"
            result = main([
                "--probe-live-contract-once", "--enable-live-read",
                "--organization", ORG, "--query", "severity=ERROR",
                "--start-time", START, "--end-time", END,
                "--ledger-path", str(db_path),
            ])
            self.assertEqual(result, 3)
            self.assertFalse(db_path.exists())

    def test_controller_requires_explicit_read_gate(self):
        def responder(_host, _path, _headers, _body):
            return _response([])

        enricher, _, _, ledger = _build_offline(responder=responder)
        controller = LiveLogAlertController(enricher=enricher, ledger=ledger)
        with self.assertRaises(LiveControllerBlocked):
            controller.probe_once(
                start_time_utc=START,
                end_time_utc=END,
                query="severity=ERROR",
                enable_live_read=False,
            )
        ledger.close()

    def test_controller_never_sends_synthetic_fake_transport_output(self):
        def responder(_host, _path, _headers, _body):
            return _response([_item()])

        enricher, exchange, _, ledger = _build_offline(responder=responder)
        telegram_calls = []
        credentials = SyntheticTelegramSecretProvider().acquire()
        sender = CentralTelegramSender.for_offline_test(
            credentials=credentials,
            responder=lambda *_args: telegram_calls.append(True),
        )
        controller = LiveLogAlertController(enricher=enricher, ledger=ledger, sender=sender)
        with self.assertRaisesRegex(LiveControllerBlocked, "synthetic"):
            controller.live_alert_once(
                end_time_utc=END,
                query="severity=ERROR",
                enable_live_read=True,
                enable_telegram_delivery=True,
            )
        self.assertEqual(exchange.calls, [])
        self.assertEqual(telegram_calls, [])
        self.assertIsNone(ledger.get_cursor())
        ledger.close()


if __name__ == "__main__":
    unittest.main()
