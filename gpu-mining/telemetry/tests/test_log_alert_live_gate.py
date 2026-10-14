"""Offline-only tests for the disabled Salad organization-log boundary."""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
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
    LiveQueryPolicyError,
    canonical_utc,
)
from log_alerts.central_telegram import (  # noqa: E402
    CentralTelegramSender,
    SyntheticTelegramSecretProvider,
)
from log_alerts.engine import LogAlertEnricher  # noqa: E402
from log_alerts.ledger import SQLiteAlertLedger  # noqa: E402
from log_alerts.live_adapter import (  # noqa: E402
    QUERY_FAILURE_CODES,
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
    _validate_salad_query_window,
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


def _window_responder(items, captured):
    """Synthetic provider honoring the actual encoded interval and page cap."""
    def moment(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    ordered = sorted(items, key=lambda item: moment(item["time"]))

    def responder(_host, _path, _headers, body):
        payload = json.loads(body)
        captured.append(payload)
        start, end = moment(payload["start_time"]), moment(payload["end_time"])
        selected = [item for item in ordered if start <= moment(item["time"]) <= end]
        return _response(selected[:payload["page_size"]])

    return responder


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
    def test_encoded_query_body_truncates_datetime_bounds_only(self):
        captured = []
        query = '(resource.type = "container" or resource.type = "instance_controller")'

        def responder(_host, _path, _headers, body):
            captured.append(json.loads(body))
            return _response([])

        policy = LiveLogQueryPolicy(ORG)
        exchange = OfflineSaladExchange(responder)
        transport = LiveSaladReadTransport.for_offline_test(policy=policy, exchange=exchange)
        request = policy.build_request(
            start_time_utc=datetime(2026, 10, 14, 11, 24, 34, 123456, tzinfo=timezone.utc),
            end_time_utc=datetime(2026, 10, 14, 11, 24, 34, 999999, tzinfo=timezone.utc),
            query=query, page_size=37,
        )
        original = asdict(request)
        with patch("log_alerts.live_transport.http.client.HTTPSConnection", side_effect=AssertionError("network forbidden")):
            transport.fetch_query(request)
        self.assertEqual(captured, [{
            "start_time": "2026-10-14T11:24:34.123Z",
            "end_time": "2026-10-14T11:24:34.999Z",
            "query": query, "page_size": 37, "sort_order": "asc",
        }])
        _validate_salad_query_window(captured[0]["start_time"], captured[0]["end_time"])
        self.assertEqual(asdict(request), original)
        self.assertEqual(request.start_time_utc, "2026-10-14T11:24:34.123456Z")
        self.assertEqual(request.end_time_utc, "2026-10-14T11:24:34.999999Z")
        self.assertIs(policy.validate(request), request)
        self.assertEqual(len(exchange.calls), 1)

    def test_encoded_query_body_accepts_seconds_and_normalizes_non_utc(self):
        cases = (
            (START, END, "2026-10-13T12:00:00.000Z", "2026-10-13T12:01:00.000Z"),
            ("2026-10-14T05:24:34.123456-06:00", "2026-10-14T13:24:35.999999+02:00",
             "2026-10-14T11:24:34.123Z", "2026-10-14T11:24:35.999Z"),
        )
        for start, end, expected_start, expected_end in cases:
            with self.subTest(start=start):
                captured = []

                def responder(_host, _path, _headers, body):
                    captured.append(json.loads(body))
                    return _response([])

                policy = LiveLogQueryPolicy(ORG)
                transport = LiveSaladReadTransport.for_offline_test(
                    policy=policy, exchange=OfflineSaladExchange(responder),
                )
                request = policy.build_request(start_time_utc=start, end_time_utc=end, query="severity=ERROR")
                transport.fetch_query(request)
                payload = captured[0]
                self.assertEqual((payload["start_time"], payload["end_time"]), (expected_start, expected_end))
                for name in ("start_time", "end_time"):
                    self.assertRegex(payload[name], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
                _validate_salad_query_window(payload["start_time"], payload["end_time"])
                self.assertEqual(request.start_time_utc, canonical_utc(start))
                self.assertEqual(request.end_time_utc, canonical_utc(end))

    def test_serialized_window_validator_rejects_submillisecond_values(self):
        _validate_salad_query_window("2026-10-14T11:24:34.123Z", "2026-10-14T11:24:34.999Z")
        with self.assertRaisesRegex(LiveQueryPolicyError, "UTC milliseconds"):
            _validate_salad_query_window("2026-10-14T11:24:34.123456Z", "2026-10-14T11:24:34.999Z")

    def test_truncation_collapsed_window_fails_before_exchange(self):
        policy = LiveLogQueryPolicy(ORG)
        exchange = OfflineSaladExchange(lambda *_args: self.fail("collapsed window must never be sent"))
        transport = LiveSaladReadTransport.for_offline_test(policy=policy, exchange=exchange)
        request = policy.build_request(
            start_time_utc="2026-10-14T11:24:34.123001Z",
            end_time_utc="2026-10-14T11:24:34.123999Z", query="severity=ERROR",
        )
        with (
            patch("log_alerts.live_transport.http.client.HTTPSConnection", side_effect=AssertionError("network forbidden")),
            patch("log_alerts.live_transport.secret_boundary_types", side_effect=AssertionError("credential access forbidden")),
            self.assertRaisesRegex(LiveQueryPolicyError, "positive at millisecond precision"),
        ):
            transport.fetch_query(request)
        self.assertEqual(exchange.calls, [])

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
    def test_nonempty_provider_shapes_are_processed_without_requiring_an_alert(self):
        variants = (
            ("container", "Device [1] hashRate: 150.0 TH/s", None),
            ("container", "", None),
            ("container", None, {"message": "ordinary structured message", "count": 1}),
            ("container", None, '{"message":"ordinary structured message"}'),
            ("container", None, "ordinary bounded structured string"),
            ("instance_controller", None, {"message": "Instance Running"}),
        )
        for index, (resource_type, text, structured) in enumerate(variants):
            with self.subTest(shape=index):
                item = _item(text=text)
                item["resource"]["type"] = resource_type
                item["json_log"] = structured
                item["unknown_provider_field"] = "discarded-synthetic-value"
                enricher, exchange, _, ledger = _build_offline(responder=lambda *_args: _response([item]))
                try:
                    result = enricher.run_once(end_time_utc=END, query='(resource.type = "container" or resource.type = "instance_controller")')
                    self.assertEqual(result.records_seen, 1)
                    self.assertEqual(result.prepared_count, 0)
                    self.assertEqual(result.data_classification, DATA_CLASSIFICATION)
                    self.assertEqual(ledger.get_cursor(), canonical_utc(END))
                    self.assertEqual(len(exchange.calls), 1)
                finally:
                    ledger.close()

    def test_exactly_100_nonempty_records_split_with_raw_counts_and_boundary_dedup(self):
        base = datetime.fromisoformat(START.replace("Z", "+00:00"))
        items = []
        for seconds in range(100):
            item = _item(canonical_utc(base + timedelta(seconds=seconds)), text="Device [1] hashRate: 150.0 TH/s")
            item["resource"]["type"] = "container"
            items.append(item)
        captured = []
        enricher, _, _, ledger = _build_offline(
            responder=_window_responder(items, captured),
            limits=LiveQueryLimits(maximum_window_seconds=120, overlap_seconds=0),
        )
        try:
            end = "2026-10-13T12:02:00Z"
            query = '(resource.type = "container" or resource.type = "instance_controller")'
            first = enricher.run_once(end_time_utc=end, query=query)
            self.assertEqual(first.records_seen, 100)
            self.assertEqual(first.prepared_count, 0)
            self.assertEqual(len(captured), 3)
            self.assertEqual(ledger.get_cursor(), canonical_utc(end))
            self.assertTrue(all(body["query"] == query and body["page_size"] == 100 and body["sort_order"] == "asc" for body in captured))
            second = enricher.run_once(end_time_utc="2026-10-13T12:02:01Z", query=query)
            self.assertEqual(second.prepared_count, 0)
            self.assertEqual(ledger.alert_count(), 0)
        finally:
            ledger.close()

    def test_fixed_rejection_codes_reproduce_nonempty_failures_without_cursor_advance(self):
        ordinary = _item(text="ordinary bounded miner output")
        missing_bounds = json.loads(_response([ordinary]).body)
        missing_bounds.pop("page_min_time")
        invalid_bounds = dict(missing_bounds, page_min_time="synthetic-invalid-time")
        outside_bounds = dict(missing_bounds, page_min_time="2026-10-13T11:00:00Z")
        mismatched_bounds = dict(missing_bounds, page_min_time=START)
        malformed_resource = _item(text="ordinary bounded miner output")
        malformed_resource["resource"]["labels"] = []
        normalization_failure = _item(text="ordinary output\nsecond line")
        oversized_structured = _item(text=None)
        oversized_structured["json_log"] = "s" * 32_001
        wrong_org = _item(labels=_labels(organization_name="synthetic-other-org"), text="ordinary output")
        cases = (
            ("RESPONSE_JSON_INVALID", SaladTransportResponse(200, b"not-json")),
            ("RESPONSE_SHAPE_INVALID", SaladTransportResponse(200, b'{"items":{}}')),
            ("PAGE_BOUNDS_MISSING", SaladTransportResponse(200, json.dumps(missing_bounds).encode())),
            ("PAGE_BOUNDS_INVALID", SaladTransportResponse(200, json.dumps(invalid_bounds).encode())),
            ("PAGE_BOUNDS_OUTSIDE_WINDOW", SaladTransportResponse(200, json.dumps(outside_bounds).encode())),
            ("PAGE_BOUNDS_ITEM_MISMATCH", SaladTransportResponse(200, json.dumps(mismatched_bounds).encode())),
            ("RESOURCE_SHAPE_INVALID", _response([malformed_resource])),
            ("ENTRY_NORMALIZATION_REJECTED", _response([normalization_failure])),
            ("STRUCTURED_LOG_LIMIT", _response([oversized_structured])),
            ("ORGANIZATION_SCOPE_INVALID", _response([wrong_org])),
        )
        for code, response in cases:
            with self.subTest(code=code):
                enricher, exchange, _, ledger = _build_offline(responder=lambda *_args: response)
                try:
                    with self.assertRaises(LiveAdapterError) as caught:
                        enricher.run_once(end_time_utc=END, query="severity=ERROR")
                    self.assertEqual(caught.exception.failure_code, code)
                    self.assertIn(caught.exception.failure_code, QUERY_FAILURE_CODES)
                    self.assertIsNone(ledger.get_cursor())
                    self.assertEqual(ledger.alert_count(), 0)
                    self.assertEqual(len(exchange.calls), 1)
                    # Provider values and the underlying normalization exception
                    # are never copied into the local diagnostic exception.
                    rendered = str(caught.exception)
                    for value in ("machine-sensitive-test", "instance-sensitive-test", "sensitive-label-value", "second line"):
                        self.assertNotIn(value, rendered)
                finally:
                    ledger.close()

    def test_saturated_malformed_page_still_rejects_before_subdivision(self):
        items = [_item(text="ordinary output") for _ in range(100)]
        items[0]["resource"]["labels"] = []
        enricher, exchange, _, ledger = _build_offline(responder=lambda *_args: _response(items))
        try:
            with self.assertRaises(LiveAdapterError) as caught:
                enricher.run_once(end_time_utc=END, query="severity=ERROR")
            self.assertEqual(caught.exception.failure_code, "RESOURCE_SHAPE_INVALID")
            self.assertEqual(len(exchange.calls), 1)
            self.assertIsNone(ledger.get_cursor())
        finally:
            ledger.close()

    def test_hard_limits_have_precise_codes_and_leave_cursor_uncommitted(self):
        saturated = [_item(text="ordinary output") for _ in range(100)]
        small = [_item(text="ordinary output")]
        cases = (
            ("SUBQUERY_LIMIT", LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=0, maximum_subqueries=1), saturated),
            ("SPLIT_DEPTH_LIMIT", LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=0, maximum_split_depth=1), saturated),
            ("ENTRY_LIMIT", LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=0, maximum_entries=1), small * 2),
            ("TOTAL_BYTES_LIMIT", LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=0, maximum_response_bytes=100), small),
            ("TIME_SLICE_LIMIT", LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=0, minimum_slice_seconds=60), saturated),
        )
        for code, limits, items in cases:
            with self.subTest(code=code):
                captured = []
                enricher, exchange, _, ledger = _build_offline(responder=_window_responder(items, captured), limits=limits)
                try:
                    with self.assertRaises(LiveAdapterError) as caught:
                        enricher.run_once(end_time_utc=END, query="severity=ERROR")
                    self.assertEqual(caught.exception.failure_code, code)
                    self.assertLessEqual(len(exchange.calls), limits.maximum_subqueries)
                    self.assertIsNone(ledger.get_cursor())
                finally:
                    ledger.close()

    def test_default_64_query_5000_item_and_5mb_caps_remain_enforced(self):
        cases = (
            ("SUBQUERY_LIMIT", 1, 1_000, 0),
            ("ENTRY_LIMIT", 99, 3_000, 0),
            ("TOTAL_BYTES_LIMIT", 1, 1_000, 900_000),
        )
        for code, leaf_count, leaf_seconds, padding_bytes in cases:
            with self.subTest(code=code):
                def responder(_host, _path, _headers, body):
                    query = json.loads(body)
                    start = datetime.fromisoformat(query["start_time"].replace("Z", "+00:00"))
                    end = datetime.fromisoformat(query["end_time"].replace("Z", "+00:00"))
                    count = 100 if (end - start).total_seconds() > leaf_seconds else leaf_count
                    instant = canonical_utc(start + (end - start) / 2)
                    response = _response([_item(instant, text=f"ordinary synthetic output {index}") for index in range(count)])
                    if padding_bytes:
                        payload = json.loads(response.body)
                        payload["unknown_provider_padding"] = "x" * padding_bytes
                        response = SaladTransportResponse(200, json.dumps(payload).encode())
                    return response

                limits = LiveQueryLimits(maximum_window_seconds=86_400, overlap_seconds=0)
                enricher, exchange, _, ledger = _build_offline(responder=responder, limits=limits)
                try:
                    with self.assertRaises(LiveAdapterError) as caught:
                        enricher.run_once(end_time_utc="2026-10-14T12:00:00Z", query="severity=ERROR")
                    self.assertEqual(caught.exception.failure_code, code)
                    self.assertLessEqual(len(exchange.calls), 64)
                    self.assertIsNone(ledger.get_cursor())
                    self.assertEqual(ledger.alert_count(), 0)
                finally:
                    ledger.close()

    def test_hard_caps_cannot_be_increased_to_hide_an_incomplete_page(self):
        for overrides in (
            {"maximum_subqueries": 65}, {"maximum_entries": 5_001},
            {"maximum_response_bytes": 5_000_001}, {"maximum_split_depth": 17},
            {"page_size": 101},
        ):
            with self.subTest(parameter=next(iter(overrides))):
                with self.assertRaises(ValueError):
                    LiveQueryLimits(**overrides)

    def test_both_adapter_routes_cover_fractional_bounds_and_filter_wire_margins(self):
        start = "2026-10-13T12:00:00.123456Z"
        end = "2026-10-13T12:00:00.999999Z"
        times = (
            "2026-10-13T12:00:00.123200Z", start,
            "2026-10-13T12:00:00.999500Z", "2026-10-13T12:00:01.000000Z",
        )
        query = '(resource.type = "container" or resource.type = "instance_controller")'
        for method in ("fetch_complete_window", "probe_single_request"):
            with self.subTest(method=method):
                captured = []
                enricher, exchange, _, ledger = _build_offline(
                    responder=_window_responder([_item(event_time=t) for t in times], captured),
                )
                self.addCleanup(ledger.close)
                result = getattr(enricher.live_adapter, method)(
                    start_time_utc=start, end_time_utc=end, query=query,
                )
                self.assertEqual(captured[0]["start_time"], "2026-10-13T12:00:00.123Z")
                self.assertEqual(captured[0]["end_time"], "2026-10-13T12:00:01.000Z")
                self.assertEqual(captured[0]["query"], query)
                self.assertEqual(captured[0]["page_size"], 100)
                self.assertEqual(captured[0]["sort_order"], "asc")
                self.assertEqual(result.query_start_utc, start)
                self.assertEqual(result.query_end_utc, end)
                self.assertEqual([item.event_time_utc for item in result.entries], list(times[1:3]))
                self.assertEqual(result.response_items_seen, 4)
                self.assertEqual(result.window_completeness, "COMPLETE")
                self.assertEqual(len(exchange.calls), 1)

    def test_wire_margin_does_not_weaken_provider_identity_or_time_validation(self):
        start = "2026-10-13T12:00:00.123456Z"
        end = "2026-10-13T12:00:00.999999Z"
        cases = (
            (_item(event_time="2026-10-13T12:00:00.123200Z", labels=_labels(organization_name="other-org")), "organization label"),
            (_item(event_time="2026-10-13T12:00:01.001000Z"), "outside"),
        )
        for method in ("fetch_complete_window", "probe_single_request"):
            for item, reason in cases:
                with self.subTest(method=method, reason=reason):
                    enricher, _, _, ledger = _build_offline(responder=lambda *_args, item=item: _response([item]))
                    self.addCleanup(ledger.close)
                    with self.assertRaisesRegex(LiveAdapterError, reason):
                        getattr(enricher.live_adapter, method)(start_time_utc=start, end_time_utc=end, query="severity=ERROR")
                    self.assertIsNone(ledger.get_cursor())

    def test_fractional_coverage_survives_restart_with_zero_and_positive_overlap(self):
        first_end = "2026-10-13T12:01:00.999999Z"
        second_end = "2026-10-13T12:01:30.987654Z"
        times = (
            "2026-10-13T12:00:00.999200Z",
            "2026-10-13T12:01:00.999500Z",
            "2026-10-13T12:01:01.000000Z",
        )
        items = [_item(event_time=t, labels=_labels(machine_id=f"boundary-machine-{i}", instance_id=f"boundary-instance-{i}"))
                 for i, t in enumerate(times)]
        for overlap in (0, 10):
            with self.subTest(overlap=overlap), tempfile.TemporaryDirectory() as directory:
                captured = []
                responder = _window_responder(items, captured)
                limits = LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=overlap)
                db_path = Path(directory) / "boundaries.sqlite3"
                ledger = SQLiteAlertLedger(db_path)
                try:
                    enricher, _, _, _ = _build_offline(responder=responder, limits=limits, ledger=ledger)
                    first = enricher.run_once(end_time_utc=first_end, query="severity=ERROR")
                    self.assertEqual(first.prepared_count, 1)
                    self.assertEqual([item.event_time_utc for item in first.evidence], [times[1]])
                    self.assertEqual(ledger.get_cursor(), first_end)
                finally:
                    ledger.close()
                ledger = SQLiteAlertLedger(db_path)
                try:
                    self.assertEqual(ledger.get_cursor(), first_end)
                    enricher, _, _, _ = _build_offline(responder=responder, limits=limits, ledger=ledger)
                    second = enricher.run_once(end_time_utc=second_end, query="severity=ERROR")
                    self.assertEqual(second.prepared_count, 1)
                    self.assertEqual(second.duplicate_count, 1 if overlap else 0)
                    self.assertEqual(ledger.alert_count(), 2)
                    self.assertEqual(ledger.get_cursor(), second_end)
                    self.assertIn(times[2], [item.event_time_utc for item in second.evidence])
                finally:
                    ledger.close()
                for payload in captured:
                    duration = datetime.fromisoformat(payload["end_time"].replace("Z", "+00:00")) - datetime.fromisoformat(payload["start_time"].replace("Z", "+00:00"))
                    self.assertLessEqual(duration.total_seconds(), 60)

    def test_outward_maximum_window_is_partitioned_and_single_probe_is_blocked(self):
        start = "2026-10-13T12:00:00.123456Z"
        end = "2026-10-13T12:01:00.123456Z"
        captured = []
        limits = LiveQueryLimits(page_size=37, maximum_window_seconds=60, overlap_seconds=0)
        enricher, _, _, ledger = _build_offline(responder=_window_responder([], captured), limits=limits)
        self.addCleanup(ledger.close)
        result = enricher.live_adapter.fetch_complete_window(start_time_utc=start, end_time_utc=end, query="severity=ERROR")
        self.assertEqual(result.subqueries_seen, 2)
        self.assertEqual((result.query_start_utc, result.query_end_utc), (start, end))
        self.assertEqual([(p["start_time"], p["end_time"]) for p in captured], [
            ("2026-10-13T12:00:00.123Z", "2026-10-13T12:01:00.123Z"),
            ("2026-10-13T12:01:00.123Z", "2026-10-13T12:01:00.124Z"),
        ])
        self.assertTrue(all(p["page_size"] == 37 and p["sort_order"] == "asc" for p in captured))
        probe, exchange, provider, probe_ledger = _build_offline(responder=lambda *_args: self.fail("oversized probe must not POST"), limits=limits)
        self.addCleanup(probe_ledger.close)
        with (
            patch.object(provider, "acquire", side_effect=AssertionError("probe must reject before secret access")),
            self.assertRaisesRegex(LiveAdapterError, "probe wire window exceeds"),
        ):
            probe.live_adapter.probe_single_request(start_time_utc=start, end_time_utc=end, query="severity=ERROR")
        self.assertEqual(exchange.calls, [])
        self.assertEqual(provider.read_count, 0)

    def test_rounded_window_subquery_cap_does_not_advance_cursor(self):
        enricher, exchange, _, ledger = _build_offline(
            responder=lambda *_args: _response([]),
            limits=LiveQueryLimits(maximum_subqueries=1, maximum_window_seconds=60, overlap_seconds=0),
        )
        self.addCleanup(ledger.close)
        with self.assertRaisesRegex(LiveAdapterError, "subquery count"):
            enricher.run_once(end_time_utc="2026-10-13T12:01:00.123456Z", query="severity=ERROR")
        self.assertEqual(len(exchange.calls), 1)
        self.assertIsNone(ledger.get_cursor())
        self.assertEqual(ledger.alert_count(), 0)

    def test_raw_margin_saturation_is_not_hidden_by_logical_filtering(self):
        captured = []
        items = [_item(event_time=f"2026-10-13T12:00:00.{suffix}Z") for suffix in ("123100", "123200")]
        enricher, _, _, ledger = _build_offline(
            responder=_window_responder(items, captured),
            limits=LiveQueryLimits(page_size=2, maximum_window_seconds=60, overlap_seconds=0),
        )
        self.addCleanup(ledger.close)
        arguments = dict(start_time_utc="2026-10-13T12:00:00.123456Z", end_time_utc="2026-10-13T12:00:00.999999Z", query="severity=ERROR")
        probe = enricher.live_adapter.probe_single_request(**arguments)
        self.assertEqual(probe.entries, ())
        self.assertEqual(probe.response_items_seen, 2)
        self.assertEqual(probe.window_completeness, "UNKNOWN_SATURATED")
        with self.assertRaisesRegex(LiveAdapterError, "minimum time slice remains saturated"):
            enricher.live_adapter.fetch_complete_window(**arguments)
        self.assertIsNone(ledger.get_cursor())

    def test_saturated_fractional_slices_preserve_end_events_and_boundary_dedup(self):
        times = (
            "2026-10-13T12:00:00.123200Z", "2026-10-13T12:00:00.123500Z",
            "2026-10-13T12:00:02.000000Z", "2026-10-13T12:00:04.999500Z",
            "2026-10-13T12:00:05.000000Z",
        )
        captured = []
        enricher, _, _, ledger = _build_offline(
            responder=_window_responder([_item(event_time=t) for t in times], captured),
            limits=LiveQueryLimits(page_size=3, maximum_window_seconds=60, overlap_seconds=0),
        )
        self.addCleanup(ledger.close)
        result = enricher.live_adapter.fetch_complete_window(
            start_time_utc="2026-10-13T12:00:00.123456Z", end_time_utc="2026-10-13T12:00:04.999999Z", query="severity=ERROR",
        )
        self.assertEqual([item.event_time_utc for item in result.entries], list(times[1:4]))
        self.assertEqual(result.window_completeness, "COMPLETE")
        self.assertEqual(result.subqueries_seen, 7)
        self.assertEqual(result.response_items_seen, 15)
        for payload in captured:
            for field in ("start_time", "end_time"):
                self.assertRegex(payload[field], r"\.\d{3}Z$")

    def test_millisecond_post_preserves_durable_microsecond_cursor_after_restart(self):
        captured = []
        event_time = "2026-10-13T12:00:59.654321Z"
        first_end = "2026-10-13T12:01:00.123456Z"
        second_end = "2026-10-13T12:01:30.987654Z"

        def responder(_host, _path, _headers, body):
            payload = json.loads(body)
            captured.append(payload)
            start = datetime.fromisoformat(payload["start_time"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(payload["end_time"].replace("Z", "+00:00"))
            event = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            return _response([_item(event_time=event_time)] if start <= event <= end else [])

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cursor.sqlite3"
            limits = LiveQueryLimits(maximum_window_seconds=60, overlap_seconds=10)
            ledger = SQLiteAlertLedger(db_path)
            enricher, _, _, _ = _build_offline(responder=responder, limits=limits, ledger=ledger)
            first = enricher.run_once(end_time_utc=first_end, query="severity=ERROR")
            self.assertEqual(first.prepared_count, 1)
            self.assertEqual(first.evidence[0].event_time_utc, event_time)
            self.assertEqual(ledger.get_cursor(), first_end)
            ledger.close()

            ledger = SQLiteAlertLedger(db_path)
            try:
                self.assertEqual(ledger.get_cursor(), first_end)
                enricher, _, _, _ = _build_offline(responder=responder, limits=limits, ledger=ledger)
                second = enricher.run_once(end_time_utc=second_end, query="severity=ERROR")
                self.assertEqual(second.prepared_count, 0)
                self.assertEqual(second.duplicate_count, 1)
                self.assertEqual(ledger.alert_count(), 1)
                self.assertEqual(ledger.get_cursor(), second_end)
                self.assertEqual(second.query_start_utc, "2026-10-13T12:00:50.123456Z")
                self.assertEqual(second.evidence[0].event_time_utc, event_time)
            finally:
                ledger.close()
        self.assertEqual(captured[0]["end_time"], "2026-10-13T12:01:00.123Z")
        self.assertEqual(captured[1]["end_time"], "2026-10-13T12:01:00.124Z")
        self.assertEqual(captured[2]["start_time"], "2026-10-13T12:00:50.123Z")
        self.assertEqual(captured[2]["end_time"], "2026-10-13T12:01:30.988Z")

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
