"""Offline-only regressions for the bounded Salad log-query contract probe."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import http.client
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from log_query_probe import (  # noqa: E402
    MAX_EXPERIMENT_REQUESTS,
    OfflineSyntheticTransport,
    ProbeError,
    ProbeHttpResponse,
    ProbeRequest,
    ProbeRunner,
    make_synthetic_saturated_responder,
    parse_rfc3339,
)
from log_query_probe.core import (  # noqa: E402
    MAX_PRODUCTION_RECURSION_TRACE_DEPTH,
    MAX_PRODUCTION_RECURSION_TRACE_ITEMS,
    MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
    MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
    MAX_PAGE_MIN_BEFORE_CAPTURE_ATTEMPTS,
    MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS,
    PAGE_MIN_BEFORE_CAPTURE_CADENCE_SECONDS,
    PAGE_MIN_BEFORE_CAPTURE_WINDOW_SECONDS,
    MAX_SATURATED_TRACE_DEPTH,
    MAX_SATURATED_TRACE_REQUESTS,
    MAX_PROVIDER_ERROR_BODY_BYTES,
    MAX_RESPONSE_BYTES,
    LiveManualTransport,
    _format_utc_ns,
    _production_split_midpoint,
    _wire_request,
    authorize_live_probe,
)
from log_query_probe import cli  # noqa: E402


ORG = "synthetic-org"
QUERY = '(resource.type = "container" or resource.type = "instance_controller")'
START = "2026-10-14T20:00:00Z"
END = "2026-10-14T20:30:00Z"
PRIVATE_LOG = "SYNTHETIC_PRIVATE_LOG_MARKER"
PRIVATE_JSON = "SYNTHETIC_PRIVATE_JSON_MARKER"
PRIVATE_MACHINE = "SYNTHETIC_PRIVATE_MACHINE_ID"
PRIVATE_INSTANCE = "SYNTHETIC_PRIVATE_INSTANCE_ID"
PRIVATE_QUERY = "SYNTHETIC_PRIVATE_QUERY_MARKER"
PRIVATE_SECRET = "SYNTHETIC_ONLY_NOT_A_CREDENTIAL"


class _SyntheticTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def _request(**changes) -> ProbeRequest:
    values = {
        "organization_name": ORG,
        "start_time": START,
        "end_time": END,
        "query": QUERY,
        "page_size": 100,
        "sort_order": "asc",
    }
    values.update(changes)
    return ProbeRequest.from_values(**values)


def _response(
    request,
    *,
    times: list[str] | None = None,
    page_min: str | None = None,
    page_max: str | None = None,
    include_bounds: bool = True,
    extra_top: dict | None = None,
    item_overrides: list[dict] | None = None,
    status: int = 200,
    raw_body: bytes | None = None,
) -> ProbeHttpResponse:
    if raw_body is not None:
        return ProbeHttpResponse(status, raw_body)
    payload = json.loads(request.body.decode("utf-8"))
    if times is None:
        span = request.wire_end.epoch_ns - request.wire_start.epoch_ns
        times = [
            _format_utc_ns(request.wire_start.epoch_ns + span // 2),
        ]
    items = []
    for timestamp in times:
        items.append({"time": timestamp, "receive_time": timestamp})
    if item_overrides:
        items = item_overrides
    body = {"items": items}
    if include_bounds:
        body["page_min_time"] = page_min or (times[0] if times else None)
        body["page_max_time"] = page_max or (times[-1] if times else None)
    if extra_top:
        body.update(extra_top)
    return ProbeHttpResponse(
        status, json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
    )


def _bound_responder(*, count_for_role=None, decorate=None):
    def respond(request):
        count = (
            count_for_role(request)
            if count_for_role is not None else min(1, request.page_size)
        )
        span = request.wire_end.epoch_ns - request.wire_start.epoch_ns
        times = [
            _format_utc_ns(
                request.wire_start.epoch_ns + span * (index + 1) // (count + 1)
            )
            for index in range(count)
        ]
        options = decorate(request, times) if decorate is not None else {}
        if "times" in options:
            times = options.pop("times")
        return _response(request, times=times, **options)
    return respond


class ProbeTimestampTests(unittest.TestCase):
    def test_fractional_wire_start_is_truncated_to_milliseconds_and_end_is_ceiled(self):
        request = _request(
            start_time="2026-10-14T20:00:00.123456Z",
            end_time="2026-10-14T20:00:02.999999Z",
        )
        captured = []

        def respond(wire):
            captured.append(json.loads(wire.body.decode("utf-8")))
            return _response(wire)

        report = ProbeRunner(OfflineSyntheticTransport(respond)).run_single(request)
        self.assertEqual(captured[0]["start_time"], "2026-10-14T20:00:00.123Z")
        self.assertEqual(captured[0]["end_time"], "2026-10-14T20:00:03.000Z")
        self.assertEqual(report["requests"][0]["wire_window_utc"]["start"], "2026-10-14T20:00:00.123Z")

    def test_nine_digits_at_start_are_truncated_without_float_rounding(self):
        request = _request(
            start_time="2026-10-14T20:00:00.999999999Z",
            end_time="2026-10-14T20:00:02Z",
        )
        captured = []
        transport = OfflineSyntheticTransport(
            lambda wire: (
                captured.append(json.loads(wire.body.decode("utf-8")))
                or _response(wire)
            )
        )
        ProbeRunner(transport).run_single(request)
        self.assertEqual(captured[0]["start_time"], "2026-10-14T20:00:00.999Z")

    def test_seconds_only_inputs_remain_valid_and_emit_canonical_milliseconds(self):
        request = _request()
        captured = []
        transport = OfflineSyntheticTransport(
            lambda wire: (
                captured.append(json.loads(wire.body.decode("utf-8")))
                or _response(wire)
            )
        )
        ProbeRunner(transport).run_single(request)
        self.assertEqual(captured[0]["start_time"], START.replace("Z", ".000Z"))
        self.assertEqual(captured[0]["end_time"], END.replace("Z", ".000Z"))

    def test_non_utc_inputs_normalize_to_utc(self):
        request = _request(
            start_time="2026-10-14T22:00:00.123456+02:00",
            end_time="2026-10-14T22:01:00.123456+02:00",
        )
        captured = []
        transport = OfflineSyntheticTransport(
            lambda wire: (
                captured.append(json.loads(wire.body.decode("utf-8")))
                or _response(wire)
            )
        )
        report = ProbeRunner(transport).run_single(request)
        self.assertEqual(captured[0]["start_time"], "2026-10-14T20:00:00.123Z")
        self.assertEqual(captured[0]["end_time"], "2026-10-14T20:01:00.124Z")
        self.assertEqual(report["requests"][0]["logical_window_utc"]["start"], "2026-10-14T20:00:00.123456Z")

    def test_millisecond_and_timezone_classes_preserve_precision_bands(self):
        cases = [
            ("2026-10-14T20:00:00Z", "SECONDS", "Z"),
            ("2026-10-14T20:00:00.123Z", "MILLISECOND", "Z"),
            ("2026-10-14T20:00:00.123456+00:00", "MICROSECOND", "UTC_OFFSET"),
            ("2026-10-14T22:00:00.1234567+02:00", "SUBMICROSECOND", "NONUTC_OFFSET"),
            ("2026-10-14T20:00:00.123456789Z", "SUBMICROSECOND", "Z"),
        ]
        for value, precision, zone in cases:
            with self.subTest(value=value):
                parsed = parse_rfc3339(value)
                self.assertEqual(parsed.precision_class, precision)
                self.assertEqual(parsed.timezone_class, zone)

    def test_millisecond_wire_serialization_round_trips_under_utc_policy(self):
        request = _request(
            start_time="2026-10-14T20:00:00.123456Z",
            end_time="2026-10-14T20:00:01.654321Z",
        )
        wire = _wire_request(
            request, role="SINGLE_REQUEST", start=request.start_time,
            end=request.end_time, page_size=100,
        )
        payload = json.loads(wire.body.decode("utf-8"))
        for name in ("start_time", "end_time"):
            value = payload[name]
            self.assertTrue(value.endswith("Z"))
            fraction = value.split(".", 1)[1][:-1]
            self.assertEqual(len(fraction), 3)
            self.assertEqual(parse_rfc3339(value).precision_class, "MILLISECOND")

    def test_submillisecond_window_is_covered_by_distinct_wire_milliseconds(self):
        request = _request(
            start_time="2026-10-14T20:00:00.123100Z",
            end_time="2026-10-14T20:00:00.123900Z",
        )
        captured = []
        transport = OfflineSyntheticTransport(
            lambda wire: (
                captured.append(json.loads(wire.body.decode("utf-8")))
                or _response(wire)
            )
        )
        ProbeRunner(transport).run_single(request)
        self.assertEqual(captured[0]["start_time"], "2026-10-14T20:00:00.123Z")
        self.assertEqual(captured[0]["end_time"], "2026-10-14T20:00:00.124Z")


class ProbeRequestAndExperimentTests(unittest.TestCase):
    def test_fixed_route_body_and_page_sizes_one_through_one_hundred(self):
        for page_size in range(1, 101):
            for sort_order in ("asc", "desc"):
                with self.subTest(page_size=page_size, sort_order=sort_order):
                    request = _request(page_size=page_size, sort_order=sort_order)
                    captured = []
                    transport = OfflineSyntheticTransport(
                        lambda wire: (
                            captured.append(wire)
                            or _response(wire)
                        )
                    )
                    ProbeRunner(transport).run_single(request)
                    wire = captured[0]
                    payload = json.loads(wire.body.decode("utf-8"))
                    self.assertEqual((wire.method, wire.host, wire.port), ("POST", "api.salad.com", 443))
                    self.assertEqual(wire.path, "/api/public/organizations/synthetic-org/log-entries")
                    self.assertEqual(
                        set(payload),
                        {"start_time", "end_time", "query", "page_size", "sort_order"},
                    )
                    self.assertEqual(payload["page_size"], page_size)
                    self.assertEqual(payload["sort_order"], sort_order)
                    self.assertEqual(payload["query"], QUERY)
                    self.assertNotIn("page_token", payload)

    def test_experiment_runs_parent_control_repeat_children_and_direct_child_at_most_six(self):
        def count_for_role(wire):
            return {
                "PARENT_100": 100,
                "CONTROL_99": 99,
                "REPEAT_PARENT_100": 100,
                "LEFT_CHILD_100": 2,
                "RIGHT_CHILD_100": 2,
                "DIRECT_CHILD_100": 1,
            }[wire.role]

        transport = OfflineSyntheticTransport(_bound_responder(count_for_role=count_for_role))
        runner = ProbeRunner(transport)
        report = runner.run_experiment(
            _request(),
            repeat_parent=True,
            direct_child=("2026-10-14T20:00:00Z", "2026-10-14T20:15:00Z"),
        )
        self.assertEqual(report["request_count"], 6)
        self.assertEqual(transport.request_count, 6)
        self.assertEqual(
            transport.roles_seen,
            [
                "PARENT_100", "CONTROL_99", "REPEAT_PARENT_100",
                "LEFT_CHILD_100", "RIGHT_CHILD_100", "DIRECT_CHILD_100",
            ],
        )
        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertIn("OBSERVED_COUNT_AT_LIMIT", report["interpretations"])
        self.assertIn("PAGINATION_COMPLETENESS_UNKNOWN", report["interpretations"])
        self.assertFalse(report["count_at_limit_proves_truncation"])
        self.assertFalse(report["child_count_sum_proves_completeness"])
        with self.assertRaises(ProbeError) as caught:
            runner.run_single(_request())
        self.assertEqual(caught.exception.code, "REQUEST_BUDGET_EXCEEDED")

    def test_children_are_created_only_for_exactly_saturated_parent(self):
        def count_for_role(wire):
            return 99 if wire.role == "PARENT_100" else min(wire.page_size, 99)

        transport = OfflineSyntheticTransport(_bound_responder(count_for_role=count_for_role))
        report = ProbeRunner(transport).run_experiment(_request())
        self.assertEqual(report["request_count"], 2)
        self.assertEqual(transport.roles_seen, ["PARENT_100", "CONTROL_99"])
        self.assertIsNone(report["comparisons"]["split_children"])

    def test_experiment_children_share_whole_second_midpoint_and_report_ties(self):
        split_ns = parse_rfc3339("2026-10-14T20:15:00Z").epoch_ns

        def count_for_role(wire):
            return 100 if wire.role == "PARENT_100" else 2

        def decorate(wire, _times):
            if wire.role in {"LEFT_CHILD_100", "RIGHT_CHILD_100"}:
                boundary = _format_utc_ns(split_ns)
                return {"times": [boundary, boundary]}
            return {}

        transport = OfflineSyntheticTransport(
            _bound_responder(count_for_role=count_for_role, decorate=decorate)
        )
        report = ProbeRunner(transport).run_experiment(_request())
        split = report["comparisons"]["split_children"]
        self.assertEqual(split["left_items_at_split_boundary"], 2)
        self.assertEqual(split["right_items_at_split_boundary"], 2)
        self.assertEqual(split["shared_event_timestamps_between_children"], 1)
        self.assertFalse(split["shared_timestamp_proves_same_event"])

    def test_direct_child_must_be_validated_before_any_request(self):
        for direct_child in (
            ("2026-10-14T20:02:00Z", "2026-10-14T20:04:00Z"),
            ("2026-10-14T19:00:00Z", "2026-10-14T19:30:00Z"),
        ):
            transport = OfflineSyntheticTransport(_bound_responder())
            runner = ProbeRunner(transport)
            with self.subTest(direct_child=direct_child), self.assertRaises(ProbeError) as caught:
                runner.run_experiment(_request(), direct_child=direct_child)
            self.assertEqual(caught.exception.code, "DIRECT_CHILD_INVALID")
            self.assertEqual(transport.request_count, 0)

    def test_experiment_rejects_non_100_configured_page_size_before_request(self):
        transport = OfflineSyntheticTransport(_bound_responder())
        with self.assertRaises(ProbeError) as caught:
            ProbeRunner(transport).run_experiment(_request(page_size=99))
        self.assertEqual(caught.exception.code, "CONFIGURATION_INVALID")
        self.assertEqual(transport.request_count, 0)

    def test_exact_right_direct_child_is_allowed(self):
        transport = OfflineSyntheticTransport(_bound_responder())
        report = ProbeRunner(transport).run_experiment(
            _request(),
            direct_child=("2026-10-14T20:15:00Z", "2026-10-14T20:30:00Z"),
        )
        self.assertEqual(transport.roles_seen, ["PARENT_100", "CONTROL_99", "DIRECT_CHILD_100"])
        self.assertEqual(report["comparisons"]["direct_child"]["count"], 1)

    def test_split_midpoint_matches_production_timedelta_rounding_at_second_boundary(self):
        start_text = "2026-10-14T20:00:00.000000Z"
        end_text = "2026-10-14T20:00:01.999999Z"
        start = parse_rfc3339(start_text)
        end = parse_rfc3339(end_text)
        production_start = datetime.fromisoformat(start_text.replace("Z", "+00:00"))
        production_end = datetime.fromisoformat(end_text.replace("Z", "+00:00"))
        expected = (
            production_start + (production_end - production_start) / 2
        ).replace(microsecond=0)
        midpoint = _production_split_midpoint(start, end)
        self.assertEqual(_format_utc_ns(midpoint.epoch_ns), "2026-10-14T20:00:01Z")
        self.assertEqual(
            _format_utc_ns(midpoint.epoch_ns),
            expected.isoformat().replace("+00:00", "Z"),
        )

        request = _request(start_time=start_text, end_time=end_text)
        report = ProbeRunner(OfflineSyntheticTransport(
            _bound_responder(count_for_role=lambda wire: 100 if wire.role == "PARENT_100" else 0)
        )).run_experiment(request)
        children = report["requests"][2:4]
        self.assertEqual(children[0]["logical_window_utc"]["end"], "2026-10-14T20:00:01Z")
        self.assertEqual(children[1]["logical_window_utc"]["start"], "2026-10-14T20:00:01Z")

    def test_request_validation_bounds_window_size_page_size_and_sort(self):
        with self.assertRaises(ProbeError):
            _request(end_time="2026-10-14T21:00:01Z")
        with self.assertRaises(ProbeError):
            _request(page_size=0)
        with self.assertRaises(ProbeError):
            _request(page_size=101)
        with self.assertRaises(ProbeError):
            _request(sort_order="sideways")
        with self.assertRaises(ProbeError):
            _request(start_time="2026-10-14T20:00:00Z", end_time="2026-10-14T20:00:00Z")


class ProbeSaturatedBranchTraceTests(unittest.TestCase):
    def _run_trace(self, count_for_role, *, request=None, decorate=None):
        captured = []

        def respond(wire):
            captured.append(wire)
            count = count_for_role(wire)
            span = wire.logical_end.epoch_ns - wire.logical_start.epoch_ns
            inner = wire.logical_start.epoch_ns + max(0, span // 2)
            times = [_format_utc_ns(inner)] * count
            options = decorate(wire, times) if decorate is not None else {}
            if "times" in options:
                times = options.pop("times")
            return _response(wire, times=times, **options)

        transport = OfflineSyntheticTransport(
            respond, request_budget=MAX_SATURATED_TRACE_REQUESTS,
        )
        report = ProbeRunner(transport).run_saturated_branch_trace(request or _request())
        return report, transport, captured

    def test_recurses_from_parent_left_saturated_right_empty_to_first_partial(self):
        def count(wire):
            return {
                "TRACE_PARENT_0_100": 100,
                "TRACE_DEPTH_1_LEFT_100": 100,
                "TRACE_DEPTH_1_RIGHT_100": 0,
                "TRACE_DEPTH_2_LEFT_100": 100,
                "TRACE_DEPTH_2_RIGHT_100": 0,
                "TRACE_DEPTH_3_LEFT_100": 37,
                "TRACE_DEPTH_3_RIGHT_100": 0,
            }[wire.role]

        report, transport, captured = self._run_trace(count)
        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertEqual(report["request_count"], 7)
        self.assertEqual(report["request_budget"], 11)
        self.assertEqual(report["trace_depth"], 3)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_NO_SATURATED_CHILDREN")
        self.assertEqual(report["saturated_nodes_seen"], 3)
        self.assertEqual(report["first_nonempty_unsaturated_depth"], 3)
        self.assertEqual(len(captured), 7)
        self.assertEqual(transport.request_count, 7)
        self.assertEqual(captured[0].role, "TRACE_PARENT_0_100")

    def test_reports_logical_vs_wire_page_max_without_rejecting_items_in_window(self):
        request = _request(
            start_time="2026-10-14T20:00:00.000123Z",
            end_time="2026-10-14T20:30:00.123456Z",
        )

        def count(wire):
            return {
                "TRACE_PARENT_0_100": 100,
                "TRACE_DEPTH_1_LEFT_100": 0,
                "TRACE_DEPTH_1_RIGHT_100": 100,
                "TRACE_DEPTH_2_LEFT_100": 0,
                "TRACE_DEPTH_2_RIGHT_100": 100,
                "TRACE_DEPTH_3_LEFT_100": 0,
                "TRACE_DEPTH_3_RIGHT_100": 12,
            }[wire.role]

        def decorate(wire, _times):
            if wire.role != "TRACE_DEPTH_3_RIGHT_100":
                return {}
            inner = wire.logical_start.epoch_ns + (
                wire.logical_end.epoch_ns - wire.logical_start.epoch_ns
            ) // 2
            return {
                "times": [_format_utc_ns(inner)] * 12,
                "page_min": _format_utc_ns(wire.logical_start.epoch_ns),
                "page_max": _format_utc_ns(wire.wire_end.epoch_ns, millisecond_only=True),
            }

        report, _transport, _captured = self._run_trace(
            count, request=request, decorate=decorate,
        )
        target = next(
            item for item in report["requests"]
            if item["request_role"] == "TRACE_DEPTH_3_RIGHT_100"
        )
        self.assertEqual(target["item_count"], 12)
        self.assertEqual(target["page_max_vs_logical_end"], "AFTER")
        self.assertEqual(target["page_max_vs_wire_end"], "EQUAL")
        self.assertEqual(target["items_vs_logical_window"], "WITHIN_WINDOW")
        self.assertEqual(target["items_vs_wire_window"], "WITHIN_WINDOW")
        self.assertEqual(report["first_nonempty_unsaturated_depth"], 3)

    def test_two_saturated_children_stop_without_choosing_a_branch(self):
        report, transport, _captured = self._run_trace(lambda _wire: 100)
        self.assertEqual(report["request_count"], 3)
        self.assertEqual(report["trace_depth"], 1)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_MULTIPLE_SATURATED_CHILDREN")
        self.assertEqual(report["saturated_nodes_seen"], 3)
        self.assertEqual(transport.request_count, 3)


    def test_depth_limit_caps_trace_at_eleven_requests(self):
        report, transport, captured = self._run_trace(
            lambda wire: 0 if "RIGHT_100" in wire.role else 100,
        )
        self.assertEqual(MAX_SATURATED_TRACE_DEPTH, 5)
        self.assertEqual(report["request_count"], MAX_SATURATED_TRACE_REQUESTS)
        self.assertEqual(report["request_budget"], MAX_SATURATED_TRACE_REQUESTS)
        self.assertEqual(report["trace_depth"], MAX_SATURATED_TRACE_DEPTH)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_DEPTH_LIMIT")
        self.assertEqual(transport.request_count, MAX_SATURATED_TRACE_REQUESTS)
        self.assertEqual(len(captured), MAX_SATURATED_TRACE_REQUESTS)

    def test_parent_below_limit_stops_without_children(self):
        report, transport, _captured = self._run_trace(lambda _wire: 99)
        self.assertEqual(report["request_count"], 1)
        self.assertEqual(report["trace_depth"], 0)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_PARENT_NOT_AT_LIMIT")
        self.assertEqual(report["saturated_nodes_seen"], 0)
        self.assertIsNone(report["first_nonempty_unsaturated_depth"])
        self.assertEqual(transport.request_count, 1)

    def test_trace_output_omits_raw_logs_and_provider_labels(self):
        markers = (
            "PRIVATE_TRACE_LOG", "PRIVATE_TRACE_JSON", "PRIVATE_TRACE_MACHINE",
            "PRIVATE_TRACE_INSTANCE", "PRIVATE_TRACE_LABEL",
        )

        def respond(wire):
            span = wire.logical_end.epoch_ns - wire.logical_start.epoch_ns
            stamp = _format_utc_ns(wire.logical_start.epoch_ns + span // 2)
            body = {
                "page_min_time": stamp,
                "page_max_time": stamp,
                "items": [{
                    "time": stamp,
                    "text_log": markers[0],
                    "json_log": {markers[1]: markers[1]},
                    "resource": {"labels": {
                        "machine_id": markers[2], "instance_id": markers[3],
                        "custom": markers[4],
                    }},
                }],
            }
            return ProbeHttpResponse(200, json.dumps(body).encode("utf-8"))

        transport = OfflineSyntheticTransport(
            respond, request_budget=MAX_SATURATED_TRACE_REQUESTS,
        )
        report = ProbeRunner(transport).run_saturated_branch_trace(_request())
        rendered = json.dumps(report, sort_keys=True)
        for marker in markers:
            self.assertNotIn(marker, rendered)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_PARENT_NOT_AT_LIMIT")

    def test_cli_dispatches_trace_and_rejects_noncanonical_trace_policy(self):
        arguments = [
            "--mode", "offline-synthetic", "--operation", "saturated-branch-trace",
            "--organization", ORG, "--start-time", START, "--end-time", END,
            "--query", QUERY,
        ]
        output = io.StringIO()
        with patch("sys.stdout", output), patch(
            "socket.socket", side_effect=AssertionError("socket forbidden")
        ), patch(
            "http.client.HTTPSConnection", side_effect=AssertionError("HTTPS forbidden")
        ):
            exit_code = cli.main(arguments)
        self.assertEqual(exit_code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["request_budget"], MAX_SATURATED_TRACE_REQUESTS)
        self.assertIn("trace_stop_reason", report)
        output = io.StringIO()
        with patch("sys.stdout", output):
            exit_code = cli.main(arguments + ["--sort-order", "desc"])
        self.assertEqual(exit_code, 2)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"status": "BLOCKED", "failure_code": "CONFIGURATION_INVALID"},
        )


class ProbePageMinBeforeTests(unittest.TestCase):
    def _run_probe(self, count_for_role, *, page_min_offset_seconds=-5):
        captured = []

        def respond(wire):
            captured.append(wire)
            count = count_for_role(wire)
            start_ns = wire.logical_start.epoch_ns
            end_ns = wire.logical_end.epoch_ns
            span = end_ns - start_ns
            times = [
                _format_utc_ns(start_ns + span * (index + 1) // (count + 1))
                for index in range(count)
            ]
            min_text = _format_utc_ns(
                start_ns + page_min_offset_seconds * 1_000_000_000,
            )
            max_text = _format_utc_ns(end_ns + 2_000_000_000)
            return _response(
                wire, times=times, page_min=min_text, page_max=max_text,
                item_overrides=[{
                    "time": stamp,
                    "receive_time": stamp,
                    "text_log": "PRIVATE_PAGE_MIN_PROBE_LOG",
                    "json_log": {"private": "PRIVATE_PAGE_MIN_PROBE_JSON"},
                    "resource": {"labels": {
                        "machine_id": "PRIVATE_PAGE_MIN_PROBE_MACHINE",
                        "instance_id": "PRIVATE_PAGE_MIN_PROBE_INSTANCE",
                    }},
                } for stamp in times] if times else None,
            )

        transport = OfflineSyntheticTransport(
            respond, request_budget=MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
        )
        report = ProbeRunner(transport).run_page_min_before_probe(_request())
        return report, transport, captured

    def test_saturated_parent_observes_page_min_before_and_immediate_children_only(self):
        report, transport, captured = self._run_probe(
            lambda wire: {
                "PAGE_MIN_PROBE_PARENT_100": 100,
                "PAGE_MIN_PROBE_LEFT_100": 23,
                "PAGE_MIN_PROBE_RIGHT_100": 17,
            }[wire.role],
        )

        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertEqual(report["request_count"], 3)
        self.assertEqual(report["request_budget"], 3)
        self.assertEqual(report["trace_depth"], 1)
        self.assertEqual(
            report["trace_stop_reason"],
            "TRACE_STOPPED_ONE_LEVEL_CHILDREN_OBSERVED",
        )
        self.assertTrue(report["page_min_before_slice_signature_observed"])
        self.assertEqual(
            report["page_min_before_slice_signature_roles"],
            ["PAGE_MIN_PROBE_PARENT_100"],
        )
        self.assertEqual(
            [wire.role for wire in captured],
            [
                "PAGE_MIN_PROBE_PARENT_100",
                "PAGE_MIN_PROBE_LEFT_100",
                "PAGE_MIN_PROBE_RIGHT_100",
            ],
        )
        self.assertEqual(transport.request_count, 3)
        self.assertEqual(report["pagination_completeness"], "UNKNOWN")
        self.assertEqual(report["requests"][0]["page_min_vs_logical_start"], "BEFORE")
        self.assertEqual(report["requests"][0]["page_min_vs_wire_start"], "BEFORE")
        self.assertEqual(report["requests"][0]["items_vs_logical_window"], "WITHIN_WINDOW")
        self.assertEqual(report["requests"][0]["items_vs_wire_window"], "WITHIN_WINDOW")
        self.assertEqual(report["requests"][1]["items_vs_logical_window"], "WITHIN_WINDOW")
        self.assertEqual(report["requests"][2]["items_vs_logical_window"], "WITHIN_WINDOW")
        self.assertFalse(report["recursive_descendants_requested"])
        rendered = json.dumps(report, sort_keys=True)
        for marker in (
            "PRIVATE_PAGE_MIN_PROBE_LOG", "PRIVATE_PAGE_MIN_PROBE_JSON",
            "PRIVATE_PAGE_MIN_PROBE_MACHINE", "PRIVATE_PAGE_MIN_PROBE_INSTANCE",
        ):
            self.assertNotIn(marker, rendered)

    def test_unsaturated_parent_uses_one_request_and_does_not_claim_signature(self):
        report, transport, captured = self._run_probe(lambda _wire: 7)
        self.assertEqual(report["request_count"], 1)
        self.assertEqual(report["request_budget"], 3)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_PARENT_NOT_AT_LIMIT")
        self.assertFalse(report["page_min_before_slice_signature_observed"])
        self.assertEqual(report["page_min_before_slice_signature_roles"], [])
        self.assertEqual(len(captured), 1)
        self.assertEqual(transport.request_count, 1)
        self.assertEqual(report["requests"][0]["items_vs_wire_window"], "WITHIN_WINDOW")

    def test_empty_parent_without_page_bounds_reports_absent_not_invented_times(self):
        transport = OfflineSyntheticTransport(
            lambda wire: _response(
                wire, times=[], include_bounds=False,
            ),
            request_budget=MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
        )
        report = ProbeRunner(transport).run_page_min_before_probe(_request())
        self.assertEqual(report["request_count"], 1)
        self.assertEqual(report["requests"][0]["item_count"], 0)
        self.assertFalse(report["requests"][0]["page_bounds_present"])
        self.assertEqual(report["requests"][0]["page_min_vs_logical_start"], "ABSENT")
        self.assertEqual(report["requests"][0]["page_min_vs_wire_start"], "ABSENT")
        self.assertFalse(report["page_min_before_slice_signature_observed"])
        self.assertEqual(transport.request_count, 1)

    def test_saturated_immediate_children_are_not_recursed_and_keep_completeness_unknown(self):
        report, transport, _captured = self._run_probe(lambda _wire: 100)
        self.assertEqual(report["request_count"], 3)
        self.assertEqual(report["saturated_page_count"], 3)
        self.assertEqual(report["nonempty_unsaturated_page_count"], 0)
        self.assertEqual(report["pagination_completeness"], "UNKNOWN")
        self.assertFalse(report["count_at_limit_proves_truncation"])
        self.assertFalse(report["recursive_descendants_requested"])
        self.assertEqual(transport.request_count, 3)

    def test_malformed_and_reversed_page_bounds_remain_rejected(self):
        for page_min, page_max, expected in (
            ("not-a-timestamp", END, "PAGE_BOUNDS_INVALID"),
            (END, START, "PAGE_BOUNDS_REVERSED"),
        ):
            def respond(wire, low=page_min, high=page_max):
                stamp = _format_utc_ns(
                    wire.logical_start.epoch_ns
                    + (wire.logical_end.epoch_ns - wire.logical_start.epoch_ns) // 2,
                )
                return _response(
                    wire, times=[stamp], page_min=low, page_max=high,
                )

            runner = ProbeRunner(OfflineSyntheticTransport(
                respond, request_budget=MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
            ))
            with self.assertRaises(ProbeError) as raised:
                runner.run_page_min_before_probe(_request())
            self.assertEqual(raised.exception.code, expected)

    def test_cli_dispatches_offline_without_sockets_and_rejects_noncanonical_options(self):
        args = [
            "--mode", "offline-synthetic", "--operation", "page-min-before-probe",
            "--organization", ORG, "--start-time", START,
            "--end-time", END, "--query", QUERY,
        ]
        output = io.StringIO()
        with patch("sys.stdout", output), patch(
            "socket.socket", side_effect=AssertionError("socket forbidden"),
        ), patch(
            "http.client.HTTPSConnection", side_effect=AssertionError("HTTPS forbidden"),
        ):
            result = cli.main(args)
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertEqual(report["request_budget"], MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS)
        self.assertLessEqual(report["request_count"], 3)
        for extra in (
            ("--page-size", "99"), ("--sort-order", "desc"),
            ("--repeat-parent",), ("--direct-child-start", START,
             "--direct-child-end", END),
        ):
            bad_output = io.StringIO()
            with patch("sys.stdout", bad_output):
                bad_result = cli.main(args + list(extra))
            self.assertEqual(bad_result, 2)
            self.assertEqual(
                json.loads(bad_output.getvalue())["failure_code"],
                "CONFIGURATION_INVALID",
            )

class ProbePageMinBeforeCaptureTests(unittest.TestCase):
    class _FakeTime:
        def __init__(self):
            self.base = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
            self.elapsed = 0.0
            self.waits = []

        def utc_now(self):
            return self.base + timedelta(seconds=self.elapsed)

        def monotonic(self):
            return self.elapsed

        def wait(self, seconds):
            self.waits.append(seconds)
            self.elapsed += seconds

    def _run_capture(self, response_for_call, *, request_budget=MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS):
        fake_time = self._FakeTime()
        captured = []

        def respond(wire):
            call_number = len(captured)
            captured.append(wire)
            return response_for_call(wire, call_number, fake_time)

        transport = OfflineSyntheticTransport(
            respond, request_budget=request_budget,
        )
        runner = ProbeRunner(transport)
        with patch(
            "socket.socket", side_effect=AssertionError("network forbidden"),
        ), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("HTTPS forbidden"),
        ):
            report = runner.run_page_min_before_capture(
                _request(),
                utc_now=fake_time.utc_now,
                monotonic=fake_time.monotonic,
                wait=fake_time.wait,
            )
        return report, transport, captured, fake_time

    @staticmethod
    def _page_response(wire, count, *, page_min_before=False):
        start_ns = wire.logical_start.epoch_ns
        end_ns = wire.logical_end.epoch_ns
        span = end_ns - start_ns
        times = [
            _format_utc_ns(start_ns + span * (index + 1) // (count + 1))
            for index in range(count)
        ]
        page_min_ns = (
            start_ns - 1_000_000_000
            if page_min_before else start_ns + 1_000_000_000
        )
        page_max_ns = end_ns - 1_000_000_000
        private_items = [{
            "time": stamp,
            "receive_time": stamp,
            "text_log": PRIVATE_LOG,
            "json_log": {"detail": PRIVATE_JSON},
            "resource": {"labels": {
                "machine_id": PRIVATE_MACHINE,
                "instance_id": PRIVATE_INSTANCE,
            }},
        } for stamp in times]
        return _response(
            wire,
            times=times,
            page_min=_format_utc_ns(page_min_ns),
            page_max=_format_utc_ns(page_max_ns),
            item_overrides=private_items,
        )

    def test_signature_on_first_page_stops_before_saturated_children(self):
        report, transport, captured, _fake_time = self._run_capture(
            lambda wire, _number, _clock: self._page_response(
                wire, 100, page_min_before=True,
            ),
        )

        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertEqual(report["capture_attempts_completed"], 1)
        self.assertTrue(report["capture_signature_observed"])
        self.assertEqual(report["capture_signature_attempt"], 1)
        self.assertEqual(
            report["capture_signature_role"], "PAGE_MIN_PROBE_PARENT_100",
        )
        self.assertEqual(
            report["capture_stop_reason"], "SIGNATURE",
        )
        self.assertEqual(report["total_request_count"], 1)
        self.assertEqual(transport.request_count, 1)
        self.assertEqual([wire.role for wire in captured], ["PAGE_MIN_PROBE_PARENT_100"])
        details = report["capture_signature_details"]
        for field in (
            "item_count", "page_class", "items_vs_logical_window",
            "items_vs_wire_window", "item_min_vs_logical_start",
            "item_min_vs_wire_start", "receive_times_vs_wire_window",
        ):
            self.assertIn(field, details)
        self.assertEqual(details["page_class"], "NONEMPTY_SATURATED")
        rendered = json.dumps(report, sort_keys=True)
        for private_value in (PRIVATE_LOG, PRIVATE_JSON, PRIVATE_MACHINE, PRIVATE_INSTANCE):
            self.assertNotIn(private_value, rendered)

    def test_signature_on_later_attempt_stops_at_that_attempt(self):
        def response(wire, call_number, _clock):
            return self._page_response(
                wire, 4, page_min_before=(call_number == 1),
            )

        report, transport, captured, fake_time = self._run_capture(response)
        self.assertEqual(report["capture_attempts_completed"], 2)
        self.assertTrue(report["capture_signature_observed"])
        self.assertEqual(report["capture_signature_attempt"], 2)
        self.assertEqual(
            report["capture_signature_role"], "PAGE_MIN_PROBE_PARENT_100",
        )
        self.assertEqual(report["capture_stop_reason"], "SIGNATURE")
        self.assertEqual(report["total_request_count"], 2)
        self.assertEqual(transport.request_count, 2)
        self.assertEqual(len(fake_time.waits), 1)
        self.assertEqual(fake_time.waits[0], PAGE_MIN_BEFORE_CAPTURE_CADENCE_SECONDS)
        self.assertEqual(len(captured), 2)

    def test_saturated_child_signature_stops_before_the_other_child(self):
        def response(wire, call_number, _clock):
            return self._page_response(
                wire, 100, page_min_before=(call_number == 1),
            )

        report, transport, captured, _fake_time = self._run_capture(response)
        self.assertEqual(report["capture_signature_attempt"], 1)
        self.assertEqual(report["capture_signature_role"], "PAGE_MIN_PROBE_LEFT_100")
        self.assertEqual(report["total_request_count"], 2)
        self.assertEqual(transport.request_count, 2)
        self.assertEqual(
            [wire.role for wire in captured],
            ["PAGE_MIN_PROBE_PARENT_100", "PAGE_MIN_PROBE_LEFT_100"],
        )

    def test_no_signature_stops_after_ten_exact_rolling_windows(self):
        def response(wire, _call_number, fake_time):
            page = self._page_response(wire, 6)
            fake_time.elapsed += 2.0
            return page

        report, transport, captured, fake_time = self._run_capture(response)
        self.assertEqual(
            report["capture_attempts_completed"],
            MAX_PAGE_MIN_BEFORE_CAPTURE_ATTEMPTS,
        )
        self.assertFalse(report["capture_signature_observed"])
        self.assertIsNone(report["capture_signature_attempt"])
        self.assertIsNone(report["capture_signature_role"])
        self.assertEqual(
            report["capture_stop_reason"], "MAX_ATTEMPTS",
        )
        self.assertEqual(report["total_request_count"], 10)
        self.assertLessEqual(report["total_request_count"], MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS)
        self.assertEqual(transport.request_count, 10)
        self.assertEqual(len(fake_time.waits), 9)
        self.assertEqual(fake_time.waits, [13.0] * 9)
        logical_windows = [
            (wire.logical_start.epoch_ns, wire.logical_end.epoch_ns)
            for wire in captured
        ]
        for start_ns, end_ns in logical_windows:
            self.assertEqual(
                end_ns - start_ns,
                PAGE_MIN_BEFORE_CAPTURE_WINDOW_SECONDS * 1_000_000_000,
            )
        for previous, current in zip(logical_windows, logical_windows[1:]):
            self.assertEqual(current[1] - previous[1], 15 * 1_000_000_000)
        for attempt in report["attempts"]:
            self.assertEqual(attempt["window_seconds"], 135)
            self.assertEqual(len(attempt["pages"]), 1)

    def test_remaining_budget_too_small_does_not_start_another_attempt(self):
        report, transport, captured, fake_time = self._run_capture(
            lambda wire, _number, _clock: self._page_response(wire, 5),
            request_budget=MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
        )
        self.assertEqual(report["capture_attempts_completed"], 1)
        self.assertEqual(
            report["capture_stop_reason"], "REQUEST_BUDGET",
        )
        self.assertEqual(report["total_request_count"], 1)
        self.assertEqual(transport.request_count, 1)
        self.assertEqual(len(captured), 1)
        self.assertEqual(fake_time.waits, [])
        self.assertLessEqual(report["total_request_count"], 30)

    def test_saturated_attempts_hard_stop_at_thirty_total_requests(self):
        report, transport, captured, _fake_time = self._run_capture(
            lambda wire, _number, _clock: self._page_response(wire, 100),
        )
        self.assertEqual(report["capture_attempts_completed"], 10)
        self.assertFalse(report["capture_signature_observed"])
        self.assertEqual(report["capture_stop_reason"], "MAX_ATTEMPTS")
        self.assertEqual(report["request_budget"], MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS)
        self.assertEqual(report["total_request_count"], MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS)
        self.assertEqual(transport.request_count, MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS)
        self.assertEqual(len(captured), MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS)
        self.assertTrue(all(len(attempt["pages"]) == 3 for attempt in report["attempts"]))

    def test_cli_capture_dispatch_is_offline_and_uses_thirty_request_cap(self):
        args = [
            "--mode", "offline-synthetic", "--operation", "page-min-before-capture",
            "--organization", ORG, "--start-time", START,
            "--end-time", END, "--query", QUERY,
        ]
        output = io.StringIO()
        with patch("sys.stdout", output), patch(
            "socket.socket", side_effect=AssertionError("socket forbidden"),
        ), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("HTTPS forbidden"),
        ):
            result = cli.main(args)
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["operation"], "page-min-before-capture")
        self.assertEqual(report["request_budget"], MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS)
        self.assertEqual(report["capture_stop_reason"], "SIGNATURE")
        self.assertEqual(report["total_request_count"], 1)


class ProbeProductionRecursionTraceTests(unittest.TestCase):
    def _run_trace(self, count_for_role, *, request=None, decorate=None):
        captured = []

        def respond(wire):
            captured.append(wire)
            count = count_for_role(wire)
            span = wire.logical_end.epoch_ns - wire.logical_start.epoch_ns
            inner = wire.logical_start.epoch_ns + max(0, span // 2)
            times = [_format_utc_ns(inner)] * count
            options = decorate(wire, times) if decorate is not None else {}
            if "times" in options:
                times = options.pop("times")
            return _response(wire, times=times, **options)

        transport = OfflineSyntheticTransport(
            respond, request_budget=MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
        )
        report = ProbeRunner(transport).run_production_recursion_trace(
            request or _request(),
        )
        return report, transport, captured

    @staticmethod
    def _node(depth, number):
        return f"PRODUCTION_TRACE_D{depth}_N{number}_100"

    def test_dfs_visits_both_saturated_depth_five_children_and_continues(self):
        counts = {
            self._node(0, 1): 100,
            self._node(1, 2): 100,
            self._node(2, 4): 100,
            self._node(3, 8): 100,
            self._node(4, 16): 6,
            self._node(4, 17): 100,
            self._node(5, 34): 100,
            self._node(5, 35): 100,
        }

        report, transport, captured = self._run_trace(
            lambda wire: counts.get(wire.role, 0),
        )
        roles = [wire.role for wire in captured]
        self.assertLess(roles.index(self._node(5, 34)), roles.index(self._node(5, 35)))
        self.assertIn(self._node(6, 68), roles)
        self.assertIn(self._node(6, 70), roles)
        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_TRAVERSAL_COMPLETE")
        self.assertEqual(report["visited_node_count"], 15)
        self.assertEqual(report["saturated_node_count"], 7)
        self.assertEqual(report["nonempty_unsaturated_node_count"], 1)
        self.assertEqual(report["deepest_depth_seen"], 6)
        self.assertFalse(report["target_signature_observed"])
        self.assertEqual(transport.request_count, 15)

    def test_target_signature_stops_at_first_matching_partial_page(self):
        counts = {
            self._node(0, 1): 100,
            self._node(1, 2): 100,
            self._node(2, 4): 100,
            self._node(3, 8): 100,
            self._node(4, 16): 6,
        }

        def decorate(wire, _times):
            if wire.role != self._node(4, 16):
                return {}
            after = wire.logical_end.epoch_ns + 1
            return {"page_max": _format_utc_ns(after)}

        report, _transport, captured = self._run_trace(
            lambda wire: counts.get(wire.role, 0), decorate=decorate,
        )
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_TARGET_SIGNATURE")
        self.assertTrue(report["target_signature_observed"])
        self.assertEqual(report["target_signature_depth"], 4)
        self.assertEqual(report["target_signature_role"], self._node(4, 16))
        self.assertEqual(len(captured), 5)
        self.assertEqual(captured[-1].role, self._node(4, 16))
        self.assertEqual(report["requests"][-1]["item_count"], 6)
        self.assertEqual(report["requests"][-1]["page_max_vs_logical_end"], "AFTER")
        self.assertEqual(report["requests"][-1]["items_vs_logical_window"], "WITHIN_WINDOW")
        self.assertEqual(report["requests"][-1]["items_vs_wire_window"], "WITHIN_WINDOW")

    def test_target_accepts_page_max_after_logical_end_but_before_wire_end(self):
        request = _request(end_time="2026-10-14T20:30:00.123456Z")
        counts = {
            self._node(0, 1): 100,
            self._node(1, 3): 100,
            self._node(2, 7): 100,
            self._node(3, 15): 100,
            self._node(4, 31): 6,
        }

        def decorate(wire, _times):
            if wire.role != self._node(4, 31):
                return {}
            after_logical = wire.logical_end.epoch_ns + 1_000
            return {"page_max": _format_utc_ns(after_logical)}

        report, _transport, _captured = self._run_trace(
            lambda wire: counts.get(wire.role, 0),
            request=request,
            decorate=decorate,
        )
        observed = report["requests"][-1]
        self.assertEqual(observed["page_max_vs_logical_end"], "AFTER")
        self.assertEqual(observed["page_max_vs_wire_end"], "BEFORE")
        self.assertEqual(observed["items_vs_logical_window"], "WITHIN_WINDOW")
        self.assertEqual(observed["items_vs_wire_window"], "WITHIN_WINDOW")
        self.assertTrue(report["target_signature_observed"])
        self.assertEqual(report["target_signature_role"], self._node(4, 31))

    def test_after_page_max_does_not_match_target_when_items_are_outside(self):
        counts = {self._node(0, 1): 100, self._node(1, 2): 6}

        def decorate(wire, _times):
            if wire.role != self._node(1, 2):
                return {}
            outside = wire.wire_end.epoch_ns + 1_000_000
            stamp = _format_utc_ns(outside)
            return {"page_max": stamp, "times": [stamp] * 6}

        report, _transport, captured = self._run_trace(
            lambda wire: counts.get(wire.role, 0), decorate=decorate,
        )
        observed = report["requests"][1]
        self.assertEqual(observed["page_max_vs_wire_end"], "AFTER")
        self.assertEqual(observed["items_vs_wire_window"], "AFTER_WINDOW")
        self.assertFalse(report["target_signature_observed"])
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_TRAVERSAL_COMPLETE")
        self.assertEqual(len(captured), 3)

    def test_full_saturated_tree_obeys_23_request_cap_and_left_first_order(self):
        def saturated_through_depth_five(wire):
            depth = int(wire.role.split("_")[2][1:])
            return 100 if depth <= 5 else 0

        report, transport, captured = self._run_trace(saturated_through_depth_five)
        self.assertEqual(MAX_PRODUCTION_RECURSION_TRACE_DEPTH, 7)
        self.assertEqual(MAX_PRODUCTION_RECURSION_TRACE_REQUESTS, 23)
        self.assertEqual(MAX_PRODUCTION_RECURSION_TRACE_ITEMS, 2300)
        self.assertEqual(report["request_count"], 23)
        self.assertEqual(report["request_budget"], 23)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_REQUEST_BUDGET")
        self.assertEqual(report["visited_node_count"], 23)
        self.assertLess(report["saturated_node_count"], 23)
        self.assertEqual(report["deepest_depth_seen"], 6)
        self.assertEqual(captured[0].role, self._node(0, 1))
        self.assertEqual(captured[1].role, self._node(1, 2))
        self.assertEqual(captured[2].role, self._node(2, 4))
        self.assertNotIn(self._node(1, 3), [wire.role for wire in captured])
        self.assertEqual(transport.request_count, 23)
        self.assertEqual(ProbeRunner(OfflineSyntheticTransport(
            lambda wire: _response(wire),
            request_budget=MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
        ))._request_budget, 23)

    def test_depth_limit_stops_globally_before_pending_sibling_requests(self):
        def count(wire):
            depth_number = wire.role.removeprefix("PRODUCTION_TRACE_D")
            depth_text, node_text = depth_number.removesuffix("_100").split("_N")
            depth, number = int(depth_text), int(node_text)
            return 100 if number == 1 << depth else 0

        report, _transport, captured = self._run_trace(count)
        roles = [wire.role for wire in captured]
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_DEPTH_LIMIT")
        self.assertEqual(report["deepest_depth_seen"], MAX_PRODUCTION_RECURSION_TRACE_DEPTH)
        self.assertIn(self._node(7, 128), roles)
        self.assertEqual(roles[-1], self._node(7, 128))
        self.assertNotIn(self._node(7, 129), roles)
        self.assertNotIn(self._node(6, 65), roles)
        self.assertLess(len(captured), MAX_PRODUCTION_RECURSION_TRACE_REQUESTS)
        self.assertEqual(report["request_count"], len(captured))
        self.assertLessEqual(report["request_count"], MAX_PRODUCTION_RECURSION_TRACE_REQUESTS)

    def test_empty_root_completes_and_report_preserves_unknown_semantics(self):
        report, _transport, captured = self._run_trace(lambda _wire: 0)
        self.assertEqual(report["trace_stop_reason"], "TRACE_STOPPED_TRAVERSAL_COMPLETE")
        self.assertEqual(report["visited_node_count"], 1)
        self.assertEqual(report["nonempty_unsaturated_node_count"], 0)
        self.assertEqual(report["deepest_depth_seen"], 0)
        self.assertEqual(len(captured), 1)
        self.assertEqual(report["pagination_completeness"], "UNKNOWN")
        self.assertFalse(report["synthetic_response_proves_provider_contract"])
        self.assertFalse(report["durable_cursor_written"])
        self.assertFalse(report["alert_or_delivery_state_written"])

    def test_cli_dispatches_offline_trace_and_rejects_noncanonical_settings(self):
        arguments = [
            "--mode", "offline-synthetic", "--operation",
            "production-recursion-trace", "--organization", ORG,
            "--start-time", START, "--end-time", END, "--query", QUERY,
        ]
        output = io.StringIO()
        with patch("sys.stdout", output), patch(
            "socket.socket", side_effect=AssertionError("socket forbidden"),
        ), patch(
            "http.client.HTTPSConnection", side_effect=AssertionError("HTTPS forbidden"),
        ):
            exit_code = cli.main(arguments)
        self.assertEqual(exit_code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertEqual(report["request_budget"], 23)
        self.assertIn(report["trace_stop_reason"], {
            "TRACE_STOPPED_REQUEST_BUDGET", "TRACE_STOPPED_DEPTH_LIMIT",
            "TRACE_STOPPED_TARGET_SIGNATURE", "TRACE_STOPPED_TRAVERSAL_COMPLETE",
        })
        for extra in (("--page-size", "99"), ("--sort-order", "desc"), ("--repeat-parent",)):
            bad_output = io.StringIO()
            with patch("sys.stdout", bad_output):
                result = cli.main(arguments + list(extra))
            self.assertEqual(result, 2)
            self.assertEqual(json.loads(bad_output.getvalue())["failure_code"], "CONFIGURATION_INVALID")

    def test_report_omits_raw_log_and_label_values(self):
        markers = ("PRIVATE_TRACE_TEXT", "PRIVATE_TRACE_JSON", "PRIVATE_TRACE_MACHINE")

        def respond(_wire):
            stamp = "2026-10-14T20:15:00Z"
            body = {
                "page_min_time": stamp,
                "page_max_time": stamp,
                "items": [{
                    "time": stamp,
                    "text_log": markers[0],
                    "json_log": {"private": markers[1]},
                    "resource": {"labels": {"machine_id": markers[2]}},
                }],
            }
            return ProbeHttpResponse(200, json.dumps(body).encode("utf-8"))

        transport = OfflineSyntheticTransport(
            respond, request_budget=MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
        )
        report = ProbeRunner(transport).run_production_recursion_trace(_request())
        rendered = json.dumps(report, sort_keys=True)
        for marker in markers:
            self.assertNotIn(marker, rendered)


class ProbeSecretDiagnosticTests(unittest.TestCase):
    def setUp(self):
        from log_alerts.live_transport import secret_boundary_types

        self.provider_type, _, self.material_type = secret_boundary_types()
        self.capability = authorize_live_probe(
            enabled=True, confirmation="CENTRAL_FLEET_MONITOR",
        )
        self.wire = _wire_request(
            _request(), role="SINGLE_REQUEST", start=_request().start_time,
            end=_request().end_time, page_size=100,
        )

    def _transport(self, provider=None):
        if provider is None:
            provider = self.provider_type(enabled=True)
        return LiveManualTransport(
            capability=self.capability, secret_provider=provider,
        )

    def _post_with_synthetic_input(self, value, *, transport=None):
        transport = transport or self._transport()
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "getpass.getpass", return_value=value,
        ), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("HTTPS must not be constructed for invalid material"),
        ), patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(ProbeError) as caught:
                transport.post(self.wire)
        return caught.exception

    def test_approved_provider_type_is_stable_and_hidden_getpass_returns_cached_str_material(self):
        from log_alerts.live_transport import secret_boundary_types

        provider_type_again, _, material_type_again = secret_boundary_types()
        self.assertIs(provider_type_again, self.provider_type)
        self.assertIs(material_type_again, self.material_type)
        provider = self.provider_type(enabled=True)
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "getpass.getpass", return_value=PRIVATE_SECRET,
        ) as prompt:
            first = provider.acquire()
            second = provider.acquire()
        self.assertIs(type(PRIVATE_SECRET), str)
        self.assertIs(type(first), self.material_type)
        self.assertIs(first, second)
        self.assertEqual(provider.read_count, 1)
        self.assertEqual(prompt.call_count, 1)
        self.assertNotIn(PRIVATE_SECRET, repr(first))
        self.assertNotIn(PRIVATE_SECRET, str(first))

    def test_duplicate_module_identity_is_rejected_without_weakening_exact_type_check(self):
        module_name = "_probe_duplicate_secret_boundary_for_test"
        source = Path(__file__).resolve().parents[2] / "g4c-live" / "live_secret_boundary.py"
        spec = importlib.util.spec_from_file_location(module_name, source)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        duplicate_module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = duplicate_module
        try:
            spec.loader.exec_module(duplicate_module)
            duplicate_provider = duplicate_module.InteractiveSecretProvider(enabled=True)
            self.assertIsNot(type(duplicate_provider), self.provider_type)
            with self.assertRaises(ProbeError) as caught:
                LiveManualTransport(
                    capability=self.capability,
                    secret_provider=duplicate_provider,
                )
            self.assertEqual(
                caught.exception.code, "SECRET_PROVIDER_IDENTITY_INVALID",
            )
        finally:
            sys.modules.pop(module_name, None)

    def test_invalid_hidden_input_values_have_one_fixed_category_and_no_echo(self):
        invalid_values = (
            "", " ", "\t", "\r", "\n", "token\r", "token\n", "é",
            "x" * 5000,
        )
        for value in invalid_values:
            with self.subTest(input_class="empty_or_invalid"):
                stdout = io.StringIO()
                stderr = io.StringIO()
                transport = self._transport()
                with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                    error = self._post_with_synthetic_input(value, transport=transport)
                self.assertEqual(error.code, "SECRET_INPUT_EMPTY_OR_INVALID")
                self.assertEqual(transport._secret_provider.read_count, 1)
                if value:
                    self.assertNotIn(value, stdout.getvalue())
                    self.assertNotIn(value, stderr.getvalue())

    def test_getpass_exception_is_acquisition_failed_and_exception_text_is_redacted(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        transport = self._transport()
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "getpass.getpass",
            side_effect=RuntimeError(PRIVATE_SECRET + PRIVATE_MACHINE),
        ), patch("sys.stdout", stdout), patch("sys.stderr", stderr), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("HTTPS must not be constructed"),
        ), patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(ProbeError) as caught:
                transport.post(self.wire)
        self.assertEqual(caught.exception.code, "SECRET_ACQUISITION_FAILED")
        self.assertEqual(transport._secret_provider.read_count, 0)
        rendered = (
            stdout.getvalue() + stderr.getvalue() + str(caught.exception)
            + repr(caught.exception)
            + "".join(traceback.format_exception(caught.exception))
        )
        self.assertNotIn(PRIVATE_SECRET, rendered)
        self.assertNotIn(PRIVATE_MACHINE, rendered)

    def test_valid_input_reaches_https_construction_without_opening_a_socket(self):
        transport = self._transport()
        construction_calls = []

        def stop_at_https_construction(*args, **kwargs):
            construction_calls.append((args, kwargs))
            raise RuntimeError(PRIVATE_SECRET)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "getpass.getpass", return_value=PRIVATE_SECRET,
        ), patch("sys.stdout", stdout), patch("sys.stderr", stderr), patch(
            "http.client.HTTPSConnection", side_effect=stop_at_https_construction,
        ), patch("socket.socket", side_effect=AssertionError("network forbidden")), patch(
            "socket.create_connection", side_effect=AssertionError("network forbidden"),
        ), patch("socket.getaddrinfo", side_effect=AssertionError("DNS forbidden")):
            with self.assertRaises(ProbeError) as caught:
                transport.post(self.wire)
            with self.assertRaises(ProbeError) as cached_attempt:
                transport.post(self.wire)
        self.assertEqual(caught.exception.code, "LIVE_TRANSPORT_FAILED")
        self.assertEqual(cached_attempt.exception.code, "LIVE_TRANSPORT_FAILED")
        self.assertEqual(len(construction_calls), 2)
        self.assertEqual(construction_calls[0][0], ("api.salad.com", 443))
        self.assertEqual(transport._secret_provider.read_count, 1)
        self.assertIs(type(transport._material), self.material_type)
        rendered = (
            stdout.getvalue() + stderr.getvalue() + repr(transport)
            + "".join(traceback.format_exception(caught.exception))
        )
        self.assertNotIn(PRIVATE_SECRET, rendered)

    def test_cli_reports_only_fixed_category_after_hidden_invalid_input(self):
        output = io.StringIO()
        stderr = io.StringIO()
        arguments = [
            "--mode", "live-manual", "--operation", "single",
            "--organization", ORG, "--start-time", START, "--end-time", END,
            "--query", QUERY, "--enable-live-read", "--confirm-live",
            "CENTRAL_FLEET_MONITOR",
        ]
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "getpass.getpass", return_value="\r\n",
        ), patch("sys.stdout", output), patch("sys.stderr", stderr), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("HTTPS forbidden before valid secret"),
        ), patch("socket.socket", side_effect=AssertionError("network forbidden")):
            exit_code = cli.main(arguments)
        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(
            json.loads(output.getvalue()),
            {"status": "BLOCKED", "failure_code": "SECRET_INPUT_EMPTY_OR_INVALID"},
        )

    def test_wrong_provider_identity_is_rejected_before_acquisition(self):
        with self.assertRaises(ProbeError) as constructor_error:
            LiveManualTransport(
                capability=self.capability, secret_provider=object(),
            )
        self.assertEqual(
            constructor_error.exception.code, "SECRET_PROVIDER_IDENTITY_INVALID",
        )

        transport = self._transport()
        transport._secret_provider = object()
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("network forbidden"),
        ), patch("socket.socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(ProbeError) as caught:
                transport.post(self.wire)
        self.assertEqual(caught.exception.code, "SECRET_PROVIDER_IDENTITY_INVALID")

    def test_unavailable_or_wrong_boundary_module_has_provider_identity_category(self):
        from log_query_probe.core import load_interactive_secret_provider

        with patch(
            "log_alerts.live_transport.secret_boundary_types",
            side_effect=RuntimeError(PRIVATE_SECRET),
        ):
            with self.assertRaises(ProbeError) as caught:
                load_interactive_secret_provider()
        self.assertEqual(
            caught.exception.code, "SECRET_PROVIDER_IDENTITY_INVALID",
        )
        self.assertNotIn(PRIVATE_SECRET, repr(caught.exception))

        transport = self._transport()
        with patch(
            "log_alerts.live_transport.secret_boundary_types",
            side_effect=RuntimeError(PRIVATE_SECRET),
        ), patch("sys.stdin", _SyntheticTTY()), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("network forbidden"),
        ):
            with self.assertRaises(ProbeError) as post_error:
                transport.post(self.wire)
        self.assertEqual(
            post_error.exception.code, "SECRET_PROVIDER_IDENTITY_INVALID",
        )

    def test_provider_construction_failure_is_distinct_from_module_identity_failure(self):
        from log_query_probe.core import load_interactive_secret_provider

        with patch.object(
            self.provider_type, "__init__",
            side_effect=RuntimeError(PRIVATE_SECRET),
        ):
            with self.assertRaises(ProbeError) as caught:
                load_interactive_secret_provider()
        self.assertEqual(caught.exception.code, "SECRET_ACQUISITION_FAILED")
        self.assertNotIn(PRIVATE_SECRET, repr(caught.exception))

    def test_material_type_source_and_header_failures_are_distinct(self):
        provider = self.provider_type(enabled=True)
        transport = self._transport(provider)
        with patch.object(self.provider_type, "acquire", return_value=object()), patch(
            "sys.stdin", _SyntheticTTY(),
        ), patch("http.client.HTTPSConnection", side_effect=AssertionError("no network")):
            with self.assertRaises(ProbeError) as wrong_type:
                transport.post(self.wire)
        self.assertEqual(wrong_type.exception.code, "SECRET_MATERIAL_INVALID")

        # Use the approved class loaded by the transport boundary; a synthetic
        # source is valid material but is never valid for the live probe.
        from log_alerts.live_transport import secret_boundary_types
        _, _, material_type = secret_boundary_types()
        synthetic_material = material_type(
            PRIVATE_SECRET, source_label="synthetic_test_provider",
        )
        transport = self._transport()
        with patch.object(
            self.provider_type, "acquire", return_value=synthetic_material,
        ), patch("sys.stdin", _SyntheticTTY()), patch(
            "http.client.HTTPSConnection", side_effect=AssertionError("no network"),
        ):
            with self.assertRaises(ProbeError) as wrong_source:
                transport.post(self.wire)
        self.assertEqual(wrong_source.exception.code, "SECRET_SOURCE_INVALID")

        transport = self._transport()
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "getpass.getpass", return_value=PRIVATE_SECRET,
        ), patch.object(
            material_type, "_header_value", side_effect=RuntimeError(PRIVATE_SECRET),
        ), patch("http.client.HTTPSConnection", side_effect=AssertionError("no network")):
            with self.assertRaises(ProbeError) as header_error:
                transport.post(self.wire)
        self.assertEqual(
            header_error.exception.code, "SECRET_HEADER_ENCODING_INVALID",
        )
        for error in (wrong_type.exception, wrong_source.exception, header_error.exception):
            self.assertNotIn(PRIVATE_SECRET, str(error))
            self.assertNotIn(PRIVATE_SECRET, repr(error))

class ProbeResponseSafetyTests(unittest.TestCase):
    def test_page_bounds_outside_window_are_classified_not_discarded(self):
        request = _request()

        def decorate(wire, times):
            return {
                "page_min": "2026-10-14T19:59:59Z",
                "page_max": "2026-10-14T20:30:03Z",
            }

        report = ProbeRunner(
            OfflineSyntheticTransport(_bound_responder(decorate=decorate))
        ).run_single(request)
        observed = report["requests"][0]
        self.assertEqual(observed["page_bounds_vs_wire_window"], "SPANS_WINDOW")
        self.assertEqual(observed["page_min_vs_wire_start"], "BEFORE")
        self.assertEqual(observed["page_max_vs_wire_end"], "AFTER")
        self.assertIn("page_min_to_wire_start", observed["bounded_deltas"])

    def test_item_times_outside_window_are_classified_for_diagnosis(self):
        request = _request()

        def decorate(wire, _times):
            return {
                "times": ["2026-10-14T19:59:59Z"],
                "page_min": "2026-10-14T19:59:59Z",
                "page_max": "2026-10-14T19:59:59Z",
            }

        report = ProbeRunner(
            OfflineSyntheticTransport(_bound_responder(decorate=decorate))
        ).run_single(request)
        self.assertEqual(report["requests"][0]["items_vs_wire_window"], "BEFORE_WINDOW")

    def test_empty_page_can_omit_bounds_but_partial_bounds_are_rejected(self):
        request = _request()
        accepted = ProbeRunner(
            OfflineSyntheticTransport(
                lambda wire: _response(wire, times=[], include_bounds=False)
            )
        ).run_single(request)
        self.assertEqual(accepted["requests"][0]["page_bounds_vs_wire_window"], "ABSENT")
        partial = ProbeRunner(
            OfflineSyntheticTransport(
                lambda wire: ProbeHttpResponse(
                    200,
                    json.dumps({
                        "items": [],
                        "page_min_time": "2026-10-14T20:00:00Z",
                    }).encode(),
                )
            )
        )
        with self.assertRaises(ProbeError) as caught:
            partial.run_single(request)
        self.assertEqual(caught.exception.code, "PAGE_BOUNDS_INVALID")

    def test_nonempty_page_requires_two_parseable_nonreversed_bounds(self):
        request = _request()
        cases = [
            (
                {"items": [{"time": START}]},
                "PAGE_BOUNDS_MISSING",
            ),
            (
                {
                    "items": [{"time": START}],
                    "page_min_time": "2026-10-14T20:01:00Z",
                    "page_max_time": "2026-10-14T20:00:00Z",
                },
                "PAGE_BOUNDS_REVERSED",
            ),
            (
                {
                    "items": [{"time": START}],
                    "page_min_time": "not-a-time",
                    "page_max_time": "2026-10-14T20:00:00Z",
                },
                "PAGE_BOUNDS_INVALID",
            ),
        ]
        for body, expected in cases:
            with self.subTest(expected=expected):
                transport = OfflineSyntheticTransport(
                    lambda _wire, value=body: ProbeHttpResponse(
                        200, json.dumps(value).encode(),
                    )
                )
                with self.assertRaises(ProbeError) as caught:
                    ProbeRunner(transport).run_single(request)
                self.assertEqual(caught.exception.code, expected)

    def test_missing_invalid_and_outside_item_timestamps_have_bounded_handling(self):
        request = _request()
        malformed = [
            ({"time": None}, "ITEM_TIME_MISSING"),
            ({"time": "not-a-time"}, "ITEM_TIME_INVALID"),
            ({"time": START, "receive_time": "bad"}, "RECEIVE_TIME_INVALID"),
        ]
        for item, expected in malformed:
            with self.subTest(expected=expected):
                transport = OfflineSyntheticTransport(
                    lambda wire, item=item: _response(
                        wire,
                        times=[START],
                        page_min=START,
                        page_max=START,
                        item_overrides=[item],
                    )
                )
                with self.assertRaises(ProbeError) as caught:
                    ProbeRunner(transport).run_single(request)
                self.assertEqual(caught.exception.code, expected)

    def test_pagination_metadata_malformed_json_duplicates_and_nonfinite_values_fail(self):
        request = _request()
        responses = [
            (b'{"items":[],"next_page_token":"cursor"}', "PAGINATION_METADATA_UNSUPPORTED"),
            (b"{broken", "RESPONSE_JSON_INVALID"),
            (b'{"items":[],"items":[]}', "RESPONSE_JSON_INVALID"),
            (b'{"items":[],"numeric":NaN}', "RESPONSE_JSON_INVALID"),
            (b"[]", "RESPONSE_SCHEMA_INVALID"),
        ]
        for body, expected in responses:
            with self.subTest(expected=expected):
                transport = OfflineSyntheticTransport(
                    lambda _wire, body=body: ProbeHttpResponse(200, body)
                )
                with self.assertRaises(ProbeError) as caught:
                    ProbeRunner(transport).run_single(request)
                self.assertEqual(caught.exception.code, expected)

    def test_response_status_and_page_size_overflow_are_rejected(self):
        request = _request(page_size=1)
        status_runner = ProbeRunner(
            OfflineSyntheticTransport(
                lambda wire: _response(wire, status=302, raw_body=b"redirect")
            )
        )
        with self.assertRaises(ProbeError) as caught:
            status_runner.run_single(request)
        self.assertEqual(caught.exception.code, "HTTP_STATUS_REJECTED")
        self.assertEqual(caught.exception.http_status, 302)

        overfull = ProbeRunner(
            OfflineSyntheticTransport(
                lambda wire: _response(wire, times=[START, END], page_min=START, page_max=END)
            )
        )
        with self.assertRaises(ProbeError) as caught:
            overfull.run_single(request)
        self.assertEqual(caught.exception.code, "PAGE_SIZE_EXCEEDED")

    def test_single_and_cumulative_response_byte_budgets_are_enforced(self):
        request = _request()
        oversized = ProbeRunner(
            OfflineSyntheticTransport(
                lambda _wire: ProbeHttpResponse(200, b" " * (MAX_RESPONSE_BYTES + 1))
            )
        )
        with self.assertRaises(ProbeError) as caught:
            oversized.run_single(request)
        self.assertEqual(caught.exception.code, "RESPONSE_TOO_LARGE")

        wire = _wire_request(
            request, role="SINGLE_REQUEST", start=request.start_time,
            end=request.end_time, page_size=100,
        )
        body = _response(wire).body
        transport = OfflineSyntheticTransport(
            lambda _request: ProbeHttpResponse(200, body)
        )
        runner = ProbeRunner(transport)
        with patch("log_query_probe.core.MAX_TOTAL_RESPONSE_BYTES", len(body) + 1):
            with self.assertRaises(ProbeError) as caught:
                runner.run_experiment(request)
        self.assertEqual(caught.exception.code, "BYTE_BUDGET_EXCEEDED")
        self.assertEqual(transport.request_count, 2)

    def test_transport_exception_text_is_replaced_by_a_fixed_code(self):
        transport = OfflineSyntheticTransport(
            lambda _wire: (_ for _ in ()).throw(
                RuntimeError(PRIVATE_SECRET + PRIVATE_MACHINE + PRIVATE_LOG)
            )
        )
        with self.assertRaises(ProbeError) as caught:
            ProbeRunner(transport).run_single(_request())
        self.assertEqual(caught.exception.code, "TRANSPORT_RESPONSE_INVALID")
        self.assertNotIn(PRIVATE_SECRET, str(caught.exception))
        self.assertNotIn(PRIVATE_MACHINE, repr(caught.exception))
        self.assertNotIn(PRIVATE_LOG, repr(caught.exception))

    def test_timestamp_order_ties_distinct_count_and_boundary_ties_are_reported(self):
        request = _request(
            start_time="2026-10-14T20:00:00Z",
            end_time="2026-10-14T20:00:10Z",
            page_size=4,
        )

        def responder(wire):
            return _response(
                wire,
                times=[
                    "2026-10-14T20:00:00Z",
                    "2026-10-14T20:00:00Z",
                    "2026-10-14T20:00:05Z",
                    "2026-10-14T20:00:10Z",
                ],
                page_min="2026-10-14T20:00:00Z",
                page_max="2026-10-14T20:00:10Z",
            )

        report = ProbeRunner(OfflineSyntheticTransport(responder)).run_single(request)["requests"][0]
        self.assertTrue(report["sort_order_monotonic"])
        self.assertEqual(report["distinct_item_timestamp_count"], 3)
        self.assertEqual(report["item_minimum_timestamp_tie_count"], 2)
        self.assertEqual(report["item_wire_start_boundary_tie_count"], 2)
        self.assertEqual(report["item_wire_end_boundary_tie_count"], 1)

        desc = _request(
            start_time="2026-10-14T20:00:00Z",
            end_time="2026-10-14T20:00:10Z",
            page_size=2,
            sort_order="desc",
        )
        descending = ProbeRunner(
            OfflineSyntheticTransport(
                lambda wire: _response(
                    wire,
                    times=["2026-10-14T20:00:09Z", "2026-10-14T20:00:01Z"],
                    page_min="2026-10-14T20:00:01Z",
                    page_max="2026-10-14T20:00:09Z",
                )
            )
        ).run_single(desc)["requests"][0]
        self.assertTrue(descending["sort_order_monotonic"])

    def test_output_omits_org_query_raw_logs_labels_credentials_and_provider_timestamps(self):
        private_provider_time = "2026-10-14T20:00:00.123456789Z"
        request = _request(query=PRIVATE_QUERY)

        def responder(wire):
            body = {
                "items": [{
                    "time": private_provider_time,
                    "receive_time": "2026-10-14T20:00:00.223456789Z",
                    "text_log": PRIVATE_LOG,
                    "json_log": {"payload": PRIVATE_JSON, "credential": PRIVATE_SECRET},
                    "resource": {"labels": {
                        "machine_id": PRIVATE_MACHINE,
                        "instance_id": PRIVATE_INSTANCE,
                    }},
                }],
                "page_min_time": private_provider_time,
                "page_max_time": "2026-10-14T20:00:00.223456789Z",
            }
            return ProbeHttpResponse(
                200, json.dumps(body, separators=(",", ":")).encode(),
            )

        report_text = json.dumps(
            ProbeRunner(OfflineSyntheticTransport(responder)).run_single(request),
            sort_keys=True,
        )
        for private_value in (
            ORG, QUERY, PRIVATE_QUERY, private_provider_time, PRIVATE_LOG,
            PRIVATE_JSON, PRIVATE_MACHINE, PRIVATE_INSTANCE, PRIVATE_SECRET,
        ):
            self.assertNotIn(private_value, report_text)
        self.assertIn("PROVIDER_SEMANTICS_UNKNOWN", report_text)
        self.assertIn("SYNTHETIC/UNVERIFIED", report_text)

    def test_synthetic_fixture_is_sanitized_and_never_claims_provider_semantics(self):
        report = ProbeRunner(
            OfflineSyntheticTransport(make_synthetic_saturated_responder())
        ).run_experiment(_request())
        report_text = json.dumps(report, sort_keys=True)
        for marker in (PRIVATE_LOG, PRIVATE_JSON, PRIVATE_MACHINE, PRIVATE_INSTANCE):
            self.assertNotIn(marker, report_text)
        self.assertEqual(report["classification"], "SYNTHETIC/UNVERIFIED")
        self.assertTrue(report["synthetic_response_proves_provider_contract"] is False)
        self.assertEqual(report["comparisons"]["parent_vs_control"]["parent_count"], 100)
        self.assertEqual(report["comparisons"]["parent_vs_control"]["control_count"], 99)
        self.assertEqual(
            report["requests"][0]["page_bounds_vs_wire_window"],
            "SPANS_WINDOW",
        )

    def test_cli_offline_never_uses_sockets_and_does_not_write_state(self):
        arguments = [
            "--mode", "offline-synthetic", "--operation", "experiment",
            "--organization", ORG, "--start-time", START, "--end-time", END,
            "--query", QUERY,
        ]
        with tempfile.TemporaryDirectory() as temporary:
            before = list(Path(temporary).iterdir())
            output = io.StringIO()
            with patch("sys.stdout", output), patch(
                "socket.socket", side_effect=AssertionError("socket forbidden")
            ), patch(
                "http.client.HTTPSConnection",
                side_effect=AssertionError("HTTPS forbidden"),
            ):
                exit_code = cli.main(arguments)
            self.assertEqual(exit_code, 0)
            self.assertEqual(list(Path(temporary).iterdir()), before)
            report = json.loads(output.getvalue())
            self.assertFalse(report["durable_cursor_written"])
            self.assertFalse(report["alert_or_delivery_state_written"])

    def test_cli_argument_errors_do_not_echo_private_values_to_stderr(self):
        base_args = [
            "--mode", "offline-synthetic", "--operation", "single",
            "--organization", ORG, "--start-time", START, "--end-time", END,
            "--query", QUERY,
        ]
        cases = (
            ["--page-size", PRIVATE_SECRET],
            ["--unknown-option", PRIVATE_QUERY],
        )
        for invalid_args in cases:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with self.subTest(invalid_args=invalid_args), patch(
                "sys.stdout", stdout
            ), patch("sys.stderr", stderr), patch(
                "log_query_probe.cli.load_interactive_secret_provider",
                side_effect=AssertionError("secret access forbidden"),
            ), patch(
                "http.client.HTTPSConnection",
                side_effect=AssertionError("network forbidden"),
            ):
                exit_code = cli.main(base_args + invalid_args)
            self.assertEqual(exit_code, 2)
            self.assertEqual(stderr.getvalue(), "")
            output = stdout.getvalue()
            self.assertNotIn(PRIVATE_SECRET, output)
            self.assertNotIn(PRIVATE_QUERY, output)
            self.assertEqual(
                json.loads(output),
                {"status": "BLOCKED", "failure_code": "CONFIGURATION_INVALID"},
            )

    def test_live_cli_requires_gate_and_tty_before_secret_or_network_access(self):
        base_args = [
            "--mode", "live-manual", "--operation", "single",
            "--organization", ORG, "--start-time", START, "--end-time", END,
            "--query", QUERY,
        ]
        for extra in ([], ["--enable-live-read"]):
            output = io.StringIO()
            with patch("sys.stdout", output), patch(
                "log_query_probe.cli.load_interactive_secret_provider",
                side_effect=AssertionError("secret access forbidden"),
            ), patch(
                "http.client.HTTPSConnection",
                side_effect=AssertionError("network forbidden"),
            ):
                exit_code = cli.main(base_args + extra)
            self.assertEqual(exit_code, 3)
            self.assertEqual(json.loads(output.getvalue())["failure_code"], "LIVE_AUTHORIZATION_REQUIRED")

        output = io.StringIO()
        with patch("sys.stdout", output), patch("sys.stdin", io.StringIO("")), patch(
            "log_query_probe.cli.load_interactive_secret_provider",
            side_effect=AssertionError("secret access forbidden"),
        ), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("network forbidden"),
        ):
            exit_code = cli.main(
                base_args + [
                    "--enable-live-read",
                    "--confirm-live", "CENTRAL_FLEET_MONITOR",
                ]
            )
        self.assertEqual(exit_code, 3)
        self.assertEqual(json.loads(output.getvalue())["failure_code"], "INTERACTIVE_TTY_REQUIRED")

    def test_live_transport_rejects_everything_except_exact_log_query_post_before_tty(self):
        from log_alerts.live_transport import secret_boundary_types

        interactive_provider, _, _ = secret_boundary_types()
        capability = authorize_live_probe(
            enabled=True, confirmation="CENTRAL_FLEET_MONITOR",
        )
        transport = LiveManualTransport(
            capability=capability,
            secret_provider=interactive_provider(enabled=False),
        )
        request = _request()
        valid_wire = _wire_request(
            request, role="SINGLE_REQUEST", start=request.start_time,
            end=request.end_time, page_size=request.page_size,
        )
        denied_wires = [
            replace(valid_wire, method="GET"),
            replace(valid_wire, host="example.invalid"),
            replace(valid_wire, port=444),
            replace(valid_wire, path="/api/public/organizations/synthetic-org/containers/x/start"),
            replace(valid_wire, body=valid_wire.body + b" "),
        ]
        for malformed in denied_wires:
            with self.subTest(request=repr(malformed)):
                with self.assertRaises(ProbeError) as caught, patch(
                    "http.client.HTTPSConnection",
                    side_effect=AssertionError("network forbidden"),
                ):
                    transport.post(malformed)
                self.assertEqual(caught.exception.code, "LIVE_AUTHORIZATION_REQUIRED")
        self.assertEqual(transport.request_count, 0)


class ProbeHttpErrorDiagnosticTests(unittest.TestCase):
    def _run_error(self, status: int, body: bytes) -> ProbeError:
        transport = OfflineSyntheticTransport(
            lambda _wire: ProbeHttpResponse(status, body)
        )
        with self.assertRaises(ProbeError) as caught:
            ProbeRunner(transport).run_single(_request())
        return caught.exception

    def test_known_provider_type_is_surfaced_without_arbitrary_error_text(self):
        private_message = "PRIVATE_PROVIDER_MESSAGE_MARKER"
        private_url = "https://private.invalid/path"
        body = json.dumps({
            "type": "invalid_time_range",
            "title": private_message,
            "detail": private_message,
            "instance": "PRIVATE_PROVIDER_ID_MARKER",
            "url": private_url,
            "organization": "PRIVATE_ORG_MARKER",
        }).encode("utf-8")
        error = self._run_error(400, body)
        self.assertEqual(error.code, "HTTP_STATUS_REJECTED")
        self.assertEqual(error.http_status, 400)
        self.assertEqual(error.provider_error_code, "invalid_time_range")
        self.assertIsNone(error.provider_error_category)
        rendered = str(error) + repr(error) + "".join(traceback.format_exception(error))
        for value in (
            private_message, private_url, "PRIVATE_PROVIDER_ID_MARKER",
            "PRIVATE_ORG_MARKER", PRIVATE_SECRET,
        ):
            self.assertNotIn(value, rendered)

    def test_unknown_malformed_duplicate_oversized_and_non_scalar_codes_are_unclassified(self):
        bodies = (
            b"",
            b"{malformed",
            b'{"type":"other_private_provider_code","detail":"PRIVATE_DETAIL_MARKER"}',
            b'{"type":17}',
            b'{"type":"invalid_time_range","type":"other"}',
            b'{"type":"invalid_time_range","extra":"' + b"x" * MAX_PROVIDER_ERROR_BODY_BYTES + b'"}',
        )
        for body in bodies:
            with self.subTest(body_class="bounded classification only"):
                error = self._run_error(400, body)
                self.assertEqual(error.http_status, 400)
                self.assertIsNone(error.provider_error_code)
                self.assertEqual(
                    error.provider_error_category, "PROVIDER_ERROR_UNCLASSIFIED",
                )
                self.assertNotIn("PRIVATE_DETAIL_MARKER", repr(error))

    def test_401_403_404_and_429_remain_distinguishable_and_redacted(self):
        body = json.dumps({
            "type": "invalid_time_range",
            "detail": "PRIVATE_AUTH_DETAIL_MARKER",
        }).encode("utf-8")
        for status in (401, 403, 404, 429):
            with self.subTest(status=status):
                error = self._run_error(status, body)
                self.assertEqual(error.http_status, status)
                self.assertEqual(error.code, "HTTP_STATUS_REJECTED")
                self.assertEqual(error.provider_error_code, "invalid_time_range")
                self.assertIsNone(error.provider_error_category)
                self.assertNotIn("PRIVATE_AUTH_DETAIL_MARKER", repr(error))

    def test_cli_emits_only_safe_provider_classification_and_status(self):
        body = json.dumps({
            "type": "invalid_time_range",
            "detail": "PRIVATE_CLI_DETAIL_MARKER",
            "instance": "PRIVATE_CLI_INSTANCE_MARKER",
        }).encode("utf-8")
        offline_transport = OfflineSyntheticTransport(
            lambda _wire: ProbeHttpResponse(400, body)
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = [
            "--mode", "live-manual", "--operation", "single",
            "--organization", ORG, "--start-time", START, "--end-time", END,
            "--query", QUERY, "--enable-live-read", "--confirm-live",
            "CENTRAL_FLEET_MONITOR",
        ]
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "log_query_probe.cli.load_interactive_secret_provider",
            return_value=object(),
        ), patch(
            "log_query_probe.cli.LiveManualTransport",
            return_value=offline_transport,
        ), patch("sys.stdout", stdout), patch("sys.stderr", stderr), patch(
            "socket.socket", side_effect=AssertionError("network forbidden"),
        ), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("network forbidden"),
        ):
            exit_code = cli.main(arguments)
        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue()), {
            "status": "BLOCKED",
            "failure_code": "HTTP_STATUS_REJECTED",
            "http_status": 400,
            "provider_error_code": "invalid_time_range",
        })
        self.assertNotIn("PRIVATE_CLI_DETAIL_MARKER", stdout.getvalue())
        self.assertNotIn("PRIVATE_CLI_INSTANCE_MARKER", stdout.getvalue())

    def test_cli_emits_fixed_unclassified_category_for_unknown_provider_body(self):
        body = json.dumps({
            "type": "private_provider_text_marker",
            "detail": "PRIVATE_UNKNOWN_DETAIL_MARKER",
        }).encode("utf-8")
        offline_transport = OfflineSyntheticTransport(
            lambda _wire: ProbeHttpResponse(400, body)
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = [
            "--mode", "live-manual", "--operation", "single",
            "--organization", ORG, "--start-time", START, "--end-time", END,
            "--query", QUERY, "--enable-live-read", "--confirm-live",
            "CENTRAL_FLEET_MONITOR",
        ]
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "log_query_probe.cli.load_interactive_secret_provider",
            return_value=object(),
        ), patch(
            "log_query_probe.cli.LiveManualTransport",
            return_value=offline_transport,
        ), patch("sys.stdout", stdout), patch("sys.stderr", stderr), patch(
            "socket.socket", side_effect=AssertionError("network forbidden"),
        ), patch(
            "http.client.HTTPSConnection",
            side_effect=AssertionError("network forbidden"),
        ):
            exit_code = cli.main(arguments)
        self.assertEqual(exit_code, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue()), {
            "status": "BLOCKED",
            "failure_code": "HTTP_STATUS_REJECTED",
            "http_status": 400,
            "provider_error_category": "PROVIDER_ERROR_UNCLASSIFIED",
        })
        self.assertNotIn("private_provider_text_marker", stdout.getvalue())
        self.assertNotIn("PRIVATE_UNKNOWN_DETAIL_MARKER", stdout.getvalue())

    def test_successful_200_shape_is_unchanged(self):
        report = ProbeRunner(
            OfflineSyntheticTransport(lambda wire: _response(wire))
        ).run_single(_request())
        self.assertEqual(report["requests"][0]["http_status"], 200)
        self.assertNotIn("provider_error_code", report["requests"][0])
        self.assertNotIn("provider_error_category", report["requests"][0])

    def test_live_error_read_is_bounded_and_effective_request_stays_fixed_offline(self):
        from log_alerts.contract import LiveLogQueryPolicy
        from log_alerts.live_transport import secret_boundary_types
        from log_alerts.live_transport import _encode_request_body

        provider_type, _, _ = secret_boundary_types()
        capability = authorize_live_probe(
            enabled=True, confirmation="CENTRAL_FLEET_MONITOR",
        )
        wire = _wire_request(
            _request(), role="SINGLE_REQUEST", start=_request().start_time,
            end=_request().end_time, page_size=100,
        )
        watcher_request = LiveLogQueryPolicy(ORG).build_request(
            start_time_utc=START,
            end_time_utc=END,
            query=QUERY,
            page_size=100,
            sort_order="asc",
        )
        self.assertEqual(wire.path, watcher_request.path)
        self.assertEqual(wire.body, _encode_request_body(watcher_request))
        error_body = json.dumps({
            "type": "invalid_time_range", "detail": "PRIVATE_WIRE_DETAIL_MARKER",
        }).encode("utf-8")
        captured = {"wire": bytearray(), "read_sizes": [], "stages": [], "host": None}

        class FakeResponse:
            status = 400

            def read(self, size):
                captured["stages"].append("READ")
                captured["read_sizes"].append(size)
                return error_body[:size]

        class FakeSocket:
            def sendall(self, data):
                captured["stages"].append("SEND")
                captured["wire"].extend(data)

            def setsockopt(self, *_args):
                return None

            def settimeout(self, _timeout):
                return None

            def close(self):
                return None

        def offline_connect(connection):
            captured["stages"].append("CONNECT")
            captured["host"] = (connection.host, connection.port, connection.timeout)
            connection.sock = FakeSocket()

        def offline_getresponse(_connection):
            captured["stages"].append("GETRESPONSE")
            return FakeResponse()

        transport = LiveManualTransport(
            capability=capability,
            secret_provider=provider_type(enabled=True),
        )
        with patch("sys.stdin", _SyntheticTTY()), patch(
            "getpass.getpass", return_value=PRIVATE_SECRET,
        ), patch(
            "http.client.HTTPSConnection.connect", offline_connect,
        ), patch(
            "http.client.HTTPSConnection.getresponse", offline_getresponse,
        ), patch(
            "socket.socket", side_effect=AssertionError("network forbidden"),
        ), patch(
            "socket.create_connection", side_effect=AssertionError("network forbidden"),
        ), patch(
            "socket.getaddrinfo", side_effect=AssertionError("DNS forbidden"),
        ):
            with self.assertRaises(ProbeError) as caught:
                ProbeRunner(transport).run_single(_request())

        self.assertEqual(caught.exception.code, "HTTP_STATUS_REJECTED")
        self.assertEqual(
            captured["stages"],
            ["CONNECT", "SEND", "SEND", "GETRESPONSE", "READ"],
        )
        self.assertEqual(caught.exception.http_status, 400)
        self.assertEqual(captured["read_sizes"], [MAX_PROVIDER_ERROR_BODY_BYTES + 1])
        self.assertEqual(caught.exception.provider_error_code, "invalid_time_range")
        self.assertEqual(captured["host"][:2], ("api.salad.com", 443))
        raw_request = bytes(captured["wire"])
        headers, request_body = raw_request.split(b"\r\n\r\n", 1)
        header_lines = headers.decode("ascii").split("\r\n")
        self.assertEqual(header_lines[0], f"POST {wire.path} HTTP/1.1")
        effective_headers = {
            name.lower(): value.strip()
            for name, value in (line.split(":", 1) for line in header_lines[1:])
        }
        self.assertEqual(request_body, wire.body)
        self.assertEqual(effective_headers["host"], "api.salad.com")
        self.assertIn("salad-api-key", effective_headers)
        self.assertEqual(effective_headers["accept"], "application/json")
        self.assertEqual(effective_headers["accept-encoding"], "identity")
        self.assertEqual(effective_headers["content-type"], "application/json")
        content_length_values = [
            value.strip()
            for name, value in (
                line.split(":", 1) for line in header_lines[1:]
            )
            if name.lower() == "content-length"
        ]
        self.assertEqual(content_length_values, [str(len(wire.body))])
        self.assertNotIn("transfer-encoding", effective_headers)
        self.assertNotIn(b"PRIVATE_WIRE_DETAIL_MARKER", raw_request)
        self.assertNotIn(PRIVATE_SECRET.encode("ascii"), repr(caught.exception).encode("ascii"))


if __name__ == "__main__":
    unittest.main()
