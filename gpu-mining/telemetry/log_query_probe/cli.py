"""Command-line entry point for synthetic or explicitly gated live probing."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .core import (
    LiveManualTransport,
    MAX_EXPERIMENT_REQUESTS,
    MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS,
    MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
    MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
    MAX_SATURATED_TRACE_REQUESTS,
    OfflineSyntheticTransport,
    ProbeError,
    ProbeRequest,
    ProbeRunner,
    authorize_live_probe,
    load_interactive_secret_provider,
    make_synthetic_saturated_responder,
)


class _SanitizedArgumentParser(argparse.ArgumentParser):
    """Keep argparse from echoing operator-supplied values to stderr."""

    def error(self, message: str) -> None:
        del message
        raise ProbeError("CONFIGURATION_INVALID")


def build_parser() -> argparse.ArgumentParser:
    parser = _SanitizedArgumentParser(prog="salad-log-query-probe")
    parser.add_argument("--mode", choices=("offline-synthetic", "live-manual"), default="offline-synthetic")
    parser.add_argument(
        "--operation",
        choices=(
            "experiment", "single", "saturated-branch-trace",
            "production-recursion-trace", "page-min-before-probe",
            "page-min-before-capture",
        ),
        default="experiment",
    )
    parser.add_argument("--organization", required=True)
    parser.add_argument("--start-time", required=True, help="RFC3339 timestamp including timezone")
    parser.add_argument("--end-time", required=True, help="RFC3339 timestamp including timezone")
    parser.add_argument("--query", required=True)
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--sort-order", choices=("asc", "desc"), default="asc")
    parser.add_argument("--repeat-parent", action="store_true")
    parser.add_argument("--direct-child-start")
    parser.add_argument("--direct-child-end")
    parser.add_argument("--enable-live-read", action="store_true")
    parser.add_argument("--confirm-live")
    return parser


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _failure(
    code: str, *, http_status: int | None = None,
    provider_error_code: str | None = None,
    provider_error_category: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {"status": "BLOCKED", "failure_code": code}
    if http_status is not None:
        result["http_status"] = http_status
    if provider_error_code == "invalid_time_range":
        result["provider_error_code"] = provider_error_code
    if provider_error_category == "PROVIDER_ERROR_UNCLASSIFIED":
        result["provider_error_category"] = provider_error_category
    return result


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except ProbeError as exc:
        _emit(_failure(exc.code))
        return 2
    if (args.direct_child_start is None) != (args.direct_child_end is None):
        _emit(_failure("CONFIGURATION_INVALID"))
        return 2
    if args.operation in {
        "saturated-branch-trace", "production-recursion-trace",
        "page-min-before-probe", "page-min-before-capture",
    } and (
        args.page_size != 100
        or args.sort_order != "asc"
        or args.repeat_parent
        or args.direct_child_start is not None
    ):
        _emit(_failure("CONFIGURATION_INVALID"))
        return 2
    request_budget = {
        "saturated-branch-trace": MAX_SATURATED_TRACE_REQUESTS,
        "production-recursion-trace": MAX_PRODUCTION_RECURSION_TRACE_REQUESTS,
        "page-min-before-probe": MAX_PAGE_MIN_BEFORE_PROBE_REQUESTS,
        "page-min-before-capture": MAX_PAGE_MIN_BEFORE_CAPTURE_REQUESTS,
    }.get(args.operation, MAX_EXPERIMENT_REQUESTS)
    try:
        request = ProbeRequest.from_values(
            organization_name=args.organization,
            start_time=args.start_time,
            end_time=args.end_time,
            query=args.query,
            page_size=args.page_size,
            sort_order=args.sort_order,
        )
    except ProbeError:
        _emit(_failure("CONFIGURATION_INVALID"))
        return 2

    if args.mode == "offline-synthetic":
        if args.enable_live_read or args.confirm_live is not None:
            _emit(_failure("LIVE_AUTHORIZATION_REQUIRED"))
            return 3
        transport = OfflineSyntheticTransport(
            make_synthetic_saturated_responder(), request_budget=request_budget,
        )
    else:
        try:
            capability = authorize_live_probe(
                enabled=args.enable_live_read,
                confirmation=args.confirm_live,
            )
        except ProbeError as exc:
            _emit(_failure(exc.code))
            return 3
        if not sys.stdin.isatty():
            _emit(_failure("INTERACTIVE_TTY_REQUIRED"))
            return 3
        try:
            provider = load_interactive_secret_provider()
            transport = LiveManualTransport(
                capability=capability, secret_provider=provider,
                request_budget=request_budget,
            )
        except ProbeError as exc:
            _emit(_failure(exc.code))
            return 3

    runner = ProbeRunner(transport)
    try:
        direct_child = (
            (args.direct_child_start, args.direct_child_end)
            if args.direct_child_start is not None else None
        )
        if args.operation == "single":
            if args.repeat_parent or direct_child is not None:
                raise ProbeError("CONFIGURATION_INVALID")
            report = runner.run_single(request)
        elif args.operation == "saturated-branch-trace":
            report = runner.run_saturated_branch_trace(request)
        elif args.operation == "production-recursion-trace":
            report = runner.run_production_recursion_trace(request)
        elif args.operation == "page-min-before-probe":
            report = runner.run_page_min_before_probe(request)
        elif args.operation == "page-min-before-capture":
            report = runner.run_page_min_before_capture(request)
        else:
            report = runner.run_experiment(
                request, repeat_parent=args.repeat_parent, direct_child=direct_child,
            )
    except ProbeError as exc:
        _emit(_failure(
            exc.code,
            http_status=exc.http_status,
            provider_error_code=exc.provider_error_code,
            provider_error_category=exc.provider_error_category,
        ))
        return 1
    _emit(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
