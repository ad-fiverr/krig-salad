"""Manual future live entrypoints; default and production network gates are OFF."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import sys
from typing import Sequence

from .central_telegram import (
    CentralTelegramSender,
    InteractiveTelegramSecretProvider,
    PRODUCTION_TELEGRAM_ALLOWED,
)
from .contract import LiveLogQueryPolicy
from .engine import LogAlertEnricher
from .ledger import SQLiteAlertLedger
from .live_controller import LiveLogAlertController, LiveControllerBlocked
from .live_transport import LiveSaladReadTransport, PRODUCTION_NETWORK_ALLOWED, secret_boundary_types


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="salad-log-alert-live")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe-live-contract-once", action="store_true")
    mode.add_argument("--live-alert-once", action="store_true")
    parser.add_argument("--enable-live-read", action="store_true")
    parser.add_argument("--enable-central-telegram", action="store_true")
    parser.add_argument("--organization", required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--start-time", help="required by contract probe; RFC3339 with zone")
    parser.add_argument("--end-time", required=True, help="RFC3339 with zone")
    parser.add_argument("--ledger-path", default="salad-log-alerts.sqlite3")
    return parser


def _load_interactive_salad_provider():
    # Load the exact approved provider from the repository-owned boundary.
    InteractiveSecretProvider, _, _ = secret_boundary_types()
    return InteractiveSecretProvider(enabled=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.enable_live_read:
        print("STATUS=BLOCKED LIVE_READ_GATE=OFF")
        return 2
    if args.live_alert_once and not args.enable_central_telegram:
        print("STATUS=BLOCKED CENTRAL_TELEGRAM_GATE=OFF")
        return 2
    if not args.start_time and args.probe_live_contract_once:
        print("STATUS=BLOCKED START_TIME_REQUIRED")
        return 2
    # This version is deliberately not capable of opening either production
    # boundary. Return before prompting for any secret or creating a database.
    if PRODUCTION_NETWORK_ALLOWED is not True:
        print("STATUS=BLOCKED SALAD_NETWORK_GATE=CLOSED")
        return 3
    if args.live_alert_once and PRODUCTION_TELEGRAM_ALLOWED is not True:
        print("STATUS=BLOCKED TELEGRAM_NETWORK_GATE=CLOSED")
        return 3
    if not sys.stdin.isatty():
        print("STATUS=BLOCKED INTERACTIVE_TTY_REQUIRED")
        return 3
    try:
        secret_provider = _load_interactive_salad_provider()
        policy = LiveLogQueryPolicy(args.organization)
        transport = LiveSaladReadTransport(policy=policy, secret_provider=secret_provider)
        ledger = SQLiteAlertLedger(args.ledger_path)
        sender = None
        if args.live_alert_once:
            telegram_provider = InteractiveTelegramSecretProvider(enabled=True)
            sender = CentralTelegramSender(credentials=telegram_provider.acquire())
        enricher = LogAlertEnricher(
            approved_organization=args.organization,
            transport=transport,
            ledger=ledger,
            secret_provider=secret_provider,
        )
        controller = LiveLogAlertController(enricher=enricher, ledger=ledger, sender=sender)
        if args.probe_live_contract_once:
            summary = controller.probe_once(
                start_time_utc=args.start_time,
                end_time_utc=args.end_time,
                query=args.query,
                enable_live_read=True,
            )
            print(json.dumps(asdict(summary), sort_keys=True, separators=(",", ":")))
        else:
            summary = controller.live_alert_once(
                end_time_utc=args.end_time,
                query=args.query,
                enable_live_read=True,
                enable_telegram_delivery=True,
            )
            print(json.dumps({
                "status": "COMPLETED",
                "data_classification": summary.cycle.data_classification,
                "records_seen": summary.cycle.records_seen,
                "alerts_prepared": summary.cycle.prepared_count,
                "delivery_states": [attempt.state for attempt in summary.delivery_attempts],
            }, sort_keys=True, separators=(",", ":")))
        ledger.close()
        return 0
    except LiveControllerBlocked:
        print("STATUS=BLOCKED LIVE_OPERATION_UNAVAILABLE")
        return 3
    except Exception:
        # Do not echo exception strings; URLs or provider values could appear.
        print("STATUS=FAILED DETAILS=REDACTED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
