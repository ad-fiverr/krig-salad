"""Explicit, disabled-by-default Salad contract probe and fleet watcher CLI."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys
from typing import Sequence

from .central_telegram import (
    CentralTelegramSender,
    InteractiveTelegramSecretProvider,
)
from .contract import LiveLogQueryPolicy, canonical_utc
from .engine import LogAlertEnricher
from .fleet_targets import FleetTarget, load_targets_file, parse_target, validate_targets
from .fleet_watcher import (
    CentralFleetWatcher, DEFAULT_POLL_SECONDS,
    MAX_POLL_SECONDS, MIN_POLL_SECONDS,
)
from .ledger import SQLiteAlertLedger
from .live_capability import LiveCapabilityBlocked, authorize_live_invocation
from .live_controller import LiveLogAlertController, LiveControllerBlocked
from .live_transport import LiveSaladReadTransport, secret_boundary_types


class WatcherAlreadyRunning(RuntimeError):
    """A watcher already holds the state-directory process lock."""


def _acquire_watcher_lock(state_dir: str) -> int:
    path = Path(state_dir).expanduser()
    if path.is_symlink():
        raise ValueError("watcher state directory must not be a symbolic link")
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()
    lock_path = resolved / ".watcher.lock"
    if lock_path.is_symlink():
        raise ValueError("watcher lock must not be a symbolic link")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError:
        raise ValueError("watcher lock file is unavailable") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("watcher lock file must be regular")
        if os.name == "nt":
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError:
                raise WatcherAlreadyRunning() from None
        else:
            import fcntl
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise WatcherAlreadyRunning() from None
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _release_watcher_lock(descriptor: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="salad-log-alert-live")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--probe-live-contract-once", action="store_true")
    mode.add_argument("--live-alert-once", action="store_true")
    mode.add_argument("--watch-live-alerts", action="store_true")
    parser.add_argument("--enable-live-read", action="store_true")
    parser.add_argument("--enable-central-telegram", action="store_true")
    parser.add_argument("--confirm-live", help="must equal CENTRAL_FLEET_MONITOR")
    parser.add_argument("--organization", help="single-organization compatibility mode")
    parser.add_argument("--target", action="append", default=[], metavar="ORG:PROJECT")
    parser.add_argument("--targets-file", help="non-secret JSON array of organization_name/project_name")
    parser.add_argument("--query", required=True, help="explicit Salad query; grammar must be verified separately")
    parser.add_argument("--start-time", help="required by contract probe; RFC3339 with zone")
    parser.add_argument("--end-time", help="required for one-shot alert mode; RFC3339 with zone")
    parser.add_argument("--ledger-path", default="salad-log-alerts.sqlite3")
    parser.add_argument("--state-dir", default="salad-alert-state")
    parser.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL_SECONDS)
    return parser


def _load_interactive_salad_provider():
    # Load the exact approved provider from the repository-owned boundary.
    InteractiveSecretProvider, _, _ = secret_boundary_types()
    return InteractiveSecretProvider(enabled=True)


def _watch_targets(args: argparse.Namespace) -> tuple[FleetTarget, ...]:
    targets = [parse_target(value) for value in args.target]
    if args.targets_file:
        targets.extend(load_targets_file(args.targets_file))
    if not targets and args.organization:
        raise ValueError("watch mode requires --target ORG:PROJECT or --targets-file")
    return validate_targets(targets)


def _emit(value: object) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _credential_like_query(value: str) -> bool:
    import re
    return bool(re.search(r"(?i)(?:salad[ _-]*api[ _-]*key|bearer\s+\S{8,}|(?:token|password|secret|api[_-]?key)\s*[:=])", value))


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.enable_live_read:
        print("STATUS=BLOCKED LIVE_READ_GATE=OFF")
        return 2
    if args.watch_live_alerts and not args.enable_central_telegram:
        print("STATUS=BLOCKED CENTRAL_TELEGRAM_GATE=OFF")
        return 2
    if args.live_alert_once and not args.enable_central_telegram:
        print("STATUS=BLOCKED CENTRAL_TELEGRAM_GATE=OFF")
        return 2
    if args.probe_live_contract_once:
        if not args.start_time or not args.end_time:
            print("STATUS=BLOCKED START_AND_END_TIME_REQUIRED")
            return 2
        if args.enable_central_telegram:
            print("STATUS=BLOCKED CONTRACT_PROBE_TELEGRAM_MUST_BE_OFF")
            return 2
    if not args.watch_live_alerts and not args.organization:
        print("STATUS=BLOCKED ORGANIZATION_REQUIRED")
        return 2
    try:
        mode = "watch" if args.watch_live_alerts else "probe" if args.probe_live_contract_once else "once"
        if (
            not args.query.strip() or len(args.query) > 20_000
            or any(ord(char) < 32 or ord(char) == 127 for char in args.query)
            or _credential_like_query(args.query)
        ):
            raise ValueError("query is invalid")
        targets = _watch_targets(args) if args.watch_live_alerts else None
        if args.watch_live_alerts and not MIN_POLL_SECONDS <= args.poll_seconds <= MAX_POLL_SECONDS:
            raise ValueError("poll interval is outside the allowed range")
        if not args.watch_live_alerts:
            LiveLogQueryPolicy(args.organization)
        if args.probe_live_contract_once:
            start = canonical_utc(args.start_time)
            end = canonical_utc(args.end_time)
            if datetime.fromisoformat(start.replace("Z", "+00:00")) >= datetime.fromisoformat(end.replace("Z", "+00:00")):
                raise ValueError("probe time window is invalid")
        elif args.end_time:
            canonical_utc(args.end_time)
        capability = authorize_live_invocation(
            mode=mode,
            enable_live_read=args.enable_live_read,
            enable_central_telegram=args.enable_central_telegram,
            confirmation=args.confirm_live,
        )
    except LiveCapabilityBlocked:
        print("STATUS=BLOCKED EXPLICIT_LIVE_CONFIRMATION_REQUIRED")
        return 3
    except ValueError:
        print("STATUS=BLOCKED CONFIGURATION_INVALID DETAILS=REDACTED")
        return 2
    if not sys.stdin.isatty():
        print("STATUS=BLOCKED INTERACTIVE_TTY_REQUIRED")
        return 3
    watcher_lock_fd: int | None = None
    try:
        if args.watch_live_alerts:
            watcher_lock_fd = _acquire_watcher_lock(args.state_dir)
        secret_provider = _load_interactive_salad_provider()
        InteractiveSecretProvider, _, _ = secret_boundary_types()
        if type(secret_provider) is not InteractiveSecretProvider:
            raise LiveControllerBlocked("approved Salad credential provider unavailable")
        # Hidden TTY read happens once and remains cached in memory for all orgs.
        secret_provider.acquire()
        if args.watch_live_alerts:
            telegram_provider = InteractiveTelegramSecretProvider(enabled=True)
            sender = CentralTelegramSender(
                credentials=telegram_provider.acquire(), capability=capability,
            )
            with CentralFleetWatcher(
                targets=targets,
                query=args.query,
                state_dir=args.state_dir,
                secret_provider=secret_provider,
                sender=sender,
                capability=capability,
                poll_seconds=args.poll_seconds,
            ) as watcher:
                _emit({"status": "WATCHING", "organizations": len(watcher.by_organization), "poll_seconds": args.poll_seconds})
                def emit_cycle(results):
                    _emit({"status": "POLL_COMPLETED", "organizations": [asdict(item) for item in results]})
                watcher.watch(on_cycle=emit_cycle)
            return 0

        policy = LiveLogQueryPolicy(args.organization)
        transport = LiveSaladReadTransport(
            policy=policy, secret_provider=secret_provider, capability=capability,
        )
        ledger = SQLiteAlertLedger(":memory:" if args.probe_live_contract_once else args.ledger_path)
        sender = None
        if args.live_alert_once:
            telegram_provider = InteractiveTelegramSecretProvider(enabled=True)
            sender = CentralTelegramSender(
                credentials=telegram_provider.acquire(), capability=capability,
            )
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
            _emit(asdict(summary))
        else:
            summary = controller.live_alert_once(
                end_time_utc=args.end_time or canonical_utc(datetime.now(timezone.utc)),
                query=args.query,
                enable_live_read=True,
                enable_telegram_delivery=True,
            )
            _emit({
                "status": "COMPLETED",
                "data_classification": summary.cycle.data_classification,
                "records_seen": summary.cycle.records_seen,
                "alerts_prepared": summary.cycle.prepared_count,
                "delivery_states": [attempt.state for attempt in summary.delivery_attempts],
            })
        ledger.close()
        return 0
    except KeyboardInterrupt:
        print("STATUS=STOPPED GRACEFUL=true")
        return 0
    except WatcherAlreadyRunning:
        print("STATUS=BLOCKED WATCHER_ALREADY_RUNNING")
        return 3
    except Exception:
        # Do not echo exception strings; URLs, log bodies or secrets may appear.
        print("STATUS=FAILED DETAILS=REDACTED")
        return 1
    finally:
        if watcher_lock_fd is not None:
            _release_watcher_lock(watcher_lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
