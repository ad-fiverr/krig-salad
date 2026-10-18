"""Local dashboard plus a separately gated, manual four-GET terminal mode."""

from __future__ import annotations

import argparse
import base64
import hmac
import json
from pathlib import Path
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from collector.action_ledger import ActionLedger
from collector.guard_store import GuardStore
from collector.salad_action_policy import DecisionDossierAuthority, SaladActionPolicy
from collector.salad_action_transport import RestrictedSaladActionHTTPTransport, SaladActionExecutor

from .config import G5Config, load_config
from .server import create_server
from .service import G5ControlPlaneService
from .store import ControlPlaneStore


LIVE_GET_TERMINAL_CONFIRMATION = (
    "READ ONLY GET adrianfiverr/miners: fl4shminer, fl4shminer-2, "
    "fl4shminer-3, fl4shminer-4"
)


def run_manual_live_get(
    service: G5ControlPlaneService,
    read_session: Any,
    *,
    stdin: Any = None,
    input_fn: Callable[[str], str] | None = None,
) -> dict[str, Any]:
    """Run one preconfigured four-slot read session after terminal consent.

    This function is intentionally not reachable through the localhost HTTP
    API. A future caller must provide an already configured
    ``LiveSaladReadSession`` carrying the existing signed GET capability and
    hidden interactive secret provider. The terminal phrase is an additional
    one-run operator gate, not a replacement for that signed capability.
    """
    if not isinstance(service, G5ControlPlaneService):
        return {"status": "LIVE_GET_BLOCKED", "reason": "control service unavailable", "groups_queried": 0, "live_calls_performed": False, "actions_performed": False}

    def blocked(reason: str) -> dict[str, Any]:
        result = {"status": "LIVE_GET_BLOCKED", "reason": reason, "groups_queried": 0, "live_calls_performed": False, "actions_performed": False}
        service.store.append_audit(
            "MANUAL_SALAD_GET_BLOCKED",
            {**result, "reason": reason},
            datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        )
        return result

    terminal = sys.stdin if stdin is None else stdin
    try:
        interactive = terminal.isatty() is True
    except Exception:
        interactive = False
    if not interactive:
        return blocked("interactive terminal required")
    g4c_root = str(Path(__file__).resolve().parents[2] / "g4c-live")
    inserted_g4c_root = g4c_root not in sys.path
    if inserted_g4c_root:
        sys.path.insert(0, g4c_root)
    try:
        from live_broker_gate import LiveSaladReadSession
    except Exception:
        return blocked("fixed read session implementation is unavailable")
    finally:
        if inserted_g4c_root:
            try:
                sys.path.remove(g4c_root)
            except ValueError:
                pass

    if type(read_session) is not LiveSaladReadSession:
        return blocked("preconfigured fixed-scope read session unavailable")

    reader = input if input_fn is None else input_fn
    try:
        typed = reader(f"Type exactly to authorize at most four read-only Salad GET requests: {LIVE_GET_TERMINAL_CONFIRMATION}\n> ")
    except Exception:
        return blocked("terminal confirmation was unavailable")
    if not isinstance(typed, str) or not hmac.compare_digest(typed.strip(), LIVE_GET_TERMINAL_CONFIRMATION):
        return blocked("terminal confirmation did not match the fixed read-only scope")

    try:
        raw = read_session.run_all()
    except Exception:
        uncertain = {
            "status": "LIVE_GET_OUTCOME_UNCERTAIN",
            "reason": "read session failed; details were redacted",
            "request_outcome": "UNCERTAIN_NO_RETRY",
            "groups_queried": None,
            "live_calls_performed": None,
            "actions_performed": False,
            "reallocation_enabled": False,
        }
        try:
            service.store.append_audit(
                "MANUAL_SALAD_GET_OUTCOME_UNCERTAIN",
                {key: value for key, value in uncertain.items() if key != "reason"},
                datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            )
        except Exception:
            pass
        return uncertain
    try:
        return service.persist_live_read_result(raw, local_tls_test=read_session.is_local_tls_test)
    except Exception:
        rows = raw.get("groups") if isinstance(raw, dict) else None
        attempts = sum(
            1
            for row in rows
            if isinstance(row, dict) and row.get("live_call_attempted") is True
        ) if isinstance(rows, list) else None
        return {
            "status": "LIVE_RESULT_PERSISTENCE_FAILED",
            "reason": "read result could not be stored; details were redacted and no retry was made",
            "request_outcome": "COMPLETED_OR_UNCERTAIN_NO_RETRY",
            "groups_queried": attempts,
            "live_calls_performed": raw.get("live_calls_performed") if isinstance(raw, dict) else None,
            "actions_performed": False,
            "reallocation_enabled": False,
        }


class _NoCredentialSecretProvider:
    """Local build has no credential source; acquiring a key always fails closed."""

    def __init__(self):
        self.read_attempts = 0

    def acquire(self):
        self.read_attempts += 1
        raise RuntimeError("credentials are unavailable in the offline G5 service")


class _PermanentlyClosedDispatchGate:
    """The composed production sender remains closed in this offline build."""

    enabled = False


def _offline_action_executor(config: G5Config, ledger: ActionLedger, store: ControlPlaneStore) -> SaladActionExecutor:
    return SaladActionExecutor(
        policy=SaladActionPolicy(hard_budget_usd=config.hard_budget_usd),
        ledger=ledger,
        transport=RestrictedSaladActionHTTPTransport(enabled=False),
        secret_provider=_NoCredentialSecretProvider(),
        kill_switch=_PermanentlyClosedDispatchGate(),
        clock=time.time,
        dossier_authority=DecisionDossierAuthority(),
        budget_store=store,
    )


def build_service(config: G5Config) -> G5ControlPlaneService:
    """Open file-backed local state so monitor and action history survive restart."""
    state_dir = Path(config.state_dir).expanduser()
    state_dir.mkdir(parents=True, exist_ok=True)
    control_store = ControlPlaneStore(state_dir / "control-plane.sqlite3")
    action_ledger = ActionLedger(state_dir / "actions.sqlite3")
    service = G5ControlPlaneService(
        config,
        control_store=control_store,
        guard_store=GuardStore(state_dir / "guard.sqlite3"),
        action_ledger=action_ledger,
        action_executor=_offline_action_executor(config, action_ledger, control_store),
    )
    try:
        service.ingest_configured_local_events()
        service.evaluate_control_cycle()
    except Exception:
        service.close()
        raise
    return service


class ManualLiveGETSetupError(RuntimeError):
    """Local authorization/session setup failed without exposing file contents."""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _read_bounded_file(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        resolved = path.expanduser().resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size > maximum_bytes:
            raise ValueError
        content = resolved.read_bytes()
        if not content or len(content) > maximum_bytes:
            raise ValueError
        return content
    except Exception:
        raise ManualLiveGETSetupError("authorization material is unavailable or invalid") from None


def _load_signed_get_authorization(
    authorization_file: Path,
    trust_anchor_file: Path,
    *,
    run_id: str,
    now_epoch: float,
):
    """Load a signed one-run capability and a separately provisioned public trust anchor.

    Neither file contains the Salad API key. The key is acquired later, only by
    InteractiveSecretProvider after the durable request slot and TTY gates.
    """
    if authorization_file.expanduser().resolve() == trust_anchor_file.expanduser().resolve():
        raise ManualLiveGETSetupError("authorization material is unavailable or invalid")
    try:
        envelope = json.loads(
            _read_bounded_file(authorization_file, maximum_bytes=8192).decode("utf-8"),
            object_pairs_hook=_strict_json_object,
        )
        if type(envelope) is not dict or set(envelope) != {"payload_b64", "signature_b64"}:
            raise ValueError
        if not all(type(envelope[name]) is str for name in envelope):
            raise ValueError
        payload = base64.b64decode(envelope["payload_b64"], validate=True)
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
        anchor_text = _read_bounded_file(trust_anchor_file, maximum_bytes=256).decode("ascii").strip()
        public_key = base64.b64decode(anchor_text, validate=True)
        if len(public_key) != 32:
            raise ValueError

        g4c_root = str(Path(__file__).resolve().parents[2] / "g4c-live")
        inserted = g4c_root not in sys.path
        if inserted:
            sys.path.insert(0, g4c_root)
        try:
            from live_secret_boundary import SaladAuthorizationVerifier, SignedSaladAuthorization
        finally:
            if inserted:
                try:
                    sys.path.remove(g4c_root)
                except ValueError:
                    pass

        grant = SignedSaladAuthorization(payload, signature)
        verifier = SaladAuthorizationVerifier(public_key)
        groups = ("fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4")
        if not all(
            verifier.verify_get(
                grant,
                run_id=run_id,
                container_group=group,
                now_epoch=now_epoch,
            )
            for group in groups
        ):
            raise ValueError
        return grant, verifier
    except ManualLiveGETSetupError:
        raise
    except Exception:
        raise ManualLiveGETSetupError("authorization material is unavailable or invalid") from None


def _live_get_types():
    g4c_root = str(Path(__file__).resolve().parents[2] / "g4c-live")
    inserted = g4c_root not in sys.path
    if inserted:
        sys.path.insert(0, g4c_root)
    try:
        from broker_ledger import BrokerLedger, LIVE_SALAD_GET, initialize_ledger
        from broker_offline import KillSwitch
        from live_broker_gate import LiveSaladReadSession
        from live_https_transport import ProductionSaladTransport
        from live_secret_boundary import InteractiveSecretProvider
        return (
            BrokerLedger,
            LIVE_SALAD_GET,
            initialize_ledger,
            KillSwitch,
            LiveSaladReadSession,
            ProductionSaladTransport,
            InteractiveSecretProvider,
        )
    except Exception:
        raise ManualLiveGETSetupError("fixed read-session implementation is unavailable") from None
    finally:
        if inserted:
            try:
                sys.path.remove(g4c_root)
            except ValueError:
                pass


def build_manual_live_read_session(
    ledger_path: Path,
    authorization_file: Path,
    trust_anchor_file: Path,
    *,
    transport_factory: Callable[..., Any] | None = None,
    now_epoch: float | None = None,
):
    """Open the preinitialized four-slot ledger and compose the fixed GET session."""
    (
        BrokerLedger,
        live_mode,
        _initialize_ledger,
        KillSwitch,
        LiveSaladReadSession,
        ProductionSaladTransport,
        InteractiveSecretProvider,
    ) = _live_get_types()
    try:
        ledger = BrokerLedger.open(ledger_path, expected_mode=live_mode)
        snapshot = ledger.snapshot()
    except Exception:
        raise ManualLiveGETSetupError("a prepared, unused live-read ledger is required") from None
    now = time.time() if now_epoch is None else now_epoch
    grant, verifier = _load_signed_get_authorization(
        authorization_file,
        trust_anchor_file,
        run_id=snapshot["run_id"],
        now_epoch=now,
    )
    factory = ProductionSaladTransport if transport_factory is None else transport_factory
    try:
        transport = factory(enabled=True, authorization_grant=grant, authorization_verifier=verifier)
        if type(transport) is not ProductionSaladTransport:
            raise TypeError
        return LiveSaladReadSession(
            ledger,
            transport=transport,
            secret_provider=InteractiveSecretProvider(enabled=True),
            kill_switch=KillSwitch(enabled=True),
            live_enabled=True,
        )
    except Exception:
        raise ManualLiveGETSetupError("fixed read-session setup is unavailable") from None


def _summary_for_terminal(result: dict[str, Any]) -> dict[str, Any]:
    """Return only status metadata; never print response payloads or secret material."""
    allowed = (
        "status",
        "groups_queried",
        "observations_saved",
        "data_classification",
        "live_calls_performed",
        "local_tls_test_requests_performed",
        "actions_performed",
        "reallocation_enabled",
    )
    summary = {key: result[key] for key in allowed if key in result}
    rows = result.get("groups")
    if isinstance(rows, list):
        summary["groups"] = [
            {key: item[key] for key in ("container_group", "state") if key in item}
            for item in rows
            if isinstance(item, dict)
        ]
    return summary


def _prepare_live_get_ledger(config: G5Config, ledger_path: Path | None) -> dict[str, Any]:
    _BrokerLedger, live_mode, initialize_ledger, _KillSwitch, _Session, _Transport, _SecretProvider = _live_get_types()
    selected_path = ledger_path
    if selected_path is None:
        selected_path = Path(config.state_dir).expanduser() / f"live-get-{uuid.uuid4().hex}.sqlite3"
    try:
        ledger = initialize_ledger(selected_path, now=time.time(), run_mode=live_mode)
        snapshot = ledger.snapshot()
    except Exception:
        raise ManualLiveGETSetupError("a new local ledger could not be prepared") from None
    return {
        "status": "LIVE_GET_LEDGER_PREPARED",
        "ledger_path": str(Path(selected_path).expanduser().resolve()),
        "run_id": snapshot["run_id"],
        "expires_at_epoch": snapshot["expires_at"],
        "maximum_requests": 4,
        "live_calls_performed": False,
        "actions_performed": False,
    }


def main(
    argv: list[str] | None = None,
    *,
    live_transport_factory: Callable[..., Any] | None = None,
    stdin: Any = None,
    input_fn: Callable[[str], str] | None = None,
    stdout: Any = None,
) -> int:
    parser = argparse.ArgumentParser(description="Run the local offline Salad GPU dashboard")
    parser.add_argument("--config", type=Path, default=None, help="optional JSON config; defaults are overridden by the operational environment allowlist")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--prepare-live-get-ledger",
        action="store_true",
        help="prepare a fresh durable four-request ledger; performs no network access",
    )
    mode.add_argument(
        "--manual-live-get",
        action="store_true",
        help="run the fixed four-group GET session after signed authorization and hidden TTY secret entry",
    )
    parser.add_argument("--ledger-path", type=Path, default=None, help="new path for prepare mode; existing prepared path for manual GET mode")
    parser.add_argument("--authorization-file", type=Path, default=None, help="signed one-run GET grant JSON; never the Salad API key")
    parser.add_argument("--trust-anchor-file", type=Path, default=None, help="separately provisioned base64 Ed25519 public key")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    output = sys.stdout if stdout is None else stdout

    if args.prepare_live_get_ledger:
        if args.authorization_file is not None or args.trust_anchor_file is not None:
            parser.error("authorization files are only valid with --manual-live-get")
        try:
            print(json.dumps(_prepare_live_get_ledger(config, args.ledger_path), sort_keys=True), file=output)
            return 0
        except ManualLiveGETSetupError as exc:
            print(json.dumps({"status": "LIVE_GET_PREPARATION_BLOCKED", "reason": str(exc)}, sort_keys=True), file=output)
            return 2

    if args.manual_live_get:
        if args.ledger_path is None or args.authorization_file is None or args.trust_anchor_file is None:
            parser.error("--manual-live-get requires --ledger-path, --authorization-file, and --trust-anchor-file")
        terminal = sys.stdin if stdin is None else stdin
        try:
            interactive = terminal.isatty() is True
        except Exception:
            interactive = False
        if not interactive:
            print(json.dumps({"status": "LIVE_GET_BLOCKED", "reason": "interactive terminal required", "live_calls_performed": False}, sort_keys=True), file=output)
            return 2
        try:
            session = build_manual_live_read_session(
                args.ledger_path,
                args.authorization_file,
                args.trust_anchor_file,
                transport_factory=live_transport_factory,
            )
        except ManualLiveGETSetupError as exc:
            print(json.dumps({"status": "LIVE_GET_BLOCKED", "reason": str(exc), "live_calls_performed": False, "actions_performed": False}, sort_keys=True), file=output)
            return 2
        service = build_service(config)
        try:
            result = run_manual_live_get(service, session, stdin=terminal, input_fn=input_fn)
            print(json.dumps(_summary_for_terminal(result), sort_keys=True), file=output)
            return 0 if result.get("status") == "ALL_GROUPS_OBSERVED" else 2
        finally:
            service.close()

    if args.ledger_path is not None or args.authorization_file is not None or args.trust_anchor_file is not None:
        parser.error("live-read options require --prepare-live-get-ledger or --manual-live-get")
    service = build_service(config)
    server = create_server(service, config.host, config.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        service.close()
    return 0


if __name__ == "__main__":
    main()
