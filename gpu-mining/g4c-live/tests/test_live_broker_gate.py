from __future__ import annotations

import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

BROKER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BROKER_DIR))

from broker_ledger import BrokerLedger, LIVE_SALAD_GET, initialize_ledger  # noqa: E402
from broker_offline import ContainerGroup, KillSwitch  # noqa: E402
from live_broker_gate import LIVE_GET_ALLOWED, LiveBrokerGate, LiveBrokerScopeError, LiveSaladReadSession  # noqa: E402
from live_https_transport import (  # noqa: E402
    PRODUCTION_NETWORK_ALLOWED,
    LiveHTTPSTransport,
    LoopbackTLSConfig,
    ProductionSaladTransport,
)
from live_managed_secret_adapter import REAL_SECRET_BACKEND_WIRED  # noqa: E402
from live_managed_secret_adapter import ManagedSecretAdapter, SyntheticManagedSecretBackend  # noqa: E402
from live_secret_boundary import (  # noqa: E402
    REAL_SECRET_ACCESS_ALLOWED,
    SYNTHETIC_SECRET_VALUE,
    InteractiveSecretProvider,
    SyntheticSecretProvider,
)
from pilot_scope import CONTAINER_GROUPS  # noqa: E402


def _openssl_path() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    candidate = Path(r"C:\msys64\usr\bin\openssl.exe")
    return str(candidate) if candidate.is_file() else None


class GateLocalTLSServer:
    def __init__(self, *, status: int = 200, body: bytes | None = None, delay: float = 0.0):
        executable = _openssl_path()
        if executable is None:
            raise unittest.SkipTest("local TLS certificate tool unavailable; TLS E2E is UNRUN")
        self._temp = tempfile.TemporaryDirectory(prefix="salad-live-gate-tls-")
        root = Path(self._temp.name)
        self.certificate = root / "server.crt"
        private_key = root / "server.key"
        subprocess.run(
            [
                executable,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(private_key),
                "-out",
                str(self.certificate),
                "-days",
                "1",
                "-subj",
                "/CN=api.salad.com",
                "-addext",
                "subjectAltName=DNS:api.salad.com",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        self.received: list[dict[str, str | None]] = []
        self.status = status
        self.body = body
        self.delay = delay
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):  # noqa: N802
                owner.received.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "host": self.headers.get("Host"),
                        "secret": self.headers.get("Salad-Api-Key"),
                    }
                )
                if owner.delay:
                    time.sleep(owner.delay)
                payload = owner.body
                if payload is None:
                    payload = json.dumps(
                        {"instances": [{"instance_id": "synthetic-shared", "machine_id": "synthetic-machine"}]},
                        separators=(",", ":"),
                    ).encode("utf-8")
                try:
                    self.send_response(owner.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, _format, *args):
                del args

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(str(self.certificate), str(private_key))
        self.server.socket = server_context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = int(self.server.server_address[1])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self._temp.cleanup()


class GateClock:
    def __init__(self, value: float = 1_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value


def _ledger(root: str) -> tuple[Path, BrokerLedger]:
    path = Path(root) / "live-broker.sqlite3"
    initialize_ledger(path, now=1_000.0)
    return path, BrokerLedger.open(path)


class LiveBrokerGateTests(unittest.TestCase):
    def test_all_real_access_gates_are_structurally_closed(self) -> None:
        self.assertFalse(LIVE_GET_ALLOWED)
        self.assertFalse(PRODUCTION_NETWORK_ALLOWED)
        self.assertFalse(REAL_SECRET_BACKEND_WIRED)
        self.assertFalse(REAL_SECRET_ACCESS_ALLOWED)

    def test_defaults_are_off_with_zero_reservations_secret_reads_or_sockets(self) -> None:
        server = GateLocalTLSServer()
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                _path, ledger = _ledger(temp)
                provider = SyntheticSecretProvider()
                broker = LiveBrokerGate(
                    ledger,
                    transport=LiveHTTPSTransport(
                        local_tls=LoopbackTLSConfig(server.port, str(server.certificate))
                    ),
                    secret_provider=provider,
                    clock=GateClock(),
                )
                result = broker.run_all_offline()
                self.assertEqual(result["groups"][0]["state"], "BROKER_DISABLED")
                self.assertEqual(result["request_slots_consumed"], 0)
                self.assertEqual(ledger.snapshot()["request_count"], 0)
                self.assertEqual(provider.read_count, 0)
                self.assertEqual(server.received, [])
                self.assertFalse(result["live_calls_performed"])
        finally:
            server.close()

    def test_live_session_defaults_closed_without_secret_or_socket_access(self) -> None:
        with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
            path = Path(temp) / "read-live.sqlite3"
            ledger = initialize_ledger(path, now=1_000.0, run_mode=LIVE_SALAD_GET)
            provider = InteractiveSecretProvider(enabled=False)
            session = LiveSaladReadSession(
                ledger,
                transport=ProductionSaladTransport(enabled=False),
                secret_provider=provider,
                kill_switch=KillSwitch(enabled=True),
            )
            with patch("live_https_transport.socket.create_connection") as create_connection:
                result = session.run_all()
            self.assertEqual(result["execution_mode"], "LIVE_SALAD_GET_DISABLED")
            self.assertFalse(result["live_calls_performed"])
            self.assertEqual(ledger.snapshot()["request_count"], 0)
            self.assertEqual(provider.read_count, 0)
            create_connection.assert_not_called()

    def test_live_session_requires_signed_capability_even_when_every_boolean_is_enabled(self) -> None:
        with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
            path = Path(temp) / "read-live.sqlite3"
            ledger = initialize_ledger(path, now=1_000.0, run_mode=LIVE_SALAD_GET)
            provider = InteractiveSecretProvider(enabled=True)
            session = LiveSaladReadSession(
                ledger,
                transport=ProductionSaladTransport(enabled=True),
                secret_provider=provider,
                kill_switch=KillSwitch(enabled=True),
                live_enabled=True,
                clock=GateClock(),
            )
            with patch("live_https_transport.socket.create_connection") as connect, patch(
                "live_https_transport.socket.getaddrinfo"
            ) as resolve, patch("live_secret_boundary.getpass.getpass") as prompt:
                result = session.run_all()
            self.assertEqual(result["groups"][0]["state"], "AUTHORIZATION_BLOCKED")
            self.assertEqual(ledger.snapshot()["request_count"], 0)
            self.assertEqual(provider.read_count, 0)
            prompt.assert_not_called()
            connect.assert_not_called()
            resolve.assert_not_called()

    def test_live_session_reserves_first_slot_before_synthetic_secret_access(self) -> None:
        server = GateLocalTLSServer(body=b"not-json")
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                path = Path(temp) / "read-live.sqlite3"
                ledger = initialize_ledger(path, now=1_000.0, run_mode=LIVE_SALAD_GET)
                provider = InteractiveSecretProvider(enabled=True)
                session = LiveSaladReadSession(
                    ledger,
                    transport=ProductionSaladTransport(
                        enabled=True,
                        test_local_port=server.port,
                        test_ca_file=str(server.certificate),
                    ),
                    secret_provider=provider,
                    kill_switch=KillSwitch(enabled=True),
                    live_enabled=True,
                    clock=GateClock(),
                )

                def synthetic_secret_after_reservation():
                    snapshot = ledger.snapshot()
                    self.assertEqual(snapshot["request_count"], 1)
                    self.assertEqual(snapshot["reservations"][0]["status"], "RESERVED")
                    return SyntheticSecretProvider().acquire()

                with patch.object(provider, "acquire", side_effect=synthetic_secret_after_reservation):
                    result = session.run_all()
                self.assertEqual(result["groups"][0]["state"], "RESPONSE_REJECTED")
                self.assertEqual(ledger.snapshot()["request_count"], 1)
                self.assertEqual(ledger.snapshot()["reservations"][0]["status"], "FAILED")
                self.assertEqual(len(server.received), 1)
        finally:
            server.close()

    def test_live_session_does_not_read_secret_when_durable_slot_is_unavailable(self) -> None:
        import sqlite3

        scenarios = ("expired", "uncertain", "exhausted", "corrupt")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                path = Path(temp) / "read-live.sqlite3"
                ledger = initialize_ledger(path, now=1_000.0, run_mode=LIVE_SALAD_GET)
                clock = GateClock()
                if scenario == "expired":
                    clock.value = ledger.snapshot()["expires_at"]
                elif scenario == "uncertain":
                    ledger.reserve_next("fl4shminer", now=1_000.0)
                elif scenario == "exhausted":
                    from broker_ledger import CONTAINER_GROUPS
                    for offset, group in enumerate(CONTAINER_GROUPS):
                        reservation = ledger.reserve_next(group, now=1_000.0 + offset)
                        ledger.record_result(reservation, status="SUCCESS", now=1_000.0 + offset)
                elif scenario == "corrupt":
                    connection = sqlite3.connect(path)
                    try:
                        connection.execute("UPDATE run_metadata SET policy_hash='corrupt'")
                        connection.commit()
                    finally:
                        connection.close()
                provider = InteractiveSecretProvider(enabled=True)
                session = LiveSaladReadSession(
                    ledger,
                    transport=ProductionSaladTransport(enabled=True, test_local_port=1, test_ca_file=__file__),
                    secret_provider=provider,
                    kill_switch=KillSwitch(enabled=True),
                    live_enabled=True,
                    clock=clock,
                )
                with patch("live_https_transport.socket.create_connection") as connect, patch(
                    "live_secret_boundary.getpass.getpass"
                ) as prompt:
                    result = session.run_all()
                self.assertEqual(provider.read_count, 0)
                prompt.assert_not_called()
                connect.assert_not_called()
                self.assertFalse(result["live_calls_performed"])
                if scenario in {"uncertain", "exhausted"}:
                    self.assertIn(result["groups"][0]["state"], {"OUTCOME_UNCERTAIN", "BUDGET_EXHAUSTED"})
                elif scenario == "expired":
                    self.assertEqual(result["groups"][0]["state"], "DEADLINE_BLOCKED")
                else:
                    self.assertEqual(result["groups"][0]["state"], "LEDGER_BLOCKED")

    def test_secret_failure_consumes_first_reserved_slot_and_stops_all_groups(self) -> None:
        with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
            path = Path(temp) / "read-live.sqlite3"
            ledger = initialize_ledger(path, now=1_000.0, run_mode=LIVE_SALAD_GET)
            provider = InteractiveSecretProvider(enabled=True)
            session = LiveSaladReadSession(
                ledger,
                transport=ProductionSaladTransport(enabled=True, test_local_port=1, test_ca_file=__file__),
                secret_provider=provider,
                kill_switch=KillSwitch(enabled=True),
                live_enabled=True,
                clock=GateClock(),
            )
            with patch.object(provider, "acquire", side_effect=RuntimeError("synthetic failure")):
                result = session.run_all()
            snapshot = ledger.snapshot()
            self.assertEqual(snapshot["request_count"], 1)
            self.assertEqual(snapshot["reservations"][0]["status"], "FAILED")
            self.assertEqual(result["groups"][0]["state"], "SECRET_ACCESS_BLOCKED")
            self.assertTrue(all(row["state"] == "NOT_QUERIED" for row in result["groups"][1:]))

    def test_live_schema_rejection_records_that_http_response_was_received(self) -> None:
        server = GateLocalTLSServer(body=b"not-json")
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                path = Path(temp) / "read-live.sqlite3"
                ledger = initialize_ledger(path, now=1_000.0, run_mode=LIVE_SALAD_GET)
                provider = InteractiveSecretProvider(enabled=True)
                session = LiveSaladReadSession(
                    ledger,
                    transport=ProductionSaladTransport(
                        enabled=True,
                        test_local_port=server.port,
                        test_ca_file=str(server.certificate),
                    ),
                    secret_provider=provider,
                    kill_switch=KillSwitch(enabled=True),
                    live_enabled=True,
                    clock=GateClock(),
                )
                with patch("live_secret_boundary.sys.stdin") as stdin, patch(
                    "live_secret_boundary.getpass.getpass", return_value=SYNTHETIC_SECRET_VALUE
                ):
                    stdin.isatty.return_value = True
                    result = session.run_all()
                first = result["groups"][0]
                self.assertEqual(first["state"], "RESPONSE_REJECTED")
                self.assertTrue(first["live_call_attempted"])
                self.assertTrue(first["live_calls_performed"])
                self.assertEqual(result["request_slots_consumed"], 1)
                self.assertEqual(provider.read_count, 1)
                self.assertEqual(len(server.received), 1)
                self.assertFalse(result["actions_performed"])
                self.assertFalse(result["reallocation_enabled"])
        finally:
            server.close()

    def test_production_network_is_blocked_before_slot_secret_dns_or_socket(self) -> None:
        with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
            _path, ledger = _ledger(temp)
            provider = SyntheticSecretProvider()
            broker = LiveBrokerGate(
                ledger,
                transport=LiveHTTPSTransport(),
                secret_provider=provider,
                kill_switch=KillSwitch(enabled=True),
                clock=GateClock(),
            )
            with patch("live_https_transport.socket.create_connection") as create_connection, patch(
                "live_https_transport.socket.getaddrinfo"
            ) as getaddrinfo:
                result = broker.run_next(ContainerGroup.FL4SHMINER)
            self.assertEqual(result["state"], "PRODUCTION_NETWORK_BLOCKED")
            self.assertEqual(ledger.snapshot()["request_count"], 0)
            self.assertEqual(provider.read_count, 0)
            create_connection.assert_not_called()
            getaddrinfo.assert_not_called()

    def test_four_local_tls_requests_are_sequential_and_keep_group_provenance(self) -> None:
        server = GateLocalTLSServer()
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                path, ledger = _ledger(temp)
                backend = SyntheticManagedSecretBackend()
                broker = LiveBrokerGate(
                    ledger,
                    transport=LiveHTTPSTransport(
                        local_tls=LoopbackTLSConfig(server.port, str(server.certificate))
                    ),
                    secret_provider=ManagedSecretAdapter(backend),
                    kill_switch=KillSwitch(enabled=True),
                    clock=GateClock(),
                )
                result = broker.run_all_offline()
                self.assertEqual(result["state"], "ALL_LOCAL_TESTS_COMPLETED")
                self.assertEqual(result["request_slots_consumed"], 4)
                self.assertEqual(
                    [item["container_group"] for item in result["groups"]],
                    list(CONTAINER_GROUPS),
                )
                self.assertEqual([row["path"].split("/")[-2] for row in server.received], list(CONTAINER_GROUPS))
                self.assertEqual([row["method"] for row in server.received], ["GET"] * 4)
                self.assertEqual([row["host"] for row in server.received], ["api.salad.com"] * 4)
                self.assertEqual([row["secret"] for row in server.received], [SYNTHETIC_SECRET_VALUE] * 4)
                self.assertEqual(backend.read_count, 4)
                self.assertEqual(
                    [item["evidence"]["container_group"] for item in result["groups"]],
                    list(CONTAINER_GROUPS),
                )
                self.assertEqual(
                    [item["evidence"]["payload"]["instances"][0]["instance_id"] for item in result["groups"]],
                    ["synthetic-shared"] * 4,
                )
                self.assertTrue(all(item["binding_status"] == "UNKNOWN" for item in result["groups"]))
                self.assertTrue(all(item["billing_status"] == "UNKNOWN" for item in result["groups"]))
                self.assertTrue(all(item["hashrate_attribution"] == "UNKNOWN" for item in result["groups"]))
                self.assertTrue(all(item["data_classification"] == "SYNTHETIC/UNVERIFIED" for item in result["groups"]))
                self.assertNotIn(SYNTHETIC_SECRET_VALUE, json.dumps(result))
                self.assertNotIn(SYNTHETIC_SECRET_VALUE.encode("ascii"), path.read_bytes())
        finally:
            server.close()

    def test_http_failure_consumes_one_slot_and_never_retries(self) -> None:
        server = GateLocalTLSServer(status=302, body=b"synthetic error body")
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                _path, ledger = _ledger(temp)
                backend = SyntheticManagedSecretBackend()
                broker = LiveBrokerGate(
                    ledger,
                    transport=LiveHTTPSTransport(
                        local_tls=LoopbackTLSConfig(server.port, str(server.certificate))
                    ),
                    secret_provider=ManagedSecretAdapter(backend),
                    kill_switch=KillSwitch(enabled=True),
                    clock=GateClock(),
                )
                result = broker.run_all_offline()
                self.assertEqual(result["groups"][0]["state"], "REDIRECT_BLOCKED")
                self.assertEqual(result["groups"][0]["request_slot_consumed"], True)
                self.assertEqual(result["request_slots_consumed"], 1)
                self.assertEqual(len(server.received), 1)
                self.assertEqual(backend.read_count, 1)
                self.assertEqual([item["state"] for item in result["groups"][1:]], ["NOT_QUERIED"] * 3)
                self.assertNotIn("synthetic error body", json.dumps(result))
        finally:
            server.close()

    def test_unsafe_body_is_not_returned_or_persisted(self) -> None:
        body = json.dumps({"instances": [{"token": SYNTHETIC_SECRET_VALUE}]}).encode("utf-8")
        server = GateLocalTLSServer(body=body)
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                path, ledger = _ledger(temp)
                provider = SyntheticSecretProvider()
                broker = LiveBrokerGate(
                    ledger,
                    transport=LiveHTTPSTransport(
                        local_tls=LoopbackTLSConfig(server.port, str(server.certificate))
                    ),
                    secret_provider=provider,
                    kill_switch=KillSwitch(enabled=True),
                    clock=GateClock(),
                )
                result = broker.run_next(ContainerGroup.FL4SHMINER)
                self.assertEqual(result["state"], "INVALID_OR_UNSAFE_JSON")
                self.assertNotIn(SYNTHETIC_SECRET_VALUE, json.dumps(result))
                self.assertNotIn(SYNTHETIC_SECRET_VALUE.encode("ascii"), path.read_bytes())
                self.assertEqual(ledger.snapshot()["reservations"][0]["status"], "FAILED")
        finally:
            server.close()

    def test_secret_backend_failure_after_reservation_is_terminal(self) -> None:
        server = GateLocalTLSServer()
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                _path, ledger = _ledger(temp)
                backend = SyntheticManagedSecretBackend(failure=True)
                broker = LiveBrokerGate(
                    ledger,
                    transport=LiveHTTPSTransport(
                        local_tls=LoopbackTLSConfig(server.port, str(server.certificate))
                    ),
                    secret_provider=ManagedSecretAdapter(backend),
                    kill_switch=KillSwitch(enabled=True),
                    clock=GateClock(),
                )
                result = broker.run_next(ContainerGroup.FL4SHMINER)
                self.assertEqual(result["state"], "SECRET_ACCESS_BLOCKED")
                self.assertEqual(ledger.snapshot()["request_count"], 1)
                self.assertTrue(ledger.snapshot()["halted"])
                self.assertEqual(server.received, [])
                self.assertEqual(backend.read_count, 1)
                self.assertNotIn(SYNTHETIC_SECRET_VALUE, json.dumps(result))
        finally:
            server.close()

    def test_pending_reservation_after_restart_blocks_secret_and_transport(self) -> None:
        server = GateLocalTLSServer()
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                path, ledger = _ledger(temp)
                ledger.reserve_next("fl4shminer", now=1_000.0)
                reopened = BrokerLedger.open(path)
                backend = SyntheticManagedSecretBackend()
                broker = LiveBrokerGate(
                    reopened,
                    transport=LiveHTTPSTransport(
                        local_tls=LoopbackTLSConfig(server.port, str(server.certificate))
                    ),
                    secret_provider=ManagedSecretAdapter(backend),
                    kill_switch=KillSwitch(enabled=True),
                    clock=GateClock(1_001.0),
                )
                result = broker.run_next(ContainerGroup.FL4SHMINER_2)
                self.assertEqual(result["state"], "OUTCOME_UNCERTAIN")
                self.assertEqual(reopened.snapshot()["request_count"], 1)
                self.assertEqual(backend.read_count, 0)
                self.assertEqual(server.received, [])
        finally:
            server.close()

    def test_caller_cannot_select_method_or_route_and_switch_after_reservation_consumes_slot(self) -> None:
        server = GateLocalTLSServer()
        try:
            with tempfile.TemporaryDirectory(prefix="salad-live-ledger-") as temp:
                _path, ledger = _ledger(temp)
                backend = SyntheticManagedSecretBackend()
                switch = KillSwitch(enabled=True)
                broker = LiveBrokerGate(
                    ledger,
                    transport=LiveHTTPSTransport(
                        local_tls=LoopbackTLSConfig(server.port, str(server.certificate))
                    ),
                    secret_provider=ManagedSecretAdapter(backend),
                    kill_switch=switch,
                    clock=GateClock(),
                )
                with self.assertRaises(LiveBrokerScopeError):
                    broker.run_next("fl4shminer")  # type: ignore[arg-type]
                with self.assertRaises(TypeError):
                    broker.run_next(ContainerGroup.FL4SHMINER, method="POST")  # type: ignore[call-arg]
                original_reserve = ledger.reserve_next

                def reserve_then_disable(group: str, *, now: float):
                    reservation = original_reserve(group, now=now)
                    switch.disable()
                    return reservation

                with patch.object(ledger, "reserve_next", side_effect=reserve_then_disable):
                    result = broker.run_next(ContainerGroup.FL4SHMINER)
                self.assertEqual(result["state"], "KILL_SWITCH_TRIPPED")
                self.assertEqual(ledger.snapshot()["request_count"], 1)
                self.assertEqual(backend.read_count, 0)
                self.assertEqual(server.received, [])
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
