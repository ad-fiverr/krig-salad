"""Offline tests for at-most-one central Telegram delivery and SQLite states."""

from __future__ import annotations

from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from log_alerts.central_telegram import (  # noqa: E402
    CentralTelegramSender,
    SyntheticTelegramSecretProvider,
    TelegramSecretError,
)
from log_alerts.contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED  # noqa: E402
from log_alerts.delivery import DeliveryCoordinator  # noqa: E402
from log_alerts.ledger import SQLiteAlertLedger  # noqa: E402


NOW = "2026-10-13T12:01:00Z"
ORG = "adrianfiverr"
QUERY_HASH = "f" * 64
ALERT_KEY = "a" * 64


def _post_boundary_test_seed(
    ledger: SQLiteAlertLedger, *, allow_delivery: bool = True,
    machine_id: str | None = "unit-test-machine",
) -> str:
    """Seed a post-validation ledger row, not a synthetic Salad response.

    The fixture is only for exercising delivery persistence after the trusted
    transport boundary. Tests use the offline sender and never issue HTTP.
    """
    identity = {
        "identity_status": PROVIDER_OBSERVED if machine_id is not None else "UNKNOWN",
        "machine_id": machine_id,
        "instance_id": "unit-test-instance",
        "container_group_name": "unit-test-group",
        "organization_name": ORG,
        "project_name": "unit-test-project",
        "identity_source": "resource.labels",
    }
    payload = {
        "data_classification": PROVIDER_OBSERVED,
        "query_organization": ORG,
        "event_type": "POOL_CONNECTION_FAILED",
        "alert_id": None,
        "event_time_utc": NOW,
        "resource_type": "salad.container_group_instance",
        "identity": identity,
        "event_source": "text_log",
        "event_fields": {"reason": "MINING_AUTHORIZE_RESPONSE_TIMEOUT", "retry_seconds": 10},
        "source_evidence_sha256": "b" * 64,
        "source_log_reference": None,
        "actions_performed": False,
    }
    item = {
        "dedupe_key": ALERT_KEY,
        "event_type": "POOL_CONNECTION_FAILED",
        "event_time_utc": NOW,
        "identity_key": "c" * 64,
        "identity_status": PROVIDER_OBSERVED if machine_id is not None else "UNKNOWN",
        "machine_id": identity["machine_id"],
        "instance_id": identity["instance_id"],
        "container_group_name": identity["container_group_name"],
        "alert_id": None,
        "source_evidence_sha256": "b" * 64,
        "source_log_ref": None,
        "payload": payload,
        "message_text": (
            "ALERT: POOL_CONNECTION_FAILED\n"
            "Reason: MINING_AUTHORIZE_RESPONSE_TIMEOUT\n"
            "Retry: 10s\nEvidence: PROVIDER_OBSERVED\nActions performed: false"
        ),
    }
    return_item = ledger.commit_cycle(
        [item],
        cursor_time_utc=NOW,
        committed_at_utc=NOW,
        data_classification=PROVIDER_OBSERVED,
        live_scope={
            "organization_name": ORG,
            "operation": "READ_LOG_QUERY",
            "query_sha256": QUERY_HASH,
            "data_classification": PROVIDER_OBSERVED,
        },
        allow_provider_delivery=allow_delivery,
        # This direct unit seed intentionally does not simulate a Salad HTTP
        # response. The production commit path requires sealed transport evidence.
        provider_response_evidence=_internal_test_response_evidence(),
    )
    return return_item[0]["dedupe_key"]


def _post_boundary_cuda_test_seed(ledger: SQLiteAlertLedger) -> str:
    """Seed one validated CUDA event whose provider Machine ID is unknown."""
    identity = {
        "identity_status": "UNKNOWN",
        "machine_id": None,
        "instance_id": "unit-test-instance",
        "container_group_name": "unit-test-group",
        "organization_name": ORG,
        "project_name": "unit-test-project",
        "identity_source": "resource.labels",
    }
    payload = {
        "data_classification": PROVIDER_OBSERVED,
        "query_organization": ORG,
        "event_type": "CUDA_DRIVER_INCOMPATIBLE",
        "alert_id": "cuda-alert-01",
        "event_time_utc": NOW,
        "resource_type": "salad.container_group_instance",
        "identity": identity,
        "event_source": "text_log",
        "event_fields": {
            "reason": "CUDA_DRIVER_VERSION_INSUFFICIENT",
            "gpu_initialized": False,
            "miner_exit_status": "UNKNOWN",
            "exit_status_confirmed": False,
            "exit_status_event_time_utc": None,
            "exit_evidence_sha256": None,
            "recommendation": "REALLOCATE",
            "actions_performed": False,
        },
        "source_evidence_sha256": "e" * 64,
        "source_log_reference": "cuda-log-record-01",
        "actions_performed": False,
    }
    from log_alerts.engine import _render_message

    item = {
        "dedupe_key": "d" * 64,
        "event_type": "CUDA_DRIVER_INCOMPATIBLE",
        "event_time_utc": NOW,
        "identity_key": "c" * 64,
        "identity_status": "UNKNOWN",
        "machine_id": None,
        "instance_id": identity["instance_id"],
        "container_group_name": identity["container_group_name"],
        "alert_id": payload["alert_id"],
        "source_evidence_sha256": payload["source_evidence_sha256"],
        "source_log_ref": payload["source_log_reference"],
        "payload": payload,
        "message_text": _render_message(payload),
    }
    committed = ledger.commit_cycle(
        [item],
        cursor_time_utc=NOW,
        committed_at_utc=NOW,
        data_classification=PROVIDER_OBSERVED,
        live_scope={
            "organization_name": ORG,
            "operation": "READ_LOG_QUERY",
            "query_sha256": QUERY_HASH,
            "data_classification": PROVIDER_OBSERVED,
        },
        allow_provider_delivery=True,
        provider_response_evidence=_internal_test_response_evidence(),
    )
    return committed[0]["dedupe_key"]


def _resolved_identity_enrichment(ledger: SQLiteAlertLedger, key: str) -> None:
    row = next(item for item in ledger.list_outbox() if item["dedupe_key"] == key)
    payload = row["payload"]
    identity = dict(payload["identity"])
    identity.update({
        "identity_status": PROVIDER_OBSERVED,
        "machine_id": "unit-test-machine",
        "identity_source": "list_container_group_instances",
    })
    payload["identity"] = identity
    item = {
        "dedupe_key": key,
        "event_type": payload["event_type"],
        "event_time_utc": payload["event_time_utc"],
        "identity_key": "c" * 64,
        "identity_status": PROVIDER_OBSERVED,
        "machine_id": "unit-test-machine",
        "instance_id": identity["instance_id"],
        "container_group_name": identity["container_group_name"],
        "alert_id": None,
        "source_evidence_sha256": payload["source_evidence_sha256"],
        "source_log_ref": None,
        "payload": payload,
        "message_text": (
            "Organization: adrianfiverr\nProject: unit-test-project\n"
            "Container Group: unit-test-group\nMachine ID: unit-test-machine\n"
            "Instance ID: unit-test-instance\nIdentity source: list_container_group_instances\n"
            "ALERT: POOL_CONNECTION_FAILED"
        ),
    }
    ledger.commit_cycle(
        [item],
        cursor_time_utc=NOW,
        committed_at_utc=NOW,
        data_classification=PROVIDER_OBSERVED,
        live_scope={
            "organization_name": ORG,
            "operation": "READ_LOG_QUERY",
            "query_sha256": QUERY_HASH,
            "data_classification": PROVIDER_OBSERVED,
        },
        allow_provider_delivery=True,
        provider_response_evidence=_internal_test_response_evidence(),
    )


def _internal_test_response_evidence():
    # Import and construct through the transport-owned factory used solely in
    # this state-machine unit test. No fake network response is returned.
    import log_alerts.live_transport as transport_module

    return (transport_module.ProviderResponseEvidence(
        source="salad_https_fixed_route",
        classification=PROVIDER_OBSERVED,
        status_code=200,
        response_sha256="d" * 64,
        _authority=transport_module._PROVIDER_RESPONSE_AUTHORITY,
    ),)


class DeliveryLedgerTests(unittest.TestCase):
    def _sender(self, responder):
        credentials = SyntheticTelegramSecretProvider().acquire()
        return CentralTelegramSender.for_offline_test(credentials=credentials, responder=responder)

    def test_fixed_telegram_https_request_has_exactly_one_host_header(self):
        class FakeResponse:
            status = 200

            @staticmethod
            def read(_maximum):
                return b'{"ok":true}'

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

        sender = CentralTelegramSender(credentials=SyntheticTelegramSecretProvider().acquire())
        with (
            patch("log_alerts.central_telegram.PRODUCTION_TELEGRAM_ALLOWED", True),
            patch("log_alerts.central_telegram.http.client.HTTPSConnection", FakeConnection),
        ):
            result = sender.send_provider_alert(
                payload={"data_classification": PROVIDER_OBSERVED, "actions_performed": False},
                message_text="synthetic transport test",
            )
        self.assertEqual(result.state, "SENT")
        self.assertEqual(FakeConnection.last.host, "api.telegram.org")
        self.assertEqual(FakeConnection.last.port, 443)
        host_headers = [value for name, value in FakeConnection.last.headers if name.casefold() == "host"]
        self.assertEqual(host_headers, ["api.telegram.org"])
        self.assertTrue(FakeConnection.last.putrequest_args[1]["skip_host"])

    def test_success_is_claimed_once_and_token_never_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "delivery.sqlite3"
            ledger = SQLiteAlertLedger(db_path)
            key = _post_boundary_test_seed(ledger)
            calls = []

            def responder(host, path, body):
                calls.append((host, path, body))
                return 200, b'{"ok":true,"result":{"message_id":4}}'

            sender = self._sender(responder)
            coordinator = DeliveryCoordinator(ledger, sender)
            result = coordinator.dispatch_new([key, key], now_utc=NOW)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0].state, "SENT")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], "api.telegram.org")
            self.assertIn("/botSYNTHETIC_ONLY_NOT_A_CREDENTIAL/sendMessage", calls[0][1])
            self.assertNotIn("SYNTHETIC_ONLY_NOT_A_CREDENTIAL", calls[0][2].decode())
            self.assertNotIn("SYNTHETIC_ONLY_NOT_A_CREDENTIAL", repr(sender))
            self.assertNotIn("SYNTHETIC_ONLY_NOT_A_CREDENTIAL", repr(ledger.list_deliveries()))
            ledger.close()
            persisted = db_path.read_bytes()
            self.assertNotIn(b"SYNTHETIC_ONLY_NOT_A_CREDENTIAL", persisted)

    def test_ambiguous_send_is_not_retried_after_process_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "uncertain.sqlite3"
            ledger = SQLiteAlertLedger(db_path)
            key = _post_boundary_test_seed(ledger)
            claimed = ledger.claim_delivery(key, claimed_at_utc=NOW)
            self.assertIsNotNone(claimed)
            self.assertEqual(ledger.list_deliveries()[0]["state"], "DISPATCHING")
            ledger.close()

            reopened = SQLiteAlertLedger(db_path)
            self.assertEqual(reopened.list_deliveries()[0]["state"], "DELIVERY_UNKNOWN")
            calls = []
            sender = self._sender(lambda *_args: calls.append(True))
            attempts = DeliveryCoordinator(reopened, sender).dispatch_new([key], now_utc=NOW)
            self.assertEqual(attempts, ())
            self.assertEqual(calls, [])
            self.assertEqual(reopened.list_deliveries()[0]["attempt_count"], 1)
            reopened.close()

    def test_delivery_unknown_stays_terminal_when_machine_identity_is_enriched(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "unknown-enriched.sqlite3"
            ledger = SQLiteAlertLedger(db_path)
            key = _post_boundary_test_seed(ledger, machine_id=None)
            calls = []
            sender = self._sender(
                lambda *_args: (calls.append("send") or (_ for _ in ()).throw(RuntimeError("ambiguous")))
            )
            first = DeliveryCoordinator(ledger, sender).dispatch_new([key], now_utc=NOW)
            self.assertEqual(first[0].state, "DELIVERY_UNKNOWN")
            self.assertEqual(calls, ["send"])
            ledger.close()

            reopened = SQLiteAlertLedger(db_path)
            _resolved_identity_enrichment(reopened, key)
            self.assertEqual(reopened.list_outbox()[0]["payload"]["identity"]["machine_id"], "unit-test-machine")
            self.assertEqual(reopened.list_deliveries()[0]["state"], "DELIVERY_UNKNOWN")
            self.assertEqual(reopened.list_deliveries()[0]["attempt_count"], 1)
            second = DeliveryCoordinator(reopened, sender).dispatch_new([key], now_utc=NOW)
            self.assertEqual(second, ())
            self.assertEqual(calls, ["send"])
            self.assertEqual(reopened.list_deliveries()[0]["state"], "DELIVERY_UNKNOWN")
            reopened.close()

    def test_cuda_identity_enrichment_preserves_canonical_audit_and_terminal_delivery(self):
        for terminal_state in ("SENT", "DELIVERY_UNKNOWN"):
            with self.subTest(state=terminal_state), tempfile.TemporaryDirectory() as directory:
                db_path = Path(directory) / "cuda-identity-enriched.sqlite3"
                ledger = SQLiteAlertLedger(db_path)
                key = _post_boundary_cuda_test_seed(ledger)
                calls = []

                def responder(*_args):
                    calls.append("send")
                    if terminal_state == "DELIVERY_UNKNOWN":
                        raise RuntimeError("ambiguous response")
                    return 200, b'{"ok":true,"result":{"message_id":8}}'

                sender = self._sender(responder)
                first = DeliveryCoordinator(ledger, sender).dispatch_new([key], now_utc=NOW)
                self.assertEqual(first[0].state, terminal_state)
                self.assertEqual(calls, ["send"])
                original = ledger.list_outbox()[0]["message_text"]
                for audit in (
                    f"Event time: {NOW}",
                    "Alert ID: cuda-alert-01",
                    "Evidence: PROVIDER_OBSERVED",
                ):
                    self.assertIn(audit, original)
                ledger.close()

                reopened = SQLiteAlertLedger(db_path)
                _resolved_identity_enrichment(reopened, key)
                enriched = reopened.list_outbox()[0]
                self.assertEqual(enriched["payload"]["identity"]["machine_id"], "unit-test-machine")
                self.assertEqual(enriched["message_text"].splitlines()[:6], [
                    f"Organization: {ORG}",
                    "Project: unit-test-project",
                    "Container Group: unit-test-group",
                    "Machine ID: unit-test-machine",
                    "Instance ID: unit-test-instance",
                    "Identity source: list_container_group_instances",
                ])
                for audit in (
                    f"Event time: {NOW}",
                    "Alert ID: cuda-alert-01",
                    "Evidence: PROVIDER_OBSERVED",
                ):
                    self.assertIn(audit, enriched["message_text"])
                self.assertEqual(reopened.list_deliveries()[0]["state"], terminal_state)
                self.assertEqual(reopened.list_deliveries()[0]["attempt_count"], 1)
                reopened.close()

                persisted = SQLiteAlertLedger(db_path)
                final_row = persisted.list_outbox()[0]
                self.assertEqual(final_row["message_text"], enriched["message_text"])
                for audit in (
                    f"Event time: {NOW}",
                    "Alert ID: cuda-alert-01",
                    "Evidence: PROVIDER_OBSERVED",
                ):
                    self.assertIn(audit, final_row["message_text"])
                self.assertEqual(persisted.list_deliveries()[0]["state"], terminal_state)
                second = DeliveryCoordinator(persisted, sender).dispatch_new([key], now_utc=NOW)
                self.assertEqual(second, ())
                self.assertEqual(calls, ["send"])
                self.assertEqual(persisted.list_deliveries()[0]["attempt_count"], 1)
                persisted.close()

    def test_pending_alert_is_not_scanned_or_sent_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "pending.sqlite3"
            ledger = SQLiteAlertLedger(db_path)
            key = _post_boundary_test_seed(ledger)
            self.assertEqual(ledger.list_deliveries()[0]["state"], "PENDING")
            ledger.close()
            reopened = SQLiteAlertLedger(db_path)
            calls = []
            sender = self._sender(lambda *_args: calls.append(True))
            attempts = DeliveryCoordinator(reopened, sender).dispatch_new([], now_utc=NOW)
            self.assertEqual(attempts, ())
            self.assertEqual(calls, [])
            self.assertEqual(reopened.list_deliveries()[0]["state"], "PENDING")
            self.assertEqual(reopened.list_deliveries()[0]["attempt_count"], 0)
            reopened.close()

    def test_ambiguous_transport_and_explicit_http_failure_are_terminal(self):
        for expected, responder in (
            ("DELIVERY_UNKNOWN", lambda *_args: (_ for _ in ()).throw(RuntimeError("token secret"))),
            ("FAILED", lambda *_args: (429, b'{"error":"rate limited"}')),
        ):
            with self.subTest(expected=expected):
                ledger = SQLiteAlertLedger()
                key = _post_boundary_test_seed(ledger)
                sender = self._sender(responder)
                coordinator = DeliveryCoordinator(ledger, sender)
                first = coordinator.dispatch_new([key], now_utc=NOW)
                second = coordinator.dispatch_new([key], now_utc=NOW)
                self.assertEqual(first[0].state, expected)
                self.assertEqual(second, ())
                row = ledger.list_deliveries()[0]
                self.assertEqual(row["state"], expected)
                self.assertEqual(row["attempt_count"], 1)
                self.assertNotIn("token secret", repr(row))
                ledger.close()

    def test_malformed_success_response_is_delivery_unknown(self):
        ledger = SQLiteAlertLedger()
        key = _post_boundary_test_seed(ledger)
        sender = self._sender(lambda *_args: (200, b"not-json"))
        result = DeliveryCoordinator(ledger, sender).dispatch_new([key], now_utc=NOW)
        self.assertEqual(result[0].state, "DELIVERY_UNKNOWN")
        self.assertEqual(result[0].failure_code, "RESPONSE_INVALID")
        ledger.close()

    def test_synthetic_outbox_never_queues_or_sends(self):
        ledger = SQLiteAlertLedger()
        synthetic_payload = {
            "data_classification": DATA_CLASSIFICATION,
            "actions_performed": False,
        }
        sender = self._sender(lambda *_args: (200, b'{"ok":true}'))
        with self.assertRaises(TelegramSecretError):
            sender.send_provider_alert(payload=synthetic_payload, message_text="synthetic")
        self.assertEqual(ledger.list_deliveries(), [])
        ledger.close()

    def test_live_scope_cannot_change_or_mix_with_fixture_data(self):
        ledger = SQLiteAlertLedger()
        key = _post_boundary_test_seed(ledger, allow_delivery=False)
        self.assertEqual(ledger.list_deliveries(), [])
        with self.assertRaises(Exception):
            ledger.assert_live_scope({
                "organization_name": ORG,
                "operation": "READ_LOG_QUERY",
                "query_sha256": "e" * 64,
                "data_classification": PROVIDER_OBSERVED,
            })
        self.assertIsNone(ledger.claim_delivery(key, claimed_at_utc=NOW))
        self.assertEqual(ledger.list_deliveries(), [])
        ledger.close()


if __name__ == "__main__":
    unittest.main()
