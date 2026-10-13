"""Central, one-shot Telegram sender; production HTTP remains hard-disabled."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import getpass
import http.client
import json
import ssl
import sys
from typing import Any, Callable

from .contract import PROVIDER_OBSERVED


PRODUCTION_TELEGRAM_ALLOWED = False
TELEGRAM_HOST = "api.telegram.org"
TELEGRAM_PORT = 443
TELEGRAM_TIMEOUT_SECONDS = 10.0
MAX_TELEGRAM_RESPONSE_BYTES = 8_192
MAX_TELEGRAM_TEXT_CHARS = 4_096


class TelegramSecretError(RuntimeError):
    """A Telegram credential is not available through an approved boundary."""


@dataclass(frozen=True, slots=True)
class TelegramToken:
    _value: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._value, str) or not 8 <= len(self._value) <= 512:
            raise TelegramSecretError("Telegram token format is invalid")
        if any(ord(char) < 33 or ord(char) > 126 for char in self._value):
            raise TelegramSecretError("Telegram token format is invalid")

    def reveal_for_request(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "TelegramToken([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"


@dataclass(frozen=True, slots=True)
class TelegramCredentials:
    token: TelegramToken = field(repr=False)
    chat_id: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.token) is not TelegramToken:
            raise TelegramSecretError("Telegram token source is invalid")
        if not isinstance(self.chat_id, str) or not 1 <= len(self.chat_id) <= 128:
            raise TelegramSecretError("Telegram chat identifier is invalid")
        if any(ord(char) < 33 or ord(char) > 126 for char in self.chat_id):
            raise TelegramSecretError("Telegram chat identifier is invalid")

    def __repr__(self) -> str:
        return "TelegramCredentials(token=[REDACTED], chat_id=[REDACTED])"


class InteractiveTelegramSecretProvider:
    """Acquire bot token and chat ID once from hidden interactive TTY input."""

    __slots__ = ("_enabled", "_credentials")

    def __init__(self, *, enabled: bool = False):
        if type(enabled) is not bool:
            raise TypeError("Telegram secret gate must be boolean")
        self._enabled = enabled
        self._credentials: TelegramCredentials | None = None

    def acquire(self) -> TelegramCredentials:
        if not self._enabled or not sys.stdin.isatty():
            raise TelegramSecretError("interactive Telegram secret access is disabled")
        if self._credentials is not None:
            return self._credentials
        try:
            token = getpass.getpass("Telegram bot token (input hidden): ")
            chat_id = getpass.getpass("Telegram chat ID (input hidden): ")
            self._credentials = TelegramCredentials(TelegramToken(token), chat_id)
            return self._credentials
        except TelegramSecretError:
            raise
        except Exception:
            raise TelegramSecretError("interactive Telegram credential acquisition failed") from None


class SyntheticTelegramSecretProvider:
    """Fixed fake credentials for offline sender tests only."""

    __slots__ = ("_read_count",)

    def __init__(self):
        self._read_count = 0

    @property
    def read_count(self) -> int:
        return self._read_count

    def acquire(self) -> TelegramCredentials:
        self._read_count += 1
        return TelegramCredentials(TelegramToken("SYNTHETIC_ONLY_NOT_A_CREDENTIAL"), "SYNTHETIC_CHAT")


@dataclass(frozen=True, slots=True)
class TelegramSendResult:
    state: str
    http_status: int | None = None
    failure_code: str | None = None


class CentralTelegramSender:
    """Fixed-host sender; the only default behavior is blocked/no network."""

    __slots__ = ("_credentials", "_offline_responder")

    def __init__(self, *, credentials: TelegramCredentials, offline_responder: Callable[..., Any] | None = None):
        if type(credentials) is not TelegramCredentials:
            raise TypeError("typed Telegram credentials are required")
        if offline_responder is not None and not callable(offline_responder):
            raise TypeError("offline responder must be callable")
        self._credentials = credentials
        self._offline_responder = offline_responder

    @classmethod
    def for_offline_test(
        cls, *, credentials: TelegramCredentials, responder: Callable[..., Any],
    ) -> "CentralTelegramSender":
        return cls(credentials=credentials, offline_responder=responder)

    def __repr__(self) -> str:
        return "CentralTelegramSender(host='api.telegram.org', credentials=[REDACTED], enabled=False)"

    def send_provider_alert(
        self, *, payload: Mapping[str, Any], message_text: str,
    ) -> TelegramSendResult:
        if not isinstance(payload, Mapping) or payload.get("data_classification") != PROVIDER_OBSERVED:
            raise TelegramSecretError("only provider-observed alerts are eligible for delivery")
        if payload.get("actions_performed") is not False:
            raise TelegramSecretError("alert action status is invalid")
        if not isinstance(message_text, str) or not message_text or len(message_text) > MAX_TELEGRAM_TEXT_CHARS:
            raise TelegramSecretError("Telegram message is outside local limits")
        if self._offline_responder is not None:
            return self._send_offline(message_text)
        if PRODUCTION_TELEGRAM_ALLOWED is not True:
            raise TelegramSecretError("Telegram production delivery is disabled")
        return self._send_https(message_text)

    def _payload(self, text: str) -> bytes:
        try:
            encoded = json.dumps(
                {"chat_id": self._credentials.chat_id, "text": text, "disable_web_page_preview": True},
                separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise TelegramSecretError("Telegram request is invalid") from None
        if len(encoded) > 16_384:
            raise TelegramSecretError("Telegram request exceeds local limits")
        return encoded

    def _send_offline(self, text: str) -> TelegramSendResult:
        body = self._payload(text)
        # The token appears only in a fake in-memory URL; do not retain or
        # return it. The fake is explicit and has no network capability.
        path = f"/bot{self._credentials.token.reveal_for_request()}/sendMessage"
        try:
            response = self._offline_responder(TELEGRAM_HOST, path, body)
        except Exception:
            return TelegramSendResult("DELIVERY_UNKNOWN", failure_code="TRANSPORT_AMBIGUOUS")
        return _classify_response(response)

    def _send_https(self, text: str) -> TelegramSendResult:
        conn: http.client.HTTPSConnection | None = None
        body = self._payload(text)
        path = f"/bot{self._credentials.token.reveal_for_request()}/sendMessage"
        request_started = False
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            conn = http.client.HTTPSConnection(
                TELEGRAM_HOST, TELEGRAM_PORT, timeout=TELEGRAM_TIMEOUT_SECONDS, context=context,
            )
            conn.connect()
            if conn.sock is not None:
                conn.sock.settimeout(TELEGRAM_TIMEOUT_SECONDS)
            conn.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", TELEGRAM_HOST)
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Accept", "application/json")
            conn.putheader("Content-Length", str(len(body)))
            request_started = True
            conn.endheaders(body)
            response = conn.getresponse()
            if 300 <= response.status < 400:
                return TelegramSendResult("FAILED", response.status, "HTTP_FAILURE")
            raw = response.read(MAX_TELEGRAM_RESPONSE_BYTES + 1)
            if len(raw) > MAX_TELEGRAM_RESPONSE_BYTES:
                return TelegramSendResult("DELIVERY_UNKNOWN", response.status, "RESPONSE_INVALID")
            return _classify_response((response.status, raw))
        except Exception:
            # Even a TLS/socket failure after request start is treated as
            # uncertain and never retried. Exception text may contain the URL.
            code = "TRANSPORT_AMBIGUOUS" if request_started else "TRANSPORT_AMBIGUOUS"
            return TelegramSendResult("DELIVERY_UNKNOWN", failure_code=code)
        finally:
            if conn is not None:
                conn.close()


def _classify_response(response: Any) -> TelegramSendResult:
    if not isinstance(response, tuple) or len(response) != 2:
        return TelegramSendResult("DELIVERY_UNKNOWN", failure_code="RESPONSE_INVALID")
    status, raw = response
    if type(status) is not int or not 100 <= status <= 599 or not isinstance(raw, bytes):
        return TelegramSendResult("DELIVERY_UNKNOWN", failure_code="RESPONSE_INVALID")
    if 300 <= status < 400:
        return TelegramSendResult("FAILED", status, "HTTP_FAILURE")
    if status != 200:
        return TelegramSendResult("FAILED", status, "HTTP_FAILURE")
    if len(raw) > MAX_TELEGRAM_RESPONSE_BYTES:
        return TelegramSendResult("DELIVERY_UNKNOWN", status, "RESPONSE_INVALID")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return TelegramSendResult("DELIVERY_UNKNOWN", status, "RESPONSE_INVALID")
    if not isinstance(body, Mapping) or type(body.get("ok")) is not bool:
        return TelegramSendResult("DELIVERY_UNKNOWN", status, "RESPONSE_INVALID")
    if body["ok"] is True:
        return TelegramSendResult("SENT", status)
    return TelegramSendResult("FAILED", status, "HTTP_FAILURE")
