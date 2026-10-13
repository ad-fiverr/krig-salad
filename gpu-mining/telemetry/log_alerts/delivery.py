"""One-attempt Telegram delivery state machine backed by the SQLite ledger."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .central_telegram import CentralTelegramSender, TelegramSendResult
from .ledger import SQLiteAlertLedger


@dataclass(frozen=True, slots=True)
class DeliveryAttempt:
    dedupe_key: str
    state: str
    http_status: int | None
    failure_code: str | None


class DeliveryCoordinator:
    """Dispatch only keys created by the current successful provider cycle."""

    def __init__(self, ledger: SQLiteAlertLedger, sender: CentralTelegramSender):
        if type(ledger) is not SQLiteAlertLedger or type(sender) is not CentralTelegramSender:
            raise TypeError("exact local ledger and central sender are required")
        self.ledger = ledger
        self.sender = sender

    def dispatch_new(
        self, dedupe_keys: Sequence[str], *, now_utc: str,
    ) -> tuple[DeliveryAttempt, ...]:
        attempts: list[DeliveryAttempt] = []
        for key in dedupe_keys:
            item = self.ledger.claim_delivery(key, claimed_at_utc=now_utc)
            if item is None:
                continue
            result: TelegramSendResult = self.sender.send_provider_alert(
                payload=item["payload"],
                message_text=item["message_text"],
            )
            self.ledger.finish_delivery(
                key,
                state=result.state,
                updated_at_utc=now_utc,
                http_status=result.http_status,
                failure_code=result.failure_code,
            )
            attempts.append(DeliveryAttempt(
                dedupe_key=key,
                state=result.state,
                http_status=result.http_status,
                failure_code=result.failure_code,
            ))
        return tuple(attempts)
