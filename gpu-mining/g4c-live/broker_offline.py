"""Offline-only broker enforcing the fixed four-group fixture policy."""

from __future__ import annotations

import json
import math
import time
from enum import Enum
from typing import Any, Callable

from broker_fixture import OfflineFixtureTransport
from broker_ledger import (
    BrokerLedger,
    LedgerBudgetExceeded,
    LedgerClockError,
    LedgerError,
    LedgerInFlight,
    LedgerPolicyMismatch,
    LedgerStateError,
    LedgerUnavailable,
    Reservation,
)
from pilot_evidence import EvidenceError, SYNTHETIC_CLASSIFICATION, sanitize_instance_list
from pilot_scope import (
    CONTAINER_GROUPS,
    MAX_RESPONSE_BYTES_PER_GROUP,
    MAX_RESPONSE_BYTES_TOTAL,
    REQUEST_PLAN,
    TOTAL_DEADLINE_SECONDS,
    RequestSpec,
)
from pilot_discovery import OfflineFixtureResponse


class ContainerGroup(str, Enum):
    FL4SHMINER = "fl4shminer"
    FL4SHMINER_2 = "fl4shminer-2"
    FL4SHMINER_3 = "fl4shminer-3"
    FL4SHMINER_4 = "fl4shminer-4"


class BrokerScopeError(ValueError):
    """The caller supplied something other than a fixed group enum."""


class KillSwitch:
    """In-memory switch for explicit synthetic tests; disabled by default."""

    __slots__ = ("_enabled",)

    def __init__(self, *, enabled: bool = False):
        if not isinstance(enabled, bool):
            raise TypeError("kill switch state must be boolean")
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def disable(self) -> None:
        self._enabled = False


def _clock_value(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("offline clock value is invalid")
    return float(value)


def _body_bytes(body: Any) -> bytes:
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _parse_body(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def _empty_group(group: str, ordinal: int, state: str) -> dict[str, Any]:
    return {
        "container_group": group,
        "ordinal": ordinal,
        "state": state,
        "http_status_code": None,
        "response_bytes": 0,
        "evidence": None,
        "error": None,
        "data_classification": SYNTHETIC_CLASSIFICATION,
        "provider_observation_verified": False,
        "binding_status": "UNKNOWN",
        "billing_status": "UNKNOWN",
        "live_calls_performed": False,
        "actions_performed": False,
        "reallocation_enabled": False,
    }


class OfflineBroker:
    """Consumes durable slots before invoking a concrete local fixture fake."""

    def __init__(
        self,
        ledger: BrokerLedger,
        transport: OfflineFixtureTransport,
        *,
        kill_switch: KillSwitch | None = None,
        clock: Callable[[], float] | None = None,
    ):
        if type(ledger) is not BrokerLedger:
            raise TypeError("the broker requires an initialized BrokerLedger")
        if type(transport) is not OfflineFixtureTransport:
            raise TypeError("only the concrete offline fixture transport is accepted")
        if kill_switch is not None and type(kill_switch) is not KillSwitch:
            raise TypeError("the broker requires the fixed KillSwitch type")
        self._ledger = ledger
        self._transport = transport
        self._kill_switch = kill_switch if kill_switch is not None else KillSwitch()
        self._clock = clock if clock is not None else time.time

    @staticmethod
    def _blocked_group(group: str, state: str, error: str, ordinal: int) -> dict[str, Any]:
        result = _empty_group(group, ordinal, state)
        result["error"] = error
        return result

    def _map_ledger_error(self, exc: LedgerError) -> tuple[str, str]:
        if isinstance(exc, LedgerInFlight):
            return "OUTCOME_UNCERTAIN", "a prior reservation is unresolved; no retry is permitted"
        if isinstance(exc, LedgerBudgetExceeded):
            return "BUDGET_EXHAUSTED", "the four-slot durable budget is exhausted"
        if isinstance(exc, LedgerClockError):
            return "CLOCK_OR_DEADLINE_BLOCKED", "the persisted time window is invalid or expired"
        if isinstance(exc, LedgerPolicyMismatch):
            return "POLICY_BLOCKED", "the durable policy does not match this offline broker"
        if isinstance(exc, LedgerUnavailable):
            return "LEDGER_UNAVAILABLE", "the initialized durable ledger is unavailable"
        if isinstance(exc, LedgerStateError):
            return "ORDER_OR_STATE_BLOCKED", "the request is not the next permitted group"
        return "LEDGER_BLOCKED", "the durable budget failed closed"

    def run_next(self, group: ContainerGroup) -> dict[str, Any]:
        """Run one synthetic fixture for the next fixed group, if explicitly enabled."""
        if type(group) is not ContainerGroup:
            raise BrokerScopeError("caller must provide one fixed ContainerGroup enum")
        group_name = group.value
        ordinal = CONTAINER_GROUPS.index(group_name) + 1
        if not self._kill_switch.enabled:
            return self._blocked_group(
                group_name, "BROKER_DISABLED", "offline kill switch is disabled", ordinal
            )
        try:
            before_reservation = _clock_value(self._clock)
        except Exception:
            return self._blocked_group(
                group_name, "CLOCK_BLOCKED", "offline clock is unavailable", ordinal
            )
        try:
            reservation = self._ledger.reserve_next(group_name, now=before_reservation)
        except LedgerError as exc:
            state, message = self._map_ledger_error(exc)
            return self._blocked_group(group_name, state, message, ordinal)

        # Check the switch again after the durable reservation. A consumed slot
        # is deliberately not returned if the switch changed while reserving.
        if not self._kill_switch.enabled:
            try:
                self._ledger.record_result(
                    reservation,
                    status="ABORTED_KILL_SWITCH",
                    now=_clock_value(self._clock),
                )
            except LedgerError:
                pass
            result = self._blocked_group(
                group_name,
                "KILL_SWITCH_TRIPPED",
                "slot consumed; fixture was not invoked",
                ordinal,
            )
            result["request_slot_consumed"] = True
            return result

        try:
            before_fixture = _clock_value(self._clock)
            self._ledger.observe_clock(reservation, now=before_fixture)
            if before_fixture < reservation.reserved_at or before_fixture >= reservation.expires_at:
                self._ledger.record_result(
                    reservation,
                    status="TIMEOUT",
                    now=before_fixture,
                )
                return self._blocked_group(
                    group_name,
                    "TOTAL_DEADLINE_EXCEEDED",
                    "slot consumed; total run window expired before fixture invocation",
                    ordinal,
                )
        except LedgerError:
            return self._blocked_group(
                group_name,
                "LEDGER_BLOCKED",
                "slot remains consumed with an uncertain outcome",
                ordinal,
            )
        except Exception:
            return self._blocked_group(
                group_name,
                "CLOCK_BLOCKED",
                "slot remains consumed with an uncertain outcome",
                ordinal,
            )

        request = REQUEST_PLAN[ordinal - 1]
        try:
            response = self._transport.invoke(request)
        except Exception:
            completion = None
            try:
                completion = _clock_value(self._clock)
                self._ledger.record_result(
                    reservation,
                    status="TRANSPORT_ERROR",
                    now=completion,
                )
            except Exception:
                pass
            return self._blocked_group(
                group_name,
                "SYNTHETIC_TRANSPORT_ERROR",
                "slot consumed; no retry is permitted",
                ordinal,
            )

        try:
            fixture_finished = _clock_value(self._clock)
            if fixture_finished < before_fixture:
                raise ValueError("clock moved backward during fixture invocation")
            if fixture_finished - before_fixture >= request.request_timeout_seconds:
                timeout_state = "REQUEST_TIMEOUT"
                timeout_error = "synthetic fixture exceeded the modeled request deadline"
            elif fixture_finished >= reservation.expires_at:
                timeout_state = "TOTAL_DEADLINE_EXCEEDED"
                timeout_error = "synthetic fixture completed after the total run deadline"
            else:
                timeout_state = None
                timeout_error = None
            if timeout_state is not None:
                self._ledger.record_result(
                    reservation,
                    status="TIMEOUT",
                    now=fixture_finished,
                )
                result = self._blocked_group(group_name, timeout_state, timeout_error, ordinal)
                result["request_slot_consumed"] = True
                return result
        except Exception:
            result = self._blocked_group(
                group_name,
                "LEDGER_FINALIZATION_UNCERTAIN",
                "slot remains consumed; no subsequent group may run",
                ordinal,
            )
            result["request_slot_consumed"] = True
            return result

        if type(response) is not OfflineFixtureResponse or response.container_group != group_name:
            response_state = "INVALID_FIXTURE"
            safe_error = "fixture type or group does not match the reserved scope"
            http_status = None
            body_size = 0
            evidence = None
            terminal_status = "FAILED"
        elif not isinstance(response.timed_out, bool):
            response_state, safe_error = "INVALID_FIXTURE", "timeout field is invalid"
            http_status, body_size, evidence, terminal_status = None, 0, None, "FAILED"
        elif response.timed_out:
            response_state, safe_error = "TIMEOUT", "synthetic request timeout; no retry is permitted"
            http_status, body_size, evidence, terminal_status = None, 0, None, "TIMEOUT"
        elif response.transport_error is not None:
            response_state, safe_error = "TRANSPORT_ERROR", "synthetic transport error; no retry is permitted"
            http_status, body_size, evidence, terminal_status = None, 0, None, "TRANSPORT_ERROR"
        elif (
            isinstance(response.status_code, bool)
            or not isinstance(response.status_code, int)
            or not 100 <= response.status_code <= 599
        ):
            response_state, safe_error = "INVALID_FIXTURE", "synthetic status code is invalid"
            http_status, body_size, evidence, terminal_status = None, 0, None, "FAILED"
        elif response.status_code != 200:
            status = response.status_code
            if 300 <= status < 400:
                response_state, safe_error = "REDIRECT_BLOCKED", "synthetic redirect was not followed"
            elif status in {401, 403}:
                response_state, safe_error = "AUTH_BLOCKED", "synthetic request was rejected"
            elif status == 404:
                response_state, safe_error = "NOT_FOUND_OR_SCOPE_UNKNOWN", "synthetic resource or scope is unknown"
            elif status == 429:
                response_state, safe_error = "RATE_LIMITED", "no retry or polling is permitted"
            elif status >= 500:
                response_state, safe_error = "PROVIDER_ERROR", "synthetic provider error; later groups are stopped"
            else:
                response_state, safe_error = "CONTRACT_CONFLICT", "status is outside the approved 200-only list contract"
            http_status, body_size, evidence, terminal_status = status, 0, None, "FAILED"
        else:
            http_status = response.status_code
            body_size = 0
            try:
                raw = _body_bytes(response.body)
                body_size = len(raw)
                if body_size > MAX_RESPONSE_BYTES_PER_GROUP:
                    response_state, safe_error, evidence, terminal_status = (
                        "RESPONSE_TOO_LARGE",
                        "synthetic response exceeds the per-group byte cap",
                        None,
                        "FAILED",
                    )
                elif self._ledger.snapshot()["response_bytes_total"] + body_size > MAX_RESPONSE_BYTES_TOTAL:
                    response_state, safe_error, evidence, terminal_status = (
                        "TOTAL_RESPONSE_BUDGET_EXCEEDED",
                        "synthetic response exceeds the aggregate byte cap",
                        None,
                        "FAILED",
                    )
                else:
                    payload = _parse_body(raw)
                    evidence = sanitize_instance_list(group_name, payload)
                    response_state = "OBSERVED_SYNTHETIC_UNVERIFIED"
                    safe_error = None
                    terminal_status = "SUCCESS"
            except Exception:
                response_state = "INVALID_OR_UNSAFE_PAYLOAD"
                safe_error = "synthetic payload was rejected by the approved schema or sanitizer"
                evidence = None
                terminal_status = "FAILED"

        try:
            completion = _clock_value(self._clock)
            if completion < reservation.reserved_at:
                raise ValueError("clock moved backward")
            if completion >= reservation.expires_at and terminal_status == "SUCCESS":
                response_state = "TOTAL_DEADLINE_EXCEEDED"
                safe_error = "synthetic response completed after the total run deadline"
                evidence = None
                terminal_status = "TIMEOUT"
            self._ledger.record_result(
                reservation,
                status=terminal_status,
                now=completion,
                response_bytes=min(body_size, MAX_RESPONSE_BYTES_TOTAL + 1),
                http_status_code=http_status,
            )
        except Exception:
            response_state = "LEDGER_FINALIZATION_UNCERTAIN"
            safe_error = "slot remains consumed; no subsequent group may run"
            evidence = None

        result = _empty_group(group_name, ordinal, response_state)
        result.update(
            {
                "http_status_code": http_status,
                "response_bytes": body_size,
                "evidence": evidence,
                "error": safe_error,
                "request_slot_consumed": True,
            }
        )
        return result

    def run_all_offline(self) -> dict[str, Any]:
        """Run the fixed group sequence from the durable next slot using fixtures only."""
        if not self._kill_switch.enabled:
            groups = [_empty_group(name, ordinal, "NOT_QUERIED") for ordinal, name in enumerate(CONTAINER_GROUPS, 1)]
            try:
                consumed = self._ledger.snapshot()["request_count"]
            except LedgerError:
                consumed = None
            return self._run_summary("BROKER_DISABLED", groups, consumed)
        try:
            snapshot = self._ledger.snapshot()
        except LedgerError:
            groups = [_empty_group(name, ordinal, "NOT_QUERIED") for ordinal, name in enumerate(CONTAINER_GROUPS, 1)]
            return self._run_summary("LEDGER_BLOCKED", groups, None)
        if snapshot["halted"] or snapshot["pending_outcome_uncertain"]:
            groups = [_empty_group(name, ordinal, "NOT_QUERIED") for ordinal, name in enumerate(CONTAINER_GROUPS, 1)]
            state = "OUTCOME_UNCERTAIN" if snapshot["pending_outcome_uncertain"] else "RUN_HALTED"
            return self._run_summary(state, groups, snapshot["request_count"])
        start = snapshot["request_count"]
        if start >= len(CONTAINER_GROUPS):
            return self._run_summary("ALREADY_COMPLETE", [], start)

        results: list[dict[str, Any]] = []
        for ordinal, group_name in enumerate(CONTAINER_GROUPS[start:], start=start + 1):
            enum_value = ContainerGroup(group_name)
            result = self.run_next(enum_value)
            results.append(result)
            if result["state"] != "OBSERVED_SYNTHETIC_UNVERIFIED":
                results.extend(
                    _empty_group(later, later_ordinal, "NOT_QUERIED")
                    for later_ordinal, later in enumerate(CONTAINER_GROUPS[ordinal:], start=ordinal + 1)
                )
                break
        try:
            final = self._ledger.snapshot()
        except LedgerError:
            consumed = start + sum(bool(item.get("request_slot_consumed")) for item in results)
            return self._run_summary("LEDGER_BLOCKED", results, consumed)
        full_success = (
            final["request_count"] == len(CONTAINER_GROUPS)
            and not final["halted"]
            and not final["pending_outcome_uncertain"]
            and all(row["status"] == "SUCCESS" for row in final["reservations"])
        )
        return self._run_summary(
            "ALL_FIXTURES_REPLAYED" if full_success else "PARTIAL_OR_BLOCKED",
            results,
            final["request_count"],
        )

    @staticmethod
    def _run_summary(state: str, groups: list[dict[str, Any]], attempts: int | None) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "data_classification": SYNTHETIC_CLASSIFICATION,
            "execution_mode": "OFFLINE_FIXTURE_BROKER",
            "state": state,
            "groups": groups,
            "request_slots_consumed": attempts,
            "request_limit": {
                "max_requests_total": 4,
                "max_requests_per_group": 1,
                "retries": 0,
                "polling": False,
                "redirects_followed": False,
                "connect_timeout_seconds": REQUEST_PLAN[0].connect_timeout_seconds,
                "request_timeout_seconds": REQUEST_PLAN[0].request_timeout_seconds,
                "total_deadline_seconds": TOTAL_DEADLINE_SECONDS,
                "max_response_bytes_per_group": MAX_RESPONSE_BYTES_PER_GROUP,
                "max_response_bytes_total": MAX_RESPONSE_BYTES_TOTAL,
            },
            "live_calls_performed": False,
            "actions_performed": False,
            "reallocation_enabled": False,
        }

