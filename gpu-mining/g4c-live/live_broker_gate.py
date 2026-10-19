"""Offline-only orchestration for the dormant Salad HTTPS broker.

The gate shares the existing durable four-slot ledger. It can send only to an
explicit loopback TLS test server, uses synthetic secrets only, and marks every
result SYNTHETIC/UNVERIFIED. It cannot perform a Salad request.
"""

from __future__ import annotations

import json
import math
import socket
import time
from datetime import datetime, timezone
from typing import Any, Callable

from broker_ledger import (
    BrokerLedger,
    LIVE_SALAD_GET,
    OFFLINE_LOCAL_TLS,
    LedgerBudgetExceeded,
    LedgerClockError,
    LedgerError,
    LedgerInFlight,
    LedgerPolicyMismatch,
    LedgerStateError,
    LedgerUnavailable,
    Reservation,
)
from broker_offline import ContainerGroup, KillSwitch
from live_https_policy import REQUESTS, RestrictedGET, LivePolicyError, request_for_group
from live_https_transport import (
    HTTPSResponse,
    LiveHTTPSTransport,
    ProductionSaladTransport,
    ProductionNetworkBlocked,
    ResponseContractError,
    ResponseTooLarge,
    TLSValidationFailure,
    TransportFailure,
    TransportTimeout,
)
from live_managed_secret_adapter import ManagedSecretAdapter
from live_secret_boundary import (
    DEFAULT_SECRET_PROVIDER,
    DisabledSecretProvider,
    SecretAccessBlocked,
    SecretProvider,
    SecretMaterial,
    SyntheticSecretProvider,
    InteractiveSecretProvider,
)
from pilot_evidence import (
    EvidenceError,
    SYNTHETIC_CLASSIFICATION,
    sanitize_instance_list,
    sanitize_live_instance_list,
)


class LiveBrokerScopeError(ValueError):
    """The caller did not provide one of the fixed group enum values."""


LIVE_GET_ALLOWED = False


def _clock_value(clock: Callable[[], float]) -> float:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("offline clock is invalid")
    return float(value)


def _http_failure_state(status: int) -> tuple[str, str]:
    if 300 <= status < 400:
        return "REDIRECT_BLOCKED", "redirects are never followed"
    if status in {401, 403}:
        return "AUTH_BLOCKED", "synthetic request was not authorized"
    if status == 404:
        return "NOT_FOUND_OR_SCOPE_UNKNOWN", "resource or scope remains unverified"
    if status == 429:
        return "RATE_LIMITED", "no retry or polling is performed"
    if status >= 500:
        return "PROVIDER_ERROR", "HTTP request failed; no subsequent group is queried"
    return "CONTRACT_CONFLICT", "HTTP status is outside the accepted 200-only contract"


class LiveBrokerGate:
    """Run one synthetic local TLS GET after a durable pre-attempt reservation."""

    __slots__ = ("_ledger", "_transport", "_secret_provider", "_kill_switch", "_clock", "_monotonic")

    def __init__(
        self,
        ledger: BrokerLedger,
        *,
        transport: LiveHTTPSTransport | None = None,
        secret_provider: SecretProvider | None = None,
        kill_switch: KillSwitch | None = None,
        clock: Callable[[], float] | None = None,
        monotonic: Callable[[], float] | None = None,
    ):
        if type(ledger) is not BrokerLedger:
            raise TypeError("live broker requires the initialized fixed-policy ledger")
        selected_transport = transport if transport is not None else LiveHTTPSTransport()
        if type(selected_transport) is not LiveHTTPSTransport:
            raise TypeError("live broker requires the fixed HTTPS transport")
        selected_provider = (
            secret_provider if secret_provider is not None else DEFAULT_SECRET_PROVIDER()
        )
        if type(selected_provider) not in {
            DisabledSecretProvider,
            SyntheticSecretProvider,
            ManagedSecretAdapter,
        }:
            raise TypeError("only in-module disabled or synthetic secret providers are accepted")
        if type(kill_switch) not in {type(None), KillSwitch}:
            raise TypeError("live broker requires the fixed kill switch")
        self._ledger = ledger
        self._transport = selected_transport
        self._secret_provider = selected_provider
        self._kill_switch = kill_switch if kill_switch is not None else KillSwitch()
        self._clock = clock if clock is not None else time.time
        self._monotonic = monotonic if monotonic is not None else time.monotonic

    @staticmethod
    def _empty(request: RestrictedGET, state: str, error: str | None = None) -> dict[str, Any]:
        return {
            "container_group": request.container_group.value,
            "ordinal": REQUESTS.index(request) + 1,
            "request_path": request.path,
            "method": request.method,
            "state": state,
            "http_status_code": None,
            "response_bytes": 0,
            "evidence": None,
            "error": error,
            "data_classification": SYNTHETIC_CLASSIFICATION,
            "provider_observation_verified": False,
            "binding_status": "UNKNOWN",
            "billing_status": "UNKNOWN",
            "hashrate_attribution": "UNKNOWN",
            "live_calls_performed": False,
            "actions_performed": False,
            "reallocation_enabled": False,
            "request_slot_consumed": False,
        }

    @staticmethod
    def _ledger_failure(exc: LedgerError) -> tuple[str, str]:
        if isinstance(exc, LedgerInFlight):
            return "OUTCOME_UNCERTAIN", "a prior reserved request has no confirmed result"
        if isinstance(exc, LedgerBudgetExceeded):
            return "BUDGET_EXHAUSTED", "the durable four-request budget is exhausted"
        if isinstance(exc, LedgerClockError):
            return "DEADLINE_BLOCKED", "the persisted request window is invalid or expired"
        if isinstance(exc, LedgerPolicyMismatch):
            return "POLICY_BLOCKED", "the durable policy differs from the approved scope"
        if isinstance(exc, LedgerUnavailable):
            return "LEDGER_UNAVAILABLE", "the initialized request ledger is unavailable"
        if isinstance(exc, LedgerStateError):
            return "LEDGER_BLOCKED", "the request ledger rejected the transition"
        return "LEDGER_BLOCKED", "the request ledger failed closed"

    def run_next(self, group: ContainerGroup) -> dict[str, Any]:
        """Run one fixed local TLS test request; the caller supplies only a group enum."""
        if type(group) is not ContainerGroup:
            raise LiveBrokerScopeError("container group must be an approved enum")
        try:
            request = request_for_group(group)
        except LivePolicyError as exc:
            raise LiveBrokerScopeError("container group is outside the fixed allowlist") from None

        if not self._kill_switch.enabled:
            return self._empty(request, "BROKER_DISABLED", "the offline kill switch is disabled")
        # This preflight is before ledger reservation, DNS, sockets, and secrets.
        if not self._transport.is_local_tls_test:
            return self._empty(
                request,
                "PRODUCTION_NETWORK_BLOCKED",
                "production network access is structurally unavailable",
            )

        try:
            reserved_at = _clock_value(self._clock)
            reservation = self._ledger.reserve_next(group.value, now=reserved_at)
        except LedgerError as exc:
            state, message = self._ledger_failure(exc)
            return self._empty(request, state, message)
        except Exception:
            return self._empty(request, "CLOCK_BLOCKED", "offline clock is unavailable")

        if not self._kill_switch.enabled:
            return self._abort_reserved(request, reservation, "KILL_SWITCH_TRIPPED")

        try:
            current = _clock_value(self._clock)
            self._ledger.observe_clock(reservation, now=current)
            remaining = reservation.expires_at - current
            if remaining <= 0:
                return self._finish_failure(
                    request, reservation, state="DEADLINE_EXCEEDED", ledger_status="TIMEOUT"
                )
            deadline = self._monotonic() + min(request.total_deadline_seconds, remaining)
        except Exception:
            return self._uncertain(request, "deadline or ledger check failed after reservation")

        try:
            secret = self._secret_provider.acquire()
            if type(secret) is not SecretMaterial:
                raise SecretAccessBlocked("secret provider returned an invalid value")
        except Exception:
            return self._finish_failure(
                request,
                reservation,
                state="SECRET_ACCESS_BLOCKED",
                ledger_status="FAILED",
            )

        if not self._kill_switch.enabled:
            return self._abort_reserved(request, reservation, "KILL_SWITCH_TRIPPED")

        try:
            response = self._transport.send(
                request,
                secret,
                total_deadline_monotonic=deadline,
            )
        except ResponseTooLarge as exc:
            return self._finish_failure(
                request,
                reservation,
                state="RESPONSE_TOO_LARGE",
                ledger_status="FAILED",
                response_bytes=exc.response_bytes,
            )
        except TransportTimeout:
            return self._finish_failure(
                request, reservation, state="TIMEOUT", ledger_status="TIMEOUT"
            )
        except TLSValidationFailure:
            return self._finish_failure(
                request, reservation, state="TLS_VALIDATION_FAILED", ledger_status="FAILED"
            )
        except ResponseContractError:
            return self._finish_failure(
                request, reservation, state="RESPONSE_CONTRACT_INVALID", ledger_status="FAILED"
            )
        except ProductionNetworkBlocked:
            return self._finish_failure(
                request, reservation, state="PRODUCTION_NETWORK_BLOCKED", ledger_status="FAILED"
            )
        except TransportFailure:
            return self._finish_failure(
                request, reservation, state="HTTPS_TRANSPORT_FAILED", ledger_status="FAILED"
            )
        except Exception:
            return self._finish_failure(
                request, reservation, state="HTTPS_TRANSPORT_FAILED", ledger_status="FAILED"
            )

        if type(response) is not HTTPSResponse:
            return self._finish_failure(
                request, reservation, state="TRANSPORT_RESULT_INVALID", ledger_status="FAILED"
            )
        if response.status_code != 200:
            state, message = _http_failure_state(response.status_code)
            return self._finish_failure(
                request,
                reservation,
                state=state,
                ledger_status="FAILED",
                http_status_code=response.status_code,
                error=message,
            )

        try:
            payload = json.loads(response.body.decode("utf-8"))
            evidence = sanitize_instance_list(group.value, payload)
        except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError, ValueError):
            return self._finish_failure(
                request,
                reservation,
                state="INVALID_OR_UNSAFE_JSON",
                ledger_status="FAILED",
                response_bytes=response.response_bytes,
                http_status_code=200,
            )

        try:
            completed_at = _clock_value(self._clock)
            self._ledger.record_result(
                reservation,
                status="SUCCESS",
                now=completed_at,
                response_bytes=response.response_bytes,
                http_status_code=200,
            )
        except Exception:
            return self._uncertain(request, "success could not be durably recorded")

        result = self._empty(request, "SYNTHETIC_LOCAL_TLS_UNVERIFIED")
        result.update(
            {
                "http_status_code": 200,
                "response_bytes": response.response_bytes,
                "evidence": evidence,
                "request_slot_consumed": True,
            }
        )
        return result

    def run_all_offline(self) -> dict[str, Any]:
        """Run approved groups sequentially until a safe stop condition."""
        groups: list[dict[str, Any]] = []
        stopped = False
        for request in REQUESTS:
            if stopped:
                result = self._empty(request, "NOT_QUERIED")
            else:
                result = self.run_next(request.container_group)
                if result["state"] != "SYNTHETIC_LOCAL_TLS_UNVERIFIED":
                    stopped = True
            groups.append(result)
        try:
            snapshot = self._ledger.snapshot()
            request_slots = snapshot["request_count"]
            response_bytes = snapshot["response_bytes_total"]
        except LedgerError:
            request_slots = None
            response_bytes = None
        all_done = all(group["state"] == "SYNTHETIC_LOCAL_TLS_UNVERIFIED" for group in groups)
        return {
            "schema_version": "1.0",
            "data_classification": SYNTHETIC_CLASSIFICATION,
            "execution_mode": "OFFLINE_LOCAL_TLS_TEST",
            "state": "ALL_LOCAL_TESTS_COMPLETED" if all_done else "PARTIAL_OR_BLOCKED",
            "stopped_reason": None if all_done else next(
                (item["state"] for item in groups if item["state"] not in {
                    "SYNTHETIC_LOCAL_TLS_UNVERIFIED", "NOT_QUERIED"
                }),
                "NOT_QUERIED",
            ),
            "groups": groups,
            "request_slots_consumed": request_slots,
            "response_bytes_total": response_bytes,
            "provider_observation_verified": False,
            "binding_status": "UNKNOWN",
            "billing_status": "UNKNOWN",
            "hashrate_attribution": "UNKNOWN",
            "live_calls_performed": False,
            "actions_performed": False,
            "reallocation_enabled": False,
        }

    def _abort_reserved(
        self,
        request: RestrictedGET,
        reservation: Reservation,
        state: str,
    ) -> dict[str, Any]:
        try:
            self._ledger.record_result(
                reservation,
                status="ABORTED_KILL_SWITCH",
                now=_clock_value(self._clock),
            )
        except Exception:
            return self._uncertain(request, "kill switch tripped after a durable reservation")
        result = self._empty(request, state, "slot consumed; secret and transport were not used")
        result["request_slot_consumed"] = True
        return result

    def _finish_failure(
        self,
        request: RestrictedGET,
        reservation: Reservation,
        *,
        state: str,
        ledger_status: str,
        response_bytes: int = 0,
        http_status_code: int | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        try:
            self._ledger.record_result(
                reservation,
                status=ledger_status,
                now=_clock_value(self._clock),
                response_bytes=response_bytes,
                http_status_code=http_status_code,
            )
        except Exception:
            return self._uncertain(request, "terminal result could not be durably recorded")
        result = self._empty(request, state, error or "slot consumed; no retry is permitted")
        result.update(
            {
                "http_status_code": http_status_code,
                "response_bytes": response_bytes,
                "request_slot_consumed": True,
            }
        )
        return result

    def _uncertain(self, request: RestrictedGET, message: str) -> dict[str, Any]:
        result = self._empty(request, "OUTCOME_UNCERTAIN", message)
        result["request_slot_consumed"] = True
        return result


class LiveSaladReadSession:
    """Explicitly armed future four-GET session; never used by offline QA.

    The constructor defaults closed. A live invocation requires an explicitly
    enabled session, an enabled fixed-origin transport, the one-shot TTY secret
    provider, a LIVE_SALAD_GET ledger, and an open kill switch. It performs no
    polling/retry and stops after the first uncertain or failed result.
    """

    def __init__(
        self,
        ledger: BrokerLedger,
        *,
        transport: ProductionSaladTransport,
        secret_provider: InteractiveSecretProvider,
        kill_switch: KillSwitch | None = None,
        live_enabled: bool = False,
        clock: Callable[[], float] | None = None,
        monotonic: Callable[[], float] | None = None,
    ):
        if type(ledger) is not BrokerLedger:
            raise TypeError("live session requires an initialized durable broker ledger")
        if type(transport) is not ProductionSaladTransport:
            raise TypeError("live session requires the fixed production transport")
        if type(secret_provider) is not InteractiveSecretProvider:
            raise TypeError("live session requires the hidden interactive secret provider")
        if not isinstance(live_enabled, bool):
            raise TypeError("live session enable flag must be boolean")
        if type(kill_switch) not in {type(None), KillSwitch}:
            raise TypeError("live session requires the fixed kill switch")
        self._ledger = ledger
        self._transport = transport
        self._secret_provider = secret_provider
        self._kill_switch = kill_switch if kill_switch is not None else KillSwitch()
        self._live_enabled = live_enabled
        self._clock = clock if clock is not None else time.time
        self._monotonic = monotonic if monotonic is not None else time.monotonic

    @property
    def is_local_tls_test(self) -> bool:
        """Expose transport mode so downstream stores cannot mislabel TLS fakes."""
        return self._transport.is_local_tls_test

    @staticmethod
    def _result(
        group: ContainerGroup,
        state: str,
        *,
        error: str | None = None,
        call_attempted: bool = False,
        response_received: bool = False,
    ) -> dict[str, Any]:
        request = request_for_group(group)
        return {
            "container_group": group.value,
            "request_path": request.path,
            "method": "GET",
            "state": state,
            "http_status_code": None,
            "response_bytes": 0,
            "evidence": None,
            "error": error,
            "data_classification": "PROVIDER_OBSERVED" if state == "OBSERVED" else "UNKNOWN",
            "provider_observation_verified": state == "OBSERVED",
            "binding_status": "UNKNOWN",
            "billing_status": "UNKNOWN",
            "hashrate_attribution": "UNKNOWN",
            "live_call_attempted": call_attempted,
            "live_calls_performed": response_received,
            "actions_performed": False,
            "reallocation_enabled": False,
        }

    def run_all(self) -> dict[str, Any]:
        if not self._live_enabled or not self._transport._enabled:
            groups = [self._result(group, "LIVE_GET_DISABLED", error="live GET session is closed") for group in ContainerGroup]
            return {"execution_mode": "LIVE_SALAD_GET_DISABLED", "groups": groups, "live_calls_performed": False, "actions_performed": False}
        try:
            snapshot = self._ledger.snapshot()
            if snapshot["run_mode"] != LIVE_SALAD_GET or self._ledger.expected_mode != LIVE_SALAD_GET:
                raise LedgerPolicyMismatch("live read requires its separately initialized ledger mode")
        except LedgerError:
            groups = [self._result(group, "LEDGER_BLOCKED", error="live ledger mode is unavailable") for group in ContainerGroup]
            return {"execution_mode": "LIVE_SALAD_GET", "groups": groups, "live_calls_performed": False, "actions_performed": False}
        if not self._transport.authorization_allows_session(
            run_id=snapshot["run_id"], now_epoch=_clock_value(self._clock)
        ):
            groups = [self._result(group, "AUTHORIZATION_BLOCKED", error="no valid externally signed GET capability for this run") for group in ContainerGroup]
            return {"execution_mode": "LIVE_SALAD_GET", "groups": groups, "live_calls_performed": False, "actions_performed": False}
        if not self._kill_switch.enabled:
            groups = [self._result(group, "KILL_SWITCH_BLOCKED") for group in ContainerGroup]
            return {"execution_mode": "LIVE_SALAD_GET", "groups": groups, "live_calls_performed": False, "actions_performed": False}
        results = [self._result(group, "NOT_QUERIED") for group in ContainerGroup]
        try:
            next_group_name = snapshot.get("next_group")
            next_index = next((i for i, group in enumerate(ContainerGroup) if group.value == next_group_name), None)
            if next_index is None:
                state = "OUTCOME_UNCERTAIN" if snapshot.get("pending_outcome_uncertain") else "BUDGET_EXHAUSTED"
                group = ContainerGroup.FL4SHMINER
                results[0] = self._result(group, state, error="durable ledger has no safe request slot")
                return self._session_result(results)
            group = tuple(ContainerGroup)[next_index]
            request = request_for_group(group)
            reservation = self._ledger.reserve_next(group.value, now=_clock_value(self._clock))
            current = _clock_value(self._clock)
            self._ledger.observe_clock(reservation, now=current)
            remaining = reservation.expires_at - current
            if remaining <= 0:
                self._ledger.record_result(reservation, status="TIMEOUT", now=current)
                results[next_index] = self._result(group, "DEADLINE_BLOCKED")
                return self._session_result(results)
        except LedgerError as exc:
            state = "OUTCOME_UNCERTAIN" if isinstance(exc, LedgerInFlight) else (
                "DEADLINE_BLOCKED" if isinstance(exc, LedgerClockError) else "LEDGER_BLOCKED"
            )
            group = tuple(ContainerGroup)[min(len(snapshot.get("reservations", [])), len(ContainerGroup) - 1)]
            index = tuple(ContainerGroup).index(group)
            results[index] = self._result(group, state, error="durable request slot was unavailable")
            return self._session_result(results)
        except Exception:
            group = tuple(ContainerGroup)[min(len(snapshot.get("reservations", [])), len(ContainerGroup) - 1)]
            index = tuple(ContainerGroup).index(group)
            results[index] = self._result(group, "LEDGER_BLOCKED", error="durable request slot was unavailable")
            return self._session_result(results)

        # The first durable request reservation is committed before a credential
        # provider is touched. A failed credential attempt consumes this slot
        # and ends the session; it can never turn into an unmetered retry.
        if not self._kill_switch.enabled:
            try:
                self._ledger.record_result(reservation, status="ABORTED_KILL_SWITCH", now=_clock_value(self._clock))
                results[next_index] = self._result(group, "KILL_SWITCH_BLOCKED")
            except Exception:
                results[next_index] = self._result(group, "OUTCOME_UNCERTAIN", error="reserved slot could not be closed")
            return self._session_result(results)
        try:
            secret = self._secret_provider.acquire()
        except Exception:
            try:
                self._ledger.record_result(reservation, status="FAILED", now=_clock_value(self._clock))
                results[next_index] = self._result(group, "SECRET_ACCESS_BLOCKED", error="slot consumed; no request was sent")
            except Exception:
                results[next_index] = self._result(group, "OUTCOME_UNCERTAIN", error="reserved slot could not be closed")
            return self._session_result(results)

        stopped = False
        groups = tuple(ContainerGroup)
        for index in range(next_index, len(groups)):
            group = groups[index]
            if stopped or not self._kill_switch.enabled:
                results[index] = self._result(group, "NOT_QUERIED" if stopped else "KILL_SWITCH_BLOCKED")
                stopped = True
                continue
            request = request_for_group(group)
            call_started = False
            response_received = False
            try:
                if index != next_index:
                    reserved_at = _clock_value(self._clock)
                    reservation = self._ledger.reserve_next(group.value, now=reserved_at)
                    current = _clock_value(self._clock)
                    self._ledger.observe_clock(reservation, now=current)
                    remaining = reservation.expires_at - current
                    if remaining <= 0:
                        self._ledger.record_result(reservation, status="TIMEOUT", now=current)
                        results[index] = self._result(group, "DEADLINE_BLOCKED")
                        stopped = True
                        continue
                deadline = self._monotonic() + min(request.total_deadline_seconds, remaining)
                if not self._kill_switch.enabled:
                    self._ledger.record_result(reservation, status="ABORTED_KILL_SWITCH", now=_clock_value(self._clock))
                    results[index] = self._result(group, "KILL_SWITCH_BLOCKED")
                    stopped = True
                    continue
                call_started = True
                response = self._transport.send(
                    request, secret, total_deadline_monotonic=deadline, run_id=snapshot["run_id"]
                )
                response_received = True
                if response.status_code != 200:
                    status = "TIMEOUT" if response.status_code == 408 else "FAILED"
                    self._ledger.record_result(reservation, status=status, now=_clock_value(self._clock), http_status_code=response.status_code)
                    state = _http_failure_state(response.status_code)[0]
                    results[index] = self._result(group, state, error="provider response was not accepted; no retry", call_attempted=True, response_received=True)
                    stopped = True
                    continue
                try:
                    payload = json.loads(response.body.decode("utf-8"))
                    observed_at = datetime.fromtimestamp(_clock_value(self._clock), tz=timezone.utc).isoformat().replace("+00:00", "Z")
                    evidence = sanitize_live_instance_list(group.value, payload, observed_at_utc=observed_at)
                except Exception:
                    self._ledger.record_result(reservation, status="FAILED", now=_clock_value(self._clock), response_bytes=response.response_bytes, http_status_code=200)
                    results[index] = self._result(
                        group,
                        "RESPONSE_REJECTED",
                        error="provider response failed safe schema validation",
                        call_attempted=True,
                        response_received=True,
                    )
                    stopped = True
                    continue
                self._ledger.record_result(reservation, status="SUCCESS", now=_clock_value(self._clock), response_bytes=response.response_bytes, http_status_code=200)
                item = self._result(group, "OBSERVED", call_attempted=True, response_received=True)
                item.update({"http_status_code": 200, "response_bytes": response.response_bytes, "evidence": evidence})
                results[index] = item
            except (TransportTimeout, socket.timeout, TimeoutError):
                self._record_uncertain_or_timeout(group)
                results[index] = self._result(group, "REQUEST_OUTCOME_UNCERTAIN", error="request outcome is uncertain; no retry", call_attempted=call_started)
                stopped = True
            except Exception:
                # A socket may have been reached. Persisted reservations remain
                # in flight when result recording cannot prove a terminal state.
                results[index] = self._result(
                    group,
                    "REQUEST_OUTCOME_UNCERTAIN",
                    error="request failed safely; no retry",
                    call_attempted=call_started,
                    response_received=response_received,
                )
                stopped = True
        return self._session_result(results)

    def _session_result(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "execution_mode": "LIVE_SALAD_GET",
            "groups": results,
            "request_slots_consumed": self._ledger.snapshot()["request_count"],
            "response_bytes_total": self._ledger.snapshot()["response_bytes_total"],
            "live_calls_performed": any(item["live_calls_performed"] for item in results),
            "binding_status": "UNKNOWN",
            "billing_status": "UNKNOWN",
            "hashrate_attribution": "UNKNOWN",
            "actions_performed": False,
            "reallocation_enabled": False,
        }

    def _record_uncertain_or_timeout(self, group: ContainerGroup) -> None:
        # Deliberately leave a still-RESERVED durable slot untouched. A timeout
        # can occur after request bytes reached the provider; reopening then
        # refuses the next slot until external reconciliation.
        del group
