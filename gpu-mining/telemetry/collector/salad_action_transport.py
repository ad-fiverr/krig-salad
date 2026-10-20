"""Fixed-origin Salad POST transport and durable action dispatch state machine.

The transport is disabled by default. It accepts only the three reviewed
operation types and fixed organization/project/group/instance identifiers;
callers cannot provide HTTP method, URL, path, headers, redirects, or retries.
"""

from __future__ import annotations

import http.client
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote
import uuid

from .action_ledger import ActionLedger
from .guard_store import canonical_utc
from .salad_action_policy import (
    ActionCapabilityVerifier,
    DecisionDossierAuthority,
    ActionDecision,
    SaladAction,
    SaladActionPolicy,
    SignedActionCapability,
    VerifiedActionDossier,
)


SALAD_HOST = "api.salad.com"
SALAD_PORT = 443
ORGANIZATION = "adrianfiverr"
PROJECT = "miners"
APPROVED_GROUPS = ("fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4")
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_PROVIDER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class ActionTransportBlocked(RuntimeError):
    pass


class ActionTransportFailure(RuntimeError):
    pass


@dataclass(frozen=True)
class ActionReceipt:
    status: str
    http_status_code: int | None
    action_key: str
    actions_performed: bool
    reason: str | None = None
    request_submitted: bool | None = False
    data_classification: str | None = None
    synthetic_fixture_id: str | None = None


def _segment(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_SEGMENT.fullmatch(value):
        raise ValueError(f"{label} is invalid")
    return quote(value, safe="-._~")


def fixed_action_path(action: SaladAction, target: Mapping[str, Any]) -> str:
    if type(action) is not SaladAction or not isinstance(target, Mapping):
        raise ValueError("action and target must use fixed typed contracts")
    group = target.get("container_group")
    if target.get("organization") != ORGANIZATION or target.get("project") != PROJECT:
        raise ValueError("organization and project are fixed by the approved action scope")
    if group not in APPROVED_GROUPS:
        raise ValueError("container group is outside the fixed action allowlist")
    group_path = (
        f"/api/public/organizations/{ORGANIZATION}/projects/{PROJECT}"
        f"/containers/{_segment(group, 'container_group')}"
    )
    if action is SaladAction.START_GROUP:
        if target.get("instance_id") is not None:
            raise ValueError("start action is group-scoped")
        return group_path + "/start"
    if action is SaladAction.STOP_GROUP:
        if target.get("instance_id") is not None:
            raise ValueError("stop action is group-scoped")
        return group_path + "/stop"
    if action is SaladAction.REALLOCATE_INSTANCE:
        raw_instance = target.get("instance_id")
        try:
            canonical_instance = str(uuid.UUID(raw_instance))
        except (ValueError, TypeError, AttributeError):
            raise ValueError("reallocation requires a verified UUID instance ID") from None
        return group_path + f"/instances/{canonical_instance}/reallocate"
    raise ValueError("action is not supported")


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


class RestrictedSaladActionHTTPTransport:
    """One POST to the fixed official Salad origin; disabled unless explicit."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        test_local_port: int | None = None,
        test_ca_file: str | None = None,
        authorization_capability: SignedActionCapability | None = None,
        authorization_verifier: ActionCapabilityVerifier | None = None,
    ):
        if not isinstance(enabled, bool):
            raise TypeError("action transport enable flag must be boolean")
        if test_local_port is not None and (
            isinstance(test_local_port, bool) or not isinstance(test_local_port, int) or not 1 <= test_local_port <= 65535
        ):
            raise ValueError("local test port is invalid")
        if (test_local_port is None) != (test_ca_file is None):
            raise ValueError("local TLS tests require both a loopback port and a CA file")
        if (authorization_capability is None) != (authorization_verifier is None):
            raise ValueError("production action authorization requires a signed grant and trusted verifier")
        if authorization_capability is not None and type(authorization_capability) is not SignedActionCapability:
            raise TypeError("production action capability has an invalid type")
        if authorization_verifier is not None and type(authorization_verifier) is not ActionCapabilityVerifier:
            raise TypeError("production action verifier has an invalid type")
        self.enabled = enabled
        self.test_local_port = test_local_port
        self.authorization_capability = authorization_capability
        self.authorization_verifier = authorization_verifier
        if test_ca_file is not None:
            path = Path(test_ca_file).resolve()
            if not path.is_file():
                raise ValueError("local test CA file is unavailable")
            self.test_ca_file = str(path)
        else:
            self.test_ca_file = None

    def submit(self, action: SaladAction, target: Mapping[str, Any], secret: Any) -> dict[str, Any]:
        return self._submit_bound(
            action, target, secret, action_key=None, authorization_nonce=None, nonce_ledger=None,
        )

    def action_capability_nonce(
        self,
        action: SaladAction,
        target: Mapping[str, Any],
        route: str,
        *,
        now_epoch: float,
    ) -> str | None:
        verifier = self.authorization_verifier
        capability = self.authorization_capability
        if verifier is None or capability is None:
            return None
        return verifier.verified_nonce(
            capability, action=action, target=target, route=route, now_epoch=now_epoch,
        )

    def submit_bound(
        self,
        action: SaladAction,
        target: Mapping[str, Any],
        secret: Any,
        *,
        action_key: str,
        authorization_nonce: str,
        nonce_ledger: ActionLedger,
    ) -> dict[str, Any]:
        return self._submit_bound(
            action, target, secret, action_key=action_key,
            authorization_nonce=authorization_nonce, nonce_ledger=nonce_ledger,
        )

    def _submit_bound(
        self,
        action: SaladAction,
        target: Mapping[str, Any],
        secret: Any,
        *,
        action_key: str | None,
        authorization_nonce: str | None,
        nonce_ledger: ActionLedger | None,
    ) -> dict[str, Any]:
        if not self.enabled:
            raise ActionTransportBlocked("Salad action transport is disabled")
        path = fixed_action_path(action, target)
        expected_nonce = self.action_capability_nonce(action, target, path, now_epoch=time.time())
        if (
            expected_nonce is None
            or authorization_nonce != expected_nonce
            or not isinstance(action_key, str)
            or type(nonce_ledger) is not ActionLedger
            or not nonce_ledger.signed_action_nonce_is_bound(expected_nonce, action_key)
        ):
            raise ActionTransportBlocked("a durably consumed, externally signed one-action capability is required")
        if type(secret).__name__ != "SecretMaterial" or getattr(secret, "source_label", None) not in {
            "interactive_tty_session", "synthetic_test_provider", "synthetic_managed_backend"
        }:
            raise ActionTransportBlocked("action transport requires scoped secret material")
        header_value = secret._header_value()
        if not isinstance(header_value, str) or not header_value:
            raise ActionTransportBlocked("secret material is invalid")
        context = ssl.create_default_context(cafile=self.test_ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = http.client.HTTPSConnection(
            SALAD_HOST, port=443, timeout=10, context=context
        )
        if self.test_local_port is not None:
            connection.connect = lambda: self._connect_loopback(connection, context)  # type: ignore[method-assign]
        try:
            dispatch_at_utc = canonical_utc(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            if not nonce_ledger.claim_signed_action_dispatch(expected_nonce, action_key, dispatch_at_utc):
                raise ActionTransportBlocked("signed action capability dispatch was already claimed")
            connection.request(
                "POST", path, body=None,
                headers={
                    "Host": SALAD_HOST, "Accept": "application/json",
                    "Accept-Encoding": "identity", "Connection": "close",
                    "Salad-Api-Key": header_value,
                },
            )
            response = connection.getresponse()
            status = response.status
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise ActionTransportFailure("provider returned an invalid status")
            # Response bodies are never read, retained, logged, or echoed.
            return {"http_status_code": status, "request_submitted": True, "actions_performed": False, "response_body": None}
        except (socket.timeout, TimeoutError):
            raise ActionTransportFailure("provider request timed out; outcome may be uncertain") from None
        except ActionTransportFailure:
            raise
        except ssl.SSLError:
            raise ActionTransportFailure("provider TLS verification failed") from None
        except Exception:
            raise ActionTransportFailure("provider request failed; outcome may be uncertain") from None
        finally:
            connection.close()

    def _connect_loopback(self, connection: http.client.HTTPSConnection, context: ssl.SSLContext) -> None:
        if connection.host != SALAD_HOST or connection.port != 443 or self.test_local_port is None:
            raise ActionTransportBlocked("test transport target is invalid")
        raw = socket.create_connection(("127.0.0.1", self.test_local_port), timeout=10)
        try:
            connection.sock = context.wrap_socket(raw, server_hostname=SALAD_HOST)
        except Exception:
            raw.close()
            raise


class SaladActionExecutor:
    """Serialize policy, reserve, SEND_STARTED, one POST, and reconciliation."""

    def __init__(
        self,
        *,
        policy: SaladActionPolicy,
        ledger: ActionLedger,
        transport: RestrictedSaladActionHTTPTransport,
        secret_provider: Any,
        kill_switch: Any,
        clock: Any,
        reconciliation_verifier: Any = None,
        dossier_authority: DecisionDossierAuthority | None = None,
        budget_store: Any = None,
    ):
        self.policy = policy
        self.ledger = ledger
        self.transport = transport
        self.secret_provider = secret_provider
        self.kill_switch = kill_switch
        self.clock = clock
        self.reconciliation_verifier = reconciliation_verifier
        if budget_store is not None and not all(
            callable(getattr(budget_store, method, None))
            for method in ("reserve_budget_exposure", "reconcile_budget_exposure", "append_audit")
        ):
            raise TypeError("action executor requires the durable backend budget store contract")
        self.budget_store = budget_store
        if dossier_authority is not None and type(dossier_authority) is not DecisionDossierAuthority:
            raise TypeError("action executor requires the backend dossier authority")
        self.dossier_authority = dossier_authority or DecisionDossierAuthority()

    def execute(
        self,
        action: SaladAction,
        target: Mapping[str, Any],
        *,
        decision_dossier: VerifiedActionDossier | None = None,
        auto_armed: bool = False,
        before_send_validation: Callable[[], bool] | None = None,
    ) -> ActionReceipt:
        now = float(self.clock())
        early_claims = self.dossier_authority.verified_claims(decision_dossier, now_epoch=now)
        early_dispatch = isinstance(early_claims, Mapping) and early_claims.get("schema_version") == 2
        if early_dispatch:
            assignment_generation = early_claims.get("assignment_generation")
            if (
                action is not SaladAction.REALLOCATE_INSTANCE
                or not isinstance(assignment_generation, str)
                or target.get("assignment_generation") != assignment_generation
                or not callable(before_send_validation)
            ):
                return ActionReceipt("BLOCKED", None, "early-invalid", False, "EARLY_TARGET_GENERATION_OR_REVALIDATION_REQUIRED")
            synthetic_dossier = (
                early_claims.get("data_classification") == "SYNTHETIC/UNVERIFIED"
                and early_claims.get("synthetic_fixture_id") == "G5-SYNTHETIC-ACTION-PATH"
            )
            synthetic_transport = getattr(self.transport, "synthetic_test_only", False) is True
            if synthetic_dossier != synthetic_transport:
                return ActionReceipt("BLOCKED", None, "early-invalid", False, "EARLY_EVIDENCE_TRANSPORT_PROVENANCE_MISMATCH")
            try:
                action_key = ActionLedger.early_live_key_for(action=action.value, target=target)
            except (TypeError, ValueError):
                return ActionReceipt("BLOCKED", None, "early-invalid", False, "EARLY_TARGET_GENERATION_INVALID")
        else:
            if before_send_validation is not None or target.get("assignment_generation") is not None:
                return ActionReceipt("BLOCKED", None, "early-invalid", False, "EARLY_DOSSIER_REQUIRED_FOR_GENERATION_BOUND_DISPATCH")
            try:
                action_key = ActionLedger.live_key_for(action=action.value, target=dict(target))
            except (TypeError, ValueError):
                return ActionReceipt("BLOCKED", None, "invalid-target", False, "INVALID_ACTION_TARGET")
        decision = self.policy.evaluate(
            action, target=dict(target), decision_dossier=decision_dossier,
            dossier_authority=self.dossier_authority,
            kill_switch_clear=bool(getattr(self.kill_switch, "enabled", False)),
            auto_armed=auto_armed, now_epoch=now,
        )
        if not decision.allowed:
            return ActionReceipt("BLOCKED", None, action_key, False, ",".join(decision.blockers))
        try:
            route = fixed_action_path(action, target)
        except (TypeError, ValueError):
            return ActionReceipt("BLOCKED", None, action_key, False, "INVALID_FIXED_ACTION_ROUTE")
        nonce_provider = getattr(self.transport, "action_capability_nonce", None)
        try:
            capability_nonce = nonce_provider(action, target, route, now_epoch=now) if callable(nonce_provider) else None
        except Exception:
            capability_nonce = None
        if not isinstance(capability_nonce, str):
            return ActionReceipt("BLOCKED", None, action_key, False, "SIGNED_ONE_SHOT_ACTION_CAPABILITY_REQUIRED")
        claims = self.dossier_authority.verified_claims(decision_dossier, now_epoch=now)
        required_budget_claims = (
            "action_cost_evidence_id", "action_cost_source_reference", "action_cost_usd", "hard_budget_usd",
        )
        if self.budget_store is None or claims is None or any(
            not isinstance(claims.get(name), str) or not claims[name].strip() for name in required_budget_claims
        ):
            return ActionReceipt("BLOCKED", None, action_key, False, "DURABLE_BUDGET_RESERVATION_REQUIRED")
        try:
            reservation_snapshot = self.ledger.snapshot()
            if not self.dossier_authority.verify_reservation_snapshot(
                decision_dossier,
                current_snapshot=reservation_snapshot,
                now_epoch=now,
            ):
                return ActionReceipt("BLOCKED", None, action_key, False, "ACTION_RESERVATION_OR_RECONCILIATION_UNCLEAR")
        except Exception:
            return ActionReceipt("BLOCKED", None, action_key, False, "ACTION_LEDGER_UNAVAILABLE")
        at_utc = canonical_utc(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))
        if early_dispatch:
            reservation = self.ledger.reserve_live_early(
                action_key, action.value, dict(target), assignment_generation, at_utc,
            )
        else:
            reservation = self.ledger.reserve_live(action_key, action.value, dict(target), at_utc)
        if not reservation["inserted"]:
            return ActionReceipt(
                "BLOCKED", None, action_key, False,
                reservation.get("blocker", "DUPLICATE_OR_RECONCILIATION_REQUIRED"),
            )
        if early_dispatch:
            try:
                revalidation_ok = before_send_validation() is True  # type: ignore[misc]
            except Exception:
                revalidation_ok = False
            if not revalidation_ok:
                self.ledger.transition(
                    action_key, "ABORTED_PRE_SEND", at_utc,
                    {"reason": "exact EARLY assignment generation revalidation failed", "request_submitted": False},
                )
                return ActionReceipt("ABORTED_PRE_SEND", None, action_key, False, "EARLY_TARGET_REVALIDATION_FAILED")
        try:
            nonce_consumed = self.ledger.consume_signed_action_nonce(capability_nonce, action_key, at_utc)
        except Exception:
            nonce_consumed = False
        if not nonce_consumed:
            self.ledger.transition(action_key, "BLOCKED", at_utc, {"reason": "signed one-shot action capability nonce was already consumed or invalid"})
            return ActionReceipt("BLOCKED", None, action_key, False, "ACTION_CAPABILITY_NONCE_ALREADY_USED")
        if not getattr(self.kill_switch, "enabled", False):
            self.ledger.transition(action_key, "ABORTED_PRE_SEND", at_utc, {"reason": "kill switch tripped before send"})
            return ActionReceipt("ABORTED_PRE_SEND", None, action_key, False, "KILL_SWITCH_ACTIVE")
        try:
            budget_reservation = self.budget_store.reserve_budget_exposure(
                action_key=action_key,
                evidence_id=claims["action_cost_evidence_id"],
                source_reference=claims["action_cost_source_reference"],
                amount_usd=claims["action_cost_usd"],
                occurred_at_utc=at_utc,
                source="trusted_backend_reservation",
                hard_budget_usd=claims["hard_budget_usd"],
            )
            if budget_reservation not in {"RESERVED", "ALREADY_RESERVED"}:
                raise ValueError("budget store returned an unsupported reservation state")
        except Exception:
            self.ledger.transition(action_key, "BLOCKED", at_utc, {"reason": "durable budget exposure could not be reserved"})
            return ActionReceipt("BLOCKED", None, action_key, False, "DURABLE_BUDGET_RESERVATION_FAILED")
        if not self._append_action_audit(
            "ACTION_DISPATCH_PREPARED",
            {"action": action.value, "action_key": action_key, "budget_reservation": budget_reservation,
             "target": dict(target), "actions_performed": False},
            at_utc,
        ):
            self.ledger.transition(action_key, "BLOCKED", at_utc, {"reason": "pre-dispatch audit persistence failed"})
            return ActionReceipt("BLOCKED", None, action_key, False, "ACTION_AUDIT_UNAVAILABLE")
        try:
            secret = self.secret_provider.acquire()
        except Exception:
            self.ledger.transition(action_key, "ABORTED_PRE_SEND", at_utc, {"reason": "secret unavailable"})
            return ActionReceipt("ABORTED_PRE_SEND", None, action_key, False, "SECRET_ACCESS_BLOCKED")
        if not getattr(self.kill_switch, "enabled", False):
            self.ledger.transition(action_key, "ABORTED_PRE_SEND", at_utc, {"reason": "kill switch tripped before SEND_STARTED"})
            return ActionReceipt("ABORTED_PRE_SEND", None, action_key, False, "KILL_SWITCH_ACTIVE")
        synthetic_transport = getattr(self.transport, "synthetic_test_only", False) is True
        synthetic_metadata = (
            {"data_classification": "SYNTHETIC/UNVERIFIED", "synthetic_fixture_id": "G5-SYNTHETIC-ACTION-PATH", "simulation_only": True}
            if synthetic_transport else {}
        )
        send_event = "ACTION_SEND_STARTED_SYNTHETIC_SIMULATION" if synthetic_transport else "ACTION_SEND_STARTED"
        if not self._append_action_audit(
            send_event,
            {"action": action.value, "action_key": action_key, "target": dict(target),
             "request_limit": 1, "actions_performed": False, **synthetic_metadata},
            at_utc,
        ):
            self.ledger.transition(action_key, "ABORTED_PRE_SEND", at_utc, {"reason": "pre-send audit persistence failed"})
            return ActionReceipt("ABORTED_PRE_SEND", None, action_key, False, "ACTION_AUDIT_UNAVAILABLE")
        # Persist SEND_STARTED before opening a socket. Any exception thereafter
        # can represent a delivered request, so this operation is never retried.
        self.ledger.transition(action_key, "SEND_STARTED", at_utc, {"reason": "single POST may begin", **synthetic_metadata})
        try:
            response = self.transport.submit_bound(
                action, target, secret, action_key=action_key,
                authorization_nonce=capability_nonce, nonce_ledger=self.ledger,
            )
        except Exception:
            uncertain_receipt = {
                "request_submitted": False if synthetic_transport else None,
                "reason": "synthetic POST simulation failed" if synthetic_transport else "POST outcome uncertain; automatic retry forbidden",
                **synthetic_metadata,
            }
            self.ledger.transition(action_key, "RECONCILIATION_REQUIRED", at_utc, uncertain_receipt)
            self._append_action_audit(
                "ACTION_RECONCILIATION_REQUIRED_SYNTHETIC_SIMULATION" if synthetic_transport else "ACTION_RECONCILIATION_REQUIRED",
                {"action": action.value, "action_key": action_key,
                 "reason": "SYNTHETIC_POST_SIMULATION_FAILED" if synthetic_transport else "POST_OUTCOME_UNCERTAIN",
                 "actions_performed": False, **synthetic_metadata},
                at_utc,
            )
            return ActionReceipt(
                "RECONCILIATION_REQUIRED", None, action_key, False,
                "SYNTHETIC_POST_SIMULATION_FAILED" if synthetic_transport else "POST_OUTCOME_UNCERTAIN",
                False if synthetic_transport else None,
                "SYNTHETIC/UNVERIFIED" if synthetic_transport else None,
                "G5-SYNTHETIC-ACTION-PATH" if synthetic_transport else None,
            )
        status = response.get("http_status_code")
        response_classification = response.get("data_classification")
        response_fixture_id = response.get("synthetic_fixture_id")
        synthetic_response = (
            synthetic_transport
            and response_classification == "SYNTHETIC/UNVERIFIED"
            and response_fixture_id == "G5-SYNTHETIC-ACTION-PATH"
        )
        if synthetic_transport and not synthetic_response:
            details = {
                "http_status_code": status if isinstance(status, int) else None,
                "request_submitted": False,
                "reason": "synthetic transport response provenance is invalid",
                **synthetic_metadata,
            }
            self.ledger.transition(action_key, "RECONCILIATION_REQUIRED", at_utc, details)
            self._append_action_audit(
                "ACTION_RECONCILIATION_REQUIRED_SYNTHETIC_SIMULATION",
                {"action": action.value, "action_key": action_key, "reason": "SYNTHETIC_RESPONSE_PROVENANCE_INVALID", "actions_performed": False, **synthetic_metadata},
                at_utc,
            )
            return ActionReceipt("RECONCILIATION_REQUIRED", None, action_key, False, "SYNTHETIC_RESPONSE_PROVENANCE_INVALID", False, "SYNTHETIC/UNVERIFIED", "G5-SYNTHETIC-ACTION-PATH")
        if not synthetic_transport and (response_classification is not None or response_fixture_id is not None):
            self.ledger.transition(action_key, "RECONCILIATION_REQUIRED", at_utc, {
                "http_status_code": status if isinstance(status, int) else None,
                "request_submitted": None,
                "reason": "unexpected synthetic provenance on provider transport response",
            })
            self._append_action_audit(
                "ACTION_RECONCILIATION_REQUIRED",
                {"action": action.value, "action_key": action_key, "reason": "UNEXPECTED_SYNTHETIC_PROVIDER_RESPONSE", "actions_performed": False},
                at_utc,
            )
            return ActionReceipt("RECONCILIATION_REQUIRED", status if isinstance(status, int) else None, action_key, False, "UNEXPECTED_SYNTHETIC_PROVIDER_RESPONSE", None)
        if status == 202:
            accepted_receipt = {
                "http_status_code": 202,
                "request_submitted": False if synthetic_response else True,
                **(synthetic_metadata if synthetic_response else {}),
            }
            self.ledger.transition(action_key, "ACCEPTED_PENDING", at_utc, accepted_receipt)
            self._append_action_audit(
                "ACTION_ACCEPTED_PENDING_SYNTHETIC_SIMULATION" if synthetic_response else "ACTION_ACCEPTED_PENDING",
                {"action": action.value, "action_key": action_key, "http_status_code": 202,
                 "actions_performed": False, **(synthetic_metadata if synthetic_response else {})},
                at_utc,
            )
            return ActionReceipt(
                "ACCEPTED_PENDING", 202, action_key, False,
                request_submitted=False if synthetic_response else True,
                data_classification="SYNTHETIC/UNVERIFIED" if synthetic_response else None,
                synthetic_fixture_id="G5-SYNTHETIC-ACTION-PATH" if synthetic_response else None,
            )
        self.ledger.transition(action_key, "RECONCILIATION_REQUIRED", at_utc, {"http_status_code": status, "request_submitted": True, "reason": "non-202 POST response; verify state before further action"})
        self._append_action_audit(
            "ACTION_RECONCILIATION_REQUIRED",
            {"action": action.value, "action_key": action_key, "http_status_code": status,
             "actions_performed": False},
            at_utc,
        )
        return ActionReceipt("RECONCILIATION_REQUIRED", status if isinstance(status, int) else None, action_key, False, "POST_RESULT_NOT_TERMINAL", True)

    def _append_action_audit(self, event_type: str, payload: Mapping[str, Any], at_utc: str) -> bool:
        append = getattr(self.budget_store, "append_audit", None)
        if not callable(append):
            return False
        try:
            append(event_type, payload, at_utc)
            return True
        except Exception:
            return False

    def reconcile(self, action_key: str, provider_observation: Mapping[str, Any], *, at_utc: str) -> ActionReceipt:
        """Resolve a pending action only with an injected independent verifier.

        A GET snapshot, matching ID, or caller-supplied boolean alone does not
        prove the action's outcome. This build has no default verifier, so it
        preserves RECONCILIATION_REQUIRED until a reviewed verifier exists.
        """
        entry = self.ledger.get(action_key)
        if entry is None:
            raise KeyError(action_key)
        state = entry["state"]
        if state not in {"ACCEPTED_PENDING", "RECONCILIATION_REQUIRED"}:
            return ActionReceipt("BLOCKED", None, action_key, False, "ACTION_NOT_PENDING_RECONCILIATION")
        provenance = provider_observation.get("source_provenance") if isinstance(provider_observation, Mapping) else None
        observation_digest = provider_observation.get("sanitized_observation_sha256") if isinstance(provider_observation, Mapping) else None
        verifier = self.reconciliation_verifier
        prior_receipt = entry.get("receipt") if isinstance(entry.get("receipt"), Mapping) else {}
        recommendation = entry.get("recommendation") if isinstance(entry.get("recommendation"), Mapping) else {}
        early_target = (
            recommendation.get("target")
            if recommendation.get("dispatch_kind") == "EARLY"
            and isinstance(recommendation.get("target"), Mapping)
            else None
        )
        prior_dispatch_is_synthetic = (
            prior_receipt.get("data_classification") == "SYNTHETIC/UNVERIFIED"
            and prior_receipt.get("synthetic_fixture_id") == "G5-SYNTHETIC-ACTION-PATH"
        )
        provider_observed = (
            not prior_dispatch_is_synthetic
            and isinstance(provenance, Mapping)
            and provider_observation.get("data_classification") == "PROVIDER_OBSERVED"
            and provenance.get("system") == "salad_api"
            and provenance.get("host") == SALAD_HOST
            and provenance.get("transport_tls_hostname_verified") is True
        )
        synthetic_test_observation = (
            getattr(verifier, "synthetic_test_only", False) is True
            and prior_dispatch_is_synthetic
            and isinstance(provenance, Mapping)
            and provider_observation.get("data_classification") == "SYNTHETIC/UNVERIFIED"
            and provenance.get("system") == "synthetic_test_fixture"
            and provenance.get("host") == "loopback"
            and provenance.get("transport_tls_hostname_verified") is False
            and provider_observation.get("synthetic_fixture_id") == "G5-SYNTHETIC-ACTION-PATH"
        )
        if (
            not (provider_observed or synthetic_test_observation)
            or provider_observation.get("container_group") != entry["recommendation"].get("target", {}).get("container_group")
            or not isinstance(observation_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", observation_digest) is None
        ):
            return ActionReceipt("RECONCILIATION_REQUIRED", None, action_key, False, "INDEPENDENT_PROVIDER_OBSERVATION_REQUIRED")
        early_replacement = None
        if early_target is not None:
            early_replacement, early_reason = self._validated_early_replacement(
                early_target, provider_observation, entry=entry, at_utc=at_utc,
            )
            if early_replacement is None:
                return ActionReceipt("RECONCILIATION_REQUIRED", None, action_key, False, early_reason)
        if verifier is None or not callable(getattr(verifier, "verify_action_outcome", None)):
            return ActionReceipt("RECONCILIATION_REQUIRED", None, action_key, False, "NO_INDEPENDENT_ACTION_OUTCOME_VERIFIER_CONFIGURED")
        try:
            verified_change = verifier.verify_action_outcome(entry, provider_observation) is True
        except Exception:
            verified_change = False
        if not verified_change:
            return ActionReceipt("RECONCILIATION_REQUIRED", None, action_key, False, "PROVIDER_OBSERVATION_DID_NOT_PROVE_TERMINAL_CHANGE")
        timestamp = canonical_utc(at_utc)
        if self.budget_store is None:
            return ActionReceipt("RECONCILIATION_REQUIRED", None, action_key, False, "DURABLE_BUDGET_STORE_REQUIRED_FOR_RECONCILIATION")
        if synthetic_test_observation:
            # Preserve the exposure as pending and label this terminal test result
            # as simulation-only. Synthetic fixtures can never establish provider
            # state or clear the budget reservation.
            synthetic_receipt = {
                "evidence_id": observation_digest,
                "result": "synthetic_simulation_only",
                "data_classification": "SYNTHETIC/UNVERIFIED",
                "synthetic_fixture_id": "G5-SYNTHETIC-ACTION-PATH",
                "simulation_only": True,
                "request_submitted": False,
            }
            if early_replacement is not None:
                synthetic_receipt.update(early_replacement)
            self.ledger.transition(
                action_key, "RECONCILED_SYNTHETIC_SIMULATION", timestamp, synthetic_receipt,
            )
            self._append_action_audit(
                "ACTION_RECONCILED_SYNTHETIC_SIMULATION",
                {"action_key": action_key, "evidence_id": observation_digest,
                 "data_classification": "SYNTHETIC/UNVERIFIED",
                 "synthetic_fixture_id": "G5-SYNTHETIC-ACTION-PATH",
                 "simulation_only": True, "actions_performed": False,
                 **(early_replacement or {})},
                timestamp,
            )
            return ActionReceipt(
                "RECONCILED_SYNTHETIC_SIMULATION", None, action_key, False,
                request_submitted=False, data_classification="SYNTHETIC/UNVERIFIED",
                synthetic_fixture_id="G5-SYNTHETIC-ACTION-PATH",
            )
        try:
            self.budget_store.reconcile_budget_exposure(
                action_key, evidence_id=observation_digest, status="RECONCILED",
                occurred_at_utc=timestamp, source="trusted_backend_reconciliation",
            )
        except Exception:
            return ActionReceipt("RECONCILIATION_REQUIRED", None, action_key, False, "DURABLE_BUDGET_RECONCILIATION_REQUIRED")
        self.ledger.transition(
            action_key,
            "RECONCILED_OBSERVED_CHANGE",
            timestamp,
            {"evidence_id": observation_digest, "result": "independently_verified_provider_change",
             **(early_replacement or {})},
        )
        self._append_action_audit(
            "ACTION_RECONCILED_OBSERVED_CHANGE",
            {"action_key": action_key, "evidence_id": observation_digest, "actions_performed": True},
            timestamp,
        )
        return ActionReceipt("RECONCILED_OBSERVED_CHANGE", None, action_key, True, request_submitted=True)

    @staticmethod
    def _validated_early_replacement(
        old_target: Mapping[str, Any],
        observation: Mapping[str, Any],
        *,
        entry: Mapping[str, Any],
        at_utc: str,
    ) -> tuple[dict[str, Any] | None, str]:
        """Require a complete, later, same-scope replacement assignment."""
        replacement = observation.get("replacement_binding")
        required = (
            "organization", "project", "container_group", "machine_id", "instance_id",
            "assignment_id", "assignment_generation", "observed_at_utc",
        )
        if not isinstance(replacement, Mapping) or any(name not in replacement for name in required):
            return None, "EARLY_REPLACEMENT_IDENTITY_INCOMPLETE"
        for name in ("organization", "project", "container_group"):
            if replacement.get(name) != old_target.get(name):
                return None, "EARLY_REPLACEMENT_SCOPE_MISMATCH"
        for name in ("machine_id", "assignment_id", "assignment_generation"):
            value = replacement.get(name)
            if not isinstance(value, str) or not _SAFE_PROVIDER_ID.fullmatch(value):
                return None, "EARLY_REPLACEMENT_IDENTITY_INVALID"
        try:
            new_instance = str(uuid.UUID(replacement.get("instance_id")))
            old_instance = str(uuid.UUID(old_target.get("instance_id")))
        except (TypeError, ValueError, AttributeError):
            return None, "EARLY_REPLACEMENT_IDENTITY_INVALID"
        if new_instance != replacement.get("instance_id") or new_instance == old_instance:
            return None, "EARLY_REPLACEMENT_INSTANCE_NOT_NEW"
        if (
            replacement.get("assignment_id") == old_target.get("assignment_id")
            or replacement.get("assignment_generation") == old_target.get("assignment_generation")
        ):
            return None, "EARLY_REPLACEMENT_GENERATION_NOT_NEW"
        observed_at = _parse_utc(replacement.get("observed_at_utc"))
        accepted_at = _parse_utc(entry.get("updated_at_utc"))
        reconciliation_at = _parse_utc(at_utc)
        if observed_at is None or accepted_at is None or reconciliation_at is None:
            return None, "EARLY_REPLACEMENT_TIME_INVALID"
        if not accepted_at < observed_at <= reconciliation_at:
            return None, "EARLY_REPLACEMENT_TIME_ORDER_INVALID"
        return {
            "reconciled_from": {
                key: old_target[key]
                for key in ("organization", "project", "container_group", "machine_id", "instance_id", "assignment_id", "assignment_generation")
            },
            "reconciled_to": {
                key: replacement[key]
                for key in ("organization", "project", "container_group", "machine_id", "instance_id", "assignment_id", "assignment_generation")
            },
            "replacement_observed_at_utc": observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        }, ""
