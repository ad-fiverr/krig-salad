"""Atomic local idempotency ledger for dry-run and mocked action lifecycles."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .guard_store import canonical_utc


_ALLOWED_STATES = frozenset({
    "DRY_RUN_RESERVED", "MOCK_ACCEPTED_PENDING", "MOCK_CONFIRMED",
    "BLOCKED", "RECONCILIATION_REQUIRED", "UNKNOWN",
    "RESERVED", "SEND_STARTED", "ACCEPTED_PENDING",
    "RECONCILED_OBSERVED_CHANGE", "RECONCILED_SYNTHETIC_SIMULATION",
    "ABORTED_PRE_SEND",
})
_TRANSITIONS = {
    "DRY_RUN_RESERVED": {"MOCK_ACCEPTED_PENDING", "BLOCKED", "RECONCILIATION_REQUIRED", "UNKNOWN"},
    "MOCK_ACCEPTED_PENDING": {"MOCK_CONFIRMED", "RECONCILIATION_REQUIRED", "UNKNOWN"},
    "RECONCILIATION_REQUIRED": {"MOCK_CONFIRMED", "RECONCILED_OBSERVED_CHANGE", "RECONCILED_SYNTHETIC_SIMULATION", "BLOCKED", "UNKNOWN"},
    "MOCK_CONFIRMED": set(),
    "BLOCKED": set(),
    "UNKNOWN": set(),
    "RESERVED": {"SEND_STARTED", "BLOCKED", "ABORTED_PRE_SEND", "UNKNOWN"},
    "SEND_STARTED": {"ACCEPTED_PENDING", "RECONCILIATION_REQUIRED", "UNKNOWN"},
    "ACCEPTED_PENDING": {"RECONCILED_OBSERVED_CHANGE", "RECONCILED_SYNTHETIC_SIMULATION", "RECONCILIATION_REQUIRED", "UNKNOWN"},
    "RECONCILED_OBSERVED_CHANGE": set(),
    "RECONCILED_SYNTHETIC_SIMULATION": set(),
    "ABORTED_PRE_SEND": set(),
}
_SENSITIVE_KEYS = {"authorization", "api_key", "token", "password", "secret", "credential"}
_SIMULATION_PENDING_STATES = (
    "SIMULATION_RESERVED", "SIMULATED_ACCEPTED_PENDING", "SIMULATED_RECONCILIATION_REQUIRED",
)
_SIMULATION_CONTROL_EVENTS = frozenset({
    "PROCESS_START_CLOSED", "SERVICE_START_CLOSED", "SIMULATION_ARMED",
    "SIMULATION_DISARMED", "SIMULATION_ARM_BLOCKED", "KILL_SWITCH_ENGAGED",
    "KILL_SWITCH_DISENGAGED",
})
_SIMULATION_FIXTURE_ID = "G5-SYNTHETIC-ACTION-PATH"
_SIMULATION_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class VerifiedSyntheticSimulationObservation:
    """A verifier-produced, reservation-bound synthetic terminal observation."""

    schema_version: str
    synthetic_fixture_id: str
    evidence_reference: str
    simulation_key: str
    assignment_scope: str
    target_scope: str
    original_instance_fingerprint: str
    original_generation_fingerprint: str
    result: str
    observed_instance_fingerprint: str | None
    observed_generation_fingerprint: str | None
    observed_at_utc: str

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "synthetic_fixture_id": self.synthetic_fixture_id,
            "evidence_reference": self.evidence_reference,
            "simulation_key": self.simulation_key,
            "assignment_scope": self.assignment_scope,
            "target_scope": self.target_scope,
            "original_instance_fingerprint": self.original_instance_fingerprint,
            "original_generation_fingerprint": self.original_generation_fingerprint,
            "result": self.result,
            "observed_instance_fingerprint": self.observed_instance_fingerprint,
            "observed_generation_fingerprint": self.observed_generation_fingerprint,
            "observed_at_utc": self.observed_at_utc,
        }


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _reject_secrets(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and any(fragment in key.casefold() for fragment in _SENSITIVE_KEYS):
                raise ValueError("action ledger payload must not contain credentials or secret-like fields")
            _reject_secrets(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_secrets(item)


def _serialized(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper
class ActionLedger:
    """Single-host SQLite ledger; distributed production guarantees are not implied."""

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS action_ledger (
                action_key TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                recommendation_json TEXT NOT NULL,
                receipt_json TEXT NOT NULL
            )"""
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS action_capability_nonces (
                nonce_sha256 TEXT PRIMARY KEY,
                action_key TEXT NOT NULL UNIQUE,
                consumed_at_utc TEXT NOT NULL,
                FOREIGN KEY(action_key) REFERENCES action_ledger(action_key)
            )"""
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS action_capability_dispatches (
                nonce_sha256 TEXT PRIMARY KEY,
                action_key TEXT NOT NULL UNIQUE,
                dispatched_at_utc TEXT NOT NULL,
                FOREIGN KEY(action_key) REFERENCES action_ledger(action_key)
            )"""
        )
        # EARLY startup reallocation has a stricter idempotency boundary than
        # the historical steady-state action key: one provider assignment
        # generation can consume at most one dispatch reservation, including
        # after restart or terminal reconciliation.
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS early_generation_dispatch_locks (
                generation_scope_sha256 TEXT PRIMARY KEY,
                action_key TEXT NOT NULL UNIQUE,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(action_key) REFERENCES action_ledger(action_key)
            )"""
        )
        # SCRUM-101 simulation admissions are deliberately isolated from the
        # provider-action state machine above. No simulation row can be
        # transitioned into RESERVED, SEND_STARTED, or a provider receipt.
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS auto_reallocation_simulations (
                simulation_key TEXT PRIMARY KEY,
                trigger_key TEXT NOT NULL,
                organization_scope TEXT NOT NULL,
                fleet_scope TEXT NOT NULL,
                assignment_scope TEXT NOT NULL,
                target_scope TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                created_at_epoch REAL NOT NULL,
                state TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                reconciled_at_utc TEXT
            )"""
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS auto_reallocation_simulations_org_time "
            "ON auto_reallocation_simulations(organization_scope, created_at_epoch)"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS auto_reallocation_simulations_fleet_time "
            "ON auto_reallocation_simulations(fleet_scope, created_at_epoch)"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS auto_reallocation_simulations_assignment_time "
            "ON auto_reallocation_simulations(assignment_scope, created_at_epoch)"
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS auto_reallocation_simulation_control (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                process_id INTEGER NOT NULL,
                effective_armed INTEGER NOT NULL CHECK(effective_armed IN (0, 1)),
                kill_switch_engaged INTEGER NOT NULL CHECK(kill_switch_engaged IN (0, 1)),
                updated_at_utc TEXT NOT NULL
            )"""
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS auto_reallocation_simulation_control_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                effective_armed INTEGER NOT NULL CHECK(effective_armed IN (0, 1)),
                kill_switch_engaged INTEGER NOT NULL CHECK(kill_switch_engaged IN (0, 1)),
                at_utc TEXT NOT NULL,
                limits_json TEXT NOT NULL
            )"""
        )
        self._initialize_simulation_control()

    def _initialize_simulation_control(self) -> None:
        process_id = os.getpid()
        timestamp = canonical_utc(datetime.now(timezone.utc).isoformat())
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT process_id FROM auto_reallocation_simulation_control WHERE singleton=1"
            ).fetchone()
            if row is None:
                self.connection.execute(
                    "INSERT INTO auto_reallocation_simulation_control VALUES (1, ?, 0, 1, ?)",
                    (process_id, timestamp),
                )
                self._insert_simulation_control_event(
                    process_id, "PROCESS_START_CLOSED", False, True, timestamp, {},
                )
            elif int(row["process_id"]) != process_id:
                self.connection.execute(
                    "UPDATE auto_reallocation_simulation_control "
                    "SET process_id=?, effective_armed=0, kill_switch_engaged=1, updated_at_utc=? WHERE singleton=1",
                    (process_id, timestamp),
                )
                self._insert_simulation_control_event(
                    process_id, "PROCESS_START_CLOSED", False, True, timestamp, {},
                )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def _insert_simulation_control_event(
        self, process_id: int, event_type: str, armed: bool, kill_switch_engaged: bool,
        at_utc: str, limits: Mapping[str, int],
    ) -> None:
        self.connection.execute(
            "INSERT INTO auto_reallocation_simulation_control_events "
            "(process_id, event_type, effective_armed, kill_switch_engaged, at_utc, limits_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (process_id, event_type, int(armed), int(kill_switch_engaged), at_utc, _json(dict(limits))),
        )

    @_serialized
    def close(self) -> None:
        self.connection.close()

    @_serialized
    def reserve(self, action_key: str, recommendation: Mapping[str, Any], at_utc: str) -> dict[str, Any]:
        if not isinstance(action_key, str) or not action_key.strip():
            raise ValueError("action_key must be non-empty")
        timestamp = canonical_utc(at_utc)
        payload = dict(recommendation)
        _reject_secrets(payload)
        encoded = _json(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT * FROM action_ledger WHERE action_key=?", (action_key,)).fetchone()
            if row is not None:
                if row["recommendation_json"] != encoded:
                    raise ValueError("idempotency key already exists for a different recommendation")
                self.connection.execute("COMMIT")
                return self.get(action_key) | {"inserted": False}  # type: ignore[operator]
            receipt = {"actions_performed": False, "mode": "offline_dry_run"}
            self.connection.execute(
                "INSERT INTO action_ledger VALUES (?, ?, ?, ?, ?, ?)",
                (action_key, "DRY_RUN_RESERVED", timestamp, timestamp, encoded, _json(receipt)),
            )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        return self.get(action_key) | {"inserted": True}  # type: ignore[operator]

    @_serialized
    def consume_signed_action_nonce(self, nonce: str, action_key: str, at_utc: str) -> bool:
        """Durably bind one signed grant nonce to one already-reserved action.

        Only a digest of the nonce is stored. A replay remains rejected after
        process restarts, including replay against the same action key.
        """
        try:
            canonical_nonce = str(uuid.UUID(nonce))
        except (TypeError, ValueError, AttributeError):
            return False
        if canonical_nonce != nonce or not isinstance(action_key, str) or not action_key.strip():
            return False
        timestamp = canonical_utc(at_utc)
        nonce_digest = hashlib.sha256(canonical_nonce.encode("ascii")).hexdigest()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            action = self.connection.execute(
                "SELECT state FROM action_ledger WHERE action_key=?", (action_key,),
            ).fetchone()
            if action is None or action["state"] != "RESERVED":
                self.connection.execute("COMMIT")
                return False
            used_nonce = self.connection.execute(
                "SELECT 1 FROM action_capability_nonces WHERE nonce_sha256=?", (nonce_digest,),
            ).fetchone()
            used_action = self.connection.execute(
                "SELECT 1 FROM action_capability_nonces WHERE action_key=?", (action_key,),
            ).fetchone()
            if used_nonce is not None or used_action is not None:
                self.connection.execute("COMMIT")
                return False
            self.connection.execute(
                "INSERT INTO action_capability_nonces VALUES (?, ?, ?)",
                (nonce_digest, action_key, timestamp),
            )
            self.connection.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            self.connection.execute("ROLLBACK")
            return False
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    @_serialized
    def signed_action_nonce_is_bound(self, nonce: str, action_key: str) -> bool:
        """Check a one-shot capability's durable action binding without exposing its digest."""
        try:
            canonical_nonce = str(uuid.UUID(nonce))
        except (TypeError, ValueError, AttributeError):
            return False
        if canonical_nonce != nonce or not isinstance(action_key, str) or not action_key.strip():
            return False
        digest = hashlib.sha256(canonical_nonce.encode("ascii")).hexdigest()
        row = self.connection.execute(
            "SELECT 1 FROM action_capability_nonces WHERE nonce_sha256=? AND action_key=?",
            (digest, action_key),
        ).fetchone()
        return row is not None

    @_serialized
    def claim_signed_action_dispatch(self, nonce: str, action_key: str, at_utc: str) -> bool:
        """Atomically claim the only send attempt allowed by a consumed nonce."""
        try:
            canonical_nonce = str(uuid.UUID(nonce))
        except (TypeError, ValueError, AttributeError):
            return False
        if canonical_nonce != nonce or not isinstance(action_key, str) or not action_key.strip():
            return False
        timestamp = canonical_utc(at_utc)
        digest = hashlib.sha256(canonical_nonce.encode("ascii")).hexdigest()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT state FROM action_ledger WHERE action_key=?", (action_key,),
            ).fetchone()
            binding = self.connection.execute(
                "SELECT 1 FROM action_capability_nonces WHERE nonce_sha256=? AND action_key=?",
                (digest, action_key),
            ).fetchone()
            dispatched = self.connection.execute(
                "SELECT 1 FROM action_capability_dispatches WHERE nonce_sha256=? OR action_key=?",
                (digest, action_key),
            ).fetchone()
            if row is None or row["state"] != "SEND_STARTED" or binding is None or dispatched is not None:
                self.connection.execute("COMMIT")
                return False
            self.connection.execute(
                "INSERT INTO action_capability_dispatches VALUES (?, ?, ?)",
                (digest, action_key, timestamp),
            )
            self.connection.execute("COMMIT")
            return True
        except sqlite3.IntegrityError:
            self.connection.execute("ROLLBACK")
            return False
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    @_serialized
    def reserve_live(
        self,
        action_key: str,
        action: str,
        target: Mapping[str, Any],
        at_utc: str,
    ) -> dict[str, Any]:
        if action not in {"START_GROUP", "STOP_GROUP", "REALLOCATE_INSTANCE"}:
            raise ValueError("live action type is not allowed")
        if not isinstance(target, Mapping):
            raise ValueError("live target must be a mapping")
        timestamp = canonical_utc(at_utc)
        payload = {"action": action, "target": dict(target), "actions_performed": False}
        _reject_secrets(payload)
        encoded = _json(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT * FROM action_ledger WHERE action_key=?", (action_key,)).fetchone()
            if row is not None:
                if row["recommendation_json"] != encoded:
                    raise ValueError("idempotency key already exists for a different action")
                self.connection.execute("COMMIT")
                return self.get(action_key) | {"inserted": False}  # type: ignore[operator]
            active_rows = self.connection.execute(
                "SELECT recommendation_json FROM action_ledger WHERE state IN "
                "('RESERVED', 'SEND_STARTED', 'ACCEPTED_PENDING', 'RECONCILIATION_REQUIRED')"
            ).fetchall()
            for active_row in active_rows:
                active = json.loads(active_row["recommendation_json"])
                if active.get("action") in {"START_GROUP", "STOP_GROUP", "REALLOCATE_INSTANCE"}:
                    self.connection.execute("COMMIT")
                    return {
                        "action_key": action_key,
                        "state": "BLOCKED_ACTIVE_ACTION",
                        "inserted": False,
                        "blocker": "ANOTHER_PROVIDER_ACTION_REQUIRES_RECONCILIATION",
                    }
            receipt = {"actions_performed": False, "mode": "live_action_reserved_not_sent"}
            self.connection.execute(
                "INSERT INTO action_ledger VALUES (?, 'RESERVED', ?, ?, ?, ?)",
                (action_key, timestamp, timestamp, encoded, _json(receipt)),
            )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        return self.get(action_key) | {"inserted": True}  # type: ignore[operator]

    @_serialized
    def reserve_live_early(
        self,
        action_key: str,
        action: str,
        target: Mapping[str, Any],
        assignment_generation: str,
        at_utc: str,
    ) -> dict[str, Any]:
        """Atomically reserve the only EARLY dispatch for one assignment generation.

        The lock survives all state transitions. A corrected/restarted caller
        cannot issue another POST for a generation that already reserved an
        EARLY action. A different, verified generation has its own lock key.
        """
        if action != "REALLOCATE_INSTANCE":
            raise ValueError("EARLY live action must be REALLOCATE_INSTANCE")
        if not isinstance(target, Mapping) or not isinstance(assignment_generation, str) or not assignment_generation.strip():
            raise ValueError("EARLY target and assignment generation are required")
        target_copy = dict(target)
        if target_copy.get("assignment_generation") != assignment_generation:
            raise ValueError("EARLY target generation does not match the reservation")
        expected_key = self.early_live_key_for(action=action, target=target_copy)
        if action_key != expected_key:
            raise ValueError("EARLY action key does not match the exact target generation")
        timestamp = canonical_utc(at_utc)
        generation_scope = self._early_generation_scope_sha256(target_copy, assignment_generation)
        payload = {
            "action": action,
            "target": target_copy,
            "dispatch_kind": "EARLY",
            "assignment_generation": assignment_generation,
            "actions_performed": False,
        }
        _reject_secrets(payload)
        encoded = _json(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT * FROM action_ledger WHERE action_key=?", (action_key,),
            ).fetchone()
            if row is not None:
                if row["recommendation_json"] != encoded:
                    self.connection.execute("COMMIT")
                    return {
                        "action_key": action_key,
                        "state": "BLOCKED_EARLY_GENERATION_ALREADY_DISPATCHED",
                        "inserted": False,
                        "blocker": "EARLY_GENERATION_ALREADY_DISPATCHED",
                    }
                self.connection.execute("COMMIT")
                return self.get(action_key) | {"inserted": False, "blocker": "EARLY_GENERATION_ALREADY_DISPATCHED"}  # type: ignore[operator]
            lock = self.connection.execute(
                "SELECT action_key FROM early_generation_dispatch_locks WHERE generation_scope_sha256=?",
                (generation_scope,),
            ).fetchone()
            if lock is not None:
                self.connection.execute("COMMIT")
                return {
                    "action_key": action_key,
                    "state": "BLOCKED_EARLY_GENERATION_ALREADY_DISPATCHED",
                    "inserted": False,
                    "blocker": "EARLY_GENERATION_ALREADY_DISPATCHED",
                }
            # Earlier SCRUM-175 iterations included machine_id in the lock
            # hash. Recover their durable lock meaning from the sealed ledger
            # recommendation so changing physical hosts cannot reopen the same
            # assignment generation after upgrade.
            legacy_locks = self.connection.execute(
                "SELECT a.recommendation_json FROM early_generation_dispatch_locks AS l "
                "JOIN action_ledger AS a ON a.action_key=l.action_key"
            ).fetchall()
            for legacy_lock in legacy_locks:
                try:
                    previous = json.loads(legacy_lock["recommendation_json"])
                    previous_target = previous.get("target") if isinstance(previous, dict) else None
                    previous_generation = previous.get("assignment_generation") if isinstance(previous, dict) else None
                    if not isinstance(previous_target, Mapping) or not isinstance(previous_generation, str):
                        raise ValueError("legacy EARLY lock recommendation is invalid")
                    previous_scope = self._early_generation_scope_sha256(previous_target, previous_generation)
                except (TypeError, ValueError, json.JSONDecodeError):
                    self.connection.execute("COMMIT")
                    return {
                        "action_key": action_key,
                        "state": "BLOCKED_EARLY_GENERATION_LOCK_INTEGRITY",
                        "inserted": False,
                        "blocker": "EARLY_GENERATION_LOCK_INTEGRITY_INVALID",
                    }
                if previous_scope == generation_scope:
                    self.connection.execute("COMMIT")
                    return {
                        "action_key": action_key,
                        "state": "BLOCKED_EARLY_GENERATION_ALREADY_DISPATCHED",
                        "inserted": False,
                        "blocker": "EARLY_GENERATION_ALREADY_DISPATCHED",
                    }
            active_rows = self.connection.execute(
                "SELECT recommendation_json FROM action_ledger WHERE state IN "
                "('RESERVED', 'SEND_STARTED', 'ACCEPTED_PENDING', 'RECONCILIATION_REQUIRED')"
            ).fetchall()
            for active_row in active_rows:
                active = json.loads(active_row["recommendation_json"])
                if active.get("action") in {"START_GROUP", "STOP_GROUP", "REALLOCATE_INSTANCE"}:
                    self.connection.execute("COMMIT")
                    return {
                        "action_key": action_key,
                        "state": "BLOCKED_ACTIVE_ACTION",
                        "inserted": False,
                        "blocker": "ANOTHER_PROVIDER_ACTION_REQUIRES_RECONCILIATION",
                    }
            receipt = {"actions_performed": False, "mode": "live_early_action_reserved_not_sent"}
            self.connection.execute(
                "INSERT INTO action_ledger VALUES (?, 'RESERVED', ?, ?, ?, ?)",
                (action_key, timestamp, timestamp, encoded, _json(receipt)),
            )
            self.connection.execute(
                "INSERT INTO early_generation_dispatch_locks VALUES (?, ?, ?)",
                (generation_scope, action_key, timestamp),
            )
            self.connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            self.connection.execute("ROLLBACK")
            return {
                "action_key": action_key,
                "state": "BLOCKED_EARLY_GENERATION_ALREADY_DISPATCHED",
                "inserted": False,
                "blocker": "EARLY_GENERATION_ALREADY_DISPATCHED",
            }
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        return self.get(action_key) | {"inserted": True}  # type: ignore[operator]

    @_serialized
    def transition(self, action_key: str, state: str, at_utc: str, receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
        if state not in _ALLOWED_STATES:
            raise ValueError("provider action state is not supported by the action ledger")
        timestamp = canonical_utc(at_utc)
        payload = dict(receipt or {})
        _reject_secrets(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT * FROM action_ledger WHERE action_key=?", (action_key,)).fetchone()
            if row is None:
                raise KeyError(action_key)
            current = row["state"]
            previous_receipt = json.loads(row["receipt_json"])
            previous_is_synthetic = (
                previous_receipt.get("data_classification") == "SYNTHETIC/UNVERIFIED"
                and previous_receipt.get("synthetic_fixture_id") == "G5-SYNTHETIC-ACTION-PATH"
                and previous_receipt.get("simulation_only") is True
            )
            if state == current:
                self.connection.execute("COMMIT")
                return self.get(action_key)  # type: ignore[return-value]
            if state not in _TRANSITIONS[current]:
                raise ValueError(f"invalid action ledger transition: {current} -> {state}")
            if previous_is_synthetic and state == "RECONCILED_OBSERVED_CHANGE":
                raise ValueError("synthetic action history cannot become provider-observed state")
            if previous_is_synthetic:
                payload.update({
                    "data_classification": "SYNTHETIC/UNVERIFIED",
                    "synthetic_fixture_id": "G5-SYNTHETIC-ACTION-PATH",
                    "simulation_only": True,
                    "request_submitted": False,
                })
            if state == "RECONCILED_SYNTHETIC_SIMULATION":
                if (
                    not previous_is_synthetic
                    or payload.get("data_classification") != "SYNTHETIC/UNVERIFIED"
                    or payload.get("synthetic_fixture_id") != "G5-SYNTHETIC-ACTION-PATH"
                    or payload.get("simulation_only") is not True
                ):
                    raise ValueError("synthetic reconciliation requires explicit fixture provenance")
                payload["actions_performed"] = False
                payload["request_submitted"] = False
            elif state == "RECONCILED_OBSERVED_CHANGE":
                if (
                    payload.get("data_classification") == "SYNTHETIC/UNVERIFIED"
                    or "synthetic_fixture_id" in payload
                    or payload.get("simulation_only") is True
                ):
                    raise ValueError("synthetic evidence cannot establish a provider-observed action")
                payload["actions_performed"] = True
            else:
                payload["actions_performed"] = False
            if "request_submitted" not in payload:
                payload["request_submitted"] = (
                    True if state in {"ACCEPTED_PENDING", "RECONCILED_OBSERVED_CHANGE"}
                    else None if state == "RECONCILIATION_REQUIRED"
                    else False
                )
            self.connection.execute(
                "UPDATE action_ledger SET state=?, updated_at_utc=?, receipt_json=? WHERE action_key=?",
                (state, timestamp, _json(payload), action_key),
            )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        return self.get(action_key)  # type: ignore[return-value]

    @_serialized
    def get(self, action_key: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM action_ledger WHERE action_key=?", (action_key,)).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["recommendation"] = json.loads(value.pop("recommendation_json"))
        value["receipt"] = json.loads(value.pop("receipt_json"))
        return value

    @_serialized
    def snapshot(self) -> list[dict[str, Any]]:
        keys = [row[0] for row in self.connection.execute("SELECT action_key FROM action_ledger ORDER BY created_at_utc, action_key").fetchall()]
        return [entry for key in keys if (entry := self.get(key)) is not None]

    @_serialized
    def update_auto_reallocation_simulation_control(
        self,
        *,
        armed: bool,
        event_type: str,
        kill_switch_engaged: bool,
        live_actions_enabled: bool,
        g5_authorized: bool,
        at_utc: str,
        limits: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        """Persist an offline-only simulation control event and effective state."""
        if type(armed) is not bool or type(kill_switch_engaged) is not bool:
            raise ValueError("simulation control flags must be boolean")
        if type(live_actions_enabled) is not bool or type(g5_authorized) is not bool:
            raise ValueError("simulation action flags must be boolean")
        if event_type not in _SIMULATION_CONTROL_EVENTS:
            raise ValueError("simulation control event is not allowed")
        if armed:
            if (
                event_type != "SIMULATION_ARMED" or kill_switch_engaged
                or live_actions_enabled is not False or g5_authorized is not False
                or not isinstance(limits, Mapping)
            ):
                raise ValueError("simulation arm conditions are not satisfied")
            expected_limits = {
                "max_per_minute", "max_per_day", "cooldown_seconds",
                "max_per_assignment", "max_per_fleet",
            }
            if set(limits) != expected_limits:
                raise ValueError("simulation limits are incomplete")
            for name, value in limits.items():
                if type(value) is not int or value < (0 if name == "cooldown_seconds" else 1):
                    raise ValueError("simulation limits are invalid")
            safe_limits = dict(limits)
        else:
            if event_type in {"SIMULATION_ARMED"}:
                raise ValueError("simulation arm event must be armed")
            if limits is not None:
                raise ValueError("simulation disarm events cannot change limits")
            safe_limits = {}
        timestamp = canonical_utc(at_utc)
        process_id = os.getpid()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "UPDATE auto_reallocation_simulation_control "
                "SET process_id=?, effective_armed=?, kill_switch_engaged=?, updated_at_utc=? WHERE singleton=1",
                (process_id, int(armed), int(kill_switch_engaged), timestamp),
            )
            self._insert_simulation_control_event(
                process_id, event_type, armed, kill_switch_engaged, timestamp, safe_limits,
            )
            self.connection.execute("COMMIT")
            return {
                "effective_armed": armed,
                "kill_switch_engaged": kill_switch_engaged,
                "event_type": event_type,
            }
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    @_serialized
    def auto_reallocation_simulation_control_snapshot(self) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT effective_armed, kill_switch_engaged, updated_at_utc "
            "FROM auto_reallocation_simulation_control WHERE singleton=1"
        ).fetchone()
        events = self.connection.execute(
            "SELECT event_id, event_type, effective_armed, kill_switch_engaged, at_utc, limits_json "
            "FROM auto_reallocation_simulation_control_events ORDER BY event_id"
        ).fetchall()
        return {
            "effective_armed": bool(row["effective_armed"]) if row else False,
            "kill_switch_engaged": bool(row["kill_switch_engaged"]) if row else True,
            "updated_at_utc": row["updated_at_utc"] if row else None,
            "events": [
                {
                    "event_id": int(event["event_id"]),
                    "event_type": event["event_type"],
                    "effective_armed": bool(event["effective_armed"]),
                    "kill_switch_engaged": bool(event["kill_switch_engaged"]),
                    "at_utc": event["at_utc"],
                    "limits": json.loads(event["limits_json"]),
                }
                for event in events
            ],
        }

    @_serialized
    def reserve_auto_reallocation_simulation(
        self,
        *,
        simulation_key: str,
        trigger_key: str,
        scopes: Mapping[str, str],
        at_utc: str,
        at_epoch: float,
        limits: Mapping[str, int],
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Atomically reserve one local SCRUM-101 simulation, never a live action."""
        digest_re = re.compile(r"^[0-9a-f]{64}$")
        if not isinstance(simulation_key, str) or not digest_re.fullmatch(simulation_key):
            raise ValueError("simulation key is invalid")
        if not isinstance(trigger_key, str) or not digest_re.fullmatch(trigger_key):
            raise ValueError("simulation trigger key is invalid")
        if not isinstance(scopes, Mapping) or set(scopes) != {
            "organization", "fleet", "assignment", "target",
        } or any(not isinstance(value, str) or not digest_re.fullmatch(value) for value in scopes.values()):
            raise ValueError("simulation scopes are invalid")
        if isinstance(at_epoch, bool) or not isinstance(at_epoch, (int, float)) or not math.isfinite(float(at_epoch)):
            raise ValueError("simulation time is invalid")
        if not isinstance(limits, Mapping) or set(limits) != {
            "max_per_minute", "max_per_day", "cooldown_seconds",
            "max_per_assignment", "max_per_fleet",
        }:
            raise ValueError("simulation limits are invalid")
        for name, value in limits.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < (0 if name == "cooldown_seconds" else 1):
                raise ValueError(f"simulation limit {name} is invalid")
        safe_payload = dict(payload)
        _reject_secrets(safe_payload)
        if (
            safe_payload.get("simulation_only") is not True
            or safe_payload.get("actions_performed") is not False
            or safe_payload.get("request_submitted") is not False
            or safe_payload.get("dossier_created") is not False
        ):
            raise ValueError("simulation payload must remain non-executing")
        reservation_identity = safe_payload.get("reservation_identity")
        required_identity = {
            "assignment_scope", "target_scope", "original_instance_fingerprint",
            "original_generation_fingerprint",
        }
        if (
            not isinstance(reservation_identity, Mapping)
            or set(reservation_identity) != required_identity
            or reservation_identity.get("assignment_scope") != scopes["assignment"]
            or reservation_identity.get("target_scope") != scopes["target"]
            or any(
                not isinstance(reservation_identity.get(name), str)
                or not _SIMULATION_DIGEST_RE.fullmatch(reservation_identity[name])
                for name in required_identity
            )
        ):
            raise ValueError("simulation reservation identity is invalid")
        decision_payload_sha256 = hashlib.sha256(_json(safe_payload).encode("utf-8")).hexdigest()
        safe_payload["decision_payload_sha256"] = decision_payload_sha256
        encoded = _json(safe_payload)
        timestamp = canonical_utc(at_utc)
        parsed_epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        if abs(parsed_epoch - float(at_epoch)) > 0.001:
            raise ValueError("simulation timestamp and epoch disagree")
        minute_cutoff = float(at_epoch) - 60.0
        day_cutoff = float(at_epoch) - 86400.0
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self.connection.execute(
                "SELECT payload_json FROM auto_reallocation_simulations WHERE simulation_key=?",
                (simulation_key,),
            ).fetchone()
            if existing is not None:
                existing_payload = json.loads(existing["payload_json"])
                if existing_payload.get("decision_payload_sha256") != decision_payload_sha256:
                    raise ValueError("simulation idempotency key conflicts with a different decision")
                self.connection.execute("COMMIT")
                return {"status": "DUPLICATE_SIMULATION", "inserted": False, "simulation_key": simulation_key}

            control = self.connection.execute(
                "SELECT effective_armed, kill_switch_engaged FROM auto_reallocation_simulation_control WHERE singleton=1"
            ).fetchone()
            if control is None or not bool(control["effective_armed"]) or bool(control["kill_switch_engaged"]):
                self.connection.execute("COMMIT")
                return {
                    "status": "BLOCKED_SIMULATION_DISARMED", "inserted": False,
                    "blocker": "SIMULATION_CONTROL_CLOSED",
                }

            latest_timestamp = self.connection.execute(
                "SELECT MAX(created_at_epoch) FROM auto_reallocation_simulations"
            ).fetchone()[0]
            if latest_timestamp is not None and float(at_epoch) < float(latest_timestamp):
                self.connection.execute("COMMIT")
                return {
                    "status": "BLOCKED_TIME_ORDER", "inserted": False,
                    "blocker": "SIMULATION_TIME_REGRESSION",
                }

            pending_placeholders = ",".join("?" for _ in _SIMULATION_PENDING_STATES)
            unresolved = self.connection.execute(
                "SELECT simulation_key FROM auto_reallocation_simulations "
                f"WHERE state IN ({pending_placeholders}) AND (assignment_scope=? OR target_scope=?) LIMIT 1",
                (*_SIMULATION_PENDING_STATES, scopes["assignment"], scopes["target"]),
            ).fetchone()
            if unresolved is not None:
                self.connection.execute("COMMIT")
                return {
                    "status": "BLOCKED_UNRESOLVED_SIMULATION", "inserted": False,
                    "blocker": "UNRESOLVED_TARGET_OR_ASSIGNMENT_SIMULATION",
                }

            scoped_recent = self.connection.execute(
                "SELECT COUNT(*) FROM auto_reallocation_simulations "
                "WHERE organization_scope=? AND created_at_epoch>?",
                (scopes["organization"], minute_cutoff),
            ).fetchone()[0]
            if scoped_recent >= limits["max_per_minute"]:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED_QUOTA", "inserted": False, "blocker": "ORGANIZATION_MINUTE_QUOTA"}

            scoped_day = self.connection.execute(
                "SELECT COUNT(*) FROM auto_reallocation_simulations "
                "WHERE organization_scope=? AND created_at_epoch>?",
                (scopes["organization"], day_cutoff),
            ).fetchone()[0]
            if scoped_day >= limits["max_per_day"]:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED_QUOTA", "inserted": False, "blocker": "ORGANIZATION_DAILY_QUOTA"}

            assignment_rows = self.connection.execute(
                "SELECT COUNT(*), MAX(created_at_epoch) FROM auto_reallocation_simulations "
                "WHERE assignment_scope=? AND created_at_epoch>?",
                (scopes["assignment"], day_cutoff),
            ).fetchone()
            if assignment_rows[0] >= limits["max_per_assignment"]:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED_QUOTA", "inserted": False, "blocker": "ASSIGNMENT_DAILY_QUOTA"}
            last_assignment = self.connection.execute(
                "SELECT MAX(created_at_epoch) FROM auto_reallocation_simulations WHERE assignment_scope=?",
                (scopes["assignment"],),
            ).fetchone()[0]
            if last_assignment is not None and float(at_epoch) - last_assignment < limits["cooldown_seconds"]:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED_COOLDOWN", "inserted": False, "blocker": "ASSIGNMENT_COOLDOWN_ACTIVE"}

            fleet_day = self.connection.execute(
                "SELECT COUNT(*) FROM auto_reallocation_simulations "
                "WHERE fleet_scope=? AND created_at_epoch>?",
                (scopes["fleet"], day_cutoff),
            ).fetchone()[0]
            if fleet_day >= limits["max_per_fleet"]:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED_QUOTA", "inserted": False, "blocker": "FLEET_DAILY_QUOTA"}

            self.connection.execute(
                "INSERT INTO auto_reallocation_simulations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    simulation_key, trigger_key, scopes["organization"], scopes["fleet"],
                    scopes["assignment"], scopes["target"], timestamp, float(at_epoch),
                    "SIMULATION_RESERVED", encoded,
                ),
            )
            self.connection.execute("COMMIT")
            return {"status": "SIMULATION_RESERVED", "inserted": True, "simulation_key": simulation_key}
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    @_serialized
    def record_auto_reallocation_simulation_transport(
        self, simulation_key: str, *, outcome: str, at_utc: str,
    ) -> dict[str, Any]:
        """Advance only the local simulation state machine using a fixed fake outcome."""
        if not isinstance(simulation_key, str) or not _SIMULATION_DIGEST_RE.fullmatch(simulation_key):
            raise ValueError("simulation key is invalid")
        if outcome not in {"FAKE_HTTP_202", "FAKE_TIMEOUT"}:
            raise ValueError("simulation transport outcome is invalid")
        timestamp = canonical_utc(at_utc)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT state, payload_json, created_at_utc FROM auto_reallocation_simulations WHERE simulation_key=?",
                (simulation_key,),
            ).fetchone()
            if row is None or row["state"] != "SIMULATION_RESERVED":
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SIMULATION_TRANSPORT_STATE_INVALID", "actions_performed": False}
            control = self.connection.execute(
                "SELECT effective_armed, kill_switch_engaged FROM auto_reallocation_simulation_control WHERE singleton=1"
            ).fetchone()
            if control is None or not bool(control["effective_armed"]) or bool(control["kill_switch_engaged"]):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SIMULATION_CONTROL_CLOSED", "actions_performed": False}
            if datetime.fromisoformat(timestamp.replace("Z", "+00:00")) < datetime.fromisoformat(row["created_at_utc"].replace("Z", "+00:00")):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SIMULATION_TIME_ORDER_INVALID", "actions_performed": False}
            payload = json.loads(row["payload_json"])
            if payload.get("simulation_only") is not True or payload.get("request_submitted") is not False:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SIMULATION_PROVENANCE_REQUIRED", "actions_performed": False}
            new_state = (
                "SIMULATED_ACCEPTED_PENDING" if outcome == "FAKE_HTTP_202"
                else "SIMULATED_RECONCILIATION_REQUIRED"
            )
            payload.update({
                "simulation_transport_outcome": outcome,
                "simulation_transport_at_utc": timestamp,
                "simulation_state": new_state,
                "automatic_retry": False,
                "simulation_only": True,
                "actions_performed": False,
                "request_submitted": False,
                "dossier_created": False,
                "live_action_eligible": False,
            })
            _reject_secrets(payload)
            self.connection.execute(
                "UPDATE auto_reallocation_simulations SET state=?, payload_json=? WHERE simulation_key=?",
                (new_state, _json(payload), simulation_key),
            )
            self.connection.execute("COMMIT")
            return {"status": new_state, "simulation_key": simulation_key, "automatic_retry": False,
                    "actions_performed": False, "request_submitted": False}
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    @_serialized
    def reconcile_auto_reallocation_simulation(
        self,
        simulation_key: str,
        *,
        observation: Mapping[str, Any],
        observation_verifier: Any = None,
        at_utc: str,
    ) -> dict[str, Any]:
        """Close a simulation only with an independently verified fixture observation."""
        if not isinstance(simulation_key, str) or not _SIMULATION_DIGEST_RE.fullmatch(simulation_key):
            raise ValueError("simulation key is invalid")
        timestamp = canonical_utc(at_utc)
        if not isinstance(observation, Mapping):
            return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_INVALID", "actions_performed": False}
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT state, payload_json, assignment_scope, target_scope, created_at_utc "
                "FROM auto_reallocation_simulations WHERE simulation_key=?",
                (simulation_key,),
            ).fetchone()
            if row is None or row["state"] not in {
                "SIMULATED_ACCEPTED_PENDING", "SIMULATED_RECONCILIATION_REQUIRED",
            }:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SIMULATION_NOT_RECONCILABLE", "actions_performed": False}
            payload = json.loads(row["payload_json"])
            binding = payload.get("reservation_identity")
            if (
                payload.get("data_classification") != "SYNTHETIC/UNVERIFIED"
                or payload.get("synthetic_fixture_id") != _SIMULATION_FIXTURE_ID
                or payload.get("simulation_only") is not True
                or not isinstance(binding, Mapping)
            ):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_PROVENANCE_REQUIRED", "actions_performed": False}
            reservation = {
                "simulation_key": simulation_key,
                "assignment_scope": row["assignment_scope"],
                "target_scope": row["target_scope"],
                **dict(binding),
                "created_at_utc": row["created_at_utc"],
            }
            try:
                verified = observation_verifier.verify_synthetic_observation(
                    observation=dict(observation), reservation=reservation,
                )
            except Exception:
                verified = None
            if type(verified) is not VerifiedSyntheticSimulationObservation:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_VERIFICATION_FAILED", "actions_performed": False}
            proof = verified.as_mapping()
            try:
                _reject_secrets(proof)
            except ValueError:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_INVALID", "actions_performed": False}
            if dict(observation) != proof:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_MISMATCH", "actions_performed": False}
            if (
                not isinstance(verified.schema_version, str)
                or not isinstance(verified.synthetic_fixture_id, str)
                or not isinstance(verified.evidence_reference, str)
                or not isinstance(verified.simulation_key, str)
                or not isinstance(verified.assignment_scope, str)
                or not isinstance(verified.target_scope, str)
                or not isinstance(verified.original_instance_fingerprint, str)
                or not isinstance(verified.original_generation_fingerprint, str)
                or not isinstance(verified.result, str)
                or verified.schema_version != "1.0"
                or verified.synthetic_fixture_id != _SIMULATION_FIXTURE_ID
                or not re.fullmatch(r"G5-SYNTHETIC-ACTION-PATH:V1:[A-Z0-9._-]{1,64}", verified.evidence_reference)
                or verified.simulation_key != simulation_key
                or verified.assignment_scope != row["assignment_scope"]
                or verified.target_scope != row["target_scope"]
                or verified.assignment_scope != binding.get("assignment_scope")
                or verified.target_scope != binding.get("target_scope")
                or verified.original_instance_fingerprint != binding.get("original_instance_fingerprint")
                or verified.original_generation_fingerprint != binding.get("original_generation_fingerprint")
                or any(not isinstance(value, str) or not _SIMULATION_DIGEST_RE.fullmatch(value) for value in (
                    verified.original_instance_fingerprint, verified.original_generation_fingerprint,
                ))
                or verified.result not in {"SIMULATED_CHANGE", "SIMULATED_NO_CHANGE", "SIMULATED_UNKNOWN"}
            ):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_BINDING_MISMATCH", "actions_performed": False}
            try:
                observed_at = datetime.fromisoformat(canonical_utc(verified.observed_at_utc).replace("Z", "+00:00"))
                reserved_at = datetime.fromisoformat(row["created_at_utc"].replace("Z", "+00:00"))
                reconciled_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (TypeError, ValueError, OverflowError):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_TIME_INVALID", "actions_performed": False}
            try:
                transport_at_text = payload.get("simulation_transport_at_utc")
                if not isinstance(transport_at_text, str) or not transport_at_text:
                    raise ValueError("simulation transport timestamp is missing")
                canonical_transport_at = canonical_utc(transport_at_text)
                if canonical_transport_at != transport_at_text:
                    raise ValueError("simulation transport timestamp is not canonical")
                transport_at = datetime.fromisoformat(canonical_transport_at.replace("Z", "+00:00"))
            except (TypeError, ValueError, OverflowError):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_TRANSPORT_TIME_INVALID", "actions_performed": False}
            if not reserved_at <= transport_at < observed_at <= reconciled_at:
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_TIME_INVALID", "actions_performed": False}
            previous_observed_text = payload.get("reconciliation_observed_at_utc")
            if previous_observed_text is not None:
                try:
                    previous_observed_at = datetime.fromisoformat(
                        canonical_utc(previous_observed_text).replace("Z", "+00:00")
                    )
                except (TypeError, ValueError, OverflowError):
                    self.connection.execute("COMMIT")
                    return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_TIME_INVALID", "actions_performed": False}
                if observed_at <= previous_observed_at:
                    self.connection.execute("COMMIT")
                    return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_TIME_REGRESSION", "actions_performed": False}

            observed_instance = verified.observed_instance_fingerprint
            observed_generation = verified.observed_generation_fingerprint
            for value in (observed_instance, observed_generation):
                if value is not None and (not isinstance(value, str) or not _SIMULATION_DIGEST_RE.fullmatch(value)):
                    self.connection.execute("COMMIT")
                    return {"status": "BLOCKED", "reason": "SYNTHETIC_OBSERVATION_INVALID", "actions_performed": False}
            if verified.result == "SIMULATED_CHANGE" and (
                observed_instance in {None, verified.original_instance_fingerprint}
                or observed_generation in {None, verified.original_generation_fingerprint}
            ):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_CHANGE_NOT_PROVEN", "actions_performed": False}
            if verified.result == "SIMULATED_NO_CHANGE" and (
                observed_instance != verified.original_instance_fingerprint
                or observed_generation != verified.original_generation_fingerprint
            ):
                self.connection.execute("COMMIT")
                return {"status": "BLOCKED", "reason": "SYNTHETIC_NO_CHANGE_NOT_PROVEN", "actions_performed": False}
            if verified.result == "SIMULATED_UNKNOWN":
                if observed_instance is not None or observed_generation is not None:
                    self.connection.execute("COMMIT")
                    return {"status": "BLOCKED", "reason": "SYNTHETIC_UNKNOWN_HAS_PARTIAL_IDENTITY", "actions_performed": False}
                payload.update({
                    "simulation_result": "SIMULATED_UNKNOWN",
                    "reconciliation_evidence_reference": verified.evidence_reference,
                    "reconciliation_observed_at_utc": canonical_utc(verified.observed_at_utc),
                    "simulation_state": "SIMULATED_RECONCILIATION_REQUIRED",
                    "automatic_retry": False,
                    "actions_performed": False,
                    "request_submitted": False,
                    "dossier_created": False,
                })
                _reject_secrets(payload)
                self.connection.execute(
                    "UPDATE auto_reallocation_simulations SET state='SIMULATED_RECONCILIATION_REQUIRED', "
                    "payload_json=? WHERE simulation_key=?",
                    (_json(payload), simulation_key),
                )
                self.connection.execute("COMMIT")
                return {"status": "SIMULATED_RECONCILIATION_REQUIRED", "result": "SIMULATED_UNKNOWN",
                        "actions_performed": False, "request_submitted": False}

            payload.update({
                "simulation_result": verified.result,
                "reconciliation_evidence_reference": verified.evidence_reference,
                "reconciliation_observed_at_utc": canonical_utc(verified.observed_at_utc),
                "observed_instance_fingerprint": observed_instance,
                "observed_generation_fingerprint": observed_generation,
                "simulation_state": "SIMULATED_RECONCILED",
                "data_classification": "SYNTHETIC/UNVERIFIED",
                "simulation_only": True,
                "automatic_retry": False,
                "actions_performed": False,
                "request_submitted": False,
                "dossier_created": False,
                "live_action_eligible": False,
            })
            _reject_secrets(payload)
            self.connection.execute(
                "UPDATE auto_reallocation_simulations SET state='SIMULATED_RECONCILED', payload_json=?, "
                "reconciled_at_utc=? WHERE simulation_key=?",
                (_json(payload), timestamp, simulation_key),
            )
            self.connection.execute("COMMIT")
            return {"status": "SIMULATED_RECONCILED", "result": verified.result,
                    "actions_performed": False, "request_submitted": False}
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    @_serialized
    def auto_reallocation_simulation_snapshot(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT simulation_key, trigger_key, organization_scope, fleet_scope, assignment_scope, "
            "target_scope, created_at_utc, state, payload_json, reconciled_at_utc "
            "FROM auto_reallocation_simulations ORDER BY created_at_epoch, simulation_key"
        ).fetchall()
        return [
            {**dict(row), "payload": json.loads(row["payload_json"])}
            for row in rows
        ]

    @staticmethod
    def key_for(*, organization_id: str, project_id: str, container_group_id: str, instance_id: str, generation: str, deterioration_id: str, policy_version: str) -> str:
        parts = (organization_id, project_id, container_group_id, instance_id, generation, deterioration_id, policy_version)
        if any(not isinstance(value, str) or not value.strip() for value in parts):
            raise ValueError("all logical action-key components must be explicitly known")
        digest = hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()
        return f"reallocation_{digest}"

    @staticmethod
    def live_key_for(*, action: str, target: Mapping[str, Any]) -> str:
        if action not in {"START_GROUP", "STOP_GROUP", "REALLOCATE_INSTANCE"}:
            raise ValueError("live action type is not allowed")
        fields = ("organization", "project", "container_group", "instance_id", "assignment_id", "deterioration_id")
        values = [action]
        for name in fields:
            value = target.get(name)
            if value is None:
                values.append("")
            elif isinstance(value, str) and value.strip():
                values.append(value.strip())
            else:
                raise ValueError(f"live action key component {name} is invalid")
        if not values[3]:
            raise ValueError("container group is required for a live action key")
        digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
        return f"salad_{action.casefold()}_{digest}"

    @staticmethod
    def _early_generation_scope_sha256(target: Mapping[str, Any], assignment_generation: str) -> str:
        # The one-dispatch lock belongs to the provider assignment generation,
        # not to the physical machine currently hosting it. Machine, instance,
        # or deterioration changes must not create another dispatch slot for
        # the same assignment generation.
        fields = ("organization", "project", "container_group", "assignment_id")
        values: list[str] = []
        for name in fields:
            value = target.get(name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"EARLY generation scope field {name} is invalid")
            values.append(value.strip())
        if not isinstance(assignment_generation, str) or not assignment_generation.strip():
            raise ValueError("EARLY assignment generation is invalid")
        values.append(assignment_generation.strip())
        return hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()

    @staticmethod
    def early_live_key_for(*, action: str, target: Mapping[str, Any]) -> str:
        if action != "REALLOCATE_INSTANCE" or not isinstance(target, Mapping):
            raise ValueError("EARLY live key is restricted to exact instance reallocation")
        fields = (
            "organization", "project", "container_group", "machine_id", "instance_id",
            "assignment_id", "assignment_generation", "deterioration_id",
        )
        values = [action]
        for name in fields:
            value = target.get(name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"EARLY live key component {name} is invalid")
            values.append(value.strip())
        digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
        return f"early_reallocation_{digest}"
