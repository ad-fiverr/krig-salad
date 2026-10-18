"""Local SQLite evidence and append-only audit store for the G5 UI."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from collector.guard_store import canonical_utc
from collector.salad_action_policy import APPROVED_GROUPS, HARD_BUDGET_CAP_USD


_SECRET_KEY = re.compile(r"(?i)(secret|token|password|credential|api.?key|authorization|private.?key)")
_SECRET_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+\S{8,}|salad[_-]?api[_-]?key\s*[:=]")


def _safe(value: Any) -> Any:
    if isinstance(value, Mapping):
        cleaned = {}
        for key, item in value.items():
            name = str(key)
            if _SECRET_KEY.search(name):
                raise ValueError("secret-like audit fields are forbidden")
            cleaned[name] = _safe(item)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ValueError("credential-like audit text is forbidden")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError("audit values must be JSON-safe scalars, lists, or objects")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


class ControlPlaneStore:
    """SQLite state store; never stores the Salad API key or client commands."""

    def __init__(self, path: str | Path = ":memory:"):
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, timeout=5, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS provider_observations (
                observation_id TEXT PRIMARY KEY,
                container_group TEXT NOT NULL,
                observed_at_utc TEXT NOT NULL,
                data_classification TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                audit_id TEXT PRIMARY KEY,
                dedupe_key TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS budget_evidence (
                evidence_id TEXT PRIMARY KEY,
                observed_at_utc TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                currency TEXT NOT NULL,
                amount_usd TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS action_cost_evidence (
                evidence_id TEXT PRIMARY KEY,
                source_reference TEXT NOT NULL,
                currency TEXT NOT NULL,
                amount_usd TEXT NOT NULL,
                observed_at_utc TEXT NOT NULL,
                valid_until_utc TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS budget_exposures (
                action_key TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                source_reference TEXT NOT NULL,
                amount_usd TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def append_audit(self, event_type: str, payload: Mapping[str, Any], occurred_at_utc: str) -> bool:
        if not isinstance(event_type, str) or not event_type.strip() or not isinstance(payload, Mapping):
            raise ValueError("audit event type and payload are required")
        timestamp = canonical_utc(occurred_at_utc)
        safe_payload = _safe(dict(payload))
        encoded = _json(safe_payload)
        dedupe = hashlib.sha256(f"{event_type}\0{timestamp}\0{encoded}".encode()).hexdigest()
        audit_id = f"audit_{dedupe[:32]}"
        with self._lock, self._db:
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO audit_events VALUES (?, ?, ?, ?, ?)",
                (audit_id, dedupe, event_type, timestamp, encoded),
            )
            return cursor.rowcount == 1

    def save_provider_observation(self, evidence: Mapping[str, Any], observed_at_utc: str) -> str:
        if not isinstance(evidence, Mapping):
            raise ValueError("provider evidence must be an object")
        group = evidence.get("container_group")
        if group not in APPROVED_GROUPS:
            raise ValueError("provider evidence group is outside the fixed scope")
        classification = evidence.get("data_classification")
        if classification not in {"SYNTHETIC/UNVERIFIED", "PROVIDER_OBSERVED"}:
            raise ValueError("evidence classification is not accepted")
        payload = _safe(dict(evidence))
        timestamp = canonical_utc(observed_at_utc)
        canonical = _json(payload)
        digest = hashlib.sha256(f"{group}\0{timestamp}\0{canonical}".encode()).hexdigest()
        identifier = f"observation_{digest[:32]}"
        with self._lock, self._db:
            existing = self._db.execute("SELECT payload_json FROM provider_observations WHERE observation_id=?", (identifier,)).fetchone()
            if existing and existing["payload_json"] != canonical:
                raise ValueError("observation id conflicts with existing content")
            self._db.execute(
                "INSERT OR IGNORE INTO provider_observations VALUES (?, ?, ?, ?, ?)",
                (identifier, group, timestamp, classification, canonical),
            )
        return identifier

    def record_budget_evidence(
        self,
        *,
        evidence_id: str,
        source_reference: str,
        occurred_at_utc: str,
        currency: str,
        amount_usd: str,
        verification_status: str,
        source: str,
    ) -> None:
        """Backend-only evidence ingress; browser API deliberately has no route."""
        if source != "trusted_backend_import" or verification_status not in {"VERIFIED", "UNKNOWN"}:
            raise ValueError("budget evidence requires the backend import path")
        fields = (evidence_id, source_reference, currency, amount_usd)
        if any(not isinstance(value, str) or not value.strip() for value in fields):
            raise ValueError("budget evidence fields are incomplete")
        if currency != "USD":
            raise ValueError("budget evidence currency must be USD")
        try:
            amount = Decimal(amount_usd)
        except (InvalidOperation, ValueError):
            raise ValueError("budget evidence amount is invalid") from None
        if not amount.is_finite() or amount < 0:
            raise ValueError("budget evidence amount must be finite and non-negative")
        amount_usd = format(amount, "f")
        timestamp = canonical_utc(occurred_at_utc)
        payload = {
            "evidence_id": evidence_id, "source_reference": source_reference,
            "currency": currency, "amount_usd": amount_usd,
            "observed_at_utc": timestamp, "verification_status": verification_status,
        }
        encoded = _json(_safe(payload))
        with self._lock, self._db:
            old = self._db.execute("SELECT payload_json FROM budget_evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
            if old and old["payload_json"] != encoded:
                raise ValueError("budget evidence is immutable and conflicts with the stored record")
            self._db.execute(
                "INSERT OR IGNORE INTO budget_evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, timestamp, source_reference, currency, amount_usd, verification_status, encoded),
            )

    def record_action_cost_evidence(
        self,
        *,
        evidence_id: str,
        source_reference: str,
        currency: str,
        amount_usd: str,
        observed_at_utc: str,
        valid_until_utc: str,
        verification_status: str,
        source: str,
    ) -> None:
        if source != "trusted_backend_import" or verification_status not in {"VERIFIED", "UNKNOWN"}:
            raise ValueError("action cost requires the backend evidence import path")
        if any(not isinstance(value, str) or not value.strip() for value in (evidence_id, source_reference, amount_usd)):
            raise ValueError("action cost evidence fields are incomplete")
        if currency != "USD":
            raise ValueError("action cost currency must be USD")
        try:
            amount = Decimal(amount_usd)
        except (InvalidOperation, ValueError):
            raise ValueError("action cost amount is invalid") from None
        if not amount.is_finite() or amount < 0:
            raise ValueError("action cost amount must be finite and non-negative")
        observed = canonical_utc(observed_at_utc)
        expires = canonical_utc(valid_until_utc)
        payload = _json({
            "evidence_id": evidence_id,
            "source_reference": source_reference,
            "currency": currency,
            "amount_usd": format(amount, "f"),
            "observed_at_utc": observed,
            "valid_until_utc": expires,
            "verification_status": verification_status,
        })
        with self._lock, self._db:
            old = self._db.execute("SELECT payload_json FROM action_cost_evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
            if old and old["payload_json"] != payload:
                raise ValueError("action cost evidence is immutable and conflicts with the stored record")
            self._db.execute(
                "INSERT OR IGNORE INTO action_cost_evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, source_reference, currency, format(amount, "f"), observed, expires, verification_status, payload),
            )

    def reserve_budget_exposure(
        self,
        *,
        action_key: str,
        evidence_id: str,
        source_reference: str,
        amount_usd: str,
        occurred_at_utc: str,
        source: str,
        hard_budget_usd: str = "30.00",
    ) -> str:
        if source != "trusted_backend_reservation" or any(not isinstance(value, str) or not value.strip() for value in (action_key, evidence_id, source_reference, amount_usd)):
            raise ValueError("budget exposure requires a backend durable reservation")
        try:
            amount = Decimal(amount_usd)
            hard_budget = Decimal(hard_budget_usd)
        except (InvalidOperation, ValueError):
            raise ValueError("budget exposure amount or hard cap is invalid") from None
        if not amount.is_finite() or amount < 0 or not hard_budget.is_finite() or hard_budget <= 0 or hard_budget > HARD_BUDGET_CAP_USD:
            raise ValueError("budget exposure amount or hard cap is invalid")
        timestamp = canonical_utc(occurred_at_utc)
        now_epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                old = self._db.execute("SELECT * FROM budget_exposures WHERE action_key=?", (action_key,)).fetchone()
                if old is not None:
                    if old["evidence_id"] != evidence_id or old["source_reference"] != source_reference or Decimal(old["amount_usd"]) != amount:
                        raise ValueError("action key already has conflicting durable exposure")
                    if old["status"] not in {"PENDING", "RECONCILED"}:
                        raise ValueError("released exposure cannot authorize a new dispatch")
                    self._db.execute("COMMIT")
                    return "ALREADY_RESERVED"
                spend = self._db.execute(
                    "SELECT * FROM budget_evidence ORDER BY observed_at_utc DESC LIMIT 1"
                ).fetchone()
                cost = self._db.execute(
                    "SELECT * FROM action_cost_evidence WHERE evidence_id=?", (evidence_id,)
                ).fetchone()
                if (
                    spend is None or spend["verification_status"] != "VERIFIED" or spend["currency"] != "USD"
                    or cost is None or cost["verification_status"] != "VERIFIED" or cost["currency"] != "USD"
                    or cost["source_reference"] != source_reference
                    or Decimal(cost["amount_usd"]) != amount
                    or datetime.fromisoformat(cost["valid_until_utc"].replace("Z", "+00:00")).timestamp() <= now_epoch
                ):
                    raise ValueError("current verified spend and unexpired matching action cost are required")
                spent = Decimal(spend["amount_usd"])
                if not spent.is_finite() or spent < 0:
                    raise ValueError("verified spend evidence is invalid")
                pending_rows = self._db.execute(
                    "SELECT amount_usd FROM budget_exposures WHERE status IN ('PENDING', 'RECONCILED')"
                ).fetchall()
                pending = sum((Decimal(row["amount_usd"]) for row in pending_rows), Decimal("0"))
                if not pending.is_finite() or pending < 0 or spent + pending + amount > hard_budget:
                    raise ValueError("verified spend plus pending and requested exposure exceeds the hard budget")
                self._db.execute(
                    "INSERT INTO budget_exposures VALUES (?, ?, ?, ?, 'PENDING', ?, ?)",
                    (action_key, evidence_id, source_reference, format(amount, "f"), timestamp, timestamp),
                )
                self._db.execute("COMMIT")
                return "RESERVED"
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def reconcile_budget_exposure(self, action_key: str, *, evidence_id: str, status: str, occurred_at_utc: str, source: str) -> None:
        if source != "trusted_backend_reconciliation" or status not in {"RECONCILED", "RELEASED"} or not isinstance(evidence_id, str) or not evidence_id.strip():
            raise ValueError("budget exposure reconciliation is not independently evidenced")
        timestamp = canonical_utc(occurred_at_utc)
        with self._lock, self._db:
            row = self._db.execute("SELECT status FROM budget_exposures WHERE action_key=?", (action_key,)).fetchone()
            if row is None:
                raise KeyError(action_key)
            if row["status"] != "PENDING":
                if row["status"] == status and status != "RELEASED":
                    return
                if row["status"] == "RELEASED":
                    if status == "RELEASED":
                        return
                    raise ValueError("released budget exposure is terminal")
                if row["status"] != "RECONCILED" or status != "RELEASED":
                    raise ValueError("budget exposure transition is invalid")
            if status == "RELEASED":
                billing = self._db.execute(
                    "SELECT verification_status, currency FROM budget_evidence WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                if billing is None or billing["verification_status"] != "VERIFIED" or billing["currency"] != "USD":
                    raise ValueError("exposure can be released only after verified USD billing evidence is imported")
            self._db.execute("UPDATE budget_exposures SET status=?, evidence_id=?, updated_at_utc=? WHERE action_key=?", (status, evidence_id, timestamp, action_key))

    def observations(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM provider_observations ORDER BY observed_at_utc, container_group").fetchall()
        return [{**dict(row), "payload": json.loads(row["payload_json"])} for row in rows]

    def audit(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM audit_events ORDER BY occurred_at_utc, audit_id").fetchall()
        return [{**dict(row), "payload": json.loads(row["payload_json"])} for row in rows]

    def budget_summary(self) -> dict[str, Any]:
        try:
            with self._lock:
                spend_row = self._db.execute("SELECT * FROM budget_evidence ORDER BY observed_at_utc DESC LIMIT 1").fetchone()
                cost_row = self._db.execute("SELECT * FROM action_cost_evidence ORDER BY observed_at_utc DESC LIMIT 1").fetchone()
                exposure_rows = [dict(row) for row in self._db.execute("SELECT * FROM budget_exposures ORDER BY action_key").fetchall()]
            pending = Decimal("0")
            for exposure in exposure_rows:
                amount = Decimal(exposure["amount_usd"])
                if not amount.is_finite() or amount < 0 or exposure["status"] not in {"PENDING", "RECONCILED", "RELEASED"}:
                    raise ValueError("durable exposure ledger is invalid")
                if exposure["status"] in {"PENDING", "RECONCILED"}:
                    pending += amount
            pending_digest = hashlib.sha256(_json(exposure_rows).encode("utf-8")).hexdigest()
            pending_summary = {
                "pending_exposure_usd": float(pending),
                "pending_exposure_status": "VERIFIED",
                "pending_exposure_evidence_id": f"pending-exposure-ledger:{pending_digest}",
            }
        except Exception:
            pending_summary = {
                "pending_exposure_usd": None,
                "pending_exposure_status": "UNKNOWN",
                "pending_exposure_evidence_id": None,
            }

        def epoch(value: Any) -> float | None:
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                return parsed.timestamp()
            except (TypeError, ValueError, OverflowError):
                return None

        if spend_row is None or spend_row["verification_status"] != "VERIFIED" or spend_row["currency"] != "USD":
            return {
                "status": "UNKNOWN", "verified_spend_usd": None, "currency": None,
                **pending_summary, "maximum_exposure_usd": None, "maximum_exposure_status": "UNKNOWN",
            }
        try:
            spent = Decimal(spend_row["amount_usd"])
        except (TypeError, ValueError, InvalidOperation):
            spent = None
        if spent is None or not spent.is_finite() or spent < 0:
            return {
                "status": "UNKNOWN", "verified_spend_usd": None, "currency": None,
                **pending_summary, "maximum_exposure_usd": None, "maximum_exposure_status": "UNKNOWN",
            }
        cost_verified = bool(cost_row and cost_row["verification_status"] == "VERIFIED" and cost_row["currency"] == "USD")
        try:
            cost = Decimal(cost_row["amount_usd"]) if cost_verified else None
        except (TypeError, ValueError, InvalidOperation):
            cost = None
        cost_expiry = epoch(cost_row["valid_until_utc"]) if cost_row else None
        now_epoch = datetime.now(timezone.utc).timestamp()
        cost_verified = bool(cost_verified and cost is not None and cost.is_finite() and cost >= 0 and cost_expiry is not None and cost_expiry > now_epoch)
        pending_value = pending_summary["pending_exposure_usd"]
        pending_verified = pending_summary["pending_exposure_status"] == "VERIFIED" and pending_value is not None
        if cost_verified and pending_verified:
            maximum = spent + Decimal(str(pending_value)) + cost
            maximum_summary = {
                "maximum_exposure_usd": float(maximum),
                "maximum_exposure_status": "VERIFIED",
                "maximum_exposure_evidence_id": hashlib.sha256(
                    f"{spend_row['evidence_id']}\0{cost_row['evidence_id']}\0{pending_summary['pending_exposure_evidence_id']}".encode()
                ).hexdigest(),
            }
        else:
            maximum_summary = {
                "maximum_exposure_usd": None,
                "maximum_exposure_status": "UNKNOWN",
                "maximum_exposure_evidence_id": None,
            }
        return {
            "status": "VERIFIED", "verified_spend_usd": float(spent), "currency": "USD",
            "spend_evidence_id": spend_row["evidence_id"], "spend_source_reference": spend_row["source_reference"],
            "spend_observed_at_utc": spend_row["observed_at_utc"],
            "spend_observed_at_epoch": epoch(spend_row["observed_at_utc"]),
            "verified_next_action_cost_usd": float(cost) if cost_verified else None,
            "action_cost_evidence_id": cost_row["evidence_id"] if cost_verified else None,
            "action_cost_source_reference": cost_row["source_reference"] if cost_verified else None,
            "action_cost_observed_at_utc": cost_row["observed_at_utc"] if cost_verified else None,
            "action_cost_observed_at_epoch": epoch(cost_row["observed_at_utc"]) if cost_verified else None,
            "action_cost_valid_until_utc": cost_row["valid_until_utc"] if cost_verified else None,
            "valid_until_epoch": cost_expiry if cost_verified else None,
            **pending_summary,
            **maximum_summary,
        }
