"""Restart-safe, single-host SQLite cursor and delivery ledger."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
import hashlib
import json
import re
import sqlite3
import threading

from .contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED, canonical_utc


CONFIG_ALERT_COOLDOWN_SECONDS = 300
CUDA_ALERT_COOLDOWN_SECONDS = 600
MAX_CUDA_SUPPRESSED_AUDIT_ROWS_PER_SCOPE = 100
MAX_CUDA_EXIT_AUDIT_HASHES = 100
MAX_CUDA_FATAL_CANDIDATE_HASHES = 100
CUDA_EXIT_EVIDENCE_FIELDS = frozenset({
    "resource_type", "organization_name", "project_name", "container_group_name",
    "machine_id", "instance_id", "event_time_utc", "evidence_sha256",
})


_SECRET_KEY_RE = re.compile(r"(?i)(secret|token|password|credential|api.?key|authorization|private.?key)")
_SECRET_VALUE_RE = re.compile(
    r"(?i)\b(?:bearer|basic)\s+\S{8,}|salad[_-]?api[_-]?key\s*[:=]|(?:^|[\s&])token=[^&\s]+"
)


class LedgerConflictError(RuntimeError):
    """An idempotency key was reused for different notification content."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _bounded_cuda_hashes(values: Iterable[str], maximum: int) -> tuple[list[str], bool]:
    ordered = sorted(set(values))
    return ordered[:maximum], len(ordered) > maximum


def _validate_payload(value: Any, *, depth: int = 0) -> None:
    if depth > 12:
        raise ValueError("notification payload exceeds the local depth limit")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or _SECRET_KEY_RE.search(key):
                raise ValueError("credential-like payload fields are forbidden")
            _validate_payload(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_payload(item, depth=depth + 1)
    elif isinstance(value, str):
        if len(value) > 32_000 or _SECRET_VALUE_RE.search(value):
            raise ValueError("credential-like or oversized payload text is forbidden")
    elif value is not None and not isinstance(value, (int, float, bool)):
        raise ValueError("payload values must be JSON-safe")


def _cuda_cooldown_context(
    item: Mapping[str, Any], payload: Mapping[str, Any],
) -> tuple[str, dict[str, str]] | None:
    if item.get("event_type") != "CUDA_DRIVER_INCOMPATIBLE":
        return None
    identity = payload.get("identity")
    fields = payload.get("event_fields")
    if not isinstance(identity, Mapping) or not isinstance(fields, Mapping):
        raise ValueError("CUDA alert identity or event fields are missing")
    if (
        fields.get("reason") != "CUDA_DRIVER_VERSION_INSUFFICIENT"
        or fields.get("gpu_initialized") is not False
        or fields.get("recommendation") != "REALLOCATE"
        or fields.get("actions_performed") is not False
    ):
        raise ValueError("CUDA alert fields do not match the fixed offline contract")
    exit_status = fields.get("miner_exit_status")
    exit_confirmed = fields.get("exit_status_confirmed")
    if not (
        (exit_status == 1 and exit_confirmed is True)
        or (exit_status == "UNKNOWN" and exit_confirmed is False)
    ):
        raise ValueError("CUDA alert exit status is inconsistent")
    if exit_confirmed:
        if (
            not isinstance(fields.get("exit_status_event_time_utc"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", str(fields.get("exit_evidence_sha256") or ""))
        ):
            raise ValueError("confirmed CUDA exit evidence is incomplete")
    elif fields.get("exit_status_event_time_utc") is not None or fields.get("exit_evidence_sha256") is not None:
        raise ValueError("unconfirmed CUDA exit evidence contains a confirmation")

    names = ("organization_name", "project_name", "container_group_name", "machine_id")
    if (
        identity.get("identity_status") not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}
        or identity.get("identity_source") not in {
            "resource.labels", "list_container_group_instances",
        }
        or any(not isinstance(identity.get(name), str) or not identity[name] for name in names)
        or identity.get("organization_name") != payload.get("query_organization")
    ):
        return None
    context = {
        "organization_name": str(identity["organization_name"]),
        "project_name": str(identity["project_name"]),
        "container_group_name": str(identity["container_group_name"]),
        "machine_id": str(identity["machine_id"]),
        "reason": "CUDA_DRIVER_VERSION_INSUFFICIENT",
    }
    canonical = json.dumps(
        [context[key] for key in (
            "organization_name", "project_name", "container_group_name", "machine_id", "reason",
        )],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest(), context


def _merge_notification_identity(
    existing: Any, incoming: Any, *, query_organization: Any,
) -> dict[str, Any]:
    """Merge only monotonic presentation enrichment for one stable source log."""
    if not isinstance(existing, Mapping) or not isinstance(incoming, Mapping):
        raise LedgerConflictError("deduplicated alert identity is malformed")
    allowed_sources = {"resource.labels", "list_container_group_instances"}
    for identity in (existing, incoming):
        if identity.get("identity_status") == "CONFLICTING":
            raise LedgerConflictError("deduplicated alert identity is conflicting")
        if identity.get("identity_source") not in allowed_sources:
            raise LedgerConflictError("deduplicated alert identity source changed")

    merged = dict(existing)
    fixed_fields = (
        "project_name", "container_group_name", "instance_id",
    )
    for name in fixed_fields:
        if existing.get(name) != incoming.get(name):
            raise LedgerConflictError("deduplicated alert provider scope changed")

    old_org = existing.get("organization_name")
    new_org = incoming.get("organization_name")
    if old_org != new_org:
        if old_org is None and new_org == query_organization:
            merged["organization_name"] = new_org
        elif new_org is None and old_org == query_organization:
            pass
        else:
            raise LedgerConflictError("deduplicated alert organization identity changed")

    old_machine = existing.get("machine_id")
    new_machine = incoming.get("machine_id")
    if old_machine is not None and new_machine is not None and old_machine != new_machine:
        raise LedgerConflictError("deduplicated alert machine identity changed")
    if old_machine is None and new_machine is not None:
        if not all(incoming.get(name) for name in (
            "organization_name", "project_name", "container_group_name", "instance_id",
        )):
            raise LedgerConflictError("deduplicated alert enrichment is incomplete")
        merged.update(incoming)
    elif old_machine is not None:
        # A failed or stale later GET may not downgrade previously proven IDs.
        merged.update(existing)
        if incoming.get("identity_source") == "resource.labels":
            merged["identity_source"] = "resource.labels"
    else:
        # No machine ID was proved in either observation. Preserve the first
        # presentation and any independently known source fields.
        if merged.get("identity_source") != existing.get("identity_source"):
            merged["identity_source"] = existing.get("identity_source")

    # If both observations are resolved, only the evidence source may improve.
    if old_machine is not None and new_machine is not None:
        old_status = existing.get("identity_status")
        new_status = incoming.get("identity_status")
        if old_status != new_status:
            raise LedgerConflictError("deduplicated alert identity classification changed")
    if merged.get("machine_id") is not None:
        if merged.get("identity_status") not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}:
            raise LedgerConflictError("deduplicated alert has an unverified resolved identity")
    else:
        merged["identity_status"] = "UNKNOWN"
    return merged


def _merge_cuda_exit_evidence(
    existing: Mapping[str, Any], incoming: Mapping[str, Any],
) -> dict[str, Any]:
    if existing.get("identity") is None and incoming.get("identity") is None:
        merged_identity = None
    else:
        merged_identity = _merge_notification_identity(
            existing.get("identity"), incoming.get("identity"),
            query_organization=existing.get("query_organization"),
        )
    exit_keys = {
        "miner_exit_status", "exit_status_confirmed", "exit_status_event_time_utc",
        "exit_evidence_sha256",
    }
    audit_keys = {
        "exit_correlation_status", "exit_evidence_audit_sha256",
        "exit_candidate_fatal_sha256", "exit_correlation_audit_truncated",
    }

    def audit_union(*fields: Mapping[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        truncated = False
        for key, maximum in (
            ("exit_evidence_audit_sha256", MAX_CUDA_EXIT_AUDIT_HASHES),
            ("exit_candidate_fatal_sha256", MAX_CUDA_FATAL_CANDIDATE_HASHES),
        ):
            values: set[str] = set()
            for item in fields:
                raw = item.get(key, [])
                if not isinstance(raw, list):
                    raise LedgerConflictError("CUDA exit audit evidence is malformed")
                for value in raw:
                    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                        raise LedgerConflictError("CUDA exit audit evidence is malformed")
                    values.add(value)
                marker = item.get("exit_correlation_audit_truncated", False)
                if not isinstance(marker, bool):
                    raise LedgerConflictError("CUDA exit audit truncation marker is malformed")
                truncated = truncated or marker
            if values:
                bounded, overflow = _bounded_cuda_hashes(values, maximum)
                merged[key] = bounded
                truncated = truncated or overflow
        if truncated:
            merged["exit_correlation_audit_truncated"] = True
        return merged

    def merged_payload(base: Mapping[str, Any], *audit_sources: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(base)
        if merged_identity is not None:
            result["identity"] = merged_identity
        fields = dict(result.get("event_fields", {}))
        audit = audit_union(*audit_sources)
        fields.update(audit)
        has_audit = bool(audit.get("exit_evidence_audit_sha256") or audit.get("exit_candidate_fatal_sha256"))
        must_remain_unknown = (
            audit.get("exit_correlation_audit_truncated") is True
            or fields.get("exit_correlation_status") == "AMBIGUOUS"
        )
        if must_remain_unknown:
            fields.update({
                "exit_correlation_status": "AMBIGUOUS",
                "miner_exit_status": "UNKNOWN",
                "exit_status_confirmed": False,
                "exit_status_event_time_utc": None,
                "exit_evidence_sha256": None,
            })
        elif has_audit:
            fields["exit_correlation_status"] = (
                "CONFIRMED" if fields.get("exit_status_confirmed") is True else "AMBIGUOUS"
            )
        result["event_fields"] = fields
        return result

    def core(payload: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        if merged_identity is not None:
            result["identity"] = merged_identity
        fields = dict(result.get("event_fields", {}))
        for key in exit_keys | audit_keys:
            fields.pop(key, None)
        result["event_fields"] = fields
        return result

    if core(existing) != core(incoming):
        raise LedgerConflictError("CUDA alert source identity or fatal evidence changed")
    old_fields = dict(existing.get("event_fields", {}))
    new_fields = dict(incoming.get("event_fields", {}))
    old_confirmed = old_fields.get("exit_status_confirmed") is True
    new_confirmed = new_fields.get("exit_status_confirmed") is True
    audit_sources = (old_fields, new_fields)
    if old_confirmed and new_confirmed:
        if any(old_fields.get(key) != new_fields.get(key) for key in exit_keys):
            conflict_exit_hashes: set[str] = set()
            for fields in audit_sources:
                for key in ("exit_evidence_audit_sha256",):
                    values = fields.get(key, [])
                    if not isinstance(values, list):
                        raise LedgerConflictError("CUDA exit audit evidence is malformed")
                    for value in values:
                        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                            raise LedgerConflictError("CUDA exit audit evidence is malformed")
                        conflict_exit_hashes.add(value)
                digest = fields.get("exit_evidence_sha256")
                if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise LedgerConflictError("CUDA confirmed exit evidence is malformed")
                conflict_exit_hashes.add(digest)

            bounded_exit_hashes, exits_overflow = _bounded_cuda_hashes(
                conflict_exit_hashes, MAX_CUDA_EXIT_AUDIT_HASHES,
            )
            conflict_fatal_hashes: set[str] = set()
            for fields in audit_sources:
                values = fields.get("exit_candidate_fatal_sha256", [])
                if not isinstance(values, list):
                    raise LedgerConflictError("CUDA exit audit evidence is malformed")
                for value in values:
                    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
                        raise LedgerConflictError("CUDA exit audit evidence is malformed")
                    conflict_fatal_hashes.add(value)
            for payload in (existing, incoming):
                digest = payload.get("source_evidence_sha256")
                if isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest):
                    conflict_fatal_hashes.add(digest)
            bounded_fatal_hashes, fatals_overflow = _bounded_cuda_hashes(
                conflict_fatal_hashes, MAX_CUDA_FATAL_CANDIDATE_HASHES,
            )

            conflict_fields = dict(new_fields)
            conflict_fields.update({
                "miner_exit_status": "UNKNOWN",
                "exit_status_confirmed": False,
                "exit_status_event_time_utc": None,
                "exit_evidence_sha256": None,
                "exit_correlation_status": "AMBIGUOUS",
                "exit_evidence_audit_sha256": bounded_exit_hashes,
                "exit_candidate_fatal_sha256": bounded_fatal_hashes,
            })
            if (
                exits_overflow
                or fatals_overflow
                or old_fields.get("exit_correlation_audit_truncated") is True
                or new_fields.get("exit_correlation_audit_truncated") is True
            ):
                conflict_fields["exit_correlation_audit_truncated"] = True
            conflict_payload = dict(incoming)
            conflict_payload["event_fields"] = conflict_fields
            return merged_payload(conflict_payload, *audit_sources, conflict_fields)
        return merged_payload(existing, *audit_sources)
    if old_confirmed:
        if (
            new_fields.get("exit_correlation_status") == "AMBIGUOUS"
            or new_fields.get("exit_correlation_audit_truncated") is True
        ):
            return merged_payload(incoming, *audit_sources)
        # An overlapping query without the delayed exit record cannot erase
        # evidence already durably correlated to this fatal record.
        return merged_payload(existing, *audit_sources)
    if old_fields.get("exit_correlation_status") == "AMBIGUOUS":
        # Once multiple fatal candidates competed for exit evidence, a later
        # partial page cannot make that historical association unique.
        return merged_payload(existing, *audit_sources)
    if not new_confirmed:
        base = incoming if new_fields.get("exit_correlation_status") == "AMBIGUOUS" else existing
        return merged_payload(base, *audit_sources)
    if (
        new_fields.get("miner_exit_status") != 1
        or not isinstance(new_fields.get("exit_status_event_time_utc"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", str(new_fields.get("exit_evidence_sha256") or ""))
    ):
        raise LedgerConflictError("CUDA alert delayed exit evidence is malformed")
    return merged_payload(incoming, *audit_sources)


def _render_stored_message(payload: Mapping[str, Any]) -> str:
    # Use the same central renderer for every persisted outbox update. In
    # particular, CUDA messages include event time, alert ID, and evidence
    # classification in addition to the dedicated renderer's bounded body.
    # The lazy import avoids the engine/ledger module import cycle.
    from .engine import _render_message
    return _render_message(payload)


class SQLiteAlertLedger:
    """Atomic local dedup/cursor state; not a distributed production ledger."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(
            self.path,
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS log_alert_cursor (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                cursor_time_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS log_alerts (
                dedupe_key TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                event_time_utc TEXT NOT NULL,
                identity_key TEXT NOT NULL,
                identity_status TEXT NOT NULL,
                machine_id TEXT,
                instance_id TEXT,
                container_group_name TEXT,
                alert_id TEXT,
                source_evidence_sha256 TEXT NOT NULL,
                source_log_ref_sha256 TEXT,
                payload_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS log_alert_outbox (
                dedupe_key TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                message_text TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state = 'PREPARED_OFFLINE'),
                created_at_utc TEXT NOT NULL,
                suppressed_by TEXT,
                FOREIGN KEY(dedupe_key) REFERENCES log_alerts(dedupe_key)
            );
            CREATE TABLE IF NOT EXISTS log_alert_startup_states (
                resource_key TEXT PRIMARY KEY,
                state_json TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_log_alert_event_time
                ON log_alerts(event_time_utc);
            CREATE TABLE IF NOT EXISTS log_alert_cuda_cooldowns (
                cooldown_key TEXT PRIMARY KEY,
                organization_name TEXT NOT NULL,
                project_name TEXT NOT NULL,
                container_group_name TEXT NOT NULL,
                machine_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                last_alert_at_utc TEXT NOT NULL,
                last_dedupe_key TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS log_alert_cuda_suppressed_observations (
                dedupe_key TEXT PRIMARY KEY,
                cooldown_key TEXT NOT NULL,
                event_time_utc TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                resource_type TEXT NOT NULL DEFAULT '',
                source_evidence_sha256 TEXT NOT NULL,
                observed_at_utc TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cuda_suppressed_scope_time
                ON log_alert_cuda_suppressed_observations(cooldown_key, observed_at_utc);
            CREATE TABLE IF NOT EXISTS log_alert_live_scope (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                organization_name TEXT NOT NULL,
                operation TEXT NOT NULL CHECK (operation = 'READ_LOG_QUERY'),
                query_sha256 TEXT NOT NULL,
                data_classification TEXT NOT NULL CHECK (data_classification = 'PROVIDER_OBSERVED')
            );
            CREATE TABLE IF NOT EXISTS log_alert_delivery (
                dedupe_key TEXT PRIMARY KEY,
                data_classification TEXT NOT NULL CHECK (data_classification = 'PROVIDER_OBSERVED'),
                state TEXT NOT NULL CHECK (state IN ('PENDING','DISPATCHING','SENT','DELIVERY_UNKNOWN','FAILED')),
                attempt_count INTEGER NOT NULL CHECK (attempt_count IN (0,1)),
                http_status INTEGER,
                failure_code TEXT,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(dedupe_key) REFERENCES log_alert_outbox(dedupe_key)
            );
            CREATE TABLE IF NOT EXISTS log_alert_pool_episodes (
                identity_key TEXT NOT NULL,
                monitor_session_id TEXT NOT NULL,
                pool_episode_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('OPEN','RECOVERED')),
                first_failure_utc TEXT NOT NULL,
                latest_failure_utc TEXT NOT NULL,
                failure_count INTEGER NOT NULL CHECK (failure_count BETWEEN 1 AND 1000000),
                pool_alert_sequence INTEGER NOT NULL CHECK (pool_alert_sequence BETWEEN 1 AND 1000000),
                updated_at_utc TEXT NOT NULL,
                PRIMARY KEY(identity_key,monitor_session_id,pool_episode_id)
            );
            """
        )
        # If a process stops after durably claiming a send, its delivery result
        # is unknowable. Never retry it after restart.
        self._db.execute(
            "UPDATE log_alert_delivery SET state='DELIVERY_UNKNOWN',failure_code='PROCESS_RESTARTED',updated_at_utc=created_at_utc WHERE state='DISPATCHING'"
        )
        outbox_columns = {
            row["name"] for row in self._db.execute("PRAGMA table_info(log_alert_outbox)")
        }
        if "suppressed_by" not in outbox_columns:
            self._db.execute("ALTER TABLE log_alert_outbox ADD COLUMN suppressed_by TEXT")
        suppressed_columns = {
            row["name"] for row in self._db.execute(
                "PRAGMA table_info(log_alert_cuda_suppressed_observations)"
            )
        }
        if "resource_type" not in suppressed_columns:
            self._db.execute(
                "ALTER TABLE log_alert_cuda_suppressed_observations "
                "ADD COLUMN resource_type TEXT NOT NULL DEFAULT ''"
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def get_cursor(self) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT cursor_time_utc FROM log_alert_cursor WHERE singleton=1"
            ).fetchone()
            return None if row is None else str(row["cursor_time_utc"])

    @staticmethod
    def _clean_live_scope(scope: Mapping[str, Any]) -> dict[str, str]:
        required = {"organization_name", "operation", "query_sha256", "data_classification"}
        if not isinstance(scope, Mapping) or set(scope) != required:
            raise ValueError("live query scope fields are invalid")
        result = dict(scope)
        if (
            not isinstance(result["organization_name"], str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]", result["organization_name"])
            or result["operation"] != "READ_LOG_QUERY"
            or result["data_classification"] != PROVIDER_OBSERVED
            or not isinstance(result["query_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", result["query_sha256"])
        ):
            raise ValueError("live query scope is invalid")
        return {key: str(value) for key, value in result.items()}

    def assert_live_scope(self, scope: Mapping[str, Any]) -> None:
        """Refuse to make a live request with a mixed or changed local ledger."""
        clean = self._clean_live_scope(scope)
        with self._lock:
            row = self._db.execute(
                "SELECT organization_name,operation,query_sha256,data_classification FROM log_alert_live_scope WHERE singleton=1"
            ).fetchone()
            if row is not None:
                fields = ("organization_name", "operation", "query_sha256", "data_classification")
                if tuple(row[key] for key in fields) != tuple(clean[key] for key in fields):
                    raise LedgerConflictError("live ledger scope does not match this query")
                return
            has_cursor = self._db.execute("SELECT 1 FROM log_alert_cursor WHERE singleton=1").fetchone()
            has_alerts = self._db.execute("SELECT 1 FROM log_alerts LIMIT 1").fetchone()
            if has_cursor is not None or has_alerts is not None:
                raise LedgerConflictError("unbound ledger already contains data; live query is blocked")

    def get_startup_states(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT resource_key,state_json FROM log_alert_startup_states ORDER BY resource_key"
            ).fetchall()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                value = json.loads(str(row["state_json"]))
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                result[str(row["resource_key"])] = value
        return result

    def commit_cycle(
        self,
        notifications: Sequence[Mapping[str, Any]],
        *,
        cursor_time_utc: str,
        committed_at_utc: str,
        startup_states: Mapping[str, Mapping[str, Any]] | None = None,
        cuda_exit_evidence: Sequence[Mapping[str, Any]] = (),
        data_classification: str = DATA_CLASSIFICATION,
        live_scope: Mapping[str, Any] | None = None,
        allow_provider_delivery: bool = False,
        provider_response_evidence: Sequence[Any] = (),
    ) -> list[dict[str, Any]]:
        """Insert outbox items and advance the monotonic cursor atomically."""
        cursor = canonical_utc(cursor_time_utc)
        committed = canonical_utc(committed_at_utc)
        if data_classification not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}:
            raise ValueError("cycle evidence classification is invalid")
        if type(allow_provider_delivery) is not bool:
            raise ValueError("provider delivery gate must be boolean")
        safe_live_scope = self._clean_live_scope(live_scope) if live_scope is not None else None
        if data_classification == PROVIDER_OBSERVED and safe_live_scope is None:
            raise ValueError("provider-observed cycles require a bound query scope")
        if data_classification == DATA_CLASSIFICATION and safe_live_scope is not None:
            raise ValueError("synthetic cycles cannot bind a provider scope")
        if allow_provider_delivery and data_classification != PROVIDER_OBSERVED:
            raise ValueError("synthetic evidence is never eligible for Telegram delivery")
        evidence_items = tuple(provider_response_evidence)
        if data_classification == PROVIDER_OBSERVED:
            from .live_transport import ProviderResponseEvidence

            if not evidence_items or any(
                type(item) is not ProviderResponseEvidence
                or item.source != "salad_https_fixed_route"
                or item.classification != PROVIDER_OBSERVED
                or item.status_code != 200
                or not re.fullmatch(r"[a-f0-9]{64}", item.response_sha256)
                for item in evidence_items
            ):
                raise ValueError("provider-observed cycles require exact HTTPS response evidence")
        elif any(getattr(item, "classification", None) == PROVIDER_OBSERVED for item in evidence_items):
            raise ValueError("provider response evidence conflicts with synthetic cycle")
        prepared: list[tuple[dict[str, Any], str, str]] = []
        for notification in notifications:
            if not isinstance(notification, Mapping):
                raise ValueError("notification must be a mapping")
            item = dict(notification)
            _validate_payload(item)
            key = item.get("dedupe_key")
            message = item.get("message_text")
            if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key):
                raise ValueError("notification dedupe key is invalid")
            if not isinstance(message, str) or len(message) > 8_192:
                raise ValueError("notification message is invalid")
            payload = item.get("payload")
            if not isinstance(payload, Mapping):
                raise ValueError("notification payload is missing")
            if payload.get("data_classification") != data_classification:
                raise ValueError("notification evidence classification conflicts with cycle")
            if (
                data_classification == PROVIDER_OBSERVED
                and payload.get("query_organization") != safe_live_scope["organization_name"]
            ):
                raise ValueError("provider notification organization conflicts with live scope")
            if item.get("event_type") == "CUDA_DRIVER_INCOMPATIBLE":
                _cuda_cooldown_context(item, payload)
            prepared.append((item, _canonical_json(payload), message))

        safe_cuda_exit_evidence: list[dict[str, str]] = []
        for evidence in cuda_exit_evidence:
            if not isinstance(evidence, Mapping) or set(evidence) != CUDA_EXIT_EVIDENCE_FIELDS:
                raise ValueError("CUDA exit evidence fields are invalid")
            clean: dict[str, str] = {}
            for field in CUDA_EXIT_EVIDENCE_FIELDS - {"event_time_utc", "evidence_sha256"}:
                value = evidence.get(field)
                if not isinstance(value, str) or not value or len(value) > 128 or any(ord(c) < 32 for c in value):
                    raise ValueError("CUDA exit evidence identity is invalid")
                clean[field] = value
            clean["event_time_utc"] = canonical_utc(evidence.get("event_time_utc"))
            digest = evidence.get("evidence_sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("CUDA exit evidence digest is invalid")
            clean["evidence_sha256"] = digest
            safe_cuda_exit_evidence.append(clean)

        safe_startup_states: list[tuple[str, str]] = []
        if startup_states is not None:
            from .startup_guard import sanitize_startup_state

            for resource_key, state in startup_states.items():
                if not re.fullmatch(r"[a-f0-9]{64}", resource_key):
                    raise ValueError("startup state resource key is invalid")
                safe_state = sanitize_startup_state(state)
                _validate_payload(safe_state)
                safe_startup_states.append((resource_key, _canonical_json(safe_state)))

        inserted: list[dict[str, Any]] = []
        cuda_dedupe_by_evidence = {
            item.get("source_evidence_sha256"): item["dedupe_key"]
            for item, _payload_json, _message in prepared
            if item.get("event_type") == "CUDA_DRIVER_INCOMPATIBLE"
        }

        def persist_enriched_alert(dedupe_key: str, payload: Mapping[str, Any]) -> None:
            merged_payload = dict(payload)
            _validate_payload(merged_payload)
            merged_json = _canonical_json(merged_payload)
            merged_message = _render_stored_message(merged_payload)
            identity = merged_payload.get("identity", {})
            self._db.execute(
                """UPDATE log_alerts SET alert_id=?,identity_status=?,machine_id=?,
                       instance_id=?,container_group_name=?,payload_json=? WHERE dedupe_key=?""",
                (
                    merged_payload.get("alert_id"), identity.get("identity_status", "UNKNOWN"),
                    identity.get("machine_id"), identity.get("instance_id"),
                    identity.get("container_group_name"), merged_json, dedupe_key,
                ),
            )
            self._db.execute(
                "UPDATE log_alert_outbox SET payload_json=?,message_text=? WHERE dedupe_key=?",
                (merged_json, merged_message, dedupe_key),
            )

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                scope_row = self._db.execute(
                    "SELECT organization_name,operation,query_sha256,data_classification FROM log_alert_live_scope WHERE singleton=1"
                ).fetchone()
                if safe_live_scope is not None:
                    scope_values = tuple(safe_live_scope[key] for key in (
                        "organization_name", "operation", "query_sha256", "data_classification",
                    ))
                    if scope_row is None:
                        has_cursor_before = self._db.execute("SELECT 1 FROM log_alert_cursor WHERE singleton=1").fetchone()
                        has_alerts_before = self._db.execute("SELECT 1 FROM log_alerts LIMIT 1").fetchone()
                        if has_cursor_before is not None or has_alerts_before is not None:
                            raise LedgerConflictError("unbound ledger already contains data; cannot bind live scope")
                        self._db.execute(
                            "INSERT INTO log_alert_live_scope(singleton,organization_name,operation,query_sha256,data_classification) VALUES(1,?,?,?,?)",
                            scope_values,
                        )
                    elif tuple(scope_row[key] for key in (
                        "organization_name", "operation", "query_sha256", "data_classification",
                    )) != scope_values:
                        raise LedgerConflictError("live ledger scope changed")
                elif scope_row is not None:
                    raise LedgerConflictError("synthetic and provider-observed cycles cannot share a ledger")
                current_row = self._db.execute(
                    "SELECT cursor_time_utc FROM log_alert_cursor WHERE singleton=1"
                ).fetchone()
                current = None if current_row is None else current_row["cursor_time_utc"]
                if current is not None and datetime.fromisoformat(cursor.replace("Z", "+00:00")) < datetime.fromisoformat(
                    str(current).replace("Z", "+00:00")
                ):
                    raise ValueError("durable query cursor cannot move backwards")
                for item, payload_json, message in prepared:
                    new_payload = json.loads(payload_json)
                    event_type = item.get("event_type")
                    pool_fields = new_payload.get("event_fields", {})
                    pool_episode_key: tuple[str, str, str] | None = None
                    if (
                        event_type in {
                            "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
                            "POOL_CONNECTION_RECOVERED",
                        }
                        and isinstance(pool_fields, Mapping)
                        and pool_fields.get("pool_episode_id")
                        and pool_fields.get("monitor_session_id")
                        and item.get("machine_id")
                        and item.get("instance_id")
                        and item.get("container_group_name")
                    ):
                        pool_episode_key = (
                            str(item["identity_key"]),
                            str(pool_fields["monitor_session_id"]),
                            str(pool_fields["pool_episode_id"]),
                        )
                        episode_row = self._db.execute(
                            "SELECT state FROM log_alert_pool_episodes "
                            "WHERE identity_key=? AND monitor_session_id=? AND pool_episode_id=?",
                            pool_episode_key,
                        ).fetchone()
                        if event_type == "POOL_CONNECTION_RECOVERED" and (
                            episode_row is None or episode_row["state"] != "OPEN"
                        ):
                            # A recovery record is accepted only for an exact
                            # provider resource with a previously committed
                            # unresolved episode.
                            continue
                        if event_type in {"POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE"} and (
                            episode_row is not None and episode_row["state"] == "RECOVERED"
                        ):
                            # Late/replayed records cannot reopen a closed episode.
                            continue
                    existing = self._db.execute(
                        "SELECT payload_json FROM log_alerts WHERE dedupe_key=?",
                        (item["dedupe_key"],),
                    ).fetchone()
                    if existing is not None:
                        old_payload = json.loads(existing["payload_json"])
                        new_payload = json.loads(payload_json)
                        if event_type in {"NO_FLOOR_CONFIGURED", "MONITOR_CONFIGURATION_INVALID"}:
                            old_fields = old_payload.get("event_fields", {})
                            new_fields = new_payload.get("event_fields", {})
                            if old_payload.get("event_type") != new_payload.get("event_type"):
                                raise LedgerConflictError("stable allocation alert identity changed")
                            if event_type == "NO_FLOOR_CONFIGURED":
                                same_key = all(
                                    old_fields.get(key) == new_fields.get(key)
                                    for key in ("gpu_key", "device", "policy_hash", "suggestion")
                                )
                            else:
                                same_key = old_fields.get("reason") == new_fields.get("reason")
                            if not same_key:
                                raise LedgerConflictError("stable allocation alert evidence conflicted")
                            merged_identity = _merge_notification_identity(
                                old_payload.get("identity"), new_payload.get("identity"),
                                query_organization=old_payload.get("query_organization"),
                            )
                            merged_payload = dict(old_payload)
                            merged_payload["identity"] = merged_identity
                            if merged_payload != old_payload:
                                persist_enriched_alert(item["dedupe_key"], merged_payload)
                            # Repeated observations intentionally retain the
                            # first evidence record while allowing verified ID enrichment.
                            continue
                        if event_type == "CUDA_DRIVER_INCOMPATIBLE":
                            merged_payload = _merge_cuda_exit_evidence(old_payload, new_payload)
                            if merged_payload != old_payload:
                                persist_enriched_alert(item["dedupe_key"], merged_payload)
                            continue
                        old_alert_id = old_payload.get("alert_id")
                        new_alert_id = new_payload.get("alert_id")
                        merged_identity = _merge_notification_identity(
                            old_payload.get("identity"), new_payload.get("identity"),
                            query_organization=old_payload.get("query_organization"),
                        )
                        old_without_id = dict(old_payload)
                        new_without_id = dict(new_payload)
                        old_without_id["identity"] = merged_identity
                        new_without_id["identity"] = merged_identity
                        old_without_id["alert_id"] = None
                        new_without_id["alert_id"] = None
                        if old_without_id != new_without_id:
                            raise LedgerConflictError("deduplicated alert evidence changed")
                        if old_alert_id is not None and new_alert_id is not None and old_alert_id != new_alert_id:
                            raise LedgerConflictError("deduplicated alert has conflicting IDs")
                        merged_payload = dict(old_payload)
                        merged_payload["identity"] = merged_identity
                        merged_payload["alert_id"] = old_alert_id or new_alert_id
                        if merged_payload != old_payload:
                            # Update presentation in place. The delivery state
                            # is untouched, so SENT/DELIVERY_UNKNOWN never re-send.
                            persist_enriched_alert(item["dedupe_key"], merged_payload)
                        continue
                    if item.get("event_type") == "MONITOR_CONFIGURATION_INVALID":
                        new_payload = json.loads(payload_json)
                        reason = new_payload.get("event_fields", {}).get("reason")
                        previous_rows = self._db.execute(
                            "SELECT event_time_utc,payload_json FROM log_alerts "
                            "WHERE identity_key=? AND event_type=? ORDER BY event_time_utc DESC LIMIT 1000",
                            (item["identity_key"], "MONITOR_CONFIGURATION_INVALID"),
                        ).fetchall()
                        current_time = datetime.fromisoformat(
                            str(item["event_time_utc"]).replace("Z", "+00:00")
                        )
                        suppress = False
                        for previous in previous_rows:
                            previous_payload = json.loads(previous["payload_json"])
                            previous_reason = previous_payload.get("event_fields", {}).get("reason")
                            if previous_reason != reason:
                                continue
                            previous_time = datetime.fromisoformat(
                                str(previous["event_time_utc"]).replace("Z", "+00:00")
                            )
                            # Older overlapping records and repeated restart
                            # lines inside the five-minute cooldown are muted.
                            if (current_time - previous_time).total_seconds() < CONFIG_ALERT_COOLDOWN_SECONDS:
                                suppress = True
                                break
                        if suppress:
                            continue
                    cooldown_context = _cuda_cooldown_context(item, json.loads(payload_json))
                    if cooldown_context is not None:
                        cooldown_key, context = cooldown_context
                        cooldown_row = self._db.execute(
                            "SELECT last_alert_at_utc FROM log_alert_cuda_cooldowns WHERE cooldown_key=?",
                            (cooldown_key,),
                        ).fetchone()
                        if cooldown_row is not None:
                            last_time = datetime.fromisoformat(
                                str(cooldown_row["last_alert_at_utc"]).replace("Z", "+00:00")
                            )
                            current_time = datetime.fromisoformat(
                                str(item["event_time_utc"]).replace("Z", "+00:00")
                            )
                            if (current_time - last_time).total_seconds() < CUDA_ALERT_COOLDOWN_SECONDS:
                                self._db.execute(
                                    """INSERT OR IGNORE INTO log_alert_cuda_suppressed_observations(
                                           dedupe_key,cooldown_key,event_time_utc,instance_id,
                                           resource_type,source_evidence_sha256,observed_at_utc
                                       ) VALUES(?,?,?,?,?,?,?)""",
                                    (
                                        item["dedupe_key"], cooldown_key, item["event_time_utc"],
                                        item.get("instance_id") or "UNKNOWN",
                                        str(json.loads(payload_json).get("resource_type") or ""),
                                        item["source_evidence_sha256"], committed,
                                    ),
                                )
                                self._db.execute(
                                    """DELETE FROM log_alert_cuda_suppressed_observations
                                       WHERE cooldown_key=? AND dedupe_key IN (
                                           SELECT dedupe_key FROM log_alert_cuda_suppressed_observations
                                           WHERE cooldown_key=?
                                           ORDER BY observed_at_utc DESC,dedupe_key DESC
                                           LIMIT -1 OFFSET ?
                                       )""",
                                    (cooldown_key, cooldown_key, MAX_CUDA_SUPPRESSED_AUDIT_ROWS_PER_SCOPE),
                                )
                                continue
                    source_log_ref = item.get("source_log_ref")
                    source_log_hash = (
                        hashlib.sha256(str(source_log_ref).encode("utf-8")).hexdigest()
                        if source_log_ref is not None else None
                    )
                    payload = json.loads(payload_json)
                    self._db.execute(
                        """INSERT INTO log_alerts VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )""",
                        (
                            item["dedupe_key"], item["event_type"], item["event_time_utc"],
                            item["identity_key"], item["identity_status"], item.get("machine_id"),
                            item.get("instance_id"), item.get("container_group_name"),
                            item.get("alert_id"), item["source_evidence_sha256"], source_log_hash,
                            payload_json, committed,
                        ),
                    )
                    self._db.execute(
                        """INSERT INTO log_alert_outbox(
                               dedupe_key,payload_json,message_text,state,created_at_utc,suppressed_by
                           ) VALUES (?, ?, ?, 'PREPARED_OFFLINE', ?, NULL)""",
                        (item["dedupe_key"], payload_json, message, committed),
                    )
                    if pool_episode_key is not None:
                        if event_type in {"POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE"}:
                            first_failure = pool_fields.get("first_failure_utc")
                            latest_failure = pool_fields.get("latest_failure_utc")
                            failure_count = int(pool_fields.get("failure_count", 1))
                            pool_sequence = int(pool_fields.get("pool_alert_sequence", 1))
                            self._db.execute(
                                """INSERT INTO log_alert_pool_episodes(
                                       identity_key,monitor_session_id,pool_episode_id,state,
                                       first_failure_utc,latest_failure_utc,failure_count,
                                       pool_alert_sequence,updated_at_utc
                                   ) VALUES(?,?,?,'OPEN',?,?,?,?,?)
                                   ON CONFLICT(identity_key,monitor_session_id,pool_episode_id)
                                   DO UPDATE SET
                                       latest_failure_utc=excluded.latest_failure_utc,
                                       failure_count=MAX(log_alert_pool_episodes.failure_count,excluded.failure_count),
                                       pool_alert_sequence=MAX(log_alert_pool_episodes.pool_alert_sequence,excluded.pool_alert_sequence),
                                       updated_at_utc=excluded.updated_at_utc
                                   WHERE log_alert_pool_episodes.state='OPEN'""",
                                (
                                    *pool_episode_key, first_failure, latest_failure,
                                    failure_count, pool_sequence, committed,
                                ),
                            )
                        elif event_type == "POOL_CONNECTION_RECOVERED":
                            self._db.execute(
                                """UPDATE log_alert_pool_episodes SET state='RECOVERED',
                                       pool_alert_sequence=MAX(pool_alert_sequence,?),updated_at_utc=?
                                   WHERE identity_key=? AND monitor_session_id=? AND pool_episode_id=?
                                     AND state='OPEN'""",
                                (
                                    int(pool_fields["pool_alert_sequence"]), committed,
                                    *pool_episode_key,
                                ),
                            )
                    if cooldown_context is not None:
                        cooldown_key, context = cooldown_context
                        self._db.execute(
                            """INSERT INTO log_alert_cuda_cooldowns(
                                   cooldown_key,organization_name,project_name,container_group_name,
                                   machine_id,reason,last_alert_at_utc,last_dedupe_key
                               ) VALUES(?,?,?,?,?,?,?,?)
                               ON CONFLICT(cooldown_key) DO UPDATE SET
                                 last_alert_at_utc=excluded.last_alert_at_utc,
                                 last_dedupe_key=excluded.last_dedupe_key""",
                            (
                                cooldown_key, context["organization_name"], context["project_name"],
                                context["container_group_name"], context["machine_id"], context["reason"],
                                item["event_time_utc"], item["dedupe_key"],
                            ),
                        )
                    inserted.append({
                        "dedupe_key": item["dedupe_key"],
                        "event_type": item["event_type"],
                        "event_time_utc": item["event_time_utc"],
                        "payload": payload,
                        "message_text": message,
                        "state": "PREPARED_OFFLINE",
                    })
                self._apply_late_cuda_exit_evidence(safe_cuda_exit_evidence, prepared)
                self._suppress_startup_alerts_for_cuda(
                    safe_startup_states,
                    cuda_dedupe_by_evidence,
                )
                if allow_provider_delivery:
                    for newly_inserted in inserted:
                        delivery_row = self._db.execute(
                            "SELECT payload_json,suppressed_by FROM log_alert_outbox WHERE dedupe_key=?",
                            (newly_inserted["dedupe_key"],),
                        ).fetchone()
                        if delivery_row is None or delivery_row["suppressed_by"] is not None:
                            continue
                        delivery_payload = json.loads(delivery_row["payload_json"])
                        if delivery_payload.get("data_classification") != PROVIDER_OBSERVED:
                            continue
                        self._db.execute(
                            "INSERT OR IGNORE INTO log_alert_delivery(dedupe_key,data_classification,state,attempt_count,http_status,failure_code,created_at_utc,updated_at_utc) VALUES(?,?,'PENDING',0,NULL,NULL,?,?)",
                            (newly_inserted["dedupe_key"], PROVIDER_OBSERVED, committed, committed),
                        )
                for resource_key, state_json in safe_startup_states:
                    self._db.execute(
                        """INSERT INTO log_alert_startup_states(resource_key,state_json,updated_at_utc)
                           VALUES(?,?,?)
                           ON CONFLICT(resource_key) DO UPDATE SET
                             state_json=excluded.state_json,
                             updated_at_utc=excluded.updated_at_utc""",
                        (resource_key, state_json, committed),
                    )
                self._db.execute(
                    """INSERT INTO log_alert_cursor(singleton, cursor_time_utc)
                       VALUES (1, ?)
                       ON CONFLICT(singleton) DO UPDATE SET cursor_time_utc=excluded.cursor_time_utc""",
                    (cursor,),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return inserted

    def claim_delivery(self, dedupe_key: str, *, claimed_at_utc: str) -> dict[str, Any] | None:
        """Atomically claim a one-shot Telegram attempt before network I/O."""
        if not isinstance(dedupe_key, str) or not re.fullmatch(r"[a-f0-9]{64}", dedupe_key):
            raise ValueError("delivery key is invalid")
        claimed = canonical_utc(claimed_at_utc)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT d.state,o.payload_json,o.message_text,o.suppressed_by FROM log_alert_delivery d JOIN log_alert_outbox o USING(dedupe_key) WHERE d.dedupe_key=?",
                    (dedupe_key,),
                ).fetchone()
                if row is None or row["state"] != "PENDING" or row["suppressed_by"] is not None:
                    self._db.execute("COMMIT")
                    return None
                payload = json.loads(row["payload_json"])
                if payload.get("data_classification") != PROVIDER_OBSERVED:
                    raise LedgerConflictError("only provider-observed alerts may be delivered")
                self._db.execute(
                    "UPDATE log_alert_delivery SET state='DISPATCHING',attempt_count=1,updated_at_utc=? WHERE dedupe_key=? AND state='PENDING'",
                    (claimed, dedupe_key),
                )
                self._db.execute("COMMIT")
                return {"dedupe_key": dedupe_key, "payload": payload, "message_text": row["message_text"]}
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def finish_delivery(
        self, dedupe_key: str, *, state: str, updated_at_utc: str,
        http_status: int | None = None, failure_code: str | None = None,
    ) -> None:
        allowed = {"SENT", "DELIVERY_UNKNOWN", "FAILED"}
        if state not in allowed:
            raise ValueError("delivery terminal state is invalid")
        if http_status is not None and (type(http_status) is not int or not 100 <= http_status <= 599):
            raise ValueError("delivery HTTP status is invalid")
        if failure_code is not None and failure_code not in {
            "HTTP_FAILURE", "RESPONSE_INVALID", "TRANSPORT_AMBIGUOUS", "PROCESS_RESTARTED",
        }:
            raise ValueError("delivery failure code is invalid")
        updated = canonical_utc(updated_at_utc)
        with self._lock:
            cursor = self._db.execute(
                "UPDATE log_alert_delivery SET state=?,http_status=?,failure_code=?,updated_at_utc=? WHERE dedupe_key=? AND state='DISPATCHING' AND attempt_count=1",
                (state, http_status, failure_code, updated, dedupe_key),
            )
            if cursor.rowcount != 1:
                raise LedgerConflictError("delivery is not in a dispatchable state")

    def list_deliveries(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT dedupe_key,data_classification,state,attempt_count,http_status,failure_code,created_at_utc,updated_at_utc FROM log_alert_delivery ORDER BY created_at_utc,dedupe_key"
            ).fetchall()
        return [dict(row) for row in rows]

    def _apply_late_cuda_exit_evidence(
        self,
        evidence: Sequence[Mapping[str, str]],
        prepared_notifications: Sequence[tuple[Mapping[str, Any], str, str]] = (),
    ) -> None:
        """Reconcile all known fatal/exit candidates per exact resource scope.

        The graph is evaluated as a whole, including persisted confirmations
        and cooldown-suppressed fatal observations. Processing exits one at a
        time can incorrectly confirm the first member of an ambiguous set.
        """
        from .cuda_guard import MAX_EXIT_CORRELATION_SECONDS, render_cuda_message

        def scope_from_identity(resource_type: Any, identity: Any) -> tuple[str, ...] | None:
            names = (
                "organization_name", "project_name", "container_group_name",
                "machine_id", "instance_id",
            )
            if (
                not isinstance(resource_type, str) or not resource_type
                or not isinstance(identity, Mapping)
                or identity.get("identity_status") not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}
                or identity.get("identity_source") != "resource.labels"
                or any(not isinstance(identity.get(name), str) or not identity[name] for name in names)
            ):
                return None
            return (resource_type, *(str(identity[name]) for name in names))

        scopes: dict[tuple[str, ...], dict[str, Any]] = {}

        def scope_state(scope: tuple[str, ...]) -> dict[str, Any]:
            return scopes.setdefault(scope, {"triggers": [], "incoming_exits": {}})

        for observation in evidence:
            scope = (
                observation["resource_type"], observation["organization_name"],
                observation["project_name"], observation["container_group_name"],
                observation["machine_id"], observation["instance_id"],
            )
            state = scope_state(scope)
            timestamp = canonical_utc(observation["event_time_utc"])
            state["triggers"].append(datetime.fromisoformat(timestamp.replace("Z", "+00:00")))
            existing = state["incoming_exits"].get(observation["evidence_sha256"])
            if existing is not None and existing != timestamp:
                state["input_conflict"] = True
            state["incoming_exits"][observation["evidence_sha256"]] = timestamp

        for item, payload_json, _message in prepared_notifications:
            if item.get("event_type") != "CUDA_DRIVER_INCOMPATIBLE":
                continue
            payload = json.loads(payload_json)
            scope = scope_from_identity(payload.get("resource_type"), payload.get("identity"))
            if scope is None or payload.get("query_organization") != scope[1]:
                continue
            fields = payload.get("event_fields", {})
            if not isinstance(fields, Mapping) or fields.get("reason") != "CUDA_DRIVER_VERSION_INSUFFICIENT":
                continue
            timestamp = canonical_utc(item.get("event_time_utc"))
            scope_state(scope)["triggers"].append(
                datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            )

        for scope, state in scopes.items():
            (resource_type, organization, project, group, machine, instance) = scope
            triggers = state["triggers"]
            if not triggers:
                continue
            window = timedelta(seconds=MAX_EXIT_CORRELATION_SECONDS)
            lower = canonical_utc(min(triggers) - window)
            upper = canonical_utc(max(triggers) + window)
            rows = self._db.execute(
                """SELECT dedupe_key,event_time_utc,source_evidence_sha256,payload_json FROM log_alerts
                   WHERE event_type=? AND machine_id=? AND instance_id=?
                     AND container_group_name=? AND event_time_utc>=? AND event_time_utc<=?
                   ORDER BY event_time_utc,dedupe_key LIMIT ?""",
                (
                    "CUDA_DRIVER_INCOMPATIBLE", machine, instance, group,
                    lower, upper, MAX_CUDA_FATAL_CANDIDATE_HASHES + 1,
                ),
            ).fetchall()
            query_overflow = len(rows) > MAX_CUDA_FATAL_CANDIDATE_HASHES
            fatal_nodes: dict[str, dict[str, Any]] = {}
            for row in rows[:MAX_CUDA_FATAL_CANDIDATE_HASHES]:
                payload = json.loads(row["payload_json"])
                identity = payload.get("identity", {})
                fields = payload.get("event_fields", {})
                if (
                    payload.get("event_type") != "CUDA_DRIVER_INCOMPATIBLE"
                    or payload.get("resource_type") != resource_type
                    or payload.get("query_organization") != organization
                    or identity.get("identity_status") not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}
                    or identity.get("identity_source") != "resource.labels"
                    or identity.get("organization_name") != organization
                    or identity.get("project_name") != project
                    or identity.get("container_group_name") != group
                    or identity.get("machine_id") != machine
                    or identity.get("instance_id") != instance
                    or fields.get("reason") != "CUDA_DRIVER_VERSION_INSUFFICIENT"
                ):
                    continue
                fatal_hash = str(row["source_evidence_sha256"])
                try:
                    fatal_time = datetime.fromisoformat(
                        canonical_utc(row["event_time_utc"]).replace("Z", "+00:00")
                    )
                except (TypeError, ValueError):
                    query_overflow = True
                    continue
                prior_audit = fields.get("exit_evidence_audit_sha256", [])
                prior_candidates = fields.get("exit_candidate_fatal_sha256", [])
                if not isinstance(prior_audit, list) or not isinstance(prior_candidates, list):
                    query_overflow = True
                    continue
                latched = (
                    fields.get("exit_correlation_status") == "AMBIGUOUS"
                    or fields.get("exit_correlation_audit_truncated") is True
                    or bool(prior_audit)
                    or bool(prior_candidates)
                )
                fatal_nodes[fatal_hash] = {
                    "time": fatal_time,
                    "row": row,
                    "fields": dict(fields),
                    "latched_ambiguous": latched,
                }

            cooldown = self._db.execute(
                """SELECT cooldown_key FROM log_alert_cuda_cooldowns
                   WHERE organization_name=? AND project_name=? AND container_group_name=?
                     AND machine_id=? AND reason=?""",
                (organization, project, group, machine, "CUDA_DRIVER_VERSION_INSUFFICIENT"),
            ).fetchone()
            scope_uncertain = False
            if cooldown is not None:
                suppressed = self._db.execute(
                    """SELECT event_time_utc,instance_id,resource_type,source_evidence_sha256
                       FROM log_alert_cuda_suppressed_observations
                       WHERE cooldown_key=? AND instance_id=? AND event_time_utc>=? AND event_time_utc<=?
                         AND (resource_type=? OR resource_type='')
                       ORDER BY event_time_utc,dedupe_key LIMIT ?""",
                    (
                        str(cooldown["cooldown_key"]), instance, lower, upper, resource_type,
                        MAX_CUDA_FATAL_CANDIDATE_HASHES + 1,
                    ),
                ).fetchall()
                if len(suppressed) > MAX_CUDA_FATAL_CANDIDATE_HASHES:
                    query_overflow = True
                for row in suppressed[:MAX_CUDA_FATAL_CANDIDATE_HASHES]:
                    if not row["resource_type"]:
                        # A legacy suppressed record lacks enough provider
                        # provenance to safely participate in a unique match.
                        scope_uncertain = True
                    fatal_hash = str(row["source_evidence_sha256"])
                    try:
                        fatal_time = datetime.fromisoformat(
                            canonical_utc(row["event_time_utc"]).replace("Z", "+00:00")
                        )
                    except (TypeError, ValueError):
                        query_overflow = True
                        continue
                    fatal_nodes.setdefault(fatal_hash, {
                        "time": fatal_time,
                        "row": None,
                        "fields": {},
                        "latched_ambiguous": False,
                    })

            if len(fatal_nodes) > MAX_CUDA_FATAL_CANDIDATE_HASHES:
                query_overflow = True

            exit_nodes: dict[str, datetime] = {}
            for exit_hash, timestamp in state["incoming_exits"].items():
                exit_nodes[exit_hash] = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            for fatal_hash, node in fatal_nodes.items():
                fields = node["fields"]
                if fields.get("exit_status_confirmed") is not True:
                    continue
                exit_hash = fields.get("exit_evidence_sha256")
                exit_time = fields.get("exit_status_event_time_utc")
                if (
                    not isinstance(exit_hash, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", exit_hash)
                    or not isinstance(exit_time, str)
                ):
                    node["latched_ambiguous"] = True
                    continue
                try:
                    normalized_exit_time = canonical_utc(exit_time)
                    parsed_exit_time = datetime.fromisoformat(normalized_exit_time.replace("Z", "+00:00"))
                except (TypeError, ValueError):
                    node["latched_ambiguous"] = True
                    continue
                old_time = exit_nodes.get(exit_hash)
                if old_time is not None and old_time != parsed_exit_time:
                    state["input_conflict"] = True
                exit_nodes[exit_hash] = parsed_exit_time

            fatal_to_exits: dict[str, set[str]] = {key: set() for key in fatal_nodes}
            exit_to_fatals: dict[str, set[str]] = {key: set() for key in exit_nodes}
            for fatal_hash, fatal_node in fatal_nodes.items():
                for exit_hash, exit_time in exit_nodes.items():
                    delta = (exit_time - fatal_node["time"]).total_seconds()
                    if 0 < delta <= MAX_EXIT_CORRELATION_SECONDS:
                        fatal_to_exits[fatal_hash].add(exit_hash)
                        exit_to_fatals.setdefault(exit_hash, set()).add(fatal_hash)

            for fatal_hash, node in fatal_nodes.items():
                matching_exits = fatal_to_exits.get(fatal_hash, set())
                row = node["row"]
                if not matching_exits:
                    continue
                candidate_fatals = set().union(*(
                    exit_to_fatals.get(exit_hash, set()) for exit_hash in matching_exits
                ))
                ambiguous = (
                    node["latched_ambiguous"]
                    or query_overflow
                    or scope_uncertain
                    or state.get("input_conflict", False)
                    or len(matching_exits) != 1
                    or any(len(exit_to_fatals.get(exit_hash, ())) != 1 for exit_hash in matching_exits)
                )
                if row is None:
                    continue
                if ambiguous:
                    self._record_cuda_exit_ambiguity(
                        row,
                        sorted(matching_exits),
                        sorted(candidate_fatals),
                        audit_truncated=query_overflow or state.get("input_conflict", False),
                    )
                    continue
                exit_hash = next(iter(matching_exits))
                exit_time = exit_nodes[exit_hash]
                fields = node["fields"]
                if (
                    fields.get("exit_status_confirmed") is True
                    and fields.get("exit_evidence_sha256") == exit_hash
                    and fields.get("exit_status_event_time_utc") == canonical_utc(exit_time)
                ):
                    continue
                if node["latched_ambiguous"] or fields.get("exit_correlation_audit_truncated") is True:
                    self._record_cuda_exit_ambiguity(
                        row, [exit_hash], sorted(candidate_fatals),
                        audit_truncated=fields.get("exit_correlation_audit_truncated") is True,
                    )
                    continue
                payload = json.loads(row["payload_json"])
                updated_fields = dict(fields)
                updated_fields.update({
                    "miner_exit_status": 1,
                    "exit_status_confirmed": True,
                    "exit_status_event_time_utc": canonical_utc(exit_time),
                    "exit_evidence_sha256": exit_hash,
                    "exit_correlation_status": "CONFIRMED",
                })
                updated_payload = dict(payload)
                updated_payload["event_fields"] = updated_fields
                _validate_payload(updated_payload)
                payload_json = _canonical_json(updated_payload)
                message = render_cuda_message(updated_payload)
                dedupe_key = str(row["dedupe_key"])
                self._db.execute(
                    "UPDATE log_alerts SET payload_json=? WHERE dedupe_key=?",
                    (payload_json, dedupe_key),
                )
                self._db.execute(
                    "UPDATE log_alert_outbox SET payload_json=?,message_text=? WHERE dedupe_key=?",
                    (payload_json, message, dedupe_key),
                )

    def _record_cuda_exit_ambiguity(
        self,
        row: sqlite3.Row,
        exit_evidence_sha256: Sequence[str],
        candidate_fatal_sha256: Sequence[str],
        *,
        audit_truncated: bool = False,
    ) -> None:
        from .cuda_guard import render_cuda_message

        payload = json.loads(row["payload_json"])
        fields = dict(payload.get("event_fields", {}))
        exit_hashes = set(fields.get("exit_evidence_audit_sha256", []))
        exit_hashes.update(exit_evidence_sha256)
        prior_confirmed_exit = fields.get("exit_evidence_sha256")
        if isinstance(prior_confirmed_exit, str):
            exit_hashes.add(prior_confirmed_exit)
        fatal_hashes = set(fields.get("exit_candidate_fatal_sha256", []))
        fatal_hashes.update(candidate_fatal_sha256)
        bounded_exits, exits_overflow = _bounded_cuda_hashes(
            exit_hashes, MAX_CUDA_EXIT_AUDIT_HASHES,
        )
        bounded_fatals, fatals_overflow = _bounded_cuda_hashes(
            fatal_hashes, MAX_CUDA_FATAL_CANDIDATE_HASHES,
        )
        fields.update({
            "exit_status_confirmed": False,
            "miner_exit_status": "UNKNOWN",
            "exit_status_event_time_utc": None,
            "exit_evidence_sha256": None,
            "exit_correlation_status": "AMBIGUOUS",
            "exit_evidence_audit_sha256": bounded_exits,
            "exit_candidate_fatal_sha256": bounded_fatals,
        })
        if (
            audit_truncated
            or exits_overflow
            or fatals_overflow
            or fields.get("exit_correlation_audit_truncated") is True
        ):
            fields["exit_correlation_audit_truncated"] = True
        updated_payload = dict(payload)
        updated_payload["event_fields"] = fields
        _validate_payload(updated_payload)
        payload_json = _canonical_json(updated_payload)
        message = render_cuda_message(updated_payload)
        dedupe_key = str(row["dedupe_key"])
        self._db.execute(
            "UPDATE log_alerts SET payload_json=? WHERE dedupe_key=?",
            (payload_json, dedupe_key),
        )
        self._db.execute(
            "UPDATE log_alert_outbox SET payload_json=?,message_text=? WHERE dedupe_key=?",
            (payload_json, message, dedupe_key),
        )

    def _suppress_startup_alerts_for_cuda(
        self,
        startup_states: Sequence[tuple[str, str]],
        cuda_dedupe_by_evidence: Mapping[Any, str],
    ) -> None:
        for resource_key, state_json in startup_states:
            state = json.loads(state_json)
            if (
                not isinstance(state.get("terminal_failure_time_utc"), str)
                or not isinstance(state.get("generation_id"), str)
                or not isinstance(state.get("terminal_failure_evidence_sha256"), str)
            ):
                continue
            evidence_hash = state["terminal_failure_evidence_sha256"]
            reference = cuda_dedupe_by_evidence.get(evidence_hash)
            if reference is None:
                existing_cuda = self._db.execute(
                    """SELECT dedupe_key FROM log_alerts
                       WHERE event_type='CUDA_DRIVER_INCOMPATIBLE'
                         AND source_evidence_sha256=? LIMIT 1""",
                    (evidence_hash,),
                ).fetchone()
                reference = None if existing_cuda is None else str(existing_cuda["dedupe_key"])
            if reference is None:
                reference = evidence_hash
            rows = self._db.execute(
                """SELECT dedupe_key,payload_json FROM log_alerts
                   WHERE event_type='RUNNING_READY_BUT_MINER_NOT_STARTED' AND identity_key=?
                   ORDER BY event_time_utc DESC LIMIT 100""",
                (resource_key,),
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload_json"])
                if payload.get("generation_id") != state["generation_id"]:
                    continue
                self._db.execute(
                    """UPDATE log_alert_outbox SET suppressed_by=?
                       WHERE dedupe_key=? AND state='PREPARED_OFFLINE' AND suppressed_by IS NULL""",
                    (reference, row["dedupe_key"]),
                )

    def list_cuda_suppressed_observations(self) -> list[dict[str, str]]:
        """Return bounded, redacted audit metadata for cooldown-suppressed instances."""
        with self._lock:
            rows = self._db.execute(
                """SELECT cooldown_key,event_time_utc,instance_id,source_evidence_sha256,observed_at_utc
                   FROM log_alert_cuda_suppressed_observations
                   ORDER BY observed_at_utc,dedupe_key"""
            ).fetchall()
        return [
            {
                "cooldown_key": str(row["cooldown_key"]),
                "event_time_utc": str(row["event_time_utc"]),
                "instance_id": str(row["instance_id"]),
                "source_evidence_sha256": str(row["source_evidence_sha256"]),
                "observed_at_utc": str(row["observed_at_utc"]),
            }
            for row in rows
        ]

    def list_outbox(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT dedupe_key,payload_json,message_text,state,created_at_utc,suppressed_by "
                "FROM log_alert_outbox ORDER BY created_at_utc,dedupe_key"
            ).fetchall()
        result = []
        for row in rows:
            item = {
                "dedupe_key": row["dedupe_key"],
                "payload": json.loads(row["payload_json"]),
                "message_text": row["message_text"],
                "state": "SUPPRESSED_BY_CUDA_FATAL" if row["suppressed_by"] else row["state"],
                "created_at_utc": row["created_at_utc"],
            }
            if row["suppressed_by"]:
                item["suppressed_by"] = row["suppressed_by"]
            result.append(item)
        return result

    def alert_count(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) AS n FROM log_alerts").fetchone()
            return int(row["n"])
