"""Durable, fail-closed request budget for the synthetic G4-C broker.

This ledger limits an offline fixture run. It is not a distributed production
coordinator and does not make a Salad credential read-only.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from pilot_scope import (
    CONTAINER_GROUPS,
    MAX_REQUESTS_PER_GROUP,
    MAX_REQUESTS_TOTAL,
    MAX_RESPONSE_BYTES_PER_GROUP,
    MAX_RESPONSE_BYTES_TOTAL,
    REQUEST_PLAN,
    TOTAL_DEADLINE_SECONDS,
)


SCHEMA_VERSION = 2
OFFLINE_LOCAL_TLS = "OFFLINE_LOCAL_TLS"
LIVE_SALAD_GET = "LIVE_SALAD_GET"
_RUN_MODES = frozenset({OFFLINE_LOCAL_TLS, LIVE_SALAD_GET})
_TERMINAL_STATUSES = frozenset(
    {"SUCCESS", "FAILED", "TIMEOUT", "ABORTED_KILL_SWITCH", "TRANSPORT_ERROR"}
)
_RESERVATION_STATUSES = _TERMINAL_STATUSES | {"RESERVED"}


class LedgerError(RuntimeError):
    """The durable request budget cannot safely authorize another fixture."""


class LedgerInitializationError(LedgerError):
    """Explicit ledger initialization was unsafe or invalid."""


class LedgerUnavailable(LedgerError):
    """The initialized ledger is absent, locked, or unavailable."""


class LedgerCorrupt(LedgerError):
    """The initialized ledger is corrupt or has an unexpected schema."""


class LedgerPolicyMismatch(LedgerError):
    """The ledger was initialized for a different request policy."""


class LedgerStateError(LedgerError):
    """The requested transition violates the fixed run state machine."""


class LedgerBudgetExceeded(LedgerError):
    """The fixed four-attempt budget is exhausted."""


class LedgerClockError(LedgerError):
    """The clock moved backward or the durable time window is inconsistent."""


class LedgerInFlight(LedgerError):
    """A previous reservation has an uncertain outcome; fail closed."""


def _policy_document(run_mode: str = OFFLINE_LOCAL_TLS) -> dict[str, Any]:
    if run_mode not in _RUN_MODES:
        raise LedgerInitializationError("ledger run mode is not approved")
    return {
        "organization": REQUEST_PLAN[0].organization,
        "project": REQUEST_PLAN[0].project,
        "groups": list(CONTAINER_GROUPS),
        "requests": [asdict(spec) for spec in REQUEST_PLAN],
        "max_requests_total": MAX_REQUESTS_TOTAL,
        "max_requests_per_group": MAX_REQUESTS_PER_GROUP,
        "total_deadline_seconds": TOTAL_DEADLINE_SECONDS,
        "max_response_bytes_per_group": MAX_RESPONSE_BYTES_PER_GROUP,
        "max_response_bytes_total": MAX_RESPONSE_BYTES_TOTAL,
        "retries": 0,
        "polling": False,
        "redirects": False,
        "transport": run_mode,
    }


def policy_hash_for(run_mode: str) -> str:
    return hashlib.sha256(
        json.dumps(_policy_document(run_mode), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


POLICY_HASH = policy_hash_for(OFFLINE_LOCAL_TLS)


@dataclass(frozen=True)
class Reservation:
    sequence: int
    reservation_id: str
    container_group: str
    reserved_at: float
    expires_at: float
    owner_id: str


def _finite_timestamp(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise LedgerClockError(f"{label} must be a finite numeric timestamp")
    result = float(value)
    if not math.isfinite(result):
        raise LedgerClockError(f"{label} must be a finite numeric timestamp")
    return result


def _ledger_path(value: str | os.PathLike[str]) -> Path:
    raw = os.fspath(value)
    if not raw or raw == ":memory:":
        raise LedgerInitializationError("a file-backed ledger path is required")
    return Path(raw).expanduser().resolve()


def initialize_ledger(
    path: str | os.PathLike[str],
    *,
    now: float,
    run_mode: str = OFFLINE_LOCAL_TLS,
) -> "BrokerLedger":
    """Create a fresh ledger explicitly; never reset or overwrite an existing file."""
    if run_mode not in _RUN_MODES:
        raise LedgerInitializationError("ledger run mode is not approved")
    ledger_path = _ledger_path(path)
    start = _finite_timestamp(now, "now")
    selected_run_id = uuid.uuid4().hex
    if ledger_path.exists():
        raise LedgerInitializationError("refusing to overwrite an existing ledger")
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            ledger_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o600,
        )
    except FileExistsError as exc:
        raise LedgerInitializationError("refusing to overwrite an existing ledger") from exc
    except OSError as exc:
        raise LedgerUnavailable("ledger could not be created") from exc
    else:
        os.close(descriptor)

    try:
        connection = sqlite3.connect(str(ledger_path), isolation_level=None, timeout=1.0)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=1000")
        connection.executescript(
            """
            CREATE TABLE run_metadata (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                policy_hash TEXT NOT NULL,
                run_mode TEXT NOT NULL,
                run_id TEXT NOT NULL UNIQUE,
                groups_json TEXT NOT NULL,
                started_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                last_clock REAL NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count BETWEEN 0 AND 4),
                response_bytes_total INTEGER NOT NULL DEFAULT 0 CHECK (response_bytes_total >= 0),
                halted INTEGER NOT NULL DEFAULT 0 CHECK (halted IN (0, 1))
            );
            CREATE TABLE reservations (
                sequence INTEGER PRIMARY KEY CHECK (sequence BETWEEN 1 AND 4),
                reservation_id TEXT NOT NULL UNIQUE,
                run_id TEXT NOT NULL REFERENCES run_metadata(run_id),
                container_group TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK (status IN (
                    'RESERVED', 'SUCCESS', 'FAILED', 'TIMEOUT',
                    'ABORTED_KILL_SWITCH', 'TRANSPORT_ERROR'
                )),
                reserved_at REAL NOT NULL,
                completed_at REAL,
                response_bytes INTEGER NOT NULL DEFAULT 0 CHECK (response_bytes >= 0),
                http_status_code INTEGER,
                outcome_code TEXT NOT NULL,
                CHECK ((status = 'RESERVED' AND completed_at IS NULL) OR
                       (status != 'RESERVED' AND completed_at IS NOT NULL))
            );
            """
        )
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """INSERT INTO run_metadata (
                singleton, schema_version, policy_hash, run_mode, run_id, groups_json,
                started_at, expires_at, last_clock, request_count,
                response_bytes_total, halted
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)""",
            (
                SCHEMA_VERSION,
                policy_hash_for(run_mode),
                run_mode,
                selected_run_id,
                json.dumps(list(CONTAINER_GROUPS), separators=(",", ":")),
                start,
                start + TOTAL_DEADLINE_SECONDS,
                start,
            ),
        )
        connection.execute("COMMIT")
        connection.close()
    except (sqlite3.Error, OSError) as exc:
        try:
            connection.close()  # type: ignore[possibly-undefined]
        except Exception:
            pass
        raise LedgerUnavailable("ledger initialization failed; existing files were not removed") from exc
    return BrokerLedger(ledger_path, expected_mode=run_mode)


class BrokerLedger:
    """SQLite ledger with atomic pre-attempt reservations and no auto-create."""

    def __init__(self, path: str | os.PathLike[str], *, expected_mode: str | None = None):
        self.path = _ledger_path(path)
        if expected_mode is not None and expected_mode not in _RUN_MODES:
            raise LedgerInitializationError("expected ledger run mode is not approved")
        self.expected_mode = expected_mode
        self.owner_id = uuid.uuid4().hex
        self._validate_existing()

    @classmethod
    def open(cls, path: str | os.PathLike[str], *, expected_mode: str | None = None) -> "BrokerLedger":
        """Open an existing ledger. A missing database is never created implicitly."""
        return cls(path, expected_mode=expected_mode)

    def _uri(self) -> str:
        if not self.path.is_file():
            raise LedgerUnavailable("initialized ledger is missing")
        return f"{self.path.as_uri()}?mode=rw"

    def _connect(self) -> sqlite3.Connection:
        connection = None
        try:
            with self.path.open("rb") as stream:
                file_header = stream.read(16)
            if file_header != b"SQLite format 3\x00":
                raise LedgerCorrupt("ledger file is not a SQLite database")
            connection = sqlite3.connect(
                self._uri(), uri=True, isolation_level=None, timeout=1.0
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=1000")
            if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
                connection.close()
                raise LedgerUnavailable("SQLite FULL synchronous mode is unavailable")
            if connection.execute("PRAGMA journal_mode").fetchone()[0].casefold() != "delete":
                connection.close()
                raise LedgerCorrupt("ledger journal mode differs from the initialized policy")
            return connection
        except LedgerError:
            if connection is not None:
                connection.close()
            raise
        except (sqlite3.Error, OSError) as exc:
            if connection is not None:
                connection.close()
            raise LedgerUnavailable("initialized ledger cannot be opened") from exc

    def _validate_connection(self, connection: sqlite3.Connection) -> sqlite3.Row:
        try:
            table_names = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            if table_names != {"run_metadata", "reservations"}:
                raise LedgerCorrupt("unexpected ledger schema")
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise LedgerCorrupt("ledger integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise LedgerCorrupt("ledger referential integrity check failed")
            metadata_rows = connection.execute("SELECT * FROM run_metadata").fetchall()
            if len(metadata_rows) != 1 or metadata_rows[0]["singleton"] != 1:
                raise LedgerCorrupt("ledger metadata is missing or ambiguous")
            metadata = metadata_rows[0]
            if metadata["schema_version"] != SCHEMA_VERSION:
                raise LedgerCorrupt("unsupported ledger schema version")
            run_mode = metadata["run_mode"]
            if run_mode not in _RUN_MODES:
                raise LedgerPolicyMismatch("ledger run mode is not approved")
            if self.expected_mode is not None and run_mode != self.expected_mode:
                raise LedgerPolicyMismatch("ledger run mode differs from the requested mode")
            if metadata["policy_hash"] != policy_hash_for(run_mode):
                raise LedgerPolicyMismatch("ledger policy does not match the approved scope")
            if metadata["groups_json"] != json.dumps(list(CONTAINER_GROUPS), separators=(",", ":")):
                raise LedgerPolicyMismatch("ledger group order does not match the approved scope")
            started = _finite_timestamp(metadata["started_at"], "started_at")
            expires = _finite_timestamp(metadata["expires_at"], "expires_at")
            last_clock = _finite_timestamp(metadata["last_clock"], "last_clock")
            if expires != started + TOTAL_DEADLINE_SECONDS or last_clock < started:
                raise LedgerCorrupt("ledger time metadata is inconsistent")
            attempts = connection.execute(
                "SELECT * FROM reservations ORDER BY sequence"
            ).fetchall()
            if metadata["request_count"] != len(attempts) or len(attempts) > MAX_REQUESTS_TOTAL:
                raise LedgerCorrupt("ledger request count is inconsistent")
            if metadata["halted"] not in (0, 1):
                raise LedgerCorrupt("ledger stop state is invalid")
            expected_bytes = 0
            successful_response_over_group_cap = False
            for expected_sequence, row in enumerate(attempts, start=1):
                if row["sequence"] != expected_sequence:
                    raise LedgerCorrupt("ledger sequence is not contiguous")
                if row["run_id"] != metadata["run_id"]:
                    raise LedgerCorrupt("reservation belongs to a different run")
                if row["container_group"] != CONTAINER_GROUPS[expected_sequence - 1]:
                    raise LedgerCorrupt("ledger group order is not approved")
                if row["status"] not in _RESERVATION_STATUSES:
                    raise LedgerCorrupt("ledger reservation status is invalid")
                if row["outcome_code"] != row["status"]:
                    raise LedgerCorrupt("ledger outcome code is invalid")
                reserved = _finite_timestamp(row["reserved_at"], "reserved_at")
                if reserved < started or reserved > last_clock:
                    raise LedgerCorrupt("ledger reservation time is inconsistent")
                if row["status"] == "RESERVED":
                    if row["completed_at"] is not None:
                        raise LedgerCorrupt("pending reservation has a completion time")
                else:
                    completed = _finite_timestamp(row["completed_at"], "completed_at")
                    if completed < reserved or completed > last_clock:
                        raise LedgerCorrupt("ledger completion time is inconsistent")
                size = row["response_bytes"]
                if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                    raise LedgerCorrupt("ledger response byte count is invalid")
                if size > MAX_RESPONSE_BYTES_PER_GROUP + 1:
                    raise LedgerCorrupt("ledger response byte count exceeds the recording bound")
                if row["status"] == "SUCCESS" and size > MAX_RESPONSE_BYTES_PER_GROUP:
                    successful_response_over_group_cap = True
                expected_bytes += size
                status_code = row["http_status_code"]
                if status_code is not None and (
                    isinstance(status_code, bool)
                    or not isinstance(status_code, int)
                    or not 100 <= status_code <= 599
                ):
                    raise LedgerCorrupt("ledger status code is invalid")
            if metadata["response_bytes_total"] != expected_bytes:
                raise LedgerCorrupt("ledger aggregate byte count is inconsistent")
            if expected_bytes > MAX_RESPONSE_BYTES_TOTAL:
                last = attempts[-1] if attempts else None
                is_terminal_oversize_failure = (
                    last is not None
                    and last["status"] != "SUCCESS"
                    and last["response_bytes"] == MAX_RESPONSE_BYTES_PER_GROUP + 1
                    and expected_bytes == MAX_RESPONSE_BYTES_TOTAL + 1
                )
                if not is_terminal_oversize_failure:
                    raise LedgerCorrupt("ledger aggregate byte count exceeds the approved cap")
            if successful_response_over_group_cap:
                raise LedgerCorrupt("successful response exceeds the per-group byte cap")
            return metadata
        except LedgerError:
            raise
        except (sqlite3.Error, KeyError, TypeError, ValueError, OverflowError) as exc:
            raise LedgerCorrupt("ledger schema or contents are invalid") from exc

    def _validate_existing(self) -> None:
        connection = self._connect()
        try:
            self._validate_connection(connection)
        finally:
            connection.close()

    def _write_transaction(self):
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_connection(connection)
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _check_clock(metadata: sqlite3.Row, now: float) -> float:
        current = _finite_timestamp(now, "now")
        if current < float(metadata["last_clock"]):
            raise LedgerClockError("clock moved backward; no slot was released")
        if current < float(metadata["started_at"]):
            raise LedgerClockError("clock precedes the persisted run start")
        return current

    def reserve_next(self, container_group: str, *, now: float) -> Reservation:
        if not isinstance(container_group, str) or container_group not in CONTAINER_GROUPS:
            raise LedgerStateError("container group is outside the fixed allowlist")
        try:
            connection = self._write_transaction()
            metadata = connection.execute("SELECT * FROM run_metadata WHERE singleton=1").fetchone()
            current = self._check_clock(metadata, now)
            if metadata["halted"]:
                raise LedgerStateError("run is halted")
            if current >= float(metadata["expires_at"]):
                raise LedgerClockError("run deadline has expired")
            attempts = connection.execute(
                "SELECT * FROM reservations ORDER BY sequence"
            ).fetchall()
            if any(row["status"] == "RESERVED" for row in attempts):
                raise LedgerInFlight("a previous reservation has an uncertain outcome")
            if len(attempts) >= MAX_REQUESTS_TOTAL:
                raise LedgerBudgetExceeded("the fixed request budget is exhausted")
            expected_group = CONTAINER_GROUPS[len(attempts)]
            if container_group != expected_group:
                raise LedgerStateError("only the next fixed group may be reserved")
            sequence = len(attempts) + 1
            reservation_id = uuid.uuid4().hex
            connection.execute(
                """INSERT INTO reservations (
                    sequence, reservation_id, run_id, container_group, status,
                    reserved_at, completed_at, response_bytes, http_status_code,
                    outcome_code
                ) VALUES (?, ?, ?, ?, 'RESERVED', ?, NULL, 0, NULL, 'RESERVED')""",
                (sequence, reservation_id, metadata["run_id"], container_group, current),
            )
            connection.execute(
                "UPDATE run_metadata SET request_count=?, last_clock=? WHERE singleton=1",
                (sequence, current),
            )
            connection.execute("COMMIT")
            return Reservation(
                sequence=sequence,
                reservation_id=reservation_id,
                container_group=container_group,
                reserved_at=current,
                expires_at=float(metadata["expires_at"]),
                owner_id=self.owner_id,
            )
        except LedgerError:
            try:
                connection.execute("ROLLBACK")  # type: ignore[possibly-undefined]
            except Exception:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.execute("ROLLBACK")  # type: ignore[possibly-undefined]
            except Exception:
                pass
            raise LedgerStateError("reservation conflicts with the durable budget") from exc
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")  # type: ignore[possibly-undefined]
            except Exception:
                pass
            raise LedgerUnavailable("reservation transaction failed; no retry is authorized") from exc
        finally:
            try:
                connection.close()  # type: ignore[possibly-undefined]
            except Exception:
                pass

    def observe_clock(self, reservation: Reservation, *, now: float) -> None:
        """Persist an intermediate clock observation before fixture invocation."""
        if type(reservation) is not Reservation or reservation.owner_id != self.owner_id:
            raise LedgerStateError("reservation ownership is invalid")
        connection = None
        try:
            connection = self._write_transaction()
            metadata = connection.execute("SELECT * FROM run_metadata WHERE singleton=1").fetchone()
            current = self._check_clock(metadata, now)
            row = connection.execute(
                "SELECT container_group, status FROM reservations WHERE sequence=? AND reservation_id=?",
                (reservation.sequence, reservation.reservation_id),
            ).fetchone()
            if row is None or row["container_group"] != reservation.container_group or row["status"] != "RESERVED":
                raise LedgerStateError("reservation is absent or already consumed")
            if current < reservation.reserved_at:
                raise LedgerClockError("clock precedes its reservation")
            connection.execute(
                "UPDATE run_metadata SET last_clock=? WHERE singleton=1", (current,)
            )
            connection.execute("COMMIT")
        except LedgerError:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise LedgerUnavailable("clock observation failed; reserved slot remains consumed") from exc
        finally:
            if connection is not None:
                connection.close()

    def record_result(
        self,
        reservation: Reservation,
        *,
        status: str,
        now: float,
        response_bytes: int = 0,
        http_status_code: int | None = None,
    ) -> None:
        if type(reservation) is not Reservation or reservation.owner_id != self.owner_id:
            raise LedgerStateError("reservation ownership is invalid")
        if status not in _TERMINAL_STATUSES:
            raise LedgerStateError("terminal status is invalid")
        if (
            isinstance(response_bytes, bool)
            or not isinstance(response_bytes, int)
            or response_bytes < 0
            or response_bytes > MAX_RESPONSE_BYTES_PER_GROUP + 1
        ):
            raise LedgerStateError("response size is outside the safe recording bound")
        if status == "SUCCESS" and response_bytes > MAX_RESPONSE_BYTES_PER_GROUP:
            raise LedgerStateError("successful response exceeds the per-group byte cap")
        if http_status_code is not None and (
            isinstance(http_status_code, bool)
            or not isinstance(http_status_code, int)
            or not 100 <= http_status_code <= 599
        ):
            raise LedgerStateError("HTTP status is invalid")
        should_halt = status != "SUCCESS"
        connection = None
        try:
            connection = self._write_transaction()
            metadata = connection.execute("SELECT * FROM run_metadata WHERE singleton=1").fetchone()
            current = self._check_clock(metadata, now)
            if status == "SUCCESS" and current >= float(metadata["expires_at"]):
                raise LedgerClockError("successful result arrived after the run deadline")
            row = connection.execute(
                "SELECT * FROM reservations WHERE sequence=? AND reservation_id=?",
                (reservation.sequence, reservation.reservation_id),
            ).fetchone()
            if (
                row is None
                or row["container_group"] != reservation.container_group
                or row["status"] != "RESERVED"
            ):
                raise LedgerStateError("reservation is absent or already consumed")
            if current < float(row["reserved_at"]):
                raise LedgerClockError("completion precedes its reservation")
            previous_total = int(metadata["response_bytes_total"])
            new_total = previous_total + response_bytes
            if status == "SUCCESS" and new_total > MAX_RESPONSE_BYTES_TOTAL:
                raise LedgerStateError("successful responses exceed the aggregate byte cap")
            if new_total > MAX_RESPONSE_BYTES_TOTAL and not (
                status != "SUCCESS"
                and response_bytes == MAX_RESPONSE_BYTES_PER_GROUP + 1
                and new_total == MAX_RESPONSE_BYTES_TOTAL + 1
            ):
                raise LedgerStateError("response bytes exceed the aggregate recording bound")
            connection.execute(
                """UPDATE reservations SET status=?, completed_at=?, response_bytes=?,
                    http_status_code=?, outcome_code=? WHERE sequence=?""",
                (status, current, response_bytes, http_status_code, status, reservation.sequence),
            )
            connection.execute(
                """UPDATE run_metadata SET last_clock=?, response_bytes_total=?,
                    halted=CASE WHEN ? THEN 1 ELSE halted END WHERE singleton=1""",
                (current, new_total, int(should_halt)),
            )
            self._validate_connection(connection)
            connection.execute("COMMIT")
        except LedgerError:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise LedgerUnavailable("result transaction failed; reserved slot remains consumed") from exc
        finally:
            if connection is not None:
                connection.close()

    def halt(self, *, now: float) -> None:
        """Persist a stop without releasing any already reserved slot."""
        connection = None
        try:
            connection = self._write_transaction()
            metadata = connection.execute("SELECT * FROM run_metadata WHERE singleton=1").fetchone()
            current = self._check_clock(metadata, now)
            connection.execute(
                "UPDATE run_metadata SET halted=1, last_clock=? WHERE singleton=1",
                (current,),
            )
            connection.execute("COMMIT")
        except LedgerError:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            raise LedgerUnavailable("stop state could not be persisted") from exc
        finally:
            if connection is not None:
                connection.close()

    def snapshot(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            metadata = self._validate_connection(connection)
            attempts = connection.execute(
                """SELECT sequence, container_group, status, reserved_at, completed_at,
                        response_bytes, http_status_code, outcome_code
                   FROM reservations ORDER BY sequence"""
            ).fetchall()
            rows = [dict(row) for row in attempts]
            pending = any(row["status"] == "RESERVED" for row in rows)
            count = len(rows)
            halted = bool(metadata["halted"])
            next_group = (
                CONTAINER_GROUPS[count]
                if not halted and not pending and count < MAX_REQUESTS_TOTAL
                else None
            )
            return {
                "schema_version": SCHEMA_VERSION,
                "policy_hash": policy_hash_for(metadata["run_mode"]),
                "run_mode": metadata["run_mode"],
                "run_id": metadata["run_id"],
                "started_at": float(metadata["started_at"]),
                "expires_at": float(metadata["expires_at"]),
                "last_clock": float(metadata["last_clock"]),
                "request_count": count,
                "response_bytes_total": int(metadata["response_bytes_total"]),
                "halted": halted,
                "pending_outcome_uncertain": pending,
                "next_group": next_group,
                "reservations": rows,
            }
        except sqlite3.Error as exc:
            raise LedgerUnavailable("ledger snapshot is unavailable") from exc
        finally:
            connection.close()
