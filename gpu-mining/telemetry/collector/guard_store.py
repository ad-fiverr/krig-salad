"""Local, transactional persistence for offline continuous guard evaluations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = "1"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any, prefix: str) -> str:
    return f"{prefix}_{hashlib.sha256(_json(value).encode('utf-8')).hexdigest()[:32]}"


def canonical_utc(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be an RFC3339 string with an explicit timezone")
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("naive timestamps cannot be used for continuous replay; UTC must not be invented")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds" if parsed.microsecond else "seconds").replace("+00:00", "Z")


def _epoch(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class GuardStore:
    """SQLite ledger; opening it never contacts or mutates a provider."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tracks (
                track_id TEXT PRIMARY KEY,
                family_id TEXT NOT NULL,
                fleet_id TEXT,
                worker_id TEXT,
                allocation_id TEXT,
                assignment_id TEXT,
                run_id TEXT,
                machine_id TEXT,
                instance_id TEXT,
                device_namespace TEXT,
                device_id TEXT,
                gpu_identity_json TEXT NOT NULL,
                started_at_utc TEXT NOT NULL,
                start_anchor_verified INTEGER NOT NULL,
                latest_sample_utc TEXT,
                last_evaluation_utc TEXT,
                last_evaluation_elapsed REAL,
                last_decision TEXT,
                hash_health TEXT NOT NULL DEFAULT 'UNKNOWN',
                deterioration_start_utc TEXT,
                reallocation_count INTEGER,
                reallocation_history_known INTEGER NOT NULL DEFAULT 0,
                last_reallocation_utc TEXT,
                closed_at_utc TEXT,
                terminal_reason TEXT,
                replaced_track_id TEXT,
                provenance_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS tracks_family_active ON tracks(family_id, closed_at_utc);
            CREATE TABLE IF NOT EXISTS observations (
                event_id TEXT PRIMARY KEY,
                track_id TEXT NOT NULL REFERENCES tracks(track_id),
                occurred_at_utc TEXT NOT NULL,
                elapsed_seconds REAL NOT NULL,
                hashrate_ths REAL NOT NULL,
                hashrate_semantics TEXT NOT NULL,
                hashrate_source TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS observations_by_track_time ON observations(track_id, occurred_at_utc);
            CREATE INDEX IF NOT EXISTS observations_by_track_elapsed ON observations(track_id, elapsed_seconds);
            CREATE TABLE IF NOT EXISTS lifecycle_events (
                event_id TEXT PRIMARY KEY,
                allocation_id TEXT,
                assignment_id TEXT,
                machine_id TEXT,
                instance_id TEXT,
                reported_state TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL,
                source TEXT,
                event_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS source_cursors (
                source_id TEXT PRIMARY KEY,
                source_format TEXT NOT NULL,
                generation INTEGER NOT NULL,
                row_count INTEGER NOT NULL,
                prefix_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                track_id TEXT NOT NULL REFERENCES tracks(track_id),
                evaluated_at_utc TEXT NOT NULL,
                elapsed_seconds REAL NOT NULL,
                policy_hash TEXT NOT NULL,
                decision TEXT NOT NULL,
                hash_health TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                audit_id TEXT PRIMARY KEY,
                track_id TEXT,
                event_type TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_by_track_time ON audit_events(track_id, occurred_at_utc);
            """
        )
        existing = self.connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
        if existing is None:
            self.connection.execute("INSERT INTO metadata(key, value) VALUES('schema_version', ?)", (SCHEMA_VERSION,))
            self.connection.commit()
        elif existing["value"] != SCHEMA_VERSION:
            raise ValueError(f"unsupported guard-store schema version: {existing['value']}")

    def close(self) -> None:
        self.connection.close()

    def count_observations(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0])

    @staticmethod
    def _source_prefix_sha256(snapshot: Mapping[str, Any], row_count: int) -> str:
        row_hashes = snapshot.get("row_sha256")
        if not isinstance(row_hashes, list) or len(row_hashes) < row_count:
            raise ValueError("source snapshot must contain hashes for every observed record")
        prefix: list[str] = []
        header_hash = snapshot.get("header_sha256")
        if isinstance(header_hash, str) and header_hash:
            prefix.append(header_hash)
        prefix.extend(row_hashes[:row_count])
        return hashlib.sha256(_json(prefix).encode("utf-8")).hexdigest()

    def begin_source_cursor(self, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        source_id = snapshot.get("source_id")
        source_format = snapshot.get("source_format")
        row_count = snapshot.get("row_count")
        if not isinstance(source_id, str) or not source_id or not isinstance(source_format, str) or not source_format:
            raise ValueError("source cursor requires source_id and source_format")
        if isinstance(row_count, bool) or not isinstance(row_count, int) or row_count < 0:
            raise ValueError("source cursor row_count must be a non-negative integer")
        prefix = self._source_prefix_sha256(snapshot, row_count)
        prior = self.connection.execute("SELECT * FROM source_cursors WHERE source_id=?", (source_id,)).fetchone()
        if prior is None:
            generation, start_row_count, reset_detected = 1, 0, False
        else:
            prior_count = int(prior["row_count"])
            append_only = (
                prior["source_format"] == source_format
                and row_count >= prior_count
                and self._source_prefix_sha256(snapshot, prior_count) == prior["prefix_sha256"]
            )
            reset_detected = not append_only
            generation = int(prior["generation"]) + int(reset_detected)
            start_row_count = prior_count if append_only else 0
        return {
            "source_id": source_id,
            "source_format": source_format,
            "generation": generation,
            "start_row_count": start_row_count,
            "current_row_count": row_count,
            "prefix_sha256": prefix,
            "reset_detected": reset_detected,
        }

    def commit_source_cursor(self, snapshot: Mapping[str, Any], cursor: Mapping[str, Any]) -> None:
        source_id = snapshot.get("source_id")
        source_format = snapshot.get("source_format")
        generation = cursor.get("generation")
        row_count = snapshot.get("row_count")
        if (
            not isinstance(source_id, str) or not source_id
            or not isinstance(source_format, str) or not source_format
            or isinstance(generation, bool) or not isinstance(generation, int) or generation < 1
            or isinstance(row_count, bool) or not isinstance(row_count, int) or row_count < 0
        ):
            raise ValueError("invalid source cursor commit")
        prefix = self._source_prefix_sha256(snapshot, row_count)
        with self.connection:
            self.connection.execute(
                """INSERT INTO source_cursors(source_id, source_format, generation, row_count, prefix_sha256)
                   VALUES(?, ?, ?, ?, ?)
                   ON CONFLICT(source_id) DO UPDATE SET source_format=excluded.source_format,
                     generation=excluded.generation, row_count=excluded.row_count, prefix_sha256=excluded.prefix_sha256""",
                (source_id, source_format, generation, row_count, prefix),
            )

    def source_cursor_rows(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM source_cursors ORDER BY source_id").fetchall()]

    def count_source_cursors(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM source_cursors").fetchone()[0])

    def ingest_lifecycle(self, event: Mapping[str, Any]) -> dict[str, Any]:
        event_id = event.get("event_id")
        state = event.get("reported_state")
        if not isinstance(event_id, str) or not event_id.strip() or not isinstance(state, str) or not state.strip():
            raise ValueError("lifecycle event requires event_id and reported_state")
        timestamp = canonical_utc(event.get("occurred_at_utc"))
        identity = event.get("provider_identity") if isinstance(event.get("provider_identity"), Mapping) else {}
        allocation_id = event.get("allocation_id") or "|".join(
            str(event.get(key) or "") for key in ("container_group_name", "container_group_version")
        ).strip("|") or None
        assignment_id = event.get("assignment_id") or allocation_id
        machine_id = event.get("machine_id") or identity.get("Resource labels machine id")
        instance_id = event.get("instance_id") or identity.get("Resource labels instance id")
        source = event.get("event_source") or event.get("source")
        termination_applied = False
        unscoped_terminal = False
        with self.connection:
            before = self.connection.total_changes
            self.connection.execute(
                """INSERT OR IGNORE INTO lifecycle_events
                   (event_id, allocation_id, assignment_id, machine_id, instance_id,
                    reported_state, occurred_at_utc, source, event_json)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event_id, allocation_id, assignment_id, machine_id, instance_id, state.strip().casefold(), timestamp, source, _json(dict(event))),
            )
            inserted = self.connection.total_changes > before
            state_key = state.strip().casefold()
            if inserted and state_key in {"stopped", "preempted", "lost", "terminated", "reallocated", "allocation_terminated"}:
                if not machine_id and not instance_id:
                    # An allocation label can refer to multiple concurrent
                    # machine assignments. Preserve the observation, but never
                    # let an unscoped provider event close unrelated GPU tracks.
                    unscoped_terminal = True
                    self.append_audit(
                        None, "UNSCOPED_TERMINAL_LIFECYCLE", timestamp,
                        {"event_id": event_id, "allocation_id": allocation_id, "reported_state": state_key, "source": source, "provenance": dict(event), "tracks_closed": 0, "reason": "missing_machine_and_instance_identity"},
                        dedupe_key=f"unscoped-terminal:{event_id}",
                    )
                else:
                    conditions = ["closed_at_utc IS NULL"]
                    args: list[Any] = []
                    for column, value in (("allocation_id", allocation_id), ("machine_id", machine_id), ("instance_id", instance_id)):
                        if value:
                            conditions.append(f"{column} = ?")
                            args.append(value)
                    tracks = self.connection.execute(
                        "SELECT * FROM tracks WHERE " + " AND ".join(conditions), args
                    ).fetchall()
                    assignment_keys = {
                        (track["allocation_id"], track["assignment_id"], track["machine_id"], track["instance_id"])
                        for track in tracks
                    }
                    if len(assignment_keys) > 1:
                        unscoped_terminal = True
                        self.append_audit(
                            None, "UNSCOPED_TERMINAL_LIFECYCLE", timestamp,
                            {
                                "event_id": event_id, "allocation_id": allocation_id,
                                "machine_id": machine_id, "instance_id": instance_id,
                                "reported_state": state_key, "source": source,
                                "provenance": dict(event), "tracks_closed": 0,
                                "reason": "partial_identity_matches_multiple_assignments",
                                "candidate_assignments": [
                                    {"allocation_id": key[0], "assignment_id": key[1], "machine_id": key[2], "instance_id": key[3]}
                                    for key in sorted(assignment_keys, key=lambda value: tuple(str(part or "") for part in value))
                                ],
                            },
                            dedupe_key=f"unscoped-terminal:{event_id}",
                        )
                    elif len(assignment_keys) == 1:
                        for track in tracks:
                            self._close_track(track["track_id"], timestamp, f"provider_lifecycle:{state_key}")
                            self.append_audit(
                                track["track_id"], "ALLOCATION_TERMINATED", timestamp,
                                {"reported_state": state_key, "source": source, "provenance": dict(event)},
                                dedupe_key=f"terminated:{track['track_id']}:{timestamp}:{state_key}",
                            )
                        termination_applied = bool(tracks)
        return {
            "inserted": inserted,
            "event_id": event_id,
            "state": state_key,
            "termination_applied": termination_applied,
            "unscoped_terminal": unscoped_terminal,
        }

    def invalidate_assignment_gpu_identity(self, event: Mapping[str, Any]) -> int:
        """Remove a per-device floor identity when one provider GPU maps to multiple devices."""
        event_id = event.get("event_id")
        timestamp = canonical_utc(event.get("occurred_at_utc"))
        required = ("allocation_id", "assignment_id", "machine_id", "instance_id", "monitor_source_id")
        if not isinstance(event_id, str) or not event_id.strip() or any(not isinstance(event.get(key), str) or not event[key].strip() for key in required):
            raise ValueError("GPU mapping ambiguity requires event id, source lineage, and complete assignment identity")
        raw_keys = event.get("device_keys")
        if not isinstance(raw_keys, list) or len(raw_keys) < 2:
            raise ValueError("GPU mapping ambiguity requires at least two observed device keys")
        device_keys = sorted({str(value) for value in raw_keys})
        if len(device_keys) < 2:
            raise ValueError("GPU mapping ambiguity requires distinct device keys")
        dedupe_key = "gpu-device-mapping-ambiguous:" + _digest(
            [event.get(key) for key in required] + [event.get("monitor_source_generation"), device_keys],
            "ambiguity",
        )
        if self.has_audit(dedupe_key):
            return 0
        changed = 0
        with self.connection:
            tracks = self.connection.execute(
                """SELECT * FROM tracks WHERE closed_at_utc IS NULL AND fleet_id IS ? AND worker_id IS ?
                   AND allocation_id=? AND assignment_id=? AND machine_id=? AND instance_id=?""",
                tuple(event.get(key) for key in ("fleet_id", "worker_id", "allocation_id", "assignment_id", "machine_id", "instance_id")),
            ).fetchall()
            affected_ids: list[str] = []
            for track in tracks:
                provenance = json.loads(track["provenance_json"])
                if provenance.get("monitor_source_id") not in {None, event.get("monitor_source_id")}:
                    continue
                identity = json.loads(track["gpu_identity_json"])
                identity.update({
                    "identity_verified": False,
                    "identity_status": "provider_assignment_identity_not_mapped_to_single_device",
                    "identity_scope": "provider_assignment",
                    "ambiguous_device_keys": device_keys,
                })
                self.connection.execute(
                    "UPDATE tracks SET gpu_identity_json=?, hash_health='UNKNOWN', last_decision='INSUFFICIENT_DATA' WHERE track_id=?",
                    (_json(identity), track["track_id"]),
                )
                affected_ids.append(track["track_id"])
                changed += 1
            self.append_audit(
                affected_ids[0] if len(affected_ids) == 1 else None,
                "GPU_DEVICE_MAPPING_AMBIGUOUS", timestamp,
                {
                    "event_id": event_id,
                    "fleet_id": event.get("fleet_id"),
                    "worker_id": event.get("worker_id"),
                    "allocation_id": event.get("allocation_id"),
                    "assignment_id": event.get("assignment_id"),
                    "machine_id": event.get("machine_id"),
                    "instance_id": event.get("instance_id"),
                    "device_keys": device_keys,
                    "invalidated_track_ids": sorted(affected_ids),
                    "tracks_invalidated": changed,
                    "actions_performed": False,
                    "provenance": event.get("provenance"),
                },
                dedupe_key=dedupe_key,
            )
        return changed

    def _close_track(self, track_id: str, timestamp: str, reason: str) -> None:
        self.connection.execute(
            "UPDATE tracks SET closed_at_utc=?, terminal_reason=? WHERE track_id=? AND closed_at_utc IS NULL",
            (timestamp, reason, track_id),
        )

    def ingest_observation(self, event: Mapping[str, Any]) -> dict[str, Any]:
        event_id = event.get("event_id") or event.get("observation_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("hash observation requires a stable event_id")
        timestamp = canonical_utc(event.get("occurred_at_utc") or event.get("observed_at_utc"))
        rate = event.get("hashrate_ths")
        if isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate < 0:
            raise ValueError("hash observation requires a non-negative device hashrate_ths")
        semantics = event.get("hashrate_semantics")
        source = event.get("hashrate_source")
        if not isinstance(semantics, str) or not semantics.strip() or semantics == "fl4shminer_cuda_autotune_pool_equivalent_estimate":
            raise ValueError("only explicitly labeled local device hashrate observations are eligible for physical floors")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("hash observation requires hashrate_source provenance")

        fields = {
            "fleet_id": event.get("fleet_id"),
            "worker_id": event.get("worker_id"),
            "allocation_id": event.get("allocation_id"),
            "assignment_id": event.get("assignment_id"),
            "run_id": event.get("run_id"),
            "machine_id": event.get("machine_id"),
            "instance_id": event.get("instance_id"),
            "device_namespace": event.get("device_namespace"),
            "device_id": str(event.get("device_id")) if event.get("device_id") is not None else None,
        }
        required_identity = ("allocation_id", "assignment_id", "run_id", "machine_id", "instance_id", "device_namespace", "device_id")
        identity_complete = all(isinstance(fields.get(name), str) and fields[name].strip() for name in required_identity)
        identity = event.get("gpu_identity") if isinstance(event.get("gpu_identity"), Mapping) else {}
        started = event.get("assignment_started_at_utc") or event.get("run_started_at_utc")
        start_verified = isinstance(started, str) and bool(started.strip()) and event.get("start_anchor_verified") is True
        if not start_verified and fields.get("allocation_id"):
            lifecycle = self.connection.execute(
                """SELECT occurred_at_utc FROM lifecycle_events
                   WHERE allocation_id=? AND (? IS NULL OR assignment_id=? )
                     AND (? IS NULL OR machine_id=?) AND (? IS NULL OR instance_id=?)
                     AND reported_state IN ('allocated','allocating','downloading','creating','starting','running','ready')
                   ORDER BY julianday(occurred_at_utc) LIMIT 1""",
                (
                    fields["allocation_id"], fields["assignment_id"], fields["assignment_id"],
                    fields["machine_id"], fields["machine_id"], fields["instance_id"], fields["instance_id"],
                ),
            ).fetchone()
            if lifecycle is not None:
                started = lifecycle["occurred_at_utc"]
                start_verified = True
        started_at = canonical_utc(started) if start_verified else timestamp
        provenance = event.get("provenance") if isinstance(event.get("provenance"), Mapping) else {}
        family_id = _digest(
            [fields.get("fleet_id"), fields.get("worker_id"), fields.get("allocation_id"), fields.get("assignment_id"), fields.get("device_namespace"), fields.get("device_id")],
            "family",
        )
        monitor_source_id = event.get("monitor_source_id") or provenance.get("monitor_source_id")
        monitor_generation = event.get("monitor_source_generation") or provenance.get("monitor_source_generation")
        if isinstance(monitor_source_id, str) and monitor_source_id and isinstance(monitor_generation, int) and not isinstance(monitor_generation, bool):
            # A monitor cursor provides stable source lineage across appends
            # and a new generation after source reset. It replaces a possibly
            # unverified first-sample timestamp as the track boundary.
            track_key = [fields, fields.get("run_id"), "monitor-source", monitor_source_id, monitor_generation, event_id if not identity_complete else None]
        else:
            # Keep pre-cursor and direct-import track identity backward
            # compatible; no source lineage is inferred for those events.
            track_key = [fields, fields.get("run_id"), started_at, event_id if not identity_complete else None]
        track_id = _digest(track_key, "track")
        reallocation_known = event.get("reallocation_history_known") is True
        reallocations = event.get("reallocation_count") if reallocation_known else None
        if reallocations is not None and (isinstance(reallocations, bool) or not isinstance(reallocations, int) or reallocations < 0):
            raise ValueError("reallocation_count must be a non-negative integer when history is verified")
        elapsed = max(0.0, _epoch(timestamp) - _epoch(started_at))

        with self.connection:
            if self.connection.execute("SELECT 1 FROM observations WHERE event_id=?", (event_id,)).fetchone():
                existing = self.connection.execute("SELECT track_id FROM observations WHERE event_id=?", (event_id,)).fetchone()
                return {"inserted": False, "event_id": event_id, "track_id": existing["track_id"]}

            existing_track = self.connection.execute("SELECT * FROM tracks WHERE track_id=?", (track_id,)).fetchone()
            if existing_track is not None:
                previous_identity = json.loads(existing_track["gpu_identity_json"])
                identity_signature = lambda value: tuple(value.get(name) for name in ("raw_model", "model", "form_factor", "identity_source", "identity_verified"))
                if identity_signature(previous_identity) != identity_signature(identity):
                    conflicted_identity = {
                        "raw_model": identity.get("raw_model") or previous_identity.get("raw_model"),
                        "model": None,
                        "form_factor": "unknown",
                        "identity_source": None,
                        "identity_verified": False,
                        "identity_status": "conflicting_identity_observations",
                        "conflicting_claims": [previous_identity, dict(identity)],
                    }
                    self.connection.execute("UPDATE tracks SET gpu_identity_json=? WHERE track_id=?", (_json(conflicted_identity), track_id))
                    self.append_audit(
                        track_id, "GPU_IDENTITY_CONFLICT", timestamp,
                        {"previous_claim": previous_identity, "new_claim": dict(identity), "source_event_id": event_id, "actions_performed": False},
                        dedupe_key=f"identity-conflict:{track_id}:{event_id}",
                    )
            replaced_track_id = None
            continuity_ambiguous = False
            active_family = self.connection.execute(
                "SELECT * FROM tracks WHERE family_id=? AND closed_at_utc IS NULL ORDER BY started_at_utc",
                (family_id,),
            ).fetchall()
            to_close: dict[str, tuple[sqlite3.Row, str]] = {}
            for prior in active_family:
                if prior["track_id"] != track_id and (
                    prior["assignment_id"] != fields["assignment_id"]
                    or prior["allocation_id"] != fields["allocation_id"]
                    or prior["machine_id"] != fields["machine_id"]
                    or prior["instance_id"] != fields["instance_id"]
                    or prior["run_id"] != fields["run_id"]
                ):
                    to_close[prior["track_id"]] = (prior, "assignment_identity_changed")

            # This continuity key intentionally excludes assignment/run
            # generations, but requires an exact fleet, worker, machine,
            # instance, and device namespace/id. It can therefore recognize a
            # changed assignment on the same concrete machine without merging
            # two incomplete identities or GPUs on different machines.
            if fields["machine_id"] and fields["instance_id"]:
                continuity_rows = self.connection.execute(
                    """SELECT * FROM tracks WHERE closed_at_utc IS NULL
                       AND fleet_id IS ? AND worker_id IS ? AND machine_id=? AND instance_id=?
                       AND device_namespace=? AND device_id=? ORDER BY started_at_utc""",
                    (fields["fleet_id"], fields["worker_id"], fields["machine_id"], fields["instance_id"], fields["device_namespace"], fields["device_id"]),
                ).fetchall()
                continuity_candidates = [
                    prior for prior in continuity_rows
                    if prior["track_id"] != track_id
                    and (prior["assignment_id"] != fields["assignment_id"] or prior["allocation_id"] != fields["allocation_id"] or prior["run_id"] != fields["run_id"])
                ]
                if len(continuity_candidates) == 1:
                    prior = continuity_candidates[0]
                    to_close.setdefault(prior["track_id"], (prior, "assignment_generation_changed_on_same_machine"))
                elif len(continuity_candidates) > 1 and not to_close:
                    continuity_ambiguous = True
                    self.append_audit(
                        None, "AMBIGUOUS_ASSIGNMENT_CONTINUITY", timestamp,
                        {"source_event_id": event_id, "machine_id": fields["machine_id"], "instance_id": fields["instance_id"], "device_namespace": fields["device_namespace"], "device_id": fields["device_id"], "candidate_track_ids": sorted(row["track_id"] for row in continuity_candidates), "tracks_closed": 0},
                        dedupe_key=f"ambiguous-continuity:{event_id}",
                    )

            for prior_id, (prior, reason) in to_close.items():
                self._close_track(prior_id, timestamp, reason)
                replaced_track_id = prior_id
                self.append_audit(
                    prior_id, "ALLOCATION_TERMINATED", timestamp,
                    {"reason": reason, "new_machine_id": fields["machine_id"], "new_instance_id": fields["instance_id"], "new_assignment_id": fields["assignment_id"], "source_event_id": event_id},
                    dedupe_key=f"identity-change:{prior_id}:{track_id}",
                )

            if existing_track is None:
                self.connection.execute(
                    """INSERT INTO tracks (
                        track_id, family_id, fleet_id, worker_id, allocation_id, assignment_id,
                        run_id, machine_id, instance_id, device_namespace, device_id, gpu_identity_json,
                        started_at_utc, start_anchor_verified, reallocation_count, reallocation_history_known,
                        replaced_track_id, provenance_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        track_id, family_id, fields["fleet_id"], fields["worker_id"], fields["allocation_id"],
                        fields["assignment_id"], fields["run_id"], fields["machine_id"], fields["instance_id"],
                        fields["device_namespace"], fields["device_id"], _json(dict(identity)), started_at,
                        int(start_verified), reallocations, int(reallocation_known), replaced_track_id, _json(dict(provenance)),
                    ),
                )
            self.connection.execute(
                """INSERT INTO observations
                   (event_id, track_id, occurred_at_utc, elapsed_seconds, hashrate_ths,
                    hashrate_semantics, hashrate_source, provenance_json, event_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (event_id, track_id, timestamp, elapsed, float(rate), semantics.strip(), source.strip(), _json(dict(provenance)), _json(dict(event))),
            )
            self.connection.execute(
                """UPDATE tracks SET latest_sample_utc = CASE
                     WHEN latest_sample_utc IS NULL OR julianday(latest_sample_utc) < julianday(?) THEN ? ELSE latest_sample_utc END
                   WHERE track_id=?""",
                (timestamp, timestamp, track_id),
            )
        return {"inserted": True, "event_id": event_id, "track_id": track_id, "identity_complete": identity_complete, "replaced_track_id": replaced_track_id, "continuity_ambiguous": continuity_ambiguous}

    def add_evaluation(self, track_id: str, evaluated_at_utc: str, elapsed_seconds: float, policy_hash: str, result: Mapping[str, Any]) -> bool:
        timestamp = canonical_utc(evaluated_at_utc)
        evaluation_id = _digest([track_id, timestamp, policy_hash], "evaluation")
        details = result.get("details", {}) if isinstance(result, Mapping) else {}
        decision = result.get("decision", "INSUFFICIENT_DATA") if isinstance(result, Mapping) else "INSUFFICIENT_DATA"
        health = details.get("hash_health", "UNKNOWN") if isinstance(details, Mapping) else "UNKNOWN"
        with self.connection:
            cursor = self.connection.execute(
                """INSERT OR IGNORE INTO evaluations
                   (evaluation_id, track_id, evaluated_at_utc, elapsed_seconds, policy_hash, decision, hash_health, result_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (evaluation_id, track_id, timestamp, float(elapsed_seconds), policy_hash, decision, health, _json(dict(result))),
            )
            if cursor.rowcount:
                self.connection.execute(
                    """UPDATE tracks SET last_evaluation_utc=?, last_evaluation_elapsed=?, last_decision=?,
                       hash_health=? WHERE track_id=?""",
                    (timestamp, float(elapsed_seconds), decision, health, track_id),
                )
                return True
        return False

    def append_audit(self, track_id: str | None, event_type: str, occurred_at_utc: str, payload: Mapping[str, Any], *, dedupe_key: str) -> bool:
        timestamp = canonical_utc(occurred_at_utc)
        audit_id = _digest([track_id, event_type, dedupe_key], "audit")
        with self.connection:
            cursor = self.connection.execute(
                "INSERT OR IGNORE INTO audit_events(audit_id, track_id, event_type, occurred_at_utc, dedupe_key, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                (audit_id, track_id, event_type, timestamp, dedupe_key, _json(dict(payload))),
            )
        return cursor.rowcount > 0

    def confirm_reallocation(self, track_id: str, occurred_at_utc: str, event: Mapping[str, Any]) -> dict[str, Any]:
        timestamp = canonical_utc(occurred_at_utc)
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("reallocation confirmation requires a stable event_id")
        dedupe_key = f"reallocation-confirmed:{event_id}"
        row = self.connection.execute("SELECT * FROM tracks WHERE track_id=?", (track_id,)).fetchone()
        if row is None:
            raise ValueError("reallocation confirmation references an unknown track")
        previous_confirmation = self.connection.execute("SELECT track_id FROM audit_events WHERE dedupe_key=?", (dedupe_key,)).fetchone()
        if previous_confirmation is not None:
            if previous_confirmation["track_id"] != track_id:
                raise ValueError("reallocation event_id was already attributed to a different track")
            return {"track_id": track_id, "reallocation_count": row["reallocation_count"], "reallocation_history_known": bool(row["reallocation_history_known"]), "duplicate": True}
        supplied_count = event.get("reallocation_count")
        known = event.get("reallocation_history_known") is True and isinstance(supplied_count, int) and not isinstance(supplied_count, bool) and supplied_count >= 0
        current = row["reallocation_count"]
        if known:
            count = supplied_count
        elif row["reallocation_history_known"] and current is not None:
            count = current + 1
            known = True
        else:
            count = None
        with self.connection:
            self.connection.execute(
                "UPDATE tracks SET reallocation_count=?, reallocation_history_known=?, last_reallocation_utc=? WHERE track_id=?",
                (count, int(known), timestamp, track_id),
            )
            self.append_audit(
                track_id, "REALLOCATION_CONFIRMED", timestamp,
                {"evidence": dict(event), "reallocation_count": count, "reallocation_history_known": known, "action_performed_by_monitor": False},
                dedupe_key=dedupe_key,
            )
        return {"track_id": track_id, "reallocation_count": count, "reallocation_history_known": known}

    def track_rows(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM tracks" + (" WHERE closed_at_utc IS NULL" if active_only else "") + " ORDER BY started_at_utc, track_id"
        rows = self.connection.execute(sql).fetchall()
        return [dict(row) for row in rows]

    def get_track(self, track_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM tracks WHERE track_id=?", (track_id,)).fetchone()
        return None if row is None else dict(row)

    def samples_for_track(self, track_id: str, *, since_elapsed_seconds: float | None = None) -> list[dict[str, Any]]:
        if since_elapsed_seconds is None:
            rows = self.connection.execute(
                "SELECT * FROM observations WHERE track_id=? ORDER BY julianday(occurred_at_utc), event_id", (track_id,)
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM observations WHERE track_id=? AND elapsed_seconds>=? ORDER BY julianday(occurred_at_utc), event_id",
                (track_id, float(since_elapsed_seconds)),
            ).fetchall()
        return [
            {
                "elapsed_seconds": row["elapsed_seconds"],
                "hashrate_ths": row["hashrate_ths"],
                "hashrate_semantics": row["hashrate_semantics"],
                "hashrate_source": row["hashrate_source"],
                "occurred_at_utc": row["occurred_at_utc"],
                "provenance": json.loads(row["provenance_json"]),
            }
            for row in rows
        ]

    def last_evaluation(self, track_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM evaluations WHERE track_id=? ORDER BY evaluated_at_utc DESC LIMIT 1", (track_id,)
        ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["result"] = json.loads(value.pop("result_json"))
        return value

    def evaluations_for_track(self, track_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM evaluations WHERE track_id=? ORDER BY julianday(evaluated_at_utc), evaluation_id", (track_id,)).fetchall()
        return [{**dict(row), "result": json.loads(row["result_json"])} for row in rows]

    def audit_rows(self, *, track_id: str | None = None) -> list[dict[str, Any]]:
        if track_id is None:
            rows = self.connection.execute("SELECT * FROM audit_events ORDER BY julianday(occurred_at_utc), audit_id").fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM audit_events WHERE track_id=? ORDER BY julianday(occurred_at_utc), audit_id", (track_id,)).fetchall()
        return [{**dict(row), "payload": json.loads(row["payload_json"])} for row in rows]

    def has_audit(self, dedupe_key: str) -> bool:
        return self.connection.execute("SELECT 1 FROM audit_events WHERE dedupe_key=?", (dedupe_key,)).fetchone() is not None

    def lifecycle_events(self, allocation_id: str, machine_id: str | None, instance_id: str | None) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM lifecycle_events WHERE allocation_id=? AND (? IS NULL OR machine_id=?) AND (? IS NULL OR instance_id=?) ORDER BY julianday(occurred_at_utc)",
            (allocation_id, machine_id, machine_id, instance_id, instance_id),
        ).fetchall()
        return [json.loads(row["event_json"]) for row in rows]

    def latest_sample_timestamp(self) -> str | None:
        row = self.connection.execute("SELECT occurred_at_utc AS latest FROM observations ORDER BY julianday(occurred_at_utc) DESC LIMIT 1").fetchone()
        return row["latest"] if row else None

    def update_track_deterioration(self, track_id: str, started_at_utc: str | None) -> None:
        with self.connection:
            self.connection.execute("UPDATE tracks SET deterioration_start_utc=? WHERE track_id=?", (started_at_utc, track_id))

    def terminate_track(self, track_id: str, timestamp: str, reason: str) -> None:
        timestamp = canonical_utc(timestamp)
        with self.connection:
            self._close_track(track_id, timestamp, reason)
