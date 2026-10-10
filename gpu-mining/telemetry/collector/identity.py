"""Conservative, provenance-preserving identities for multi-export KRig snapshots."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from .krig_csv import ParsedKrigCsv
from .models import V2_SCHEMA_VERSION


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32]
    return f"{prefix}_{digest}"


def _utc_datetime(event: dict[str, Any]) -> datetime | None:
    value = event.get("occurred_at_utc")
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _utc_key(value: datetime) -> str:
    return value.isoformat(timespec="microseconds" if value.microsecond else "seconds").replace("+00:00", "Z")


def _provider_identity(event: dict[str, Any]) -> tuple[str, str, str, str] | None:
    values = tuple(
        event.get(name) for name in (
            "container_group_name",
            "container_group_version",
            "instance_id",
            "machine_id",
        )
    )
    if not event.get("segment_identity_complete") or any(not isinstance(value, str) or not value or value == "UNKNOWN" for value in values):
        return None
    return values  # type: ignore[return-value]


def _source_reference(event: dict[str, Any]) -> dict[str, Any]:
    reference = event.get("raw_reference")
    return dict(reference) if isinstance(reference, dict) else {}


def _source_event_id(event: dict[str, Any]) -> str:
    reference = _source_reference(event)
    return _stable_id(
        "source-event-v2",
        [reference.get("source_file_sha256"), reference.get("source_row"), event.get("event_type")],
    )


def build_v2_event_snapshot(sources: Iterable[ParsedKrigCsv]) -> dict[str, Any]:
    """Return stable V2 IDs only where provider, run, time and event evidence agree.

    A worker_start with complete provider identity and UTC time anchors a run. Events
    from an export that omits worker_start can join that run only when a unique
    preceding anchor exists for the same allocation. Otherwise they remain
    source-local and cannot be deduplicated across exports.
    """
    unique_sources: dict[str, ParsedKrigCsv] = {}
    for source in sources:
        existing = unique_sources.get(source.source_file_sha256)
        if existing is not None and existing.source_timezone != source.source_timezone:
            raise ValueError("same CSV was parsed under different timezone interpretations")
        if existing is None or (source.source_file_name, source.recorded_at_utc) < (existing.source_file_name, existing.recorded_at_utc):
            unique_sources[source.source_file_sha256] = source
    ordered_sources = [unique_sources[key] for key in sorted(unique_sources)]
    if not ordered_sources:
        raise ValueError("at least one KRig CSV source is required")
    timezone_options = {source.source_timezone for source in ordered_sources}
    if len(timezone_options) != 1:
        raise ValueError("all CSV sources in one V2 batch must use the same source timezone option")

    records: list[dict[str, Any]] = []
    for source in ordered_sources:
        for original in source.events:
            event = dict(original)
            event["payload"] = dict(original.get("payload", {}))
            if event.get("event_type") == "share_accepted":
                event["payload"].setdefault("share_difficulty_value", None)
                event["payload"].setdefault("share_difficulty_unit", None)
                event["payload"].setdefault("share_difficulty_provenance", None)
                event["payload"].setdefault("share_difficulty_context", None)
                event["payload"].setdefault("share_difficulty_verified", False)
                event["payload"].setdefault("share_work_hashes", None)
                event["payload"].setdefault("share_work_unit", None)
                event["payload"].setdefault("share_work_context", None)
                event["payload"].setdefault("share_work_provenance", None)
                event["payload"].setdefault("share_work_verified", False)
            reference = _source_reference(event)
            source_hash = reference.get("source_file_sha256")
            if source_hash != source.source_file_sha256:
                raise ValueError("parsed event provenance does not match its source CSV")
            event["source_event_id"] = _source_event_id(event)
            event["legacy_event_id"] = event.get("event_id")
            event["legacy_run_id"] = event.get("run_id")
            event["legacy_segment_id"] = event.get("segment_id")
            event["source_references"] = [reference]
            event["logical_event_id"] = None
            event["identity_status"] = "unresolved"
            event["schema_version"] = V2_SCHEMA_VERSION
            event["_provider_identity"] = _provider_identity(event)
            event["_event_time"] = _utc_datetime(event)
            event["_source_hash"] = source_hash
            event["_source_run_id"] = event.get("legacy_run_id")
            event["_logical_fingerprint"] = None
            records.append(event)

    # A repeated identical start row in one export is not enough evidence to say
    # whether the exporter duplicated a row or KRig emitted two starts.
    anchor_fingerprints: dict[str, dict[str, Any]] = {}
    source_anchor_counts: Counter[tuple[str, str]] = Counter()
    for event in records:
        identity = event["_provider_identity"]
        when = event["_event_time"]
        if identity is None or when is None or event.get("event_type") != "worker_start":
            continue
        fingerprint_data = [identity, _utc_key(when), event.get("event_type"), event.get("payload")]
        fingerprint = _stable_id("run-anchor-v2", fingerprint_data)
        event["_anchor_fingerprint"] = fingerprint
        source_anchor_counts[(event["_source_hash"], fingerprint)] += 1
        anchor_fingerprints.setdefault(
            fingerprint,
            {"identity": identity, "when": when, "run_id": _stable_id("run-v2", fingerprint_data)},
        )

    ambiguous_anchor_fingerprints = {
        fingerprint
        for (_, fingerprint), count in source_anchor_counts.items()
        if count > 1
    }
    anchors_by_identity: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for fingerprint, anchor in anchor_fingerprints.items():
        if fingerprint not in ambiguous_anchor_fingerprints:
            anchors_by_identity[anchor["identity"]].append({**anchor, "fingerprint": fingerprint})
    for anchors in anchors_by_identity.values():
        anchors.sort(key=lambda item: (item["when"], item["fingerprint"]))

    for event in records:
        identity = event["_provider_identity"]
        when = event["_event_time"]
        anchor_fingerprint = event.get("_anchor_fingerprint")
        run_id: str | None = None
        run_status = "unresolved"
        if identity is not None and when is not None:
            if event.get("event_type") == "worker_start" and anchor_fingerprint not in ambiguous_anchor_fingerprints:
                run_id = anchor_fingerprints[anchor_fingerprint]["run_id"]
                run_status = "verified_start_anchor"
            else:
                prior = [item for item in anchors_by_identity.get(identity, []) if item["when"] <= when]
                if prior:
                    latest_time = prior[-1]["when"]
                    latest = [item for item in prior if item["when"] == latest_time]
                    if len(latest) == 1:
                        run_id = latest[0]["run_id"]
                        run_status = "verified_unique_start_interval"
                    else:
                        run_status = "ambiguous_multiple_starts_at_timestamp"
                else:
                    run_status = "no_verified_preceding_start"
        elif identity is None:
            run_status = "incomplete_provider_identity"
        else:
            run_status = "timestamp_not_trusted_utc"

        if run_id is None:
            run_id = _stable_id(
                "run-v2-source-local",
                [event["_source_hash"], event["_source_run_id"], event["source_event_id"] if identity is None else identity],
            )
        event["run_id"] = run_id
        event["run_identity_status"] = run_status

        if identity is not None:
            event["allocation_id"] = _stable_id("allocation-v2", list(identity))
        else:
            event["allocation_id"] = None
        if identity is not None and run_status.startswith("verified_"):
            event["segment_id"] = _stable_id("segment-v2", [run_id, list(identity)])
        else:
            event["segment_id"] = _stable_id("segment-v2-source-local", [run_id, event["source_event_id"]])

        if identity is not None and when is not None and run_status.startswith("verified_"):
            fingerprint_data = [
                list(identity),
                run_id,
                _utc_key(when),
                event.get("event_type"),
                event.get("payload"),
            ]
            fingerprint = _stable_id("logical-fingerprint-v2", fingerprint_data)
            event["_logical_fingerprint"] = fingerprint
            event["logical_event_id"] = _stable_id("logical-event-v2", fingerprint_data)
            event["identity_status"] = "candidate_verified"
        elif identity is None:
            event["identity_status"] = "incomplete_provider_identity"
        elif when is None:
            event["identity_status"] = "timestamp_not_trusted_utc"
        else:
            event["identity_status"] = run_status

    source_fingerprint_counts: Counter[tuple[str, str]] = Counter(
        (event["_source_hash"], event["_logical_fingerprint"])
        for event in records
        if event["_logical_fingerprint"] is not None
    )
    duplicate_fingerprints = {
        fingerprint
        for (source_hash, fingerprint), count in source_fingerprint_counts.items()
        if count > 1
    }
    logical_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    output: list[dict[str, Any]] = []
    for event in records:
        fingerprint = event["_logical_fingerprint"]
        if fingerprint is None or fingerprint in duplicate_fingerprints:
            event["event_id"] = event["source_event_id"]
            if fingerprint in duplicate_fingerprints:
                event["logical_event_id"] = None
                event["identity_status"] = "ambiguous_repeated_fingerprint_within_source"
            output.append(event)
        else:
            logical_groups[fingerprint].append(event)

    for fingerprint, matches in logical_groups.items():
        matches.sort(
            key=lambda item: (
                item["_source_hash"],
                int(item["source_row"]),
                str(item.get("event_type")),
            )
        )
        representative = matches[0]
        references = {
            json.dumps(reference, ensure_ascii=False, sort_keys=True, separators=(",", ":")): reference
            for item in matches
            for reference in item["source_references"]
        }
        representative["source_references"] = [references[key] for key in sorted(references)]
        representative["raw_reference"] = representative["source_references"][0]
        representative["source_event_ids"] = sorted({item["source_event_id"] for item in matches})
        representative["source_file_count"] = len({item["_source_hash"] for item in matches})
        representative["event_id"] = representative["logical_event_id"]
        representative["identity_status"] = "verified_equivalent"
        output.append(representative)

    output.sort(
        key=lambda event: (
            event.get("run_id", ""),
            event.get("segment_id", ""),
            event.get("occurred_at_utc") is None,
            event.get("occurred_at_utc") or "",
            event.get("event_id", ""),
        )
    )
    for event in output:
        for key in (
            "_provider_identity", "_event_time", "_source_hash", "_source_run_id",
            "_logical_fingerprint", "_anchor_fingerprint",
        ):
            event.pop(key, None)

    source_manifest = [
        {
            "source_file_sha256": source.source_file_sha256,
            "source_file_name": source.source_file_name,
            "source_timezone_option": source.source_timezone,
            "data_rows": source.data_rows,
            "recognized_event_count": len(source.events),
            "empty_log_rows_ignored": source.empty_log_rows_ignored,
            "unrecognized_nonempty_rows": source.unrecognized_nonempty_rows,
        }
        for source in ordered_sources
    ]
    source_bundle_sha256 = hashlib.sha256(
        json.dumps(
            {"source_file_sha256s": [item["source_file_sha256"] for item in source_manifest], "source_timezone": ordered_sources[0].source_timezone},
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    deduplicated_event_count = sum(max(0, len(matches) - 1) for matches in logical_groups.values())
    return {
        "schema_version": V2_SCHEMA_VERSION,
        "events": output,
        "source_manifest": source_manifest,
        "source_bundle_sha256": source_bundle_sha256,
        "source_timezone": ordered_sources[0].source_timezone,
        "recorded_at_utc": max(source.recorded_at_utc for source in ordered_sources),
        "source_event_count": sum(len(source.events) for source in ordered_sources),
        "deduplicated_event_count": deduplicated_event_count,
        "ambiguous_event_count": sum(event.get("identity_status") == "ambiguous_repeated_fingerprint_within_source" for event in output),
        "unresolved_event_count": sum(event.get("identity_status") not in {"verified_equivalent", "ambiguous_repeated_fingerprint_within_source"} for event in output),
    }
