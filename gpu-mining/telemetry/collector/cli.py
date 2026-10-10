"""Offline entry point for KRig CSV import and dry-run guard evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    # Support the documented direct-file invocation as well as python -m collector.cli.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from collector.aggregate import write_import_outputs
    from collector.batch import write_v2_batch
    from collector.fl4shminer import import_fl4shminer_csv, write_fl4shminer_outputs
    from collector.fleet import build_fleet_rankings, evaluate_economic_profit, summarize_fleet
    from collector.continuous import ContinuousMonitor, fleet_monitor_status
    from collector.device_guard import inspect_monitor_source, load_monitor_events
    from collector.guard_store import GuardStore
    from collector.guards import GuardResult, HashGuardPolicy, evaluate_economics, evaluate_hash_floor, evaluate_provider_state_mismatch
    from collector.krig_csv import import_krig_csv
    from collector.reconcile import reconcile_money
    from collector.revenue import estimate_revenue
    from collector.salad_lifecycle import import_salad_lifecycle_csv, write_salad_lifecycle_outputs
    from collector.yield_fixtures import load_revenue_fixture
    from collector.gpu_identity import SUPPORTED_EXACT_MODELS, VERIFIED_GPU_IDENTITY_SOURCES
else:
    from .aggregate import write_import_outputs
    from .batch import write_v2_batch
    from .fl4shminer import import_fl4shminer_csv, write_fl4shminer_outputs
    from .fleet import build_fleet_rankings, evaluate_economic_profit, summarize_fleet
    from .continuous import ContinuousMonitor, fleet_monitor_status
    from .device_guard import inspect_monitor_source, load_monitor_events
    from .guard_store import GuardStore
    from .guards import GuardResult, HashGuardPolicy, evaluate_economics, evaluate_hash_floor, evaluate_provider_state_mismatch
    from .krig_csv import import_krig_csv
    from .reconcile import reconcile_money
    from .revenue import estimate_revenue
    from .salad_lifecycle import import_salad_lifecycle_csv, write_salad_lifecycle_outputs
    from .yield_fixtures import load_revenue_fixture
    from .gpu_identity import SUPPORTED_EXACT_MODELS, VERIFIED_GPU_IDENTITY_SOURCES


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def _monitor_policy(config_path: Path) -> HashGuardPolicy:
    config = _load_json(config_path)
    if config.get("schema_version") != "2.0":
        raise ValueError("guard config must use schema_version 2.0")
    hash_cfg = config.get("hash_guard")
    if not isinstance(hash_cfg, dict) or not isinstance(hash_cfg.get("gpu_floors_ths", {}), dict):
        raise ValueError("hash_guard.gpu_floors_ths must be an object")
    for key, value in hash_cfg.get("gpu_floors_ths", {}).items():
        parts = key.split("|") if isinstance(key, str) else []
        if (
            len(parts) != 3
            or parts[0] not in SUPPORTED_EXACT_MODELS
            or parts[1] not in {"desktop", "laptop"}
            or parts[2] not in VERIFIED_GPU_IDENTITY_SOURCES - {"synthetic_test_fixture"}
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise ValueError("GPU floors must use exact verified production keys and positive TH/s values")
    return HashGuardPolicy(
        gpu_floors_ths=hash_cfg.get("gpu_floors_ths", {}),
        warmup_seconds=hash_cfg.get("warmup_seconds"),
        hash_window_seconds=hash_cfg.get("hash_window_seconds"),
        minimum_samples_per_window=hash_cfg.get("minimum_samples_per_window"),
        expected_sample_interval_seconds=hash_cfg.get("expected_sample_interval_seconds"),
        maximum_sample_gap_seconds=hash_cfg.get("maximum_sample_gap_seconds"),
        minimum_window_coverage_ratio=hash_cfg.get("minimum_window_coverage_ratio"),
        consecutive_bad_windows=hash_cfg.get("consecutive_bad_windows"),
        reallocation_cooldown_seconds=hash_cfg.get("reallocation_cooldown_seconds"),
        max_reallocations_per_run=hash_cfg.get("max_reallocations_per_run"),
        reevaluation_interval_seconds=hash_cfg.get("reevaluation_interval_seconds"),
    )


def _monitor_events(args: argparse.Namespace, store: GuardStore) -> tuple[list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any]]]]:
    events: list[dict[str, Any]] = []
    pending: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for path in args.input:
        snapshot = inspect_monitor_source(path, args.format)
        cursor = store.begin_source_cursor(snapshot)
        events.extend(load_monitor_events(
            [path],
            input_format=snapshot["source_format"],
            fleet_id=args.fleet_id,
            worker_id=args.worker_id,
            source_contexts={snapshot["source_path_key"]: cursor},
        ))
        pending.append((snapshot, cursor))
    return events, pending


def _commit_monitor_source_cursors(store: GuardStore, pending: list[tuple[dict[str, Any], dict[str, Any]]]) -> list[dict[str, Any]]:
    updates = []
    for snapshot, cursor in pending:
        store.commit_source_cursor(snapshot, cursor)
        updates.append({
            "source_id": cursor["source_id"],
            "source_format": cursor["source_format"],
            "generation": cursor["generation"],
            "previous_row_count": cursor["start_row_count"],
            "current_row_count": cursor["current_row_count"],
            "appended_row_count": max(0, cursor["current_row_count"] - cursor["start_row_count"]),
            "reset_detected": cursor["reset_detected"],
        })
    return updates


def _parse_clock(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _guard_results(report_path: Path, config_path: Path) -> dict[str, Any]:
    report = _load_json(report_path)
    config = _load_json(config_path)
    report_schema = report.get("schema_version", "1.0")
    if report_schema not in {"1.0", "2.0"}:
        raise ValueError(f"evaluate-guards supports report schema 1.0 or 2.0, not {report_schema!r}")
    report_segments = report.get("segments")
    if not isinstance(report_segments, list):
        raise ValueError("guard report must contain a segments array")
    if config.get("schema_version") != "2.0":
        raise ValueError("guard config must use schema_version 2.0; migrate legacy economics explicitly")
    events_path = report_path.parent / "events.jsonl"
    if not events_path.exists():
        raise FileNotFoundError(f"The sibling event ledger is required: {events_path}")

    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(events_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {events_path.name} line {line_number}") from exc

    hash_cfg = config.get("hash_guard", {})
    if not isinstance(hash_cfg, dict):
        raise ValueError("hash_guard must be an object")
    policy = HashGuardPolicy(
        gpu_floors_ths=hash_cfg.get("gpu_floors_ths", {}),
        warmup_seconds=hash_cfg.get("warmup_seconds"),
        hash_window_seconds=hash_cfg.get("hash_window_seconds"),
        minimum_samples_per_window=hash_cfg.get("minimum_samples_per_window"),
        expected_sample_interval_seconds=hash_cfg.get("expected_sample_interval_seconds"),
        maximum_sample_gap_seconds=hash_cfg.get("maximum_sample_gap_seconds"),
        minimum_window_coverage_ratio=hash_cfg.get("minimum_window_coverage_ratio"),
        consecutive_bad_windows=hash_cfg.get("consecutive_bad_windows"),
        reallocation_cooldown_seconds=hash_cfg.get("reallocation_cooldown_seconds"),
        max_reallocations_per_run=hash_cfg.get("max_reallocations_per_run"),
    )
    if not isinstance(policy.gpu_floors_ths, dict):
        raise ValueError("hash_guard.gpu_floors_ths must be an object")
    for key, value in policy.gpu_floors_ths.items():
        parts = key.split("|") if isinstance(key, str) else []
        if (
            len(parts) != 3
            or parts[0] not in SUPPORTED_EXACT_MODELS
            or parts[1] not in {"desktop", "laptop"}
            or parts[2] not in VERIFIED_GPU_IDENTITY_SOURCES - {"synthetic_test_fixture"}
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or float(value) <= 0
        ):
            raise ValueError(
                "GPU floors must use exact keys MODEL|desktop-or-laptop|verified-source with a positive TH/s value"
            )

    event_groups: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        event_groups.setdefault(event.get("segment_id", ""), []).append(event)

    per_segment: list[dict[str, Any]] = []
    for segment in report_segments:
        if not isinstance(segment, dict):
            raise ValueError("each guard report segment must be an object")
        segment_events = event_groups.get(segment.get("segment_id"), [])
        starts = [event for event in segment_events if event.get("event_type") == "worker_start"]
        start_clocks = [
            clock
            for event in starts
            if (clock := _parse_clock(event.get("occurred_at_source_clock"))) is not None
        ]
        start_clock = min(start_clocks) if start_clocks else None
        device_events: dict[tuple[str, str] | None, list[dict[str, Any]]] = defaultdict(list)
        for event in segment_events:
            if event.get("event_type") != "gpu_sample":
                continue
            payload = event.get("payload", {})
            namespace = payload.get("device_namespace")
            device_id = payload.get("device_id")
            if not isinstance(namespace, str) or not namespace.strip():
                if isinstance(payload.get("gpu_index"), (str, int)) and not isinstance(payload.get("gpu_index"), bool):
                    namespace = "krig_gpu_index"
                else:
                    namespace = None
            if not isinstance(device_id, (str, int)) or isinstance(device_id, bool) or not str(device_id).strip():
                device_id = payload.get("gpu_index")
            key = (namespace.strip(), str(device_id)) if namespace and isinstance(device_id, (str, int)) and not isinstance(device_id, bool) else None
            device_events[key].append(event)

        segment_identity = segment.get("gpu_identity")
        if not isinstance(segment_identity, dict):
            candidates = {
                json.dumps(
                    event.get("payload", {}).get("assignment_gpu_identity")
                    if isinstance(event.get("payload", {}).get("assignment_gpu_identity"), dict)
                    else event.get("payload", {}).get("gpu_identity"),
                    sort_keys=True,
                )
                for event in segment_events
                if isinstance(event.get("payload", {}).get("assignment_gpu_identity"), dict)
                or isinstance(event.get("payload", {}).get("gpu_identity"), dict)
            }
            segment_identity = json.loads(next(iter(candidates))) if len(candidates) == 1 else {}
        if not device_events:
            device_events[None] = []

        device_results: list[dict[str, Any]] = []
        for device_key, associated_events in sorted(
            device_events.items(), key=lambda item: (item[0] is None, item[0] or ("", ""))
        ):
            samples: list[dict[str, Any]] = []
            identity_candidates = {
                json.dumps(event.get("payload", {}).get("gpu_identity"), sort_keys=True)
                for event in associated_events
                if isinstance(event.get("payload", {}).get("gpu_identity"), dict)
            }
            gpu_identity = json.loads(next(iter(identity_candidates))) if len(identity_candidates) == 1 else {}
            if not gpu_identity and len(identity_candidates) > 1:
                identity_conflict = True
            else:
                identity_conflict = False
            if (
                len(device_events) == 1
                and isinstance(segment_identity, dict)
                and segment_identity.get("identity_verified") is True
                and len(identity_candidates) <= 1
            ):
                # A verified identity attached to a single-device segment can
                # refine the parser's unverified model-only label.
                gpu_identity = segment_identity
            if not gpu_identity and not identity_conflict and len(device_events) == 1:
                gpu_identity = segment_identity
            elif not gpu_identity and not identity_conflict and len(device_events) > 1:
                # A segment-level identity cannot be attributed to one device
                # when multiple device streams are present.
                identity_conflict = True

            if start_clock is not None and device_key is not None:
                for event in associated_events:
                    timestamp = _parse_clock(event.get("occurred_at_source_clock"))
                    payload = event.get("payload", {})
                    hashrate = payload.get("hashrate_ths")
                    if timestamp is None or hashrate is None:
                        continue
                    try:
                        elapsed = (timestamp - start_clock).total_seconds()
                        if elapsed >= 0:
                            samples.append(
                                {
                                    "elapsed_seconds": elapsed,
                                    "hashrate_ths": float(hashrate),
                                    "hashrate_semantics": payload.get("hashrate_semantics", "krig_device_reported"),
                                    "hashrate_source": payload.get("hashrate_source", "krig_text_log_gpu_sample"),
                                }
                            )
                    except (TypeError, ValueError):
                        continue

            associated_identity = gpu_identity if isinstance(gpu_identity, dict) else {}
            gpu_model = (
                associated_identity.get("raw_model")
                or (segment.get("gpu_model") if len(device_events) == 1 else None)
                or "UNKNOWN"
            )
            if device_key is None or identity_conflict:
                hash_result = GuardResult(
                    "INSUFFICIENT_DATA",
                    "GPU sample device or verified GPU identity cannot be attributed unambiguously",
                    {
                        "device_namespace": None if device_key is None else device_key[0],
                        "device_id": None if device_key is None else device_key[1],
                        "gpu_identity": associated_identity,
                        "hash_health": "UNKNOWN",
                        "recommended_action": "INSUFFICIENT_DATA",
                    },
                )
            else:
                hash_result = evaluate_hash_floor(
                    gpu_model if isinstance(gpu_model, str) and gpu_model.strip() else "UNKNOWN",
                    samples,
                    policy,
                    gpu_identity=associated_identity,
                    # Current KRig CSV data does not establish provider reallocation history.
                    reallocations_per_run=None,
                )
            valid_rates = [sample["hashrate_ths"] for sample in samples]
            device_results.append(
                {
                    "device_namespace": None if device_key is None else device_key[0],
                    "device_id": None if device_key is None else device_key[1],
                    "gpu_model": gpu_model,
                    "gpu_identity": associated_identity,
                    "observed_hashrate_ths": math.fsum(valid_rates) / len(valid_rates) if valid_rates else None,
                    "hash_sample_count": len(samples),
                    "hash_floor_guard": hash_result.to_dict(),
                    "hash_health": hash_result.details.get("hash_health", "UNKNOWN"),
                    "recommended_action": hash_result.details.get("recommended_action", "INSUFFICIENT_DATA"),
                }
            )

        if len(device_results) == 1:
            primary_device = device_results[0]
            hash_result_payload = primary_device["hash_floor_guard"]
            hash_health = primary_device["hash_health"]
            recommended_action = primary_device["recommended_action"]
            gpu_identity = primary_device["gpu_identity"]
            gpu_model = primary_device["gpu_model"]
        else:
            hash_result = GuardResult(
                "INSUFFICIENT_DATA",
                "segment-level hash health is not aggregated across distinct GPU devices",
                {"device_count": len(device_results), "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"},
            )
            hash_result_payload = hash_result.to_dict()
            hash_health = "UNKNOWN"
            recommended_action = "INSUFFICIENT_DATA"
            gpu_identity = segment_identity if isinstance(segment_identity, dict) else {}
            gpu_model = gpu_identity.get("raw_model") or segment.get("gpu_model") or "UNKNOWN"

        provider_cfg = config.get("provider_mismatch_guard", {})
        if not isinstance(provider_cfg, dict):
            raise ValueError("provider_mismatch_guard must be an object")
        provider_evidence_segment_id = provider_cfg.get("segment_id")
        if not isinstance(provider_evidence_segment_id, str) or not provider_evidence_segment_id:
            provider_result = GuardResult(
                "INSUFFICIENT_DATA",
                "provider state evidence must identify its segment_id",
                {"segment_id": segment.get("segment_id"), "evidence_segment_id": provider_evidence_segment_id},
            )
        elif provider_evidence_segment_id != segment.get("segment_id"):
            provider_result = GuardResult(
                "INSUFFICIENT_DATA",
                "provider state evidence belongs to a different segment",
                {"segment_id": segment.get("segment_id"), "evidence_segment_id": provider_evidence_segment_id},
            )
        else:
            provider_result = evaluate_provider_state_mismatch(
                container_group_state=provider_cfg.get("container_group_state"),
                instance_state=provider_cfg.get("instance_state"),
                miner_telemetry_state=provider_cfg.get("miner_telemetry_state"),
                mismatch_duration_seconds=provider_cfg.get("mismatch_duration_seconds"),
                grace_period_seconds=provider_cfg.get("grace_period_seconds"),
                confirmed_action=provider_cfg.get("confirmed_action"),
            )

        economics_cfg = config.get("economics", {})
        if not isinstance(economics_cfg, dict):
            raise ValueError("economics must be an object")
        if "target_profit_margin_fraction" in economics_cfg:
            raise ValueError("legacy target_profit_margin_fraction is ambiguous; use target_profit_over_rental_cost_fraction in schema 2.0")
        observed_hashrate_ths = (
            segment.get("mean_observed_hashrate_ths")
            if report_schema == "2.0"
            else segment.get("mean_hashrate_ths")
        )
        economic_evaluation = evaluate_economic_profit({
            "machine_id": segment.get("segment_id"),
            "attribution_id": economics_cfg.get("attribution_id"),
            "rental_usd_per_hour": economics_cfg.get("rental_usd_per_hour"),
            "target_profit_over_rental_cost_fraction": economics_cfg.get("target_profit_over_rental_cost_fraction"),
            "observed_productive_ratio": economics_cfg.get("observed_productive_ratio"),
            "net_revenue_usd_per_ths_hour": economics_cfg.get("net_revenue_usd_per_ths_hour"),
            "observed_hashrate_ths": observed_hashrate_ths,
            "economic_evidence": economics_cfg.get("economic_evidence"),
        })
        economics_result = GuardResult(
            economic_evaluation["economic_guard"]["decision"],
            economic_evaluation["economic_guard"]["reason"],
            economic_evaluation["economic_guard"]["details"],
        )
        per_segment.append(
            {
                "run_id": segment.get("run_id"),
                "segment_id": segment.get("segment_id"),
                "gpu_model": gpu_model,
                "gpu_identity": gpu_identity,
                "input_report_schema_version": report_schema,
                "observed_hashrate_ths": observed_hashrate_ths,
                "device_results": device_results,
                "hash_floor_guard": hash_result_payload,
                "hash_health": hash_health,
                "recommended_action": recommended_action,
                "provider_mismatch_guard": provider_result.to_dict(),
                "economic_guard": economics_result.to_dict(),
                "actions_performed": False,
            }
        )

    return {
        "schema_version": "2.0",
        "mode": "dry_run_only",
        "input_report_schema_version": report_schema,
        "source_file_sha256": report.get("source_file_sha256"),
        "segment_results": per_segment,
        "actions_performed": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline KRig telemetry ledger and dry-run guards")
    commands = parser.add_subparsers(dest="command", required=True)

    import_parser = commands.add_parser("import-krig", help="read a Salad-exported KRig CSV and write ledger artifacts")
    import_parser.add_argument("--input", required=True, type=Path, help="source CSV (read-only)")
    import_parser.add_argument("--output", required=True, type=Path, help="operator-selected output directory")
    import_parser.add_argument("--source-timezone", help="IANA timezone for naive source timestamps, e.g. UTC")

    batch_parser = commands.add_parser("import-krig-batch", help="create a new, coherent V2 snapshot from original CSV exports")
    batch_parser.add_argument("--input", required=True, action="append", type=Path, help="source CSV; repeat for every export in this snapshot")
    batch_parser.add_argument("--output", required=True, type=Path, help="new output directory; existing directories are rejected")
    batch_parser.add_argument("--source-timezone", help="IANA timezone for naive source timestamps, e.g. UTC")

    guard_parser = commands.add_parser("evaluate-guards", help="evaluate the offline report against a dry-run policy")
    guard_parser.add_argument("--report", required=True, type=Path, help="report.json from a supported miner telemetry import")
    guard_parser.add_argument("--config", required=True, type=Path, help="guard JSON config")

    fixture_parser = commands.add_parser("validate-revenue-fixture", help="validate an offline ten-field RevenueObservation envelope")
    fixture_parser.add_argument("--input", required=True, type=Path, help="local JSON fixture; no network request is made")

    estimate_parser = commands.add_parser("estimate-revenue", help="calculate an offline estimate from explicit pool rate and productive time")
    estimate_parser.add_argument("--fixture", required=True, type=Path, help="local RevenueObservation envelope JSON")
    estimate_parser.add_argument("--pool-hashrate-ths", required=True, help="pool-effective rate; never inferred from local GPU rate or share count")
    estimate_parser.add_argument("--pool-hashrate-provenance", required=True)
    estimate_parser.add_argument("--pool-hashrate-coin", required=True)
    estimate_parser.add_argument("--pool-hashrate-algorithm", required=True)
    estimate_parser.add_argument("--productive-seconds", required=True)
    estimate_parser.add_argument("--attribution-id", required=True)
    estimate_parser.add_argument("--attribution-status", required=True, choices=("verified", "ambiguous"))
    estimate_parser.add_argument("--window-start", required=True, help="RFC3339 timestamp with timezone")
    estimate_parser.add_argument("--window-end", required=True, help="RFC3339 timestamp with timezone")
    estimate_parser.add_argument("--historical-analysis", action="store_true", help="allow a frozen historical fixture for offline analysis only")
    estimate_parser.add_argument("--as-of", help="RFC3339 observation freshness reference for a non-historical estimate")
    estimate_parser.add_argument("--max-observation-age-seconds", help="explicit freshness maximum; no default is assumed")

    reconcile_parser = commands.add_parser("reconcile-money", help="reconcile offline evidence stages and balance snapshots without promoting them")
    reconcile_parser.add_argument("--input", required=True, type=Path, help="JSON object with money_evidence and balance_snapshots arrays")
    reconcile_parser.add_argument("--salad-billed-cost-usd")
    reconcile_parser.add_argument("--salad-billing-evidence-id")
    reconcile_parser.add_argument("--salad-billing-attribution-id")

    lifecycle_parser = commands.add_parser("import-salad-lifecycle", help="read provider lifecycle observations from Salad CSV log columns")
    lifecycle_parser.add_argument("--input", required=True, action="append", type=Path, help="source Salad export CSV; repeat to import several files")
    lifecycle_parser.add_argument("--output", required=True, type=Path, help="new output directory for lifecycle events and report")

    fl4sh_parser = commands.add_parser("import-fl4shminer", help="read Fl4shMiner telemetry from Salad-exported CSV files")
    fl4sh_parser.add_argument("--input", required=True, action="append", type=Path, help="source Fl4shMiner export CSV; repeat for additional exports")
    fl4sh_parser.add_argument("--output", required=True, type=Path, help="new output directory for normalized events, work, and report")

    fleet_parser = commands.add_parser("evaluate-fleet", help="rank observed work separately from evidence-complete economic profit")
    fleet_parser.add_argument("--input", required=True, type=Path, help="JSON object with a machines array and explicit economic evidence")

    fleet_summary_parser = commands.add_parser("fleet-summary", help="summarize shared-worker fleet evidence without assigning revenue to machines")
    fleet_summary_parser.add_argument("--input", required=True, type=Path, help="JSON object with fleet, assignments, worker evidence, and compatible costs")

    monitor_init = commands.add_parser("monitor-init", help="initialize a local SQLite state file for dry-run guard monitoring")
    monitor_init.add_argument("--state", required=True, type=Path, help="operator-selected SQLite state file")
    monitor_init.add_argument("--config", required=True, type=Path, help="guard configuration JSON")

    def add_monitor_inputs(command: argparse.ArgumentParser) -> None:
        command.add_argument("--state", required=True, type=Path, help="local SQLite state file")
        command.add_argument("--config", required=True, type=Path, help="guard configuration JSON")
        command.add_argument("--input", required=True, action="append", type=Path, help="historical CSV or normalized JSONL; repeat for multiple sources")
        command.add_argument("--format", choices=("auto", "fl4shminer-csv", "salad-lifecycle-csv", "normalized-jsonl"), default="auto")
        command.add_argument("--fleet-id", help="explicit local fleet identifier")
        command.add_argument("--worker-id", help="explicit shared Kryptex worker identifier")

    monitor_ingest = commands.add_parser("monitor-ingest", help="incrementally ingest local CSV/JSONL and persist dry-run evaluations")
    add_monitor_inputs(monitor_ingest)

    monitor_replay = commands.add_parser("monitor-replay", help="replay local historical events in chronological order into a new empty state file")
    add_monitor_inputs(monitor_replay)

    monitor_evaluate = commands.add_parser("monitor-evaluate", help="evaluate due windows from persisted observations")
    monitor_evaluate.add_argument("--state", required=True, type=Path)
    monitor_evaluate.add_argument("--config", required=True, type=Path)
    monitor_evaluate.add_argument("--as-of", help="optional RFC3339 UTC evaluation time; no timezone is inferred")

    monitor_status = commands.add_parser("monitor-status", help="show persisted machine, instance, worker, and guard state")
    monitor_status.add_argument("--state", required=True, type=Path)

    monitor_audit = commands.add_parser("monitor-audit", help="show persisted health transitions and dry-run recommendations")
    monitor_audit.add_argument("--state", required=True, type=Path)

    monitor_watch = commands.add_parser("monitor-watch-local", help="foreground polling of local evidence files; no provider calls or background service")
    add_monitor_inputs(monitor_watch)
    monitor_watch.add_argument("--poll-seconds", required=True, type=float, help="explicit local polling interval")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "import-krig":
            parsed = import_krig_csv(args.input, source_timezone=args.source_timezone)
            result = write_import_outputs(parsed, args.output)
            result.update(
                {
                    "source_file_sha256": parsed.source_file_sha256,
                    "data_rows": parsed.data_rows,
                    "recognized_event_count": len(parsed.events),
                    "empty_log_rows_ignored": parsed.empty_log_rows_ignored,
                    "unrecognized_nonempty_rows": parsed.unrecognized_nonempty_rows,
                    "billing_status": "UNKNOWN",
                }
            )
        elif args.command == "import-krig-batch":
            sources = [import_krig_csv(path, source_timezone=args.source_timezone) for path in args.input]
            result = write_v2_batch(sources, args.output)
        elif args.command == "evaluate-guards":
            result = _guard_results(args.report, args.config)
        elif args.command == "import-salad-lifecycle":
            sources = [import_salad_lifecycle_csv(path) for path in args.input]
            result = write_salad_lifecycle_outputs(sources, args.output)
        elif args.command == "import-fl4shminer":
            sources = [import_fl4shminer_csv(path) for path in args.input]
            result = write_fl4shminer_outputs(sources, args.output)
        elif args.command == "evaluate-fleet":
            record = _load_json(args.input)
            machines = record.get("machines")
            if not isinstance(machines, list) or any(not isinstance(machine, dict) for machine in machines):
                raise ValueError("fleet input requires a machines array of JSON objects")
            result = build_fleet_rankings(machines)
        elif args.command == "fleet-summary":
            result = summarize_fleet(_load_json(args.input))
        elif args.command == "monitor-init":
            policy = _monitor_policy(args.config)
            store = GuardStore(args.state)
            store.close()
            result = {
                "state_path": str(args.state),
                "schema_version": "1.0",
                "policy_hash": hashlib.sha256(json.dumps(policy.__dict__, sort_keys=True, default=str).encode("utf-8")).hexdigest(),
                "status": "INITIALIZED_OR_REUSED",
                "actions_performed": False,
            }
        elif args.command in {"monitor-ingest", "monitor-replay", "monitor-watch-local"}:
            policy = _monitor_policy(args.config)
            if args.command == "monitor-replay" and args.state.exists():
                probe = GuardStore(args.state)
                has_state = (
                    probe.count_observations() > 0 or bool(probe.track_rows())
                    or probe.connection.execute("SELECT COUNT(*) FROM lifecycle_events").fetchone()[0] > 0
                    or probe.count_source_cursors() > 0
                )
                probe.close()
                if has_state:
                    raise ValueError("monitor-replay requires a new empty state path; existing evidence will not be overwritten")
            if args.command == "monitor-watch-local" and args.poll_seconds <= 0:
                raise ValueError("poll-seconds must be positive")
            store = GuardStore(args.state)
            monitor = ContinuousMonitor(store, policy)
            try:
                if args.command == "monitor-watch-local":
                    result = {"mode": "foreground_local_file_watch", "iterations": 0, "actions_performed": False}
                    try:
                        while True:
                            events, pending_sources = _monitor_events(args, store)
                            latest_ingest = monitor.ingest(events)
                            latest_ingest["source_cursor_updates"] = _commit_monitor_source_cursors(store, pending_sources)
                            result["last_ingest"] = latest_ingest
                            result["iterations"] += 1
                            print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False), flush=True)
                            time.sleep(args.poll_seconds)
                    except KeyboardInterrupt:
                        result["stopped_by_operator"] = True
                else:
                    events, pending_sources = _monitor_events(args, store)
                    ingest_result = monitor.ingest(events)
                    ingest_result["source_cursor_updates"] = _commit_monitor_source_cursors(store, pending_sources)
                    if args.command == "monitor-replay":
                        result = {
                            "mode": "deterministic_offline_replay",
                            "ingest": ingest_result,
                            "status": fleet_monitor_status(store, policy),
                            "transitions": store.audit_rows(),
                            "actions_performed": False,
                        }
                    else:
                        result = {
                            **ingest_result,
                            "status": fleet_monitor_status(store, policy),
                            "actions_performed": False,
                        }
            finally:
                store.close()
        elif args.command == "monitor-evaluate":
            policy = _monitor_policy(args.config)
            store = GuardStore(args.state)
            try:
                results = ContinuousMonitor(store, policy).evaluate_all(args.as_of)
                result = {"evaluations": results, "status": fleet_monitor_status(store, policy), "actions_performed": False}
            finally:
                store.close()
        elif args.command == "monitor-status":
            store = GuardStore(args.state)
            try:
                result = fleet_monitor_status(store)
            finally:
                store.close()
        elif args.command == "monitor-audit":
            store = GuardStore(args.state)
            try:
                result = {"audit_events": store.audit_rows(), "actions_performed": False}
            finally:
                store.close()
        elif args.command == "validate-revenue-fixture":
            fixture = load_revenue_fixture(args.input)
            result = {
                "valid": True,
                "schema_version": "2.0",
                "observation_id": fixture.get("observation_id"),
                "source": fixture["source"],
                "freshness": fixture["freshness"],
                "coin": fixture["payload"]["coin"],
                "fee_inclusion_state": fixture["payload"]["fee_inclusion_state"],
            }
        elif args.command == "estimate-revenue":
            fixture = load_revenue_fixture(args.fixture)
            result = estimate_revenue(
                fixture,
                effective_pool_hashrate_ths=args.pool_hashrate_ths,
                pool_hashrate_provenance=args.pool_hashrate_provenance,
                pool_hashrate_coin=args.pool_hashrate_coin,
                pool_hashrate_algorithm=args.pool_hashrate_algorithm,
                productive_seconds=args.productive_seconds,
                attribution_id=args.attribution_id,
                attribution_status=args.attribution_status,
                window_start=args.window_start,
                window_end=args.window_end,
                historical_analysis=args.historical_analysis,
                as_of=args.as_of,
                max_observation_age_seconds=args.max_observation_age_seconds,
            )
        else:
            record = _load_json(args.input)
            if record.get("schema_version") != "2.0":
                raise ValueError("money input must use schema_version 2.0")
            evidence = record.get("money_evidence", [])
            snapshots = record.get("balance_snapshots", [])
            billing_evidence = record.get("billing_evidence", [])
            active_counts = record.get("active_worker_count_by_interval", {})
            if not isinstance(evidence, list) or not isinstance(snapshots, list) or not isinstance(billing_evidence, list) or not isinstance(active_counts, dict):
                raise ValueError("money input requires arrays money_evidence/balance_snapshots/billing_evidence and an optional worker-count object")
            result = reconcile_money(
                evidence,
                snapshots,
                active_worker_count_by_interval=active_counts,
                billing_evidence=billing_evidence,
                salad_billed_cost_usd=args.salad_billed_cost_usd,
                salad_billing_evidence_id=args.salad_billing_evidence_id,
                salad_billing_attribution_id=args.salad_billing_attribution_id,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
