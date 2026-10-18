"""Optional local-only regression; the standard unittest suite does not require this CSV."""

from __future__ import annotations

import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = TELEMETRY_ROOT.parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.aggregate import build_ledger  # noqa: E402
from collector.fl4shminer import build_fl4shminer_snapshot, import_fl4shminer_csv  # noqa: E402
from collector.krig_csv import import_krig_csv  # noqa: E402


def main() -> int:
    historical = REPO_ROOT / "gpu-mining" / "Miners" / "KRig" / "3090-low" / "1hr-28min-krig-pearl-logs-10_8_2026, 2_15_34 PM.csv"
    if not historical.exists():
        print(f"SKIP: historical CSV not present: {historical}")
        return 0

    parsed = import_krig_csv(historical)
    _, segments, _, report = build_ledger(parsed)
    assert parsed.data_rows == 850
    assert parsed.empty_log_rows_ignored == 286
    assert parsed.unrecognized_nonempty_rows == 6
    assert len(parsed.events) == 558

    failed_attempts_by_version = Counter(
        event["container_group_version"]
        for event in parsed.events
        if event["event_type"] == "miner_error"
        and event["payload"].get("error_category") == "legacy_nvidia_runtime_not_exposed"
    )
    assert failed_attempts_by_version == Counter({"3": 2, "4": 8, "6": 19, "7": 6}), failed_attempts_by_version

    v8 = [segment for segment in segments if segment["container_group_version"] == "8"]
    assert len(v8) == 1, f"expected one v8 segment, found {len(v8)}"
    segment = v8[0]
    assert segment["container_group_name"] == "krig-pearl"
    assert segment["instance_id"] == "68854e2b-8feb-42e7-a75c-37c4472e3560"
    assert segment["machine_id"] == "10d35ae6-380d-685d-95ff-2cade5f5f878"
    assert segment["miner_version"] == "1.5.6"
    assert segment["gpu_model"] == "RTX 3090"
    assert segment["gpu_sample_count"] == 176
    assert segment["accepted_share_event_count"] == 56
    assert segment["final_accepted_counter"] == 56
    assert segment["final_stale_counter"] == 0
    assert segment["final_rejected_counter"] == 0
    assert abs(segment["mean_hashrate_ths"] - 93.25) < 0.03, segment["mean_hashrate_ths"]
    assert abs(segment["mean_power_w"] - 324.23) < 0.1, segment["mean_power_w"]
    assert abs(segment["mean_temperature_c"] - 61.60) < 0.1, segment["mean_temperature_c"]
    assert datetime.fromisoformat(segment["first_gpu_sample_source_clock"]).isoformat(timespec="milliseconds") == "2026-10-08T18:21:07.394"
    assert datetime.fromisoformat(segment["first_accepted_share_source_clock"]).isoformat(timespec="milliseconds") == "2026-10-08T18:21:14.264"
    assert datetime.fromisoformat(segment["last_gpu_sample_source_clock"]).isoformat(timespec="milliseconds") == "2026-10-08T19:48:37.617"
    assert 29.9 <= segment["maximum_gpu_sample_gap_seconds"] <= 30.1
    legacy_failures = sum(
        count
        for item in segments
        for category, count in item["error_categories"].items()
        if category == "legacy_nvidia_runtime_not_exposed"
    )
    assert legacy_failures == 35, legacy_failures
    assert report["billing_status"] == "UNKNOWN"

    fl4sh_directory = REPO_ROOT / "gpu-mining" / "Miners" / "Flashminer"
    fl4sh_paths = sorted(fl4sh_directory.glob("*-fl4shminer-logs-*.csv"))
    if len(fl4sh_paths) != 4:
        raise AssertionError(f"expected the four inspected Fl4shMiner CSV exports, found {len(fl4sh_paths)} at {fl4sh_directory}")
    fl4sh_sources = [import_fl4shminer_csv(path) for path in fl4sh_paths]
    fl4sh_snapshot = build_fl4shminer_snapshot(fl4sh_sources)
    fl4sh_report = fl4sh_snapshot["report"]
    assert fl4sh_report["data_rows"] == 897, fl4sh_report["data_rows"]
    assert fl4sh_report["recognized_source_event_count"] == 847, fl4sh_report["recognized_source_event_count"]
    assert fl4sh_report["event_count"] == 847, fl4sh_report["event_count"]
    assert fl4sh_report["event_counts"] == {
        "gpu_sample": 727,
        "hashrate_estimate": 8,
        "solution_accepted": 102,
        "solution_rejected": 2,
        "worker_connection": 4,
        "worker_start": 4,
    }, fl4sh_report["event_counts"]
    assert fl4sh_report["run_count"] == 4
    assert fl4sh_report["segment_count"] == 4
    assert fl4sh_report["deduplicated_event_count"] == 0
    assert fl4sh_report["worker_hashrate_status"] == "UNKNOWN_NOT_REPORTED_IN_SUPPORTED_RECORDS"
    assert fl4sh_report["billing_status"] == "UNKNOWN"
    assert all(segment["gpu_identity"]["identity_verified"] for segment in fl4sh_snapshot["segments"])
    assert all(segment["gpu_identity"]["form_factor"] == "laptop" for segment in fl4sh_snapshot["segments"])
    assert all(segment["gpu_sample_count"] > 0 for segment in fl4sh_snapshot["segments"])
    assert all(segment["actual_kryptex_worker_hashrate_ths"] is None for segment in fl4sh_snapshot["segments"])
    assert all(segment["billing_status"] == "UNKNOWN" for segment in fl4sh_snapshot["segments"])
    assert all(
        { (item["namespace"], item["id"]) for item in segment["device_id_observations"] }
        >= {("salad_wrapper_device", "0"), ("fl4shminer_device", "1")}
        for segment in fl4sh_snapshot["segments"]
    )
    assert all(
        work["accepted_share_count"] == 0 and work["explicit_solution_accepted_count"] > 0
        for work in fl4sh_snapshot["work"]["segments"]
    )

    print("HISTORICAL REGRESSION: PASS")
    print(f"source rows: {parsed.data_rows}; recognized events: {len(parsed.events)}; segments: {report['segment_count']}")
    print(f"legacy failed-start errors by version: {dict(sorted(failed_attempts_by_version.items()))}")
    print(
        "v8: samples={gpu_sample_count}, accepted={accepted_share_event_count}, "
        "final={final_accepted_counter}/{final_stale_counter}/{final_rejected_counter}, "
        "mean={mean_hashrate_ths} TH/s, power={mean_power_w} W, temp={mean_temperature_c} C".format(**segment)
    )
    print(f"legacy NVIDIA preflight failures: {legacy_failures}")
    print(f"billed time: {segment['billed_running_seconds']} ({segment['billing_status']})")
    print(
        "Fl4shMiner CSVs: sources={source_count}, rows={data_rows}, events={event_count}, "
        "segments={segment_count}, accepted/rejected solutions={accepted}/{rejected}, billing={billing}".format(
            source_count=fl4sh_report["source_count"],
            data_rows=fl4sh_report["data_rows"],
            event_count=fl4sh_report["event_count"],
            segment_count=fl4sh_report["segment_count"],
            accepted=fl4sh_report["event_counts"]["solution_accepted"],
            rejected=fl4sh_report["event_counts"]["solution_rejected"],
            billing=fl4sh_report["billing_status"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
