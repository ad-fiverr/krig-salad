from __future__ import annotations

import ast
import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.cli import main  # noqa: E402
from collector.guard_store import GuardStore  # noqa: E402
from collector.gpu_identity import normalize_gpu_identity  # noqa: E402
from helpers import row, write_csv  # noqa: E402


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_import_cli_writes_four_artifacts_without_changing_source(self):
        source = write_csv(
            self.root / "source.csv",
            [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")],
        )
        original = source.read_bytes()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = main(["import-krig", "--input", str(source), "--output", str(self.root / "out"), "--source-timezone", "UTC"])
        self.assertEqual(result, 0)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual({path.name for path in (self.root / "out").iterdir()}, {"events.jsonl", "segments.json", "minute_stats.jsonl", "report.json"})
        self.assertEqual(json.loads(out.getvalue())["billing_status"], "UNKNOWN")

    def test_batch_import_writes_v2_without_changing_v1_snapshot(self):
        common = [
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
            row("2026-10-08T12:00:30Z", "12:00:30.000 GPU0 RTX 3090: 93 TH/s 1/0/0"),
        ]
        first = write_csv(self.root / "first.csv", common)
        second = write_csv(self.root / "second.csv", common + [
            row("2026-10-08T12:01:00Z", "12:01:00.000 GPU0 RTX 3090: 94 TH/s 2/0/0"),
        ])
        v1 = self.root / "v1"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["import-krig", "--input", str(first), "--output", str(v1), "--source-timezone", "UTC"]), 0)
        original_v1 = {path.name: path.read_bytes() for path in v1.iterdir()}
        v2 = self.root / "v2"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main([
                "import-krig-batch", "--input", str(first), "--input", str(second),
                "--output", str(v2), "--source-timezone", "UTC",
            ])
        payload = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(payload["schema_version"], "2.0")
        self.assertEqual(payload["source_count"], 2)
        self.assertGreater(payload["deduplicated_event_count"], 0)
        self.assertEqual({path.name for path in v2.iterdir()}, {"events.jsonl", "segments.json", "minute_stats.jsonl", "work.json", "report.json"})
        self.assertEqual({path.name: path.read_bytes() for path in v1.iterdir()}, original_v1)
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(main([
                "import-krig-batch", "--input", str(first), "--output", str(v2), "--source-timezone", "UTC",
            ]), 2)
        self.assertIn("must be new", error.getvalue())

    def test_legacy_guard_config_is_rejected_instead_of_reinterpreted(self):
        source = write_csv(self.root / "source.csv", [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")])
        output_dir = self.root / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["import-krig", "--input", str(source), "--output", str(output_dir)]), 0)
        legacy = json.loads((TELEMETRY_ROOT / "guard-config.example.json").read_text(encoding="utf-8"))
        legacy["schema_version"] = "1.0"
        legacy["economics"]["target_profit_margin_fraction"] = 0.2
        config_path = self.root / "legacy-config.json"
        config_path.write_text(json.dumps(legacy), encoding="utf-8")
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(main(["evaluate-guards", "--report", str(output_dir / "report.json"), "--config", str(config_path)]), 2)
        self.assertIn("migrate legacy economics explicitly", error.getvalue())

    def test_historical_fixture_cli_is_offline_and_reports_unknown_fees(self):
        fixture = TELEMETRY_ROOT / "fixtures" / "revenue" / "prl_2026-10-07.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["validate-revenue-fixture", "--input", str(fixture)]), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["valid"])
        self.assertEqual(result["freshness"], "historical_fixture")
        self.assertEqual(result["fee_inclusion_state"], "unknown")

    def test_historical_estimate_cli_requires_explicit_pool_rate_and_window(self):
        fixture = TELEMETRY_ROOT / "fixtures" / "revenue" / "prl_2026-10-07.json"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main([
                "estimate-revenue", "--fixture", str(fixture),
                "--pool-hashrate-ths", "93.33", "--pool-hashrate-provenance", "explicit-pool-rate-test",
                "--pool-hashrate-coin", "PRL", "--pool-hashrate-algorithm", "PearlHash",
                "--productive-seconds", "3600", "--attribution-id", "run-a/segment-a",
                "--attribution-status", "verified", "--window-start", "2026-10-08T18:30:00Z",
                "--window-end", "2026-10-08T19:30:00Z", "--historical-analysis",
            ])
        self.assertEqual(result, 0)
        estimate = json.loads(output.getvalue())
        self.assertEqual(estimate["evidence_stage"], "estimated")
        self.assertEqual(estimate["estimate_status"], "historical_fixture_for_offline_analysis_only")
        self.assertIsNone(estimate["actual_profit_loss_usd"])

    def test_reconcile_money_cli_keeps_unknown_billing_unknown(self):
        source = self.root / "money.json"
        source.write_text(json.dumps({
            "schema_version": "2.0",
            "money_evidence": [{
                "evidence_id": "pool-observed-1", "evidence_stage": "pool_observed", "amount": "0.00000170",
                "currency": "BTC", "observed_at": "2026-10-08T19:00:00Z", "observed_at_precision": "second",
                "raw_reference": "pool-balance-screen",
            }],
            "balance_snapshots": [],
        }), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["reconcile-money", "--input", str(source)])
        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["stage_totals_non_additive"]["pool_observed"]["BTC"], "0.00000170")
        self.assertIsNone(report["actual_profit_loss_usd"])

    def test_new_offline_import_and_fleet_commands_keep_unknowns_separate(self):
        lifecycle_source = self.root / "lifecycle.csv"
        lifecycle_columns = ["Json Log message", "Text Log", "Time", "Resource labels instance id"]
        with lifecycle_source.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=lifecycle_columns)
            writer.writeheader()
            writer.writerow({"Json Log message": "Instance Allocated", "Time": "2026-10-10T18:00:00Z", "Resource labels instance id": "instance-a"})
        lifecycle_out = self.root / "lifecycle-out"
        lifecycle_stdout = io.StringIO()
        with contextlib.redirect_stdout(lifecycle_stdout):
            self.assertEqual(main(["import-salad-lifecycle", "--input", str(lifecycle_source), "--output", str(lifecycle_out)]), 0)
        lifecycle_result = json.loads(lifecycle_stdout.getvalue())
        self.assertEqual(lifecycle_result["billing_status"], "UNKNOWN")
        lifecycle_report = json.loads((lifecycle_out / "report.json").read_text(encoding="utf-8"))
        self.assertFalse(lifecycle_report["billing_inferred_from_provider_events"])

        miner_source = self.root / "fl4sh.csv"
        miner_columns = [
            "Json Log gpu class name", "Time", "Resource labels machine id", "Text Log",
            "Resource labels container group name", "Resource labels instance id", "Resource labels container group version",
        ]
        identity = {
            "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
            "Resource labels machine id": "machine-a",
            "Resource labels container group name": "fl4shminer",
            "Resource labels instance id": "instance-a",
            "Resource labels container group version": "13",
        }
        with miner_source.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=miner_columns)
            writer.writeheader()
            writer.writerow({**identity, "Time": "10/10/2026, 6:30:00 PM", "Text Log": "2026/10/10 18:30:00 Starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://prl-us.kryptex.network:7048 device=0"})
            writer.writerow({**identity, "Time": "10/10/2026, 6:30:30 PM", "Text Log": "2026/10/10 18:30:30 Device [1] hashRate: 150.00 TH/s, stale: 3/100 (3.0%), warm: 0"})
        fl4sh_out = self.root / "fl4sh-out"
        fl4sh_stdout = io.StringIO()
        with contextlib.redirect_stdout(fl4sh_stdout):
            self.assertEqual(main(["import-fl4shminer", "--input", str(miner_source), "--output", str(fl4sh_out)]), 0)
        fl4sh_result = json.loads(fl4sh_stdout.getvalue())
        self.assertEqual(fl4sh_result["segment_count"], 1)
        fl4sh_segments = json.loads((fl4sh_out / "segments.json").read_text(encoding="utf-8"))["segments"]
        self.assertEqual(fl4sh_segments[0]["gpu_identity"]["form_factor"], "laptop")

        fleet_input = self.root / "fleet.json"
        fleet_input.write_text(json.dumps({"machines": [{
            "machine_id": "laptop-5090", "coin": "PRL", "algorithm": "PearlHash",
            "hashrate_semantics": "fl4shminer_device_reported", "hashrate_source": "Text Log:Device hashRate",
            "observed_hashrate_ths": 150,
        }]}), encoding="utf-8")
        fleet_stdout = io.StringIO()
        with contextlib.redirect_stdout(fleet_stdout):
            self.assertEqual(main(["evaluate-fleet", "--input", str(fleet_input)]), 0)
        fleet_result = json.loads(fleet_stdout.getvalue())
        self.assertEqual(fleet_result["observed_work_rankings"][0]["machines"][0]["observed_hashrate_ths"], 150)
        self.assertEqual(fleet_result["economic_profit_rankings"], [])
        self.assertEqual(fleet_result["economic_profit_unknown"][0]["profit_status"], "UNKNOWN")
        self.assertFalse(fleet_result["actions_performed"])

    def test_monitor_replay_cli_persists_chronological_transition_without_actions(self):
        identity = normalize_gpu_identity(
            "NVIDIA GeForce RTX 5090 Laptop GPU",
            identity_source="salad_json_log_gpu_class_name",
            identity_verified=True,
        )
        start = datetime(2026, 10, 8, tzinfo=timezone.utc)
        events = []
        for elapsed in range(0, 121, 10):
            occurred_at = (start + timedelta(seconds=elapsed)).isoformat().replace("+00:00", "Z")
            events.append({
                "event_type": "gpu_sample",
                "event_id": f"replay-sample-{elapsed}",
                "fleet_id": "fleet-shared-worker",
                "worker_id": "kryptex-worker",
                "allocation_id": "container-group|13",
                "assignment_id": "container-group|13",
                "run_id": "run-replay",
                "machine_id": "machine-laptop-a",
                "instance_id": "instance-a",
                "device_namespace": "fl4shminer_device",
                "device_id": "1",
                "occurred_at_utc": occurred_at,
                "assignment_started_at_utc": start.isoformat().replace("+00:00", "Z"),
                "start_anchor_verified": True,
                "hashrate_ths": 20,
                "hashrate_semantics": "fl4shminer_device_reported",
                "hashrate_source": "synthetic_cli_test: local device rate",
                "gpu_identity": identity,
                "reallocation_history_known": True,
                "reallocation_count": 0,
                "provenance": {"source": "synthetic_cli_test", "event_source": "fixture"},
            })
        jsonl = self.root / "monitor.jsonl"
        jsonl.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")

        config = json.loads((TELEMETRY_ROOT / "guard-config.example.json").read_text(encoding="utf-8"))
        config["hash_guard"].update({
            "warmup_seconds": 0,
            "hash_window_seconds": 60,
            "reevaluation_interval_seconds": 30,
            "minimum_samples_per_window": 6,
            "expected_sample_interval_seconds": 10,
            "maximum_sample_gap_seconds": 20,
            "minimum_window_coverage_ratio": 0.8,
            "consecutive_bad_windows": 1,
            "reallocation_cooldown_seconds": 0,
            "max_reallocations_per_run": 1,
        })
        config_path = self.root / "monitor-config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        state = self.root / "monitor.sqlite"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main([
                "monitor-replay", "--state", str(state), "--config", str(config_path),
                "--input", str(jsonl), "--format", "normalized-jsonl",
            ])
        replay = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(replay["mode"], "deterministic_offline_replay")
        self.assertEqual(replay["ingest"]["inserted_sample_count"], len(events))
        self.assertFalse(replay["actions_performed"])
        self.assertIn("REALLOCATION_RECOMMENDED", [item["event_type"] for item in replay["transitions"]])

        status = io.StringIO()
        with contextlib.redirect_stdout(status):
            self.assertEqual(main(["monitor-status", "--state", str(state)]), 0)
        persisted = json.loads(status.getvalue())
        self.assertEqual(len(persisted["tracks"]), 1)
        self.assertEqual(persisted["tracks"][0]["machine_id"], "machine-laptop-a")
        self.assertFalse(persisted["actions_performed"])

    def test_monitor_ingest_cursor_preserves_append_ids_and_isolates_rotated_generation(self):
        columns = [
            "Json Log message", "Text Log", "Resource labels instance id", "Time",
            "Resource labels machine id", "Json Log gpu class name",
            "Resource labels container group version", "Resource labels container group name",
        ]
        identity = {
            "Resource labels instance id": "instance-cursor",
            "Resource labels machine id": "machine-cursor",
            "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
            "Resource labels container group version": "13",
            "Resource labels container group name": "fl4shminer",
            "Json Log message": "",
        }
        rows = [
            {
                **identity,
                "Time": "2026-10-08T12:00:00Z",
                "Text Log": "2026/10/08 12:00:00 Starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://prl-us.kryptex.network:7048 device=0",
            },
            {
                **identity,
                "Time": "2026-10-08T12:00:30Z",
                "Text Log": "2026/10/08 12:00:30 Device [1] hashRate: 150.00 TH/s, stale: 0/1 (0.0%), warm: 0",
            },
        ]
        source = self.root / "incremental-fl4sh.csv"

        def write_rows(*, append: bool = False) -> None:
            mode = "a" if append else "w"
            with source.open(mode, encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns)
                if not append:
                    writer.writeheader()
                writer.writerows(rows if not append else rows[-1:])

        write_rows()
        config_path = TELEMETRY_ROOT / "guard-config.example.json"
        state = self.root / "monitor-cursor.sqlite"

        def ingest() -> dict:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([
                    "monitor-ingest", "--state", str(state), "--config", str(config_path),
                    "--input", str(source), "--format", "fl4shminer-csv",
                ]), 0)
            return json.loads(output.getvalue())

        first = ingest()
        self.assertEqual(first["inserted_sample_count"], 1)
        store = GuardStore(state)
        first_observations = store.connection.execute(
            "SELECT event_id, track_id FROM observations ORDER BY occurred_at_utc"
        ).fetchall()
        self.assertEqual(len(first_observations), 1)
        original_event_id = first_observations[0]["event_id"]
        original_track_id = first_observations[0]["track_id"]
        store.close()

        rows.append({
            **identity,
            "Time": "2026-10-08T12:01:00Z",
            "Text Log": "2026/10/08 12:01:00 Device [1] hashRate: 151.00 TH/s, stale: 0/2 (0.0%), warm: 0",
        })
        write_rows(append=True)
        appended = ingest()
        self.assertEqual(appended["inserted_sample_count"], 1)
        store = GuardStore(state)
        appended_observations = store.connection.execute(
            "SELECT event_id, track_id FROM observations ORDER BY occurred_at_utc"
        ).fetchall()
        cursor = store.source_cursor_rows()[0]
        self.assertEqual(len(appended_observations), 2)
        self.assertEqual(appended_observations[0]["event_id"], original_event_id)
        self.assertEqual({item["track_id"] for item in appended_observations}, {original_track_id})
        self.assertEqual(cursor["generation"], 1)
        self.assertEqual(cursor["row_count"], 3)
        store.close()

        # An edit to a previously consumed row is not an append. It starts a
        # separate source generation and must not reuse old event or track IDs.
        rows[1]["Text Log"] = "2026/10/08 12:00:30 Device [1] hashRate: 149.00 TH/s, stale: 0/1 (0.0%), warm: 0"
        write_rows()
        rotated = ingest()
        self.assertEqual(rotated["inserted_sample_count"], 2)
        self.assertTrue(rotated["source_cursor_updates"][0]["reset_detected"])
        self.assertEqual(rotated["source_cursor_updates"][0]["generation"], 2)
        store = GuardStore(state)
        tracks = store.track_rows()
        current_observations = store.connection.execute(
            "SELECT event_id, track_id FROM observations ORDER BY occurred_at_utc, event_id"
        ).fetchall()
        cursor = store.source_cursor_rows()[0]
        self.assertEqual(len(tracks), 2)
        self.assertIsNotNone(store.get_track(original_track_id)["closed_at_utc"])
        self.assertEqual(len({item["track_id"] for item in current_observations}), 2)
        self.assertNotIn(original_event_id, {item["event_id"] for item in current_observations if item["track_id"] != original_track_id})
        self.assertEqual(cursor["generation"], 2)
        self.assertEqual(cursor["row_count"], 3)
        store.close()

    def test_monitor_append_revealing_second_fl4sh_device_revokes_prior_assignment_identity(self):
        columns = [
            "Json Log message", "Text Log", "Resource labels instance id", "Time",
            "Resource labels machine id", "Json Log gpu class name",
            "Resource labels container group version", "Resource labels container group name",
        ]
        identity = {
            "Json Log message": "",
            "Resource labels instance id": "instance-multi-device",
            "Resource labels machine id": "machine-multi-device",
            "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
            "Resource labels container group version": "17",
            "Resource labels container group name": "fl4shminer",
        }
        rows = [
            {
                **identity,
                "Time": "2026-10-08T12:00:00Z",
                "Text Log": "2026/10/08 12:00:00 Starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://prl-us.kryptex.network:7048 device=0",
            },
            {
                **identity,
                "Time": "2026-10-08T12:00:30Z",
                "Text Log": "2026/10/08 12:00:30 Device [0] hashRate: 150.00 TH/s, stale: 0/1 (0.0%), warm: 0",
            },
        ]
        source = self.root / "second-device-append.csv"
        with source.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        config = TELEMETRY_ROOT / "guard-config.example.json"
        state = self.root / "append-identity.sqlite"

        def run(command: str, state_path: Path) -> dict:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main([
                    command, "--state", str(state_path), "--config", str(config),
                    "--input", str(source), "--format", "fl4shminer-csv",
                    "--fleet-id", "fleet-device-append", "--worker-id", "worker-shared",
                ]), 0)
            return json.loads(output.getvalue())

        first = run("monitor-ingest", state)
        self.assertEqual(first["inserted_sample_count"], 1)
        store = GuardStore(state)
        old_track = store.track_rows(active_only=True)[0]
        old_track_id = old_track["track_id"]
        self.assertTrue(json.loads(old_track["gpu_identity_json"])["identity_verified"])
        old_event_id = store.connection.execute("SELECT event_id FROM observations").fetchone()[0]
        store.close()

        rows.append({
            **identity,
            "Time": "2026-10-08T12:00:40Z",
            "Text Log": "2026/10/08 12:00:40 Device [1] hashRate: 80.00 TH/s, stale: 0/1 (0.0%), warm: 0",
        })
        with source.open("a", encoding="utf-8", newline="") as handle:
            csv.DictWriter(handle, fieldnames=columns).writerows(rows[-1:])
        appended = run("monitor-ingest", state)
        self.assertEqual(appended["inserted_sample_count"], 1)
        self.assertEqual(appended["identity_invalidated_track_count"], 1)
        store = GuardStore(state)
        tracks = store.track_rows(active_only=True)
        observations = store.connection.execute("SELECT event_id FROM observations").fetchall()
        self.assertEqual(len(tracks), 2)
        self.assertEqual(len(observations), 2)
        self.assertIn(old_event_id, {item["event_id"] for item in observations})
        self.assertEqual(store.get_track(old_track_id)["hash_health"], "UNKNOWN")
        self.assertFalse(json.loads(store.get_track(old_track_id)["gpu_identity_json"])["identity_verified"])
        self.assertTrue(all(not json.loads(track["gpu_identity_json"])["identity_verified"] for track in tracks))
        self.assertEqual(len([item for item in store.audit_rows() if item["event_type"] == "GPU_DEVICE_MAPPING_AMBIGUOUS"]), 1)
        store.close()

        repeated = run("monitor-ingest", state)
        self.assertEqual(repeated["inserted_sample_count"], 0)
        replay_state = self.root / "append-identity-replay.sqlite"
        replay = run("monitor-replay", replay_state)
        self.assertEqual(replay["mode"], "deterministic_offline_replay")
        store = GuardStore(replay_state)
        replay_tracks = store.track_rows(active_only=True)
        self.assertEqual(len(replay_tracks), 2)
        self.assertTrue(all(not json.loads(track["gpu_identity_json"])["identity_verified"] for track in replay_tracks))
        self.assertEqual(store.count_observations(), 2)
        store.close()

    def test_fleet_summary_cli_keeps_shared_worker_btc_at_fleet_scope(self):
        fleet_input = self.root / "fleet-summary.json"
        fleet_input.write_text(json.dumps({
            "fleet_id": "five-gpu-fleet",
            "worker_id": "shared-kryptex-worker",
            "assignments": [{
                "assignment_id": f"assignment-{index}",
                "machine_id": f"machine-{index}",
                "instance_id": f"instance-{index}",
                "status": "running",
            } for index in range(5)],
            "device_hashrate_observations": [{
                "window_start_utc": "2026-10-08T18:30:00Z",
                "window_end_utc": "2026-10-08T19:30:00Z",
                "machine_id": f"machine-{index}",
                "device_namespace": "fl4shminer_device",
                "device_id": "0",
                "coin": "PRL",
                "algorithm": "PearlHash",
                "hashrate_ths": 90 + index,
                "hashrate_semantics": "fl4shminer_device_reported",
                "hashrate_source": "Text Log:Device hashRate",
            } for index in range(5)],
            "worker_btc_evidence": [{
                "evidence_id": "pool-credit-1",
                "worker_id": "shared-kryptex-worker",
                "status": "verified",
                "evidence_stage": "pool_observed",
                "amount": "0.00000170",
                "currency": "BTC",
                "observed_at": "2026-10-08T19:30:00Z",
                "source_reference": "redacted-worker-balance-record",
            }],
        }), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["fleet-summary", "--input", str(fleet_input)]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["observed_hashrate_by_coin_algorithm_window"][0]["device_count"], 5)
        self.assertEqual(result["observed_hashrate_by_coin_algorithm_window"][0]["observed_hashrate_ths"], 460.0)
        self.assertEqual(result["worker_btc_revenue"]["amount_btc_by_stage"]["pool_observed"], "0.00000170")
        self.assertEqual(result["worker_btc_revenue"]["machine_level_distribution"], "NOT_DISTRIBUTED")
        self.assertEqual(result["economic_reconciliation_status"], "UNKNOWN")
        self.assertFalse(result["actions_performed"])

    def test_guard_cli_is_dry_run_and_reports_unconfigured_policy(self):
        source = write_csv(
            self.root / "source.csv",
            [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")],
        )
        output = self.root / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            main(["import-krig", "--input", str(source), "--output", str(output)])
        config = TELEMETRY_ROOT / "guard-config.example.json"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = main(["evaluate-guards", "--report", str(output / "report.json"), "--config", str(config)])
        payload = json.loads(out.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(payload["mode"], "dry_run_only")
        self.assertFalse(payload["actions_performed"])
        self.assertEqual(payload["segment_results"][0]["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")
        self.assertEqual(payload["segment_results"][0]["provider_mismatch_guard"]["decision"], "INSUFFICIENT_DATA")

    def test_guard_cli_adapts_v2_report_model_and_observed_hashrate(self):
        source = write_csv(self.root / "v2-5090.csv", [
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=QTC pool=qtc.pool.example:8048 device=0"),
            row("2026-10-08T12:00:10Z", "12:00:10.000 GPU0 RTX 5090: 360 TH/s 2/0/0"),
            row("2026-10-08T12:00:20Z", "12:00:20.000 GPU0 RTX 5090: 360 TH/s 3/0/0"),
            row("2026-10-08T12:00:30Z", "12:00:30.000 GPU0 RTX 5090: 360 TH/s 4/0/0"),
        ])
        output_dir = self.root / "v2"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([
                "import-krig-batch", "--input", str(source), "--output", str(output_dir), "--source-timezone", "UTC",
            ]), 0)
        report = json.loads((output_dir / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["segments"][0]["gpu_model"], "RTX 5090")
        config = {
            "schema_version": "2.0",
            "hash_guard": {
                "gpu_floors_ths": {"RTX 5090|desktop|salad_json_log_gpu_class_name": 350},
                "warmup_seconds": 0,
                "hash_window_seconds": 30,
                "minimum_samples_per_window": 2,
                "expected_sample_interval_seconds": 15,
                "maximum_sample_gap_seconds": 15,
                "minimum_window_coverage_ratio": 1.0,
                "consecutive_bad_windows": 1,
                "reallocation_cooldown_seconds": 0,
                "max_reallocations_per_run": 0,
            },
            "provider_mismatch_guard": {},
            "economics": {},
        }
        config_path = self.root / "v2-guard-config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = main(["evaluate-guards", "--report", str(output_dir / "report.json"), "--config", str(config_path)])
        payload = json.loads(out.getvalue())
        segment = payload["segment_results"][0]
        self.assertEqual(result, 0)
        self.assertEqual(payload["input_report_schema_version"], "2.0")
        self.assertEqual(segment["gpu_model"], "RTX 5090")
        self.assertEqual(segment["observed_hashrate_ths"], 360.0)
        self.assertEqual(segment["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")
        self.assertEqual(segment["hash_floor_guard"]["details"]["hash_health"], "UNKNOWN")
        self.assertEqual(segment["economic_guard"]["decision"], "ECONOMICS_UNKNOWN")

    def _two_device_guard_fixture(self, name: str) -> tuple[Path, Path]:
        rows = [row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0")]
        for second in (10, 40, 70, 100, 130):
            timestamp = f"2026-10-08T12:{second // 60:02d}:{second % 60:02d}Z"
            clock = f"12:{second // 60:02d}:{second % 60:02d}.000"
            rows.append(row(timestamp, f"{clock} GPU0 RTX 5090: 360 TH/s 2/0/0"))
            rows.append(row(timestamp, f"{clock} GPU1 RTX 5090: 20 TH/s 2/0/0"))
        source = write_csv(self.root / f"{name}.csv", rows)
        output = self.root / name
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["import-krig", "--input", str(source), "--output", str(output), "--source-timezone", "UTC"]), 0)

        desktop = normalize_gpu_identity(
            "NVIDIA GeForce RTX 5090 Desktop GPU",
            identity_source="salad_json_log_gpu_class_name",
            identity_verified=True,
        )
        report_path = output / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["segments"][0]["gpu_identity"] = desktop
        report_path.write_text(json.dumps(report), encoding="utf-8")
        events_path = output / "events.jsonl"
        events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
        for event in events:
            if event.get("event_type") == "gpu_sample":
                event["payload"]["gpu_identity"] = desktop
        events_path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")

        config = json.loads((TELEMETRY_ROOT / "guard-config.example.json").read_text(encoding="utf-8"))
        config["hash_guard"].update(
            {
                "warmup_seconds": 0,
                "hash_window_seconds": 60,
                "minimum_samples_per_window": 2,
                "expected_sample_interval_seconds": 30,
                "maximum_sample_gap_seconds": 30,
                "minimum_window_coverage_ratio": 1.0,
                "consecutive_bad_windows": 3,
                "reallocation_cooldown_seconds": 0,
                "max_reallocations_per_run": 1,
            }
        )
        config_path = self.root / f"{name}-config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        return report_path, config_path

    def test_guard_cli_evaluates_each_gpu_device_independently(self):
        report_path, config_path = self._two_device_guard_fixture("two-device")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["evaluate-guards", "--report", str(report_path), "--config", str(config_path)]), 0)

        segment = json.loads(output.getvalue())["segment_results"][0]
        devices = {(item["device_namespace"], item["device_id"]): item for item in segment["device_results"]}
        fast = devices[("krig_gpu_index", "0")]
        slow = devices[("krig_gpu_index", "1")]
        self.assertEqual(fast["observed_hashrate_ths"], 360.0)
        self.assertEqual(fast["hash_floor_guard"]["decision"], "PASS")
        self.assertEqual(slow["observed_hashrate_ths"], 20.0)
        self.assertEqual(slow["hash_floor_guard"]["decision"], "WOULD_WAIT")
        self.assertEqual(segment["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")

    def test_guard_cli_does_not_apply_segment_gpu_identity_to_unattributed_device(self):
        report_path, config_path = self._two_device_guard_fixture("two-device-ambiguous")
        events_path = report_path.parent / "events.jsonl"
        events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
        for event in events:
            payload = event.get("payload", {})
            if event.get("event_type") == "gpu_sample" and payload.get("gpu_index") == 1:
                payload.pop("gpu_identity", None)
        events_path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["evaluate-guards", "--report", str(report_path), "--config", str(config_path)]), 0)

        segment = json.loads(output.getvalue())["segment_results"][0]
        devices = {(item["device_namespace"], item["device_id"]): item for item in segment["device_results"]}
        self.assertEqual(devices[("krig_gpu_index", "0")]["hash_floor_guard"]["decision"], "PASS")
        self.assertEqual(devices[("krig_gpu_index", "1")]["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")
        self.assertIn("cannot be attributed", devices[("krig_gpu_index", "1")]["hash_floor_guard"]["reason"])

    def test_fl4sh_assignment_gpu_label_does_not_promote_to_multiple_device_floors(self):
        columns = [
            "Json Log gpu class name", "Time", "Resource labels machine id", "Text Log",
            "Resource labels container group name", "Resource labels instance id", "Resource labels container group version",
        ]
        identity = {
            "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Desktop (32 GB)",
            "Resource labels machine id": "machine-fl4sh",
            "Resource labels container group name": "fl4shminer",
            "Resource labels instance id": "instance-fl4sh",
            "Resource labels container group version": "13",
        }
        rows = [{
            **identity,
            "Time": "2026-10-10T18:30:00Z",
            "Text Log": "2026/10/10 18:30:00 Starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://prl-us.kryptex.network:7048 device=0",
        }]
        for second in (10, 40, 70, 100, 130):
            minute, second_part = divmod(second, 60)
            clock = f"18:{30 + minute:02d}:{second_part:02d}"
            timestamp = f"2026-10-10T{clock}Z"
            for device, rate in ((0, 360), (1, 20)):
                rows.append({
                    **identity,
                    "Time": timestamp,
                    "Text Log": f"2026/10/10 {clock} Device [{device}] hashRate: {rate}.00 TH/s, stale: 0/100 (0.0%), warm: 0",
                })
        source = self.root / "fl4sh-two-devices.csv"
        with source.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        output_dir = self.root / "fl4sh-two-devices-output"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["import-fl4shminer", "--input", str(source), "--output", str(output_dir)]), 0)

        report_path = output_dir / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["segment_count"], 1)
        self.assertTrue(report["segments"][0]["gpu_identity"]["identity_verified"])
        self.assertEqual(report["segments"][0]["gpu_identity_scope"], "provider_assignment")
        events = [json.loads(line) for line in (output_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
        gpu_events = [event for event in events if event["event_type"] == "gpu_sample"]
        self.assertTrue(all("gpu_identity" not in event["payload"] for event in gpu_events))
        self.assertTrue(all(event["payload"]["assignment_gpu_identity"]["identity_verified"] for event in gpu_events))

        config = json.loads((TELEMETRY_ROOT / "guard-config.example.json").read_text(encoding="utf-8"))
        config["hash_guard"].update({
            "warmup_seconds": 0,
            "hash_window_seconds": 60,
            "minimum_samples_per_window": 2,
            "expected_sample_interval_seconds": 30,
            "maximum_sample_gap_seconds": 30,
            "minimum_window_coverage_ratio": 1.0,
            "consecutive_bad_windows": 2,
            "reallocation_cooldown_seconds": 0,
            "max_reallocations_per_run": 1,
        })
        config_path = self.root / "fl4sh-two-device-config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        guard_output = io.StringIO()
        with contextlib.redirect_stdout(guard_output):
            self.assertEqual(main(["evaluate-guards", "--report", str(report_path), "--config", str(config_path)]), 0)

        segment = json.loads(guard_output.getvalue())["segment_results"][0]
        devices = {item["device_id"]: item for item in segment["device_results"]}
        self.assertEqual(devices["0"]["observed_hashrate_ths"], 360.0)
        self.assertEqual(devices["1"]["observed_hashrate_ths"], 20.0)
        self.assertEqual(devices["0"]["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")
        self.assertEqual(devices["1"]["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")
        self.assertEqual(segment["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")

    def test_provider_mismatch_evidence_is_scoped_to_its_segment(self):
        source = write_csv(
            self.root / "multi-machine.csv",
            [
                row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0", instance="instance-a", machine="machine-a"),
                row("10/8/2026, 12:00:30 PM", "12:00:30.000 GPU0 RTX 5080: 220 TH/s 2/0/0", instance="instance-b", machine="machine-b"),
            ],
        )
        output = self.root / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["import-krig", "--input", str(source), "--output", str(output)]), 0)

        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(len(report["segments"]), 2)
        evidence_segment_id = report["segments"][0]["segment_id"]

        config = json.loads((TELEMETRY_ROOT / "guard-config.example.json").read_text(encoding="utf-8"))
        config["provider_mismatch_guard"] = {
            "segment_id": evidence_segment_id,
            "grace_period_seconds": 30,
            "container_group_state": "running",
            "instance_state": "allocating",
            "miner_telemetry_state": "stale",
            "mismatch_duration_seconds": 45,
            "confirmed_action": "WOULD_STOP",
        }
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["evaluate-guards", "--report", str(output / "report.json"), "--config", str(config_path)]), 0)
        payload = json.loads(out.getvalue())
        results = {item["segment_id"]: item["provider_mismatch_guard"] for item in payload["segment_results"]}
        other_segment_id = next(segment["segment_id"] for segment in report["segments"] if segment["segment_id"] != evidence_segment_id)
        self.assertEqual(results[evidence_segment_id]["decision"], "WOULD_STOP")
        self.assertEqual(results[other_segment_id]["decision"], "INSUFFICIENT_DATA")
        self.assertEqual(results[other_segment_id]["details"]["evidence_segment_id"], evidence_segment_id)

    def test_guard_cli_uses_earliest_timestamped_worker_start(self):
        source = write_csv(
            self.root / "multiple-starts.csv",
            [
                row("2026-10-08T12:00:30Z", "12:00:30.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
                row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
                row("2026-10-08T12:00:20Z", "12:00:20.000 GPU0 RTX 5090: 300 TH/s 0/0/0"),
                row("2026-10-08T12:00:50Z", "12:00:50.000 GPU0 RTX 5090: 300 TH/s 0/0/0"),
                row("2026-10-08T12:01:00Z", "12:01:00.000 GPU0 RTX 5090: 300 TH/s 0/0/0"),
            ],
        )
        output = self.root / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["import-krig", "--input", str(source), "--output", str(output)]), 0)

        report_path = output / "report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        # This test-only provider class observation isolates CLI window timing;
        # real KRig text labels alone remain unverified for Desktop floors.
        report["segments"][0]["gpu_identity"] = normalize_gpu_identity(
            "NVIDIA GeForce RTX 5090 Desktop GPU",
            identity_source="salad_json_log_gpu_class_name",
            identity_verified=True,
        )
        report_path.write_text(json.dumps(report), encoding="utf-8")

        config = json.loads((TELEMETRY_ROOT / "guard-config.example.json").read_text(encoding="utf-8"))
        config["hash_guard"].update(
            {
                "warmup_seconds": 0,
                "hash_window_seconds": 60,
                "minimum_samples_per_window": 2,
                "expected_sample_interval_seconds": 30,
                "maximum_sample_gap_seconds": 30,
                "minimum_window_coverage_ratio": 0.5,
                "consecutive_bad_windows": 1,
                "reallocation_cooldown_seconds": 0,
                "max_reallocations_per_run": 1,
            }
        )
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["evaluate-guards", "--report", str(output / "report.json"), "--config", str(config_path)]), 0)
        payload = json.loads(out.getvalue())
        windows = payload["segment_results"][0]["hash_floor_guard"]["details"]["windows"]
        self.assertEqual(windows[0]["start_seconds"], 0)
        self.assertEqual(windows[0]["sample_count"], 2)
        self.assertEqual(payload["segment_results"][0]["hash_floor_guard"]["decision"], "INSUFFICIENT_DATA")
        self.assertIn("reallocation history", payload["segment_results"][0]["hash_floor_guard"]["reason"])

    def test_source_has_no_network_or_external_mutation_adapters(self):
        forbidden_imports = {"requests", "httpx", "urllib", "firebase_admin", "google.cloud"}
        for path in TELEMETRY_ROOT.rglob("*.py"):
            if "tests" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = {alias.name for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    names = {node.module or ""}
                else:
                    continue
                self.assertTrue(not (names & forbidden_imports), f"external side-effect import in {path}: {names & forbidden_imports}")

    def test_example_config_contains_editable_floors_and_lab_timing(self):
        config = json.loads((TELEMETRY_ROOT / "guard-config.example.json").read_text(encoding="utf-8"))
        self.assertEqual(config["hash_guard"]["gpu_floors_ths"], {
            "RTX 5090|desktop|salad_json_log_gpu_class_name": 350,
            "RTX 5080|desktop|salad_json_log_gpu_class_name": 209,
            "RTX 5090|laptop|salad_json_log_gpu_class_name": 120,
            "RTX 5080|laptop|salad_json_log_gpu_class_name": 120,
        })
        for name, expected in {
            "warmup_seconds": 90,
            "hash_window_seconds": 120,
            "reevaluation_interval_seconds": 30,
            "minimum_samples_per_window": 10,
            "expected_sample_interval_seconds": 10,
            "maximum_sample_gap_seconds": 30,
            "minimum_window_coverage_ratio": 0.8,
            "consecutive_bad_windows": 2,
        }.items():
            self.assertEqual(config["hash_guard"][name], expected)
        for name in ("reallocation_cooldown_seconds", "max_reallocations_per_run"):
            self.assertIsNone(config["hash_guard"][name])
        self.assertIsNone(config["provider_mismatch_guard"]["grace_period_seconds"])
        self.assertIsNone(config["provider_mismatch_guard"]["segment_id"])


if __name__ == "__main__":
    unittest.main()
