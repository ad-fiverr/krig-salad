from __future__ import annotations

import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.aggregate import build_ledger, write_import_outputs
from collector.krig_csv import import_krig_csv
from helpers import row, write_csv


class AggregateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def import_rows(self, rows):
        source = write_csv(self.root / "source.csv", rows)
        parsed = import_krig_csv(source, source_timezone="UTC", recorded_at_utc="2026-10-09T00:00:00Z")
        return parsed, build_ledger(parsed)

    def test_share_interarrival_uses_explicit_accepted_event_timestamps(self):
        parsed, (_, segments, _, _) = self.import_rows(
            [
                row("10/8/2026, 12:00:06 PM", "12:00:06.000 share accepted: GPU0 14ms"),
                row("10/8/2026, 12:00:02 PM", "12:00:02.000 share accepted: GPU0 14ms"),
                row("10/8/2026, 12:00:00 PM", "12:00:00.000 share accepted: GPU0 14ms"),
            ]
        )
        segment = segments[0]
        self.assertEqual(segment["share_interarrival_interval_count"], 2)
        self.assertEqual(segment["share_interarrival_mean_seconds"], 3)
        self.assertEqual(segment["share_interarrival_median_seconds"], 3)
        self.assertEqual(segment["share_interarrival_p95_seconds_nearest_rank"], 4)
        self.assertEqual(segment["share_interarrival_max_seconds"], 4)
        self.assertTrue(segment["share_interarrival_timestamps_complete"])

    def test_minute_aggregation_groups_samples_and_explicit_share_events(self):
        _, (_, _, minute_stats, _) = self.import_rows(
            [
                row("10/8/2026, 12:01:10 PM", "12:01:10.000 share accepted: GPU0 14ms"),
                row("10/8/2026, 12:00:40 PM", "12:00:40.000 GPU0 RTX 5090: 380 TH/s 3/0/0 300 GH/W 500W 60C"),
                row("10/8/2026, 12:00:30 PM", "12:00:30.000 share accepted: GPU0 14ms"),
                row("10/8/2026, 12:00:10 PM", "12:00:10.000 GPU0 RTX 5090: 360 TH/s 2/0/0 300 GH/W 500W 58C"),
            ]
        )
        self.assertEqual(len(minute_stats), 2)
        first_minute = minute_stats[0]
        self.assertEqual(first_minute["minute_source_clock_bucket"], "2026-10-08T12:00")
        self.assertEqual(first_minute["sample_count"], 2)
        self.assertEqual(first_minute["hashrate_mean_ths"], 370)
        self.assertEqual(first_minute["accepted_share_events"], 1)

    def test_billing_and_productive_ratio_remain_unknown_from_krig_logs(self):
        _, (_, segments, _, report) = self.import_rows(
            [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 3090: 93 TH/s 0/0/0")]
        )
        self.assertIsNone(segments[0]["billed_running_seconds"])
        self.assertIsNone(segments[0]["observed_productive_ratio"])
        self.assertEqual(report["billing_status"], "UNKNOWN")

    def test_duration_weighted_rate_is_labeled_as_sample_interpolation(self):
        _, (_, segments, _, _) = self.import_rows(
            [
                row("10/8/2026, 12:00:30 PM", "12:00:30.000 GPU0 RTX 5090: 380 TH/s 3/0/0"),
                row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0"),
            ]
        )
        self.assertEqual(segments[0]["duration_weighted_hashrate_ths"], 370)
        self.assertIn("trapezoidal estimate", segments[0]["duration_weighted_hashrate_method"])
        self.assertEqual(segments[0]["maximum_gpu_sample_gap_seconds"], 30)

    def test_event_ledger_reimport_does_not_duplicate_ids(self):
        source = write_csv(self.root / "source.csv", [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")])
        parsed_a = import_krig_csv(source, recorded_at_utc="2026-10-09T00:00:00Z")
        parsed_b = import_krig_csv(source, recorded_at_utc="2026-10-09T01:00:00Z")
        output = self.root / "out"
        self.assertEqual(write_import_outputs(parsed_a, output)["events_appended"], 1)
        self.assertEqual(write_import_outputs(parsed_b, output)["events_appended"], 0)
        ledger_lines = (output / "events.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(ledger_lines), 1)

    def test_same_source_and_timezone_reimport_preserves_all_artifacts(self):
        source = write_csv(self.root / "source.csv", [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")])
        parsed_a = import_krig_csv(source, source_timezone="UTC", recorded_at_utc="2026-10-09T00:00:00Z")
        parsed_b = import_krig_csv(source, source_timezone="UTC", recorded_at_utc="2026-10-09T00:00:00Z")
        output = self.root / "out"
        write_import_outputs(parsed_a, output)
        artifact_names = ("events.jsonl", "segments.json", "minute_stats.jsonl", "report.json")
        before = {name: (output / name).read_bytes() for name in artifact_names}

        self.assertEqual(write_import_outputs(parsed_b, output)["events_appended"], 0)
        after = {name: (output / name).read_bytes() for name in artifact_names}
        self.assertEqual(after, before)

    def test_same_source_with_different_timezone_is_rejected_without_changing_artifacts(self):
        source = write_csv(self.root / "source.csv", [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")])
        parsed_utc = import_krig_csv(source, source_timezone="UTC", recorded_at_utc="2026-10-09T00:00:00Z")
        parsed_local = import_krig_csv(source, recorded_at_utc="2026-10-09T00:00:00Z")
        output = self.root / "out"
        write_import_outputs(parsed_utc, output)
        artifact_names = ("events.jsonl", "segments.json", "minute_stats.jsonl", "report.json")
        before = {name: (output / name).read_bytes() for name in artifact_names}

        with self.assertRaisesRegex(ValueError, "different source timezone"):
            write_import_outputs(parsed_local, output)

        after = {name: (output / name).read_bytes() for name in artifact_names}
        self.assertEqual(after, before)

    def test_mixed_source_import_is_rejected_without_changing_existing_artifacts(self):
        source_a = write_csv(self.root / "source-a.csv", [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")])
        source_b = write_csv(self.root / "source-b.csv", [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 361 TH/s 2/0/0")])
        parsed_a = import_krig_csv(source_a, recorded_at_utc="2026-10-09T00:00:00Z")
        parsed_b = import_krig_csv(source_b, recorded_at_utc="2026-10-09T00:00:00Z")
        output = self.root / "out"
        write_import_outputs(parsed_a, output)
        artifact_names = ("events.jsonl", "segments.json", "minute_stats.jsonl", "report.json")
        before = {name: (output / name).read_bytes() for name in artifact_names}

        with self.assertRaisesRegex(ValueError, "different source CSV"):
            write_import_outputs(parsed_b, output)

        after = {name: (output / name).read_bytes() for name in artifact_names}
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
