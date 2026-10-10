from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.salad_lifecycle import import_salad_lifecycle_csv, write_salad_lifecycle_outputs  # noqa: E402


class SaladLifecycleTests(unittest.TestCase):
    def _write_csv(self, path: Path, rows: list[dict[str, str]]) -> None:
        # Intentionally place log columns away from their historical ordinal positions.
        columns = [
            "Json Log message", "Severity", "Resource labels machine id", "Time",
            "Resource labels instance id", "Text Log", "Resource labels container group version",
            "Resource labels container group name", "Receive Time",
        ]
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)

    def test_named_columns_capture_json_only_events_duplicates_conflicts_and_readiness(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lifecycle.csv"
            self._write_csv(path, [
                {"Json Log message": "Instance Allocated", "Time": "2026-10-09T12:00:00Z"},
                {"Text Log": "Instance Downloading", "Time": "2026-10-09T12:00:01Z"},
                {"Json Log message": "Instance Running", "Text Log": "Instance Running", "Time": "2026-10-09T12:00:02Z"},
                {"Json Log message": "Instance Running", "Text Log": "Instance Starting", "Time": "2026-10-09T12:00:03Z"},
                {"Json Log message": "Instance Startup Probe Passed", "Time": "2026-10-09T12:00:04Z"},
                {"Text Log": "Starting Fl4shMiner v1.5.2: coin=PRL device=0", "Time": "2026-10-09T12:00:05Z"},
            ])
            parsed = import_salad_lifecycle_csv(path, recorded_at_utc="2026-10-09T13:00:00Z")
            self.assertEqual(parsed.data_rows, 6)
            self.assertEqual(parsed.recognized_observations, 7)
            self.assertEqual(parsed.duplicate_observation_groups, 1)
            self.assertEqual(len(parsed.source_conflict_groups), 1)
            allocated = next(event for event in parsed.events if event["reported_state"] == "allocated")
            self.assertEqual(allocated["event_source"], "Json Log message")
            self.assertFalse(allocated["billing_evidence_present"])
            self.assertEqual(allocated["billing_status"], "UNKNOWN")
            duplicate = [event for event in parsed.events if event["reported_state"] == "running" and event["source_row"] == 4]
            self.assertEqual({event["event_source"] for event in duplicate}, {"Text Log", "Json Log message"})
            self.assertTrue(all(event["cross_source_observation_status"] == "equivalent_observation_in_both_log_columns" for event in duplicate))
            self.assertEqual(parsed.source_conflict_groups[0]["status"], "conflicting_observations_in_log_columns")
            startup = next(event for event in parsed.events if event["event_type"] == "readiness_observation")
            self.assertEqual(startup["readiness_probe"], "startup")
            self.assertEqual(startup["readiness_outcome"], "passed")
            existing = Path(temporary) / "existing"
            existing.mkdir()
            with self.assertRaises(ValueError):
                write_salad_lifecycle_outputs([parsed], existing)

    def test_writer_creates_report_without_promoting_lifecycle_to_billing(self):
        with tempfile.TemporaryDirectory() as temporary:
            source_path = Path(temporary) / "lifecycle.csv"
            self._write_csv(source_path, [{"Json Log message": "Instance Allocated", "Time": "2026-10-09T12:00:00Z"}])
            parsed = import_salad_lifecycle_csv(source_path, recorded_at_utc="2026-10-09T13:00:00Z")
            output = Path(temporary) / "out"
            result = write_salad_lifecycle_outputs([parsed], output)
            report = __import__("json").loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(result["billing_status"], "UNKNOWN")
            self.assertFalse(report["billing_evidence_present"])
            self.assertFalse(report["billing_inferred_from_provider_events"])

    def test_text_log_miner_start_is_not_misclassified_as_provider_starting(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "miner-only.csv"
            self._write_csv(path, [{"Text Log": "Starting Fl4shMiner v1.5.2: coin=PRL device=0"}])
            parsed = import_salad_lifecycle_csv(path, recorded_at_utc="2026-10-09T13:00:00Z")
            self.assertEqual(parsed.events, [])
            self.assertEqual(parsed.empty_log_rows, 0)

    def test_naive_salad_export_time_retains_precision_without_inventing_utc(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "naive-time.csv"
            self._write_csv(path, [{"Json Log message": "Instance Running", "Time": "10/09/2026, 12:00:00 PM"}])
            parsed = import_salad_lifecycle_csv(path, recorded_at_utc="2026-10-09T13:00:00Z")
            self.assertEqual(parsed.events[0]["occurred_at_precision"], "second")
            self.assertIsNone(parsed.events[0]["occurred_at_utc"])

    def test_allocating_and_startup_probe_do_not_promote_startup_to_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "probe.csv"
            self._write_csv(path, [
                {"Json Log message": "Instance Allocating", "Time": "2026-10-09T12:00:00Z"},
                {"Json Log message": "Instance Startup Probe Passed", "Time": "2026-10-09T12:00:01Z"},
                {"Json Log message": "Instance Ready (Readiness Probe Passed)", "Time": "2026-10-09T12:00:02Z"},
            ])
            parsed = import_salad_lifecycle_csv(path, recorded_at_utc="2026-10-09T13:00:00Z")
        self.assertEqual([event["reported_state"] for event in parsed.events], [
            "allocating", "startup_probe_passed", "ready",
        ])
        startup = parsed.events[1]
        self.assertEqual(startup["readiness_probe"], "startup")
        self.assertNotEqual(startup["reported_state"], "ready")

    def test_terminal_assignment_events_are_preserved_without_billing_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "terminal.csv"
            self._write_csv(path, [
                {"Json Log message": "Instance Preempted", "Time": "2026-10-09T12:00:00Z"},
                {"Text Log": "Instance Lost", "Time": "2026-10-09T12:00:01Z"},
                {"Json Log message": "Instance Reallocated", "Time": "2026-10-09T12:00:02Z"},
            ])
            parsed = import_salad_lifecycle_csv(path, recorded_at_utc="2026-10-09T13:00:00Z")
        self.assertEqual([event["reported_state"] for event in parsed.events], ["preempted", "lost", "reallocated"])
        self.assertTrue(all(event["billing_status"] == "UNKNOWN" for event in parsed.events))


if __name__ == "__main__":
    unittest.main()
