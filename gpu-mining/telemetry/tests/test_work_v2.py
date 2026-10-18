from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.krig_csv import import_krig_csv  # noqa: E402
from collector.work import build_work_accounting  # noqa: E402
from helpers import row, write_csv  # noqa: E402


class V2WorkTests(unittest.TestCase):
    def _event(self, kind, timestamp, payload, event_id):
        return {
            "event_type": kind,
            "occurred_at_utc": timestamp,
            "segment_id": "segment-test",
            "event_id": event_id,
            "raw_reference": {"source_file_sha256": "source", "source_row": event_id},
            "payload": payload,
        }

    def test_gpu_rate_work_is_bracketed_per_gpu_and_does_not_add_total(self):
        events = [
            self._event("gpu_sample", "2026-10-08T12:00:00Z", {"gpu_index": 0, "hashrate_ths": 100}, "a"),
            self._event("gpu_sample", "2026-10-08T12:00:30Z", {"gpu_index": 0, "hashrate_ths": 200}, "b"),
            self._event("total_sample", "2026-10-08T12:00:30Z", {"hashrate_ths": 300}, "c"),
            self._event("share_accepted", "2026-10-08T12:00:15Z", {"gpu_index": 0}, "d"),
        ]
        segment = build_work_accounting(events)["segments"][0]
        gpu = segment["gpu_hashrate_work_estimates"][0]
        self.assertEqual(gpu["integrated_th_seconds_estimate"], "4500.0")
        self.assertEqual(gpu["integrated_th_hours_estimate"], "1.25")
        self.assertEqual(gpu["gap_intervals_reported_without_classification_threshold"], 1)
        self.assertIsNone(segment["productive_seconds"])
        self.assertIsNone(segment["accepted_work_amount"])

    def test_verified_share_work_sums_only_with_explicit_provenance(self):
        events = [
            self._event("share_accepted", "2026-10-08T12:00:00Z", {"share_work_hashes": "1000", "share_work_unit": "H", "share_work_context": "pool-a/PRL/PearlHash", "share_work_verified": True, "share_work_provenance": "pool-share-record"}, "a"),
            self._event("share_accepted", "2026-10-08T12:00:05Z", {"share_work_hashes": "2500", "share_work_unit": "H", "share_work_context": "pool-a/PRL/PearlHash", "share_work_verified": True, "share_work_provenance": "pool-share-record"}, "b"),
        ]
        segment = build_work_accounting(events)["segments"][0]
        self.assertEqual(segment["accepted_work_amount"], "3500")
        self.assertEqual(segment["accepted_work_unit"], "H")
        self.assertEqual(segment["accepted_work_context"], "pool-a/PRL/PearlHash")
        self.assertEqual(segment["accepted_work_status"], "verified")
        self.assertEqual(segment["accepted_share_interarrival_seconds"], ["5.0"])

    def test_compatible_verified_difficulty_is_summed_in_its_native_unit(self):
        events = [
            self._event("share_accepted", "2026-10-08T12:00:00Z", {"share_difficulty_value": "2", "share_difficulty_unit": "PRL-share-difficulty", "share_difficulty_context": "pool-a/PRL/PearlHash", "share_difficulty_verified": True, "share_difficulty_provenance": "pool-share-record"}, "a"),
            self._event("share_accepted", "2026-10-08T12:00:05Z", {"share_difficulty_value": "3.5", "share_difficulty_unit": "PRL-share-difficulty", "share_difficulty_context": "pool-a/PRL/PearlHash", "share_difficulty_verified": True, "share_difficulty_provenance": "pool-share-record"}, "b"),
        ]
        segment = build_work_accounting(events)["segments"][0]
        self.assertEqual(segment["accepted_work_amount"], "5.5")
        self.assertEqual(segment["accepted_work_unit"], "PRL-share-difficulty")
        self.assertEqual(segment["accepted_work_basis"], "explicit_verified_compatible_share_difficulty")

    def test_incompatible_verified_difficulty_contexts_do_not_sum(self):
        events = [
            self._event("share_accepted", "2026-10-08T12:00:00Z", {"share_difficulty_value": "2", "share_difficulty_unit": "share-difficulty", "share_difficulty_context": "pool-a", "share_difficulty_verified": True, "share_difficulty_provenance": "source-a"}, "a"),
            self._event("share_accepted", "2026-10-08T12:00:05Z", {"share_difficulty_value": "3", "share_difficulty_unit": "share-difficulty", "share_difficulty_context": "pool-b", "share_difficulty_verified": True, "share_difficulty_provenance": "source-b"}, "b"),
        ]
        segment = build_work_accounting(events)["segments"][0]
        self.assertIsNone(segment["accepted_work_amount"])
        self.assertEqual(segment["accepted_work_status"], "unknown_missing_or_incompatible_verified_share_work")

    def test_counter_decreases_are_candidates_scoped_by_csv_gpu_and_counter(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = write_csv(Path(temporary) / "counter.csv", [
                row("2026-10-08T12:00:00Z", "12:00:00.000 GPU0 RTX 3090: 93 TH/s 5/1/0"),
                row("2026-10-08T12:00:30Z", "12:00:30.000 GPU0 RTX 3090: 93 TH/s 1/0/0"),
                row("2026-10-08T12:00:30Z", "12:00:30.000 Total: 93 TH/s shares: 1 accepted 0 stale 0 rejected"),
            ])
            source = import_krig_csv(path, source_timezone="UTC")
            result = build_work_accounting([], [source])
            resets = result["counter_reset_candidates"]
            self.assertEqual(len(resets), 2)
            self.assertEqual(
                {(item["device"]["namespace"], item["device"]["id"], item["counter"]) for item in resets},
                {("krig_gpu_index", 0, "accepted_total"), ("krig_gpu_index", 0, "stale_total")},
            )
            self.assertTrue(all(item["status"] == "counter_decrease_candidate_reset_not_proven" for item in resets))

    def test_same_gpu_index_on_two_machines_does_not_create_cross_machine_reset(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = write_csv(Path(temporary) / "two-machines.csv", [
                row("2026-10-08T12:00:00Z", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 5/1/0", instance="instance-a", machine="machine-a"),
                row("2026-10-08T12:00:30Z", "12:00:30.000 GPU0 RTX 5090: 360 TH/s 1/0/0", instance="instance-b", machine="machine-b"),
                row("2026-10-08T12:01:00Z", "12:01:00.000 GPU0 RTX 5090: 360 TH/s 6/1/0", instance="instance-a", machine="machine-a"),
                row("2026-10-08T12:01:30Z", "12:01:30.000 GPU0 RTX 5090: 360 TH/s 2/0/0", instance="instance-b", machine="machine-b"),
            ])
            source = import_krig_csv(path, source_timezone="UTC")
            result = build_work_accounting([], [source])
            self.assertEqual(result["counter_reset_candidates"], [])
            self.assertEqual(result["counter_reset_identity_unknown_samples"], [])

    def test_missing_assignment_identity_is_reported_without_cross_comparison(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = write_csv(Path(temporary) / "missing-machine.csv", [
                row("2026-10-08T12:00:00Z", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 5/1/0", machine=""),
                row("2026-10-08T12:00:30Z", "12:00:30.000 GPU0 RTX 5090: 360 TH/s 1/0/0", machine=""),
            ])
            source = import_krig_csv(path, source_timezone="UTC")
            result = build_work_accounting([], [source])
            self.assertEqual(result["counter_reset_candidates"], [])
            self.assertTrue(result["counter_reset_identity_unknown_samples"])
            self.assertTrue(all(item["status"] == "counter_comparison_unresolved_missing_assignment_identity" for item in result["counter_reset_identity_unknown_samples"]))

    def test_no_gap_cutoff_is_invented_and_a_long_interval_remains_explicit(self):
        events = [
            self._event("gpu_sample", "2026-10-08T12:00:00Z", {"gpu_index": 0, "hashrate_ths": 100}, "a"),
            self._event("gpu_sample", "2026-10-08T12:10:00Z", {"gpu_index": 0, "hashrate_ths": 100}, "b"),
        ]
        gpu = build_work_accounting(events)["segments"][0]["gpu_hashrate_work_estimates"][0]
        self.assertIsNone(gpu["unobserved_gap_threshold"])
        self.assertEqual(gpu["intervals"][0]["duration_seconds"], "600.0")
        self.assertEqual(gpu["intervals"][0]["interpolation"], "linear_trapezoid_between_observed_endpoints")


if __name__ == "__main__":
    unittest.main()
