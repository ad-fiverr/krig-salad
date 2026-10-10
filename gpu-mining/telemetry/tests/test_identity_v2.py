from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.identity import build_v2_event_snapshot  # noqa: E402
from collector.krig_csv import import_krig_csv  # noqa: E402
from helpers import row, write_csv  # noqa: E402


class V2IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _overlap_sources(self):
        common = [
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
            row("2026-10-08T12:00:10Z", "12:00:10.000 GPU0 RTX 3090: 93.2 TH/s 2/0/0 324 W 62 C"),
            row("2026-10-08T12:00:20Z", "12:00:20.000 share accepted: GPU0 45.0 ms"),
        ]
        first = write_csv(self.root / "export-a.csv", common)
        second = write_csv(self.root / "export-b.csv", [
            common[0],
            row("2026-10-08T12:00:05Z", "12:00:05.000 stratum: new job"),
            *common[1:],
        ])
        return [import_krig_csv(first, source_timezone="UTC"), import_krig_csv(second, source_timezone="UTC")]

    def test_overlapping_exports_deduplicate_logical_events_and_preserve_provenance(self):
        sources = self._overlap_sources()
        result = build_v2_event_snapshot(sources)
        self.assertEqual(result["source_event_count"], 7)
        self.assertEqual(result["deduplicated_event_count"], 3)
        self.assertEqual(len(result["events"]), 4)
        common = next(event for event in result["events"] if event["event_type"] == "share_accepted")
        self.assertEqual(common["identity_status"], "verified_equivalent")
        self.assertEqual(common["source_file_count"], 2)
        self.assertEqual(len(common["source_references"]), 2)
        self.assertNotEqual(common["source_references"][0]["source_row"], common["source_references"][1]["source_row"])
        self.assertTrue(common["logical_event_id"].startswith("logical-event-v2_"))
        self.assertNotEqual(common["event_id"], common["legacy_event_id"])
        self.assertIsNone(common["payload"]["share_difficulty_value"])
        self.assertFalse(common["payload"]["share_difficulty_verified"])

    def test_v2_logical_ids_are_independent_of_input_order(self):
        sources = self._overlap_sources()
        left = build_v2_event_snapshot(sources)
        right = build_v2_event_snapshot(list(reversed(sources)))
        self.assertEqual([e["event_id"] for e in left["events"]], [e["event_id"] for e in right["events"]])
        self.assertEqual(left["source_bundle_sha256"], right["source_bundle_sha256"])

    def test_incomplete_provider_identity_never_merges_between_exports(self):
        first = write_csv(self.root / "partial-a.csv", [
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0", machine=""),
            row("2026-10-08T12:00:10Z", "12:00:10.000 GPU0 RTX 3090: 93 TH/s 1/0/0", machine=""),
        ])
        second = write_csv(self.root / "partial-b.csv", [
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0", machine=""),
            row("2026-10-08T12:00:10Z", "12:00:10.000 GPU0 RTX 3090: 93 TH/s 1/0/0", machine=""),
            row("2026-10-08T12:00:20Z", "12:00:20.000 GPU0 RTX 3090: 94 TH/s 2/0/0", machine=""),
        ])
        result = build_v2_event_snapshot([
            import_krig_csv(first, source_timezone="UTC"), import_krig_csv(second, source_timezone="UTC")
        ])
        self.assertEqual(result["deduplicated_event_count"], 0)
        self.assertEqual(len(result["events"]), 5)
        self.assertTrue(all(event["identity_status"] == "incomplete_provider_identity" for event in result["events"]))

    def test_missing_trusted_utc_timestamp_never_merges(self):
        rows = [
            row("10/8/2026, 12:00:00 PM", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
            row("10/8/2026, 12:00:10 PM", "12:00:10.000 GPU0 RTX 3090: 93 TH/s 1/0/0"),
        ]
        first = write_csv(self.root / "naive-a.csv", rows)
        second = write_csv(self.root / "naive-b.csv", rows + [row("10/8/2026, 12:00:20 PM", "12:00:20.000 GPU0 RTX 3090: 93 TH/s 1/0/0")])
        result = build_v2_event_snapshot([
            import_krig_csv(first), import_krig_csv(second)
        ])
        self.assertEqual(result["deduplicated_event_count"], 0)
        self.assertTrue(all(event["occurred_at_utc"] is None for event in result["events"]))

    def test_repeated_fingerprint_inside_one_source_is_kept_as_ambiguous_multiplicity(self):
        path = write_csv(self.root / "repeated.csv", [
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
            row("2026-10-08T12:00:10Z", "12:00:10.000 GPU0 RTX 3090: 93 TH/s 1/0/0"),
            row("2026-10-08T12:00:10Z", "12:00:10.000 GPU0 RTX 3090: 93 TH/s 1/0/0"),
        ])
        result = build_v2_event_snapshot([import_krig_csv(path, source_timezone="UTC")])
        samples = [event for event in result["events"] if event["event_type"] == "gpu_sample"]
        self.assertEqual(len(samples), 2)
        self.assertTrue(all(event["identity_status"] == "ambiguous_repeated_fingerprint_within_source" for event in samples))
        self.assertTrue(all(event["logical_event_id"] is None for event in samples))
        self.assertEqual(result["deduplicated_event_count"], 0)

    def test_partial_export_can_join_a_unique_verified_anchor_from_another_export(self):
        start = row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0")
        sample = row("2026-10-08T12:00:10Z", "12:00:10.000 GPU0 RTX 3090: 93 TH/s 1/0/0")
        first = write_csv(self.root / "anchored.csv", [start, sample])
        partial = write_csv(self.root / "partial.csv", [sample, row("2026-10-08T12:00:20Z", "12:00:20.000 share accepted: GPU0 43ms")])
        result = build_v2_event_snapshot([
            import_krig_csv(first, source_timezone="UTC"), import_krig_csv(partial, source_timezone="UTC")
        ])
        gpu_samples = [event for event in result["events"] if event["event_type"] == "gpu_sample"]
        self.assertEqual(len(gpu_samples), 1)
        self.assertEqual(gpu_samples[0]["source_file_count"], 2)
        self.assertEqual(len(gpu_samples[0]["source_references"]), 2)
        self.assertEqual(result["deduplicated_event_count"], 1)

    def test_different_machine_ids_do_not_share_runs_or_segments(self):
        path = write_csv(self.root / "two-machines.csv", [
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0", machine="machine-a"),
            row("2026-10-08T12:00:00Z", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0", machine="machine-b"),
        ])
        result = build_v2_event_snapshot([import_krig_csv(path, source_timezone="UTC")])
        self.assertEqual(len({event["run_id"] for event in result["events"]}), 2)
        self.assertEqual(len({event["segment_id"] for event in result["events"]}), 2)


if __name__ == "__main__":
    unittest.main()
