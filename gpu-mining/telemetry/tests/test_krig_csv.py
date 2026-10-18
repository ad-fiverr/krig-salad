from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.krig_csv import import_krig_csv
from helpers import row, write_csv


class KrigCsvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def import_rows(self, rows, **kwargs):
        source = write_csv(self.root / "source.csv", rows)
        return import_krig_csv(source, recorded_at_utc="2026-10-09T00:00:00Z", **kwargs)

    def test_reverse_chronological_csv_becomes_chronological_events(self):
        parsed = self.import_rows(
            [
                row("10/8/2026, 12:01:00 PM", "12:01:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0 300 GH/W 500W 60C"),
                row("10/8/2026, 12:00:00 PM", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
            ]
        )
        self.assertEqual([event["event_type"] for event in parsed.events], ["worker_start", "gpu_sample"])

    def test_exact_machine_and_instance_values_form_segment_identity(self):
        parsed = self.import_rows(
            [
                row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0", instance="instance-a", machine="machine-a"),
                row("10/8/2026, 12:00:30 PM", "12:00:30.000 GPU0 RTX 5090: 361 TH/s 2/0/0", instance="instance-b", machine="machine-b"),
            ]
        )
        events_by_identity = {(event["instance_id"], event["machine_id"]): event for event in parsed.events}
        self.assertEqual(set(events_by_identity), {("instance-a", "machine-a"), ("instance-b", "machine-b")})
        self.assertNotEqual(events_by_identity[("instance-a", "machine-a")]["segment_id"], events_by_identity[("instance-b", "machine-b")]["segment_id"])

    def test_multiple_machines_never_merge(self):
        parsed = self.import_rows(
            [
                row("10/8/2026, 12:00:00 PM", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0", machine="machine-a"),
                row("10/8/2026, 12:00:05 PM", "12:00:05.000 GPU0 RTX 5090: 360 TH/s 2/0/0", machine="machine-b"),
            ]
        )
        self.assertEqual(len({event["segment_id"] for event in parsed.events}), 2)

    def test_krig_startup_fields_are_parsed_without_mining_identifier(self):
        parsed = self.import_rows(
            [row("10/8/2026, 12:00:00 PM", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl-us.kryptex.network:8048 device=0 mining-identifier=secret-wallet")]
        )
        event = parsed.events[0]
        self.assertEqual(event["event_type"], "worker_start")
        self.assertEqual(event["payload"], {
            "miner": "KRig",
            "miner_version": "1.5.6",
            "coin": "PRL",
            "pool_host": "prl-us.kryptex.network",
            "pool_port": 8048,
            "device": "0",
        })
        self.assertNotIn("secret-wallet", json.dumps(event))

    def test_gpu_sample_fields_are_parsed(self):
        parsed = self.import_rows(
            [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 01:00.0 RTX 3090: 93.51 TH/s 56/0/0 289 GH/W 324W 62C n/a 100% 1350 (+0) 9501 (+0)")]
        )
        payload = parsed.events[0]["payload"]
        self.assertEqual(parsed.events[0]["event_type"], "gpu_sample")
        self.assertEqual(payload["gpu_model"], "RTX 3090")
        self.assertEqual(payload["gpu_index"], 0)
        self.assertEqual(payload["hashrate_ths"], 93.51)
        self.assertEqual(payload["accepted_total"], 56)
        self.assertEqual(payload["power_w"], 324)
        self.assertEqual(payload["temperature_c"], 62)
        self.assertEqual(payload["utilization_percent"], 100)
        self.assertEqual(payload["core_clock_mhz"], 1350)
        self.assertEqual(payload["memory_clock_mhz"], 9501)

    def test_total_counters_are_parsed(self):
        parsed = self.import_rows(
            [row("10/8/2026, 12:00:00 PM", "12:00:00.000 Total: 93.51 TH/s shares: 56 accepted 0 stale 0 rejected")]
        )
        self.assertEqual(parsed.events[0]["event_type"], "total_sample")
        self.assertEqual(parsed.events[0]["payload"]["accepted_total"], 56)
        self.assertEqual(parsed.events[0]["payload"]["stale_total"], 0)
        self.assertEqual(parsed.events[0]["payload"]["rejected_total"], 0)

    def test_accepted_share_is_parsed(self):
        parsed = self.import_rows(
            [row("10/8/2026, 12:00:00 PM", "12:00:00.123 share accepted: GPU0 14ms")]
        )
        self.assertEqual(parsed.events[0]["event_type"], "share_accepted")
        self.assertEqual(parsed.events[0]["payload"]["response_latency_ms"], 14)
        self.assertEqual(parsed.events[0]["occurred_at_precision"], "millisecond")

    def test_runtime_error_is_classified_as_legacy_preflight_failure(self):
        parsed = self.import_rows(
            [row("10/8/2026, 12:00:00 PM", "krig-entrypoint: NVIDIA runtime is not exposed: /dev/nvidiactl is missing", severity="error")]
        )
        event = parsed.events[0]
        self.assertEqual(event["event_type"], "miner_error")
        self.assertEqual(event["payload"]["error_category"], "legacy_nvidia_runtime_not_exposed")
        self.assertEqual(event["payload"]["error_source_class"], "legacy_runtime_preflight_failure")

    def test_empty_log_rows_are_ignored_safely(self):
        parsed = self.import_rows([row("10/8/2026, 12:00:00 PM", "")])
        self.assertEqual(parsed.events, [])
        self.assertEqual(parsed.empty_log_rows_ignored, 1)

    def test_event_ids_are_deterministic(self):
        rows = [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")]
        first = self.import_rows(rows)
        second = self.import_rows(rows)
        self.assertEqual(first.events[0]["event_id"], second.events[0]["event_id"])

    def test_reimport_has_stable_ids_and_segment_identity(self):
        rows = [
            row("10/8/2026, 12:00:00 PM", "12:00:00.000 starting KRig v1.5.6: coin=PRL pool=prl.pool.example:8048 device=0"),
            row("10/8/2026, 12:00:30 PM", "12:00:30.000 GPU0 RTX 5090: 360 TH/s 2/0/0"),
        ]
        first = self.import_rows(rows)
        second = self.import_rows(rows)
        self.assertEqual([event["event_id"] for event in first.events], [event["event_id"] for event in second.events])
        self.assertEqual([event["segment_id"] for event in first.events], [event["segment_id"] for event in second.events])

    def test_naive_timestamp_does_not_invent_utc(self):
        parsed = self.import_rows([row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")])
        event = parsed.events[0]
        self.assertIsNone(event["occurred_at_utc"])
        self.assertEqual(event["source_timestamp_text"], "10/8/2026, 12:00:00 PM")

    def test_explicit_timezone_normalizes_to_utc(self):
        parsed = self.import_rows(
            [row("10/8/2026, 12:00:00 PM", "12:00:00.000 GPU0 RTX 5090: 360 TH/s 2/0/0")],
            source_timezone="UTC",
        )
        self.assertEqual(parsed.events[0]["occurred_at_utc"], "2026-10-08T12:00:00Z")

    def test_explicit_offset_is_preserved_when_log_clock_has_milliseconds(self):
        parsed = self.import_rows(
            [row("2026-10-08T12:00:00-05:00", "12:00:00.123 GPU0 RTX 5090: 360 TH/s 2/0/0")],
            source_timezone="UTC",
        )
        self.assertEqual(parsed.events[0]["occurred_at_utc"], "2026-10-08T17:00:00.123000Z")

    def test_log_clock_selects_the_nearest_date_across_midnight(self):
        parsed = self.import_rows(
            [
                row("2026-10-09T00:00:05Z", "23:59:55.000 GPU0 RTX 5090: 360 TH/s 2/0/0"),
                row("2026-10-08T23:59:55Z", "00:00:05.000 GPU0 RTX 5090: 361 TH/s 2/0/0"),
            ]
        )
        clocks = [event["occurred_at_utc"] for event in parsed.events]
        self.assertEqual(clocks, ["2026-10-08T23:59:55Z", "2026-10-09T00:00:05Z"])


if __name__ == "__main__":
    unittest.main()
