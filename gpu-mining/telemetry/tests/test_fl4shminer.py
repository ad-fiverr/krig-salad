from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.fl4shminer import (  # noqa: E402
    build_fl4shminer_snapshot,
    import_fl4shminer_csv,
)


class Fl4shMinerTests(unittest.TestCase):
    columns = [
        "Json Log message", "Text Log", "Resource labels instance id", "Time",
        "Resource labels machine id", "Json Log gpu class name",
        "Resource labels container group version", "Resource labels container group name",
    ]

    def _write_csv(self, path: Path, rows: list[dict[str, str]]) -> Path:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.columns)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _rows(self) -> list[dict[str, str]]:
        identity = {
            "Resource labels instance id": "instance-a",
            "Resource labels machine id": "machine-a",
            "Resource labels container group version": "13",
            "Resource labels container group name": "fl4shminer",
        }
        return [
            {
                **identity,
                "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
                "Time": "10/10/2026, 6:30:00 PM",
                "Text Log": "2026/10/10 18:30:00 Starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://prl-us.kryptex.network:7048 device=0",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:30:30 PM",
                "Text Log": "2026/10/10 18:30:30 Device [1] hashRate: 150.00 TH/s, stale: 3/100 (3.0%), warm: 0",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:30:35 PM",
                "Text Log": "2026/10/10 18:30:35 Device [1] CUDA autotune: 130.20 TH/s (measured pool-equivalent)",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:30:36 PM",
                "Text Log": "2026/10/10 18:30:36 GPU=NVIDIA GeForce RTX 5090 Laptop Pearl autotune hashrate = 148.5 TH/s",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:31:00 PM",
                "Text Log": "2026/10/10 18:31:00 Solutions accepted: 1-NVIDIA GeForce RTX 5090 Laptop GPU, 0xabc, pool=stratum+tcp://prl-us.kryptex.network:7048, proof=bbb902fd",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:31:10 PM",
                "Text Log": "2026/10/10 18:31:10 Solutions rejected: 1-NVIDIA GeForce RTX 5090 Laptop GPU, 0xdef, pool=stratum+tcp://prl-us.kryptex.network:7048, status=stale, reason=Stale",
            },
            {
                **identity,
                "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
                "Time": "10/10/2026, 6:31:30 PM",
                "Text Log": "2026/10/10 18:31:30 Device [1] hashRate: 151.00 TH/s, stale: 4/120 (3.3%), warm: 0",
            },
            {
                **identity,
                "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
                "Time": "10/10/2026, 6:32:00 PM",
                "Text Log": "",
            },
        ]

    def test_wrapper_and_miner_device_ids_keep_namespaces_without_splitting_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "run.csv", self._rows()))
        snapshot = build_fl4shminer_snapshot([parsed])
        self.assertEqual(len(snapshot["segments"]), 1)
        segment = snapshot["segments"][0]
        self.assertEqual(segment["gpu_identity"]["form_factor"], "laptop")
        self.assertTrue(segment["gpu_identity"]["identity_verified"])
        self.assertEqual(segment["gpu_sample_count"], 2)
        observations = {(item["namespace"], item["id"]) for item in segment["device_id_observations"]}
        self.assertIn(("salad_wrapper_device", "0"), observations)
        self.assertIn(("fl4shminer_device", "1"), observations)
        self.assertEqual({event["segment_id"] for event in snapshot["events"]}, {segment["segment_id"]})
        self.assertIn("wall_clock_anchor_timezone_unverified", segment["run_identity_status"])

    def test_hashrate_estimates_solutions_and_stale_counters_remain_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "run.csv", self._rows()))
        snapshot = build_fl4shminer_snapshot([parsed])
        events = snapshot["events"]
        device = next(event for event in events if event["event_type"] == "gpu_sample")
        estimates = [event for event in events if event["event_type"] == "hashrate_estimate"]
        accepted = next(event for event in events if event["event_type"] == "solution_accepted")
        rejected = next(event for event in events if event["event_type"] == "solution_rejected")
        segment = snapshot["segments"][0]
        self.assertEqual(device["payload"]["hashrate_ths"], 150.0)
        self.assertEqual(device["payload"]["hashrate_semantics"], "fl4shminer_device_reported")
        self.assertEqual({item["payload"]["hashrate_semantics"] for item in estimates}, {
            "fl4shminer_cuda_autotune_pool_equivalent_estimate", "pearl_autotune_estimate",
        })
        self.assertTrue(all(item["payload"]["worker_hashrate"] is False for item in estimates))
        self.assertEqual(accepted["payload"]["share_difficulty_value"], None)
        self.assertEqual(accepted["payload"]["solution_hex_interpretation"], "unverified_solution_field_not_difficulty")
        self.assertEqual(rejected["payload"]["reported_rejection_status"], "stale")
        self.assertEqual(segment["explicit_accepted_solution_count"], 1)
        self.assertEqual(segment["explicit_rejected_solution_count"], 1)
        work_segment = snapshot["work"]["segments"][0]
        self.assertEqual(work_segment["accepted_share_count"], 0)
        self.assertEqual(work_segment["explicit_share_accepted_count"], 0)
        self.assertEqual(work_segment["explicit_solution_accepted_count"], 1)
        self.assertEqual(work_segment["explicit_solution_rejected_count"], 1)
        self.assertEqual(len(segment["cumulative_stale_counter_observations"]), 2)
        self.assertTrue(all(not item["is_paid_share_count"] for item in segment["cumulative_stale_counter_observations"] if "is_paid_share_count" in item))
        self.assertEqual(segment["actual_kryptex_worker_hashrate_ths"], None)
        self.assertEqual(segment["actual_kryptex_worker_hashrate_status"], "not_observed_in_supported_records")
        self.assertEqual(segment["billing_status"], "UNKNOWN")

    def test_timezone_unverified_exports_do_not_cross_deduplicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = self._rows()
            first = import_fl4shminer_csv(self._write_csv(root / "first.csv", rows))
            second_rows = self._rows()
            second_rows[-1]["Json Log message"] = "provider observation not consumed by the miner parser"
            second = import_fl4shminer_csv(self._write_csv(root / "second.csv", second_rows))
        snapshot = build_fl4shminer_snapshot([first, second])
        self.assertEqual(snapshot["report"]["segment_count"], 2)
        self.assertEqual(snapshot["report"]["deduplicated_event_count"], 0)
        self.assertEqual(snapshot["report"]["worker_hashrate_status"], "UNKNOWN_NOT_REPORTED_IN_SUPPORTED_RECORDS")

    def test_gpu_identity_is_scoped_to_each_complete_provider_assignment(self):
        desktop_rows = self._rows()[:2]
        desktop_rows[0]["Json Log gpu class name"] = "NVIDIA GeForce RTX 5090 Desktop (24 GB)"
        laptop_rows = self._rows()[:2]
        for row_item in laptop_rows:
            row_item["Resource labels instance id"] = "instance-b"
            row_item["Resource labels machine id"] = "machine-b"
            row_item["Time"] = row_item["Time"].replace("6:30", "6:31")
        all_rows = desktop_rows + laptop_rows
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "two-machines.csv", all_rows))
        snapshot = build_fl4shminer_snapshot([parsed])
        identities = {segment["machine_id"]: segment["gpu_identity"] for segment in snapshot["segments"]}
        self.assertEqual(len(identities), 2)
        self.assertEqual(identities["machine-a"]["form_factor"], "desktop")
        self.assertEqual(identities["machine-b"]["form_factor"], "laptop")
        self.assertTrue(all(identity["identity_verified"] for identity in identities.values()))

    def test_incomplete_provider_assignment_isolated_per_event_and_gpu_identity_unknown(self):
        rows = self._rows()[:2]
        for row_item in rows:
            row_item["Resource labels machine id"] = ""
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "incomplete.csv", rows))
        snapshot = build_fl4shminer_snapshot([parsed])
        self.assertEqual(len(snapshot["segments"]), 2)
        self.assertEqual(len({event["segment_id"] for event in snapshot["events"]}), 2)
        self.assertTrue(all(not segment["gpu_identity"]["identity_verified"] for segment in snapshot["segments"]))
        self.assertTrue(all(segment["run_identity_status"] == "incomplete_provider_assignment_event_isolated" for segment in snapshot["segments"]))


if __name__ == "__main__":
    unittest.main()
