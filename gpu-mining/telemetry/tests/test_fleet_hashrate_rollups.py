from __future__ import annotations

import json
import math
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.fleet_hashrate_rollups import build_hashrate_rollups
from collector.guard_store import GuardStore


AS_OF = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


def stamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def make_track(
    track_id: str,
    *,
    start: datetime,
    closed: datetime | None = None,
    organization: str | None = "org-a",
    project: str | None = "miners",
    machine: str = "machine-a",
    instance: str | None = None,
    device: str = "0",
    assignment: str | None = None,
    active_anchor: bool = True,
    identity_status: str = "verified",
) -> dict:
    provider_scope = {
        "scope_status": "VERIFIED",
        "organization_id": organization,
        "project_id": project,
    } if organization and project else {}
    return {
        "track_id": track_id,
        "fleet_id": "fleet-main",
        "worker_id": "worker-main",
        "allocation_id": assignment or f"allocation-{track_id}",
        "assignment_id": assignment or f"assignment-{track_id}",
        "run_id": f"run-{track_id}",
        "machine_id": machine,
        "instance_id": instance or f"instance-{track_id}",
        "device_namespace": "fl4shminer_device",
        "device_id": device,
        "started_at_utc": stamp(start),
        "start_anchor_verified": 1 if active_anchor else 0,
        "closed_at_utc": stamp(closed) if closed else None,
        "gpu_identity_json": json.dumps({"model": "RTX 5090", "identity_verified": True, "identity_status": identity_status}),
        "provenance_json": json.dumps({"provider_scope": provider_scope}),
    }


def make_samples(track_id: str, start: datetime, end: datetime, rate: float, *, every: int = 30) -> list[dict]:
    samples: list[dict] = []
    current = start
    index = 0
    while current <= end:
        samples.append({
            "event_id": f"{track_id}-{index}",
            "occurred_at_utc": stamp(current),
            "hashrate_ths": rate,
            "hashrate_semantics": "fl4shminer_device_reported",
            "hashrate_source": "synthetic_verified_device_line",
        })
        current += timedelta(seconds=every)
        index += 1
    if not samples or samples[-1]["occurred_at_utc"] != stamp(end):
        samples.append({
            "event_id": f"{track_id}-end",
            "occurred_at_utc": stamp(end),
            "hashrate_ths": rate,
            "hashrate_semantics": "fl4shminer_device_reported",
            "hashrate_source": "synthetic_verified_device_line",
        })
    return samples


def build(tracks: list[dict], sample_map: dict[str, list[dict]], *, as_of: datetime = AS_OF, max_gap: int = 30) -> dict:
    return build_hashrate_rollups(
        tracks,
        sample_map,
        as_of_utc=as_of,
        maximum_sample_gap_seconds=max_gap,
        minimum_window_coverage_ratio=0.8,
    )


def independent_midpoint_fleet_mean(
    sample_sets: list[list[dict]],
    *,
    window_start: datetime,
    window_end: datetime,
    maximum_gap_seconds: float,
) -> float:
    """Reference via 1-second midpoint slices, independent of production integration."""
    duration = int((window_end - window_start).total_seconds())
    aggregate_sum = 0.0
    for offset in range(duration):
        midpoint = window_start + timedelta(seconds=offset + 0.5)
        fleet_rate = 0.0
        for samples in sample_sets:
            points = sorted(
                (
                    datetime.fromisoformat(sample["occurred_at_utc"].replace("Z", "+00:00")),
                    float(sample["hashrate_ths"]),
                )
                for sample in samples
            )
            segment = next(
                ((left, right) for left, right in zip(points, points[1:]) if left[0] <= midpoint <= right[0]),
                None,
            )
            if segment is None:
                raise AssertionError("reference slice is not bracketed by observations")
            left, right = segment
            gap = (right[0] - left[0]).total_seconds()
            if gap <= 0 or gap > maximum_gap_seconds:
                raise AssertionError("reference slice exceeds the approved sample gap")
            fraction = (midpoint - left[0]).total_seconds() / gap
            fleet_rate += left[1] + (right[1] - left[1]) * fraction
        aggregate_sum += fleet_rate
    return aggregate_sum / duration


def independent_partial_midpoint_reference(
    track_samples: list[tuple[dict, list[dict]]],
    *,
    window_start: datetime,
    window_end: datetime,
    maximum_gap_seconds: float,
) -> dict[str, float | None]:
    """Reference observed-only fleet contribution on independent 1s slices."""
    duration = int((window_end - window_start).total_seconds())
    integrated = 0.0
    covered_seconds = 0.0
    active_device_seconds = 0.0
    observed_device_seconds = 0.0
    missing_device_seconds = 0.0
    ambiguous_device_seconds = 0.0
    for offset in range(duration):
        midpoint = window_start + timedelta(seconds=offset + 0.5)
        by_physical: dict[tuple[str, str, str], list[list[tuple[datetime, float]]]] = {}
        for track, samples in track_samples:
            track_start = datetime.fromisoformat(track["started_at_utc"].replace("Z", "+00:00"))
            track_end = (
                datetime.fromisoformat(track["closed_at_utc"].replace("Z", "+00:00"))
                if track.get("closed_at_utc") else None
            )
            if not track_start <= midpoint or (track_end is not None and midpoint >= track_end):
                continue
            physical = (track["machine_id"], track["device_namespace"], track["device_id"])
            points = sorted((
                datetime.fromisoformat(item["occurred_at_utc"].replace("Z", "+00:00")),
                float(item["hashrate_ths"]),
            ) for item in samples)
            by_physical.setdefault(physical, []).append(points)

        active_device_seconds += len(by_physical)
        contribution = 0.0
        contributing = 0
        for candidate_sets in by_physical.values():
            if len(candidate_sets) != 1:
                ambiguous_device_seconds += 1.0
                continue
            points = candidate_sets[0]
            bracket = next((
                (left, right) for left, right in zip(points, points[1:])
                if left[0] <= midpoint <= right[0]
            ), None)
            if bracket is None:
                missing_device_seconds += 1.0
                continue
            left, right = bracket
            gap = (right[0] - left[0]).total_seconds()
            if gap <= 0 or gap > maximum_gap_seconds:
                missing_device_seconds += 1.0
                continue
            fraction = (midpoint - left[0]).total_seconds() / gap
            contribution += left[1] + (right[1] - left[1]) * fraction
            contributing += 1
        if contributing:
            integrated += contribution
            covered_seconds += 1.0
            observed_device_seconds += contributing
    return {
        "fleet_time_weighted_average_hashrate_ths": integrated / covered_seconds if covered_seconds else None,
        "integrated_observed_th_hours": integrated / 3600.0 if covered_seconds else None,
        "covered_seconds": covered_seconds,
        "active_device_seconds": active_device_seconds,
        "observed_device_seconds": observed_device_seconds,
        "missing_device_seconds": missing_device_seconds,
        "ambiguous_device_seconds": ambiguous_device_seconds,
    }


class FleetHashrateRollupTests(unittest.TestCase):
    def test_guard_store_rollup_sample_query_is_bounded_and_reports_omitted_history(self):
        store = GuardStore(":memory:")
        start = AS_OF - timedelta(minutes=5)
        try:
            inserted = []
            for index in range(5):
                timestamp = start + timedelta(seconds=index * 30)
                result = store.ingest_observation({
                    "event_id": f"bounded-store-{index}",
                    "fleet_id": "fleet-store",
                    "worker_id": "worker-store",
                    "allocation_id": "allocation-store",
                    "assignment_id": "assignment-store",
                    "run_id": "run-store",
                    "machine_id": "machine-store",
                    "instance_id": "instance-store",
                    "device_namespace": "fl4shminer_device",
                    "device_id": "0",
                    "occurred_at_utc": stamp(timestamp),
                    "assignment_started_at_utc": stamp(start),
                    "start_anchor_verified": True,
                    "hashrate_ths": 100.0 + index,
                    "hashrate_semantics": "fl4shminer_device_reported",
                    "hashrate_source": "synthetic_test_fixture",
                    "provenance": {"data_classification": "SYNTHETIC/UNVERIFIED"},
                })
                inserted.append(result)

            track_id = inserted[0]["track_id"]
            bounded = store.rollup_samples_for_track(track_id, since_elapsed_seconds=0, maximum_records=3)
            unbounded = store.rollup_samples_for_track(track_id, since_elapsed_seconds=0, maximum_records=5)

            self.assertTrue(bounded["truncated"])
            self.assertEqual([sample["event_id"] for sample in bounded["samples"]], [
                "bounded-store-2", "bounded-store-3", "bounded-store-4",
            ])
            self.assertFalse(unbounded["truncated"])
            self.assertEqual(len(unbounded["samples"]), 5)
        finally:
            store.close()

    def test_ten_aligned_gpus_sum_only_inside_verified_scope(self):
        start = AS_OF - timedelta(seconds=600)
        tracks = [make_track(f"track-{index}", start=start, machine=f"machine-{index}") for index in range(10)]
        samples = {item["track_id"]: make_samples(item["track_id"], start, AS_OF, 100.0) for item in tracks}

        result = build(tracks, samples)

        fleet = result["fleets"][0]
        window = fleet["windows"]["10m"]
        self.assertEqual(fleet["observed_online_gpu_count"], 10)
        self.assertEqual(fleet["requested_gpu_count"], None)
        self.assertEqual(fleet["allocating_gpu_count"], None)
        self.assertEqual(window["fleet_time_weighted_average_hashrate_ths"], 1000.0)
        self.assertAlmostEqual(window["integrated_observed_th_hours"], 1000 * 600 / 3600)
        self.assertEqual(fleet["provider_inventory_status"], "UNKNOWN")
        self.assertEqual(window["device_coverage_status"], "COMPLETE_TRACK_COVERAGE")
        self.assertEqual(window["fleet_completeness_status"], "UNKNOWN_PROVIDER_GPU_INVENTORY_UNAVAILABLE")
        self.assertEqual(window["status"], "PARTIAL")
        self.assertFalse(result["actions_performed"])

    def test_fleet_mean_matches_independent_time_slice_reference(self):
        start = AS_OF - timedelta(seconds=600)
        first = make_track("reference-first", start=start, machine="machine-1")
        second = make_track("reference-second", start=start, machine="machine-2")
        first_samples = make_samples("reference-first", start, AS_OF, 100.0, every=150)
        second_samples = make_samples("reference-second", start, AS_OF, 60.0, every=200)
        for index, sample in enumerate(first_samples):
            sample["hashrate_ths"] = 80.0 + (index % 3) * 40.0
        for index, sample in enumerate(second_samples):
            sample["hashrate_ths"] = 40.0 + (index % 4) * 30.0

        result = build(
            [first, second],
            {"reference-first": first_samples, "reference-second": second_samples},
            max_gap=250,
        )

        expected = independent_midpoint_fleet_mean(
            [first_samples, second_samples],
            window_start=start,
            window_end=AS_OF,
            maximum_gap_seconds=250,
        )
        window = result["fleets"][0]["windows"]["10m"]
        self.assertAlmostEqual(window["fleet_time_weighted_average_hashrate_ths"], expected, places=8)
        self.assertAlmostEqual(window["integrated_observed_th_hours"], expected * 600 / 3600, places=8)

    def test_exact_10m_30m_60m_24h_windows_and_th_hours(self):
        start = AS_OF - timedelta(hours=24)
        track = make_track("constant", start=start)
        samples = make_samples("constant", start, AS_OF, 100.0, every=30)

        result = build([track], {"constant": samples})

        windows = result["devices"][0]["windows"]
        self.assertEqual([windows[name]["window_seconds"] for name in ("10m", "30m", "60m", "24h")], [600, 1800, 3600, 86400])
        for name, seconds in (("10m", 600), ("30m", 1800), ("60m", 3600), ("24h", 86400)):
            self.assertAlmostEqual(windows[name]["mean_hashrate_ths"], 100.0)
            self.assertAlmostEqual(windows[name]["integrated_th_hours"], 100 * seconds / 3600)
            self.assertEqual(windows[name]["window_coverage_ratio"], 1.0)
            self.assertEqual(windows[name]["status"], "COMPLETE")

    def test_replacement_halfway_contributes_once_and_preserves_generation_identity(self):
        boundary = AS_OF - timedelta(seconds=300)
        start = AS_OF - timedelta(seconds=600)
        old = make_track("old", start=start, closed=boundary, machine="same-machine", instance="old-instance")
        new = make_track("new", start=boundary, machine="same-machine", instance="new-instance")
        samples = {
            "old": make_samples("old", start, boundary, 100.0),
            "new": make_samples("new", boundary, AS_OF, 100.0),
        }

        result = build([old, new], samples)

        fleet = result["fleets"][0]
        window = fleet["windows"]["10m"]
        self.assertAlmostEqual(window["fleet_time_weighted_average_hashrate_ths"], 100.0)
        self.assertAlmostEqual(window["integrated_observed_th_hours"], 100 * 600 / 3600)
        self.assertEqual(fleet["observed_online_gpu_count"], 1)
        self.assertEqual({item["instance_id"] for item in result["devices"]}, {"old-instance", "new-instance"})

    def test_offline_two_hours_is_not_reported_as_online_or_zero_hashrate(self):
        stopped = AS_OF - timedelta(hours=2)
        start = AS_OF - timedelta(hours=3)
        track = make_track("offline", start=start, closed=stopped)
        samples = make_samples("offline", start, stopped, 100.0, every=30)

        result = build([track], {"offline": samples})

        device = result["devices"][0]
        self.assertEqual(device["current"]["status"], "INACTIVE")
        self.assertIsNone(device["current"]["hashrate_ths"])
        self.assertEqual(result["fleets"][0]["observed_online_gpu_count"], 0)
        self.assertIsNotNone(device["windows"]["24h"]["integrated_th_hours"])
        self.assertEqual(device["windows"]["10m"]["status"], "UNKNOWN")

    def test_stale_or_missing_data_is_partial_or_unknown_and_never_carried_forward(self):
        start = AS_OF - timedelta(minutes=20)
        track = make_track("stale", start=start)
        samples = make_samples("stale", AS_OF - timedelta(seconds=180), AS_OF - timedelta(seconds=120), 100.0)

        result = build([track], {"stale": samples})

        device = result["devices"][0]
        self.assertEqual(device["current"]["status"], "STALE")
        self.assertIsNone(device["current"]["hashrate_ths"])
        self.assertEqual(device["windows"]["10m"]["status"], "PARTIAL")
        self.assertLess(device["windows"]["10m"]["window_coverage_ratio"], 0.8)
        self.assertIsNone(result["fleets"][0]["requested_gpu_count"])

    def test_healthy_gpu_contribution_is_preserved_when_another_active_gpu_is_stale(self):
        start = AS_OF - timedelta(seconds=600)
        healthy = make_track("healthy-stale-peer", start=start, machine="machine-healthy")
        stale = make_track("stale-peer", start=start, machine="machine-stale")
        healthy_samples = make_samples("healthy-stale-peer", start, AS_OF, 120.0)
        stale_samples = make_samples("stale-peer", AS_OF - timedelta(seconds=180), AS_OF - timedelta(seconds=120), 500.0)

        result = build([healthy, stale], {"healthy-stale-peer": healthy_samples, "stale-peer": stale_samples})

        window = result["fleets"][0]["windows"]["10m"]
        reference = independent_partial_midpoint_reference(
            [(healthy, healthy_samples), (stale, stale_samples)],
            window_start=start, window_end=AS_OF, maximum_gap_seconds=30,
        )
        # The stale device still contributes only over its real observed
        # 60-second segment; its last rate is not carried forward afterward.
        self.assertAlmostEqual(window["fleet_time_weighted_average_hashrate_ths"], 170.0)
        self.assertAlmostEqual(window["integrated_observed_th_hours"], (120 * 600 + 500 * 60) / 3600)
        self.assertEqual(window["covered_seconds"], 600.0)
        self.assertEqual(window["observed_device_seconds"], 660.0)
        self.assertEqual(window["missing_device_seconds"], 540.0)
        self.assertEqual(window["device_coverage_ratio"], 0.55)
        self.assertEqual(window["device_coverage_status"], "PARTIAL_TRACK_COVERAGE")
        self.assertEqual(window["observed_contribution_status"], "OBSERVED")
        self.assertEqual(window["fleet_completeness_status"], "UNKNOWN_PROVIDER_GPU_INVENTORY_UNAVAILABLE")
        self.assertEqual(window["fleet_time_weighted_average_hashrate_ths"], reference["fleet_time_weighted_average_hashrate_ths"])
        self.assertEqual(window["integrated_observed_th_hours"], reference["integrated_observed_th_hours"])

    def test_healthy_gpu_contribution_is_preserved_when_another_active_gpu_has_no_samples(self):
        start = AS_OF - timedelta(seconds=600)
        healthy = make_track("healthy-offline-peer", start=start, machine="machine-healthy")
        offline = make_track("offline-peer", start=start, machine="machine-offline")
        healthy_samples = make_samples("healthy-offline-peer", start, AS_OF, 80.0)

        result = build([healthy, offline], {"healthy-offline-peer": healthy_samples, "offline-peer": []})

        window = result["fleets"][0]["windows"]["10m"]
        self.assertEqual(window["fleet_time_weighted_average_hashrate_ths"], 80.0)
        self.assertAlmostEqual(window["integrated_observed_th_hours"], 80 * 600 / 3600)
        self.assertEqual(window["missing_device_seconds"], 600.0)
        self.assertEqual(window["device_coverage_ratio"], 0.5)
        self.assertEqual(window["status"], "PARTIAL")

    def test_staggered_track_observations_keep_partial_sum_and_match_reference(self):
        start = AS_OF - timedelta(seconds=600)
        second_observed_start = start + timedelta(seconds=300)
        first = make_track("staggered-first", start=start, machine="machine-1")
        second = make_track("staggered-second", start=start, machine="machine-2")
        first_samples = make_samples("staggered-first", start, AS_OF, 100.0)
        second_samples = make_samples("staggered-second", second_observed_start, AS_OF, 50.0)

        result = build([first, second], {"staggered-first": first_samples, "staggered-second": second_samples})

        window = result["fleets"][0]["windows"]["10m"]
        reference = independent_partial_midpoint_reference(
            [(first, first_samples), (second, second_samples)],
            window_start=start, window_end=AS_OF, maximum_gap_seconds=30,
        )
        self.assertAlmostEqual(window["fleet_time_weighted_average_hashrate_ths"], 125.0)
        self.assertAlmostEqual(window["integrated_observed_th_hours"], (100 * 300 + 150 * 300) / 3600)
        self.assertEqual(window["missing_device_seconds"], 300.0)
        self.assertEqual(window["device_coverage_ratio"], 0.75)
        for key in reference:
            self.assertAlmostEqual(window[key], reference[key])

    def test_truncated_history_keeps_recent_observation_but_marks_24h_unknown(self):
        start = AS_OF - timedelta(hours=24)
        track = make_track("bounded", start=start)
        recent_start = AS_OF - timedelta(seconds=600)
        recent_samples = make_samples("bounded", recent_start, AS_OF, 100.0)

        result = build([track], {"bounded": {"samples": recent_samples, "truncated": True}})

        device = result["devices"][0]
        self.assertEqual(device["current"]["status"], "FRESH")
        self.assertEqual(device["current"]["hashrate_ths"], 100.0)
        self.assertEqual(device["windows"]["10m"]["status"], "COMPLETE")
        self.assertEqual(device["windows"]["24h"]["status"], "UNKNOWN")
        self.assertEqual(device["windows"]["24h"]["reason"], "SAMPLE_HISTORY_LIMIT_EXCEEDED")

    def test_same_fleet_ids_in_two_organizations_never_mix(self):
        start = AS_OF - timedelta(seconds=600)
        first = make_track("org-a", start=start, organization="org-a", project="miners", machine="same-machine")
        second = make_track("org-b", start=start, organization="org-b", project="miners", machine="same-machine")
        samples = {
            "org-a": make_samples("org-a", start, AS_OF, 50.0),
            "org-b": make_samples("org-b", start, AS_OF, 200.0),
        }

        result = build([first, second], samples)

        self.assertEqual(len(result["fleets"]), 2)
        self.assertEqual({item["windows"]["10m"]["fleet_time_weighted_average_hashrate_ths"] for item in result["fleets"]}, {50.0, 200.0})
        self.assertEqual(len({item["provider_scope_fingerprint"] for item in result["fleets"]}), 2)

    def test_disjoint_uptime_integrates_only_observed_active_slices(self):
        start = AS_OF - timedelta(seconds=600)
        first_end = AS_OF - timedelta(seconds=360)
        second_start = AS_OF - timedelta(seconds=240)
        first = make_track("first", start=start, closed=first_end, machine="machine-1")
        second = make_track("second", start=second_start, machine="machine-2")
        samples = {
            "first": make_samples("first", start, first_end, 100.0),
            "second": make_samples("second", second_start, AS_OF, 200.0),
        }

        result = build([first, second], samples)

        window = result["fleets"][0]["windows"]["10m"]
        self.assertAlmostEqual(window["fleet_time_weighted_average_hashrate_ths"], 150.0)
        self.assertAlmostEqual(window["integrated_observed_th_hours"], 150 * 480 / 3600)
        self.assertAlmostEqual(window["known_active_seconds"], 480.0)
        self.assertAlmostEqual(window["covered_seconds"], 480.0)
        self.assertAlmostEqual(window["window_coverage_ratio"], 0.8)
        self.assertEqual(window["status"], "PARTIAL")

    def test_out_of_order_samples_and_exact_duplicates_are_deterministic(self):
        start = AS_OF - timedelta(seconds=600)
        track = make_track("ordered", start=start)
        samples = make_samples("ordered", start, AS_OF, 100.0)
        samples = list(reversed(samples))
        samples.append(dict(samples[0]))

        result = build([track], {"ordered": samples})

        window = result["devices"][0]["windows"]["10m"]
        self.assertEqual(window["status"], "COMPLETE")
        self.assertAlmostEqual(window["mean_hashrate_ths"], 100.0)
        self.assertEqual(window["timestamp_conflict_count"], 0)

    def test_conflicting_same_timestamp_values_break_interpolation(self):
        start = AS_OF - timedelta(seconds=600)
        track = make_track("conflict", start=start)
        samples = make_samples("conflict", start, AS_OF, 100.0)
        samples.append({**samples[10], "event_id": "conflicting-duplicate", "hashrate_ths": 150.0})

        result = build([track], {"conflict": samples})

        window = result["devices"][0]["windows"]["10m"]
        self.assertGreater(window["timestamp_conflict_count"], 0)
        self.assertLess(window["window_coverage_ratio"], 1.0)
        self.assertEqual(window["status"], "PARTIAL")

    def test_window_boundaries_are_inclusive_but_zero_duration_track_is_unknown(self):
        start = AS_OF - timedelta(seconds=600)
        track = make_track("boundary", start=start)
        samples = make_samples("boundary", start, AS_OF, 50.0)
        zero = make_track("zero", start=AS_OF, closed=AS_OF)

        result = build([track, zero], {"boundary": samples, "zero": make_samples("zero", AS_OF, AS_OF, 99.0)})

        by_id = {item["track_id"]: item for item in result["devices"]}
        self.assertEqual(by_id["boundary"]["windows"]["10m"]["status"], "COMPLETE")
        self.assertEqual(by_id["zero"]["windows"]["10m"]["status"], "UNKNOWN")

    def test_autotune_pool_equivalent_estimate_is_never_a_physical_sample(self):
        start = AS_OF - timedelta(seconds=600)
        track = make_track("autotune", start=start)
        samples = make_samples("autotune", start, AS_OF, 999.0)
        for sample in samples:
            sample["hashrate_semantics"] = "fl4shminer_cuda_autotune_pool_equivalent_estimate"

        result = build([track], {"autotune": samples})

        device = result["devices"][0]
        self.assertEqual(device["current"]["status"], "UNKNOWN")
        self.assertIsNone(device["current"]["hashrate_ths"])
        self.assertEqual(device["windows"]["10m"]["status"], "UNKNOWN")
        self.assertIsNone(device["windows"]["10m"]["mean_hashrate_ths"])

    def test_missing_assignment_anchor_or_provider_scope_stays_unknown_and_isolated(self):
        start = AS_OF - timedelta(seconds=600)
        unanchored = make_track("unanchored", start=start, active_anchor=False)
        unscoped = make_track("unscoped", start=start, organization=None, project=None)
        samples = {
            "unanchored": make_samples("unanchored", start, AS_OF, 100.0),
            "unscoped": make_samples("unscoped", start, AS_OF, 100.0),
        }

        result = build([unanchored, unscoped], samples)

        devices = {item["track_id"]: item for item in result["devices"]}
        self.assertEqual(devices["unanchored"]["identity_status"], "UNKNOWN")
        self.assertEqual(devices["unanchored"]["reason"], "UNVERIFIED_ASSIGNMENT_START")
        self.assertEqual(devices["unscoped"]["provider_scope_status"], "UNKNOWN")
        self.assertEqual(devices["unscoped"]["windows"]["10m"]["status"], "COMPLETE")
        self.assertEqual(len(result["fleets"]), 1)
        self.assertEqual(result["fleets"][0]["provider_scope_status"], "UNKNOWN")
        self.assertIsNone(result["fleets"][0]["windows"]["10m"]["fleet_time_weighted_average_hashrate_ths"])

    def test_overlapping_generations_for_one_physical_device_are_not_double_counted(self):
        start = AS_OF - timedelta(seconds=600)
        boundary = AS_OF - timedelta(seconds=300)
        first = make_track("overlap-a", start=start, closed=AS_OF, machine="same-machine", device="0")
        second = make_track("overlap-b", start=boundary, machine="same-machine", device="0")
        samples = {
            "overlap-a": make_samples("overlap-a", start, AS_OF, 100.0),
            "overlap-b": make_samples("overlap-b", boundary, AS_OF, 100.0),
        }

        result = build([first, second], samples)

        window = result["fleets"][0]["windows"]["10m"]
        self.assertEqual(window["ambiguous_overlap_seconds"], 300.0)
        self.assertEqual(window["ambiguous_device_seconds"], 300.0)
        self.assertEqual(window["observed_device_seconds"], 300.0)
        self.assertEqual(window["device_coverage_ratio"], 0.5)
        self.assertEqual(window["status"], "PARTIAL")
        self.assertAlmostEqual(window["integrated_observed_th_hours"], 100 * 300 / 3600)

    def test_future_observations_are_rejected_and_never_reported_as_current(self):
        start = AS_OF - timedelta(minutes=20)
        track = make_track("future", start=start)
        samples = make_samples("future", AS_OF + timedelta(seconds=30), AS_OF + timedelta(seconds=60), 500.0)

        result = build([track], {"future": samples})

        device = result["devices"][0]
        self.assertEqual(device["current"]["status"], "UNKNOWN")
        self.assertIsNone(device["current"]["hashrate_ths"])
        self.assertGreater(device["windows"]["10m"]["rejected_sample_count"], 0)
        self.assertEqual(device["windows"]["10m"]["status"], "UNKNOWN")

    def test_invalid_track_end_and_conflicting_provider_scope_fail_closed(self):
        start = AS_OF - timedelta(seconds=600)
        bad_lifetime = make_track("bad-lifetime", start=start, closed=start - timedelta(seconds=1))
        conflicted_scope = make_track("scope-conflict", start=start)
        conflicted_scope["provenance_json"] = json.dumps({"provider_scope": {
            "scope_status": "VERIFIED",
            "organization_id": "org-a",
            "organization_name": "org-b",
            "project_id": "miners",
        }})
        samples = {
            "bad-lifetime": make_samples("bad-lifetime", start, AS_OF, 100.0),
            "scope-conflict": make_samples("scope-conflict", start, AS_OF, 100.0),
        }

        result = build([bad_lifetime, conflicted_scope], samples)

        by_id = {item["track_id"]: item for item in result["devices"]}
        self.assertEqual(by_id["bad-lifetime"]["identity_status"], "UNKNOWN")
        self.assertEqual(by_id["bad-lifetime"]["reason"], "TRACK_END_PRECEDES_START")
        self.assertEqual(by_id["scope-conflict"]["provider_scope_status"], "UNKNOWN")
        self.assertEqual(by_id["scope-conflict"]["windows"]["10m"]["status"], "COMPLETE")
        self.assertEqual(len(result["fleets"]), 1)
        self.assertEqual(result["fleets"][0]["provider_scope_status"], "UNKNOWN")

    def test_rates_and_configuration_reject_nonfinite_or_invalid_values(self):
        start = AS_OF - timedelta(seconds=600)
        track = make_track("invalid", start=start)
        samples = make_samples("invalid", start, AS_OF, 100.0)
        samples[0]["hashrate_ths"] = math.inf
        with self.assertRaises(ValueError):
            build_hashrate_rollups([track], {"invalid": samples}, as_of_utc=AS_OF, maximum_sample_gap_seconds=float("nan"), minimum_window_coverage_ratio=0.8)
        with self.assertRaises(ValueError):
            build_hashrate_rollups([track], {"invalid": samples}, as_of_utc="2026-10-18T12:00:00", maximum_sample_gap_seconds=30, minimum_window_coverage_ratio=0.8)
        result = build([track], {"invalid": samples})
        self.assertGreater(result["devices"][0]["windows"]["10m"]["rejected_sample_count"], 0)


if __name__ == "__main__":
    unittest.main()
