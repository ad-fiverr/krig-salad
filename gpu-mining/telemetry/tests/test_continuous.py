from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.continuous import ContinuousMonitor
from collector.gpu_identity import normalize_gpu_identity
from collector.guard_store import GuardStore
from collector.guards import HashGuardPolicy, evaluate_hash_floor


BASE = datetime(2026, 10, 8, tzinfo=timezone.utc)


def at(seconds: int | float) -> str:
    return (BASE + timedelta(seconds=seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")


def make_policy(*, test_floor_130: bool = False, cooldown: int | None = 300, maximum: int | None = 2) -> HashGuardPolicy:
    floors = {
        "RTX 5090|desktop|salad_json_log_gpu_class_name": 350,
        "RTX 5080|desktop|salad_json_log_gpu_class_name": 209,
        "RTX 5090|laptop|salad_json_log_gpu_class_name": 120,
        "RTX 5080|laptop|salad_json_log_gpu_class_name": 120,
    }
    if test_floor_130:
        floors = {"RTX 5090|laptop|synthetic_test_fixture": 130}
    return HashGuardPolicy(
        gpu_floors_ths=floors,
        warmup_seconds=90,
        hash_window_seconds=120,
        minimum_samples_per_window=10,
        expected_sample_interval_seconds=10,
        maximum_sample_gap_seconds=30,
        minimum_window_coverage_ratio=0.8,
        consecutive_bad_windows=2,
        reallocation_cooldown_seconds=cooldown,
        max_reallocations_per_run=maximum,
        reevaluation_interval_seconds=30,
    )


def make_sample(
    seconds: int,
    hashrate: float,
    *,
    scenario: str = "a",
    model: str = "RTX 5090",
    variant: str = "laptop",
    identity_source: str = "salad_json_log_gpu_class_name",
    identity_verified: bool = True,
    reallocation_history_known: bool = True,
    reallocation_count: int = 0,
    machine_id: str | None = None,
    instance_id: str | None = None,
) -> dict:
    raw_model = f"NVIDIA GeForce {model} {variant.title()} GPU"
    identity = normalize_gpu_identity(
        raw_model,
        identity_source=identity_source,
        identity_verified=identity_verified,
    )
    return {
        "event_type": "gpu_sample",
        "event_id": f"sample-{scenario}-{seconds}-{hashrate}",
        "fleet_id": "fleet-test",
        "worker_id": "kryptex-shared-worker",
        "allocation_id": f"allocation-{scenario}",
        "assignment_id": f"allocation-{scenario}-v1",
        "run_id": f"run-{scenario}",
        "machine_id": machine_id or f"machine-{scenario}",
        "instance_id": instance_id or f"instance-{scenario}",
        "device_namespace": "fl4shminer_device",
        "device_id": "0",
        "occurred_at_utc": at(seconds),
        "assignment_started_at_utc": at(0),
        "start_anchor_verified": True,
        "hashrate_ths": hashrate,
        "hashrate_semantics": "fl4shminer_device_reported",
        "hashrate_source": "synthetic_test: local device rate",
        "gpu_identity": identity,
        "reallocation_history_known": reallocation_history_known,
        "reallocation_count": reallocation_count if reallocation_history_known else None,
        "provenance": {"source": "synthetic_test_fixture", "event_source": "fixture"},
    }


def series(duration: int, segments: list[tuple[int, int | None, float]], **kwargs) -> list[dict]:
    output = []
    for seconds in range(0, duration + 1, 10):
        rate = next(value for start, end, value in segments if start <= seconds and (end is None or seconds < end))
        output.append(make_sample(seconds, rate, **kwargs))
    return output


def run_series(events: list[dict], policy: HashGuardPolicy):
    store = GuardStore(":memory:")
    monitor = ContinuousMonitor(store, policy)
    result = monitor.ingest(events)
    tracks = store.track_rows()
    assert len(tracks) == 1
    return store, monitor, result, tracks[0]


class ContinuousMonitorTests(unittest.TestCase):
    def test_a_sustained_twenty_ths_is_classified_after_warmup_and_two_windows(self):
        store, _, result, track = run_series(series(240, [(0, None, 20)], scenario="a"), make_policy())
        try:
            latest = store.last_evaluation(track["track_id"])
            self.assertEqual(latest["decision"], "WOULD_REALLOCATE")
            self.assertEqual(latest["hash_health"], "BELOW_CONFIGURED_FLOOR")
            types = [event["event_type"] for event in store.audit_rows(track_id=track["track_id"])]
            self.assertIn("FLOOR_BREACH_DETECTED", types)
            self.assertIn("SUSTAINED_LOW_HASHRATE", types)
            self.assertIn("REALLOCATION_RECOMMENDED", types)
            self.assertFalse(result["actions_performed"])
        finally:
            store.close()

    def test_b_healthy_hour_passes_without_economic_claim(self):
        store, _, _, track = run_series(
            series(3600, [(0, 60, 170), (60, None, 165)], scenario="b"), make_policy()
        )
        try:
            latest = store.last_evaluation(track["track_id"])
            self.assertEqual(latest["decision"], "PASS")
            self.assertEqual(latest["hash_health"], "MEETS_CONFIGURED_FLOOR")
            self.assertEqual(store.audit_rows(track_id=track["track_id"]), [])
        finally:
            store.close()

    def test_c_late_degradation_transitions_after_thirty_minutes_and_deduplicates_recommendation(self):
        store, _, _, track = run_series(
            series(1980, [(0, 1800, 170), (1800, None, 90)], scenario="c"), make_policy()
        )
        try:
            evaluations = store.evaluations_for_track(track["track_id"])
            at_30m = [item for item in evaluations if item["elapsed_seconds"] == 1800][-1]
            self.assertEqual(at_30m["decision"], "PASS")
            low = [item for item in evaluations if item["hash_health"] == "BELOW_CONFIGURED_FLOOR"]
            self.assertTrue(low)
            self.assertGreater(low[0]["elapsed_seconds"], 1800)
            self.assertEqual(evaluations[-1]["decision"], "WOULD_WAIT")
            event_types = [event["event_type"] for event in store.audit_rows(track_id=track["track_id"])]
            self.assertEqual(event_types.count("REALLOCATION_RECOMMENDED"), 1)
            self.assertIn("SUSTAINED_LOW_HASHRATE", event_types)
        finally:
            store.close()

    def test_d_twenty_second_drop_recovers_without_reallocation(self):
        events = series(2400, [(0, 1800, 150), (1800, 1820, 90), (1820, None, 155)], scenario="d")
        store, _, _, track = run_series(events, make_policy())
        try:
            latest = store.last_evaluation(track["track_id"])
            self.assertEqual(latest["decision"], "PASS")
            event_types = [event["event_type"] for event in store.audit_rows(track_id=track["track_id"])]
            self.assertNotIn("SUSTAINED_LOW_HASHRATE", event_types)
            self.assertNotIn("REALLOCATION_RECOMMENDED", event_types)
        finally:
            store.close()

    def test_e_125_is_low_only_under_test_only_130_override(self):
        events = series(
            240, [(0, None, 125)], scenario="e", identity_source="synthetic_test_fixture"
        )
        store, _, _, track = run_series(events, make_policy(test_floor_130=True))
        try:
            latest = store.last_evaluation(track["track_id"])
            self.assertEqual(latest["decision"], "WOULD_REALLOCATE")
            self.assertEqual(latest["result"]["details"]["gpu_floor_ths"], 130)
            self.assertEqual(make_policy().gpu_floors_ths["RTX 5090|laptop|salad_json_log_gpu_class_name"], 120)
        finally:
            store.close()

    def test_f_and_g_desktop_thresholds_remain_independent(self):
        under, _, _, under_track = run_series(
            series(240, [(0, None, 320)], scenario="f", variant="desktop"), make_policy()
        )
        above, _, _, above_track = run_series(
            series(240, [(0, None, 215)], scenario="g", model="RTX 5080", variant="desktop"), make_policy()
        )
        try:
            self.assertEqual(under.last_evaluation(under_track["track_id"])["decision"], "WOULD_REALLOCATE")
            self.assertEqual(above.last_evaluation(above_track["track_id"])["decision"], "PASS")
        finally:
            under.close()
            above.close()

    def test_duration_weighting_duplicate_import_and_restart_are_deterministic(self):
        policy = make_policy()
        # An inserted 5-second observation must contribute 5 seconds, not one
        # full sample vote; duplicated same-timestamp records remain deduplicated.
        identity = normalize_gpu_identity(
            "NVIDIA GeForce RTX 5090 Laptop GPU",
            identity_source="salad_json_log_gpu_class_name",
            identity_verified=True,
        )
        irregular = [
            {"elapsed_seconds": seconds, "hashrate_ths": rate, "hashrate_semantics": "fl4shminer_device_reported", "hashrate_source": "test"}
            for seconds, rate in [(0, 150), (5, 0), (10, 150), (20, 150), (30, 150), (40, 150), (50, 150), (60, 150), (70, 150), (80, 150), (90, 150), (100, 150), (110, 150)]
        ]
        weighted_policy = HashGuardPolicy(
            gpu_floors_ths={"RTX 5090|laptop|salad_json_log_gpu_class_name": 120},
            warmup_seconds=0,
            hash_window_seconds=120,
            minimum_samples_per_window=10,
            expected_sample_interval_seconds=10,
            maximum_sample_gap_seconds=30,
            minimum_window_coverage_ratio=0.8,
            consecutive_bad_windows=1,
            reallocation_cooldown_seconds=0,
            max_reallocations_per_run=1,
        )
        weighted = evaluate_hash_floor(
            "RTX 5090 Laptop", irregular + [irregular[1]], weighted_policy,
            gpu_identity=identity, reallocations_per_run=0, now_elapsed_seconds=120,
        )
        last_window = weighted.details["windows"][-1]
        self.assertTrue(last_window["valid"])
        self.assertEqual(last_window["covered_seconds"], 120)
        self.assertAlmostEqual(last_window["mean_hashrate_ths"], 143.75)

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "monitor.sqlite"
            first_events = series(240, [(0, None, 20)], scenario="restart")
            store = GuardStore(state)
            monitor = ContinuousMonitor(store, policy)
            first = monitor.ingest(first_events)
            track_id = store.track_rows()[0]["track_id"]
            before = len(store.audit_rows(track_id=track_id))
            store.close()

            reopened = GuardStore(state)
            restarted = ContinuousMonitor(reopened, policy)
            duplicate = restarted.ingest(first_events)
            self.assertEqual(duplicate["duplicate_sample_count"], len(first_events))
            self.assertEqual(len(reopened.audit_rows(track_id=track_id)), before)
            appended = restarted.ingest([make_sample(seconds, 20, scenario="restart") for seconds in (250, 260, 270)])
            self.assertEqual(appended["inserted_sample_count"], 3)
            self.assertFalse(appended["actions_performed"])
            self.assertEqual(len([event for event in reopened.audit_rows(track_id=track_id) if event["event_type"] == "REALLOCATION_RECOMMENDED"]), 1)
            reopened.close()

    def test_incomplete_identity_coverage_and_stale_telemetry_fail_closed(self):
        events = series(240, [(0, None, 20)], scenario="quality")
        events[5]["gpu_identity"]["identity_verified"] = False
        store, _, _, track = run_series(events, make_policy())
        try:
            latest = store.last_evaluation(track["track_id"])
            self.assertEqual(latest["decision"], "INSUFFICIENT_DATA")
        finally:
            store.close()

        # Direct V1 evaluation distinguishes uncovered windows from stale tails.
        identity = normalize_gpu_identity(
            "NVIDIA GeForce RTX 5090 Laptop GPU",
            identity_source="salad_json_log_gpu_class_name",
            identity_verified=True,
        )
        policy = make_policy()
        samples = [
            {"elapsed_seconds": seconds, "hashrate_ths": 150, "hashrate_semantics": "krig_device_reported", "hashrate_source": "test"}
            for seconds in range(90, 211, 10) if seconds not in {130, 140, 150, 160}
        ]
        uncovered = evaluate_hash_floor("RTX 5090 Laptop", samples, policy, gpu_identity=identity, reallocations_per_run=0, now_elapsed_seconds=210)
        self.assertEqual(uncovered.decision, "INSUFFICIENT_DATA")
        stale = evaluate_hash_floor("RTX 5090 Laptop", samples, policy, gpu_identity=identity, reallocations_per_run=0, now_elapsed_seconds=250)
        self.assertEqual(stale.decision, "TELEMETRY_STALE")

    def test_assignment_change_closes_prior_track_and_unknown_reallocation_history_blocks_action(self):
        store = GuardStore(":memory:")
        monitor = ContinuousMonitor(store, make_policy())
        first = make_sample(0, 20, scenario="replacement")
        monitor.ingest([first])
        first_track = store.track_rows()[0]["track_id"]
        replacement = make_sample(
            10, 20, scenario="replacement", machine_id="machine-replacement-2", instance_id="instance-replacement-2"
        )
        outcome = monitor.ingest([replacement])
        rows = store.track_rows()
        self.assertEqual(len(rows), 2)
        old = store.get_track(first_track)
        self.assertIsNotNone(old["closed_at_utc"])
        self.assertIn("ALLOCATION_TERMINATED", [event["event_type"] for event in store.audit_rows(track_id=first_track)])
        self.assertEqual(outcome["terminated_track_ids"], [first_track])
        store.close()

        unknown_store, _, _, unknown_track = run_series(
            series(240, [(0, None, 20)], scenario="unknown-history", reallocation_history_known=False),
            make_policy(),
        )
        try:
            latest = unknown_store.last_evaluation(unknown_track["track_id"])
            self.assertEqual(latest["hash_health"], "BELOW_CONFIGURED_FLOOR")
            self.assertEqual(latest["decision"], "INSUFFICIENT_DATA")
            self.assertNotIn("REALLOCATION_RECOMMENDED", [event["event_type"] for event in unknown_store.audit_rows(track_id=unknown_track["track_id"])])
        finally:
            unknown_store.close()

    def test_provider_preemption_closes_the_matching_assignment_track(self):
        store = GuardStore(":memory:")
        monitor = ContinuousMonitor(store, make_policy())
        sample = make_sample(0, 150, scenario="preempted")
        monitor.ingest([sample])
        track_id = store.track_rows()[0]["track_id"]
        terminal = {
            "event_type": "provider_lifecycle_observation",
            "event_id": "provider-preempted-1",
            "reported_state": "preempted",
            "occurred_at_utc": at(240),
            "allocation_id": sample["allocation_id"],
            "assignment_id": sample["assignment_id"],
            "machine_id": sample["machine_id"],
            "instance_id": sample["instance_id"],
            "event_source": "Json Log message",
            "billing_status": "UNKNOWN",
            "provenance": {"source": "synthetic_test_fixture"},
        }
        result = monitor.ingest([terminal])
        closed = store.get_track(track_id)
        try:
            self.assertEqual(result["terminated_track_ids"], [track_id])
            self.assertEqual(closed["terminal_reason"], "provider_lifecycle:preempted")
            self.assertIn("ALLOCATION_TERMINATED", [item["event_type"] for item in store.audit_rows(track_id=track_id)])
            self.assertFalse(result["actions_performed"])
        finally:
            store.close()

    def test_unscoped_terminal_lifecycle_is_audited_but_closes_no_assignment(self):
        store = GuardStore(":memory:")
        monitor = ContinuousMonitor(store, make_policy())
        first = make_sample(0, 150, scenario="unscoped-a", machine_id="machine-a", instance_id="instance-a")
        second = make_sample(0, 160, scenario="unscoped-b", machine_id="machine-b", instance_id="instance-b")
        # A terminal event with no allocation, machine, or instance identity
        # must never act across two separate active assignments.
        second["allocation_id"] = "allocation-unscoped-b"
        second["assignment_id"] = "assignment-unscoped-b"
        monitor.ingest([first, second])
        tracks_before = store.track_rows(active_only=True)
        event = {
            "event_type": "provider_lifecycle_observation",
            "event_id": "terminal-without-assignment-identity",
            "reported_state": "preempted",
            "occurred_at_utc": at(240),
            "event_source": "Json Log message",
            "billing_status": "UNKNOWN",
        }
        outcome = monitor.ingest([event])
        try:
            self.assertEqual(len(tracks_before), 2)
            self.assertEqual(outcome["terminated_track_ids"], [])
            self.assertEqual(len(store.track_rows(active_only=True)), 2)
            unscoped = [item for item in store.audit_rows() if item["event_type"] == "UNSCOPED_TERMINAL_LIFECYCLE"]
            self.assertEqual(len(unscoped), 1)
            self.assertIsNone(unscoped[0]["track_id"])
        finally:
            store.close()

    def test_partial_machine_terminal_matching_multiple_instances_closes_none(self):
        store = GuardStore(":memory:")
        monitor = ContinuousMonitor(store, make_policy())
        first = make_sample(0, 150, scenario="partial-terminal-a", machine_id="shared-machine", instance_id="instance-a")
        second = make_sample(0, 160, scenario="partial-terminal-b", machine_id="shared-machine", instance_id="instance-b")
        monitor.ingest([first, second])
        terminal = {
            "event_type": "provider_lifecycle_observation",
            "event_id": "terminal-machine-only-matches-two-instances",
            "reported_state": "preempted",
            "occurred_at_utc": at(240),
            "machine_id": "shared-machine",
            "event_source": "Json Log message",
        }
        outcome = monitor.ingest([terminal])
        try:
            self.assertEqual(len(store.track_rows(active_only=True)), 2)
            self.assertEqual(outcome["terminated_track_ids"], [])
            self.assertTrue(outcome["lifecycle_event_count"] == 1)
            audits = [item for item in store.audit_rows() if item["event_type"] == "UNSCOPED_TERMINAL_LIFECYCLE"]
            self.assertEqual(len(audits), 1)
            self.assertEqual(audits[0]["payload"]["reason"], "partial_identity_matches_multiple_assignments")
            self.assertEqual(audits[0]["payload"]["tracks_closed"], 0)
        finally:
            store.close()

    def test_health_status_moves_to_unknown_when_latest_evaluation_loses_quality(self):
        events = series(240, [(0, None, 165)], scenario="stale-health")
        store, monitor, _, track = run_series(events, make_policy())
        try:
            self.assertEqual(store.get_track(track["track_id"])["hash_health"], "MEETS_CONFIGURED_FLOOR")
            stale = monitor.evaluate_track(track["track_id"], at(300))
            self.assertEqual(stale["decision"], "TELEMETRY_STALE")
            self.assertEqual(store.get_track(track["track_id"])["hash_health"], "UNKNOWN")
            self.assertEqual(store.last_evaluation(track["track_id"])["hash_health"], "UNKNOWN")
        finally:
            store.close()

    def test_health_status_moves_from_low_to_unknown_when_window_has_timestamp_conflict(self):
        events = series(240, [(0, None, 20)], scenario="low-to-unknown")
        store, monitor, _, track = run_series(events, make_policy())
        try:
            self.assertEqual(store.get_track(track["track_id"])["hash_health"], "BELOW_CONFIGURED_FLOOR")
            duplicate_a = make_sample(250, 20, scenario="low-to-unknown")
            duplicate_b = make_sample(250, 21, scenario="low-to-unknown")
            duplicate_b["event_id"] = "low-to-unknown-conflicting-250"
            monitor.ingest([duplicate_a, duplicate_b])
            latest = monitor.evaluate_track(track["track_id"], at(270))
            self.assertEqual(latest["hash_health"], "UNKNOWN")
            self.assertEqual(latest["decision"], "INSUFFICIENT_DATA")
            self.assertEqual(store.get_track(track["track_id"])["hash_health"], "UNKNOWN")
            self.assertEqual(store.last_evaluation(track["track_id"])["hash_health"], "UNKNOWN")
        finally:
            store.close()

    def test_health_status_moves_from_low_to_unknown_when_later_window_coverage_is_insufficient(self):
        events = series(240, [(0, None, 20)], scenario="low-to-insufficient-coverage")
        store, monitor, _, track = run_series(events, make_policy())
        try:
            self.assertEqual(store.get_track(track["track_id"])["hash_health"], "BELOW_CONFIGURED_FLOOR")
            late_sample = make_sample(300, 20, scenario="low-to-insufficient-coverage")
            monitor.ingest([late_sample])
            latest = store.last_evaluation(track["track_id"])
            self.assertEqual(latest["hash_health"], "UNKNOWN")
            self.assertEqual(latest["decision"], "INSUFFICIENT_DATA")
            last_window = latest["result"]["details"]["windows"][-1]
            self.assertFalse(last_window["valid"])
            self.assertLess(last_window["coverage_ratio"], 0.8)
            self.assertEqual(store.get_track(track["track_id"])["hash_health"], "UNKNOWN")
        finally:
            store.close()

    def test_assignment_id_generation_change_on_same_machine_closes_old_track(self):
        store = GuardStore(":memory:")
        monitor = ContinuousMonitor(store, make_policy())
        old_events = series(
            240, [(0, None, 160)], scenario="generation-old",
            machine_id="machine-stable", instance_id="instance-stable",
        )
        first = old_events[0]
        monitor.ingest(old_events)
        old_track_id = store.track_rows()[0]["track_id"]
        replacement = make_sample(250, 155, scenario="generation-new", machine_id="machine-stable", instance_id="instance-stable")
        replacement["allocation_id"] = first["allocation_id"]
        replacement["assignment_id"] = "allocation-generation-2"
        replacement["run_id"] = "run-generation-2"
        replacement["assignment_started_at_utc"] = at(250)
        result = monitor.ingest([replacement])
        tracks = store.track_rows()
        try:
            self.assertEqual(len(tracks), 2)
            old = store.get_track(old_track_id)
            self.assertIsNotNone(old["closed_at_utc"])
            self.assertEqual(old["last_decision"], "PASS")
            new_track = next(item for item in tracks if item["track_id"] != old_track_id)
            self.assertIsNone(new_track["closed_at_utc"])
            self.assertEqual(new_track["replaced_track_id"], old_track_id)
            self.assertEqual(result["terminated_track_ids"], [old_track_id])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
