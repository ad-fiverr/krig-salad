from __future__ import annotations

import sys
import json
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.guards import (  # noqa: E402
    HashGuardPolicy,
    evaluate_economics,
    evaluate_hash_floor,
    evaluate_provider_state_mismatch,
)
from collector.gpu_identity import normalize_gpu_identity  # noqa: E402


def configured_policy(**overrides):
    values = {
        "gpu_floors_ths": {
            "RTX 5090|desktop|salad_json_log_gpu_class_name": 350,
            "RTX 5080|desktop|salad_json_log_gpu_class_name": 209,
        },
        "warmup_seconds": 0,
        "hash_window_seconds": 60,
        "minimum_samples_per_window": 2,
        "expected_sample_interval_seconds": 30,
        "maximum_sample_gap_seconds": 30,
        "minimum_window_coverage_ratio": 1.0,
        "consecutive_bad_windows": 2,
        "reallocation_cooldown_seconds": 120,
        "max_reallocations_per_run": 2,
    }
    values.update(overrides)
    return HashGuardPolicy(**values)


def gpu_identity(model="RTX 5090", form_factor="desktop", source="salad_json_log_gpu_class_name", verified=True):
    model = next((candidate for candidate in ("RTX 5090", "RTX 5080", "RTX 4090", "RTX 3090") if candidate in model), model)
    return normalize_gpu_identity(
        f"NVIDIA GeForce {model} {form_factor.title()} GPU",
        identity_source=source,
        identity_verified=verified,
    )


def device_samples(samples, *, source="test_device_log"):
    return [
        {**sample, "hashrate_semantics": "krig_device_reported", "hashrate_source": source}
        for sample in samples
    ]


def evaluate_floor(model, samples, policy=None, **kwargs):
    return evaluate_hash_floor(
        model,
        device_samples(samples),
        policy or configured_policy(),
        gpu_identity=gpu_identity(model),
        **kwargs,
    )


class HashGuardTests(unittest.TestCase):
    def test_rtx_5090_uses_350_ths_floor(self):
        result = evaluate_floor(
            "NVIDIA GeForce RTX 5090",
            [{"elapsed_seconds": 0, "hashrate_ths": 360}, {"elapsed_seconds": 30, "hashrate_ths": 355}],
            configured_policy(),
            reallocations_per_run=0,
            now_elapsed_seconds=60,
        )
        self.assertEqual(result.decision, "PASS")
        self.assertEqual(result.details["gpu_floor_ths"], 350)

    def test_rtx_5080_uses_209_ths_floor(self):
        result = evaluate_floor(
            "RTX 5080",
            [{"elapsed_seconds": 0, "hashrate_ths": 210}, {"elapsed_seconds": 30, "hashrate_ths": 212}],
            configured_policy(),
            reallocations_per_run=0,
            now_elapsed_seconds=60,
        )
        self.assertEqual(result.decision, "PASS")
        self.assertEqual(result.details["gpu_floor_ths"], 209)

    def test_rtx_3090_has_no_invented_floor(self):
        result = evaluate_hash_floor("RTX 3090", [], configured_policy(), reallocations_per_run=0)
        self.assertEqual(result.decision, "INSUFFICIENT_DATA")

    def test_rtx_5090_laptop_never_inherits_desktop_floor(self):
        laptop = gpu_identity("RTX 5090", "laptop")
        result = evaluate_hash_floor(
            "RTX 5090 Laptop",
            device_samples([{"elapsed_seconds": 0, "hashrate_ths": 150}, {"elapsed_seconds": 30, "hashrate_ths": 150}]),
            configured_policy(),
            gpu_identity=laptop,
            reallocations_per_run=0,
            now_elapsed_seconds=60,
        )
        self.assertEqual(result.decision, "NO_FLOOR_CONFIGURED")
        self.assertEqual(result.details["hash_health"], "UNCONFIGURED")

    def test_ambiguous_form_factor_or_unverified_source_has_no_floor(self):
        ambiguous = normalize_gpu_identity(
            "NVIDIA GeForce RTX 5090 GPU",
            identity_source="krig_text_log_gpu_model",
            identity_verified=False,
        )
        result = evaluate_hash_floor(
            "RTX 5090",
            device_samples([{"elapsed_seconds": 0, "hashrate_ths": 20}, {"elapsed_seconds": 30, "hashrate_ths": 20}]),
            configured_policy(),
            gpu_identity=ambiguous,
            reallocations_per_run=0,
            now_elapsed_seconds=60,
        )
        self.assertEqual(result.decision, "INSUFFICIENT_DATA")

    def test_one_low_instantaneous_sample_cannot_trigger_reallocation(self):
        result = evaluate_floor(
            "RTX 5090",
            [{"elapsed_seconds": 10, "hashrate_ths": 100}],
            configured_policy(consecutive_bad_windows=1),
            reallocations_per_run=0,
            now_elapsed_seconds=20,
        )
        self.assertNotEqual(result.decision, "WOULD_REALLOCATE")
        self.assertEqual(result.decision, "INSUFFICIENT_DATA")

    def test_required_consecutive_bad_windows_trigger_dry_run_reallocation(self):
        samples = [
            {"elapsed_seconds": 0, "hashrate_ths": 300},
            {"elapsed_seconds": 30, "hashrate_ths": 310},
            {"elapsed_seconds": 60, "hashrate_ths": 320},
            {"elapsed_seconds": 90, "hashrate_ths": 330},
        ]
        result = evaluate_floor("RTX 5090", samples, configured_policy(), reallocations_per_run=0, now_elapsed_seconds=120)
        self.assertEqual(result.decision, "WOULD_REALLOCATE")
        self.assertTrue(result.details["action_is_dry_run_only"])

    def test_missing_hash_timing_policy_blocks_reallocation(self):
        policy = configured_policy(warmup_seconds=None, hash_window_seconds=None, minimum_samples_per_window=None, consecutive_bad_windows=None, reallocation_cooldown_seconds=None, max_reallocations_per_run=None)
        result = evaluate_floor("RTX 5090", [], policy, reallocations_per_run=0)
        self.assertEqual(result.decision, "INSUFFICIENT_DATA")
        self.assertIn("warmup_seconds", result.details["missing_policy"])

    def test_cooldown_prevents_immediate_reallocation(self):
        samples = [
            {"elapsed_seconds": 0, "hashrate_ths": 300},
            {"elapsed_seconds": 30, "hashrate_ths": 310},
            {"elapsed_seconds": 60, "hashrate_ths": 320},
            {"elapsed_seconds": 90, "hashrate_ths": 330},
        ]
        result = evaluate_floor("RTX 5090", samples, configured_policy(), reallocations_per_run=1, seconds_since_last_reallocation=30, now_elapsed_seconds=120)
        self.assertEqual(result.decision, "WOULD_WAIT")

    def test_max_reallocations_transitions_to_stop(self):
        samples = [
            {"elapsed_seconds": 0, "hashrate_ths": 300},
            {"elapsed_seconds": 30, "hashrate_ths": 310},
            {"elapsed_seconds": 60, "hashrate_ths": 320},
            {"elapsed_seconds": 90, "hashrate_ths": 330},
        ]
        result = evaluate_floor("RTX 5090", samples, configured_policy(), reallocations_per_run=2, now_elapsed_seconds=120)
        self.assertEqual(result.decision, "WOULD_STOP")
        self.assertEqual(result.details["action_reason"], "GPU_CLASS_UNDERPERFORMING")

    def test_synthetic_5090_laptop_low_rate_requires_warmup_coverage_and_full_windows(self):
        fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "guards" / "rtx5090_laptop_20_ths_synthetic.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(fixture["fixture_status"], "SYNTHETIC_TEST_ONLY")
        policy = HashGuardPolicy(**fixture["policy"])
        kwargs = {"gpu_identity": fixture["gpu_identity"], "reallocations_per_run": 0}
        result = evaluate_hash_floor(
            fixture["gpu_identity"]["raw_model"], fixture["samples"], policy,
            now_elapsed_seconds=1080, **kwargs,
        )
        self.assertEqual(result.decision, "WOULD_REALLOCATE")
        self.assertEqual(result.details["hash_health"], "BELOW_CONFIGURED_FLOOR")
        self.assertEqual(len(result.details["windows"]), 3)
        self.assertTrue(all(window["valid"] and window["coverage_ratio"] == 1.0 for window in result.details["windows"]))

        before_warmup = evaluate_hash_floor(
            fixture["gpu_identity"]["raw_model"], fixture["samples"], policy,
            now_elapsed_seconds=179, **kwargs,
        )
        self.assertEqual(before_warmup.decision, "INSUFFICIENT_DATA")

        one_bad_window_samples = [sample for sample in fixture["samples"] if sample["elapsed_seconds"] <= 420]
        one_bad_window = evaluate_hash_floor(
            fixture["gpu_identity"]["raw_model"], one_bad_window_samples, policy,
            now_elapsed_seconds=480, **kwargs,
        )
        self.assertEqual(one_bad_window.decision, "WOULD_WAIT")
        self.assertEqual(one_bad_window.details["consecutive_bad_windows_observed"], 1)

        missing_sample = [sample for sample in fixture["samples"] if sample["elapsed_seconds"] != 900]
        uncovered = evaluate_hash_floor(
            fixture["gpu_identity"]["raw_model"], missing_sample, policy,
            now_elapsed_seconds=1080, **kwargs,
        )
        self.assertEqual(uncovered.decision, "INSUFFICIENT_DATA")

        no_coverage_policy = HashGuardPolicy(**{**fixture["policy"], "minimum_window_coverage_ratio": None})
        unconfigured = evaluate_hash_floor(
            fixture["gpu_identity"]["raw_model"], fixture["samples"], no_coverage_policy,
            now_elapsed_seconds=1080, **kwargs,
        )
        self.assertEqual(unconfigured.decision, "INSUFFICIENT_DATA")


class ProviderMismatchTests(unittest.TestCase):
    def test_running_plus_allocating_with_stale_telemetry_is_detected_after_grace(self):
        within_grace = evaluate_provider_state_mismatch(
            container_group_state="running", instance_state="allocating", miner_telemetry_state="stale",
            mismatch_duration_seconds=20, grace_period_seconds=30,
        )
        self.assertEqual(within_grace.decision, "INSUFFICIENT_DATA")
        confirmed = evaluate_provider_state_mismatch(
            container_group_state="running", instance_state="allocating", miner_telemetry_state="stale",
            mismatch_duration_seconds=45, grace_period_seconds=30,
        )
        self.assertEqual(confirmed.decision, "PROVIDER_STATE_MISMATCH")
        self.assertEqual(confirmed.details["billing_status"], "UNKNOWN")

    def test_provider_mismatch_can_return_only_configured_dry_run_action(self):
        result = evaluate_provider_state_mismatch(
            container_group_state="running", instance_state="creating", miner_telemetry_state="missing",
            mismatch_duration_seconds=90, grace_period_seconds=30, confirmed_action="WOULD_STOP",
        )
        self.assertEqual(result.decision, "WOULD_STOP")
        self.assertTrue(result.details["action_is_dry_run_only"])

    def test_provider_mismatch_grace_period_has_no_default(self):
        result = evaluate_provider_state_mismatch(
            container_group_state="running", instance_state="downloading", miner_telemetry_state="missing",
            mismatch_duration_seconds=600, grace_period_seconds=None,
        )
        self.assertEqual(result.decision, "INSUFFICIENT_DATA")


class EconomicGuardTests(unittest.TestCase):
    def test_healthy_hashrate_with_bad_economics_stops_instead_of_reallocating(self):
        result = evaluate_economics(
            rental_usd_per_hour=0.117,
            target_profit_over_rental_cost_fraction=0,
            observed_productive_ratio=1,
            net_revenue_usd_per_ths_hour=0.0003,
            observed_hashrate_ths=370,
        )
        self.assertEqual(result.decision, "WOULD_STOP")
        self.assertAlmostEqual(result.details["economic_required_ths"], 390)
        self.assertNotEqual(result.decision, "WOULD_REALLOCATE")
        self.assertTrue(result.details["action_is_dry_run_only"])

    def test_missing_economic_input_is_unknown_not_zero(self):
        result = evaluate_economics(
            rental_usd_per_hour=0.117,
            target_profit_over_rental_cost_fraction=None,
            observed_productive_ratio=1,
            net_revenue_usd_per_ths_hour=0.0003,
            observed_hashrate_ths=370,
        )
        self.assertEqual(result.decision, "ECONOMICS_UNKNOWN")
        self.assertIn("target_profit_over_rental_cost_fraction", result.details["missing_inputs"])

    def test_observed_productive_ratio_adjusts_economic_threshold(self):
        result = evaluate_economics(
            rental_usd_per_hour=0.117,
            target_profit_over_rental_cost_fraction=0,
            observed_productive_ratio=0.5,
            net_revenue_usd_per_ths_hour=0.0003,
            observed_hashrate_ths=800,
        )
        self.assertEqual(result.decision, "PASS")
        self.assertAlmostEqual(result.details["economic_required_ths"], 780)

    def test_positive_profit_target_is_margin_over_rental_cost(self):
        result = evaluate_economics(
            rental_usd_per_hour=0.12,
            target_profit_over_rental_cost_fraction=0.2,
            observed_productive_ratio=1,
            net_revenue_usd_per_ths_hour=0.0003,
            observed_hashrate_ths=500,
        )
        self.assertEqual(result.decision, "PASS")
        self.assertAlmostEqual(result.details["required_hourly_revenue_usd"], 0.144)
        self.assertAlmostEqual(result.details["economic_required_ths"], 480)

    def test_profit_target_of_one_is_valid_cost_markup(self):
        result = evaluate_economics(
            rental_usd_per_hour=0.12,
            target_profit_over_rental_cost_fraction=1,
            observed_productive_ratio=1,
            net_revenue_usd_per_ths_hour=0.0003,
            observed_hashrate_ths=500,
        )
        self.assertEqual(result.decision, "WOULD_STOP")
        self.assertAlmostEqual(result.details["required_hourly_revenue_usd"], 0.24)

    def test_negative_profit_target_is_invalid(self):
        result = evaluate_economics(
            rental_usd_per_hour=0.12,
            target_profit_over_rental_cost_fraction=-0.01,
            observed_productive_ratio=1,
            net_revenue_usd_per_ths_hour=0.0003,
            observed_hashrate_ths=500,
        )
        self.assertEqual(result.decision, "ECONOMICS_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
