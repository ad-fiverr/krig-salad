"""Deterministic offline tests for polling latency and cost sensitivities."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.startup_latency import (  # noqa: E402
    estimate_operator_exposure,
    polling_comparison,
    polling_scenario,
    reaction_exposure_comparison,
)


class StartupLatencyTests(unittest.TestCase):
    def test_15_and_30_second_detection_and_base_request_rates(self):
        thirty, fifteen = polling_comparison((30, 15), organization_count=3)
        self.assertEqual(thirty["maximum_detection_latency_seconds"], 30)
        self.assertEqual(thirty["expected_detection_latency_seconds"], 15)
        self.assertEqual(thirty["minimum_requests_per_hour_if_one_subquery_per_org_cycle"], 360)
        self.assertEqual(fifteen["maximum_detection_latency_seconds"], 15)
        self.assertEqual(fifteen["expected_detection_latency_seconds"], 7.5)
        self.assertEqual(fifteen["minimum_requests_per_hour_if_one_subquery_per_org_cycle"], 720)
        self.assertEqual(thirty["actual_request_rate_status"], "UNKNOWN_UNTIL_WATCHER_MEASUREMENT")
        self.assertIsNone(thirty["actual_requests_per_hour"])

    def test_measured_page_amplification_is_applied_without_changing_poll_default(self):
        scenario = polling_scenario(30, organization_count=3, measured_subqueries_per_organization_cycle=2.5)
        self.assertEqual(scenario["actual_requests_per_hour"], 900)
        self.assertEqual(scenario["actual_request_rate_status"], "MEASURED")
        self.assertEqual(scenario["configuration_status"], "SCENARIO_ONLY_DEFAULT_UNCHANGED")

    def test_operator_rate_sensitivity_is_estimated_not_billing(self):
        comparison = reaction_exposure_comparison()
        self.assertEqual(comparison["180_seconds"]["total_exposure_seconds"], 35_640)
        self.assertEqual(comparison["180_seconds"]["total_exposure_hours"], 9.9)
        self.assertAlmostEqual(comparison["180_seconds"]["estimated_exposure_usd"], 4.1283)
        self.assertAlmostEqual(comparison["30_seconds"]["estimated_exposure_usd"], 0.68805)
        self.assertAlmostEqual(comparison["15_seconds"]["estimated_exposure_usd"], 0.344025)
        for item in comparison.values():
            self.assertEqual(item["classification"], "ESTIMATED_OPERATOR_RATE_NOT_VERIFIED_BILLING")
            self.assertFalse(item["billing_verified"])
            self.assertFalse(item["spend_authorized"])

    def test_invalid_poll_rates_and_request_amplification_fail_closed(self):
        for interval in (14, 301, True):
            with self.assertRaises(ValueError):
                polling_scenario(interval)
        for amplification in (0, float("inf"), float("nan"), True):
            with self.assertRaises(ValueError):
                polling_scenario(30, measured_subqueries_per_organization_cycle=amplification)

    def test_negative_or_nonfinite_operator_rate_is_rejected(self):
        for rate in (-0.01, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                estimate_operator_exposure(30, operator_rate_usd_per_hour=rate)


if __name__ == "__main__":
    unittest.main()
