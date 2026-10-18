from __future__ import annotations

import copy
import sys
import unittest
from decimal import Decimal
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.revenue import estimate_revenue  # noqa: E402
from collector.yield_fixtures import load_revenue_fixture, validate_revenue_fixture  # noqa: E402


class V2RevenueTests(unittest.TestCase):
    def setUp(self):
        self.fixture = load_revenue_fixture(TELEMETRY_ROOT / "fixtures" / "revenue" / "prl_2026-10-07.json")

    def _estimate(self, **overrides):
        args = {
            "effective_pool_hashrate_ths": "93.33",
            "pool_hashrate_provenance": "explicit-test-pool-rate",
            "pool_hashrate_coin": "PRL",
            "pool_hashrate_algorithm": "PearlHash",
            "productive_seconds": "3600",
            "attribution_id": "run/segment-session",
            "attribution_status": "verified",
            "window_start": "2026-10-08T18:30:00Z",
            "window_end": "2026-10-08T19:30:00Z",
            "historical_analysis": True,
        }
        args.update(overrides)
        return estimate_revenue(self.fixture, **args)

    def test_historical_prl_fixture_is_valid_and_only_produces_estimated_usd(self):
        self.assertEqual(set(self.fixture["payload"]), {
            "coin", "algorithm", "hashrate", "estimated_coin_per_second", "estimated_usd_per_second",
            "source", "source_timestamp", "confidence", "fee_inclusion_state", "raw_reference",
        })
        result = self._estimate()
        self.assertEqual(result["evidence_stage"], "estimated")
        self.assertEqual(result["estimated_usd"], str(Decimal("0.000000271325") * Decimal("93.33") * Decimal(3600)))
        self.assertEqual(result["fee_inclusion_state"], "unknown")
        self.assertIsNone(result["realized_usd"])
        self.assertIsNone(result["actual_profit_loss_usd"])

    def test_historical_qtc_fixture_preserves_mhs_units_and_estimated_only_classification(self):
        qtc = load_revenue_fixture(TELEMETRY_ROOT / "fixtures" / "revenue" / "qtc_2026-10-07.json")
        payload = qtc["payload"]
        self.assertEqual(qtc["freshness"], "historical_fixture")
        self.assertEqual(payload["coin"], "QTC")
        self.assertEqual(payload["algorithm"], "QPoW")
        self.assertEqual(payload["hashrate"], {"value": "1", "unit": "MH/s"})
        self.assertEqual(payload["estimated_coin_per_second"], "0.000000000670491898148148148148148148")
        self.assertEqual(payload["fee_inclusion_state"], "unknown")
        self.assertIsNone(payload["source_timestamp"])
        result = estimate_revenue(
            qtc,
            effective_pool_hashrate_ths="0.000001",
            pool_hashrate_provenance="explicit-QTC-pool-rate-test",
            pool_hashrate_coin="QTC",
            pool_hashrate_algorithm="QPoW",
            productive_seconds="86400",
            attribution_id="qtc-run-segment",
            attribution_status="verified",
            window_start="2026-10-07T00:00:00Z",
            window_end="2026-10-08T00:00:00Z",
            historical_analysis=True,
        )
        self.assertEqual(result["evidence_stage"], "estimated")
        self.assertEqual(result["estimate_status"], "historical_fixture_for_offline_analysis_only")
        self.assertLess(abs(Decimal(result["estimated_usd"]) - Decimal("0.00579323")), Decimal("1e-25"))
        self.assertIsNone(result["realized_usd"])
        self.assertIsNone(result["actual_profit_loss_usd"])

    def test_frozen_observation_is_rejected_as_a_fresh_rate(self):
        with self.assertRaisesRegex(ValueError, "fresh"):
            self._estimate(historical_analysis=False, as_of="2026-10-08T19:30:00Z", max_observation_age_seconds="3600")

    def test_ambiguous_attribution_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "verified attribution"):
            self._estimate(attribution_status="ambiguous")

    def test_pool_rate_must_match_coin_and_algorithm(self):
        with self.assertRaisesRegex(ValueError, "incompatible"):
            self._estimate(pool_hashrate_algorithm="different-algorithm")

    def test_missing_pool_rate_and_productive_time_are_rejected(self):
        with self.assertRaises(ValueError):
            self._estimate(effective_pool_hashrate_ths=None)
        with self.assertRaises(ValueError):
            self._estimate(productive_seconds=None)

    def test_productive_time_cannot_exceed_the_explicit_window(self):
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            self._estimate(productive_seconds="3601")

    def test_fresh_rate_requires_explicit_freshness_age_bound(self):
        fresh = copy.deepcopy(self.fixture)
        fresh["source"] = "kryptex_calculator"
        fresh["payload"]["source"] = "kryptex_calculator"
        fresh["freshness"] = "fresh"
        fresh["observed_at"] = "2026-10-08T19:00:00Z"
        fresh["observed_at_precision"] = "second"
        args = {
            "effective_pool_hashrate_ths": "90",
            "pool_hashrate_provenance": "documented-pool-hashrate",
            "pool_hashrate_coin": "PRL",
            "pool_hashrate_algorithm": "PearlHash",
            "productive_seconds": "60",
            "attribution_id": "segment-1",
            "attribution_status": "verified",
            "window_start": "2026-10-08T19:00:00Z",
            "window_end": "2026-10-08T19:01:00Z",
            "as_of": "2026-10-08T19:01:00Z",
            "max_observation_age_seconds": "3600",
        }
        self.assertEqual(estimate_revenue(fresh, **args)["estimate_status"], "freshness_checked_against_explicit_age_limit")
        with self.assertRaisesRegex(ValueError, "stale"):
            estimate_revenue(fresh, **{**args, "as_of": "2026-10-09T00:00:00Z"})

    def test_fixture_requires_exactly_ten_payload_fields(self):
        bad = copy.deepcopy(self.fixture)
        bad["payload"]["unreviewed_extra"] = "value"
        with self.assertRaisesRegex(ValueError, "exactly ten"):
            validate_revenue_fixture(bad)


if __name__ == "__main__":
    unittest.main()
