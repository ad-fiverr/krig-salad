from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collector.fleet import build_fleet_rankings, evaluate_economic_profit, summarize_fleet  # noqa: E402


def verified_machine(machine_id: str, *, hashrate: float) -> dict:
    attribution = "salad-run-001"
    evidence_base = {
        "attribution_id": attribution,
        "status": "verified",
        "observed_at": "2026-10-10T18:00:00Z",
        "freshness": "historical",
        "source_reference": "local-evidence-record-001",
    }
    return {
        "machine_id": machine_id,
        "coin": "PRL",
        "algorithm": "PearlHash",
        "hashrate_semantics": "fl4shminer_device_reported",
        "hashrate_source": "Text Log:Device hashRate",
        "observed_hashrate_ths": hashrate,
        "rental_usd_per_hour": 0.117,
        "target_profit_over_rental_cost_fraction": 0.1,
        "observed_productive_ratio": 0.5,
        "net_revenue_usd_per_ths_hour": 0.000001,
        "attribution_id": attribution,
        "economic_evidence": {
            "salad_billing": {**evidence_base, "evidence_id": "billing-001", "billed_seconds": 3600, "amount_usd": 0.117},
            "rental_price": {**evidence_base, "evidence_id": "price-001", "rental_usd_per_hour": 0.117},
            "productive_ratio": {**evidence_base, "evidence_id": "productive-001", "productive_seconds": 1800, "billed_seconds": 3600, "value": 0.5},
            "pool_revenue": {**evidence_base, "evidence_id": "revenue-001", "net_revenue_usd_per_ths_hour": 0.000001, "evidence_stage": "pool_observed", "fee_inclusion_state": "included"},
        },
    }


class FleetRankingTests(unittest.TestCase):
    def test_observed_work_survives_but_missing_economics_stay_unknown_and_unranked(self):
        machine = {
            "machine_id": "laptop-5090",
            "coin": "PRL",
            "algorithm": "PearlHash",
            "hashrate_semantics": "fl4shminer_device_reported",
            "hashrate_source": "Text Log:Device hashRate",
            "observed_hashrate_ths": 150.0,
            "gpu_identity": {"model": "RTX 5090", "form_factor": "laptop"},
        }
        result = build_fleet_rankings([machine])
        self.assertEqual(result["mode"], "dry_run_only")
        self.assertEqual(result["observed_work_rankings"][0]["machines"][0]["observed_hashrate_ths"], 150.0)
        self.assertEqual(result["economic_profit_rankings"], [])
        self.assertEqual(result["economic_profit_unknown"][0]["profit_status"], "UNKNOWN")
        self.assertIn("salad_billing_evidence_missing", result["economic_profit_unknown"][0]["rank_exclusion_reason"])
        self.assertFalse(result["actions_performed"])

    def test_verified_economic_record_can_rank_but_cannot_perform_action(self):
        result = build_fleet_rankings([verified_machine("verified-laptop", hashrate=150)])
        self.assertEqual(result["economic_profit_unknown"], [])
        ranking = result["economic_profit_rankings"][0]
        self.assertEqual(ranking["profit_status"], "ECONOMICS_VERIFIED")
        self.assertEqual(ranking["rank"], 1)
        self.assertLess(ranking["net_profit_usd_per_billed_hour"], 0)
        self.assertEqual(ranking["economic_guard"]["decision"], "WOULD_STOP")
        self.assertFalse(ranking["actions_performed"])

    def test_unreconciled_cost_is_unknown_not_a_verified_loss(self):
        machine = verified_machine("bad-billing", hashrate=150)
        machine["economic_evidence"]["salad_billing"]["amount_usd"] = 0.50
        result = evaluate_economic_profit(machine)
        self.assertEqual(result["profit_status"], "UNKNOWN")
        self.assertIsNone(result["net_profit_usd_per_billed_hour"])
        self.assertIn("salad_billing_cost_not_reconciled_to_price", result["economic_guard"]["details"]["unknown_reasons"])

    def test_observed_hashrate_without_coin_and_algorithm_is_not_comparably_ranked(self):
        result = build_fleet_rankings([{
            "machine_id": "unlabeled-workload",
            "hashrate_semantics": "fl4shminer_device_reported",
            "hashrate_source": "Text Log:Device hashRate",
            "observed_hashrate_ths": 150,
        }])
        self.assertEqual(result["observed_work_rankings"], [])
        self.assertEqual(result["observed_work_unranked"][0]["reason"], "coin_or_algorithm_missing_for_comparison")
        self.assertEqual(result["observed_work_unranked"][0]["observed_hashrate_ths"], 150)

    def test_krig_and_fl4shminer_share_observed_work_engine_but_not_economic_evidence(self):
        machines = [
            {
                "machine_id": "3090-krig",
                "coin": "PRL",
                "algorithm": "PearlHash",
                "hashrate_semantics": "krig_device_reported",
                "hashrate_source": "KRig text GPU sample",
                "observed_hashrate_ths": 93.25,
            },
            {
                "machine_id": "5090-laptop-fl4shminer",
                "coin": "PRL",
                "algorithm": "PearlHash",
                "hashrate_semantics": "fl4shminer_device_reported",
                "hashrate_source": "Fl4shMiner Text Log:Device hashRate",
                "observed_hashrate_ths": 150.0,
            },
        ]
        result = build_fleet_rankings(machines)
        ranked = result["observed_work_rankings"][0]["machines"]
        self.assertEqual([item["machine_id"] for item in ranked], ["5090-laptop-fl4shminer", "3090-krig"])
        self.assertEqual(ranked[0]["rank"], 1)
        self.assertEqual(ranked[1]["rank"], 2)
        self.assertEqual(result["economic_profit_rankings"], [])
        self.assertEqual(len(result["economic_profit_unknown"]), 2)


class FleetSummaryTests(unittest.TestCase):
    def test_shared_worker_btc_is_fleet_level_and_not_distributed_to_five_gpus(self):
        window = {"window_start_utc": "2026-10-08T18:30:00Z", "window_end_utc": "2026-10-08T19:30:00Z"}
        record = {
            "fleet_id": "fleet-five-gpu",
            "worker_id": "kryptex-worker-shared",
            "assignments": [
                {"assignment_id": "failed-1", "machine_id": "m0", "status": "failed", "replaces_assignment_id": "old-0"},
                {"assignment_id": "running-1", "machine_id": "m1", "status": "running", "replaces_assignment_id": "failed-1"},
            ],
            "device_hashrate_observations": [
                {
                    **window,
                    "machine_id": f"m{index}",
                    "device_namespace": "fl4shminer_device",
                    "device_id": "0",
                    "coin": "PRL",
                    "algorithm": "PearlHash",
                    "hashrate_ths": 90 + index,
                    "hashrate_semantics": "fl4shminer_device_reported",
                    "hashrate_source": "Text Log:Device hashRate",
                }
                for index in range(5)
            ],
            "worker_btc_evidence": [{
                "evidence_id": "worker-credit-1",
                "worker_id": "kryptex-worker-shared",
                "status": "verified",
                "evidence_stage": "pool_observed",
                "amount": "0.00000170",
                "currency": "BTC",
                "observed_at": "2026-10-08T19:30:00Z",
                "source_reference": "redacted-worker-balance-record",
            }],
        }
        result = summarize_fleet(record)
        self.assertEqual(result["observed_hashrate_by_coin_algorithm_window"][0]["device_count"], 5)
        self.assertEqual(result["observed_hashrate_by_coin_algorithm_window"][0]["observed_hashrate_ths"], 460)
        self.assertEqual(result["worker_btc_revenue"]["amount_btc_by_stage"]["pool_observed"], "0.00000170")
        self.assertEqual(result["worker_btc_revenue"]["machine_level_distribution"], "NOT_DISTRIBUTED")
        self.assertEqual(result["failed_assignment_costs"]["status"], "UNKNOWN")
        self.assertEqual(result["economic_reconciliation_status"], "UNKNOWN")
        self.assertFalse(result["actions_performed"])

    def test_fleet_net_profit_requires_realized_usd_and_matching_billing_window(self):
        record = {
            "fleet_id": "fleet-a",
            "worker_id": "worker-a",
            "assignments": [],
            "worker_usd_revenue_evidence": [{
                "evidence_id": "revenue-usd-1", "worker_id": "worker-a", "status": "verified",
                "evidence_stage": "realized", "amount_usd": "1.25", "source_reference": "sale-record",
                "window_start_utc": "2026-10-08T00:00:00Z", "window_end_utc": "2026-10-08T01:00:00Z",
            }],
            "fleet_billing_evidence": [{
                "evidence_id": "salad-bill-1", "fleet_id": "fleet-a", "status": "verified",
                "amount_usd": "0.50", "source_reference": "invoice-row",
                "window_start_utc": "2026-10-08T00:00:00Z", "window_end_utc": "2026-10-08T01:00:00Z",
            }],
        }
        record["worker_usd_revenue_evidence"][0]["evidence_stage"] = "converted"
        converted = summarize_fleet(record)
        self.assertEqual(converted["economic_reconciliation_status"], "UNKNOWN")
        self.assertEqual(converted["net_profit_by_compatible_window"], [])

        record["worker_usd_revenue_evidence"][0]["evidence_stage"] = "realized"
        result = summarize_fleet(record)
        self.assertEqual(result["economic_reconciliation_status"], "RECONCILED")
        self.assertEqual(result["net_profit_by_compatible_window"][0]["net_profit_usd"], "0.75")


if __name__ == "__main__":
    unittest.main()
