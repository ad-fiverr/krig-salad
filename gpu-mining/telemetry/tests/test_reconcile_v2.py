from __future__ import annotations

import sys
import unittest
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.reconcile import reconcile_money  # noqa: E402


def money_time():
    return {"observed_at": "2026-10-08T19:00:00Z", "observed_at_precision": "second"}


def snapshot(snapshot_id, timestamp, amount, *, scope="worker", worker="worker-a", run="run-a", segment="segment-a"):
    return {
        "snapshot_id": snapshot_id,
        "account_id": "pool-account",
        "scope": scope,
        "worker_id": worker,
        "currency": "BTC",
        "evidence_stage": "pool_observed",
        "observed_at": timestamp,
        "amount": amount,
        "raw_reference": "local-test-snapshot",
        "run_id": run,
        "segment_id": segment,
    }


class V2ReconcileTests(unittest.TestCase):
    def test_stages_are_kept_separate_and_estimate_is_not_realized(self):
        result = reconcile_money([
            {"evidence_id": "estimate-1", "evidence_stage": "estimated", "amount": "0.10", "currency": "USD", "window_start": "2026-10-08T18:00:00Z", "window_end": "2026-10-08T19:00:00Z", "raw_reference": "estimate-record"},
            {"evidence_id": "pool-1", "evidence_stage": "pool_observed", "amount": "0.10", "currency": "USD", **money_time(), "raw_reference": "pool-snapshot"},
            {"evidence_id": "paid-1", "evidence_stage": "paid", "amount": "0.10", "currency": "USD", **money_time(), "raw_reference": "payment-record"},
        ], [])
        self.assertEqual(result["stage_totals_non_additive"]["estimated"]["USD"], "0.10")
        self.assertEqual(result["stage_totals_non_additive"]["pool_observed"]["USD"], "0.10")
        self.assertEqual(result["stage_totals_non_additive"]["paid"]["USD"], "0.10")
        self.assertFalse(result["money_stages_added_together"])
        self.assertIsNone(result["actual_profit_loss_usd"])

    def test_duplicate_evidence_ids_are_idempotent_but_conflicts_reject(self):
        evidence = {"evidence_id": "payment-1", "evidence_stage": "paid", "amount": "1", "currency": "USDT", **money_time(), "raw_reference": "tx-1"}
        result = reconcile_money([evidence, dict(evidence)], [])
        self.assertEqual(result["stage_totals_non_additive"]["paid"]["USDT"], "1")
        with self.assertRaisesRegex(ValueError, "conflicting monetary"):
            reconcile_money([evidence, {**evidence, "amount": "2"}], [])

    def test_converted_evidence_requires_timestamped_rate_and_source(self):
        bare = {"evidence_id": "conversion-1", "evidence_stage": "converted", "amount": "2.53", "currency": "MXN", "raw_reference": "conversion-record"}
        with self.assertRaisesRegex(ValueError, "conversion metadata"):
            reconcile_money([bare], [])
        complete = {
            **bare,
            **money_time(),
            "conversion": {
                "from_amount": "0.00000170", "from_currency": "BTC", "rate": "1488235.294117647",
                "to_currency": "MXN", "observed_at": "2026-10-08T20:00:00Z", "source_reference": "rate-source",
            },
        }
        result = reconcile_money([complete], [])
        self.assertEqual(result["stage_totals_non_additive"]["converted"]["MXN"], "2.53")
        self.assertEqual(result["money_evidence"][0]["conversion_reconciliation"]["status"], "RECONCILED_RATE_AMOUNT")

    def test_conversion_mismatch_is_retained_but_not_counted_as_reconciled(self):
        converted = {
            "evidence_id": "conversion-mismatch", "evidence_stage": "converted", "amount": "2.54", "currency": "MXN",
            **money_time(), "raw_reference": "conversion-record",
            "conversion": {
                "from_amount": "0.00000170", "from_currency": "BTC", "rate": "1488235.294117647",
                "to_currency": "MXN", "observed_at": "2026-10-08T20:00:00Z", "source_reference": "rate-source",
            },
        }
        result = reconcile_money([converted], [])
        self.assertEqual(result["money_evidence"][0]["conversion_reconciliation"]["status"], "UNRECONCILED")
        self.assertEqual(result["unreconciled_conversion_evidence_ids"], ["conversion-mismatch"])
        self.assertEqual(result["stage_totals_non_additive"]["converted"], {})

    def test_conversion_mismatch_needs_a_timestamped_documented_adjustment(self):
        converted = {
            "evidence_id": "conversion-adjusted", "evidence_stage": "converted", "amount": "2.52", "currency": "MXN",
            **money_time(), "raw_reference": "conversion-record",
            "conversion": {
                "from_amount": "0.00000170", "from_currency": "BTC", "rate": "1488235.294117647",
                "to_currency": "MXN", "observed_at": "2026-10-08T20:00:00Z", "source_reference": "rate-source",
                "documented_adjustment": {"amount": "-0.01", "observed_at": "2026-10-08T20:01:00Z", "source_reference": "fee-record"},
            },
        }
        result = reconcile_money([converted], [])
        self.assertEqual(result["money_evidence"][0]["conversion_reconciliation"]["status"], "RECONCILED_WITH_DOCUMENTED_ADJUSTMENT")
        self.assertEqual(result["stage_totals_non_additive"]["converted"]["MXN"], "2.52")

    def test_worker_balance_delta_requires_same_session_and_is_idempotent(self):
        left = snapshot("before", "2026-10-08T18:30:00Z", "0.001")
        right = snapshot("after", "2026-10-08T19:30:00Z", "0.0017")
        result = reconcile_money([], [left, left, right])
        self.assertEqual(len(result["balance_deltas"]), 1)
        self.assertEqual(result["balance_deltas"][0]["attributed_amount"], "0.0007")
        self.assertEqual(result["balance_deltas"][0]["attribution_status"], "attributed_to_bounded_session_interval")
        self.assertEqual(result["stage_totals_non_additive"]["pool_observed"], {})

    def test_account_balance_with_multiple_workers_is_not_attributed(self):
        left = snapshot("before", "2026-10-08T18:30:00Z", "0.001", scope="account", worker=None)
        right = snapshot("after", "2026-10-08T19:30:00Z", "0.0017", scope="account", worker=None)
        interval = "2026-10-08T18:30:00Z..2026-10-08T19:30:00Z"
        result = reconcile_money([], [left, right], active_worker_count_by_interval={interval: 3})
        self.assertIsNone(result["balance_deltas"][0]["attributed_amount"])
        self.assertEqual(result["balance_deltas"][0]["attribution_status"], "unresolved_account_scope_multiple_or_unknown_workers")

    def test_actual_pnl_needs_matching_realized_usd_and_direct_billing_evidence(self):
        evidence = [{
            "evidence_id": "realized-a", "evidence_stage": "realized", "amount": "1.25", "currency": "USD",
            "attribution_id": "session-a", "fee_inclusion_state": "included",
            **money_time(),
            "raw_reference": "exchange-statement-row-1",
        }]
        billing = [{
            "evidence_id": "bill-a", "attribution_id": "session-a", "amount": "0.50", "currency": "USD",
            **money_time(), "raw_reference": "salad-invoice-row-1",
        }]
        unknown = reconcile_money(evidence, [], salad_billed_cost_usd="0.50", salad_billing_evidence_id="bill-a", salad_billing_attribution_id="session-a")
        self.assertIsNone(unknown["actual_profit_loss_usd"])
        self.assertEqual(unknown["salad_billing_evidence_status"], "UNKNOWN_BILLING_EVIDENCE_ID_NOT_FOUND")
        known = reconcile_money(evidence, [], billing_evidence=billing, salad_billed_cost_usd="0.50", salad_billing_evidence_id="bill-a", salad_billing_attribution_id="session-a")
        self.assertEqual(known["actual_profit_loss_usd"], "0.75")
        self.assertEqual(known["actual_profit_loss_status"], "COMPUTABLE_FROM_MATCHED_BILLING_AND_REALIZED_EVIDENCE")
        self.assertEqual(known["salad_billing_evidence_status"], "MATCHED_BILLING_RECORD_AND_ATTRIBUTION")

    def test_billing_attribution_and_candidate_cost_must_match_record(self):
        billing = [{
            "evidence_id": "bill-a", "attribution_id": "session-other", "amount": "0.50", "currency": "USD",
            **money_time(), "raw_reference": "salad-invoice-row-1",
        }]
        result = reconcile_money([], [], billing_evidence=billing, salad_billed_cost_usd="0.51", salad_billing_evidence_id="bill-a", salad_billing_attribution_id="session-a")
        self.assertIsNone(result["salad_billed_cost_usd"])
        self.assertIsNone(result["actual_profit_loss_usd"])
        self.assertEqual(result["salad_billing_evidence_status"], "UNRECONCILED_BILLING_ATTRIBUTION_MISMATCH")
        amount_mismatch = reconcile_money(
            [], [],
            billing_evidence=[{**billing[0], "attribution_id": "session-a"}],
            salad_billed_cost_usd="0.51", salad_billing_evidence_id="bill-a", salad_billing_attribution_id="session-a",
        )
        self.assertIsNone(amount_mismatch["salad_billed_cost_usd"])
        self.assertEqual(amount_mismatch["salad_billing_evidence_status"], "UNRECONCILED_BILLING_AMOUNT_MISMATCH")

    def test_money_evidence_requires_a_verifiable_timestamp(self):
        evidence = {"evidence_id": "paid-no-time", "evidence_stage": "paid", "amount": "1", "currency": "USDT", "raw_reference": "tx-1"}
        with self.assertRaisesRegex(ValueError, "timezone-aware observed_at"):
            reconcile_money([evidence], [])

    def test_billing_evidence_requires_timestamp_and_source_reference(self):
        billing = {"evidence_id": "bill-no-time", "attribution_id": "session-a", "amount": "0.50", "currency": "USD", "raw_reference": "invoice-row"}
        with self.assertRaisesRegex(ValueError, "billing evidence requires a timezone-aware observed_at"):
            reconcile_money([], [], billing_evidence=[billing])

    def test_unverified_fees_prevent_claiming_realized_net_pnl(self):
        evidence = [{
            "evidence_id": "realized-a", "evidence_stage": "realized", "amount": "1.25", "currency": "USD",
            "attribution_id": "session-a", "fee_inclusion_state": "unknown",
            **money_time(),
            "raw_reference": "exchange-statement-row-1",
        }]
        result = reconcile_money(evidence, [], salad_billed_cost_usd="0.50", salad_billing_evidence_id="bill-a", salad_billing_attribution_id="session-a")
        self.assertIsNone(result["actual_profit_loss_usd"])


if __name__ == "__main__":
    unittest.main()
