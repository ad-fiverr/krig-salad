from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
import sys
import unittest

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.salad_billing_cost import build_cost_reconciliation, operator_reaction_cost_scenarios  # noqa: E402


T0 = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
SCOPE = {
    "organization": "adrianfiverr",
    "project": "miners",
    "fleet_id": "fl4sh-fleet",
    "billing_account_id": "billing-account-1",
    "window_start_utc": T0.isoformat().replace("+00:00", "Z"),
    "window_end_utc": (T0 + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
}


def event(event_id: str, state: str, seconds: int, *, assignment="assignment-1", instance="instance-1", machine="machine-1", account="billing-account-1", **extra):
    return {
        "event_id": event_id,
        "source": "salad_exported_lifecycle_csv",
        "source_reference": f"lifecycle-{event_id}",
        "organization": "adrianfiverr",
        "project": "miners",
        "fleet_id": "fl4sh-fleet",
        "billing_account_id": account,
        "assignment_id": assignment,
        "instance_id": instance,
        "machine_id": machine,
        "gpu_model": "RTX_5080_LAPTOP",
        "state": state,
        "occurred_at_utc": (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
        **extra,
    }


def rate(quote_id="quote-1", *, amount="0.417", start=T0, end=None, account="billing-account-1", gpu="RTX_5080_LAPTOP", priority=None, plan=None, classification="QUOTED"):
    return {
        "quote_id": quote_id,
        "organization": "adrianfiverr",
        "project": "miners",
        "fleet_id": "fl4sh-fleet",
        "billing_account_id": account,
        "usd_per_hour": amount,
        "effective_from_utc": start.isoformat().replace("+00:00", "Z"),
        "effective_until_utc": end.isoformat().replace("+00:00", "Z") if end else None,
        "rate_classification": classification,
        "source_reference": f"quote-source-{quote_id}",
        "source_timestamp_utc": T0.isoformat().replace("+00:00", "Z"),
        "gpu_model": gpu,
        "priority": priority,
        "plan_identity": plan,
    }


def record(events, rates=None, billing=None, **scope):
    return {
        **SCOPE,
        **scope,
        "lifecycle_events": events,
        "quoted_rates": list(rates or []),
        "billing_evidence": list(billing or []),
    }


class SaladBillingCostTests(unittest.TestCase):
    def test_operator_regression_is_exact_and_explicitly_estimated(self):
        result = operator_reaction_cost_scenarios()
        baseline = result["scenarios"]["180_seconds"]
        self.assertEqual(baseline["estimated_exposure_seconds"], 35_640)
        self.assertEqual(baseline["estimated_exposure_minutes"], "594")
        self.assertEqual(baseline["estimated_exposure_hours"], "9.9")
        self.assertEqual(baseline["estimated_cost_usd"], "4.1283")
        self.assertEqual(baseline["classification"], "ESTIMATED_OPERATOR_RATE")
        self.assertEqual(result["scenarios"]["30_seconds"]["estimated_cost_usd"], "0.68805")
        self.assertEqual(result["scenarios"]["15_seconds"]["estimated_cost_usd"], "0.344025")
        self.assertEqual(result["savings_vs_180_seconds"]["30_seconds"]["estimated_savings_usd"], "3.44025")
        self.assertEqual(result["savings_vs_180_seconds"]["15_seconds"]["estimated_savings_usd"], "3.784275")
        self.assertEqual(result["savings_vs_180_seconds"]["30_seconds"]["classification"], "ESTIMATED_SCENARIO_SAVINGS")
        self.assertFalse(result["billing_verified"])

    def test_actual_lifecycle_segments_use_seconds_and_scoped_rate(self):
        result = build_cost_reconciliation(record([
            event("e1", "ALLOCATING", 0),
            event("e2", "RUNNING", 600),
            event("e3", "STOPPING", 1500),
            event("e4", "STOPPED", 1800),
        ], [rate()]))
        self.assertEqual(result["estimated_exposure_seconds"], "1800")
        self.assertEqual(result["estimated_coverage_seconds"], "1800")
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.2085")
        self.assertEqual(result["estimated_cost_status"], "PROVISIONAL_COMPLETE")
        self.assertEqual(result["quoted_24h_cost_usd"], "10.008")
        self.assertEqual(result["verified_billing_status"], "UNKNOWN")
        self.assertIsNone(result["reconciliation_delta_usd"])
        self.assertEqual(result["chargeability_status"], "PROVISIONAL_PROVIDER_CHARGEABILITY_UNVERIFIED")

    def test_exact_fractional_second_duration_is_preserved(self):
        result = build_cost_reconciliation(record([
            event("e1", "RUNNING", 0),
            event("e2", "STOPPED", 10, occurred_at_utc=(T0 + timedelta(seconds=10, microseconds=250000)).isoformat().replace("+00:00", "Z")),
        ], [rate()]))
        self.assertEqual(result["estimated_exposure_seconds"], "10.25")
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.001187291666666666666666666667")

    def test_accounting_window_clips_observed_segments_without_extrapolation(self):
        result = build_cost_reconciliation(record([
            event("e1", "CREATING", 0), event("e2", "RUNNING", 600), event("e3", "STOPPED", 1200),
        ], [rate()], window_start_utc=(T0 + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"), window_end_utc=(T0 + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")))
        self.assertEqual(result["estimated_exposure_seconds"], "600")
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.0695")

    def test_rate_change_is_applied_only_in_its_effective_interval(self):
        split = T0 + timedelta(minutes=10)
        result = build_cost_reconciliation(record([
            event("e1", "RUNNING", 0), event("e2", "STOPPED", 1800),
        ], [rate("r1", amount="0.36", end=split), rate("r2", amount="0.72", start=split)]))
        self.assertEqual(result["estimated_exposure_seconds"], "1800")
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.3")
        self.assertIsNone(result["quoted_rate_usd_per_hour"])
        self.assertIsNone(result["quoted_24h_cost_usd"])

    def test_partial_rate_coverage_does_not_report_partial_amount_as_total(self):
        result = build_cost_reconciliation(record([
            event("e1", "RUNNING", 0), event("e2", "STOPPED", 1200),
        ], [rate(end=T0 + timedelta(seconds=600))]))
        self.assertEqual(result["estimated_exposure_seconds"], "1200")
        self.assertEqual(result["estimated_coverage_seconds"], "600")
        self.assertEqual(result["estimated_cost_status"], "PARTIAL")
        self.assertIsNone(result["estimated_accumulated_cost_usd"])

    def test_missing_terminal_boundary_is_not_extrapolated(self):
        result = build_cost_reconciliation(record([event("e1", "RUNNING", 0)], [rate()]))
        self.assertIsNone(result["estimated_exposure_seconds"])
        self.assertIsNone(result["estimated_coverage_seconds"])
        self.assertIsNone(result["estimated_accumulated_cost_usd"])
        self.assertEqual(result["assignments"][0]["status"], "PARTIAL_OPEN_LIFECYCLE")

    def test_preemption_and_replacement_remain_separate_assignments(self):
        result = build_cost_reconciliation(record([
            event("a1-start", "RUNNING", 0, assignment="a1", instance="i1", machine="m1"),
            event("a1-end", "PREEMPTED", 600, assignment="a1", instance="i1", machine="m1"),
            event("a2-start", "RUNNING", 700, assignment="a2", instance="i2", machine="m2"),
            event("a2-end", "TERMINATED", 1000, assignment="a2", instance="i2", machine="m2"),
        ], [rate()]))
        self.assertEqual([row["assignment_id"] for row in result["assignments"]], ["a1", "a2"])
        self.assertEqual(result["estimated_exposure_seconds"], "900")
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.10425")

    def test_reused_assignment_with_replacement_identity_conflict_fails_closed(self):
        result = build_cost_reconciliation(record([
            event("a1", "RUNNING", 0, assignment="a1", instance="i1", machine="m1"),
            event("a2", "STOPPED", 10, assignment="a1", instance="i2", machine="m2"),
        ], [rate()]))
        self.assertIsNone(result["estimated_accumulated_cost_usd"])
        self.assertIn("LIFECYCLE_IDENTITY_CONFLICT", result["lifecycle_error_codes"])

    def test_priority_and_gpu_rate_scope_must_match_exactly(self):
        events = [event("e1", "RUNNING", 0, gpu_model="RTX_5080_LAPTOP", priority="high"), event("e2", "STOPPED", 600, gpu_model="RTX_5080_LAPTOP", priority="high")]
        result = build_cost_reconciliation(record(events, [rate(priority="low")]))
        self.assertEqual(result["estimated_cost_status"], "UNKNOWN")
        self.assertIsNone(result["estimated_accumulated_cost_usd"])

    def test_billing_account_is_never_inferred_from_organization(self):
        no_account = {key: value for key, value in SCOPE.items() if key != "billing_account_id"}
        result = build_cost_reconciliation(record([
            event("e1", "RUNNING", 0, account=None), event("e2", "STOPPED", 60, account=None),
        ], [], billing_account_id=None, **no_account))
        self.assertEqual(result["estimated_exposure_seconds"], "60")
        self.assertEqual(result["estimated_cost_status"], "UNKNOWN")
        self.assertEqual(result["reason"], "BILLING_ACCOUNT_SCOPE_UNKNOWN")
        self.assertIsNone(result["estimated_accumulated_cost_usd"])
        self.assertIsNone(result["billing_account_id"])

    def test_conflicting_organization_scope_is_not_aggregated(self):
        events = [event("e1", "RUNNING", 0), event("e2", "STOPPED", 60, organization="other-org")]
        result = build_cost_reconciliation(record(events, [rate()]))
        self.assertIn("LIFECYCLE_SCOPE_CONFLICT", result["lifecycle_error_codes"])
        self.assertIsNone(result["estimated_accumulated_cost_usd"])

    def test_duplicate_observation_group_is_counted_once(self):
        first = event("e1", "RUNNING", 0, cross_source_observation_group_id="same-row")
        second = event("e1-copy", "RUNNING", 0, cross_source_observation_group_id="same-row")
        result = build_cost_reconciliation(record([
            first, second, event("e2", "STOPPED", 60),
        ], [rate()]))
        self.assertEqual(result["provenance"]["lifecycle_evidence_count"], 2)
        self.assertEqual(result["estimated_exposure_seconds"], "60")
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.00695")

    def test_conflicting_duplicate_group_is_rejected(self):
        first = event("e1", "RUNNING", 0, cross_source_observation_group_id="same-row")
        second = event("e1-copy", "ALLOCATING", 0, cross_source_observation_group_id="same-row")
        result = build_cost_reconciliation(record([first, second, event("e2", "STOPPED", 60)], [rate()]))
        self.assertIn("LIFECYCLE_IDENTITY_CONFLICT", result["lifecycle_error_codes"])
        self.assertIsNone(result["estimated_accumulated_cost_usd"])

    def test_independent_matching_billing_evidence_is_separate_from_estimate(self):
        billing = [{
            "evidence_id": "invoice-line-1", "organization": "adrianfiverr", "project": "miners",
            "fleet_id": "fl4sh-fleet", "billing_account_id": "billing-account-1",
            "window_start_utc": SCOPE["window_start_utc"], "window_end_utc": SCOPE["window_end_utc"],
            "amount": "0.21", "currency": "USD", "record_type": "GPU_CONSUMPTION_CHARGE",
            "source_kind": "PROVIDER_INVOICE_EXPORT", "source_reference": "provider-invoice-row-1",
            "verified_at_utc": "2026-10-18T13:05:00Z", "verification_status": "VERIFIED", "independent_source": True,
        }]
        result = build_cost_reconciliation(record([
            event("e1", "RUNNING", 0), event("e2", "STOPPED", 1800),
        ], [rate()], billing))
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.2085")
        self.assertEqual(result["verified_billed_cost_usd"], "0.21")
        self.assertEqual(result["verified_billing_status"], "BILLED_VERIFIED")
        self.assertEqual(result["reconciliation_delta_usd"], "0.0015")
        self.assertEqual(result["reconciliation_status"], "COMPARED_ESTIMATE_TO_VERIFIED_BILLING")
        self.assertEqual(result["estimated_classification"], "ESTIMATED")

    def test_unverified_record_cannot_promote_quote_or_estimate(self):
        evidence = [{
            "evidence_id": "invoice-line-1", "organization": "adrianfiverr", "project": "miners",
            "fleet_id": "fl4sh-fleet", "billing_account_id": "billing-account-1",
            "window_start_utc": SCOPE["window_start_utc"], "window_end_utc": SCOPE["window_end_utc"],
            "amount": "9.99", "currency": "USD", "record_type": "GPU_CONSUMPTION_CHARGE",
            "source_kind": "PROVIDER_INVOICE_EXPORT", "source_reference": "invoice-row",
            "verified_at_utc": "2026-10-18T13:05:00Z", "verification_status": "ESTIMATED", "independent_source": False,
        }]
        result = build_cost_reconciliation(record([event("e1", "RUNNING", 0), event("e2", "STOPPED", 600)], [rate()], evidence))
        self.assertEqual(result["verified_billing_status"], "UNKNOWN_NOT_INDEPENDENTLY_VERIFIED")
        self.assertIsNone(result["verified_billed_cost_usd"])
        self.assertIsNone(result["reconciliation_delta_usd"])

    def test_deposit_is_not_consumption_charge(self):
        evidence = [{
            "evidence_id": "deposit-1", "organization": "adrianfiverr", "project": "miners",
            "fleet_id": "fl4sh-fleet", "billing_account_id": "billing-account-1",
            "window_start_utc": SCOPE["window_start_utc"], "window_end_utc": SCOPE["window_end_utc"],
            "amount": "50", "currency": "USD", "record_type": "DEPOSIT",
            "source_kind": "PROVIDER_INVOICE_EXPORT", "source_reference": "wallet-deposit",
            "verified_at_utc": "2026-10-18T13:05:00Z", "verification_status": "VERIFIED", "independent_source": True,
        }]
        result = build_cost_reconciliation(record([event("e1", "RUNNING", 0), event("e2", "STOPPED", 600)], [rate()], evidence))
        self.assertEqual(result["verified_billing_status"], "UNKNOWN_NON_CONSUMPTION_ONLY")
        self.assertIsNone(result["verified_billed_cost_usd"])

    def test_currency_period_and_account_mismatches_fail_closed(self):
        base = {
            "evidence_id": "invoice-line-1", "organization": "adrianfiverr", "project": "miners",
            "fleet_id": "fl4sh-fleet", "billing_account_id": "billing-account-1",
            "window_start_utc": SCOPE["window_start_utc"], "window_end_utc": SCOPE["window_end_utc"],
            "amount": "1", "currency": "USD", "record_type": "GPU_CONSUMPTION_CHARGE",
            "source_kind": "PROVIDER_INVOICE_EXPORT", "source_reference": "invoice-row",
            "verified_at_utc": "2026-10-18T13:05:00Z", "verification_status": "VERIFIED", "independent_source": True,
        }
        for changes, expected in (({"currency": "EUR"}, "UNKNOWN_CURRENCY_MISMATCH"),
                                  ({"billing_account_id": "other-account"}, "UNKNOWN_SCOPE_CONFLICT"),
                                  ({"window_start_utc": "2026-10-18T12:01:00Z"}, "UNKNOWN_PERIOD_MISMATCH")):
            with self.subTest(expected=expected):
                evidence = {**base, **changes}
                result = build_cost_reconciliation(record([event("e1", "RUNNING", 0), event("e2", "STOPPED", 60)], [rate()], [evidence]))
                self.assertEqual(result["verified_billing_status"], expected)
                self.assertIsNone(result["verified_billed_cost_usd"])
                self.assertIsNone(result["reconciliation_delta_usd"])

    def test_hashrate_and_synthetic_messages_do_not_affect_cost_or_leak(self):
        secret = "synthetic-never-display-credential"
        rows = [event("e1", "RUNNING", 0, hashrate_ths=1.0, message=secret), event("e2", "STOPPED", 60, hashrate_ths=999.0, message=secret)]
        result = build_cost_reconciliation(record(rows, [rate()]))
        serialized = json.dumps(result, sort_keys=True)
        self.assertEqual(result["estimated_accumulated_cost_usd"], "0.00695")
        self.assertNotIn(secret, serialized)
        self.assertNotIn("hashrate_ths", serialized)
        self.assertFalse(result["actions_performed"])

    def test_unknown_is_never_zero_and_conflicting_rates_do_not_choose(self):
        no_evidence = build_cost_reconciliation(record([], []))
        self.assertIsNone(no_evidence["estimated_accumulated_cost_usd"])
        self.assertIsNone(no_evidence["verified_billed_cost_usd"])
        result = build_cost_reconciliation(record([
            event("e1", "RUNNING", 0), event("e2", "STOPPED", 60),
        ], [rate("r1"), rate("r2", amount="0.5")]))
        self.assertEqual(result["estimated_cost_status"], "UNKNOWN")
        self.assertIsNone(result["estimated_accumulated_cost_usd"])


if __name__ == "__main__":
    unittest.main()
