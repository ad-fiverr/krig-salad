"""Offline revenue estimates; never promotes estimate evidence to a payout."""

from __future__ import annotations

import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .yield_fixtures import validate_revenue_fixture

_UNIT_TO_TH = {
    "H/s": Decimal("1e-12"),
    "kH/s": Decimal("1e-9"),
    "MH/s": Decimal("1e-6"),
    "GH/s": Decimal("1e-3"),
    "TH/s": Decimal(1),
}


def _decimal(value: Any, field: str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise ValueError(f"{field} is required")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field} must be a decimal") from exc
    if not result.is_finite():
        raise ValueError(f"{field} must be finite")
    return result


def _parse_aware(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not re.search(r"T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$", value):
        raise ValueError(f"{field} must be a timezone-aware timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a timezone-aware timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must be a timezone-aware timestamp")
    return parsed


def estimate_revenue(
    observation: dict[str, Any], *, effective_pool_hashrate_ths: Any,
    pool_hashrate_provenance: str, pool_hashrate_coin: str,
    pool_hashrate_algorithm: str, productive_seconds: Any,
    attribution_id: str, attribution_status: str,
    window_start: str | None = None, window_end: str | None = None,
    historical_analysis: bool = False, as_of: str | None = None,
    max_observation_age_seconds: Any = None,
) -> dict[str, Any]:
    """Estimate USD from a verified pool rate; local GPU rate is never substituted."""
    envelope = validate_revenue_fixture(observation)
    if not isinstance(attribution_id, str) or not attribution_id.strip() or attribution_status != "verified":
        raise ValueError("revenue estimate requires a unique, verified attribution_id")
    if not isinstance(pool_hashrate_provenance, str) or not pool_hashrate_provenance.strip():
        raise ValueError("pool_hashrate_provenance is required")
    pool_rate = _decimal(effective_pool_hashrate_ths, "effective_pool_hashrate_ths")
    seconds = _decimal(productive_seconds, "productive_seconds")
    if pool_rate < 0 or seconds < 0:
        raise ValueError("pool hashrate and productive seconds must be nonnegative")
    payload = envelope["payload"]
    usd_per_second = _decimal(payload.get("estimated_usd_per_second"), "payload.estimated_usd_per_second")
    base_hashrate = _decimal(payload["hashrate"]["value"], "payload.hashrate.value") * _UNIT_TO_TH[payload["hashrate"]["unit"]]
    if base_hashrate <= 0:
        raise ValueError("RevenueObservation hashrate must be positive")
    if pool_hashrate_coin != payload["coin"] or pool_hashrate_algorithm != payload["algorithm"]:
        raise ValueError("pool hashrate coin/algorithm is incompatible with the revenue observation")

    start = _parse_aware(window_start, "window_start") if window_start else None
    end = _parse_aware(window_end, "window_end") if window_end else None
    if start is None or end is None:
        raise ValueError("revenue estimates require exact window_start and window_end timestamps")
    if end <= start:
        raise ValueError("window_end must be after window_start")
    window_seconds = Decimal(str((end - start).total_seconds()))
    if seconds > window_seconds:
        raise ValueError("productive_seconds cannot exceed the explicitly bounded estimate window")

    if historical_analysis:
        if envelope.get("freshness") != "historical_fixture" or payload.get("source") != "frozen_snapshot":
            raise ValueError("historical_analysis requires a frozen historical fixture")
        freshness_status = "historical_fixture_for_offline_analysis_only"
    else:
        if envelope.get("freshness") != "fresh":
            raise ValueError("observation freshness must be explicitly fresh")
        observed = _parse_aware(envelope.get("observed_at"), "envelope.observed_at")
        age_limit = _decimal(max_observation_age_seconds, "max_observation_age_seconds")
        if age_limit < 0:
            raise ValueError("max_observation_age_seconds must be nonnegative")
        reference = _parse_aware(as_of, "as_of")
        age = Decimal(str((reference - observed).total_seconds()))
        if age < 0 or age > age_limit:
            raise ValueError("revenue observation is stale for the explicit max-age policy")
        freshness_status = "freshness_checked_against_explicit_age_limit"

    usd_per_th_second = usd_per_second / base_hashrate
    estimated = usd_per_th_second * pool_rate * seconds
    return {
        "schema_version": "2.0",
        "evidence_stage": "estimated",
        "estimate_status": freshness_status,
        "coin": payload["coin"],
        "algorithm": payload["algorithm"],
        "estimated_usd": str(estimated),
        "currency": "USD",
        "observation_reference": payload["raw_reference"],
        "revenue_observation_source_timestamp": payload["source_timestamp"],
        "pool_effective_hashrate_ths": str(pool_rate),
        "pool_hashrate_provenance": pool_hashrate_provenance.strip(),
        "pool_hashrate_coin": pool_hashrate_coin,
        "pool_hashrate_algorithm": pool_hashrate_algorithm,
        "revenue_reference_hashrate_ths": str(base_hashrate),
        "revenue_reference_usd_per_second": str(usd_per_second),
        "productive_seconds": str(seconds),
        "attribution_id": attribution_id,
        "attribution_status": attribution_status,
        "window_start": window_start,
        "window_end": window_end,
        "fee_inclusion_state": payload["fee_inclusion_state"],
        "fee_adjustment_usd": None,
        "realized_usd": None,
        "actual_profit_loss_usd": None,
        "actual_profit_loss_status": "UNKNOWN_REQUIRES_BILLING_AND_REALIZED_PAYMENT_EVIDENCE",
    }
