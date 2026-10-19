"""Bounded polling-latency and operator-rate sensitivity calculations.

All money outputs are labelled estimates. They are not Salad billing data.
Actual request amplification is UNKNOWN until measured subquery counts are
supplied by the watcher; the one-request figures are lower-bound scenarios.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import math
from typing import Iterable


MIN_POLL_SECONDS = 15
MAX_POLL_SECONDS = 300
DEFAULT_POLL_SECONDS = 30
DEFAULT_ORGANIZATION_COUNT = 3
ESTIMATED_BAD_PLACEMENTS = 198
ESTIMATED_BASELINE_REACTION_SECONDS = 180
ESTIMATED_OPERATOR_RATE_USD_PER_HOUR = Decimal("0.417")


def polling_scenario(
    interval_seconds: int,
    *,
    organization_count: int = DEFAULT_ORGANIZATION_COUNT,
    measured_subqueries_per_organization_cycle: float | None = None,
) -> dict[str, int | float | None | str]:
    """Return detection bounds and a lower-bound request-rate estimate."""
    if type(interval_seconds) is not int or not MIN_POLL_SECONDS <= interval_seconds <= MAX_POLL_SECONDS:
        raise ValueError("poll interval is outside the approved 15..300 second range")
    if type(organization_count) is not int or not 1 <= organization_count <= 10_000:
        raise ValueError("organization count is outside safe bounds")
    amplification: float | None = None
    if measured_subqueries_per_organization_cycle is not None:
        value = measured_subqueries_per_organization_cycle
        if type(value) not in {int, float} or not math.isfinite(float(value)) or not 1 <= value <= 10_000:
            raise ValueError("measured request amplification is invalid")
        amplification = float(value)
    cycles = 3600.0 / interval_seconds
    lower_bound = cycles * organization_count
    actual = lower_bound * amplification if amplification is not None else None
    return {
        "poll_interval_seconds": interval_seconds,
        "maximum_detection_latency_seconds": interval_seconds,
        "expected_detection_latency_seconds": interval_seconds / 2,
        "cycles_per_hour": cycles,
        "organization_count": organization_count,
        "minimum_requests_per_hour_if_one_subquery_per_org_cycle": lower_bound,
        "measured_subqueries_per_organization_cycle": amplification,
        "actual_requests_per_hour": actual,
        "actual_request_rate_status": "MEASURED" if amplification is not None else "UNKNOWN_UNTIL_WATCHER_MEASUREMENT",
        "configuration_status": "SCENARIO_ONLY_DEFAULT_UNCHANGED",
    }


def polling_comparison(
    intervals: Iterable[int] = (30, 15),
    *, organization_count: int = DEFAULT_ORGANIZATION_COUNT,
    measured_subqueries_per_organization_cycle: float | None = None,
) -> list[dict[str, int | float | None | str]]:
    """Compare approved candidate intervals without changing watcher config."""
    return [
        polling_scenario(
            interval,
            organization_count=organization_count,
            measured_subqueries_per_organization_cycle=measured_subqueries_per_organization_cycle,
        )
        for interval in intervals
    ]


def estimate_operator_exposure(
    reaction_seconds: int,
    *,
    placement_count: int = ESTIMATED_BAD_PLACEMENTS,
    operator_rate_usd_per_hour: Decimal | str | float = ESTIMATED_OPERATOR_RATE_USD_PER_HOUR,
) -> dict[str, int | float | str]:
    """Estimate time/rate sensitivity; never report verified billing or spend."""
    if type(reaction_seconds) is not int or not 0 <= reaction_seconds <= 86_400:
        raise ValueError("reaction seconds are outside safe bounds")
    if type(placement_count) is not int or not 0 <= placement_count <= 1_000_000:
        raise ValueError("placement count is outside safe bounds")
    try:
        rate = Decimal(str(operator_rate_usd_per_hour))
    except (InvalidOperation, ValueError):
        raise ValueError("operator rate is invalid") from None
    if not rate.is_finite() or rate < 0 or rate > Decimal("1000000"):
        raise ValueError("operator rate is outside safe bounds")
    total_seconds = placement_count * reaction_seconds
    hours = Decimal(total_seconds) / Decimal(3600)
    amount = hours * rate
    return {
        "classification": "ESTIMATED_OPERATOR_RATE_NOT_VERIFIED_BILLING",
        "placement_count": placement_count,
        "reaction_seconds_per_placement": reaction_seconds,
        "total_exposure_seconds": total_seconds,
        "total_exposure_hours": float(hours),
        "operator_rate_usd_per_hour": float(rate),
        "estimated_exposure_usd": float(amount),
        "billing_verified": False,
        "spend_authorized": False,
    }


def reaction_exposure_comparison() -> dict[str, dict[str, int | float | str]]:
    """Compare the supplied 180s case with 30s and 15s polling bounds."""
    intervals = (ESTIMATED_BASELINE_REACTION_SECONDS, 30, 15)
    return {f"{seconds}_seconds": estimate_operator_exposure(seconds) for seconds in intervals}
