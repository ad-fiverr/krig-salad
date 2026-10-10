"""Pure, dry-run-only health, provider-state, and economics guards."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .gpu_identity import normalize_gpu_identity


@dataclass(frozen=True)
class HashGuardPolicy:
    gpu_floors_ths: Mapping[str, float]
    warmup_seconds: int | None = None
    hash_window_seconds: int | None = None
    minimum_samples_per_window: int | None = None
    expected_sample_interval_seconds: int | None = None
    maximum_sample_gap_seconds: int | None = None
    minimum_window_coverage_ratio: float | None = None
    consecutive_bad_windows: int | None = None
    reallocation_cooldown_seconds: int | None = None
    max_reallocations_per_run: int | None = None
    reevaluation_interval_seconds: int | None = None


@dataclass(frozen=True)
class GuardResult:
    decision: str
    reason: str
    details: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"decision": self.decision, "reason": self.reason, "details": dict(self.details)}


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _positive_integer(value: Any, *, allow_zero: bool = False) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return value >= 0 if allow_zero else value > 0


def _floor_for_model(
    gpu_model: str,
    floors: Mapping[str, float],
    *,
    gpu_identity: Mapping[str, Any] | None = None,
) -> float | None:
    """Match an exact model, form factor, and verified identity source.

    Floor keys use ``MODEL|FORM_FACTOR|IDENTITY_SOURCE``. A plain model string,
    an unverified source, or a Laptop identity without a matching Laptop rule
    never inherits a Desktop floor.
    """
    identity = gpu_identity if isinstance(gpu_identity, Mapping) else {}
    normalized = normalize_gpu_identity(
        identity.get("raw_model") or gpu_model,
        identity_source=identity.get("identity_source"),
        identity_verified=identity.get("identity_verified"),
        reported_form_factor=identity.get("form_factor"),
    )
    if not normalized["identity_verified"]:
        return None
    key = "|".join((normalized["model"], normalized["form_factor"], normalized["identity_source"]))
    value = floors.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or float(value) <= 0:
        return None
    return float(value)


def _window_policy_missing(policy: HashGuardPolicy) -> list[str]:
    required = (
        "warmup_seconds",
        "hash_window_seconds",
        "minimum_samples_per_window",
        "expected_sample_interval_seconds",
        "maximum_sample_gap_seconds",
        "minimum_window_coverage_ratio",
        "consecutive_bad_windows",
    )
    return [name for name in required if getattr(policy, name) is None]


def evaluate_hash_floor(
    gpu_model: str,
    samples: Iterable[Mapping[str, Any]],
    policy: HashGuardPolicy,
    *,
    reallocations_per_run: int | None,
    gpu_identity: Mapping[str, Any] | None = None,
    seconds_since_last_reallocation: float | None = None,
    now_elapsed_seconds: float | None = None,
) -> GuardResult:
    """Evaluate duration-weighted windows; this function never performs actions."""
    identity = gpu_identity if isinstance(gpu_identity, Mapping) else {}
    normalized_identity = normalize_gpu_identity(
        identity.get("raw_model") or gpu_model,
        identity_source=identity.get("identity_source"),
        identity_verified=identity.get("identity_verified"),
        reported_form_factor=identity.get("form_factor"),
    )
    if not normalized_identity["identity_verified"]:
        return GuardResult(
            "INSUFFICIENT_DATA",
            "GPU model, form factor, or identity source is not verified for a physical-floor decision",
            {"gpu_model": gpu_model, "gpu_identity": dict(gpu_identity or {}), "normalized_gpu_identity": normalized_identity, "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"},
        )
    floor = _floor_for_model(gpu_model, policy.gpu_floors_ths, gpu_identity=gpu_identity)
    if floor is None:
        return GuardResult(
            "NO_FLOOR_CONFIGURED",
            "no editable floor exists for this exact verified model/form-factor/source key",
            {"gpu_model": gpu_model, "gpu_identity": dict(gpu_identity or {}), "normalized_gpu_identity": normalized_identity, "hash_health": "UNCONFIGURED", "recommended_action": "NONE"},
        )
    missing = _window_policy_missing(policy)
    if missing:
        return GuardResult(
            "INSUFFICIENT_DATA",
            "operator-required hash timing/action policy is unconfigured",
            {"missing_policy": missing, "gpu_floor_ths": floor, "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"},
        )

    assert policy.warmup_seconds is not None
    assert policy.hash_window_seconds is not None
    assert policy.minimum_samples_per_window is not None
    assert policy.expected_sample_interval_seconds is not None
    assert policy.maximum_sample_gap_seconds is not None
    assert policy.minimum_window_coverage_ratio is not None
    assert policy.consecutive_bad_windows is not None

    if (
        not _positive_integer(policy.warmup_seconds, allow_zero=True)
        or not _positive_integer(policy.hash_window_seconds)
        or not _positive_integer(policy.minimum_samples_per_window)
        or policy.minimum_samples_per_window < 2
        or not _positive_integer(policy.expected_sample_interval_seconds)
        or not _positive_integer(policy.maximum_sample_gap_seconds)
        or policy.maximum_sample_gap_seconds < policy.expected_sample_interval_seconds
        or _finite_number(policy.minimum_window_coverage_ratio) is None
        or not 0 < float(policy.minimum_window_coverage_ratio) <= 1
        or not _positive_integer(policy.consecutive_bad_windows)
        or (policy.reevaluation_interval_seconds is not None and not _positive_integer(policy.reevaluation_interval_seconds))
        or (policy.reevaluation_interval_seconds is not None and policy.reevaluation_interval_seconds > policy.hash_window_seconds)
    ):
        return GuardResult(
            "INSUFFICIENT_DATA",
            "hash guard policy values are invalid; windows require at least two samples",
            {"gpu_floor_ths": floor, "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"},
        )

    parsed_samples: list[tuple[float, float, str, str]] = []
    invalid_sample_count = 0
    for sample in samples:
        elapsed = _finite_number(sample.get("elapsed_seconds"))
        hashrate = _finite_number(sample.get("hashrate_ths"))
        semantics = sample.get("hashrate_semantics")
        source = sample.get("hashrate_source")
        if (
            elapsed is None or hashrate is None or elapsed < 0 or hashrate < 0
            or not isinstance(semantics, str) or not semantics.strip()
            or not isinstance(source, str) or not source.strip()
            or semantics not in {"krig_device_reported", "fl4shminer_device_reported"}
        ):
            invalid_sample_count += 1
            continue
        parsed_samples.append((elapsed, hashrate, semantics.strip(), source.strip()))
    parsed_samples.sort(key=lambda sample: sample[0])
    if not parsed_samples:
        return GuardResult(
            "INSUFFICIENT_DATA",
            "no valid timestamped, semantically labeled device hashrate samples",
            {"gpu_floor_ths": floor, "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA", "invalid_samples_ignored": invalid_sample_count},
        )

    semantics = {sample[2] for sample in parsed_samples}
    sources = {sample[3] for sample in parsed_samples}
    if len(semantics) != 1 or len(sources) != 1:
        return GuardResult(
            "INSUFFICIENT_DATA",
            "hashrate samples mix semantics or source; incomparable samples are not combined",
            {"gpu_floor_ths": floor, "hashrate_semantics": sorted(semantics), "hashrate_sources": sorted(sources), "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"},
        )

    observed_end = max(value[0] for value in parsed_samples)
    evaluation_end = observed_end if now_elapsed_seconds is None else _finite_number(now_elapsed_seconds)
    if evaluation_end is None or evaluation_end < 0:
        return GuardResult("INSUFFICIENT_DATA", "evaluation time is missing or invalid", {"gpu_floor_ths": floor})
    if evaluation_end < observed_end:
        return GuardResult(
            "INSUFFICIENT_DATA",
            "evaluation time precedes an observed sample",
            {"evaluation_end_seconds": evaluation_end, "last_sample_seconds": observed_end},
        )

    if evaluation_end - observed_end > policy.maximum_sample_gap_seconds:
        return GuardResult(
            "TELEMETRY_STALE",
            "latest device hashrate sample exceeds the configured maximum telemetry gap",
            {"gpu_floor_ths": floor, "evaluation_end_seconds": evaluation_end, "last_sample_seconds": observed_end, "sample_age_seconds": evaluation_end - observed_end, "maximum_sample_gap_seconds": policy.maximum_sample_gap_seconds, "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"},
        )

    stride = policy.reevaluation_interval_seconds or policy.hash_window_seconds
    first_end = policy.warmup_seconds + policy.hash_window_seconds
    if evaluation_end < first_end:
        return GuardResult(
            "INSUFFICIENT_DATA",
            "warmup has not ended or no complete hash window is available",
            {"evaluation_end_seconds": evaluation_end, "warmup_seconds": policy.warmup_seconds, "hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"},
        )
    complete_window_count = int((evaluation_end - first_end) // stride) + 1

    windows: list[dict[str, Any]] = []
    for index in range(complete_window_count):
        start = policy.warmup_seconds + index * stride
        end = start + policy.hash_window_seconds
        # A preceding sample may cover the left boundary for at most one expected
        # cadence. This is bounded hold-forward, never interpolation across a gap.
        points = [(elapsed, rate) for elapsed, rate, _, _ in parsed_samples if start - policy.maximum_sample_gap_seconds <= elapsed <= end]
        points.sort()
        distinct: dict[float, set[float]] = {}
        for elapsed, rate in points:
            distinct.setdefault(elapsed, set()).add(rate)
        times = sorted(distinct)
        values = [next(iter(distinct[elapsed])) for elapsed in times if len(distinct[elapsed]) == 1]
        expected_samples = math.ceil(policy.hash_window_seconds / policy.expected_sample_interval_seconds)
        gaps = ([max(0.0, times[0] - start)] if times else [policy.hash_window_seconds])
        gaps.extend(right - left for left, right in zip(times, times[1:]))
        if times:
            gaps.append(max(0.0, end - times[-1]))
        maximum_observed_gap = max(gaps, default=policy.hash_window_seconds)
        timestamp_conflict = any(len(rates) > 1 for rates in distinct.values())
        weighted_seconds = 0.0
        weighted_hashrate = 0.0
        for point_index, (elapsed, rates) in enumerate(sorted(distinct.items())):
            if len(rates) != 1:
                continue
            interval_start = max(start, elapsed)
            next_elapsed = sorted(distinct)[point_index + 1] if point_index + 1 < len(distinct) else end
            interval_end = min(end, next_elapsed, elapsed + policy.expected_sample_interval_seconds)
            if interval_end <= interval_start:
                continue
            duration = interval_end - interval_start
            weighted_seconds += duration
            weighted_hashrate += next(iter(rates)) * duration
        coverage = min(1.0, weighted_seconds / policy.hash_window_seconds)
        unique_sample_count = sum(1 for elapsed in times if start <= elapsed < end)
        valid = (
            unique_sample_count >= policy.minimum_samples_per_window
            and not timestamp_conflict
            and coverage >= policy.minimum_window_coverage_ratio
            and maximum_observed_gap <= policy.maximum_sample_gap_seconds
            and weighted_seconds > 0
        )
        weighted_mean = weighted_hashrate / weighted_seconds if weighted_seconds else None
        windows.append(
            {
                "index": index,
                "start_seconds": start,
                "end_seconds": end,
                "sample_count": unique_sample_count,
                "expected_sample_count": expected_samples,
                "coverage_ratio": round(coverage, 6),
                "covered_seconds": round(weighted_seconds, 6),
                "maximum_observed_gap_seconds": maximum_observed_gap,
                "timestamp_conflict": timestamp_conflict,
                "valid": valid,
                "mean_hashrate_ths": round(weighted_mean, 9) if valid else None,
                "mean_method": "duration_weighted_bounded_hold_forward",
                "below_floor": weighted_mean < floor if valid else None,
            }
        )

    bad_streak = 0
    for window in reversed(windows):
        if not window["valid"]:
            break
        if not window["below_floor"]:
            break
        bad_streak += 1

    details: dict[str, Any] = {
        "gpu_model": gpu_model,
        "gpu_identity": dict(gpu_identity or {}),
        "gpu_floor_ths": floor,
        "hashrate_semantics": next(iter(semantics)),
        "hashrate_source": next(iter(sources)),
        "windows": windows,
        "reevaluation_interval_seconds": stride,
        "consecutive_bad_windows_observed": bad_streak,
        "consecutive_bad_windows_required": policy.consecutive_bad_windows,
        "invalid_samples_ignored": invalid_sample_count,
    }
    if not windows[-1]["valid"]:
        details.update({"hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"})
        return GuardResult("INSUFFICIENT_DATA", "most recent complete window fails sample, coverage, gap, or timestamp-conflict requirements", details)
    if bad_streak == 0:
        details.update({"hash_health": "MEETS_CONFIGURED_FLOOR", "recommended_action": "NONE"})
        return GuardResult("PASS", "most recent complete window meets the physical hash floor", details)
    if bad_streak < policy.consecutive_bad_windows:
        details.update({"hash_health": "BELOW_CONFIGURED_FLOOR", "recommended_action": "WAIT"})
        return GuardResult("WOULD_WAIT", "low windows are present but the configured consecutive-window threshold is not met", details)

    if policy.reallocation_cooldown_seconds is None or policy.max_reallocations_per_run is None:
        details.update({"hash_health": "BELOW_CONFIGURED_FLOOR", "recommended_action": "INSUFFICIENT_DATA"})
        missing_actions = [
            field for field in ("reallocation_cooldown_seconds", "max_reallocations_per_run")
            if getattr(policy, field) is None
        ]
        return GuardResult("INSUFFICIENT_DATA", "physical floor breach is confirmed but action-policy limits are not configured", {**details, "missing_action_policy": missing_actions})
    if (
        not _positive_integer(policy.reallocation_cooldown_seconds, allow_zero=True)
        or not _positive_integer(policy.max_reallocations_per_run, allow_zero=True)
    ):
        details.update({"hash_health": "UNKNOWN", "recommended_action": "INSUFFICIENT_DATA"})
        return GuardResult("INSUFFICIENT_DATA", "reallocation cooldown or maximum count is invalid", details)
    if reallocations_per_run is None or not _positive_integer(reallocations_per_run, allow_zero=True):
        details.update({"hash_health": "BELOW_CONFIGURED_FLOOR", "recommended_action": "INSUFFICIENT_DATA"})
        return GuardResult("INSUFFICIENT_DATA", "reallocation history is required to enforce the per-run action limit", details)
    if reallocations_per_run >= policy.max_reallocations_per_run:
        details.update({"hash_health": "BELOW_CONFIGURED_FLOOR", "recommended_action": "WOULD_STOP"})
        return GuardResult(
            "WOULD_STOP",
            "maximum reallocations reached; stop this run for an underperforming GPU class",
            {**details, "action_reason": "GPU_CLASS_UNDERPERFORMING", "reallocations_per_run": reallocations_per_run},
        )

    if reallocations_per_run > 0 and policy.reallocation_cooldown_seconds > 0:
        elapsed_since = _finite_number(seconds_since_last_reallocation)
        if elapsed_since is None or elapsed_since < 0:
            return GuardResult("INSUFFICIENT_DATA", "last reallocation time is required to enforce cooldown", details)
        if elapsed_since < policy.reallocation_cooldown_seconds:
            details.update({"hash_health": "BELOW_CONFIGURED_FLOOR", "recommended_action": "WOULD_WAIT"})
            return GuardResult(
                "WOULD_WAIT",
                "reallocation cooldown has not elapsed",
                {**details, "seconds_since_last_reallocation": elapsed_since, "cooldown_seconds": policy.reallocation_cooldown_seconds},
            )

    details.update({"hash_health": "BELOW_CONFIGURED_FLOOR", "recommended_action": "WOULD_REALLOCATE"})
    return GuardResult(
        "WOULD_REALLOCATE",
        "consecutive complete post-warmup windows are below the configured physical hash floor",
        {**details, "reallocations_per_run": reallocations_per_run, "action_is_dry_run_only": True},
    )


def evaluate_provider_state_mismatch(
    *,
    container_group_state: str | None,
    instance_state: str | None,
    miner_telemetry_state: str | None,
    mismatch_duration_seconds: float | None,
    grace_period_seconds: int | None,
    confirmed_action: str | None = None,
) -> GuardResult:
    """Classify lifecycle/telemetry disagreement without contacting a provider."""
    if not container_group_state or not instance_state or not miner_telemetry_state:
        return GuardResult("INSUFFICIENT_DATA", "provider states or miner telemetry state are missing", {})

    group = container_group_state.strip().casefold()
    instance = instance_state.strip().casefold()
    telemetry = miner_telemetry_state.strip().casefold()
    details = {
        "container_group_state": group,
        "instance_state": instance,
        "miner_telemetry_state": telemetry,
        "billing_status": "UNKNOWN",
    }
    if telemetry not in {"fresh", "stale", "missing"}:
        return GuardResult("INSUFFICIENT_DATA", "miner telemetry freshness state is unresolved", details)

    mismatch_candidate = (
        group == "running"
        and instance in {"allocating", "downloading", "creating"}
        and telemetry in {"stale", "missing"}
    )
    if not mismatch_candidate:
        return GuardResult("PASS", "no configured provider/telemetry mismatch pattern is present", details)

    if grace_period_seconds is None or not _positive_integer(grace_period_seconds, allow_zero=True):
        return GuardResult("INSUFFICIENT_DATA", "provider mismatch grace period is unconfigured or invalid", details)
    duration = _finite_number(mismatch_duration_seconds)
    if duration is None or duration < 0:
        return GuardResult("INSUFFICIENT_DATA", "duration of the provider mismatch is unknown", details)
    details.update({"mismatch_duration_seconds": duration, "grace_period_seconds": grace_period_seconds})
    if duration < grace_period_seconds:
        return GuardResult("INSUFFICIENT_DATA", "provider mismatch remains within the configured grace period", details)

    if confirmed_action is None or confirmed_action == "REPORT_ONLY":
        return GuardResult("PROVIDER_STATE_MISMATCH", "provider lifecycle conflicts with stale or missing miner telemetry", details)
    if confirmed_action not in {"WOULD_REALLOCATE", "WOULD_STOP"}:
        return GuardResult("INSUFFICIENT_DATA", "confirmed mismatch action is not a supported dry-run decision", details)
    return GuardResult(confirmed_action, "configured dry-run response to a confirmed provider mismatch", {**details, "action_is_dry_run_only": True})


def evaluate_economics(
    *,
    rental_usd_per_hour: float | None,
    target_profit_over_rental_cost_fraction: float | None,
    observed_productive_ratio: float | None,
    net_revenue_usd_per_ths_hour: float | None,
    observed_hashrate_ths: float | None,
) -> GuardResult:
    """Compare hash output with a separately derived economic threshold; never reallocates."""
    inputs = {
        "rental_usd_per_hour": rental_usd_per_hour,
        "target_profit_over_rental_cost_fraction": target_profit_over_rental_cost_fraction,
        "observed_productive_ratio": observed_productive_ratio,
        "net_revenue_usd_per_ths_hour": net_revenue_usd_per_ths_hour,
    }
    missing = [key for key, value in inputs.items() if _finite_number(value) is None]
    if missing:
        return GuardResult("ECONOMICS_UNKNOWN", "one or more economic inputs are unknown", {"missing_inputs": missing})

    rental = float(rental_usd_per_hour)  # type: ignore[arg-type]
    margin = float(target_profit_over_rental_cost_fraction)  # type: ignore[arg-type]
    ratio = float(observed_productive_ratio)  # type: ignore[arg-type]
    net_revenue = float(net_revenue_usd_per_ths_hour)  # type: ignore[arg-type]
    if rental < 0 or margin < 0 or not 0 <= ratio <= 1 or net_revenue < 0:
        return GuardResult("ECONOMICS_UNKNOWN", "economic inputs are outside their valid ranges", {"inputs": inputs})
    if observed_hashrate_ths is None or _finite_number(observed_hashrate_ths) is None:
        return GuardResult("INSUFFICIENT_DATA", "observed hashrate is required to compare with the economic threshold", {"inputs": inputs})

    effective_revenue_per_ths_billed_hour = net_revenue * ratio
    required_hourly_revenue = rental * (1 + margin)
    details = {
        "rental_usd_per_hour": rental,
        "target_profit_over_rental_cost_fraction": margin,
        "observed_productive_ratio": ratio,
        "net_revenue_usd_per_ths_hour": net_revenue,
        "effective_revenue_usd_per_ths_billed_hour": effective_revenue_per_ths_billed_hour,
        "required_hourly_revenue_usd": required_hourly_revenue,
        "observed_hashrate_ths": float(observed_hashrate_ths),
        "physical_hash_floor_applied_here": False,
        "action_is_dry_run_only": True,
    }
    if effective_revenue_per_ths_billed_hour <= 0:
        return GuardResult("WOULD_STOP", "no positive productive revenue rate is available to cover rental", details)

    required_hashrate = required_hourly_revenue / effective_revenue_per_ths_billed_hour
    details["economic_required_ths"] = required_hashrate
    if float(observed_hashrate_ths) < required_hashrate:
        return GuardResult("WOULD_STOP", "observed machine is below the economic threshold; do not reallocate for an economic shortfall", details)
    return GuardResult("PASS", "observed hashrate meets the economic threshold", details)
