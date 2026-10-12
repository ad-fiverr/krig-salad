#!/usr/bin/env python3
"""Opt-in Fl4shMiner supervisor and Device hashRate observer.

The operator-selected profile controls alert thresholds only. It does not
verify a provider GPU identity or authorize any action.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Mapping


DEVICE_RATE_RE = re.compile(
    r"Device\s*\[(?P<device>[0-9]+)\]\s+hashRate:\s*"
    r"(?P<rate>[0-9]+(?:\.[0-9]+)?)\s+TH/s"
    r"(?:\s*,\s*stale:\s*(?P<stale>[0-9]+)/(?P<total>[0-9]+)\s*"
    r"\((?P<stale_pct>[0-9]+(?:\.[0-9]+)?)%\))?"
    r"(?:\s*,\s*warm:\s*(?P<warm>[0-9]+))?\b",
    re.IGNORECASE,
)
MAX_PARSE_LINE_BYTES = 64 * 1024

PROFILE_FLOORS: dict[str, tuple[str, float]] = {
    "RTX_5080_LAPTOP": ("SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS", 120.0),
    "RTX_5090_LAPTOP": ("SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS", 120.0),
    "RTX_5080_DESKTOP": ("SALAD_G5_GPU_FLOOR_RTX_5080_DESKTOP_THS", 209.0),
    "RTX_5090_DESKTOP": ("SALAD_G5_GPU_FLOOR_RTX_5090_DESKTOP_THS", 350.0),
}

TIMING_ENV: dict[str, tuple[str, str, float | int]] = {
    "warmup_seconds": ("SALAD_G5_WARMUP_SECONDS", "int", 90),
    "expected_sample_interval_seconds": ("SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS", "int", 10),
    "hash_window_seconds": ("SALAD_G5_HASH_WINDOW_SECONDS", "int", 120),
    "reevaluation_interval_seconds": ("SALAD_G5_REEVALUATION_INTERVAL_SECONDS", "int", 30),
    "minimum_samples_per_window": ("SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW", "int", 10),
    "maximum_sample_gap_seconds": ("SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS", "int", 30),
    "minimum_window_coverage_ratio": ("SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO", "float", 0.8),
    "consecutive_bad_windows": ("SALAD_G5_CONSECUTIVE_BAD_WINDOWS", "int", 2),
}


class MonitorConfigError(ValueError):
    """Raised for invalid monitor settings without echoing supplied values."""


@dataclass(frozen=True)
class MonitorConfig:
    enabled: bool
    profile: str | None
    floor_ths: float | None
    floor_source: str
    warmup_seconds: int
    expected_sample_interval_seconds: int
    hash_window_seconds: int
    reevaluation_interval_seconds: int
    minimum_samples_per_window: int
    maximum_sample_gap_seconds: int
    minimum_window_coverage_ratio: float
    consecutive_bad_windows: int
    policy_hash: str

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
        *,
        require_enabled: bool = False,
    ) -> "MonitorConfig":
        env = os.environ if environ is None else environ
        enabled_text = env.get("FL4SH_MONITOR_ENABLED", "0")
        if enabled_text not in {"0", "1"}:
            raise MonitorConfigError("FL4SH_MONITOR_ENABLED must be 0 or 1")
        enabled = enabled_text == "1"
        if require_enabled and not enabled:
            raise MonitorConfigError("FL4SH_MONITOR_ENABLED must be 1")

        profile_text = env.get("FL4SH_MONITOR_PROFILE")
        profile: str | None = profile_text if profile_text else None
        if profile is not None and profile not in PROFILE_FLOORS:
            raise MonitorConfigError("FL4SH_MONITOR_PROFILE is not an exact supported profile")

        floor: float | None = None
        floor_source = "UNCONFIGURED"
        if profile is not None:
            floor_env, default_floor = PROFILE_FLOORS[profile]
            if floor_env in env:
                floor = _parse_finite_number(env[floor_env], floor_env, allow_zero=False)
                floor_source = "ENV"
            else:
                floor = default_floor
                floor_source = "G5_DEFAULT"

        timing: dict[str, int | float] = {}
        for key, (env_name, kind, default) in TIMING_ENV.items():
            if env_name not in env:
                timing[key] = default
            elif kind == "int":
                timing[key] = _parse_positive_integer(
                    env[env_name], env_name, allow_zero=(key == "warmup_seconds")
                )
            else:
                value = _parse_finite_number(env[env_name], env_name, allow_zero=False)
                if value > 1.0:
                    raise MonitorConfigError(f"{env_name} must be within (0, 1]")
                timing[key] = value

        _validate_timing(timing)
        policy = {
            "profile": profile,
            "floor_ths": floor,
            "floor_source": floor_source,
            **timing,
        }
        policy_hash = hashlib.sha256(
            json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        ).hexdigest()
        return cls(
            enabled=enabled,
            profile=profile,
            floor_ths=floor,
            floor_source=floor_source,
            **timing,
            policy_hash=policy_hash,
        )


def _parse_finite_number(value: str, name: str, *, allow_zero: bool) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise MonitorConfigError(f"{name} must be a finite positive number") from None
    if not math.isfinite(parsed) or parsed < 0 or (parsed == 0 and not allow_zero):
        raise MonitorConfigError(f"{name} must be a finite positive number")
    return parsed


def _parse_positive_integer(value: str, name: str, *, allow_zero: bool = False) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise MonitorConfigError(f"{name} must be an integer")
    parsed = int(value)
    if parsed < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise MonitorConfigError(f"{name} must be a {qualifier} integer")
    return parsed


def _validate_timing(values: Mapping[str, int | float]) -> None:
    window = int(values["hash_window_seconds"])
    expected = int(values["expected_sample_interval_seconds"])
    gap = int(values["maximum_sample_gap_seconds"])
    reevaluation = int(values["reevaluation_interval_seconds"])
    minimum_samples = int(values["minimum_samples_per_window"])
    coverage = float(values["minimum_window_coverage_ratio"])
    if gap < expected:
        raise MonitorConfigError("maximum sample gap must be at least the expected interval")
    if reevaluation > window:
        raise MonitorConfigError("reevaluation interval must not exceed the hash window")
    if coverage <= 0 or coverage > 1:
        raise MonitorConfigError("minimum window coverage ratio must be within (0, 1]")
    maximum_samples = math.ceil(window / expected)
    if minimum_samples < 2 or minimum_samples > maximum_samples:
        raise MonitorConfigError(
            "minimum sample count must be at least two and cannot exceed expected window samples"
        )


@dataclass(frozen=True)
class DeviceSample:
    device_index: int
    hashrate_ths: float
    stale_count: int | None
    stale_total: int | None
    stale_percent: float | None
    warm_count: int | None


def parse_device_hashrate(line: str) -> DeviceSample | None:
    """Parse only one explicit Fl4shMiner Device hashRate value in TH/s."""
    matches = list(DEVICE_RATE_RE.finditer(line))
    if len(matches) != 1:
        return None
    match = matches[0]
    try:
        rate = float(match.group("rate"))
        stale_count = int(match.group("stale")) if match.group("stale") is not None else None
        stale_total = int(match.group("total")) if match.group("total") is not None else None
        stale_percent = float(match.group("stale_pct")) if match.group("stale_pct") is not None else None
        device_index = int(match.group("device"))
        warm_count = int(match.group("warm")) if match.group("warm") is not None else None
    except (ValueError, OverflowError):
        return None
    if (
        not math.isfinite(rate)
        or rate < 0
        or (stale_percent is not None and not math.isfinite(stale_percent))
        or (stale_percent is not None and (stale_percent < 0 or stale_percent > 100))
        or (stale_count is not None and stale_total is not None and stale_count > stale_total)
        or ((stale_count is None) != (stale_total is None))
        or ((stale_count is None) != (stale_percent is None))
    ):
        return None
    return DeviceSample(device_index, rate, stale_count, stale_total, stale_percent, warm_count)


@dataclass(frozen=True)
class SamplePoint:
    monotonic_seconds: float
    sample: DeviceSample


@dataclass
class DeviceState:
    device_index: int
    samples: deque[SamplePoint] = field(default_factory=deque)
    last_evaluation_at: float | None = None
    last_state: str | None = None
    consecutive_bad_windows: int = 0
    recommendation_emitted: bool = False
    last_window_mean_ths: float | None = None
    last_coverage_ratio: float = 0.0
    last_window_sample_count: int = 0
    duplicate_timestamps: int = 0


class Fl4shMonitor:
    """Incremental per-device rolling-window monitor using a monotonic clock."""

    def __init__(self, config: MonitorConfig, *, start_monotonic: float | None = None) -> None:
        self.config = config
        self.started_at = time.monotonic() if start_monotonic is None else start_monotonic
        self.devices: dict[int, DeviceState] = {}
        self._global_state: str | None = None
        self._global_eval_at: float | None = None

    def observe_line(self, line: str, *, now: float | None = None) -> list[dict[str, Any]]:
        sample = parse_device_hashrate(line)
        if sample is None:
            return []
        timestamp = time.monotonic() if now is None else now
        state = self.devices.setdefault(sample.device_index, DeviceState(sample.device_index))
        if state.samples and timestamp <= state.samples[-1].monotonic_seconds:
            state.duplicate_timestamps += 1
            return []
        state.samples.append(SamplePoint(timestamp, sample))
        self._trim_samples(state, timestamp)
        if state.last_state is None:
            initial_state = "WARMUP" if self.config.floor_ths is not None else "NO_FLOOR_CONFIGURED"
            state.last_state = initial_state
            return [self._event(state, initial_state, observed=sample.hashrate_ths)]
        return []

    def tick(self, *, now: float | None = None) -> list[dict[str, Any]]:
        timestamp = time.monotonic() if now is None else now
        if not self.devices:
            if self._global_eval_at is not None and timestamp - self._global_eval_at < self.config.reevaluation_interval_seconds:
                return []
            self._global_eval_at = timestamp
            elapsed = timestamp - self.started_at
            if elapsed < self.config.warmup_seconds:
                state_name = "WARMUP"
            elif elapsed < self.config.warmup_seconds + self.config.maximum_sample_gap_seconds:
                state_name = "INSUFFICIENT_DATA"
            else:
                state_name = "TELEMETRY_STALE"
            if state_name == self._global_state:
                return []
            self._global_state = state_name
            return [self._event(None, state_name, observed=None)]

        events: list[dict[str, Any]] = []
        for state in self.devices.values():
            if (
                state.last_evaluation_at is not None
                and timestamp - state.last_evaluation_at < self.config.reevaluation_interval_seconds
            ):
                continue
            state.last_evaluation_at = timestamp
            if timestamp - self.started_at < self.config.warmup_seconds:
                events.extend(self._set_state(state, "WARMUP", observed=self._latest_rate(state)))
                continue
            if not state.samples:
                state.consecutive_bad_windows = 0
                events.extend(self._set_state(state, "INSUFFICIENT_DATA", observed=None))
                continue
            age = timestamp - state.samples[-1].monotonic_seconds
            if age > self.config.maximum_sample_gap_seconds:
                state.consecutive_bad_windows = 0
                events.extend(self._set_state(state, "TELEMETRY_STALE", observed=None))
                continue
            if timestamp - self.started_at < (
                self.config.warmup_seconds + self.config.hash_window_seconds
            ):
                # G5's first evaluation is anchored after a complete post-warmup
                # window. A high-coverage rolling prefix is not a substitute.
                state.consecutive_bad_windows = 0
                stats = self._window_stats(state, timestamp)
                events.extend(
                    self._set_state(
                        state,
                        "INSUFFICIENT_DATA",
                        observed=None,
                        stats=stats,
                    )
                )
                continue
            if self.config.floor_ths is None:
                state.consecutive_bad_windows = 0
                stats = self._window_stats(state, timestamp)
                events.extend(
                    self._set_state(
                        state,
                        "NO_FLOOR_CONFIGURED",
                        observed=stats["mean_ths"] if stats["valid"] else self._latest_rate(state),
                        stats=stats,
                    )
                )
                continue

            stats = self._window_stats(state, timestamp)
            if not stats["valid"]:
                state.consecutive_bad_windows = 0
                events.extend(
                    self._set_state(
                        state,
                        "INSUFFICIENT_DATA",
                        observed=None,
                        stats=stats,
                    )
                )
                continue

            mean_rate = float(stats["mean_ths"])
            state.last_window_mean_ths = mean_rate
            state.last_coverage_ratio = float(stats["coverage_ratio"])
            state.last_window_sample_count = int(stats["sample_count"])
            if mean_rate < self.config.floor_ths:
                state.consecutive_bad_windows += 1
                if (
                    state.consecutive_bad_windows >= self.config.consecutive_bad_windows
                    and not state.recommendation_emitted
                ):
                    state.recommendation_emitted = True
                    events.extend(
                        self._set_state(
                            state,
                            "REALLOCATE_RECOMMENDED",
                            observed=mean_rate,
                            stats=stats,
                        )
                    )
                elif not state.recommendation_emitted:
                    events.extend(
                        self._set_state(state, "BELOW_FLOOR", observed=mean_rate, stats=stats)
                    )
            else:
                recovered = state.consecutive_bad_windows > 0 or state.recommendation_emitted
                state.consecutive_bad_windows = 0
                state.recommendation_emitted = False
                events.extend(
                    self._set_state(
                        state,
                        "RECOVERED" if recovered else "HEALTHY",
                        observed=mean_rate,
                        stats=stats,
                    )
                )
        return events

    def _trim_samples(self, state: DeviceState, now: float) -> None:
        retention_start = now - self.config.hash_window_seconds - self.config.maximum_sample_gap_seconds
        while len(state.samples) > 2 and state.samples[1].monotonic_seconds < retention_start:
            state.samples.popleft()

    def _latest_rate(self, state: DeviceState) -> float | None:
        return state.samples[-1].sample.hashrate_ths if state.samples else None

    def _window_stats(self, state: DeviceState, now: float) -> dict[str, Any]:
        window = float(self.config.hash_window_seconds)
        cutoff = now - window
        points = [
            point
            for point in state.samples
            if cutoff - self.config.maximum_sample_gap_seconds
            <= point.monotonic_seconds
            <= now
        ]
        sample_count = sum(
            1 for point in points if cutoff <= point.monotonic_seconds < now
        )
        weighted_rate_seconds = 0.0
        covered_seconds = 0.0
        times = [point.monotonic_seconds for point in points]
        gaps = (
            [max(0.0, times[0] - cutoff)]
            if times
            else [window]
        )
        gaps.extend(right - left for left, right in zip(times, times[1:]))
        if times:
            gaps.append(max(0.0, now - times[-1]))
        maximum_observed_gap = max(gaps, default=window)
        for left, right in zip(points, points[1:]):
            gap = right.monotonic_seconds - left.monotonic_seconds
            if gap <= 0:
                continue
            start = max(cutoff, left.monotonic_seconds)
            end = min(now, right.monotonic_seconds)
            end = min(end, left.monotonic_seconds + self.config.expected_sample_interval_seconds)
            if end <= start:
                continue
            duration = end - start
            covered_seconds += duration
            weighted_rate_seconds += left.sample.hashrate_ths * duration

        last = points[-1] if points else None
        if last is not None:
            age = now - last.monotonic_seconds
            if 0 <= age:
                start = max(cutoff, last.monotonic_seconds)
                end = min(now, last.monotonic_seconds + self.config.expected_sample_interval_seconds)
                if end > start:
                    duration = end - start
                    covered_seconds += duration
                    weighted_rate_seconds += last.sample.hashrate_ths * duration

        coverage = min(1.0, covered_seconds / window)
        mean_rate = weighted_rate_seconds / covered_seconds if covered_seconds > 0 else None
        valid = (
            mean_rate is not None
            and sample_count >= self.config.minimum_samples_per_window
            and coverage >= self.config.minimum_window_coverage_ratio
            and maximum_observed_gap <= self.config.maximum_sample_gap_seconds
        )
        return {
            "mean_ths": mean_rate,
            "coverage_ratio": coverage,
            "sample_count": sample_count,
            "covered_seconds": covered_seconds,
            "maximum_observed_gap_seconds": maximum_observed_gap,
            "valid": valid,
        }

    def _set_state(
        self,
        state: DeviceState,
        state_name: str,
        *,
        observed: float | None,
        stats: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        if state.last_state == state_name:
            # Keep current performance visible on the configured reevaluation
            # cadence, while leaving a recommendation event one-shot.
            if state_name in {"WARMUP", "HEALTHY", "BELOW_FLOOR", "NO_FLOOR_CONFIGURED"}:
                return [self._event(state, state_name, observed=observed, stats=stats)]
            return []
        state.last_state = state_name
        return [self._event(state, state_name, observed=observed, stats=stats)]

    def _event(
        self,
        state: DeviceState | None,
        state_name: str,
        *,
        observed: float | None,
        stats: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        latest = state.samples[-1].sample if state is not None and state.samples else None
        device = f"fl4shminer_device:{state.device_index}" if state is not None else "unobserved"
        return {
            "component": "FL4SH_MONITOR",
            "state": state_name,
            "profile": self.config.profile or "unknown",
            "profile_is_operator_configuration_only": True,
            "device": device,
            "device_namespace": "fl4shminer_device" if state is not None else "unknown",
            "floor_ths": self.config.floor_ths,
            "floor_source": self.config.floor_source,
            "observed_window_mean_ths": observed,
            "latest_device_hashrate_ths": self._latest_rate(state) if state is not None else None,
            "window_coverage_ratio": float(stats["coverage_ratio"]) if stats is not None else None,
            "window_sample_count": int(stats["sample_count"]) if stats is not None else None,
            "maximum_observed_gap_seconds": (
                float(stats["maximum_observed_gap_seconds"]) if stats is not None else None
            ),
            "consecutive_bad_windows": state.consecutive_bad_windows if state is not None else 0,
            "consecutive_bad_windows_required": self.config.consecutive_bad_windows,
            "stale_counter": (
                {
                    "numerator": latest.stale_count,
                    "denominator": latest.stale_total,
                    "reported_percent": latest.stale_percent,
                    "semantics": "Fl4shMiner cumulative stale counter; not paid-share evidence",
                }
                if latest is not None and latest.stale_count is not None
                else None
            ),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": "fl4shminer_stdout:Device hashRate",
            "policy_hash": self.config.policy_hash,
            "provider_binding_status": "UNKNOWN",
            "gpu_identity_verified": False,
            "billing_status": "UNKNOWN",
            "actions_performed": False,
        }


def format_event(event: Mapping[str, Any]) -> str:
    observed = event["observed_window_mean_ths"]
    floor = event["floor_ths"]
    coverage = event["window_coverage_ratio"]
    stale = event["stale_counter"]
    bad = f'{event["consecutive_bad_windows"]}/{event["consecutive_bad_windows_required"]}'
    fields = [
        "FL4SH_MONITOR",
        f'state={event["state"]}',
        f'profile={event["profile"]}',
        f'device={event["device"]}',
        f'floor={_format_number(floor)}',
        f'floor_source={event["floor_source"]}',
        f'observed={_format_number(observed)}',
        f'bad_windows={bad}',
        f'coverage={_format_number(coverage)}',
        f'window_samples={_format_number(event["window_sample_count"])}',
    ]
    if stale is not None:
        fields.append(
            f'stale={stale["numerator"]}/{stale["denominator"]}'
        )
        fields.append(f'stale_pct={_format_number(stale["reported_percent"])}%')
    fields.extend(
        [
            "provider_binding=UNKNOWN",
            "gpu_identity_verified=false",
            "billing=UNKNOWN",
            "actions_performed=false",
            f'policy_hash={event["policy_hash"]}',
            f'timestamp={event["timestamp_utc"]}',
        ]
    )
    return " ".join(fields)


def format_config(config: MonitorConfig) -> str:
    return " ".join(
        (
            "FL4SH_MONITOR",
            "state=CONFIG",
            "enabled=true",
            f"profile={config.profile or 'unknown'}",
            f"floor={_format_number(config.floor_ths)}",
            f"floor_source={config.floor_source}",
            f"warmup_seconds={config.warmup_seconds}",
            f"expected_sample_interval_seconds={config.expected_sample_interval_seconds}",
            f"hash_window_seconds={config.hash_window_seconds}",
            f"reevaluation_interval_seconds={config.reevaluation_interval_seconds}",
            f"minimum_samples_per_window={config.minimum_samples_per_window}",
            f"maximum_sample_gap_seconds={config.maximum_sample_gap_seconds}",
            f"minimum_window_coverage_ratio={_format_number(config.minimum_window_coverage_ratio)}",
            f"consecutive_bad_windows={config.consecutive_bad_windows}",
            f"policy_hash={config.policy_hash}",
            "provider_binding=UNKNOWN",
            "gpu_identity_verified=false",
            "billing=UNKNOWN",
            "actions_performed=false",
        )
    )


def _format_number(value: Any) -> str:
    if value is None:
        return "unknown"
    return f"{float(value):.3f}".rstrip("0").rstrip(".")


class BoundedLineParser:
    """Split complete log records for parsing without buffering unbounded lines."""

    def __init__(self, max_line_bytes: int = MAX_PARSE_LINE_BYTES) -> None:
        if max_line_bytes < 1:
            raise ValueError("maximum parser line length must be positive")
        self.max_line_bytes = max_line_bytes
        self.buffer = bytearray()
        self._dropping_oversized_line = False

    def feed(self, chunk: bytes, *, final: bool = False) -> list[str]:
        records: list[str] = []
        parts = chunk.split(b"\n")
        for index, part in enumerate(parts):
            if not self._dropping_oversized_line:
                if len(self.buffer) + len(part) > self.max_line_bytes:
                    self.buffer.clear()
                    self._dropping_oversized_line = True
                else:
                    self.buffer.extend(part)
            if index < len(parts) - 1:
                if not self._dropping_oversized_line:
                    records.append(bytes(self.buffer).rstrip(b"\r").decode("utf-8", errors="replace"))
                self.buffer.clear()
                self._dropping_oversized_line = False
        if final:
            if self.buffer and not self._dropping_oversized_line:
                records.append(bytes(self.buffer).rstrip(b"\r").decode("utf-8", errors="replace"))
            self.buffer.clear()
            self._dropping_oversized_line = False
        return records


class StreamingRedactor:
    """Redact configured byte secrets even when reads split a secret."""

    def __init__(self, secrets: list[str]) -> None:
        self.secrets = sorted(
            {secret.encode("utf-8") for secret in secrets if secret},
            key=len,
            reverse=True,
        )
        self.buffer = bytearray()

    def feed(self, chunk: bytes, *, final: bool = False) -> bytes:
        self.buffer.extend(chunk)
        output = bytearray()
        replacement = b"[REDACTED]"
        while self.buffer:
            full_match = next(
                (secret for secret in self.secrets if self.buffer.startswith(secret)),
                None,
            )
            if full_match is not None:
                output.extend(replacement)
                del self.buffer[: len(full_match)]
                continue
            possible_prefix = any(
                len(self.buffer) < len(secret) and secret.startswith(self.buffer)
                for secret in self.secrets
            )
            if possible_prefix and not final:
                break
            if possible_prefix and final:
                output.extend(replacement)
                self.buffer.clear()
                break
            output.append(self.buffer[0])
            del self.buffer[0]
        return bytes(output)


def _write_stream(stream_name: str, content: bytes, open_streams: dict[str, bool], write_lock: threading.Lock) -> None:
    if not content or not open_streams.get(stream_name, False):
        return
    target = sys.stdout.buffer if stream_name == "stdout" else sys.stderr.buffer
    try:
        with write_lock:
            target.write(content)
            target.flush()
    except (BrokenPipeError, OSError, ValueError):
        open_streams[stream_name] = False


def _install_signal_forwarding(child_ref: dict[str, subprocess.Popen[bytes] | None]) -> tuple[dict[int, Any], dict[str, int | None]]:
    previous: dict[int, Any] = {}
    pending: dict[str, int | None] = {"signal": None}

    def forward(signum: int, _frame: Any) -> None:
        pending["signal"] = signum
        child = child_ref.get("child")
        if child is not None and child.poll() is None:
            _send_signal_to_child(child, signum)

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, forward)
    return previous, pending


def _send_signal_to_child(child: subprocess.Popen[bytes], signum: int) -> None:
    try:
        child.send_signal(signum)
    except (OSError, ValueError):
        # Windows does not deliver every POSIX-style signal through
        # Popen.send_signal; termination remains safe and local there.
        if os.name == "nt" and child.poll() is None:
            try:
                child.terminate()
            except OSError:
                pass


def run_supervisor(
    config: MonitorConfig,
    command: list[str],
    *,
    monotonic=time.monotonic,
    popen_factory=subprocess.Popen,
) -> int:
    if not config.enabled:
        print("FL4SH_MONITOR requires FL4SH_MONITOR_ENABLED=1", file=sys.stderr, flush=True)
        return 64
    if not command:
        print("FL4SH_MONITOR requires a fixed miner command", file=sys.stderr, flush=True)
        return 64

    started_at = monotonic()
    monitor = Fl4shMonitor(config, start_monotonic=started_at)
    print(format_config(config), flush=True)
    event_queue: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=256)
    child_ref: dict[str, subprocess.Popen[bytes] | None] = {"child": None}
    previous_signals, pending_signal = _install_signal_forwarding(child_ref)
    try:
        child = popen_factory(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
    except OSError as exc:
        for signum, handler in previous_signals.items():
            signal.signal(signum, handler)
        print(f"FL4SH_MONITOR state=SUPERVISOR_ERROR error={type(exc).__name__}", file=sys.stderr, flush=True)
        return 70
    child_ref["child"] = child
    if pending_signal["signal"] is not None and child.poll() is None:
        _send_signal_to_child(child, int(pending_signal["signal"]))

    assert child.stdout is not None and child.stderr is not None
    def read_stream(name: str, pipe: Any) -> None:
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                event_queue.put((name, chunk))
        except (OSError, ValueError):
            pass
        finally:
            event_queue.put((name, None))

    readers = [
        threading.Thread(target=read_stream, args=("stdout", child.stdout), daemon=True),
        threading.Thread(target=read_stream, args=("stderr", child.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()

    redactors = {
        "stdout": StreamingRedactor([os.environ.get("FL4SH_MINING_ID", "")]),
        "stderr": StreamingRedactor([os.environ.get("FL4SH_MINING_ID", "")]),
    }
    parsers = {"stdout": BoundedLineParser()}
    open_streams = {"stdout": True, "stderr": True}
    write_lock = threading.Lock()
    finished_streams: set[str] = set()
    last_monitor_error = False

    def emit(events: list[dict[str, Any]]) -> None:
        for event in events:
            line = (format_event(event) + "\n").encode("utf-8")
            _write_stream("stdout", line, open_streams, write_lock)

    def safe_tick() -> None:
        nonlocal last_monitor_error
        try:
            emit(monitor.tick(now=monotonic()))
        except Exception as exc:  # The observer must not stop the miner.
            if not last_monitor_error:
                _write_stream(
                    "stderr",
                    f"FL4SH_MONITOR state=MONITOR_ERROR error={type(exc).__name__}\n".encode("ascii", "replace"),
                    open_streams,
                    write_lock,
                )
                last_monitor_error = True

    emit(monitor.tick(now=started_at))
    try:
        while len(finished_streams) < 2:
            try:
                name, data = event_queue.get(timeout=0.5)
            except queue.Empty:
                safe_tick()
                continue
            if data is None:
                if name == "stdout":
                    try:
                        for line_text in parsers[name].feed(b"", final=True):
                            emit(monitor.observe_line(line_text, now=monotonic()))
                    except Exception as exc:  # A malformed sample is not a miner failure.
                        if not last_monitor_error:
                            _write_stream(
                                "stderr",
                                f"FL4SH_MONITOR state=MONITOR_ERROR error={type(exc).__name__}\n".encode("ascii", "replace"),
                                open_streams,
                                write_lock,
                            )
                            last_monitor_error = True
                tail = redactors[name].feed(b"", final=True)
                _write_stream(name, tail, open_streams, write_lock)
                finished_streams.add(name)
                continue

            if name == "stdout":
                try:
                    for line_text in parsers[name].feed(data):
                        emit(monitor.observe_line(line_text, now=monotonic()))
                except Exception as exc:  # A malformed sample is not a miner failure.
                    if not last_monitor_error:
                        _write_stream(
                            "stderr",
                            f"FL4SH_MONITOR state=MONITOR_ERROR error={type(exc).__name__}\n".encode("ascii", "replace"),
                            open_streams,
                            write_lock,
                        )
                        last_monitor_error = True
            safe = redactors[name].feed(data)
            _write_stream(name, safe, open_streams, write_lock)
            safe_tick()
    finally:
        for reader in readers:
            reader.join()
        for pipe in (child.stdout, child.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
        for signum, handler in previous_signals.items():
            signal.signal(signum, handler)

    return_code = child.wait()
    # Match the conventional shell status for signal-terminated children. In
    # particular, SIGKILL cannot be installed as a supervisor signal handler.
    return 128 + abs(return_code) if return_code < 0 else return_code


def _check_config() -> int:
    try:
        config = MonitorConfig.from_env(require_enabled=True)
    except MonitorConfigError as exc:
        print(f"FL4SH_MONITOR configuration invalid: {exc}", file=sys.stderr, flush=True)
        return 64
    print(format_config(config), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--check-config"]:
        return _check_config()
    try:
        config = MonitorConfig.from_env(require_enabled=True)
    except MonitorConfigError as exc:
        print(f"FL4SH_MONITOR configuration invalid: {exc}", file=sys.stderr, flush=True)
        return 64
    if "--" not in args:
        print("FL4SH_MONITOR miner command separator is required", file=sys.stderr, flush=True)
        return 64
    separator = args.index("--")
    if separator != 0:
        print("FL4SH_MONITOR accepts only a command after --", file=sys.stderr, flush=True)
        return 64
    return run_supervisor(config, args[separator + 1 :])


if __name__ == "__main__":
    raise SystemExit(main())
