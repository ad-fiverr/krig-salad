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
import http.client
import json
import math
import os
import queue
import re
import signal
import ssl
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable, Mapping


DEVICE_RATE_RE = re.compile(
    r"Device\s*\[(?P<device>[0-9]+)\]\s+hashRate:\s*"
    r"(?P<rate>[0-9]+(?:\.[0-9]+)?)\s+TH/s"
    r"(?:\s*,\s*stale:\s*(?P<stale>[0-9]+)/(?P<total>[0-9]+)\s*"
    r"\((?P<stale_pct>[0-9]+(?:\.[0-9]+)?)%\))?"
    r"(?:\s*,\s*warm:\s*(?P<warm>[0-9]+))?\b",
    re.IGNORECASE,
)
GPU_KEY_RE = re.compile(
    r"RTX_[0-9]{4}(?:_[A-Z0-9]{1,16})*(?:_(?:LAPTOP|DESKTOP))?"
)
GPU_INITIALIZED_RE = re.compile(
    r"Device\s*\[(?P<device>[0-9]{1,3})\]\s+"
    r"(?P<gpu>[^\r\n:]{1,256})\s*:\s*Initialized\b",
    re.IGNORECASE,
)
PEARL_GPU_RE = re.compile(
    r"(?:Device\s*\[(?P<device>[0-9]{1,3})\]\s*)?"
    r"GPU\s*=\s*(?P<gpu>[^\r\n]{1,256}?)\s+"
    r"Pearl\s+autotune\s+hashrate\s*=",
    re.IGNORECASE,
)
SOLUTIONS_GPU_RE = re.compile(
    r"Solutions\s+accepted:.*?(?P<device>[0-9]{1,3})-"
    r"(?P<gpu>NVIDIA\s+GeForce\s+RTX\s+[^,;\r\n]{1,192})",
    re.IGNORECASE,
)
MAX_PARSE_LINE_BYTES = 64 * 1024
MAX_GPU_REGISTRY_BYTES = 16 * 1024
MAX_GPU_REGISTRY_ENTRIES = 64
MAX_GPU_FLOOR_THS = 10_000.0

PROFILE_FLOORS: dict[str, tuple[str, float]] = {
    "RTX_5080_LAPTOP": ("SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS", 120.0),
    "RTX_5090_LAPTOP": ("SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS", 120.0),
    "RTX_5080_DESKTOP": ("SALAD_G5_GPU_FLOOR_RTX_5080_DESKTOP_THS", 209.0),
    "RTX_5090_DESKTOP": ("SALAD_G5_GPU_FLOOR_RTX_5090_DESKTOP_THS", 350.0),
}
DEFAULT_GPU_FLOORS: dict[str, float] = {
    profile: default for profile, (_env_name, default) in PROFILE_FLOORS.items()
}
GPU_REGISTRY_ENV = "FL4SH_MONITOR_GPU_FLOORS_JSON"
POOL_CONNECTION_FAILED_LINE = "Pool connection failed: mining.authorize response timeout"
POOL_CONNECTION_FAILED_RE = re.compile(
    r"(?:(?P<timestamp>[0-9]{4}/[0-9]{2}/[0-9]{2} "
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}) )?"
    r"Pool connection failed: mining\.authorize response timeout"
    r"; reconnecting; retrying in (?P<retry_seconds>[0-9]{1,5})s"
)
MAX_POOL_RETRY_SECONDS = 86_400
TELEGRAM_QUEUE_CAPACITY = 32
TELEGRAM_TIMEOUT_SECONDS = 5.0
TELEGRAM_MAX_RESPONSE_BYTES = 4096
TELEGRAM_ENABLED_ENV = "FL4SH_TELEGRAM_ENABLED"
TELEGRAM_TOKEN_ENV = "FL4SH_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ENV = "FL4SH_TELEGRAM_CHAT_ID"
TELEGRAM_COOLDOWN_ENV = "FL4SH_TELEGRAM_POOL_ERROR_COOLDOWN_SECONDS"
TELEGRAM_LABEL_ENV = "FL4SH_MONITOR_LABEL"

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


class TelegramConfigError(ValueError):
    """Raised for invalid Telegram settings without echoing supplied values."""


@dataclass(frozen=True)
class TelegramConfig:
    enabled: bool
    bot_token: str | None = field(default=None, repr=False)
    chat_id: str | None = field(default=None, repr=False)
    pool_error_cooldown_seconds: int = 300
    label: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "TelegramConfig":
        env = os.environ if environ is None else environ
        enabled_text = env.get(TELEGRAM_ENABLED_ENV, "0")
        if enabled_text not in {"0", "1"}:
            raise TelegramConfigError(f"{TELEGRAM_ENABLED_ENV} must be 0 or 1")
        enabled = enabled_text == "1"
        if not enabled:
            return cls(enabled=False)

        token = env.get(TELEGRAM_TOKEN_ENV, "")
        if not token or len(token) > 256 or not re.fullmatch(r"[A-Za-z0-9:_-]+", token):
            raise TelegramConfigError(f"{TELEGRAM_TOKEN_ENV} is required and must use supported characters")
        chat_id = env.get(TELEGRAM_CHAT_ENV, "")
        if not chat_id or len(chat_id) > 40 or not re.fullmatch(r"-?[0-9]{1,24}|@[A-Za-z0-9_]{5,32}", chat_id):
            raise TelegramConfigError(f"{TELEGRAM_CHAT_ENV} is required and must be a Telegram chat identifier")
        cooldown = 300
        if TELEGRAM_COOLDOWN_ENV in env:
            raw_cooldown = env[TELEGRAM_COOLDOWN_ENV]
            if len(raw_cooldown) > 5 or not re.fullmatch(r"[0-9]+", raw_cooldown):
                raise TelegramConfigError(f"{TELEGRAM_COOLDOWN_ENV} must be a supported integer")
            cooldown = int(raw_cooldown)
            if cooldown > 86400:
                raise TelegramConfigError(f"{TELEGRAM_COOLDOWN_ENV} exceeds the supported limit")
        label = env.get(TELEGRAM_LABEL_ENV, "")
        if label:
            if len(label) > 64 or any(ord(char) < 32 or ord(char) == 127 for char in label):
                raise TelegramConfigError(f"{TELEGRAM_LABEL_ENV} must be at most 64 printable characters")
            if token in label or chat_id in label:
                raise TelegramConfigError(f"{TELEGRAM_LABEL_ENV} cannot contain notifier credentials")
        return cls(
            enabled=True,
            bot_token=token,
            chat_id=chat_id,
            pool_error_cooldown_seconds=cooldown,
            label=label or None,
        )


@dataclass(frozen=True)
class MonitorConfig:
    enabled: bool
    profile: str | None
    floor_ths: float | None
    floor_source: str
    floor_registry: tuple[tuple[str, float], ...]
    floor_registry_sources: tuple[tuple[str, str], ...]
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
        if profile is not None and not _is_canonical_gpu_key(profile):
            raise MonitorConfigError("FL4SH_MONITOR_PROFILE must be a canonical GPU key")

        floor_registry = dict(DEFAULT_GPU_FLOORS)
        floor_sources = {key: "G5_DEFAULT" for key in floor_registry}
        for key, (floor_env, _default_floor) in PROFILE_FLOORS.items():
            if floor_env in env:
                floor_registry[key] = _parse_env_floor(env[floor_env], floor_env)
                floor_sources[key] = "ENV"

        if GPU_REGISTRY_ENV in env:
            dynamic_floors = _parse_gpu_floor_registry(env[GPU_REGISTRY_ENV])
            for key, value in dynamic_floors.items():
                floor_registry[key] = value
                floor_sources[key] = "ENV_REGISTRY"

        floor: float | None = floor_registry.get(profile) if profile is not None else None
        floor_source = (
            floor_sources.get(profile, "UNCONFIGURED")
            if profile is not None
            else "UNCONFIGURED"
        )

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
            "floor_registry": sorted(floor_registry.items()),
            "floor_registry_sources": sorted(floor_sources.items()),
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
            floor_registry=tuple(sorted(floor_registry.items())),
            floor_registry_sources=tuple(sorted(floor_sources.items())),
            **timing,
            policy_hash=policy_hash,
        )


def _is_canonical_gpu_key(key: str) -> bool:
    return bool(GPU_KEY_RE.fullmatch(key))


def _parse_floor(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise MonitorConfigError(f"{name} values must be numeric")
    try:
        parsed = float(value)
    except (OverflowError, ValueError):
        raise MonitorConfigError(f"{name} values must be finite, positive, and within the supported limit") from None
    if not math.isfinite(parsed) or parsed <= 0 or parsed > MAX_GPU_FLOOR_THS:
        raise MonitorConfigError(f"{name} values must be finite, positive, and within the supported limit")
    return parsed


def _parse_env_floor(value: str, name: str) -> float:
    parsed = _parse_finite_number(value, name, allow_zero=False)
    if parsed > MAX_GPU_FLOOR_THS:
        raise MonitorConfigError(f"{name} exceeds the supported floor limit")
    return parsed


def _parse_gpu_floor_registry(raw: str) -> dict[str, float]:
    if len(raw.encode("utf-8", "replace")) > MAX_GPU_REGISTRY_BYTES:
        raise MonitorConfigError(f"{GPU_REGISTRY_ENV} exceeds the supported size")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        seen_aliases: set[str] = set()
        for key, value in pairs:
            if key in result or key.upper() in seen_aliases:
                raise MonitorConfigError(f"{GPU_REGISTRY_ENV} contains duplicate or aliased keys")
            if not _is_canonical_gpu_key(key):
                raise MonitorConfigError(f"{GPU_REGISTRY_ENV} keys must be canonical GPU keys")
            result[key] = value
            seen_aliases.add(key.upper())
        return result

    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except MonitorConfigError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError, UnicodeError):
        raise MonitorConfigError(f"{GPU_REGISTRY_ENV} must contain a valid JSON object") from None
    if not isinstance(decoded, dict):
        raise MonitorConfigError(f"{GPU_REGISTRY_ENV} must contain a valid JSON object")
    if len(decoded) > MAX_GPU_REGISTRY_ENTRIES:
        raise MonitorConfigError(f"{GPU_REGISTRY_ENV} exceeds the supported entry count")
    return {key: _parse_floor(value, GPU_REGISTRY_ENV) for key, value in decoded.items()}


@dataclass(frozen=True)
class GpuIdentityObservation:
    device_index: int | None
    raw_name: str
    gpu_key: str | None
    source: str


def normalize_gpu_identity(raw_name: str) -> str | None:
    """Normalize Fl4shMiner names, retaining neutral keys when form is absent."""
    match = re.fullmatch(
        r"NVIDIA\s+GeForce\s+RTX\s+(?P<model>[0-9]{4})(?P<tail>.*)",
        raw_name.strip(),
        re.IGNORECASE,
    )
    if match is None:
        return None
    model = match.group("model")
    tokens = re.findall(r"[A-Za-z0-9]+", match.group("tail"))
    tokens = [token.upper() for token in tokens if token.upper() != "GPU"]
    laptop_tags = {"LAPTOP", "NOTEBOOK", "MOBILE"}
    forms = {token for token in tokens if token in laptop_tags | {"DESKTOP"}}
    if len(forms) > 1:
        return None
    if forms:
        form = "LAPTOP" if next(iter(forms)) in laptop_tags else "DESKTOP"
        variants = [token for token in tokens if token not in laptop_tags | {"DESKTOP"}]
    elif not tokens and model in {"5080", "5090"}:
        # Preserve the existing exact 5080/5090 mappings used by the operator.
        # Other models without a form factor remain neutral below.
        form = "DESKTOP"
        variants = []
    else:
        # Preserve the missing form factor as a neutral identity. This can only
        # match an equally neutral registry key; it never inherits a Laptop or
        # Desktop floor.
        form = None
        variants = tokens
    if len(variants) > 3:
        return None
    variant_suffix = "".join(f"_{token}" for token in variants)
    form_suffix = f"_{form}" if form is not None else ""
    key = f"RTX_{model}{variant_suffix}{form_suffix}"
    return key if _is_canonical_gpu_key(key) else None


def parse_gpu_identity_observations(line: str) -> list[GpuIdentityObservation]:
    """Read model identity only; autotune values never become performance samples."""
    observations: list[GpuIdentityObservation] = []
    for match in GPU_INITIALIZED_RE.finditer(line):
        raw_name = match.group("gpu").strip()
        safe_name = _redact_complete_text(raw_name)
        observations.append(
            GpuIdentityObservation(
                int(match.group("device")), raw_name,
                normalize_gpu_identity(raw_name) if safe_name == raw_name else None,
                "device_initialized",
            )
        )
    for match in PEARL_GPU_RE.finditer(line):
        raw_name = match.group("gpu").strip()
        safe_name = _redact_complete_text(raw_name)
        device_text = match.group("device")
        observations.append(
            GpuIdentityObservation(
                int(device_text) if device_text is not None else None,
                raw_name,
                normalize_gpu_identity(raw_name) if safe_name == raw_name else None,
                "pearl_autotune_model",
            )
        )
    for match in SOLUTIONS_GPU_RE.finditer(line):
        raw_name = match.group("gpu").strip()
        safe_name = _redact_complete_text(raw_name)
        observations.append(
            GpuIdentityObservation(
                int(match.group("device")), raw_name,
                normalize_gpu_identity(raw_name) if safe_name == raw_name else None,
                "solutions_accepted_model",
            )
        )
    return observations


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
    identity_candidates: set[str] = field(default_factory=set)
    identity_sources: set[str] = field(default_factory=set)
    identity_primary_seen: bool = False
    gpu_key: str | None = None
    gpu_raw_name: str | None = None
    gpu_identity_source: str | None = None
    gpu_identity_status: str = "UNOBSERVED"
    identity_conflict: bool = False
    profile_mismatch: bool = False
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
        timestamp = time.monotonic() if now is None else now
        events: list[dict[str, Any]] = []
        for observation in parse_gpu_identity_observations(line):
            device_index = observation.device_index
            if device_index is None:
                # An unindexed autotune observation is corroboration only after
                # the primary Device [N] Initialized identity exists.
                if len(self.devices) != 1:
                    continue
                device_index = next(iter(self.devices))
                if not self.devices[device_index].identity_primary_seen:
                    continue
            state = self.devices.setdefault(device_index, DeviceState(device_index))
            events.extend(self._apply_identity(state, observation))

        sample = parse_device_hashrate(line)
        if sample is None:
            return events
        state = self.devices.setdefault(sample.device_index, DeviceState(sample.device_index))
        if state.samples and timestamp <= state.samples[-1].monotonic_seconds:
            state.duplicate_timestamps += 1
            return events
        state.samples.append(SamplePoint(timestamp, sample))
        self._trim_samples(state, timestamp)
        if state.last_state is None:
            floor, _source, _issue = self._effective_floor(state)
            initial_state = "WARMUP" if floor is not None else "NO_FLOOR_CONFIGURED"
            state.last_state = initial_state
            events.append(self._event(state, initial_state, observed=sample.hashrate_ths))
        return events

    def _effective_floor(
        self, state: DeviceState | None
    ) -> tuple[float | None, str, str | None]:
        if state is not None and state.identity_conflict:
            return None, "IDENTITY_CONFLICT", "GPU_IDENTITY_CONFLICT"
        if state is not None and state.profile_mismatch:
            return None, "PROFILE_MISMATCH", "GPU_PROFILE_MISMATCH"
        if state is not None and state.gpu_identity_status == "UNKNOWN":
            return None, "UNCONFIGURED", "NO_FLOOR_CONFIGURED"
        if self.config.profile is not None:
            if state is not None and state.gpu_key and state.gpu_key != self.config.profile:
                return None, "PROFILE_MISMATCH", "GPU_PROFILE_MISMATCH"
            if self.config.floor_ths is None:
                return None, "UNCONFIGURED", "NO_FLOOR_CONFIGURED"
            return self.config.floor_ths, "PROFILE_OVERRIDE", None
        if state is None or state.gpu_identity_status != "DETECTED" or state.gpu_key is None:
            return None, "UNCONFIGURED", "NO_FLOOR_CONFIGURED"
        registry = dict(self.config.floor_registry)
        sources = dict(self.config.floor_registry_sources)
        floor = registry.get(state.gpu_key)
        if floor is None:
            return None, "UNCONFIGURED", "NO_FLOOR_CONFIGURED"
        return floor, sources.get(state.gpu_key, "ENV_REGISTRY"), None

    def _apply_identity(
        self, state: DeviceState, observation: GpuIdentityObservation
    ) -> list[dict[str, Any]]:
        prior_status = state.gpu_identity_status
        is_primary = observation.source == "device_initialized"
        state.identity_sources.add(observation.source)
        if observation.gpu_key is not None:
            if state.identity_candidates and observation.gpu_key not in state.identity_candidates:
                state.identity_conflict = True
            state.identity_candidates.add(observation.gpu_key)
        elif state.identity_candidates:
            # A GPU-specific but ambiguous observation cannot silently leave
            # an older model's floor and low-performance episode active.
            state.identity_conflict = True
        else:
            state.gpu_identity_status = "UNKNOWN"
            state.gpu_key = None
            state.consecutive_bad_windows = 0
            state.recommendation_emitted = False
            if is_primary or state.gpu_raw_name is None:
                state.gpu_raw_name = observation.raw_name
                state.gpu_identity_source = observation.source
            state.last_state = "GPU_IDENTITY_UNKNOWN"
            if prior_status != "UNKNOWN":
                return [self._event(state, "GPU_IDENTITY_UNKNOWN", observed=self._latest_rate(state))]
            return []

        if state.identity_conflict:
            state.gpu_key = None
            state.gpu_identity_status = "CONFLICT"
            state.profile_mismatch = False
            state.consecutive_bad_windows = 0
            state.recommendation_emitted = False
            state.last_state = "GPU_IDENTITY_CONFLICT"
            if prior_status != "CONFLICT":
                return [self._event(state, "GPU_IDENTITY_CONFLICT", observed=self._latest_rate(state))]
            return []

        if observation.gpu_key is None:
            return []

        if not is_primary:
            # Secondary sources may confirm or conflict with a primary source,
            # but may never establish an identity or enable a floor by themselves.
            if not state.identity_primary_seen:
                state.gpu_key = None
                state.gpu_identity_status = "UNKNOWN"
                state.consecutive_bad_windows = 0
                state.recommendation_emitted = False
                state.last_state = "GPU_IDENTITY_UNKNOWN"
                if prior_status != "UNKNOWN":
                    return [self._event(state, "GPU_IDENTITY_UNKNOWN", observed=self._latest_rate(state))]
            return []

        state.identity_primary_seen = True
        state.gpu_key = observation.gpu_key
        state.gpu_identity_status = "DETECTED"
        state.gpu_raw_name = observation.raw_name
        state.gpu_identity_source = observation.source
        if self.config.profile is not None and observation.gpu_key != self.config.profile:
            state.profile_mismatch = True
            state.gpu_identity_status = "PROFILE_MISMATCH"
            state.consecutive_bad_windows = 0
            state.recommendation_emitted = False
            state.last_state = "GPU_PROFILE_MISMATCH"
            if prior_status != "PROFILE_MISMATCH":
                return [self._event(state, "GPU_PROFILE_MISMATCH", observed=self._latest_rate(state))]
            return []
        if state.last_state == "NO_FLOOR_CONFIGURED":
            state.last_state = None
        if prior_status not in {"DETECTED", "PROFILE_MISMATCH"}:
            return [self._event(state, "GPU_DETECTED", observed=self._latest_rate(state))]
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
            if not state.samples:
                if state.identity_conflict or state.profile_mismatch:
                    continue
                if (
                    state.last_evaluation_at is not None
                    and timestamp - state.last_evaluation_at < self.config.reevaluation_interval_seconds
                ):
                    continue
                state.last_evaluation_at = timestamp
                elapsed = timestamp - self.started_at
                if elapsed < self.config.warmup_seconds:
                    no_sample_state = "WARMUP"
                elif elapsed < self.config.warmup_seconds + self.config.maximum_sample_gap_seconds:
                    no_sample_state = "INSUFFICIENT_DATA"
                else:
                    no_sample_state = "TELEMETRY_STALE"
                events.extend(self._set_state(state, no_sample_state, observed=None))
                continue
            if (
                state.last_evaluation_at is not None
                and timestamp - state.last_evaluation_at < self.config.reevaluation_interval_seconds
            ):
                continue
            state.last_evaluation_at = timestamp
            _floor, _floor_source, identity_issue = self._effective_floor(state)
            if identity_issue in {"GPU_IDENTITY_CONFLICT", "GPU_PROFILE_MISMATCH"}:
                state.consecutive_bad_windows = 0
                events.extend(
                    self._set_state(state, identity_issue, observed=self._latest_rate(state))
                )
                continue
            if timestamp - self.started_at < self.config.warmup_seconds:
                events.extend(self._set_state(state, "WARMUP", observed=self._latest_rate(state)))
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
            floor, _floor_source, floor_issue = self._effective_floor(state)
            if floor is None:
                state.consecutive_bad_windows = 0
                stats = self._window_stats(state, timestamp)
                events.extend(
                    self._set_state(
                        state,
                        floor_issue or "NO_FLOOR_CONFIGURED",
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
            if mean_rate < floor:
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
        floor, floor_source, _identity_issue = self._effective_floor(state)
        identity_sources = sorted(state.identity_sources) if state is not None else []
        return {
            "component": "FL4SH_MONITOR",
            "state": state_name,
            "profile": self.config.profile or "unknown",
            "profile_is_operator_configuration_only": True,
            "device": device,
            "device_namespace": "fl4shminer_device" if state is not None else "unknown",
            "gpu_key": state.gpu_key if state is not None and state.gpu_key else "unknown",
            "gpu_raw": _redact_complete_text(state.gpu_raw_name) if state is not None and state.gpu_raw_name else None,
            "gpu_identity_status": state.gpu_identity_status if state is not None else "UNKNOWN",
            "gpu_identity_sources": identity_sources,
            "gpu_identity_candidates": sorted(state.identity_candidates) if state is not None else [],
            "floor_ths": floor,
            "floor_source": floor_source,
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
            "source": (
                f"fl4shminer_stdout:{state.gpu_identity_source or 'identity'}"
                if state is not None and state_name in {
                    "GPU_DETECTED", "GPU_IDENTITY_UNKNOWN", "GPU_IDENTITY_CONFLICT", "GPU_PROFILE_MISMATCH"
                }
                else "fl4shminer_stdout:Device hashRate"
            ),
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
        f'gpu_key={event["gpu_key"]}',
        f'gpu_candidates={",".join(event["gpu_identity_candidates"]) or "unknown"}',
        f'gpu_raw={json.dumps(event["gpu_raw"], ensure_ascii=True) if event["gpu_raw"] is not None else "unknown"}',
        f'floor={_format_number(floor)}',
        f'floor_ths={_format_number(floor)}',
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


def format_config(config: MonitorConfig, *, telegram_enabled: bool = False) -> str:
    fields = [
        "FL4SH_MONITOR",
        "state=CONFIG",
        "enabled=true",
        f"profile={config.profile or 'unknown'}",
        f"floor={_format_number(config.floor_ths)}",
        f"floor_source={config.floor_source}",
        f"floor_registry_entries={len(config.floor_registry)}",
        "floor_registry_sources=G5_DEFAULT+SALAD_G5_GPU_FLOOR_*+FL4SH_MONITOR_GPU_FLOORS_JSON",
        f"warmup_seconds={config.warmup_seconds}",
        f"expected_sample_interval_seconds={config.expected_sample_interval_seconds}",
        f"hash_window_seconds={config.hash_window_seconds}",
        f"reevaluation_interval_seconds={config.reevaluation_interval_seconds}",
        f"minimum_samples_per_window={config.minimum_samples_per_window}",
        f"maximum_sample_gap_seconds={config.maximum_sample_gap_seconds}",
        f"minimum_window_coverage_ratio={_format_number(config.minimum_window_coverage_ratio)}",
        f"consecutive_bad_windows={config.consecutive_bad_windows}",
        f"policy_hash={config.policy_hash}",
    ]
    if telegram_enabled:
        fields.append("telegram_enabled=true")
    fields.extend(
        [
            "provider_binding=UNKNOWN",
            "gpu_identity_verified=false",
            "billing=UNKNOWN",
            "actions_performed=false",
        ]
    )
    return " ".join(fields)


def format_telegram_message(
    event_name: str,
    event: Mapping[str, Any],
    *,
    alert_id: str,
    monitor_session_id: str | None,
    label: str | None,
) -> str:
    """Build a bounded plain-text audit message from local monitor evidence."""
    stale = event.get("stale_counter")
    stale_text = "unknown"
    if isinstance(stale, Mapping):
        numerator = stale.get("numerator", "unknown")
        denominator = stale.get("denominator", "unknown")
        reported_percent = stale.get("reported_percent")
        if (
            isinstance(reported_percent, (int, float))
            and math.isfinite(float(reported_percent))
        ):
            stale_text = (
                f"{numerator}/{denominator} "
                f"({_format_number(reported_percent)}%)"
            )
        else:
            stale_text = f"{numerator}/{denominator} (unknown)"
    timestamp = event.get("timestamp_utc") or datetime.now(timezone.utc).isoformat(timespec="seconds")
    fields = [
        "Fl4shMiner audit alert",
        f"event: {event_name}",
        f"alert_id: {alert_id}",
        f"monitor_session_id: {monitor_session_id or 'unknown'}",
    ]
    if event_name == "POOL_CONNECTION_FAILED":
        fields.append("reason: MINING_AUTHORIZE_RESPONSE_TIMEOUT")
        retry_seconds = event.get("retry_seconds")
        if (
            isinstance(retry_seconds, int)
            and not isinstance(retry_seconds, bool)
            and 1 <= retry_seconds <= MAX_POOL_RETRY_SECONDS
        ):
            fields.append(f"retry: {retry_seconds}s")
        else:
            fields.append("retry: unknown")
    if label:
        fields.append(f"label: {label}")
    fields.extend(
        [
            f"GPU: {event.get('gpu_key') or 'unknown'}",
            f"device: {event.get('device') or 'unknown'}",
            f"floor_ths: {_format_number(event.get('floor_ths'))}",
            f"observed_window_mean_ths: {_format_number(event.get('observed_window_mean_ths'))}",
            "bad_windows: "
            f"{event.get('consecutive_bad_windows', 0)}/{event.get('consecutive_bad_windows_required', 0)}",
            f"stale_counter: {stale_text}",
            f"timestamp_utc: {timestamp}",
            "actions_performed: false",
            "Machine ID: correlate Alert ID in Salad Logs",
        ]
    )
    # All inserted data is local and bounded by parser/config validation. This
    # final cap also protects Telegram's message limit if a future event grows.
    return "\n".join(fields)[:3500]


def _send_telegram_message(
    config: TelegramConfig,
    message: str,
    *,
    connection_factory: Callable[..., Any] | None = None,
) -> bool:
    """POST one message to the fixed Bot API host; never expose transport errors."""
    if not config.enabled or not config.bot_token or not config.chat_id:
        return False
    connection: Any | None = None
    try:
        factory = connection_factory or http.client.HTTPSConnection
        connection = factory(
            "api.telegram.org",
            443,
            timeout=TELEGRAM_TIMEOUT_SECONDS,
            context=ssl.create_default_context(),
        )
        body = json.dumps(
            {"chat_id": config.chat_id, "text": message},
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        # Bot API requires the token in the path. The path is never logged,
        # included in errors, or persisted; HTTPSConnection targets the fixed
        # official host directly and does not use environment proxy settings.
        connection.request(
            "POST",
            f"/bot{config.bot_token}/sendMessage",
            body=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        response = connection.getresponse()
        response_body = response.read(TELEGRAM_MAX_RESPONSE_BYTES + 1)
        if response.status != 200 or len(response_body) > TELEGRAM_MAX_RESPONSE_BYTES:
            return False
        try:
            decoded = json.loads(response_body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return False
        return isinstance(decoded, dict) and decoded.get("ok") is True
    except Exception:
        # Exceptions can contain the request target (and therefore the bot
        # token); deliberately discard their text and traceback.
        return False
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


class TelegramNotifier:
    """One bounded, non-blocking notification worker. Disabled means no thread."""

    def __init__(
        self,
        config: TelegramConfig,
        *,
        audit: Callable[[str], None],
        sender: Callable[[TelegramConfig, str], bool] | None = None,
        queue_capacity: int = TELEGRAM_QUEUE_CAPACITY,
    ) -> None:
        self.config = config
        self.audit = audit
        self.sender = sender or _send_telegram_message
        self._queue: queue.Queue[tuple[str, str, str] | None] | None = None
        self._worker: threading.Thread | None = None
        if config.enabled:
            self._queue = queue.Queue(maxsize=queue_capacity)
            self._worker = threading.Thread(target=self._run, name="fl4sh-telegram-audit", daemon=True)
            self._worker.start()

    def submit(self, event_name: str, event: Mapping[str, Any], *, monitor_session_id: str) -> str | None:
        if not self.config.enabled or self._queue is None:
            return None
        alert_id = str(uuid.uuid4())
        message = format_telegram_message(
            event_name,
            event,
            alert_id=alert_id,
            monitor_session_id=monitor_session_id,
            label=self.config.label,
        )
        self.audit(
            f"FL4SH_MONITOR state=TELEGRAM_ALERT alert_id={alert_id} "
            f"event={event_name} actions_performed=false"
        )
        try:
            self._queue.put_nowait((alert_id, event_name, message))
        except queue.Full:
            self.audit(
                f"FL4SH_MONITOR state=TELEGRAM_NOTIFY_FAILED alert_id={alert_id} "
                "reason=QUEUE_FULL actions_performed=false"
            )
            return alert_id
        return alert_id

    def _run(self) -> None:
        assert self._queue is not None
        while True:
            item = self._queue.get()
            if item is None:
                return
            alert_id, event_name, message = item
            try:
                sent = bool(self.sender(self.config, message))
            except Exception:
                # Sender exception text may contain the bot token URL.
                sent = False
            if sent:
                self.audit(
                    f"FL4SH_MONITOR state=TELEGRAM_NOTIFY_SENT alert_id={alert_id} "
                    f"event={event_name} actions_performed=false"
                )
            else:
                self.audit(
                    f"FL4SH_MONITOR state=TELEGRAM_NOTIFY_FAILED alert_id={alert_id} "
                    f"event={event_name} reason=TRANSPORT actions_performed=false"
                )

    def close(self) -> None:
        if self._queue is None or self._worker is None:
            return
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            # The daemon worker drains accepted records; process shutdown must
            # never wait behind network I/O or an unbounded queue operation.
            return
        self._worker.join(timeout=0.1)


class TelegramAlertCoordinator:
    """Apply per-episode recommendation dedup and monotonic pool cooldown."""

    def __init__(
        self,
        notifier: TelegramNotifier,
        config: TelegramConfig,
        *,
        monotonic: Callable[[], float],
        monitor_session_id: str,
    ) -> None:
        self.notifier = notifier
        self.config = config
        self.monotonic = monotonic
        self.monitor_session_id = monitor_session_id
        self._recommendation_devices: set[str] = set()
        self._last_pool_alert_at: float | None = None

    def monitor_events(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            device = str(event.get("device") or "unknown")
            if event.get("state") == "RECOVERED":
                self._recommendation_devices.discard(device)
            elif event.get("state") == "REALLOCATE_RECOMMENDED":
                if device not in self._recommendation_devices:
                    self._recommendation_devices.add(device)
                    self.notifier.submit(
                        "REALLOCATE_RECOMMENDED", event,
                        monitor_session_id=self.monitor_session_id,
                    )

    def stdout_line(self, line: str, monitor: Fl4shMonitor) -> None:
        retry_seconds = _parse_pool_connection_failed_retry_seconds(line)
        if retry_seconds is None:
            return
        now = self.monotonic()
        if (
            self._last_pool_alert_at is not None
            and now - self._last_pool_alert_at < self.config.pool_error_cooldown_seconds
        ):
            return
        self._last_pool_alert_at = now
        event = _pool_alert_context(monitor)
        event["retry_seconds"] = retry_seconds
        self.notifier.submit(
            "POOL_CONNECTION_FAILED", event,
            monitor_session_id=self.monitor_session_id,
        )


def _parse_pool_connection_failed_retry_seconds(line: str) -> int | None:
    """Match only the known authorize-timeout/reconnect line, with bounded retry."""
    if not isinstance(line, str) or len(line) > 256:
        return None
    match = POOL_CONNECTION_FAILED_RE.fullmatch(line)
    if match is None:
        return None
    timestamp = match.group("timestamp")
    if timestamp is not None:
        try:
            datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
    retry_seconds = int(match.group("retry_seconds"))
    if not 1 <= retry_seconds <= MAX_POOL_RETRY_SECONDS:
        return None
    return retry_seconds


def _pool_alert_context(monitor: Fl4shMonitor) -> dict[str, Any]:
    state = next(iter(monitor.devices.values())) if len(monitor.devices) == 1 else None
    floor, _source, _issue = monitor._effective_floor(state)
    latest = state.samples[-1].sample if state is not None and state.samples else None
    return {
        "gpu_key": state.gpu_key if state is not None else "unknown",
        "device": f"fl4shminer_device:{state.device_index}" if state is not None else "unknown",
        "floor_ths": floor,
        "observed_window_mean_ths": state.last_window_mean_ths if state is not None else None,
        "consecutive_bad_windows": state.consecutive_bad_windows if state is not None else 0,
        "consecutive_bad_windows_required": monitor.config.consecutive_bad_windows,
        "stale_counter": (
            {
                "numerator": latest.stale_count,
                "denominator": latest.stale_total,
                "reported_percent": latest.stale_percent,
            }
            if latest is not None and latest.stale_count is not None
            else None
        ),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


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


def _redact_complete_text(value: str, extra_secrets: list[str] | None = None) -> str:
    """Redact a complete record using the same secret policy as raw streams."""
    secret = os.environ.get("FL4SH_MINING_ID", "")
    redactor = StreamingRedactor([secret, *(extra_secrets or [])])
    return redactor.feed(value.encode("utf-8"), final=True).decode("utf-8", errors="replace")


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
    telegram_config: TelegramConfig | None = None,
    telegram_sender: Callable[[TelegramConfig, str], bool] | None = None,
) -> int:
    if not config.enabled:
        print("FL4SH_MONITOR requires FL4SH_MONITOR_ENABLED=1", file=sys.stderr, flush=True)
        return 64
    if not command:
        print("FL4SH_MONITOR requires a fixed miner command", file=sys.stderr, flush=True)
        return 64
    try:
        notifier_config = telegram_config or TelegramConfig.from_env()
    except TelegramConfigError as exc:
        print(f"FL4SH_TELEGRAM configuration invalid: {exc}", file=sys.stderr, flush=True)
        return 64

    started_at = monotonic()
    monitor = Fl4shMonitor(config, start_monotonic=started_at)
    print(format_config(config, telegram_enabled=notifier_config.enabled), flush=True)
    event_queue: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=256)
    child_ref: dict[str, subprocess.Popen[bytes] | None] = {"child": None}
    previous_signals, pending_signal = _install_signal_forwarding(child_ref)
    try:
        child_kwargs: dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "bufsize": 0,
        }
        if notifier_config.enabled:
            child_environment = os.environ.copy()
            # Telegram credentials are for the supervisor only. The miner
            # child never inherits notifier settings when alerts are enabled.
            for secret_name in (
                TELEGRAM_TOKEN_ENV,
                TELEGRAM_CHAT_ENV,
                TELEGRAM_ENABLED_ENV,
                TELEGRAM_COOLDOWN_ENV,
                TELEGRAM_LABEL_ENV,
            ):
                child_environment.pop(secret_name, None)
            child_kwargs["env"] = child_environment
        child = popen_factory(command, **child_kwargs)
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

    relay_secrets = [
        os.environ.get("FL4SH_MINING_ID", ""),
        notifier_config.bot_token or "",
        notifier_config.chat_id or "",
    ]
    redactors = {
        "stdout": StreamingRedactor(relay_secrets),
        "stderr": StreamingRedactor(relay_secrets),
    }
    parsers = {"stdout": BoundedLineParser()}
    open_streams = {"stdout": True, "stderr": True}
    write_lock = threading.Lock()
    finished_streams: set[str] = set()
    last_monitor_error = False
    monitor_session_id = str(uuid.uuid4()) if notifier_config.enabled else ""

    def telegram_audit(line: str) -> None:
        _write_stream("stdout", (line + "\n").encode("utf-8"), open_streams, write_lock)

    notifier = TelegramNotifier(
        notifier_config,
        audit=telegram_audit,
        sender=telegram_sender,
    )
    alert_coordinator = (
        TelegramAlertCoordinator(
            notifier,
            notifier_config,
            monotonic=monotonic,
            monitor_session_id=monitor_session_id,
        )
        if notifier_config.enabled
        else None
    )

    def emit(events: list[dict[str, Any]]) -> None:
        for event in events:
            line = _redact_complete_text(
                format_event(event) + "\n",
                [notifier_config.bot_token or "", notifier_config.chat_id or ""],
            ).encode("utf-8")
            _write_stream("stdout", line, open_streams, write_lock)
        if alert_coordinator is not None:
            alert_coordinator.monitor_events(events)

    def process_stdout_line(line_text: str) -> None:
        emit(monitor.observe_line(line_text, now=monotonic()))
        if alert_coordinator is not None:
            alert_coordinator.stdout_line(line_text, monitor)

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
                            process_stdout_line(line_text)
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
                        process_stdout_line(line_text)
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
        notifier.close()

    return_code = child.wait()
    # Match the conventional shell status for signal-terminated children. In
    # particular, SIGKILL cannot be installed as a supervisor signal handler.
    return 128 + abs(return_code) if return_code < 0 else return_code


def _check_config() -> int:
    try:
        config = MonitorConfig.from_env(require_enabled=True)
        telegram_config = TelegramConfig.from_env()
    except (MonitorConfigError, TelegramConfigError) as exc:
        print(f"FL4SH_MONITOR configuration invalid: {exc}", file=sys.stderr, flush=True)
        return 64
    print(format_config(config, telegram_enabled=telegram_config.enabled), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--check-config"]:
        return _check_config()
    try:
        config = MonitorConfig.from_env(require_enabled=True)
        telegram_config = TelegramConfig.from_env()
    except (MonitorConfigError, TelegramConfigError) as exc:
        print(f"FL4SH_MONITOR configuration invalid: {exc}", file=sys.stderr, flush=True)
        return 64
    if "--" not in args:
        print("FL4SH_MONITOR miner command separator is required", file=sys.stderr, flush=True)
        return 64
    separator = args.index("--")
    if separator != 0:
        print("FL4SH_MONITOR accepts only a command after --", file=sys.stderr, flush=True)
        return 64
    return run_supervisor(
        config,
        args[separator + 1 :],
        telegram_config=telegram_config,
    )


if __name__ == "__main__":
    raise SystemExit(main())
