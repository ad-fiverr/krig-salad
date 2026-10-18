"""Strict local G5 configuration with operator tunables and fixed safety gates.

Only an explicit allowlist of operational tuning variables is read from the
environment. Credentials and capability flags are intentionally not supported
there; this build remains offline and local-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping


ORGANIZATION = "adrianfiverr"
PROJECT = "miners"
GROUPS = ("fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4")
FLOORS = {
    "RTX 5090|laptop|salad_json_log_gpu_class_name": 120,
    "RTX 5080|laptop|salad_json_log_gpu_class_name": 120,
    "RTX 5090|desktop|salad_json_log_gpu_class_name": 350,
    "RTX 5080|desktop|salad_json_log_gpu_class_name": 209,
}

MONITOR_DEFAULTS: dict[str, int | float] = {
    "warmup_seconds": 90,
    "expected_sample_interval_seconds": 10,
    "hash_window_seconds": 120,
    "reevaluation_interval_seconds": 30,
    "minimum_samples_per_window": 10,
    "maximum_sample_gap_seconds": 30,
    "minimum_window_coverage_ratio": 0.8,
    "consecutive_bad_windows": 2,
}

FLOOR_ENVIRONMENT = {
    "SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS": "RTX 5080|laptop|salad_json_log_gpu_class_name",
    "SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS": "RTX 5090|laptop|salad_json_log_gpu_class_name",
    "SALAD_G5_GPU_FLOOR_RTX_5080_DESKTOP_THS": "RTX 5080|desktop|salad_json_log_gpu_class_name",
    "SALAD_G5_GPU_FLOOR_RTX_5090_DESKTOP_THS": "RTX 5090|desktop|salad_json_log_gpu_class_name",
}
MONITOR_ENVIRONMENT = {
    "SALAD_G5_WARMUP_SECONDS": "warmup_seconds",
    "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "expected_sample_interval_seconds",
    "SALAD_G5_HASH_WINDOW_SECONDS": "hash_window_seconds",
    "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "reevaluation_interval_seconds",
    "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "minimum_samples_per_window",
    "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "maximum_sample_gap_seconds",
    "SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO": "minimum_window_coverage_ratio",
    "SALAD_G5_CONSECUTIVE_BAD_WINDOWS": "consecutive_bad_windows",
}
PRICE_ENVIRONMENT = "SALAD_G5_HOURLY_PRICE_USD_ESTIMATE"


class G5ConfigError(ValueError):
    pass


def _finite_positive(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise G5ConfigError(f"{name} must be a finite positive number")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise G5ConfigError(f"{name} must be a finite positive number")
    return parsed


def _integer(value: Any, name: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise G5ConfigError(f"{name} must be an integer")
    if value < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise G5ConfigError(f"{name} must be a {qualifier} integer")
    return value


def _validate_floors(value: Any) -> dict[str, float]:
    if not isinstance(value, Mapping):
        raise G5ConfigError("gpu_floors_ths must be a JSON object keyed by verified model, form factor, and source")
    allowed = set(FLOORS)
    floors: dict[str, float] = {}
    for key, floor in value.items():
        if not isinstance(key, str) or key not in allowed:
            raise G5ConfigError("GPU floor identity must exactly match a supported verified model/form-factor/source key")
        floors[key] = _finite_positive(floor, f"gpu_floors_ths.{key}")
    return floors


def _validated_monitor(values: Mapping[str, Any]) -> dict[str, int | float]:
    monitor: dict[str, int | float] = {}
    for key, default in MONITOR_DEFAULTS.items():
        value = values.get(key, default)
        if key == "warmup_seconds":
            monitor[key] = _integer(value, key, allow_zero=True)
        elif key == "minimum_window_coverage_ratio":
            ratio = _finite_positive(value, key)
            if ratio > 1:
                raise G5ConfigError("minimum_window_coverage_ratio must be within (0, 1]")
            monitor[key] = ratio
        else:
            monitor[key] = _integer(value, key)

    interval = monitor["expected_sample_interval_seconds"]
    window = monitor["hash_window_seconds"]
    maximum_gap = monitor["maximum_sample_gap_seconds"]
    minimum_samples = monitor["minimum_samples_per_window"]
    expected_samples = math.ceil(window / interval)
    if maximum_gap < interval:
        raise G5ConfigError("maximum_sample_gap_seconds cannot be shorter than expected_sample_interval_seconds")
    if minimum_samples > expected_samples:
        raise G5ConfigError("minimum_samples_per_window exceeds the expected samples in hash_window_seconds")
    return monitor


def _environment_number(raw: str, name: str, *, integer: bool) -> int | float:
    if not isinstance(raw, str) or not raw.strip():
        raise G5ConfigError(f"{name} must not be empty")
    value = raw.strip()
    try:
        if integer:
            if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
                raise ValueError
            return int(value)
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError
        return parsed
    except ValueError:
        raise G5ConfigError(f"{name} must be a finite {'integer' if integer else 'number'}") from None


@dataclass(frozen=True)
class G5Config:
    mode: str = "offline_local"
    host: str = "127.0.0.1"
    port: int = 8765
    organization: str = ORGANIZATION
    project: str = PROJECT
    container_groups: tuple[str, ...] = GROUPS
    gpu_floors_ths: Mapping[str, float] = field(default_factory=lambda: dict(FLOORS))
    warmup_seconds: int = 90
    expected_sample_interval_seconds: int = 10
    hash_window_seconds: int = 120
    reevaluation_interval_seconds: int = 30
    minimum_samples_per_window: int = 10
    maximum_sample_gap_seconds: int = 30
    minimum_window_coverage_ratio: float = 0.8
    consecutive_bad_windows: int = 2
    salad_hourly_price_usd_estimate: float | None = None
    value_sources: Mapping[str, str] | None = None
    live_get_enabled: bool = False
    live_actions_enabled: bool = False
    live_spend_authorized: bool = False
    auto_reallocate: bool = False
    hard_budget_usd: float = 30.0
    kill_switch_engaged: bool = True
    firebase_enabled: bool = False
    firebase_project_id: str = "demo-salad-miners"
    state_dir: str = "~/.local/share/salad-miners-g5"
    local_telemetry_sources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode != "offline_local":
            raise G5ConfigError("this build accepts only offline_local mode")
        if self.host != "127.0.0.1":
            raise G5ConfigError("control-plane host must be exactly 127.0.0.1")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1024 <= self.port <= 65535:
            raise G5ConfigError("control-plane port must be an unprivileged local port")
        if not isinstance(self.state_dir, str) or not self.state_dir.strip():
            raise G5ConfigError("local state directory must be a non-empty path string")
        if (
            not isinstance(self.local_telemetry_sources, tuple)
            or any(not isinstance(item, str) or not item.strip() for item in self.local_telemetry_sources)
            or len(set(self.local_telemetry_sources)) != len(self.local_telemetry_sources)
        ):
            raise G5ConfigError("local telemetry sources must be a tuple of unique configured paths")
        if self.organization != ORGANIZATION or self.project != PROJECT or tuple(self.container_groups) != GROUPS:
            raise G5ConfigError("Salad scope must exactly match the approved organization, project, and four groups")
        flags = {
            "live_get_enabled": self.live_get_enabled,
            "live_actions_enabled": self.live_actions_enabled,
            "live_spend_authorized": self.live_spend_authorized,
            "auto_reallocate": self.auto_reallocate,
            "kill_switch_engaged": self.kill_switch_engaged,
            "firebase_enabled": self.firebase_enabled,
        }
        if any(type(value) is not bool for value in flags.values()):
            raise G5ConfigError("all G5 feature and safety flags must be JSON booleans")
        if self.firebase_enabled or self.firebase_project_id != "demo-salad-miners":
            raise G5ConfigError("Firebase production is unavailable; only the local demo project is allowed")
        floors = _validate_floors(self.gpu_floors_ths)
        if not floors:
            raise G5ConfigError("at least one verified GPU floor must be configured")
        object.__setattr__(self, "gpu_floors_ths", MappingProxyType(floors))
        monitor = _validated_monitor({key: getattr(self, key) for key in MONITOR_DEFAULTS})
        for key, value in monitor.items():
            object.__setattr__(self, key, value)
        if self.salad_hourly_price_usd_estimate is not None:
            object.__setattr__(self, "salad_hourly_price_usd_estimate", _finite_positive(self.salad_hourly_price_usd_estimate, "salad_hourly_price_usd_estimate"))
        if (
            not isinstance(self.hard_budget_usd, (int, float))
            or isinstance(self.hard_budget_usd, bool)
            or not math.isfinite(float(self.hard_budget_usd))
            or not 0 < self.hard_budget_usd <= 30.0
        ):
            raise G5ConfigError("hard budget must be positive and no more than USD 30.00")
        if any((self.live_get_enabled, self.live_actions_enabled, self.live_spend_authorized, self.auto_reallocate)):
            raise G5ConfigError("live access, spend, and actions are disabled in the offline G5 build")
        if self.value_sources is None:
            sources = {
                f"gpu_floors_ths.{key}": "DEFAULTS" if value == FLOORS[key] else "PYTHON"
                for key, value in floors.items()
            }
            sources.update({
                key: ("DEFAULTS" if value == MONITOR_DEFAULTS[key] else "PYTHON")
                for key, value in monitor.items()
            })
            sources["salad_hourly_price_usd_estimate"] = "DEFAULTS" if self.salad_hourly_price_usd_estimate is None else "PYTHON"
            object.__setattr__(self, "value_sources", MappingProxyType(sources))
        elif any(origin not in {"DEFAULTS", "JSON", "ENV", "PYTHON"} for origin in self.value_sources.values()):
            raise G5ConfigError("configuration source labels are invalid")
        else:
            object.__setattr__(self, "value_sources", MappingProxyType(dict(self.value_sources)))

    def source_for(self, name: str) -> str:
        assert self.value_sources is not None
        return str(self.value_sources.get(name, "DEFAULTS"))


def _parse(value: Mapping[str, Any], *, environ: Mapping[str, str] | None = None) -> G5Config:
    scope = value.get("salad") if isinstance(value.get("salad"), Mapping) else {}
    actions = value.get("actions") if isinstance(value.get("actions"), Mapping) else {}
    server = value.get("server") if isinstance(value.get("server"), Mapping) else {}
    monitor_json = value.get("monitor", {})
    if not isinstance(monitor_json, Mapping):
        raise G5ConfigError("monitor must be a JSON object")
    if set(monitor_json) - set(MONITOR_DEFAULTS):
        raise G5ConfigError("monitor contains an unsupported parameter")
    raw_floors = value.get("gpu_floors_ths", {})
    if not isinstance(raw_floors, Mapping):
        raise G5ConfigError("gpu_floors_ths must be a JSON object")
    floors = dict(FLOORS)
    sources: dict[str, str] = {f"gpu_floors_ths.{key}": "DEFAULTS" for key in FLOORS}
    for key, floor in raw_floors.items():
        if not isinstance(key, str) or key not in FLOORS:
            raise G5ConfigError("GPU floor identity must exactly match a supported verified model/form-factor/source key")
        floors[key] = floor
        sources[f"gpu_floors_ths.{key}"] = "JSON"
    monitor_values: dict[str, Any] = dict(MONITOR_DEFAULTS)
    for key in MONITOR_DEFAULTS:
        if key in monitor_json:
            monitor_values[key] = monitor_json[key]
            sources[key] = "JSON"
        else:
            sources[key] = "DEFAULTS"
    price = value.get("salad_hourly_price_usd_estimate")
    sources["salad_hourly_price_usd_estimate"] = "JSON" if "salad_hourly_price_usd_estimate" in value else "DEFAULTS"

    env = os.environ if environ is None else environ
    for env_name, floor_key in FLOOR_ENVIRONMENT.items():
        if env_name in env:
            floors[floor_key] = _environment_number(env[env_name], env_name, integer=False)
            sources[f"gpu_floors_ths.{floor_key}"] = "ENV"
    for env_name, config_key in MONITOR_ENVIRONMENT.items():
        if env_name in env:
            is_integer = config_key != "minimum_window_coverage_ratio"
            monitor_values[config_key] = _environment_number(env[env_name], env_name, integer=is_integer)
            sources[config_key] = "ENV"
    if PRICE_ENVIRONMENT in env:
        price = _environment_number(env[PRICE_ENVIRONMENT], PRICE_ENVIRONMENT, integer=False)
        sources["salad_hourly_price_usd_estimate"] = "ENV"

    floors = _validate_floors(floors)
    monitor_values = _validated_monitor(monitor_values)
    raw_sources = value.get("local_telemetry_sources", [])
    if not isinstance(raw_sources, list):
        raise G5ConfigError("local telemetry sources must be a JSON array")
    return G5Config(
        mode=value.get("mode", "offline_local"),
        host=server.get("host", "127.0.0.1"),
        port=server.get("port", 8765),
        organization=scope.get("organization", ORGANIZATION),
        project=scope.get("project", PROJECT),
        container_groups=tuple(scope.get("container_groups", GROUPS)),
        gpu_floors_ths=floors,
        **monitor_values,
        salad_hourly_price_usd_estimate=price,
        value_sources=sources,
        live_get_enabled=scope.get("live_get_enabled", False),
        live_actions_enabled=actions.get("live_actions_enabled", False),
        live_spend_authorized=actions.get("live_spend_authorized", False),
        auto_reallocate=actions.get("auto_reallocate", False),
        hard_budget_usd=actions.get("hard_budget_usd", 30.0),
        kill_switch_engaged=actions.get("kill_switch_engaged", True),
        firebase_enabled=value.get("firebase_enabled", False),
        firebase_project_id=value.get("firebase_project_id", "demo-salad-miners"),
        state_dir=value.get("state_dir", "~/.local/share/salad-miners-g5"),
        local_telemetry_sources=tuple(raw_sources),
    )


def load_config(path: str | Path | None = None, *, environ: Mapping[str, str] | None = None) -> G5Config:
    """Load defaults, then optional JSON, then the operational environment allowlist."""
    value: Mapping[str, Any] = {}
    if path is not None:
        source = Path(path)
        try:
            loaded = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise G5ConfigError("G5 configuration is unreadable or invalid JSON") from None
        if not isinstance(loaded, Mapping):
            raise G5ConfigError("G5 configuration must be a JSON object")
        value = loaded
    return _parse(value, environ=environ)
