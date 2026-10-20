"""Strict local G5 configuration with operator tunables and fixed safety gates.

Only an explicit allowlist of operational tuning variables is read from the
environment. Credentials and capability flags are intentionally not supported
there; this build remains offline and local-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
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
# These four exact identities retain the historical, explicitly accepted G5
# floors. New startup identities require an explicit JSON or environment entry.
PEARL_STARTUP_FLOORS = {
    "RTX_5090_LAPTOP": 120,
    "RTX_5080_LAPTOP": 120,
    "RTX_5090_DESKTOP": 350,
    "RTX_5080_DESKTOP": 209,
}
PEARL_STARTUP_FLOORS_ENVIRONMENT = "SALAD_G5_PEARL_STARTUP_FLOORS_JSON"
_PEARL_GPU_KEY_RE = re.compile(r"[A-Z0-9]+(?:_[A-Z0-9]+)*\Z")
_FORM_FACTOR_TOKENS = frozenset({"LAPTOP", "DESKTOP", "NOTEBOOK", "MOBILE"})
_NON_MODEL_GPU_TOKENS = frozenset({"NVIDIA", "GEFORCE", "GPU", "UNKNOWN", "SERIES", "FAMILY"})
_MAX_PEARL_FLOOR_ENTRIES = 128
_MAX_PEARL_REGISTRY_JSON_CHARS = 16_384
LEGACY_GPU_FLOOR_TO_PEARL_KEY = {
    "RTX 5090|laptop|salad_json_log_gpu_class_name": "RTX_5090_LAPTOP",
    "RTX 5080|laptop|salad_json_log_gpu_class_name": "RTX_5080_LAPTOP",
    "RTX 5090|desktop|salad_json_log_gpu_class_name": "RTX_5090_DESKTOP",
    "RTX 5080|desktop|salad_json_log_gpu_class_name": "RTX_5080_DESKTOP",
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
REALLOCATION_ADMISSION_MODES = frozenset({"OFF", "SIMULATION", "LIVE"})
REALLOCATION_ADMISSION_LIMIT_KEYS = frozenset({
    "max_per_minute", "max_per_day", "cooldown_seconds",
    "max_per_assignment", "max_per_fleet",
})


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


def _validate_reallocation_admission_limits(value: Any) -> dict[str, int] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != REALLOCATION_ADMISSION_LIMIT_KEYS:
        raise G5ConfigError("reallocation admission limits must include every bounded quota and cooldown")
    limits: dict[str, int] = {}
    for key in sorted(REALLOCATION_ADMISSION_LIMIT_KEYS):
        limits[key] = _integer(value[key], f"reallocation_admission_limits.{key}", allow_zero=key == "cooldown_seconds")
        if limits[key] > 100_000:
            raise G5ConfigError("reallocation admission limits exceed the supported numeric limit")
    return limits


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


def _valid_pearl_gpu_key(key: Any) -> bool:
    """Accept exact canonical GPU keys emitted by the Fl4sh identity normalizer."""
    if not isinstance(key, str) or len(key) > 128 or _PEARL_GPU_KEY_RE.fullmatch(key) is None:
        return False
    tokens = key.split("_")
    if not tokens:
        return False
    if tokens[-1] in {"LAPTOP", "DESKTOP"}:
        model_tokens = tokens[:-1]
    else:
        model_tokens = tokens
    if (
        not model_tokens
        or any(token in _FORM_FACTOR_TOKENS | _NON_MODEL_GPU_TOKENS for token in model_tokens)
        or (tokens[0] == "RTX" and len(model_tokens) < 2)
    ):
        return False
    return any(any(char.isdigit() for char in token) for token in model_tokens)


def _legacy_pearl_floor_source(source: str, *, floor: float, default_floor: float) -> str | None:
    """Map an existing G5 floor source into Pearl only when it is an actual override."""
    if source == "ENV":
        return "LEGACY_ENV"
    if source == "JSON" and floor != default_floor:
        return "LEGACY_JSON"
    if source == "PYTHON" and floor != default_floor:
        return "PYTHON"
    return None


def _validate_pearl_startup_floors(value: Any) -> dict[str, float]:
    if not isinstance(value, Mapping):
        raise G5ConfigError("pearl_startup_floors_ths must be a JSON object")
    if len(value) > _MAX_PEARL_FLOOR_ENTRIES:
        raise G5ConfigError("Pearl startup floor registry exceeds the entry limit")
    floors: dict[str, float] = {}
    seen_casefolded: set[str] = set()
    for key, floor in value.items():
        if not _valid_pearl_gpu_key(key):
            raise G5ConfigError("Pearl startup floor identity is not a canonical exact GPU model key")
        folded = key.casefold()
        if folded in seen_casefolded:
            raise G5ConfigError("Pearl startup floor registry contains duplicate identity aliases")
        seen_casefolded.add(folded)
        parsed = _finite_positive(floor, "pearl_startup_floors_ths entry")
        if parsed > 10_000:
            raise G5ConfigError("Pearl startup floor exceeds the supported numeric limit")
        floors[key] = parsed
    return floors


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise G5ConfigError("configuration JSON contains duplicate object keys")
        result[key] = value
    return result


def _parse_pearl_registry_environment(raw: str) -> dict[str, float]:
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_PEARL_REGISTRY_JSON_CHARS:
        raise G5ConfigError("Pearl startup floor environment registry is empty or exceeds its size limit")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, G5ConfigError):
        raise G5ConfigError("Pearl startup floor environment registry is invalid JSON") from None
    return _validate_pearl_startup_floors(value)


def pearl_startup_floor_catalog_hash(floors: Mapping[str, float]) -> str:
    """Return a deterministic catalog fingerprint, not a GPU-binding claim."""
    validated = _validate_pearl_startup_floors(floors)
    payload = json.dumps(
        [[key, format(value, ".17g")] for key, value in sorted(validated.items())],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


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
    pearl_startup_floors_ths: Mapping[str, float] | None = None
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
    reallocation_admission_mode: str = "OFF"
    reallocation_admission_limits: Mapping[str, int] | None = None
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
        if type(self.reallocation_admission_mode) is not str or self.reallocation_admission_mode not in REALLOCATION_ADMISSION_MODES:
            raise G5ConfigError("reallocation admission mode must be OFF, SIMULATION, or LIVE")
        admission_limits = _validate_reallocation_admission_limits(self.reallocation_admission_limits)
        object.__setattr__(
            self,
            "reallocation_admission_limits",
            MappingProxyType(admission_limits) if admission_limits is not None else None,
        )
        floors = _validate_floors(self.gpu_floors_ths)
        if not floors:
            raise G5ConfigError("at least one verified GPU floor must be configured")
        object.__setattr__(self, "gpu_floors_ths", MappingProxyType(floors))
        inherited_pearl_sources: dict[str, str] = {}
        if self.pearl_startup_floors_ths is None:
            pearl_floors = dict(PEARL_STARTUP_FLOORS)
            supplied_sources = dict(self.value_sources or {})
            for legacy_key, pearl_key in LEGACY_GPU_FLOOR_TO_PEARL_KEY.items():
                source = str(supplied_sources.get(f"gpu_floors_ths.{legacy_key}", "PYTHON"))
                inherited_source = _legacy_pearl_floor_source(
                    source,
                    floor=floors[legacy_key],
                    default_floor=FLOORS[legacy_key],
                )
                if inherited_source is not None:
                    pearl_floors[pearl_key] = floors[legacy_key]
                    inherited_pearl_sources[pearl_key] = inherited_source
        else:
            pearl_floors = dict(self.pearl_startup_floors_ths)
        pearl_floors = _validate_pearl_startup_floors(pearl_floors)
        if not pearl_floors:
            raise G5ConfigError("at least one exact Pearl startup floor must be configured")
        object.__setattr__(self, "pearl_startup_floors_ths", MappingProxyType(pearl_floors))
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
                f"pearl_startup_floors_ths.{key}": (
                    inherited_pearl_sources.get(
                        key,
                        "DEFAULTS" if key in PEARL_STARTUP_FLOORS and value == PEARL_STARTUP_FLOORS[key]
                        else "PYTHON",
                    )
                )
                for key, value in pearl_floors.items()
            })
            sources.update({
                key: ("DEFAULTS" if value == MONITOR_DEFAULTS[key] else "PYTHON")
                for key, value in monitor.items()
            })
            sources["salad_hourly_price_usd_estimate"] = "DEFAULTS" if self.salad_hourly_price_usd_estimate is None else "PYTHON"
            sources["reallocation_admission_mode"] = "DEFAULTS" if self.reallocation_admission_mode == "OFF" else "PYTHON"
            sources["reallocation_admission_limits"] = "DEFAULTS" if admission_limits is None else "PYTHON"
            object.__setattr__(self, "value_sources", MappingProxyType(sources))
        elif any(origin not in {"DEFAULTS", "JSON", "ENV", "PYTHON", "LEGACY_JSON", "LEGACY_ENV"} for origin in self.value_sources.values()):
            raise G5ConfigError("configuration source labels are invalid")
        else:
            sources = dict(self.value_sources)
            sources.setdefault("reallocation_admission_mode", "DEFAULTS" if self.reallocation_admission_mode == "OFF" else "PYTHON")
            sources.setdefault("reallocation_admission_limits", "DEFAULTS" if admission_limits is None else "PYTHON")
            for key, value in pearl_floors.items():
                sources.setdefault(
                    f"pearl_startup_floors_ths.{key}",
                    inherited_pearl_sources.get(
                        key,
                        "DEFAULTS" if key in PEARL_STARTUP_FLOORS and value == PEARL_STARTUP_FLOORS[key] else "PYTHON",
                    ),
                )
            object.__setattr__(self, "value_sources", MappingProxyType(sources))

    def source_for(self, name: str) -> str:
        assert self.value_sources is not None
        return str(self.value_sources.get(name, "DEFAULTS"))

    @property
    def pearl_startup_floor_catalog_hash(self) -> str:
        return pearl_startup_floor_catalog_hash(self.pearl_startup_floors_ths)


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
    raw_pearl_floors = value.get("pearl_startup_floors_ths", {})
    if not isinstance(raw_pearl_floors, Mapping):
        raise G5ConfigError("pearl_startup_floors_ths must be a JSON object")
    pearl_floors = dict(PEARL_STARTUP_FLOORS)
    pearl_sources: dict[str, str] = {
        key: "DEFAULTS" for key in PEARL_STARTUP_FLOORS
    }
    explicit_json_pearl_floors = _validate_pearl_startup_floors(raw_pearl_floors)
    explicit_json_pearl_keys = set(explicit_json_pearl_floors)
    monitor_values: dict[str, Any] = dict(MONITOR_DEFAULTS)
    for key in MONITOR_DEFAULTS:
        if key in monitor_json:
            monitor_values[key] = monitor_json[key]
            sources[key] = "JSON"
        else:
            sources[key] = "DEFAULTS"
    price = value.get("salad_hourly_price_usd_estimate")
    sources["salad_hourly_price_usd_estimate"] = "JSON" if "salad_hourly_price_usd_estimate" in value else "DEFAULTS"
    sources["reallocation_admission_mode"] = (
        "JSON" if "reallocation_admission_mode" in actions else "DEFAULTS"
    )
    sources["reallocation_admission_limits"] = (
        "JSON" if "reallocation_admission_limits" in actions else "DEFAULTS"
    )

    env = os.environ if environ is None else environ
    env_pearl_floors: dict[str, float] = {}
    if PEARL_STARTUP_FLOORS_ENVIRONMENT in env:
        env_pearl_floors = _parse_pearl_registry_environment(env[PEARL_STARTUP_FLOORS_ENVIRONMENT])
        if explicit_json_pearl_keys.intersection(env_pearl_floors):
            raise G5ConfigError("Pearl startup floor identity is set by multiple explicit sources")
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
    # Preserve the historical G5 contract: the effective legacy floors also
    # governed Pearl startup admission. The dedicated Pearl catalog is a more
    # specific override and therefore wins when explicitly configured.
    for legacy_key, pearl_key in LEGACY_GPU_FLOOR_TO_PEARL_KEY.items():
        source = sources[f"gpu_floors_ths.{legacy_key}"]
        inherited_source = _legacy_pearl_floor_source(
            source,
            floor=float(floors[legacy_key]),
            default_floor=FLOORS[legacy_key],
        )
        if inherited_source is not None:
            pearl_floors[pearl_key] = floors[legacy_key]
            pearl_sources[pearl_key] = inherited_source
    for key, floor in explicit_json_pearl_floors.items():
        pearl_floors[key] = floor
        pearl_sources[key] = "JSON"
    for key, floor in env_pearl_floors.items():
        pearl_floors[key] = floor
        pearl_sources[key] = "ENV"

    pearl_floors = _validate_pearl_startup_floors(pearl_floors)
    sources.update({
        f"pearl_startup_floors_ths.{key}": source
        for key, source in pearl_sources.items()
    })
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
        pearl_startup_floors_ths=pearl_floors,
        **monitor_values,
        salad_hourly_price_usd_estimate=price,
        value_sources=sources,
        live_get_enabled=scope.get("live_get_enabled", False),
        live_actions_enabled=actions.get("live_actions_enabled", False),
        live_spend_authorized=actions.get("live_spend_authorized", False),
        auto_reallocate=actions.get("auto_reallocate", False),
        reallocation_admission_mode=actions.get("reallocation_admission_mode", "OFF"),
        reallocation_admission_limits=actions.get("reallocation_admission_limits"),
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
            loaded = json.loads(
                source.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (OSError, json.JSONDecodeError, G5ConfigError):
            raise G5ConfigError("G5 configuration is unreadable or invalid JSON") from None
        if not isinstance(loaded, Mapping):
            raise G5ConfigError("G5 configuration must be a JSON object")
        value = loaded
    return _parse(value, environ=environ)
