"""Pure, read-only loading of the G5 startup policy for the packaged watcher."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Mapping

from collector.fl4sh_early_autotune import EarlyPolicy, StartupPolicySnapshot
from collector.guards import HashGuardPolicy, hash_guard_policy

from .config import G5Config, load_config


def build_guard_policy(config: G5Config) -> HashGuardPolicy:
    """Build the exact dry-run hash guard policy used by the G5 service."""
    if type(config) is not G5Config:
        raise TypeError("validated G5 configuration required")
    return HashGuardPolicy(
        gpu_floors_ths=dict(config.gpu_floors_ths),
        warmup_seconds=config.warmup_seconds,
        hash_window_seconds=config.hash_window_seconds,
        reevaluation_interval_seconds=config.reevaluation_interval_seconds,
        minimum_samples_per_window=config.minimum_samples_per_window,
        expected_sample_interval_seconds=config.expected_sample_interval_seconds,
        maximum_sample_gap_seconds=config.maximum_sample_gap_seconds,
        minimum_window_coverage_ratio=config.minimum_window_coverage_ratio,
        consecutive_bad_windows=config.consecutive_bad_windows,
        reallocation_cooldown_seconds=None,
        max_reallocations_per_run=None,
    )


def build_startup_policy_snapshot(
    config: G5Config,
    *,
    loaded_at_utc: str | None = None,
) -> StartupPolicySnapshot:
    """Create the same policy snapshot as G5ControlPlaneService, without the service."""
    if type(config) is not G5Config:
        raise TypeError("validated G5 configuration required")
    floors = dict(config.pearl_startup_floors_ths)
    policy = EarlyPolicy(hash_guard_policy(build_guard_policy(config)), floors, margin_ths=0.0)
    floor_sources = {
        key: config.source_for(f"pearl_startup_floors_ths.{key}")
        for key in floors
    }
    floor_catalog_hash = config.pearl_startup_floor_catalog_hash
    payload = {
        "policy_hash": policy.policy_hash,
        "floor_catalog_hash": floor_catalog_hash,
        "organization": config.organization,
        "project": config.project,
        "container_groups": list(config.container_groups),
        "floor_sources": dict(sorted(floor_sources.items())),
    }
    config_sha256 = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    timestamp = loaded_at_utc or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return StartupPolicySnapshot(
        policy=policy,
        config_sha256=config_sha256,
        floor_catalog_hash=floor_catalog_hash,
        organization=config.organization,
        project=config.project,
        container_groups=tuple(config.container_groups),
        floor_sources=floor_sources,
        loaded_at_utc=timestamp,
    )


def load_startup_policy_snapshot(
    path: str | Path | None,
    *,
    environ: Mapping[str, str] | None = None,
) -> StartupPolicySnapshot:
    """Load validated local defaults/JSON/environment and return a read-only snapshot."""
    return build_startup_policy_snapshot(load_config(path, environ=environ))
