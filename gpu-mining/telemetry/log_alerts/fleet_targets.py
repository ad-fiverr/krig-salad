"""Strict non-secret target definitions for the multi-organization watcher."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable


_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,61}[a-z0-9]$")
_SECRET_LIKE_NAME_RE = re.compile(
    r"(?i)(?:salad[_-]?api[_-]?key|bearer|token|password|secret|credential)|^[a-f0-9]{40,}$"
)
MAX_TARGETS = 100
MAX_TARGET_FILE_BYTES = 65_536


@dataclass(frozen=True, slots=True, order=True)
class FleetTarget:
    organization_name: str
    project_name: str

    def __post_init__(self) -> None:
        if not _valid_name(self.organization_name):
            raise ValueError("organization target name is invalid")
        if not _valid_name(self.project_name):
            raise ValueError("project target name is invalid")


def parse_target(value: str) -> FleetTarget:
    if not isinstance(value, str) or value.count(":") != 1:
        raise ValueError("target must use organization:project form")
    organization, project = value.split(":", 1)
    return FleetTarget(organization, project)


def load_targets_file(path: str | Path) -> tuple[FleetTarget, ...]:
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size > MAX_TARGET_FILE_BYTES:
            raise ValueError
        raw = resolved.read_bytes()
        if not raw or len(raw) > MAX_TARGET_FILE_BYTES:
            raise ValueError
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_members)
    except Exception:
        raise ValueError("targets file is unavailable or invalid") from None
    if not isinstance(payload, list) or len(payload) > MAX_TARGETS:
        raise ValueError("targets file must contain at most 100 target entries")
    targets: list[FleetTarget] = []
    for row in payload:
        if not isinstance(row, dict) or set(row) != {"organization_name", "project_name"}:
            raise ValueError("targets file entries may contain only organization_name and project_name")
        targets.append(FleetTarget(row["organization_name"], row["project_name"]))
    return validate_targets(targets)


def validate_targets(targets: Iterable[FleetTarget]) -> tuple[FleetTarget, ...]:
    values = tuple(sorted(targets))
    if not values or len(values) > MAX_TARGETS:
        raise ValueError("one to 100 Salad organization/project targets are required")
    if any(type(target) is not FleetTarget for target in values):
        raise ValueError("target entries are invalid")
    if len(set(values)) != len(values):
        raise ValueError("duplicate organization/project target is not allowed")
    return values


def targets_by_organization(targets: Iterable[FleetTarget]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, set[str]] = defaultdict(set)
    for target in validate_targets(targets):
        grouped[target.organization_name].add(target.project_name)
    return {organization: tuple(sorted(projects)) for organization, projects in sorted(grouped.items())}


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _valid_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(_NAME_RE.fullmatch(value))
        and not _SECRET_LIKE_NAME_RE.search(value)
    )
