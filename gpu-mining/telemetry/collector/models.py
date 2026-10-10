"""Shared schema constants and small helpers for the offline telemetry lab."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"
V2_SCHEMA_VERSION = "2.0"
SOURCE_NAME = "salad_exported_krig_csv"
SOURCE_CLASS = "exported_log"
REVENUE_EVIDENCE_STAGES = ("estimated", "pool_observed", "paid", "converted", "realized")


def utc_now_text() -> str:
    """Return an RFC3339 UTC timestamp for local import bookkeeping."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def json_safe_number(value: Any) -> float | int | None:
    """Keep JSON output standards-compliant when an input is missing or invalid."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            return None
        return value
    return None
