"""Validation and loading for offline, immutable revenue observation fixtures."""

from __future__ import annotations

import json
import re
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

REVENUE_FIELDS = {
    "coin", "algorithm", "hashrate", "estimated_coin_per_second",
    "estimated_usd_per_second", "source", "source_timestamp", "confidence",
    "fee_inclusion_state", "raw_reference",
}
HASH_UNITS = {"H/s", "kH/s", "MH/s", "GH/s", "TH/s"}
SOURCES = {"kryptex_calculator", "network_derived", "frozen_snapshot"}
FRESHNESS = {"fresh", "stale", "unknown", "historical_fixture"}


def _nonnegative_decimal(value: Any, name: str, *, nullable: bool = False) -> Decimal | None:
    if value is None and nullable:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a nonnegative decimal")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{name} must be a nonnegative decimal") from exc
    if not result.is_finite() or result < 0:
        raise ValueError(f"{name} must be a finite nonnegative decimal")
    return result


def validate_revenue_fixture(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("payload"), dict):
        raise ValueError("revenue fixture must be an envelope object with a payload")
    payload = value["payload"]
    if set(payload) != REVENUE_FIELDS:
        missing = sorted(REVENUE_FIELDS - set(payload))
        extra = sorted(set(payload) - REVENUE_FIELDS)
        raise ValueError(f"RevenueObservation must have exactly ten fields (missing={missing}, extra={extra})")
    if not isinstance(payload.get("coin"), str) or not payload["coin"].strip():
        raise ValueError("payload.coin must be nonempty")
    if not isinstance(payload.get("algorithm"), str) or not payload["algorithm"].strip():
        raise ValueError("payload.algorithm must be nonempty")
    hashrate = payload.get("hashrate")
    if not isinstance(hashrate, dict) or set(hashrate) != {"value", "unit"}:
        raise ValueError("payload.hashrate must contain exactly value and unit")
    _nonnegative_decimal(hashrate.get("value"), "payload.hashrate.value")
    if hashrate.get("unit") not in HASH_UNITS:
        raise ValueError("payload.hashrate.unit is unsupported or missing")
    _nonnegative_decimal(payload.get("estimated_coin_per_second"), "payload.estimated_coin_per_second", nullable=True)
    _nonnegative_decimal(payload.get("estimated_usd_per_second"), "payload.estimated_usd_per_second", nullable=True)
    if payload.get("source") not in SOURCES:
        raise ValueError("payload.source is not a supported RevenueObservation source")
    timestamp = payload.get("source_timestamp")
    if timestamp is not None:
        if not isinstance(timestamp, str):
            raise ValueError("payload.source_timestamp must be RFC3339 or null")
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("payload.source_timestamp must be RFC3339 or null") from exc
        if parsed.tzinfo is None or not re.search(r"T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$", timestamp):
            raise ValueError("payload.source_timestamp must include a timezone and second precision")
        if value.get("source_time_precision") not in {"second", "millisecond"}:
            raise ValueError("exact source_timestamp requires source_time_precision=second or millisecond")
    if payload.get("confidence") not in {"high", "medium", "low", "unknown"}:
        raise ValueError("payload.confidence is invalid")
    if payload.get("fee_inclusion_state") not in {"included", "excluded", "partial", "unknown"}:
        raise ValueError("payload.fee_inclusion_state is invalid")
    if not isinstance(payload.get("raw_reference"), str) or not payload["raw_reference"].strip():
        raise ValueError("payload.raw_reference must be nonempty")
    if value.get("source") != payload.get("source"):
        raise ValueError("envelope source must match payload.source")
    if not isinstance(value.get("schema_version"), str) or not value["schema_version"] or value.get("freshness") not in FRESHNESS or value.get("confidence") not in {"high", "medium", "low", "unknown"}:
        raise ValueError("revenue envelope requires schema_version, freshness, and confidence")
    if value.get("confidence") != payload.get("confidence"):
        raise ValueError("envelope confidence must match RevenueObservation confidence")
    if not isinstance(value.get("source_class"), str) or not value["source_class"].strip():
        raise ValueError("revenue envelope source_class is required")
    for field in ("observed_at_precision", "source_time_precision"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ValueError(f"revenue envelope {field} is required")
    precision_values = {"unknown", "date", "minute", "second", "millisecond"}
    if value["observed_at_precision"] not in precision_values or value["source_time_precision"] not in precision_values:
        raise ValueError("revenue envelope timestamp precision is invalid")
    envelope_reference = value.get("raw_reference")
    if not ((isinstance(envelope_reference, str) and envelope_reference.strip()) or (isinstance(envelope_reference, dict) and envelope_reference)):
        raise ValueError("revenue envelope raw_reference is required")
    observed_at = value.get("observed_at")
    if observed_at is not None:
        if not isinstance(observed_at, str):
            raise ValueError("envelope observed_at must be a timezone-aware timestamp or null")
        try:
            observed_datetime = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("envelope observed_at must be a timezone-aware timestamp or null") from exc
        if observed_datetime.tzinfo is None or not re.search(r"T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$", observed_at):
            raise ValueError("envelope observed_at must include a timezone and second precision")
        if value["observed_at_precision"] not in {"second", "millisecond"}:
            raise ValueError("exact observed_at timestamp requires second or millisecond precision")
    if value.get("freshness") == "fresh" and observed_at is None:
        raise ValueError("fresh revenue envelope requires an exact observed_at timestamp")
    if value.get("freshness") == "historical_fixture" and payload["source"] != "frozen_snapshot":
        raise ValueError("historical_fixture freshness requires source=frozen_snapshot")
    if value.get("freshness") == "historical_fixture" and (value.get("observed_at") is not None or payload.get("source_timestamp") is not None):
        raise ValueError("historical_fixture must preserve unavailable timestamps as null")
    return value


def load_revenue_fixture(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"), parse_float=Decimal, parse_int=Decimal)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid revenue fixture JSON: {path}") from exc
    return validate_revenue_fixture(value)
