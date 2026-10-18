"""Offline KRig telemetry parsing and dry-run guard logic."""

from .krig_csv import ParsedKrigCsv, import_krig_csv

__all__ = ["ParsedKrigCsv", "import_krig_csv"]
