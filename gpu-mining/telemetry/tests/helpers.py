"""Synthetic CSV helpers; mandatory tests do not depend on historical files."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

FIELDS = [
    "Json Log",
    "Receive Time",
    "Resource labels container group name",
    "Resource labels container group version",
    "Resource labels instance id",
    "Resource labels machine id",
    "Resource labels organization id",
    "Resource labels organization name",
    "Resource labels project name",
    "Resource type",
    "Severity",
    "Text Log",
    "Time",
]


def row(
    timestamp: str,
    text: str,
    *,
    version: str = "8",
    instance: str = "instance-a",
    machine: str = "machine-a",
    group: str = "krig-pearl",
    severity: str = "default",
) -> dict[str, str]:
    return {
        "Json Log": "",
        "Receive Time": timestamp,
        "Resource labels container group name": group,
        "Resource labels container group version": version,
        "Resource labels instance id": instance,
        "Resource labels machine id": machine,
        "Resource labels organization id": "org-test",
        "Resource labels organization name": "test",
        "Resource labels project name": "test",
        "Resource type": "container",
        "Severity": severity,
        "Text Log": text,
        "Time": timestamp,
    }


def write_csv(path: Path, rows: Iterable[dict[str, str]]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return path
