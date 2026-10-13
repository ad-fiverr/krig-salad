"""Offline-first enrichment of Fl4shMiner alerts with Salad log labels.

This package intentionally contains no live Salad or Telegram transport.
"""

from .contract import DATA_CLASSIFICATION, READ_LOG_QUERY

__all__ = ["DATA_CLASSIFICATION", "READ_LOG_QUERY"]
