"""Per-invocation gates for the explicitly started live fleet watcher.

Importing this module grants no network capability. Production capabilities are
created only after the caller supplies the exact local confirmation phrase and
the required mode flags.
"""

from __future__ import annotations

from dataclasses import dataclass


_AUTHORITY = object()
LIVE_CONFIRMATION = "CENTRAL_FLEET_MONITOR"


class LiveCapabilityBlocked(RuntimeError):
    """The current process invocation did not satisfy its live gates."""


@dataclass(frozen=True, slots=True, init=False)
class LiveRuntimeCapability:
    salad_read: bool
    central_telegram: bool
    mode: str

    def __init__(self, *, salad_read: bool, central_telegram: bool, mode: str, _authority: object):
        if _authority is not _AUTHORITY:
            raise TypeError("live capabilities can only be created by the explicit gate")
        object.__setattr__(self, "salad_read", salad_read)
        object.__setattr__(self, "central_telegram", central_telegram)
        object.__setattr__(self, "mode", mode)

    @property
    def allows_salad_read(self) -> bool:
        return self.salad_read is True

    @property
    def allows_central_telegram(self) -> bool:
        return self.central_telegram is True

    def __repr__(self) -> str:
        return f"LiveRuntimeCapability(mode={self.mode!r}, salad_read={self.salad_read}, central_telegram={self.central_telegram})"


def authorize_live_invocation(
    *, mode: str, enable_live_read: bool, enable_central_telegram: bool,
    confirmation: str | None,
) -> LiveRuntimeCapability:
    """Create a short-lived capability after checking exact CLI gates."""
    if mode not in {"probe", "once", "watch"}:
        raise LiveCapabilityBlocked("live mode is invalid")
    if enable_live_read is not True or confirmation != LIVE_CONFIRMATION:
        raise LiveCapabilityBlocked("explicit Salad live-read confirmation is required")
    if mode in {"once", "watch"} and enable_central_telegram is not True:
        raise LiveCapabilityBlocked("explicit central Telegram confirmation is required")
    if mode == "probe" and enable_central_telegram:
        raise LiveCapabilityBlocked("contract probe must not enable Telegram")
    return LiveRuntimeCapability(
        salad_read=True,
        central_telegram=mode in {"once", "watch"},
        mode=mode,
        _authority=_AUTHORITY,
    )


def capability_allows(capability: object | None, field: str) -> bool:
    if type(capability) is not LiveRuntimeCapability:
        return False
    if field == "salad_read":
        return capability.allows_salad_read
    if field == "central_telegram":
        return capability.allows_central_telegram
    return False
