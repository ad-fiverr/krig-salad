"""G2-compatible adapter with a separately injected, default-off G5 executor."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class ReallocationTransport(Protocol):
    def submit(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        """Reserved for a separately reviewed future adapter; never called in G2."""


class SaladReallocationAdapter:
    """Preserve G2 behavior; G5 execution requires an explicit executor and gate."""

    enabled = False
    ACTIONS_IMPLEMENTED = False

    def __init__(
        self,
        transport: ReallocationTransport | None = None,
        *,
        executor: Any = None,
        enabled: bool = False,
    ):
        if not isinstance(enabled, bool):
            raise TypeError("reallocation adapter enable flag must be boolean")
        self._transport = transport
        self._executor = executor
        self.enabled = enabled

    def request_reallocation(
        self,
        recommendation: Mapping[str, Any],
        *,
        execution_context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.enabled and self._executor is not None and isinstance(execution_context, Mapping):
            from .salad_action_policy import SaladAction

            target = {
                key: recommendation.get(key)
                for key in ("organization", "project", "container_group", "instance_id", "assignment_id", "deterioration_id")
            }
            receipt = self._executor.execute(
                SaladAction.REALLOCATE_INSTANCE,
                target,
                **dict(execution_context),
            )
            return {
                "status": receipt.status,
                "actions_performed": receipt.actions_performed,
                "action_key": receipt.action_key,
                "reason": receipt.reason,
            }
        return {
            "status": "DISABLED",
            "actions_performed": False,
            "action_key": recommendation.get("action_key"),
            "reason": "G2 has no authenticated Salad action implementation; G5 is not authorized",
        }
