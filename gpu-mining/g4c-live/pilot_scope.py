"""Fixed, offline-only request policy for the four-group Salad discovery pilot.

This module describes a future GET plan. It deliberately contains no HTTP
transport and cannot authorize or perform a provider request.
"""

from __future__ import annotations

from dataclasses import dataclass


ORGANIZATION = "adrianfiverr"
PROJECT = "miners"
CONTAINER_GROUPS = (
    "fl4shminer",
    "fl4shminer-2",
    "fl4shminer-3",
    "fl4shminer-4",
)
API_ORIGIN = "https://api.salad.com"
OPERATION = "list_container_group_instances"

# These are operator-side future-pilot caps, not verified Salad quotas.
CONNECT_TIMEOUT_SECONDS = 3
REQUEST_TIMEOUT_SECONDS = 10
TOTAL_DEADLINE_SECONDS = 60
MAX_REQUESTS_TOTAL = 4
MAX_REQUESTS_PER_GROUP = 1
MAX_RESPONSE_BYTES_PER_GROUP = 1_048_576
MAX_RESPONSE_BYTES_TOTAL = 4_194_304
RETRIES = 0
FOLLOW_REDIRECTS = False

# G4C implementation remains offline. A separate authorization gate is needed
# before any real request can be made.
LIVE_CALLS_ENABLED = False
LIVE_CALLS_PERFORMED = False
REALLOCATION_ENABLED = False


class PilotScopeError(ValueError):
    """A proposed request is outside the fixed pilot scope."""


@dataclass(frozen=True)
class RequestSpec:
    ordinal: int
    organization: str
    project: str
    container_group: str
    method: str
    origin: str
    path: str
    operation: str
    connect_timeout_seconds: int
    request_timeout_seconds: int
    max_response_bytes: int
    retries: int
    follow_redirects: bool


def _request_spec(ordinal: int, container_group: str) -> RequestSpec:
    path = (
        "/api/public/organizations/"
        f"{ORGANIZATION}/projects/{PROJECT}"
        f"/containers/{container_group}/instances"
    )
    return RequestSpec(
        ordinal=ordinal,
        organization=ORGANIZATION,
        project=PROJECT,
        container_group=container_group,
        method="GET",
        origin=API_ORIGIN,
        path=path,
        operation=OPERATION,
        connect_timeout_seconds=CONNECT_TIMEOUT_SECONDS,
        request_timeout_seconds=REQUEST_TIMEOUT_SECONDS,
        max_response_bytes=MAX_RESPONSE_BYTES_PER_GROUP,
        retries=RETRIES,
        follow_redirects=FOLLOW_REDIRECTS,
    )


REQUEST_PLAN = tuple(
    _request_spec(index, container_group)
    for index, container_group in enumerate(CONTAINER_GROUPS, start=1)
)


def validate_scope(
    organization: str,
    project: str,
    container_groups: tuple[str, ...] | list[str],
) -> tuple[RequestSpec, ...]:
    """Return the four fixed request descriptions or reject the proposed scope.

    Order and uniqueness are part of the plan. This does not validate that the
    groups exist at Salad or that the provider contract is currently verified.
    """
    if organization != ORGANIZATION or project != PROJECT:
        raise PilotScopeError("organization and project must exactly match the approved scope")
    if not isinstance(container_groups, (tuple, list)):
        raise PilotScopeError("container_groups must be an ordered list or tuple")
    if any(not isinstance(group, str) for group in container_groups):
        raise PilotScopeError("every container group must be a string")
    if len(container_groups) != len(set(container_groups)):
        raise PilotScopeError("duplicate container groups are forbidden")
    if tuple(container_groups) != CONTAINER_GROUPS:
        raise PilotScopeError("container groups must exactly match the approved four-group order")
    return REQUEST_PLAN


def request_for_group(container_group: str) -> RequestSpec:
    """Get the one prebuilt GET description for an allowlisted group."""
    for spec in REQUEST_PLAN:
        if spec.container_group == container_group:
            return spec
    raise PilotScopeError("container group is outside the approved allowlist")
