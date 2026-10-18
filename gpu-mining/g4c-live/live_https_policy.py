"""Closed request policy for the offline-tested Salad HTTPS broker.

This module describes only the four approved list-instance GET routes. It
does not establish that the provider contract is current or authorize network
access.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from broker_offline import ContainerGroup
from pilot_scope import (
    API_ORIGIN,
    CONNECT_TIMEOUT_SECONDS,
    MAX_RESPONSE_BYTES_PER_GROUP,
    MAX_RESPONSE_BYTES_TOTAL,
    REQUEST_PLAN,
    REQUEST_TIMEOUT_SECONDS,
    RETRIES,
    TOTAL_DEADLINE_SECONDS,
    FOLLOW_REDIRECTS,
    request_for_group as _request_for_group,
)


SALAD_HOST = "api.salad.com"
SALAD_PORT = 443
SALAD_METHOD = "GET"
SALAD_OPERATION = "list_container_group_instances"


class LivePolicyError(ValueError):
    """A request does not match the fixed, approved discovery scope."""


@dataclass(frozen=True, slots=True)
class RestrictedGET:
    """A complete fixed route without caller-controlled HTTP fields."""

    container_group: ContainerGroup
    method: str
    host: str
    port: int
    path: str
    operation: str
    connect_timeout_seconds: int
    request_timeout_seconds: int
    total_deadline_seconds: int
    max_response_bytes: int
    retries: int
    follow_redirects: bool


def _build(group: ContainerGroup) -> RestrictedGET:
    if type(group) is not ContainerGroup:
        raise LivePolicyError("container group must be an approved enum")
    original = _request_for_group(group.value)
    if (
        original.origin != API_ORIGIN
        or original.method != SALAD_METHOD
        or original.operation != SALAD_OPERATION
        or original.retries != RETRIES
        or original.follow_redirects is not FOLLOW_REDIRECTS
    ):
        raise LivePolicyError("the existing pilot request contract is inconsistent")
    return RestrictedGET(
        container_group=group,
        method=SALAD_METHOD,
        host=SALAD_HOST,
        port=SALAD_PORT,
        path=original.path,
        operation=SALAD_OPERATION,
        connect_timeout_seconds=CONNECT_TIMEOUT_SECONDS,
        request_timeout_seconds=REQUEST_TIMEOUT_SECONDS,
        total_deadline_seconds=TOTAL_DEADLINE_SECONDS,
        max_response_bytes=MAX_RESPONSE_BYTES_PER_GROUP,
        retries=0,
        follow_redirects=False,
    )


REQUESTS: tuple[RestrictedGET, ...] = tuple(
    _build(ContainerGroup(group.value)) for group in ContainerGroup
)
REQUEST_BY_GROUP: Mapping[ContainerGroup, RestrictedGET] = MappingProxyType(
    {request.container_group: request for request in REQUESTS}
)


def request_for_group(group: ContainerGroup) -> RestrictedGET:
    """Return the one immutable request for an approved enum value."""
    if type(group) is not ContainerGroup:
        raise LivePolicyError("container group must be an approved enum")
    try:
        return REQUEST_BY_GROUP[group]
    except KeyError as exc:
        raise LivePolicyError("container group is outside the approved allowlist") from exc


def validate_request(request: RestrictedGET) -> RestrictedGET:
    """Reject mutated or caller-constructed requests before any reservation."""
    if type(request) is not RestrictedGET:
        raise LivePolicyError("request must be a fixed RestrictedGET")
    expected = request_for_group(request.container_group)
    if request != expected:
        raise LivePolicyError("request differs from the fixed allowlisted contract")
    return expected

