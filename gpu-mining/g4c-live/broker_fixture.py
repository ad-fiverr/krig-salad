"""Explicitly synthetic transport boundary for the offline G4-C broker.

This module has no HTTP client, sockets, environment credential reader, or
provider integration. It returns only caller-supplied local fixtures.
"""

from __future__ import annotations

from collections.abc import Sequence

from pilot_discovery import OfflineFixtureResponse
from pilot_scope import CONTAINER_GROUPS, REQUEST_PLAN, RequestSpec, request_for_group


_SYNTHETIC_SECRET_MARKER = "SYNTHETIC_ONLY_NOT_A_CREDENTIAL_MARKER"


class FixtureBoundaryError(ValueError):
    """A request or fixture does not belong to the fixed offline boundary."""


class OfflineFixtureTransport:
    """Return local responses for approved groups; never opens a connection."""

    __slots__ = ("__fixtures", "__called_groups", "__synthetic_secret_marker")

    def __init__(self, fixtures: Sequence[OfflineFixtureResponse] = ()):
        if not isinstance(fixtures, Sequence) or isinstance(fixtures, (str, bytes, bytearray)):
            raise FixtureBoundaryError("fixtures must be an ordered local sequence")
        if len(fixtures) > len(REQUEST_PLAN):
            raise FixtureBoundaryError("more than four fixture responses are prohibited")
        mapping: dict[str, OfflineFixtureResponse] = {}
        for fixture in fixtures:
            if type(fixture) is not OfflineFixtureResponse:
                raise FixtureBoundaryError("only OfflineFixtureResponse objects are accepted")
            group = fixture.container_group
            if not isinstance(group, str) or group not in CONTAINER_GROUPS:
                raise FixtureBoundaryError("fixture group is outside the fixed allowlist")
            if group in mapping:
                raise FixtureBoundaryError("duplicate group fixtures are prohibited")
            mapping[group] = fixture
        object.__setattr__(self, "_OfflineFixtureTransport__fixtures", mapping)
        object.__setattr__(self, "_OfflineFixtureTransport__called_groups", [])
        # A marker used only to make the synthetic boundary explicit. It is
        # intentionally not part of a public method, result, log, or ledger.
        object.__setattr__(self, "_OfflineFixtureTransport__synthetic_secret_marker", _SYNTHETIC_SECRET_MARKER)

    @property
    def called_groups(self) -> tuple[str, ...]:
        return tuple(self.__called_groups)

    def invoke(self, request: RequestSpec) -> OfflineFixtureResponse:
        if type(request) is not RequestSpec or request not in REQUEST_PLAN:
            raise FixtureBoundaryError("only an exact fixed-scope request specification is accepted")
        group = request.container_group
        if group in self.__called_groups:
            raise FixtureBoundaryError("a group fixture cannot be invoked twice")
        expected_ordinal = len(self.__called_groups) + 1
        # The ledger is authoritative for global order. The transport still
        # rejects a request which skips ahead within this fixture instance.
        if request.ordinal != expected_ordinal and not self.__called_groups:
            first_fixture_group = next(iter(self.__fixtures), None)
            first_fixture_spec = request_for_group(first_fixture_group) if first_fixture_group else None
            if first_fixture_spec is None or request.ordinal < first_fixture_spec.ordinal:
                raise FixtureBoundaryError("fixture invocation order is invalid")
        if self.__called_groups:
            last = request_for_group(self.__called_groups[-1])
            if request.ordinal != last.ordinal + 1:
                raise FixtureBoundaryError("fixture invocation must be sequential")
        self.__called_groups.append(group)
        return self.__fixtures.get(
            group,
            OfflineFixtureResponse(
                container_group=group,
                status_code=None,
                timed_out=False,
                transport_error="synthetic_fixture_missing",
            ),
        )
