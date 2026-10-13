"""Exact, cached List Container Group Instances fallback for provider IDs."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import replace
import hashlib
import json
import re
import time
import uuid
from typing import Any, Iterable

from collector.g4a_salad_get import normalize_instance_list_response
from .contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED
from .live_transport import (
    LiveSaladReadTransport,
    LiveTransportBlocked,
    ProviderResponseEvidence,
    SaladTransportResponse,
    secret_boundary_types,
)
from .normalize import NormalizedLogEntry, ProviderIdentity

_Snapshot = tuple[dict[str, tuple[str, ...]], frozenset[str]]


MAX_CACHE_GROUPS = 128
MAX_GROUP_LOOKUPS_PER_CYCLE = 64
MAX_RESPONSE_BYTES = 5_000_000


def _canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


class ListInstancesLookup:
    """Resolve only an exact provider Instance ID within its exact route scope.

    Cache values contain normalized IDs only. A missing, malformed, conflicting,
    saturated, or stale provider response never creates an identity claim.
    """

    def __init__(
        self,
        *,
        organization_name: str,
        transport: LiveSaladReadTransport,
        secret_provider: Any,
        allowed_projects: Iterable[str],
        ttl_seconds: float = 45.0,
        maximum_groups_per_cycle: int = MAX_GROUP_LOOKUPS_PER_CYCLE,
        clock: Any = time.monotonic,
    ) -> None:
        if type(transport) is not LiveSaladReadTransport:
            raise TypeError("exact Salad read transport is required")
        interactive_provider, synthetic_provider, _ = secret_boundary_types()
        expected_provider = synthetic_provider if transport._offline_exchange is not None else interactive_provider
        if type(secret_provider) is not expected_provider:
            raise TypeError("credential provider does not match the transport mode")
        if transport.policy.approved_organization != organization_name:
            raise ValueError("lookup organization differs from the fixed transport scope")
        projects = tuple(sorted(set(allowed_projects)))
        if not projects or any(not isinstance(value, str) or not value for value in projects):
            raise ValueError("one or more configured projects are required")
        if isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 300:
            raise ValueError("lookup cache TTL must be between 1 and 300 seconds")
        if isinstance(maximum_groups_per_cycle, bool) or not 1 <= maximum_groups_per_cycle <= 256:
            raise ValueError("group lookup budget is outside the local bound")
        self.organization_name = organization_name
        self.transport = transport
        self.secret_provider = secret_provider
        self.allowed_projects = frozenset(projects)
        self.ttl_seconds = float(ttl_seconds)
        self.maximum_groups_per_cycle = int(maximum_groups_per_cycle)
        self.clock = clock
        self._cache: OrderedDict[tuple[str, str, str], tuple[float, _Snapshot]] = OrderedDict()
        self._cycle_groups: set[tuple[str, str, str]] = set()
        self._cycle_results: dict[tuple[str, str, str], _Snapshot] = {}
        self.lookups = 0
        self.cache_hits = 0
        self.unknown_results = 0
        self.lookup_failures = 0
        self.access_denied_status: int | None = None

    def begin_cycle(self) -> None:
        self._cycle_groups.clear()
        self._cycle_results.clear()
        self.lookups = 0
        self.cache_hits = 0
        self.unknown_results = 0
        self.lookup_failures = 0
        self.access_denied_status = None

    def resolve_entry(self, entry: NormalizedLogEntry) -> NormalizedLogEntry:
        if type(entry) is not NormalizedLogEntry:
            raise TypeError("lookup accepts only normalized log entries")
        identity = entry.identity
        if (
            identity.status == "CONFLICTING"
            or identity.machine_id is not None
            or identity.instance_id is None
            or identity.container_group_name is None
            or identity.project_name not in self.allowed_projects
            or (identity.organization_name is not None and identity.organization_name != self.organization_name)
            or not _canonical_uuid(identity.instance_id)
        ):
            return entry
        scope = (self.organization_name, identity.project_name, identity.container_group_name)
        machines, unresolvable = self._snapshot(scope)
        if identity.instance_id in unresolvable:
            self.unknown_results += 1
            return entry
        matches = machines.get(identity.instance_id, ())
        if len(matches) != 1 or not _canonical_uuid(matches[0]):
            self.unknown_results += 1
            return entry
        organization = identity.organization_name or self.organization_name
        status = PROVIDER_OBSERVED if entry.data_classification == PROVIDER_OBSERVED else DATA_CLASSIFICATION
        resolved = ProviderIdentity(
            status=status,
            machine_id=matches[0],
            instance_id=identity.instance_id,
            container_group_name=identity.container_group_name,
            organization_name=organization,
            project_name=identity.project_name,
            source="list_container_group_instances",
            # Keep the exact source-label fingerprint stable while enriching
            # the identity shown to the operator.
            labels_fingerprint=identity.labels_fingerprint,
        )
        return replace(entry, identity=resolved)

    def _snapshot(self, scope: tuple[str, str, str]) -> _Snapshot:
        if scope in self._cycle_results:
            self.cache_hits += 1
            return self._cycle_results[scope]
        now = float(self.clock())
        cached = self._cache.get(scope)
        if cached is not None and now < cached[0]:
            self._cache.move_to_end(scope)
            self._cycle_results[scope] = cached[1]
            self.cache_hits += 1
            return cached[1]
        self._cache.pop(scope, None)
        if scope not in self._cycle_groups:
            if len(self._cycle_groups) >= self.maximum_groups_per_cycle:
                self.unknown_results += 1
                self._cycle_results[scope] = ({}, frozenset())
                return self._cycle_results[scope]
            self._cycle_groups.add(scope)
        try:
            secret = self.secret_provider.acquire()
            self.lookups += 1
            response = self.transport.fetch_list_instances(
                organization_name=scope[0], project_name=scope[1],
                container_group_name=scope[2], secret=secret,
            )
            response_status = getattr(response, "status_code", None)
            if response_status in {401, 403}:
                self.access_denied_status = int(response_status)
            parsed = self._validated_response(response, scope)
            if parsed is None:
                self.lookup_failures += 1
                self._cycle_results[scope] = ({}, frozenset())
                return self._cycle_results[scope]
            normalized = normalize_instance_list_response(
                parsed, organization_name=scope[0], project_name=scope[1],
                container_group_name=scope[2],
            )
            if normalized["complete"] is not True:
                self.lookup_failures += 1
                self._cycle_results[scope] = ({}, frozenset())
                return self._cycle_results[scope]
            matches: dict[str, list[str]] = {}
            unresolvable: set[str] = set()
            for row in normalized["instances"]:
                if row.get("identity_status") == "CONFLICTING":
                    # Preserve a conflicting route snapshot as unusable; no
                    # row in that response is promoted to a lookup result.
                    self.lookup_failures += 1
                    self._cycle_results[scope] = ({}, frozenset())
                    return self._cycle_results[scope]
                instance_id = row.get("instance_id")
                machine_id = row.get("machine_id")
                if _canonical_uuid(instance_id):
                    if _canonical_uuid(machine_id):
                        matches.setdefault(instance_id, []).append(machine_id)
                    else:
                        unresolvable.add(instance_id)
            unresolvable.update(key for key, values in matches.items() if len(values) != 1)
            result: _Snapshot = (
                {key: tuple(values) for key, values in matches.items()},
                frozenset(unresolvable),
            )
            self._cycle_results[scope] = result
            self._cache[scope] = (now + self.ttl_seconds, result)
            self._cache.move_to_end(scope)
            while len(self._cache) > MAX_CACHE_GROUPS:
                self._cache.popitem(last=False)
            return result
        except LiveTransportBlocked as exc:
            status = re.fullmatch(r"Salad List Instances returned HTTP (401|403)", str(exc))
            if status is not None:
                self.access_denied_status = int(status.group(1))
            # Provider errors, secrets and URLs never leave this boundary.
            self.lookup_failures += 1
            self._cycle_results[scope] = ({}, frozenset())
            return self._cycle_results[scope]
        except Exception:
            # Provider errors, secrets and URLs never leave this boundary.
            self.lookup_failures += 1
            self._cycle_results[scope] = ({}, frozenset())
            return self._cycle_results[scope]

    @staticmethod
    def _validated_response(
        response: SaladTransportResponse, scope: tuple[str, str, str],
    ) -> dict[str, Any] | None:
        if type(response) is not SaladTransportResponse or not isinstance(response.body, bytes):
            return None
        if len(response.body) > MAX_RESPONSE_BYTES:
            return None
        evidence = response.evidence
        if (
            type(evidence) is not ProviderResponseEvidence
            or evidence.status_code != response.status_code
            or evidence.classification not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}
            or hashlib.sha256(response.body).hexdigest() != evidence.response_sha256
        ):
            return None
        if evidence.classification == PROVIDER_OBSERVED and evidence.source != "salad_https_fixed_route":
            return None
        if evidence.classification == DATA_CLASSIFICATION and evidence.source != "offline_test_transport":
            return None
        if response.status_code != 200:
            return None
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None
