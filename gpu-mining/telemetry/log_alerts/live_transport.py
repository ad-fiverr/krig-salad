"""Disabled-by-default HTTPS boundary for Salad's log-query operation.

Only the exact organization log-query POST is represented here. The
production network gate is intentionally closed in this release. Offline
tests can use an explicitly named in-memory exchange that has no socket or
DNS implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import importlib.util
import json
import ssl
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

from .contract import (
    LiveLogQueryPolicy,
    LiveReadLogQueryRequest,
    LiveQueryPolicyError,
    MAX_LOCAL_PAGE_SIZE,
    PROVIDER_OBSERVED,
    canonical_utc,
)


PRODUCTION_NETWORK_ALLOWED = False
MAX_REQUEST_BYTES = 24_000
MAX_RESPONSE_BYTES = 5_000_000
CONNECT_TIMEOUT_SECONDS = 8.0
READ_TIMEOUT_SECONDS = 12.0
_SECRET_BOUNDARY_MODULE = "_salad_g4c_live_secret_boundary"


class LiveTransportBlocked(RuntimeError):
    """The production network boundary is closed or failed safely."""


def secret_boundary_types() -> tuple[type, type, type]:
    """Load the exact approved G4C secret classes from their repository path."""
    expected = (
        Path(__file__).resolve().parents[3]
        / "gpu-mining"
        / "g4c-live"
        / "live_secret_boundary.py"
    ).resolve()
    module = sys.modules.get(_SECRET_BOUNDARY_MODULE)
    if module is None:
        spec = importlib.util.spec_from_file_location(_SECRET_BOUNDARY_MODULE, expected)
        if spec is None or spec.loader is None:
            raise LiveTransportBlocked("approved Salad secret boundary is unavailable")
        module = importlib.util.module_from_spec(spec)
        sys.modules[_SECRET_BOUNDARY_MODULE] = module
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(_SECRET_BOUNDARY_MODULE, None)
            raise LiveTransportBlocked("approved Salad secret boundary is unavailable") from None
    module_path = getattr(module, "__file__", None)
    try:
        actual = Path(module_path).resolve()
    except (TypeError, OSError):
        raise LiveTransportBlocked("approved Salad secret boundary is unavailable") from None
    if actual != expected:
        raise LiveTransportBlocked("approved Salad secret boundary identity is invalid")
    try:
        interactive = module.InteractiveSecretProvider
        synthetic = module.SyntheticSecretProvider
        material = module.SecretMaterial
    except AttributeError:
        raise LiveTransportBlocked("approved Salad secret boundary is incomplete") from None
    return interactive, synthetic, material


_PROVIDER_RESPONSE_AUTHORITY = object()


@dataclass(frozen=True, slots=True, init=False)
class ProviderResponseEvidence:
    """Provenance emitted only after an actual fixed-target HTTPS response."""

    source: str
    classification: str
    status_code: int
    response_sha256: str = field(repr=False)

    def __init__(self, *, source: str, classification: str, status_code: int,
                 response_sha256: str, _authority: object):
        if _authority is not _PROVIDER_RESPONSE_AUTHORITY:
            raise TypeError("response evidence is created only by the transport")
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "status_code", status_code)
        object.__setattr__(self, "response_sha256", response_sha256)

    def __repr__(self) -> str:
        return f"ProviderResponseEvidence(source={self.source!r}, classification={self.classification!r}, status_code={self.status_code}, response_sha256=[REDACTED])"


@dataclass(frozen=True, slots=True)
class SaladTransportResponse:
    status_code: int
    body: bytes = field(repr=False)
    evidence: ProviderResponseEvidence | None = None

    def __repr__(self) -> str:
        return f"SaladTransportResponse(status_code={self.status_code}, body=[REDACTED], evidence={self.evidence!r})"


class OfflineSaladExchange:
    """Explicit test-only HTTP exchange; this class never opens a socket."""

    def __init__(self, responder: Callable[[str, str, Mapping[str, str], bytes], SaladTransportResponse]):
        if not callable(responder):
            raise TypeError("offline responder must be callable")
        self._responder = responder
        self.calls: list[dict[str, Any]] = []

    def exchange(self, host: str, path: str, headers: Mapping[str, str], body: bytes) -> SaladTransportResponse:
        self.calls.append({"host": host, "path": path, "headers": {
            key: ("[REDACTED]" if key.casefold() in {"salad-api-key", "authorization"} else value)
            for key, value in headers.items()
        }, "body_bytes": len(body)})
        return self._responder(host, path, headers, body)


class LiveSaladReadTransport:
    """One-request HTTPS transport with no redirects, retries or proxy use."""

    __slots__ = ("policy", "_secret_provider", "_offline_exchange")

    def __init__(self, *, policy: LiveLogQueryPolicy, secret_provider: Any = None):
        if type(policy) is not LiveLogQueryPolicy:
            raise TypeError("a fixed LiveLogQueryPolicy is required")
        if secret_provider is not None:
            interactive_provider, _, _ = secret_boundary_types()
            if type(secret_provider) is not interactive_provider:
                raise TypeError("the exact approved InteractiveSecretProvider is required")
        self.policy = policy
        self._secret_provider = secret_provider
        self._offline_exchange = None

    @classmethod
    def for_offline_test(
        cls,
        *,
        policy: LiveLogQueryPolicy,
        exchange: OfflineSaladExchange,
    ) -> "LiveSaladReadTransport":
        if type(policy) is not LiveLogQueryPolicy or type(exchange) is not OfflineSaladExchange:
            raise TypeError("offline transport requires exact test policy and exchange types")
        instance = cls.__new__(cls)
        instance.policy = policy
        instance._secret_provider = None
        instance._offline_exchange = exchange
        return instance

    def __repr__(self) -> str:
        return "LiveSaladReadTransport(host='api.salad.com', route=READ_LOG_QUERY, credentials=[REDACTED], enabled=False)"

    def fetch_query(self, request: LiveReadLogQueryRequest, *, secret: Any = None) -> SaladTransportResponse:
        self.policy.validate(request)
        body = _encode_request_body(request)
        if self._offline_exchange is not None:
            headers = {
                "Host": "api.salad.com",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            if secret is not None:
                _, _, secret_material = secret_boundary_types()
                if (
                    type(secret) is not secret_material
                    or getattr(secret, "source_label", None) != "synthetic_test_provider"
                ):
                    raise LiveTransportBlocked("offline transport accepts only synthetic test material")
                headers["Salad-Api-Key"] = secret._header_value()
            response = self._offline_exchange.exchange(request.host, request.path, headers, body)
            if (
                type(response) is not SaladTransportResponse
                or not isinstance(response.body, bytes)
                or len(response.body) > MAX_RESPONSE_BYTES
            ):
                raise LiveTransportBlocked("offline response is outside local limits")
            # An in-memory fake is never reclassified as a Salad observation.
            evidence = ProviderResponseEvidence(
                source="offline_test_transport",
                classification="SYNTHETIC/UNVERIFIED",
                status_code=response.status_code,
                response_sha256=_sha256(response.body),
                _authority=_PROVIDER_RESPONSE_AUTHORITY,
            )
            return SaladTransportResponse(response.status_code, response.body, evidence)

        # This immutable task-level gate is deliberately hard false. It is
        # checked before credential acquisition and before any connection.
        if PRODUCTION_NETWORK_ALLOWED is not True:
            raise LiveTransportBlocked("Salad production network access is disabled")
        interactive_provider, _, secret_material = secret_boundary_types()
        if (
            type(self._secret_provider) is not interactive_provider
            or type(secret) is not secret_material
            or getattr(secret, "source_label", None) != "interactive_tty_session"
        ):
            raise LiveTransportBlocked("interactive Salad credential is unavailable")
        try:
            if self._secret_provider.acquire() is not secret:
                raise LiveTransportBlocked("interactive Salad credential source does not match")
        except LiveTransportBlocked:
            raise
        except Exception:
            raise LiveTransportBlocked("interactive Salad credential source is unavailable") from None
        return self._https_exchange(request, body, secret)

    def _https_exchange(
        self, request: LiveReadLogQueryRequest, body: bytes, secret: Any,
    ) -> SaladTransportResponse:
        # No urllib/proxy handler is used. One HTTPS request is made to the
        # literal host and port; 3xx responses are returned as failures rather
        # than followed.
        conn: http.client.HTTPSConnection | None = None
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            conn = http.client.HTTPSConnection(
                "api.salad.com", 443, timeout=CONNECT_TIMEOUT_SECONDS, context=context,
            )
            conn.connect()
            if conn.sock is not None:
                conn.sock.settimeout(READ_TIMEOUT_SECONDS)
            conn.putrequest("POST", request.path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", "api.salad.com")
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Accept", "application/json")
            conn.putheader("Salad-Api-Key", secret._header_value())
            conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            response = conn.getresponse()
            if 300 <= response.status < 400:
                raise LiveTransportBlocked("Salad redirects are not followed")
            if response.status != 200:
                raise LiveTransportBlocked(f"Salad query returned HTTP {response.status}")
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise LiveTransportBlocked("Salad response exceeds the local byte limit")
            import hashlib
            evidence = ProviderResponseEvidence(
                source="salad_https_fixed_route",
                classification=PROVIDER_OBSERVED,
                status_code=response.status,
                response_sha256=hashlib.sha256(response_body).hexdigest(),
                _authority=_PROVIDER_RESPONSE_AUTHORITY,
            )
            return SaladTransportResponse(response.status, response_body, evidence)
        except LiveTransportBlocked:
            raise
        except Exception:
            # Never echo http.client exceptions, request headers or URL context.
            raise LiveTransportBlocked("Salad HTTPS query failed; details redacted") from None
        finally:
            if conn is not None:
                conn.close()


def _encode_request_body(request: LiveReadLogQueryRequest) -> bytes:
    payload = {
        "start_time": request.start_time_utc,
        "end_time": request.end_time_utc,
        "query": request.query,
        "page_size": request.page_size,
        "sort_order": request.sort_order,
    }
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise LiveQueryPolicyError("query request is not valid JSON") from None
    if len(encoded) > MAX_REQUEST_BYTES:
        raise LiveQueryPolicyError("query request exceeds the local byte limit")
    return encoded


def _sha256(value: bytes) -> str:
    import hashlib
    return hashlib.sha256(value).hexdigest()
