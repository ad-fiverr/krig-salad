"""HTTPS transport exercised only against an explicit loopback TLS server.

The request carries the fixed Salad host, SNI, and path so TLS and HTTP behavior
can be tested end to end. A structural production-network gate rejects calls
before DNS, socket creation, or secret access. Enabling Salad is a later task.
"""

from __future__ import annotations

import http.client
import math
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

from live_https_policy import RestrictedGET, SALAD_HOST, validate_request
from live_secret_boundary import (
    AuthorizationGrantBlocked,
    SaladAuthorizationVerifier,
    SecretMaterial,
    SignedSaladAuthorization,
)


PRODUCTION_NETWORK_ALLOWED = False
MAX_READ_CHUNK_BYTES = 16_384


class HTTPSRequestError(RuntimeError):
    """A terminal local HTTPS request failure with no provider text attached."""


class ProductionNetworkBlocked(HTTPSRequestError):
    """Production DNS and sockets are unavailable in this offline iteration."""


class TransportTimeout(HTTPSRequestError):
    """A bounded connect, request, read, or total-deadline timeout."""


class TLSValidationFailure(HTTPSRequestError):
    """Certificate, hostname, SNI, or protocol validation failed."""


class TransportFailure(HTTPSRequestError):
    """An HTTP transport failure occurred; original exception text is hidden."""


class ResponseContractError(HTTPSRequestError):
    """The HTTP response did not satisfy the local JSON response contract."""


class ResponseTooLarge(HTTPSRequestError):
    """The body crossed its cap; only the bounded byte count is retained."""

    def __init__(self, response_bytes: int):
        self.response_bytes = response_bytes
        super().__init__("response exceeds the approved byte cap")


@dataclass(frozen=True, slots=True)
class LoopbackTLSConfig:
    """Explicit test-only trust configuration for a server bound to 127.0.0.1."""

    port: int
    ca_file: str

    def __post_init__(self) -> None:
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65_535:
            raise ValueError("local TLS test port is invalid")
        if not isinstance(self.ca_file, str) or not self.ca_file:
            raise ValueError("local TLS test CA path is invalid")
        path = Path(self.ca_file).expanduser().resolve()
        if not path.is_file():
            raise ValueError("local TLS test CA file is unavailable")
        object.__setattr__(self, "ca_file", str(path))


@dataclass(frozen=True, slots=True)
class HTTPSResponse:
    """Sanitized transport result; only successful JSON bodies are retained."""

    status_code: int
    body: bytes = field(repr=False)
    response_bytes: int

    def __repr__(self) -> str:
        return (
            "HTTPSResponse(status_code="
            f"{self.status_code}, response_bytes={self.response_bytes}, body=[REDACTED])"
        )


class _LoopbackHTTPSConnection(http.client.HTTPSConnection):
    """Use 127.0.0.1 for TCP while retaining fixed api.salad.com TLS identity."""

    def connect(self) -> None:
        if self.host != SALAD_HOST or self._tunnel_host:
            raise OSError("local TLS transport host is fixed")
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=SALAD_HOST)
        except Exception:
            raw.close()
            raise


class LiveHTTPSTransport:
    """Fixed HTTPS GET implementation with production networking hard-blocked.

    The only usable mode accepts an explicit loopback TLS test target. It uses
    Python's standard library directly, so ambient proxy configuration is not
    consulted. There is no redirect handler or retry loop.
    """

    __slots__ = ("_local_tls",)

    def __init__(self, *, local_tls: LoopbackTLSConfig | None = None):
        if local_tls is not None and type(local_tls) is not LoopbackTLSConfig:
            raise TypeError("only the fixed loopback TLS test configuration is accepted")
        self._local_tls = local_tls

    @property
    def is_local_tls_test(self) -> bool:
        return self._local_tls is not None

    def send(
        self,
        request: RestrictedGET,
        secret: SecretMaterial,
        *,
        total_deadline_monotonic: float | None = None,
    ) -> HTTPSResponse:
        if not self.is_local_tls_test or PRODUCTION_NETWORK_ALLOWED:
            raise ProductionNetworkBlocked("production network gate is closed")
        fixed = validate_request(request)
        if type(secret) is not SecretMaterial:
            raise TypeError("transport requires internal SecretMaterial")
        now = time.monotonic()
        total_deadline = (
            now + fixed.total_deadline_seconds
            if total_deadline_monotonic is None
            else total_deadline_monotonic
        )
        if (
            isinstance(total_deadline, bool)
            or not isinstance(total_deadline, (float, int))
            or not math.isfinite(float(total_deadline))
            or float(total_deadline) <= now
        ):
            raise TransportTimeout("total request deadline has expired")
        request_deadline = min(
            float(total_deadline), now + fixed.request_timeout_seconds
        )
        context = ssl.create_default_context(cafile=self._local_tls.ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = _LoopbackHTTPSConnection(
            SALAD_HOST,
            port=self._local_tls.port,
            timeout=fixed.connect_timeout_seconds,
            context=context,
        )
        response: http.client.HTTPResponse | None = None
        try:
            connect_remaining = request_deadline - time.monotonic()
            if connect_remaining <= 0:
                raise TransportTimeout("request deadline expired before connect")
            connection.timeout = min(fixed.connect_timeout_seconds, connect_remaining)
            connection.connect()
            self._set_remaining_timeout(connection, request_deadline)
            connection.request(
                fixed.method,
                fixed.path,
                body=None,
                headers={
                    "Host": SALAD_HOST,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Salad-Api-Key": secret._header_value(),
                },
            )
            self._set_remaining_timeout(connection, request_deadline)
            # HTTPSConnection.getresponse() may close its socket as soon as a
            # server advertises Connection: close. Build the parser directly
            # over the still-owned TLS socket so bounded read timeouts remain
            # enforceable through the complete response body.
            if connection.sock is None:
                raise TransportFailure("HTTPS connection is unavailable")
            response = http.client.HTTPResponse(connection.sock, method=fixed.method)
            response.begin()
            status = response.status
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise ResponseContractError("HTTP status is invalid")
            if status != 200:
                # Do not read, retain, or echo provider error bodies or headers.
                return HTTPSResponse(status_code=status, body=b"", response_bytes=0)

            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().casefold()
            if content_type != "application/json" and not content_type.endswith("+json"):
                raise ResponseContractError("HTTP 200 response is not JSON")
            content_encoding = response.getheader("Content-Encoding", "identity").strip().casefold()
            if content_encoding not in {"", "identity"}:
                raise ResponseContractError("compressed response encoding is not accepted")
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    announced = int(content_length, 10)
                except (TypeError, ValueError):
                    raise ResponseContractError("content length is invalid") from None
                if announced < 0:
                    raise ResponseContractError("content length is invalid")
                if announced > fixed.max_response_bytes:
                    raise ResponseTooLarge(fixed.max_response_bytes + 1)

            body = bytearray()
            while True:
                remaining_capacity = fixed.max_response_bytes + 1 - len(body)
                if remaining_capacity <= 0:
                    raise ResponseTooLarge(fixed.max_response_bytes + 1)
                self._set_remaining_timeout(connection, request_deadline)
                chunk = response.read1(min(MAX_READ_CHUNK_BYTES, remaining_capacity))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > fixed.max_response_bytes:
                    raise ResponseTooLarge(fixed.max_response_bytes + 1)
                if time.monotonic() >= request_deadline:
                    raise TransportTimeout("response exceeded the request deadline")
            return HTTPSResponse(
                status_code=status,
                body=bytes(body),
                response_bytes=len(body),
            )
        except (ProductionNetworkBlocked, TransportTimeout, TLSValidationFailure,
                ResponseContractError, ResponseTooLarge):
            raise
        except (socket.timeout, TimeoutError):
            raise TransportTimeout("HTTPS operation timed out") from None
        except ssl.SSLError:
            raise TLSValidationFailure("TLS certificate or hostname validation failed") from None
        except Exception:
            raise TransportFailure("HTTPS operation failed") from None
        finally:
            if response is not None:
                response.close()
            connection.close()

    @staticmethod
    def _set_remaining_timeout(
        connection: http.client.HTTPSConnection,
        deadline: float,
    ) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportTimeout("request deadline expired")
        if connection.sock is None:
            raise TransportFailure("HTTPS connection is unavailable")
        connection.sock.settimeout(remaining)


class _SaladProductionConnection(http.client.HTTPSConnection):
    """Direct DNS/socket connection pinned to Salad's single HTTPS origin."""

    _loopback_test_port: int | None = None

    def connect(self) -> None:
        if self.host != SALAD_HOST or self.port != 443 or self._tunnel_host:
            raise OSError("production Salad transport origin is fixed")
        address = ("127.0.0.1", self._loopback_test_port) if self._loopback_test_port is not None else (SALAD_HOST, 443)
        raw = socket.create_connection(address, timeout=self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=SALAD_HOST)
        except Exception:
            raw.close()
            raise


class ProductionSaladTransport:
    """Dormant fixed-origin GET transport for a separately authorized session.

    The implementation has no proxy support, caller-supplied URL, method,
    headers, redirects, retries, or unbounded response handling. Its default
    constructor is closed; ``enabled=True`` is a future explicit composition
    switch and must never be set during offline G5 implementation or tests.
    """

    __slots__ = (
        "_enabled", "_test_ca_file", "_test_local_port",
        "_authorization_grant", "_authorization_verifier",
    )

    def __init__(
        self,
        *,
        enabled: bool = False,
        test_local_port: int | None = None,
        test_ca_file: str | None = None,
        authorization_grant: SignedSaladAuthorization | None = None,
        authorization_verifier: SaladAuthorizationVerifier | None = None,
    ):
        if not isinstance(enabled, bool):
            raise TypeError("production transport gate must be boolean")
        self._enabled = enabled
        if test_local_port is not None and (
            isinstance(test_local_port, bool) or not isinstance(test_local_port, int) or not 1 <= test_local_port <= 65535
        ):
            raise ValueError("local TLS test port is invalid")
        if (test_local_port is None) != (test_ca_file is None):
            raise ValueError("local TLS testing requires both a loopback port and a test CA")
        self._test_local_port = test_local_port
        if (authorization_grant is None) != (authorization_verifier is None):
            raise ValueError("production authorization requires both signed grant and trusted verifier")
        if authorization_grant is not None and type(authorization_grant) is not SignedSaladAuthorization:
            raise TypeError("production authorization grant has an invalid type")
        if authorization_verifier is not None and type(authorization_verifier) is not SaladAuthorizationVerifier:
            raise TypeError("production authorization verifier has an invalid type")
        self._authorization_grant = authorization_grant
        self._authorization_verifier = authorization_verifier
        if test_ca_file is not None:
            path = Path(test_ca_file).expanduser().resolve()
            if not path.is_file():
                raise ValueError("local TLS test CA file is unavailable")
            self._test_ca_file = str(path)
        else:
            self._test_ca_file = None

    @property
    def is_local_tls_test(self) -> bool:
        return self._test_local_port is not None

    def authorization_allows_session(self, *, run_id: str, now_epoch: float) -> bool:
        """A local boolean cannot enable production; only a signed run grant can."""
        if self.is_local_tls_test:
            return True
        verifier = self._authorization_verifier
        grant = self._authorization_grant
        return bool(
            verifier is not None
            and grant is not None
            and all(
                verifier.verify_get(
                    grant, run_id=run_id, container_group=group, now_epoch=now_epoch
                )
                for group in ("fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4")
            )
        )

    def send(
        self,
        request: RestrictedGET,
        secret: SecretMaterial,
        *,
        total_deadline_monotonic: float | None = None,
        run_id: str | None = None,
    ) -> HTTPSResponse:
        if not self._enabled:
            raise ProductionNetworkBlocked("production network gate is closed")
        fixed = validate_request(request)
        if not self.is_local_tls_test:
            verifier = self._authorization_verifier
            grant = self._authorization_grant
            if (
                verifier is None or grant is None or not isinstance(run_id, str)
                or not verifier.verify_get(
                    grant,
                    run_id=run_id,
                    container_group=request.container_group.value,
                    now_epoch=time.time(),
                )
            ):
                raise AuthorizationGrantBlocked("a valid signed Salad GET capability is required")
        if type(secret) is not SecretMaterial:
            raise TypeError("transport requires internal SecretMaterial")
        now = time.monotonic()
        deadline = now + fixed.total_deadline_seconds if total_deadline_monotonic is None else total_deadline_monotonic
        if isinstance(deadline, bool) or not isinstance(deadline, (float, int)) or not math.isfinite(float(deadline)) or float(deadline) <= now:
            raise TransportTimeout("total request deadline has expired")
        request_deadline = min(float(deadline), now + fixed.request_timeout_seconds)
        context = ssl.create_default_context(cafile=self._test_ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        connection = _SaladProductionConnection(
            SALAD_HOST, port=443, timeout=fixed.connect_timeout_seconds, context=context
        )
        connection._loopback_test_port = self._test_local_port
        response: http.client.HTTPResponse | None = None
        try:
            remaining = request_deadline - time.monotonic()
            if remaining <= 0:
                raise TransportTimeout("request deadline expired before connect")
            connection.timeout = min(fixed.connect_timeout_seconds, remaining)
            connection.connect()
            LiveHTTPSTransport._set_remaining_timeout(connection, request_deadline)
            connection.request(
                "GET", fixed.path, body=None,
                headers={
                    "Host": "api.salad.com", "Accept": "application/json",
                    "Accept-Encoding": "identity", "Connection": "close",
                    "Salad-Api-Key": secret._header_value(),
                },
            )
            LiveHTTPSTransport._set_remaining_timeout(connection, request_deadline)
            if connection.sock is None:
                raise TransportFailure("HTTPS connection is unavailable")
            response = http.client.HTTPResponse(connection.sock, method="GET")
            response.begin()
            status = response.status
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise ResponseContractError("HTTP status is invalid")
            if status != 200:
                return HTTPSResponse(status_code=status, body=b"", response_bytes=0)
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().casefold()
            if content_type != "application/json" and not content_type.endswith("+json"):
                raise ResponseContractError("HTTP 200 response is not JSON")
            if response.getheader("Content-Encoding", "identity").strip().casefold() not in {"", "identity"}:
                raise ResponseContractError("compressed response encoding is not accepted")
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    announced = int(content_length, 10)
                except (TypeError, ValueError):
                    raise ResponseContractError("content length is invalid") from None
                if announced < 0:
                    raise ResponseContractError("content length is invalid")
                if announced > fixed.max_response_bytes:
                    raise ResponseTooLarge(fixed.max_response_bytes + 1)
            body = bytearray()
            while True:
                capacity = fixed.max_response_bytes + 1 - len(body)
                if capacity <= 0:
                    raise ResponseTooLarge(fixed.max_response_bytes + 1)
                LiveHTTPSTransport._set_remaining_timeout(connection, request_deadline)
                chunk = response.read1(min(MAX_READ_CHUNK_BYTES, capacity))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > fixed.max_response_bytes:
                    raise ResponseTooLarge(fixed.max_response_bytes + 1)
                if time.monotonic() >= request_deadline:
                    raise TransportTimeout("response exceeded the request deadline")
            return HTTPSResponse(status_code=200, body=bytes(body), response_bytes=len(body))
        except (ProductionNetworkBlocked, TransportTimeout, TLSValidationFailure,
                ResponseContractError, ResponseTooLarge):
            raise
        except (socket.timeout, TimeoutError):
            raise TransportTimeout("HTTPS operation timed out") from None
        except ssl.SSLError:
            raise TLSValidationFailure("TLS certificate or hostname validation failed") from None
        except Exception:
            raise TransportFailure("HTTPS operation failed") from None
        finally:
            if response is not None:
                response.close()
            connection.close()
