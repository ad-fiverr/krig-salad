"""Offline-testable adapter boundary for a future managed secret service.

Only the disabled backend and a synthetic in-memory backend are implemented.
No SDK, ADC discovery, environment variable, credential file, or cloud request
is available in this iteration.
"""

from __future__ import annotations

from live_secret_boundary import (
    SECRET_REFERENCE_ID,
    SYNTHETIC_SECRET_VALUE,
    SecretAccessBlocked,
    SecretMaterial,
    SecretProvider,
)


REAL_SECRET_BACKEND_WIRED = False


class ManagedSecretBackend:
    """Narrow backend contract; a production backend is intentionally absent."""

    def read(self, reference_id: str) -> str | bytes:
        raise NotImplementedError


class DisabledManagedSecretBackend(ManagedSecretBackend):
    def read(self, reference_id: str) -> str | bytes:
        del reference_id
        raise SecretAccessBlocked("managed secret backend is disabled")


class SyntheticManagedSecretBackend(ManagedSecretBackend):
    """Local test double with fixed reference and synthetic-only test values."""

    __slots__ = ("_value", "_failure", "_read_count")

    def __init__(self, *, value: str | bytes = SYNTHETIC_SECRET_VALUE, failure: bool = False):
        if not isinstance(failure, bool):
            raise TypeError("failure flag must be boolean")
        self._value = value
        self._failure = failure
        self._read_count = 0

    @property
    def read_count(self) -> int:
        return self._read_count

    def read(self, reference_id: str) -> str | bytes:
        self._read_count += 1
        if reference_id != SECRET_REFERENCE_ID:
            raise SecretAccessBlocked("managed secret reference is not approved")
        if self._failure:
            raise RuntimeError(f"synthetic backend failure: {SYNTHETIC_SECRET_VALUE}")
        return self._value


class ManagedSecretAdapter(SecretProvider):
    """Calls a fixed backend reference and exposes only validated test material.

    Runtime construction rejects every backend other than the two in-module
    offline implementations. A real service integration needs a later plan.
    """

    __slots__ = ("_backend",)

    def __init__(self, backend: ManagedSecretBackend | None = None):
        selected = backend if backend is not None else DisabledManagedSecretBackend()
        if type(selected) not in {DisabledManagedSecretBackend, SyntheticManagedSecretBackend}:
            raise TypeError("only the disabled or synthetic managed backend is accepted")
        self._backend = selected

    @property
    def backend_read_count(self) -> int:
        return int(getattr(self._backend, "read_count", 0))

    @property
    def is_synthetic_only(self) -> bool:
        return type(self._backend) is SyntheticManagedSecretBackend

    def acquire(self) -> SecretMaterial:
        try:
            value = self._backend.read(SECRET_REFERENCE_ID)
            if value != SYNTHETIC_SECRET_VALUE:
                raise SecretAccessBlocked("managed backend returned a non-synthetic value")
            return SecretMaterial(value, source_label="synthetic_managed_backend")
        except SecretAccessBlocked:
            raise SecretAccessBlocked("managed secret acquisition is blocked") from None
        except Exception:
            raise SecretAccessBlocked("managed secret acquisition failed") from None
