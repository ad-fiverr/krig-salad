"""Fail-closed secret boundary for offline-only Salad broker tests.

There is deliberately no environment, filesystem, OS credential-vault, or
cloud Secret Manager reader in this module. Python object encapsulation is not
an operating-system isolation boundary.
"""

from __future__ import annotations

import getpass
import json
import re
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any


SECRET_REFERENCE_ID = "salad-api-key"
SYNTHETIC_SECRET_VALUE = "SYNTHETIC_ONLY_NOT_A_CREDENTIAL"
MAX_SECRET_BYTES = 4096


class SecretAccessBlocked(RuntimeError):
    """Secret acquisition is unavailable or failed a safe validation."""


class AuthorizationGrantBlocked(RuntimeError):
    """No externally signed, in-scope production authorization was supplied."""


@dataclass(frozen=True, slots=True)
class SignedSaladAuthorization:
    """Opaque externally signed grant; repr deliberately omits its contents."""

    payload: bytes = field(repr=False)
    signature: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes) or not 1 <= len(self.payload) <= 4096:
            raise AuthorizationGrantBlocked("authorization payload is invalid")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise AuthorizationGrantBlocked("authorization signature is invalid")

    def __repr__(self) -> str:
        return "SignedSaladAuthorization([REDACTED])"


class SaladAuthorizationVerifier:
    """Verify an operator-signed, narrowly scoped GET capability.

    No signing key is stored here. The caller must supply an already trusted
    Ed25519 public key and the signature over canonical JSON claims. Boolean
    feature flags cannot construct or verify this capability.
    """

    __slots__ = ("_public_key",)

    def __init__(self, public_key: bytes):
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise AuthorizationGrantBlocked("trusted authorization key is invalid")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            self._public_key = Ed25519PublicKey.from_public_bytes(public_key)
        except Exception:
            raise AuthorizationGrantBlocked("trusted authorization key is unavailable") from None

    def verify_get(
        self,
        grant: SignedSaladAuthorization | None,
        *,
        run_id: str,
        container_group: str,
        now_epoch: float,
    ) -> bool:
        if type(grant) is not SignedSaladAuthorization:
            return False
        if not isinstance(run_id, str) or not run_id or container_group not in {
            "fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4"
        }:
            return False
        if isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float)):
            return False
        try:
            self._public_key.verify(grant.signature, grant.payload)
            claims = json.loads(grant.payload.decode("utf-8"))
        except Exception:
            return False
        expected = {
            "schema_version", "audience", "host", "purpose", "organization",
            "project", "groups", "max_requests", "run_id", "issued_at_epoch",
            "expires_at_epoch", "nonce",
        }
        if not isinstance(claims, dict) or set(claims) != expected:
            return False
        try:
            expires = float(claims["expires_at_epoch"])
            issued = float(claims["issued_at_epoch"])
            nonce = str(uuid.UUID(claims["nonce"]))
        except (TypeError, ValueError, OverflowError):
            return False
        groups = ["fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4"]
        return (
            claims["schema_version"] == 1
            and claims["audience"] == "salad-g5-control-plane"
            and claims["host"] == "api.salad.com"
            and claims["purpose"] == "list_container_group_instances"
            and claims["organization"] == "adrianfiverr"
            and claims["project"] == "miners"
            and claims["groups"] == groups
            and claims["max_requests"] == 4
            and claims["run_id"] == run_id
            and nonce == claims["nonce"]
            and issued <= float(now_epoch) < expires
            and expires - issued <= 900
        )


class SecretMaterial:
    """Short-lived secret value whose normal representations are redacted."""

    __slots__ = ("__value", "source_label")

    def __init__(self, value: str | bytes, *, source_label: str):
        if not isinstance(source_label, str) or source_label not in {
            "synthetic_test_provider",
            "synthetic_managed_backend",
            "interactive_tty_session",
        }:
            raise SecretAccessBlocked("secret source is not approved for offline use")
        if isinstance(value, str):
            try:
                raw = value.encode("ascii")
            except UnicodeEncodeError as exc:
                raise SecretAccessBlocked("secret format is invalid") from None
        elif isinstance(value, bytes):
            raw = value
        else:
            raise SecretAccessBlocked("secret format is invalid")
        if not raw or len(raw) > MAX_SECRET_BYTES or any(byte < 33 or byte > 126 for byte in raw):
            raise SecretAccessBlocked("secret format is invalid")
        if source_label != "interactive_tty_session" and raw != SYNTHETIC_SECRET_VALUE.encode("ascii"):
            raise SecretAccessBlocked("only the fixed offline synthetic marker is accepted")
        self.__value = raw
        self.source_label = source_label

    def _header_value(self) -> str:
        """Internal transport handoff; never use in logs or result documents."""
        return self.__value.decode("ascii")

    def __repr__(self) -> str:
        return "SecretMaterial([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"


class SecretProvider:
    """Typed provider interface; the production implementation is absent."""

    def acquire(self) -> SecretMaterial:
        raise NotImplementedError


class DisabledSecretProvider(SecretProvider):
    """The default provider, which never reads any credential source."""

    def acquire(self) -> SecretMaterial:
        raise SecretAccessBlocked("secret access is disabled")


class SyntheticSecretProvider(SecretProvider):
    """A QA-only provider that returns one fixed, unmistakably fake marker."""

    __slots__ = ("_read_count",)

    def __init__(self):
        self._read_count = 0

    @property
    def read_count(self) -> int:
        return self._read_count

    def acquire(self) -> SecretMaterial:
        self._read_count += 1
        return SecretMaterial(
            SYNTHETIC_SECRET_VALUE,
            source_label="synthetic_test_provider",
        )


class InteractiveSecretProvider(SecretProvider):
    """Explicit, one-shot, hidden terminal acquisition for a future live session.

    Constructing this provider is inert. Acquisition requires ``enabled=True``
    and an interactive stdin. There is no environment, file, browser, or
    command-line secret source. Tests should patch ``getpass.getpass`` and use
    only ``SYNTHETIC_SECRET_VALUE``.
    """

    __slots__ = ("_enabled", "_read_count", "_acquired")

    def __init__(self, *, enabled: bool = False):
        if not isinstance(enabled, bool):
            raise TypeError("interactive secret enable flag must be boolean")
        self._enabled = enabled
        self._read_count = 0
        self._acquired: SecretMaterial | None = None

    @property
    def read_count(self) -> int:
        return self._read_count

    def acquire(self) -> SecretMaterial:
        if not self._enabled:
            raise SecretAccessBlocked("interactive secret access is disabled")
        if self._acquired is not None:
            return self._acquired
        try:
            if not sys.stdin.isatty():
                raise SecretAccessBlocked("secret acquisition requires an interactive terminal")
            value = getpass.getpass("Salad API key (input hidden): ")
            self._read_count += 1
            material = SecretMaterial(value, source_label="interactive_tty_session")
        except SecretAccessBlocked:
            raise
        except Exception:
            # Do not preserve or echo terminal/provider exception content.
            raise SecretAccessBlocked("interactive secret acquisition failed") from None
        self._acquired = material
        return material


DEFAULT_SECRET_PROVIDER = DisabledSecretProvider
REAL_SECRET_ACCESS_ALLOWED = False


def redact_secret(value: Any) -> str:
    """Render untrusted backend/transport failures without their contents."""
    del value
    return "[REDACTED]"
