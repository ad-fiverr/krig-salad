#!/usr/bin/env python3
"""One-shot, fixed-scope recovery for Fl4shMiner Docker Hub targets 4-6.

The command never builds an image. It copies one immutable public registry
manifest and refuses a copy if Skopeo cannot preserve its digest.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
from dataclasses import dataclass, field
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlencode

import fl4sh_publish as publisher


SOURCE_REPOSITORY = "myblockchaincompany/fl4shminer-salad"
SOURCE_DIGEST = "sha256:4091b611ea99c64abdc854a4cfe2d5b95b6202adf12a6e2ab7437a62a1325217"
SOURCE_CONFIG_DIGEST = "sha256:2462b32f85b99ea08d42a5289c62cc43e28bcf555ab2dbe0fc23207a74fa572b"
SOURCE_REVISION = "e66ba5e17bafd105c6ef89acf7ff38c1f87e3542"
SOURCE_URL = "https://github.com/ad-fiverr/krig-salad"
VERSION = "1.5.2"
TAGS = ("sha-e66ba5e17baf", VERSION, "latest")
CONFIRMATION = "RECOVER_TARGETS_4_6"
SKOPEO_VERSION = "1.4.1"
SKOPEO_COMMAND_TIMEOUT_SECONDS = 60
SKOPEO_COPY_TIMEOUT_SECONDS = 4 * 60 * 60
MAX_REGISTRY_BODY = 1_000_000
MAX_CONFIG_OUTPUT = 2_000_000
MAX_TOOL_OUTPUT = 1_000_000
RESULT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Target:
    id: str
    repository: str
    username: str
    username_secret: str
    token_secret: str


WRITE_TARGETS = (
    Target("naxter1234", "naxter1234/traning_lora", "naxter1234",
           "DOCKERHUB_USERNAME_NAXTER1234", "DOCKERHUB_TOKEN_NAXTER1234"),
    Target("ardevsolutions", "ardevsolutions/comfyui_video_wan2.5", "ardevsolutions",
           "DOCKERHUB_USERNAME_ARDEVSOLUTIONS", "DOCKERHUB_TOKEN_ARDEVSOLUTIONS"),
    Target("boeing787", "boeing787/model_funning_tuning", "boeing787",
           "DOCKERHUB_USERNAME_BOEING787", "DOCKERHUB_TOKEN_BOEING787"),
)
READ_TARGETS = (
    Target("primary", SOURCE_REPOSITORY, "myblockchaincompany",
           "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"),
    Target("loboeldrin", "loboeldrin/comfyui-minimax-h3", "loboeldrin",
           "DOCKERHUB_USERNAME_LOBOELDRIN", "DOCKERHUB_TOKEN_LOBOELDRIN"),
    Target("adrianfiverr", "adrianfiverr/pytorch-rc-2.15-dev", "adrianfiverr",
           "DOCKERHUB_USERNAME_ADRIANFIVERR", "DOCKERHUB_TOKEN_ADRIANFIVERR"),
    *WRITE_TARGETS,
)
WRITE_BY_ID = {target.id: target for target in WRITE_TARGETS}
READ_BY_ID = {target.id: target for target in READ_TARGETS}
TARGET_IDS = tuple(target.id for target in WRITE_TARGETS)
ALL_TARGET_IDS = tuple(target.id for target in READ_TARGETS)
PROTECTED_TARGET_IDS = ALL_TARGET_IDS[:3]
TAG_STATES = frozenset({
    "PENDING", "ABSENT_HTTP404", "ALREADY_PRESENT", "COPY_IN_PROGRESS",
    "PUBLISHED_VERIFIED", "COPY_FAILED", "DIGEST_MISMATCH", "VERIFIED",
    "UNKNOWN", "CONFLICT",
})
PREFLIGHT_STATES = frozenset({"PREFLIGHT_READY", "BLOCKED"})
TARGET_STATES = frozenset({"NOT_STARTED", "COPY_IN_PROGRESS", "PARTIAL_PUBLICATION",
                            "TARGET_VERIFIED", "ALREADY_PRESENT", "BLOCKED", "UNKNOWN"})
SAFE_FAILURE_CODES = frozenset({
    "ARGUMENT_INVALID", "DISPATCH_NOT_AUTHORIZED", "RERUN_NOT_ALLOWED",
    "RESULT_FILE_EXISTS", "RESULT_STATE_INVALID", "PREFLIGHT_INCOMPLETE",
    "TARGET_NOT_ALLOWED", "CREDENTIALS_INVALID", "AUTH_SCOPE_UNKNOWN",
    "AUTH_SCOPE_INSUFFICIENT", "REGISTRY_CHALLENGE_INVALID", "REGISTRY_AUTH_REJECTED",
    "REGISTRY_FORBIDDEN", "REGISTRY_RATE_LIMITED", "REGISTRY_REDIRECT_BLOCKED",
    "REGISTRY_RESPONSE_INVALID", "REGISTRY_RESPONSE_LIMIT", "REGISTRY_UNKNOWN",
    "SOURCE_IDENTITY_INVALID", "IMAGE_IDENTITY_INVALID", "TAG_CONFLICT",
    "SKOPEO_UNAVAILABLE", "SKOPEO_VERSION_UNSUPPORTED", "SKOPEO_FEATURE_UNAVAILABLE",
    "SKOPEO_LOGIN_FAILED", "SKOPEO_INSPECT_FAILED", "SKOPEO_COPY_FAILED",
    "SKOPEO_TIMEOUT", "SKOPEO_OUTPUT_LIMIT", "SKOPEO_SPAWN_FAILED",
    "DIGEST_PRESERVATION_FAILED", "RUN_ALREADY_ATTEMPTED", "INTERRUPTED",
    "PROTECTED_TARGETS_UNVERIFIED", "PROTECTED_TARGET_DRIFT", "RECOVERY_SEQUENCE_BLOCKED",
    "INTERNAL_FAILURE",
})


class RecoveryError(Exception):
    """A fixed code only; provider bodies and subprocess details are discarded."""

    def __init__(self, code: str):
        self.code = code if code in SAFE_FAILURE_CODES else "INTERNAL_FAILURE"
        super().__init__(self.code)


@dataclass(frozen=True)
class ManifestState:
    digest: str
    config: str
    content_hash: str
    layer_count: int


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes = field(repr=False)


class Credentials:
    """Keep account material out of dataclass reprs and serialized results."""

    __slots__ = ("username", "token")

    def __init__(self, username: str, token: str):
        self.username = username
        self.token = token

    def __repr__(self) -> str:
        return "Credentials(<redacted>)"


def _target(target_id: str, *, write_only: bool = False) -> Target:
    found = WRITE_BY_ID.get(target_id) if write_only else READ_BY_ID.get(target_id)
    if found is None:
        raise RecoveryError("TARGET_NOT_ALLOWED")
    return found


def _validate_credentials(target: Target, username: object, token: object) -> Credentials:
    if (not isinstance(username, str) or username != target.username
            or not isinstance(token, str) or not 1 <= len(token) <= 4096
            or any(not 33 <= ord(char) <= 126 for char in token)):
        raise RecoveryError("CREDENTIALS_INVALID")
    return Credentials(username, token)


def _new_results(run_id: str, attempt: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", run_id or "") or attempt != "1":
        raise RecoveryError("RERUN_NOT_ALLOWED")
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "run_id": run_id,
        "run_attempt": attempt,
        "source_digest": SOURCE_DIGEST,
        "source_revision": SOURCE_REVISION,
        "tags": list(TAGS),
        "preflight": {},
        "targets": {
            target_id: {"status": "NOT_STARTED", "attempted": False,
                        "failure_code": None,
                        "tags": {tag: {"status": "PENDING", "digest": None,
                                       "failure_code": None} for tag in TAGS}}
            for target_id in TARGET_IDS
        },
        "verification": {},
    }


def _validate_results(data: object) -> dict:
    if not isinstance(data, dict) or set(data) != {
        "schema_version", "run_id", "run_attempt", "source_digest", "source_revision",
        "tags", "preflight", "targets", "verification",
    }:
        raise RecoveryError("RESULT_STATE_INVALID")
    if (data.get("schema_version") != RESULT_SCHEMA_VERSION
            or data.get("source_digest") != SOURCE_DIGEST
            or data.get("source_revision") != SOURCE_REVISION
            or data.get("tags") != list(TAGS)
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", str(data.get("run_id", "")))
            or data.get("run_attempt") != "1"):
        raise RecoveryError("RESULT_STATE_INVALID")
    preflight = data.get("preflight")
    targets = data.get("targets")
    verification = data.get("verification")
    if (not isinstance(preflight, dict) or not set(preflight).issubset(TARGET_IDS)
            or not isinstance(targets, dict) or set(targets) != set(TARGET_IDS)
            or not isinstance(verification, dict) or not set(verification).issubset(ALL_TARGET_IDS)):
        raise RecoveryError("RESULT_STATE_INVALID")
    for target_id, row in preflight.items():
        if (not isinstance(row, dict) or set(row) != {"status", "failure_code", "tags"}
                or row.get("status") not in PREFLIGHT_STATES
                or row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)
                or not isinstance(row.get("tags"), dict)
                or not set(row["tags"]).issubset(TAGS)):
            raise RecoveryError("RESULT_STATE_INVALID")
    for target_id, row in targets.items():
        if (not isinstance(row, dict) or set(row) != {"status", "attempted", "failure_code", "tags"}
                or row.get("status") not in TARGET_STATES or type(row.get("attempted")) is not bool
                or row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)
                or not isinstance(row.get("tags"), dict) or set(row["tags"]) != set(TAGS)):
            raise RecoveryError("RESULT_STATE_INVALID")
        for tag_row in row["tags"].values():
            if (not isinstance(tag_row, dict) or set(tag_row) != {"status", "digest", "failure_code"}
                    or tag_row.get("status") not in TAG_STATES
                    or tag_row.get("digest") not in (None, SOURCE_DIGEST)
                    or tag_row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)):
                raise RecoveryError("RESULT_STATE_INVALID")
    for target_id, row in verification.items():
        if (not isinstance(row, dict) or set(row) != {"status", "failure_code", "tags"}
                or row.get("status") not in {"VERIFIED", "BLOCKED", "UNKNOWN"}
                or row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)
                or not isinstance(row.get("tags"), dict)
                or not set(row["tags"]).issubset(TAGS)):
            raise RecoveryError("RESULT_STATE_INVALID")
        for tag_row in row["tags"].values():
            if (not isinstance(tag_row, dict) or set(tag_row) != {"status", "digest"}
                    or tag_row.get("status") not in {"VERIFIED", "ABSENT_HTTP404", "CONFLICT", "UNKNOWN"}
                    or tag_row.get("digest") not in (None, SOURCE_DIGEST)):
                raise RecoveryError("RESULT_STATE_INVALID")
    return data


def _write_results(path: Path, data: dict) -> None:
    _validate_results(data)
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    encoded = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        temporary.replace(path)
    except Exception:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise RecoveryError("RESULT_STATE_INVALID") from None


def _read_results(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        if len(raw) > 1_000_000:
            raise ValueError
        return _validate_results(json.loads(raw))
    except RecoveryError:
        raise
    except Exception:
        raise RecoveryError("RESULT_STATE_INVALID") from None


class PrivateWorkspace:
    """Per-operation private directory; authfiles are removed on every exit."""

    def __enter__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="fl4sh-three-recovery-")
        self.path = Path(self._temporary.name)
        self.home = self.path / "home"
        self.runtime = self.path / "runtime"
        self.home.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        self.source_auth = self.path / "source-auth.json"
        self.dest_auth = self.path / "dest-auth.json"
        self._secure_file(self.source_auth, b'{"auths":{}}\n')
        self._secure_file(self.dest_auth, b'{"auths":{}}\n')
        for directory in (self.path, self.home, self.runtime):
            if os.name != "nt":
                os.chmod(directory, 0o700)
        return self

    @staticmethod
    def _secure_file(path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)

    def ensure_private_authfile(self, path: Path) -> None:
        try:
            if (not path.is_file() or path.is_symlink()
                    or path.resolve().parent != self.path.resolve()):
                raise ValueError
            if os.name != "nt":
                os.chmod(path, 0o600)
                mode = stat.S_IMODE(path.stat().st_mode)
                if mode & 0o077:
                    raise ValueError
        except Exception:
            raise RecoveryError("SKOPEO_LOGIN_FAILED") from None

    def write_destination_auth(self, credentials: Credentials) -> None:
        """Write Docker-compatible auth to a private file, never argv or env."""
        payload = json.dumps({
            "auths": {"docker.io": {
                "auth": base64.b64encode(
                    (credentials.username + ":" + credentials.token).encode("ascii")
                ).decode("ascii")
            }}
        }, separators=(",", ":")).encode("ascii") + b"\n"
        temporary = self.path / "dest-auth.new"
        try:
            self._secure_file(temporary, payload)
            temporary.replace(self.dest_auth)
            if os.name != "nt":
                os.chmod(self.dest_auth, 0o600)
            self.ensure_private_authfile(self.dest_auth)
        except RecoveryError:
            raise
        except Exception:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise RecoveryError("SKOPEO_LOGIN_FAILED") from None

    def __exit__(self, exc_type, exc, traceback):
        self._temporary.cleanup()


@contextlib.contextmanager
def _cleanup_interrupts():
    previous = {}

    def interrupt(_signum, _frame):
        raise RecoveryError("INTERRUPTED")

    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                previous[sig] = signal.signal(sig, interrupt)
            except (ValueError, OSError):
                pass
    try:
        yield
    finally:
        for sig, handler in previous.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, handler)


class Skopeo:
    """Subprocess adapter with fixed arguments, bounded output, and redaction."""

    def __init__(self, workspace: PrivateWorkspace):
        self.workspace = workspace

    def command(self, args: list[str], *, stdin: str | None = None,
                timeout: int = SKOPEO_COMMAND_TIMEOUT_SECONDS, code: str = "SKOPEO_INSPECT_FAILED") -> str:
        clean_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.workspace.home),
            "XDG_RUNTIME_DIR": str(self.workspace.runtime),
            "TMPDIR": str(self.workspace.path),
            "LC_ALL": "C",
            "LANG": "C",
        }
        try:
            result = subprocess.run(["skopeo", *args], input=stdin, text=True, encoding="utf-8",
                                    errors="replace", capture_output=True, check=False,
                                    timeout=timeout, env=clean_env)
        except subprocess.TimeoutExpired:
            raise RecoveryError("SKOPEO_TIMEOUT") from None
        except FileNotFoundError:
            raise RecoveryError("SKOPEO_UNAVAILABLE") from None
        except OSError:
            raise RecoveryError("SKOPEO_SPAWN_FAILED") from None
        except Exception:
            raise RecoveryError("INTERNAL_FAILURE") from None
        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        if len(stdout) > MAX_TOOL_OUTPUT or len(stderr) > MAX_TOOL_OUTPUT:
            raise RecoveryError("SKOPEO_OUTPUT_LIMIT")
        if type(result.returncode) is not int or result.returncode != 0:
            raise RecoveryError(code)
        return stdout

    def validate(self) -> None:
        version = self.command(["--version"], code="SKOPEO_VERSION_UNSUPPORTED")
        if not re.search(r"\bskopeo version 1\.4\.1(?:\s|$)", version):
            raise RecoveryError("SKOPEO_VERSION_UNSUPPORTED")
        expected = {
            ("copy", "--help"): ("--src-authfile", "--dest-authfile", "--preserve-digests", "--retry-times", "--digestfile"),
            ("inspect", "--help"): ("--config", "--authfile", "--retry-times"),
        }
        for args, flags in expected.items():
            help_text = self.command(list(args), code="SKOPEO_FEATURE_UNAVAILABLE")
            if any(flag not in help_text for flag in flags):
                raise RecoveryError("SKOPEO_FEATURE_UNAVAILABLE")

    def login(self, credentials: Credentials) -> None:
        self.workspace.write_destination_auth(credentials)

    def inspect_config(self, reference: str, authfile: Path) -> dict:
        raw = self.command(["inspect", "--authfile", str(authfile), "--retry-times", "0",
                            "--config", reference], code="SKOPEO_INSPECT_FAILED")
        if len(raw.encode("utf-8")) > MAX_CONFIG_OUTPUT:
            raise RecoveryError("SKOPEO_OUTPUT_LIMIT")
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except Exception:
            raise RecoveryError("IMAGE_IDENTITY_INVALID") from None

    def copy(self, source: str, destination: str, digestfile: Path,
             source_auth: Path, dest_auth: Path) -> str:
        allowed_destinations = {
            _tag_reference(target.repository, tag)
            for target in WRITE_TARGETS for tag in TAGS
        }
        if (source != _source_reference() or destination not in allowed_destinations
                or digestfile.resolve().parent != self.workspace.path.resolve()
                or source_auth != self.workspace.source_auth
                or dest_auth != self.workspace.dest_auth):
            raise RecoveryError("TARGET_NOT_ALLOWED")
        output = self.command(["copy", "--src-authfile", str(source_auth),
                               "--dest-authfile", str(dest_auth), "--preserve-digests",
                               "--retry-times", "0", "--digestfile", str(digestfile),
                               source, destination], timeout=SKOPEO_COPY_TIMEOUT_SECONDS,
                              code="SKOPEO_COPY_FAILED")
        del output
        try:
            digest = digestfile.read_text(encoding="ascii").strip()
        except Exception:
            raise RecoveryError("DIGEST_PRESERVATION_FAILED") from None
        if not publisher.DIGEST_RE.fullmatch(digest):
            raise RecoveryError("DIGEST_PRESERVATION_FAILED")
        return digest


def _parse_auth_challenge(value: str, repository: str) -> None:
    if (not isinstance(value, str) or len(value) > 4096
            or not value.lower().startswith("bearer ")):
        raise RecoveryError("REGISTRY_CHALLENGE_INVALID")
    text = value[len("Bearer "):]
    parts = []
    current = []
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\" and quoted:
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or escaped:
        raise RecoveryError("REGISTRY_CHALLENGE_INVALID")
    parts.append("".join(current).strip())
    attrs = {}
    for part in parts:
        match = re.fullmatch(r'([A-Za-z][A-Za-z0-9_-]*)="([^"\\]*)"', part)
        if not match or match.group(1) in attrs:
            raise RecoveryError("REGISTRY_CHALLENGE_INVALID")
        attrs[match.group(1)] = match.group(2)
    scope = attrs.get("scope", "")
    if (attrs.get("realm") != "https://auth.docker.io/token"
            or attrs.get("service") != "registry.docker.io"
            or not scope.startswith("repository:" + repository + ":")):
        raise RecoveryError("REGISTRY_CHALLENGE_INVALID")
    challenged = set(scope.rsplit(":", 1)[1].split(","))
    if not challenged or not challenged.issubset({"pull", "push"}):
        raise RecoveryError("REGISTRY_CHALLENGE_INVALID")


def _scope_actions(token: str, response: object, repository: str) -> set[str]:
    claims = None
    if isinstance(response, dict) and isinstance(response.get("access"), list):
        claims = response["access"]
    if claims is None:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError
            payload = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii"))).get("access")
        except Exception:
            raise RecoveryError("AUTH_SCOPE_UNKNOWN") from None
    if not isinstance(claims, list):
        raise RecoveryError("AUTH_SCOPE_UNKNOWN")
    actions = set()
    for item in claims:
        if (isinstance(item, dict) and item.get("type") == "repository"
                and item.get("name") == repository and isinstance(item.get("actions"), list)
                and all(isinstance(action, str) for action in item["actions"])):
            actions.update(item["actions"])
    if not actions.issubset({"pull", "push"}):
        raise RecoveryError("AUTH_SCOPE_UNKNOWN")
    return actions


class RegistryV2:
    """Bounded HTTPS GET-only Docker Hub Registry V2 reader."""

    def __init__(self, credentials: Credentials | None = None):
        self._credentials = credentials
        self._bearers: dict[tuple[str, tuple[str, ...]], str] = {}

    @staticmethod
    def _request(host: str, path: str, headers: dict[str, str]) -> HttpResult:
        if host not in {"auth.docker.io", "registry-1.docker.io"} or not path.startswith("/"):
            raise RecoveryError("REGISTRY_UNKNOWN")
        connection = None
        try:
            connection = http.client.HTTPSConnection(host, 443, timeout=20,
                                                     context=ssl.create_default_context())
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                raise RecoveryError("REGISTRY_REDIRECT_BLOCKED")
            body = response.read(MAX_REGISTRY_BODY + 1)
            if len(body) > MAX_REGISTRY_BODY:
                raise RecoveryError("REGISTRY_RESPONSE_LIMIT")
            parsed = {}
            for key, value in response.getheaders():
                key = key.lower()
                if key in parsed and key in {"www-authenticate", "docker-content-digest"}:
                    raise RecoveryError("REGISTRY_RESPONSE_INVALID")
                parsed[key] = value
            return HttpResult(response.status, parsed, body)
        except RecoveryError:
            raise
        except Exception:
            raise RecoveryError("REGISTRY_UNKNOWN") from None
        finally:
            if connection is not None:
                with contextlib.suppress(Exception):
                    connection.close()

    @staticmethod
    def _status_error(status: int, *, authenticated: bool) -> None:
        if status == 401:
            raise RecoveryError("REGISTRY_AUTH_REJECTED")
        if status == 403:
            raise RecoveryError("REGISTRY_FORBIDDEN")
        if status == 429:
            raise RecoveryError("REGISTRY_RATE_LIMITED")
        if status in {301, 302, 303, 307, 308}:
            raise RecoveryError("REGISTRY_REDIRECT_BLOCKED")
        raise RecoveryError("REGISTRY_UNKNOWN")

    def _token(self, repository: str, actions: tuple[str, ...]) -> str:
        cache_key = (repository, actions)
        if cache_key in self._bearers:
            return self._bearers[cache_key]
        scope = "repository:" + repository + ":" + ",".join(actions)
        path = "/token?" + urlencode({"service": "registry.docker.io", "scope": scope})
        headers = {"Accept": "application/json"}
        if self._credentials is not None:
            basic = base64.b64encode((self._credentials.username + ":" + self._credentials.token).encode("ascii")).decode("ascii")
            headers["Authorization"] = "Basic " + basic
        result = self._request("auth.docker.io", path, headers)
        if result.status != 200:
            if result.status == 401:
                raise RecoveryError("REGISTRY_AUTH_REJECTED")
            if result.status == 403:
                raise RecoveryError("REGISTRY_FORBIDDEN")
            if result.status == 429:
                raise RecoveryError("REGISTRY_RATE_LIMITED")
            raise RecoveryError("REGISTRY_UNKNOWN")
        try:
            body = json.loads(result.body)
            token = body.get("token", body.get("access_token"))
            if (not isinstance(token, str) or not 1 <= len(token) <= 16384
                    or any(not 33 <= ord(char) <= 126 for char in token)):
                raise ValueError
            if "token" in body and "access_token" in body and body["token"] != body["access_token"]:
                raise ValueError
        except Exception:
            raise RecoveryError("REGISTRY_RESPONSE_INVALID") from None
        granted = _scope_actions(token, body, repository)
        if not set(actions).issubset(granted):
            raise RecoveryError("AUTH_SCOPE_INSUFFICIENT")
        self._bearers[cache_key] = token
        return token

    def manifest(self, repository: str, reference: str,
                 actions: tuple[str, ...] = ("pull",)) -> ManifestState | None:
        allowed_references = ({SOURCE_DIGEST} if repository == SOURCE_REPOSITORY else set(TAGS))
        if (repository not in {target.repository for target in READ_TARGETS}
                or reference not in allowed_references
                or tuple(actions) not in {("pull",), ("pull", "push")}):
            raise RecoveryError("ARGUMENT_INVALID")
        path = "/v2/" + repository + "/manifests/" + reference
        headers = {"Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"}
        first = self._request("registry-1.docker.io", path, headers)
        authenticated = False
        if first.status == 401:
            _parse_auth_challenge(first.headers.get("www-authenticate", ""), repository)
            bearer = self._token(repository, actions)
            headers["Authorization"] = "Bearer " + bearer
            response = self._request("registry-1.docker.io", path, headers)
            authenticated = True
        elif first.status in {200, 404} and self._credentials is not None:
            # A public 404 is not evidence of absence until the requested
            # account scope has been granted and the exact tag is rechecked.
            bearer = self._token(repository, actions)
            headers["Authorization"] = "Bearer " + bearer
            response = self._request("registry-1.docker.io", path, headers)
            authenticated = True
        elif first.status == 200:
            response = first
        else:
            # A bare 404 may conceal an authorization failure; it is not absence evidence.
            if first.status == 401:
                raise RecoveryError("REGISTRY_CHALLENGE_INVALID")
            self._status_error(first.status, authenticated=False)
        if response.status == 404:
            if not authenticated or response.headers.get("docker-content-digest"):
                raise RecoveryError("REGISTRY_RESPONSE_INVALID")
            return None
        if response.status != 200:
            self._status_error(response.status, authenticated=authenticated)
        digest = response.headers.get("docker-content-digest", "")
        try:
            parsed = publisher.parse_manifest(response.body, digest)
        except publisher.Rejected:
            raise RecoveryError("REGISTRY_RESPONSE_INVALID") from None
        try:
            layer_count = len(json.loads(response.body)["layers"])
        except Exception:
            raise RecoveryError("REGISTRY_RESPONSE_INVALID") from None
        return ManifestState(parsed.digest, parsed.config, parsed.content_hash, layer_count)


def _config_identity(config: object) -> dict:
    try:
        if not isinstance(config, dict):
            raise ValueError
        labels = config["config"]["Labels"]
        rootfs = config["rootfs"]
        diff_ids = rootfs["diff_ids"]
        if (config["os"] != "linux" or config["architecture"] != "amd64"
                or labels["org.opencontainers.image.revision"] != SOURCE_REVISION
                or labels["org.opencontainers.image.source"] != SOURCE_URL
                or labels["org.opencontainers.image.version"] != VERSION
                or rootfs["type"] != "layers" or not isinstance(diff_ids, list)
                or not diff_ids or any(not isinstance(value, str) or not publisher.DIGEST_RE.fullmatch(value) for value in diff_ids)):
            raise ValueError
        return {"architecture": "amd64", "os": "linux", "revision": SOURCE_REVISION,
                "source": SOURCE_URL, "version": VERSION, "diff_ids": list(diff_ids)}
    except Exception:
        raise RecoveryError("IMAGE_IDENTITY_INVALID") from None


def _source_reference() -> str:
    return "docker://docker.io/" + SOURCE_REPOSITORY + "@" + SOURCE_DIGEST


def _tag_reference(repository: str, tag: str) -> str:
    if repository not in {target.repository for target in WRITE_TARGETS}:
        raise RecoveryError("TARGET_NOT_ALLOWED")
    if tag not in TAGS:
        raise RecoveryError("ARGUMENT_INVALID")
    return "docker://docker.io/" + repository + ":" + tag


def _digest_reference(repository: str, digest: str) -> str:
    if not publisher.DIGEST_RE.fullmatch(digest):
        raise RecoveryError("ARGUMENT_INVALID")
    return "docker://docker.io/" + repository + "@" + digest


class RecoveryController:
    def __init__(self, *, registry_factory=RegistryV2, skopeo_factory=Skopeo,
                 workspace_factory=PrivateWorkspace):
        self.registry_factory = registry_factory
        self.skopeo_factory = skopeo_factory
        self.workspace_factory = workspace_factory

    def _verify_source(self, registry: RegistryV2, skopeo: Skopeo, workspace: PrivateWorkspace):
        manifest = registry.manifest(SOURCE_REPOSITORY, SOURCE_DIGEST, ("pull",))
        if (manifest is None or manifest.digest != SOURCE_DIGEST
                or manifest.config != SOURCE_CONFIG_DIGEST):
            raise RecoveryError("SOURCE_IDENTITY_INVALID")
        config = skopeo.inspect_config(_source_reference(), workspace.source_auth)
        identity = _config_identity(config)
        if len(identity["diff_ids"]) != manifest.layer_count:
            raise RecoveryError("IMAGE_IDENTITY_INVALID")
        return manifest, identity

    def _verify_remote_tag(self, registry: RegistryV2, skopeo: Skopeo,
                           repository: str, tag: str, source_manifest: ManifestState,
                           source_identity: dict, authfile: Path,
                           actions: tuple[str, ...]) -> str:
        manifest = registry.manifest(repository, tag, actions)
        if manifest is None:
            return "ABSENT_HTTP404"
        if manifest.digest != SOURCE_DIGEST or manifest != source_manifest:
            return "CONFLICT"
        config = skopeo.inspect_config(_digest_reference(repository, manifest.digest), authfile)
        if _config_identity(config) != source_identity:
            raise RecoveryError("IMAGE_IDENTITY_INVALID")
        return "ALREADY_PRESENT"

    @staticmethod
    def _require_protected_snapshot(results: dict) -> None:
        verification = results["verification"]
        for target_id in PROTECTED_TARGET_IDS:
            row = verification.get(target_id)
            if (not isinstance(row, dict) or row.get("status") != "VERIFIED"
                    or set(row.get("tags", {})) != set(TAGS)
                    or any(row["tags"].get(tag) != {
                        "status": "VERIFIED", "digest": SOURCE_DIGEST,
                    } for tag in TAGS)):
                raise RecoveryError("PROTECTED_TARGETS_UNVERIFIED")

    def _verify_protected_targets(self, registry: RegistryV2, skopeo: Skopeo,
                                  workspace: PrivateWorkspace, source_manifest: ManifestState,
                                  source_identity: dict) -> None:
        for target_id in PROTECTED_TARGET_IDS:
            target = READ_BY_ID[target_id]
            for tag in TAGS:
                state = self._verify_remote_tag(
                    registry, skopeo, target.repository, tag, source_manifest,
                    source_identity, workspace.source_auth, ("pull",),
                )
                if state != "ALREADY_PRESENT":
                    raise RecoveryError("PROTECTED_TARGET_DRIFT")

    def preflight(self, target_id: str, results_path: Path,
                  username: object, token: object) -> dict:
        target = _target(target_id, write_only=True)
        credentials = _validate_credentials(target, username, token)
        results = _read_results(results_path)
        if target_id in results["preflight"]:
            raise RecoveryError("RESULT_STATE_INVALID")
        try:
            with self.workspace_factory() as workspace:
                skopeo = self.skopeo_factory(workspace)
                skopeo.validate()
                skopeo.login(credentials)
                source_registry = self.registry_factory()
                source_manifest, source_identity = self._verify_source(source_registry, skopeo, workspace)
                target_registry = self.registry_factory(credentials)
                tag_states = {}
                for tag in TAGS:
                    state = self._verify_remote_tag(target_registry, skopeo, target.repository, tag,
                                                    source_manifest, source_identity, workspace.dest_auth,
                                                    ("pull", "push"))
                    if state == "CONFLICT":
                        raise RecoveryError("TAG_CONFLICT")
                    tag_states[tag] = {"status": state, "digest": SOURCE_DIGEST if state == "ALREADY_PRESENT" else None}
                results["preflight"][target_id] = {"status": "PREFLIGHT_READY", "failure_code": None,
                                                   "tags": tag_states}
                _write_results(results_path, results)
                return {"target": target_id, "status": "PREFLIGHT_READY", "tags": tag_states}
        except RecoveryError as error:
            results["preflight"][target_id] = {"status": "BLOCKED", "failure_code": error.code,
                                               "tags": {}}
            _write_results(results_path, results)
            raise
        except Exception:
            results["preflight"][target_id] = {"status": "BLOCKED", "failure_code": "INTERNAL_FAILURE",
                                               "tags": {}}
            _write_results(results_path, results)
            raise RecoveryError("INTERNAL_FAILURE") from None

    def recover(self, target_id: str, results_path: Path,
                username: object, token: object) -> dict:
        target = _target(target_id, write_only=True)
        credentials = _validate_credentials(target, username, token)
        results = _read_results(results_path)
        target_index = TARGET_IDS.index(target_id)
        for previous_id in TARGET_IDS[:target_index]:
            if results["targets"][previous_id]["status"] not in {"TARGET_VERIFIED", "ALREADY_PRESENT"}:
                raise RecoveryError("RECOVERY_SEQUENCE_BLOCKED")
        if set(results["preflight"]) != set(TARGET_IDS) or any(
                results["preflight"][key]["status"] != "PREFLIGHT_READY" for key in TARGET_IDS):
            raise RecoveryError("PREFLIGHT_INCOMPLETE")
        self._require_protected_snapshot(results)
        target_row = results["targets"][target_id]
        if target_row["attempted"]:
            raise RecoveryError("RUN_ALREADY_ATTEMPTED")
        try:
            with self.workspace_factory() as workspace:
                skopeo = self.skopeo_factory(workspace)
                skopeo.validate()
                skopeo.login(credentials)
                source_registry = self.registry_factory()
                source_manifest, source_identity = self._verify_source(source_registry, skopeo, workspace)
                self._verify_protected_targets(source_registry, skopeo, workspace,
                                               source_manifest, source_identity)
                target_registry = self.registry_factory(credentials)

                # Recheck every tag in this repository immediately before writes.
                current = {}
                for tag in TAGS:
                    current[tag] = self._verify_remote_tag(target_registry, skopeo, target.repository, tag,
                                                            source_manifest, source_identity, workspace.dest_auth,
                                                            ("pull", "push"))
                    if current[tag] == "CONFLICT":
                        raise RecoveryError("TAG_CONFLICT")
                if all(state == "ALREADY_PRESENT" for state in current.values()):
                    for tag in TAGS:
                        target_row["tags"][tag] = {"status": "ALREADY_PRESENT", "digest": SOURCE_DIGEST,
                                                   "failure_code": None}
                    target_row["status"] = "ALREADY_PRESENT"
                    _write_results(results_path, results)
                    return {"target": target_id, "status": "ALREADY_PRESENT", "writes": 0}

                target_row["attempted"] = True
                target_row["status"] = "COPY_IN_PROGRESS"
                _write_results(results_path, results)
                for index, tag in enumerate(TAGS):
                    if current[tag] == "ALREADY_PRESENT":
                        target_row["tags"][tag] = {"status": "ALREADY_PRESENT", "digest": SOURCE_DIGEST,
                                                   "failure_code": None}
                        _write_results(results_path, results)
                        continue
                    # Last read before each tag write catches detected competitors.
                    latest = target_registry.manifest(target.repository, tag, ("pull", "push"))
                    if latest is not None:
                        if latest != source_manifest:
                            target_row["tags"][tag] = {"status": "CONFLICT", "digest": None,
                                                       "failure_code": "TAG_CONFLICT"}
                            target_row["failure_code"] = "TAG_CONFLICT"
                            target_row["status"] = (
                                "PARTIAL_PUBLICATION"
                                if any(value["status"] == "PUBLISHED_VERIFIED"
                                       for value in target_row["tags"].values())
                                else "BLOCKED"
                            )
                            _write_results(results_path, results)
                            raise RecoveryError("TAG_CONFLICT")
                        target_row["tags"][tag] = {"status": "ALREADY_PRESENT", "digest": SOURCE_DIGEST,
                                                   "failure_code": None}
                        _write_results(results_path, results)
                        continue
                    target_row["tags"][tag] = {"status": "COPY_IN_PROGRESS", "digest": None,
                                               "failure_code": None}
                    _write_results(results_path, results)
                    digestfile = workspace.path / ("copy-" + str(index) + ".digest")
                    try:
                        copied_digest = skopeo.copy(_source_reference(),
                                                    _tag_reference(target.repository, tag), digestfile,
                                                    workspace.source_auth, workspace.dest_auth)
                        if copied_digest != SOURCE_DIGEST:
                            raise RecoveryError("DIGEST_PRESERVATION_FAILED")
                        final_state = self._verify_remote_tag(target_registry, skopeo, target.repository, tag,
                                                              source_manifest, source_identity, workspace.dest_auth,
                                                              ("pull", "push"))
                        if final_state != "ALREADY_PRESENT":
                            raise RecoveryError("DIGEST_PRESERVATION_FAILED")
                        target_row["tags"][tag] = {"status": "PUBLISHED_VERIFIED", "digest": SOURCE_DIGEST,
                                                   "failure_code": None}
                        _write_results(results_path, results)
                    except RecoveryError as error:
                        # A failed copy can have an ambiguous remote outcome.
                        target_row["tags"][tag] = {"status": "UNKNOWN", "digest": None,
                                                   "failure_code": error.code}
                        target_row["failure_code"] = error.code
                        target_row["status"] = "PARTIAL_PUBLICATION"
                        _write_results(results_path, results)
                        raise
                target_row["status"] = "TARGET_VERIFIED"
                _write_results(results_path, results)
                return {"target": target_id, "status": "TARGET_VERIFIED",
                        "writes": sum(1 for row in target_row["tags"].values() if row["status"] == "PUBLISHED_VERIFIED")}
        except RecoveryError as error:
            if target_row["status"] not in {"PARTIAL_PUBLICATION", "BLOCKED"}:
                target_row["status"] = "BLOCKED" if not target_row["attempted"] else "UNKNOWN"
                target_row["failure_code"] = error.code
            _write_results(results_path, results)
            raise
        except Exception:
            target_row["status"] = "UNKNOWN" if target_row["attempted"] else "BLOCKED"
            target_row["failure_code"] = "INTERNAL_FAILURE"
            _write_results(results_path, results)
            raise RecoveryError("INTERNAL_FAILURE") from None

    def verify_target(self, target_id: str, results_path: Path,
                      username: object | None = None, token: object | None = None) -> dict:
        target = _target(target_id)
        credentials = None
        if username is not None or token is not None:
            credentials = _validate_credentials(target, username, token)
        results = _read_results(results_path)
        tag_states = {}
        status = "VERIFIED"
        failure_code = None
        try:
            with self.workspace_factory() as workspace:
                skopeo = self.skopeo_factory(workspace)
                skopeo.validate()
                if credentials is not None:
                    skopeo.login(credentials)
                source_manifest, source_identity = self._verify_source(self.registry_factory(), skopeo, workspace)
                registry = self.registry_factory(credentials)
                tag_states = {}
                for tag in TAGS:
                    state = self._verify_remote_tag(registry, skopeo, target.repository, tag, source_manifest,
                                                    source_identity, workspace.dest_auth if credentials else workspace.source_auth,
                                                    ("pull",))
                    if state == "ALREADY_PRESENT":
                        tag_states[tag] = {"status": "VERIFIED", "digest": SOURCE_DIGEST}
                    elif state == "ABSENT_HTTP404":
                        tag_states[tag] = {"status": "ABSENT_HTTP404", "digest": None}
                        if status != "BLOCKED":
                            status = "UNKNOWN"
                    else:
                        tag_states[tag] = {"status": "CONFLICT", "digest": None}
                        status = "BLOCKED"
                        failure_code = "TAG_CONFLICT"
                results["verification"][target_id] = {"status": status, "failure_code": failure_code,
                                                       "tags": tag_states}
                _write_results(results_path, results)
                return {"target": target_id, "status": status, "failure_code": failure_code,
                        "tags": tag_states}
        except RecoveryError as error:
            conflict_seen = error.code == "TAG_CONFLICT" or any(
                row.get("status") == "CONFLICT" for row in tag_states.values())
            results["verification"][target_id] = {
                "status": "BLOCKED" if conflict_seen else "UNKNOWN",
                "failure_code": "TAG_CONFLICT" if conflict_seen else error.code,
                "tags": tag_states,
            }
            _write_results(results_path, results)
            raise
        except Exception:
            results["verification"][target_id] = {"status": "UNKNOWN", "failure_code": "INTERNAL_FAILURE",
                                                   "tags": tag_states}
            _write_results(results_path, results)
            raise RecoveryError("INTERNAL_FAILURE") from None


def _summary(results: dict) -> dict:
    all_verified = set(results["verification"]) == set(ALL_TARGET_IDS)
    if all_verified:
        for target_id in ALL_TARGET_IDS:
            row = results["verification"][target_id]
            if row["status"] != "VERIFIED" or set(row["tags"]) != set(TAGS):
                all_verified = False
                break
            if any(row["tags"][tag] != {"status": "VERIFIED", "digest": SOURCE_DIGEST} for tag in TAGS):
                all_verified = False
                break
    if all_verified:
        status = "6_OF_6_VERIFIED"
    elif any(row["status"] == "PARTIAL_PUBLICATION" for row in results["targets"].values()):
        status = "PARTIAL_PUBLICATION"
    elif any(row.get("status") == "BLOCKED" for row in results["preflight"].values()):
        status = "BLOCKED"
    elif any(row.get("status") == "BLOCKED" for row in results["targets"].values()):
        status = "BLOCKED"
    elif any(row.get("status") == "BLOCKED" for row in results["verification"].values()):
        status = "BLOCKED"
    elif any(row.get("status") == "ABSENT_HTTP404"
             for verification in results["verification"].values()
             for row in verification.get("tags", {}).values()):
        status = "PARTIAL_PUBLICATION"
    else:
        status = "BLOCKED"
    return {"status": status, "published_targets": sum(
        1 for target_id in ALL_TARGET_IDS
        if results["verification"].get(target_id, {}).get("status") == "VERIFIED"),
        "required_targets": 6, "source_digest": SOURCE_DIGEST,
        "source_revision": SOURCE_REVISION, "tag_names": list(TAGS)}


def _emit(data: dict) -> None:
    # Callers construct only fixed codes, public target ids, and fixed digests.
    print(json.dumps(data, sort_keys=True, separators=(",", ":")))


def _workflow_context(confirmation: str | None = None) -> None:
    if confirmation is not None and confirmation != CONFIRMATION:
        raise RecoveryError("DISPATCH_NOT_AUTHORIZED")
    if (os.name != "posix"
            or os.environ.get("GITHUB_REPOSITORY") != "ad-fiverr/krig-salad"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"):
        raise RecoveryError("DISPATCH_NOT_AUTHORIZED")
    if (os.environ.get("GITHUB_RUN_ATTEMPT", "1") != "1"
            or os.environ.get("GITHUB_RUN_NUMBER") != "1"):
        raise RecoveryError("RERUN_NOT_ALLOWED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--results", required=True, type=Path)
    init_parser.add_argument("--confirmation", required=True)
    preflight_parser = subparsers.add_parser("preflight")
    preflight_parser.add_argument("--target", required=True, choices=TARGET_IDS)
    preflight_parser.add_argument("--results", required=True, type=Path)
    recover_parser = subparsers.add_parser("recover")
    recover_parser.add_argument("--target", required=True, choices=TARGET_IDS)
    recover_parser.add_argument("--results", required=True, type=Path)
    verify_parser = subparsers.add_parser("verify-target")
    verify_parser.add_argument("--target", required=True, choices=ALL_TARGET_IDS)
    verify_parser.add_argument("--results", required=True, type=Path)
    summary_parser = subparsers.add_parser("summarize")
    summary_parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args(argv)
    controller = RecoveryController()
    try:
        if args.command == "init":
            _workflow_context(args.confirmation)
            if args.results.exists():
                raise RecoveryError("RESULT_FILE_EXISTS")
            data = _new_results(os.environ.get("GITHUB_RUN_ID", "offline-run"),
                                os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
            _write_results(args.results, data)
            _emit({"status": "READY", "run_id": data["run_id"]})
            return 0
        _workflow_context()
        if args.command in {"preflight", "recover"}:
            target = _target(args.target, write_only=True)
            username = os.environ.get("RECOVERY_USERNAME")
            token = os.environ.get("RECOVERY_TOKEN")
            if args.command == "preflight":
                _emit(controller.preflight(args.target, args.results, username, token))
            else:
                _emit(controller.recover(args.target, args.results, username, token))
            return 0
        if args.command == "verify-target":
            result = controller.verify_target(args.target, args.results,
                                              os.environ.get("RECOVERY_USERNAME"),
                                              os.environ.get("RECOVERY_TOKEN"))
            _emit(result)
            return 0 if result["status"] == "VERIFIED" else 1
        if args.command == "summarize":
            result = _summary(_read_results(args.results))
            _emit(result)
            return 0 if result["status"] == "6_OF_6_VERIFIED" else 1
        raise RecoveryError("ARGUMENT_INVALID")
    except RecoveryError as error:
        _emit({"status": "BLOCKED", "failure_code": error.code})
        return 1
    except Exception:
        _emit({"status": "BLOCKED", "failure_code": "INTERNAL_FAILURE"})
        return 1


if __name__ == "__main__":
    with _cleanup_interrupts():
        raise SystemExit(main())
