#!/usr/bin/env python3
"""One-shot, fixed-scope Docker CLI recovery for Fl4shMiner targets 4-6.

The command never builds an image. It pulls one immutable source digest,
validates its local OCI identity, then tags and pushes only the three approved
destination repositories.
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
DOCKER_COMMAND_TIMEOUT_SECONDS = 60
DOCKER_TRANSFER_TIMEOUT_SECONDS = 4 * 60 * 60
MAX_REGISTRY_BODY = 1_000_000
MAX_CONFIG_OUTPUT = 2_000_000
MAX_TOOL_OUTPUT = 1_000_000
RESULT_SCHEMA_VERSION = 2
DOCKER_PHASES = frozenset({"DOCKER_PULL", "DOCKER_INSPECT", "DOCKER_LOGIN",
                           "DOCKER_TAG", "DOCKER_PUSH", "DOCKER_LOGOUT"})
COMMAND_FAILURE_CLASSES = frozenset({"NONZERO_EXIT", "TIMEOUT", "SPAWN_ERROR",
                                     "OUTPUT_LIMIT", "UNKNOWN"})


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
    "DOCKER_UNAVAILABLE", "DOCKER_PULL_FAILED", "DOCKER_INSPECT_FAILED",
    "DOCKER_LOGIN_FAILED", "DOCKER_TAG_FAILED", "DOCKER_PUSH_FAILED",
    "DOCKER_LOGOUT_FAILED", "DOCKER_TIMEOUT", "DOCKER_OUTPUT_LIMIT",
    "DOCKER_SPAWN_FAILED", "DOCKER_COMMAND_UNKNOWN",
    "RUN_ALREADY_ATTEMPTED", "INTERRUPTED",
    "PROTECTED_TARGETS_UNVERIFIED", "PROTECTED_TARGET_DRIFT", "RECOVERY_SEQUENCE_BLOCKED",
    "INTERNAL_FAILURE",
})


class RecoveryError(Exception):
    """Fixed, sanitized diagnostics only; raw subprocess data is discarded."""

    def __init__(self, code: str, *, phase: str | None = None,
                 failure_class: str | None = None, secondary_failure_code: str | None = None):
        self.code = code if code in SAFE_FAILURE_CODES else "INTERNAL_FAILURE"
        self.phase = phase if phase in DOCKER_PHASES else None
        self.failure_class = failure_class if failure_class in COMMAND_FAILURE_CLASSES else None
        self.secondary_failure_code = (secondary_failure_code
                                       if secondary_failure_code in SAFE_FAILURE_CODES else None)
        super().__init__(self.code)


def _failure_fields(error: RecoveryError) -> dict:
    return {"failure_code": error.code, "failure_phase": error.phase,
            "failure_class": error.failure_class}


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
                        "failure_code": None, "failure_phase": None,
                        "failure_class": None, "logout_failure_code": None,
                        "tags": {tag: {"status": "PENDING", "digest": None,
                                       "failure_code": None, "failure_phase": None,
                                       "failure_class": None} for tag in TAGS}}
            for target_id in TARGET_IDS
        },
        "verification": {},
    }


def _valid_failure_details(row: dict) -> bool:
    phase, failure_class = row.get("failure_phase"), row.get("failure_class")
    return ((phase is None and failure_class is None)
            or (phase in DOCKER_PHASES and failure_class in COMMAND_FAILURE_CLASSES))


def _valid_digest_or_none(value: object) -> bool:
    return value is None or (isinstance(value, str) and publisher.DIGEST_RE.fullmatch(value) is not None)


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
        if (not isinstance(row, dict) or set(row) != {
                    "status", "failure_code", "failure_phase", "failure_class", "tags"}
                or row.get("status") not in PREFLIGHT_STATES
                or row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)
                or not _valid_failure_details(row)
                or not isinstance(row.get("tags"), dict)
                or not set(row["tags"]).issubset(TAGS)):
            raise RecoveryError("RESULT_STATE_INVALID")
    for target_id, row in targets.items():
        if (not isinstance(row, dict) or set(row) != {
                    "status", "attempted", "failure_code", "failure_phase", "failure_class",
                    "logout_failure_code", "tags"}
                or row.get("status") not in TARGET_STATES or type(row.get("attempted")) is not bool
                or row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)
                or row.get("logout_failure_code") not in (None, "DOCKER_LOGOUT_FAILED")
                or not _valid_failure_details(row)
                or not isinstance(row.get("tags"), dict) or set(row["tags"]) != set(TAGS)):
            raise RecoveryError("RESULT_STATE_INVALID")
        for tag_row in row["tags"].values():
            if (not isinstance(tag_row, dict) or set(tag_row) != {
                        "status", "digest", "failure_code", "failure_phase", "failure_class"}
                    or tag_row.get("status") not in TAG_STATES
                    or not _valid_digest_or_none(tag_row.get("digest"))
                    or tag_row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)
                    or not _valid_failure_details(tag_row)):
                raise RecoveryError("RESULT_STATE_INVALID")
    for target_id, row in verification.items():
        if (not isinstance(row, dict) or set(row) != {
                    "status", "failure_code", "failure_phase", "failure_class", "tags"}
                or row.get("status") not in {"VERIFIED", "BLOCKED", "UNKNOWN"}
                or row.get("failure_code") not in (None, *SAFE_FAILURE_CODES)
                or not _valid_failure_details(row)
                or not isinstance(row.get("tags"), dict)
                or not set(row["tags"]).issubset(TAGS)):
            raise RecoveryError("RESULT_STATE_INVALID")
        for tag_row in row["tags"].values():
            if (not isinstance(tag_row, dict) or set(tag_row) != {"status", "digest"}
                    or tag_row.get("status") not in {"VERIFIED", "ABSENT_HTTP404", "CONFLICT", "UNKNOWN"}
                    or not _valid_digest_or_none(tag_row.get("digest"))):
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
    """Per-operation private Docker config roots removed on every exit."""

    def __enter__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="fl4sh-three-recovery-")
        self.path = Path(self._temporary.name)
        self.home = self.path / "home"
        self.runtime = self.path / "runtime"
        self.home.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        self.source_config = self.path / "source-docker-config"
        self.source_config.mkdir(mode=0o700)
        self._destination_configs = {}
        for directory in (self.path, self.home, self.runtime, self.source_config):
            if os.name != "nt":
                os.chmod(directory, 0o700)
        return self

    def destination_config(self, target_id: str) -> Path:
        _target(target_id, write_only=True)
        if target_id not in self._destination_configs:
            config_path = self.path / ("docker-config-" + target_id)
            try:
                config_path.mkdir(mode=0o700)
                if os.name != "nt":
                    os.chmod(config_path, 0o700)
                    if stat.S_IMODE(config_path.stat().st_mode) & 0o077:
                        raise OSError
                self._destination_configs[target_id] = config_path
            except Exception:
                raise RecoveryError("DOCKER_LOGIN_FAILED", phase="DOCKER_LOGIN",
                                    failure_class="UNKNOWN") from None
        return self._destination_configs[target_id]

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


class DockerCLI:
    """Fixed-scope Docker CLI adapter; secrets travel only on login stdin."""

    _PHASE_CODES = {
        "DOCKER_PULL": "DOCKER_PULL_FAILED", "DOCKER_INSPECT": "DOCKER_INSPECT_FAILED",
        "DOCKER_LOGIN": "DOCKER_LOGIN_FAILED", "DOCKER_TAG": "DOCKER_TAG_FAILED",
        "DOCKER_PUSH": "DOCKER_PUSH_FAILED", "DOCKER_LOGOUT": "DOCKER_LOGOUT_FAILED",
    }

    def __init__(self, workspace: PrivateWorkspace, config: Path | None = None):
        self.workspace = workspace
        self.config = config or workspace.source_config
        if self.config.resolve().parent != workspace.path.resolve():
            raise RecoveryError("TARGET_NOT_ALLOWED")

    def command(self, args: list[str], *, phase: str, stdin: str | None = None,
                timeout: int = DOCKER_COMMAND_TIMEOUT_SECONDS) -> str:
        code = self._PHASE_CODES.get(phase)
        if code is None or not isinstance(args, list) or not args or args[0] != "docker":
            raise RecoveryError("TARGET_NOT_ALLOWED")
        allowed_environment = ("PATH", "HOME", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP")
        clean_env = {key: os.environ[key] for key in allowed_environment if key in os.environ}
        clean_env.update({"DOCKER_CONFIG": str(self.config), "LC_ALL": "C", "LANG": "C"})

        def reject(failure_class: str, *, code_override: str | None = None) -> None:
            raise RecoveryError(code_override or code, phase=phase,
                                failure_class=failure_class) from None

        try:
            result = subprocess.run(args, input=stdin, text=True, encoding="utf-8",
                                    errors="replace", capture_output=True, check=False,
                                    timeout=timeout, env=clean_env)
        except subprocess.TimeoutExpired:
            reject("TIMEOUT")
        except FileNotFoundError:
            reject("SPAWN_ERROR", code_override="DOCKER_UNAVAILABLE")
        except OSError:
            reject("SPAWN_ERROR")
        except Exception:
            reject("UNKNOWN", code_override="DOCKER_COMMAND_UNKNOWN")
        try:
            stdout = result.stdout if result.stdout is not None else ""
            stderr = result.stderr if result.stderr is not None else ""
            returncode = result.returncode
            if not isinstance(stdout, (str, bytes)) or not isinstance(stderr, (str, bytes)) or type(returncode) is not int:
                reject("UNKNOWN", code_override="DOCKER_COMMAND_UNKNOWN")
            stdout_size = len(stdout.encode("utf-8")) if isinstance(stdout, str) else len(stdout)
            stderr_size = len(stderr.encode("utf-8")) if isinstance(stderr, str) else len(stderr)
        except RecoveryError:
            raise
        except Exception:
            reject("UNKNOWN", code_override="DOCKER_COMMAND_UNKNOWN")
        if stdout_size > MAX_TOOL_OUTPUT or stderr_size > MAX_TOOL_OUTPUT:
            reject("OUTPUT_LIMIT", code_override="DOCKER_OUTPUT_LIMIT")
        if returncode != 0:
            reject("NONZERO_EXIT")
        return stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else stdout

    def pull_source(self, reference: str) -> None:
        if reference != _source_reference():
            raise RecoveryError("SOURCE_IDENTITY_INVALID")
        self.command(["docker", "pull", "--platform", "linux/amd64", "--quiet", reference],
                     phase="DOCKER_PULL", timeout=DOCKER_TRANSFER_TIMEOUT_SECONDS)

    def inspect_source(self, reference: str) -> dict:
        if reference != _source_reference():
            raise RecoveryError("SOURCE_IDENTITY_INVALID")
        raw = self.command(["docker", "image", "inspect", "--format", "{{json .}}", reference],
                           phase="DOCKER_INSPECT")
        if len(raw.encode("utf-8")) > MAX_CONFIG_OUTPUT:
            raise RecoveryError("DOCKER_OUTPUT_LIMIT", phase="DOCKER_INSPECT",
                                failure_class="OUTPUT_LIMIT")
        try:
            image = json.loads(raw)
            if not isinstance(image, dict):
                raise ValueError
            return image
        except Exception:
            raise RecoveryError("IMAGE_IDENTITY_INVALID") from None

    def login(self, credentials: Credentials) -> None:
        self.command(["docker", "login", "docker.io", "--username", credentials.username,
                      "--password-stdin"], phase="DOCKER_LOGIN", stdin=credentials.token + "\n")

    def logout(self) -> None:
        self.command(["docker", "logout", "docker.io"], phase="DOCKER_LOGOUT")

    def tag(self, image_id: str, destination: str) -> None:
        allowed = {_tag_reference(target.repository, tag)
                   for target in WRITE_TARGETS for tag in TAGS}
        if image_id != SOURCE_CONFIG_DIGEST or destination not in allowed:
            raise RecoveryError("TARGET_NOT_ALLOWED")
        self.command(["docker", "tag", image_id, destination], phase="DOCKER_TAG")

    def push(self, destination: str) -> None:
        allowed = {_tag_reference(target.repository, tag)
                   for target in WRITE_TARGETS for tag in TAGS}
        if destination not in allowed:
            raise RecoveryError("TARGET_NOT_ALLOWED")
        self.command(["docker", "push", "--quiet", destination], phase="DOCKER_PUSH",
                     timeout=DOCKER_TRANSFER_TIMEOUT_SECONDS)


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
        allowed_references = (
            {SOURCE_DIGEST, *TAGS}
            if repository == SOURCE_REPOSITORY
            else set(TAGS)
        )
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


def _docker_image_identity(image: object) -> dict:
    """Validate Docker's local image-inspect record against the pinned OCI image."""
    try:
        if not isinstance(image, dict):
            raise ValueError
        labels = image["Config"]["Labels"]
        rootfs = image["RootFS"]
        diff_ids = rootfs["Layers"]
        image_id = image["Id"]
        if (image_id != SOURCE_CONFIG_DIGEST or image["Os"] != "linux"
                or image["Architecture"] != "amd64"
                or labels["org.opencontainers.image.revision"] != SOURCE_REVISION
                or labels["org.opencontainers.image.source"] != SOURCE_URL
                or labels["org.opencontainers.image.version"] != VERSION
                or rootfs["Type"] != "layers" or not isinstance(diff_ids, list)
                or not diff_ids or any(not isinstance(value, str)
                                       or not publisher.DIGEST_RE.fullmatch(value)
                                       for value in diff_ids)):
            raise ValueError
        repo_digests = image.get("RepoDigests")
        expected_repo_digests = {
            SOURCE_REPOSITORY + "@" + SOURCE_DIGEST,
            "docker.io/" + SOURCE_REPOSITORY + "@" + SOURCE_DIGEST,
        }
        if not isinstance(repo_digests, list) or not expected_repo_digests.intersection(repo_digests):
            raise ValueError
        return {"architecture": "amd64", "os": "linux", "revision": SOURCE_REVISION,
                "source": SOURCE_URL, "version": VERSION, "diff_ids": list(diff_ids),
                "config_digest": image_id}
    except Exception:
        raise RecoveryError("IMAGE_IDENTITY_INVALID") from None


def _same_image_content(observed: ManifestState, expected: ManifestState) -> bool:
    """Accept a registry manifest re-encoding only when config and layers match."""
    return (observed.config == expected.config
            and observed.content_hash == expected.content_hash
            and observed.layer_count == expected.layer_count)


def _source_reference() -> str:
    return "docker.io/" + SOURCE_REPOSITORY + "@" + SOURCE_DIGEST


def _tag_reference(repository: str, tag: str) -> str:
    if repository not in {target.repository for target in WRITE_TARGETS}:
        raise RecoveryError("TARGET_NOT_ALLOWED")
    if tag not in TAGS:
        raise RecoveryError("ARGUMENT_INVALID")
    return "docker.io/" + repository + ":" + tag


class RecoveryController:
    def __init__(self, *, registry_factory=RegistryV2, docker_factory=DockerCLI,
                 workspace_factory=PrivateWorkspace):
        self.registry_factory = registry_factory
        self.docker_factory = docker_factory
        self.workspace_factory = workspace_factory

    def _verify_source(self, registry: RegistryV2, docker: DockerCLI):
        manifest = registry.manifest(SOURCE_REPOSITORY, SOURCE_DIGEST, ("pull",))
        if (manifest is None or manifest.digest != SOURCE_DIGEST
                or manifest.config != SOURCE_CONFIG_DIGEST):
            raise RecoveryError("SOURCE_IDENTITY_INVALID")
        image = docker.inspect_source(_source_reference())
        identity = _docker_image_identity(image)
        if identity["config_digest"] != manifest.config:
            raise RecoveryError("SOURCE_IDENTITY_INVALID")
        if len(identity["diff_ids"]) != manifest.layer_count:
            raise RecoveryError("IMAGE_IDENTITY_INVALID")
        return manifest, identity

    def _verify_remote_tag(self, registry: RegistryV2, repository: str, tag: str,
                           source_manifest: ManifestState,
                           actions: tuple[str, ...], *,
                           require_exact_source_digest: bool = False
                           ) -> tuple[str, ManifestState | None]:
        manifest = registry.manifest(repository, tag, actions)
        if manifest is None:
            return "ABSENT_HTTP404", None
        digest_matches = not require_exact_source_digest or manifest.digest == SOURCE_DIGEST
        state = ("ALREADY_PRESENT" if digest_matches
                 and _same_image_content(manifest, source_manifest) else "CONFLICT")
        return state, manifest

    @staticmethod
    def _require_protected_snapshot(results: dict) -> None:
        verification = results["verification"]
        for target_id in PROTECTED_TARGET_IDS:
            row = verification.get(target_id)
            if (not isinstance(row, dict) or row.get("status") != "VERIFIED"
                    or set(row.get("tags", {})) != set(TAGS)
                    or any(not isinstance(row["tags"].get(tag), dict)
                           or row["tags"][tag].get("status") != "VERIFIED"
                                   or row["tags"][tag].get("digest") != SOURCE_DIGEST
                                   or not publisher.DIGEST_RE.fullmatch(
                                       str(row["tags"][tag].get("digest", ""))) for tag in TAGS)):
                raise RecoveryError("PROTECTED_TARGETS_UNVERIFIED")

    def _verify_protected_targets(self, registry: RegistryV2,
                                  source_manifest: ManifestState) -> None:
        for target_id in PROTECTED_TARGET_IDS:
            target = READ_BY_ID[target_id]
            for tag in TAGS:
                state, _manifest = self._verify_remote_tag(
                    registry, target.repository, tag, source_manifest, ("pull",),
                    require_exact_source_digest=True,
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
                docker = self.docker_factory(workspace)
                source_registry = self.registry_factory()
                source_manifest, _source_identity = self._verify_source(source_registry, docker)
                target_registry = self.registry_factory(credentials)
                tag_states = {}
                for tag in TAGS:
                    state, observed = self._verify_remote_tag(
                        target_registry, target.repository, tag, source_manifest, ("pull", "push"))
                    if state == "CONFLICT":
                        raise RecoveryError("TAG_CONFLICT")
                    tag_states[tag] = {"status": state,
                                       "digest": observed.digest if observed is not None else None}
                results["preflight"][target_id] = {
                    "status": "PREFLIGHT_READY", "failure_code": None,
                    "failure_phase": None, "failure_class": None, "tags": tag_states,
                }
                _write_results(results_path, results)
                return {"target": target_id, "status": "PREFLIGHT_READY", "tags": tag_states}
        except RecoveryError as error:
            results["preflight"][target_id] = {"status": "BLOCKED", "failure_code": error.code,
                                               "failure_phase": error.phase,
                                               "failure_class": error.failure_class, "tags": {}}
            _write_results(results_path, results)
            raise
        except Exception:
            results["preflight"][target_id] = {
                "status": "BLOCKED", "failure_code": "INTERNAL_FAILURE",
                "failure_phase": None, "failure_class": None, "tags": {},
            }
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
                source_docker = self.docker_factory(workspace)
                source_registry = self.registry_factory()
                source_manifest, source_identity = self._verify_source(source_registry, source_docker)
                self._verify_protected_targets(source_registry, source_manifest)
                target_registry = self.registry_factory(credentials)

                # Recheck every tag in this repository immediately before writes.
                current = {}
                current_manifests = {}
                for tag in TAGS:
                    current[tag], current_manifests[tag] = self._verify_remote_tag(
                        target_registry, target.repository, tag, source_manifest, ("pull", "push"))
                    if current[tag] == "CONFLICT":
                        raise RecoveryError("TAG_CONFLICT")
                if all(state == "ALREADY_PRESENT" for state in current.values()):
                    for tag in TAGS:
                        manifest = current_manifests[tag]
                        target_row["tags"][tag] = {
                            "status": "ALREADY_PRESENT", "digest": manifest.digest,
                            "failure_code": None, "failure_phase": None, "failure_class": None,
                        }
                    target_row["status"] = "ALREADY_PRESENT"
                    _write_results(results_path, results)
                    return {"target": target_id, "status": "ALREADY_PRESENT", "writes": 0}

                target_row["attempted"] = True
                target_row["status"] = "COPY_IN_PROGRESS"
                _write_results(results_path, results)

                destination_docker = self.docker_factory(
                    workspace, workspace.destination_config(target_id))
                login_attempted = False
                operation_error = None
                try:
                    login_attempted = True
                    destination_docker.login(credentials)
                    for tag in TAGS:
                        if current[tag] == "ALREADY_PRESENT":
                            state, manifest = self._verify_remote_tag(
                                target_registry, target.repository, tag, source_manifest,
                                ("pull", "push"))
                            if state == "CONFLICT":
                                error = RecoveryError("TAG_CONFLICT")
                                target_row["tags"][tag] = {
                                    "status": "CONFLICT", "digest": None,
                                    **_failure_fields(error),
                                }
                                _write_results(results_path, results)
                                raise error
                            if state != "ALREADY_PRESENT" or manifest is None:
                                error = RecoveryError("REGISTRY_UNKNOWN")
                                target_row["tags"][tag] = {
                                    "status": "UNKNOWN", "digest": None,
                                    **_failure_fields(error),
                                }
                                _write_results(results_path, results)
                                raise error
                            target_row["tags"][tag] = {
                                "status": "ALREADY_PRESENT", "digest": manifest.digest,
                                "failure_code": None, "failure_phase": None, "failure_class": None,
                            }
                            _write_results(results_path, results)
                            continue
                        # Last read before each tag write catches detected competitors.
                        latest = target_registry.manifest(target.repository, tag, ("pull", "push"))
                        if latest is not None:
                            if not _same_image_content(latest, source_manifest):
                                error = RecoveryError("TAG_CONFLICT")
                                target_row["tags"][tag] = {
                                    "status": "CONFLICT", "digest": None, **_failure_fields(error),
                                }
                                raise error
                            target_row["tags"][tag] = {
                                "status": "ALREADY_PRESENT", "digest": latest.digest,
                                "failure_code": None, "failure_phase": None, "failure_class": None,
                            }
                            _write_results(results_path, results)
                            continue

                        tag_row = target_row["tags"][tag]
                        tag_row.update({"status": "COPY_IN_PROGRESS", "digest": None,
                                        "failure_code": None, "failure_phase": None,
                                        "failure_class": None})
                        _write_results(results_path, results)
                        destination = _tag_reference(target.repository, tag)
                        try:
                            destination_docker.tag(source_identity["config_digest"], destination)
                            destination_docker.push(destination)
                            final_state, final_manifest = self._verify_remote_tag(
                                target_registry, target.repository, tag, source_manifest, ("pull", "push"))
                            if final_state != "ALREADY_PRESENT" or final_manifest is None:
                                raise RecoveryError("REGISTRY_UNKNOWN")
                            tag_row.update({"status": "PUBLISHED_VERIFIED",
                                            "digest": final_manifest.digest,
                                            "failure_code": None, "failure_phase": None,
                                            "failure_class": None})
                            _write_results(results_path, results)
                        except RecoveryError as error:
                            if error.code == "TAG_CONFLICT":
                                tag_row.update({"status": "CONFLICT", "digest": None,
                                                **_failure_fields(error)})
                            elif error.phase == "DOCKER_TAG":
                                tag_row.update({"status": "PENDING", "digest": None,
                                                **_failure_fields(error)})
                            else:
                                # A push or post-push read can have an ambiguous remote outcome.
                                tag_row.update({"status": "UNKNOWN", "digest": None,
                                                **_failure_fields(error)})
                            target_row.update(_failure_fields(error))
                            verified_any = any(value["status"] in {"PUBLISHED_VERIFIED", "ALREADY_PRESENT"}
                                               for value in target_row["tags"].values())
                            target_row["status"] = ("PARTIAL_PUBLICATION" if verified_any
                                                     else "UNKNOWN" if error.phase == "DOCKER_PUSH"
                                                     else "BLOCKED")
                            _write_results(results_path, results)
                            raise
                except RecoveryError as error:
                    operation_error = error
                finally:
                    if login_attempted:
                        try:
                            destination_docker.logout()
                        except RecoveryError:
                            target_row["logout_failure_code"] = "DOCKER_LOGOUT_FAILED"
                            if operation_error is None:
                                operation_error = RecoveryError(
                                    "DOCKER_LOGOUT_FAILED", phase="DOCKER_LOGOUT",
                                    failure_class="UNKNOWN")
                            else:
                                operation_error.secondary_failure_code = "DOCKER_LOGOUT_FAILED"
                        _write_results(results_path, results)

                if operation_error is not None:
                    target_row["failure_code"] = operation_error.code
                    target_row["failure_phase"] = operation_error.phase
                    target_row["failure_class"] = operation_error.failure_class
                    if target_row["status"] == "COPY_IN_PROGRESS":
                        verified_any = any(value["status"] in {"PUBLISHED_VERIFIED", "ALREADY_PRESENT"}
                                           for value in target_row["tags"].values())
                        target_row["status"] = "PARTIAL_PUBLICATION" if verified_any else "BLOCKED"
                    _write_results(results_path, results)
                    raise operation_error

                target_row.update({"status": "TARGET_VERIFIED", "failure_code": None,
                                   "failure_phase": None, "failure_class": None})
                _write_results(results_path, results)
                return {"target": target_id, "status": "TARGET_VERIFIED",
                        "writes": sum(1 for row in target_row["tags"].values()
                                      if row["status"] == "PUBLISHED_VERIFIED")}
        except RecoveryError as error:
            if target_row["status"] not in {"PARTIAL_PUBLICATION", "BLOCKED"}:
                target_row["status"] = "BLOCKED" if not target_row["attempted"] else "UNKNOWN"
                target_row.update(_failure_fields(error))
            _write_results(results_path, results)
            raise
        except Exception:
            target_row["status"] = "UNKNOWN" if target_row["attempted"] else "BLOCKED"
            target_row.update({"failure_code": "INTERNAL_FAILURE",
                               "failure_phase": None, "failure_class": None})
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
                docker = self.docker_factory(workspace)
                source_manifest, _source_identity = self._verify_source(self.registry_factory(), docker)
                registry = self.registry_factory(credentials)
                tag_states = {}
                for tag in TAGS:
                    state, manifest = self._verify_remote_tag(
                        registry, target.repository, tag, source_manifest, ("pull",),
                        require_exact_source_digest=target_id in PROTECTED_TARGET_IDS,
                    )
                    if state == "ALREADY_PRESENT":
                        tag_states[tag] = {"status": "VERIFIED", "digest": manifest.digest}
                    elif state == "ABSENT_HTTP404":
                        tag_states[tag] = {"status": "ABSENT_HTTP404", "digest": None}
                        if status != "BLOCKED":
                            status = "UNKNOWN"
                    else:
                        tag_states[tag] = {"status": "CONFLICT", "digest": None}
                        status = "BLOCKED"
                        failure_code = "TAG_CONFLICT"
                results["verification"][target_id] = {
                    "status": status, "failure_code": failure_code,
                    "failure_phase": None, "failure_class": None, "tags": tag_states,
                }
                _write_results(results_path, results)
                return {"target": target_id, "status": status, "failure_code": failure_code,
                        "tags": tag_states}
        except RecoveryError as error:
            conflict_seen = error.code == "TAG_CONFLICT" or any(
                row.get("status") == "CONFLICT" for row in tag_states.values())
            results["verification"][target_id] = {
                "status": "BLOCKED" if conflict_seen else "UNKNOWN",
                "failure_code": "TAG_CONFLICT" if conflict_seen else error.code,
                "failure_phase": error.phase, "failure_class": error.failure_class,
                "tags": tag_states,
            }
            _write_results(results_path, results)
            raise
        except Exception:
            results["verification"][target_id] = {
                "status": "UNKNOWN", "failure_code": "INTERNAL_FAILURE",
                "failure_phase": None, "failure_class": None, "tags": tag_states,
            }
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
            if any(row["tags"][tag].get("status") != "VERIFIED"
                   or not publisher.DIGEST_RE.fullmatch(
                       str(row["tags"][tag].get("digest", ""))) for tag in TAGS):
                all_verified = False
                break
            if target_id in PROTECTED_TARGET_IDS and any(
                    row["tags"][tag].get("digest") != SOURCE_DIGEST for tag in TAGS):
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
            or not re.fullmatch(r"[1-9][0-9]*", os.environ.get("GITHUB_RUN_NUMBER", ""))):
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
            with controller.workspace_factory() as workspace:
                docker = controller.docker_factory(workspace)
                docker.pull_source(_source_reference())
                controller._verify_source(controller.registry_factory(), docker)
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
        payload = {"status": "BLOCKED", "failure_code": error.code}
        if error.phase is not None:
            payload["failure_phase"] = error.phase
        if error.failure_class is not None:
            payload["failure_class"] = error.failure_class
        if error.secondary_failure_code is not None:
            payload["secondary_failure_code"] = error.secondary_failure_code
        _emit(payload)
        return 1
    except Exception:
        _emit({"status": "BLOCKED", "failure_code": "INTERNAL_FAILURE"})
        return 1


if __name__ == "__main__":
    with _cleanup_interrupts():
        raise SystemExit(main())
