#!/usr/bin/env python3
"""Single-runner image fanout. Only CI invokes the real adapters; tests use fakes.

Nothing in this module builds an image. Publishers tag the exact smoke-tested
local image ID. Each invocation receives only its own pair of secret values.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from urllib.parse import urlencode


SOURCE = "https://github.com/ad-fiverr/krig-salad"
VERSION = "1.5.2"
LOCAL_IMAGE = "fl4shminer-salad:ci"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
EXPECTED = (
    ("primary", "myblockchaincompany/fl4shminer-salad", "myblockchaincompany", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"),
    ("loboeldrin", "loboeldrin/comfyui-minimax-h3", "loboeldrin", "DOCKERHUB_USERNAME_LOBOELDRIN", "DOCKERHUB_TOKEN_LOBOELDRIN"),
    ("adrianfiverr", "adrianfiverr/pytorch-rc-2.15-dev", "adrianfiverr", "DOCKERHUB_USERNAME_ADRIANFIVERR", "DOCKERHUB_TOKEN_ADRIANFIVERR"),
    ("naxter1234", "naxter1234/traning_lora", "naxter1234", "DOCKERHUB_USERNAME_NAXTER1234", "DOCKERHUB_TOKEN_NAXTER1234"),
    ("ardevsolutions", "ardevsolutions/comfyui_video_wan2.5", "ardevsolutions", "DOCKERHUB_USERNAME_ARDEVSOLUTIONS", "DOCKERHUB_TOKEN_ARDEVSOLUTIONS"),
    ("boeing787", "boeing787/model_funning_tuning", "boeing787", "DOCKERHUB_USERNAME_BOEING787", "DOCKERHUB_TOKEN_BOEING787"),
)
FIELDS = ("id", "repository", "username", "username_secret", "token_secret")
FAILURES = frozenset({
    "CREDENTIALS_MISSING", "CREDENTIALS_INVALID", "USERNAME_MISMATCH", "NOT_CURRENT_MAIN",
    "CI_SCOPE_INVALID", "LOCAL_IMAGE_INVALID", "LOCAL_IMAGE_CHANGED", "SMOKE_NOT_PASSED",
    "DOCKER_COMMAND_FAILED", "REGISTRY_REQUEST_FAILED", "REGISTRY_STATUS_REJECTED",
    "REGISTRY_RESPONSE_INVALID", "MANIFEST_INVALID", "IMAGE_CONTENT_MISMATCH",
    "TAG_DIGEST_MISMATCH", "COMMIT_TAG_CONFLICT", "LOGOUT_FAILED", "INTERNAL_FAILURE",
})


class Rejected(Exception):
    """Fixed codes only. Never propagate Docker/provider exceptions or bodies."""

    def __init__(self, code: str):
        self.code = code if code in FAILURES else "INTERNAL_FAILURE"
        super().__init__(self.code)


@dataclass(frozen=True)
class Target:
    id: str
    repository: str
    username: str
    username_secret: str
    token_secret: str

    @property
    def image(self) -> str:
        return "docker.io/" + self.repository


def load_targets(path: Path) -> tuple[Target, ...]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data["targets"]
        if set(data) != {"schema_version", "targets"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValueError
        if not isinstance(rows, list) or len(rows) != len(EXPECTED):
            raise ValueError
        if any(not isinstance(row, dict) or set(row) != set(FIELDS) for row in rows):
            raise ValueError
        if tuple(tuple(row[key] for key in FIELDS) for row in rows) != EXPECTED:
            raise ValueError
        return tuple(Target(**row) for row in rows)
    except Exception:
        raise ValueError("TARGET_ALLOWLIST_INVALID") from None


def credentials(target: Target, username: str, token: str) -> None:
    if not username or not token:
        raise Rejected("CREDENTIALS_MISSING")
    if username != target.username:
        raise Rejected("USERNAME_MISMATCH")
    if not isinstance(token, str) or not 1 <= len(token) <= 4096 or any(not 33 <= ord(c) <= 126 for c in token):
        raise Rejected("CREDENTIALS_INVALID")


def tags(revision: str) -> tuple[str, ...]:
    if not SHA_RE.fullmatch(revision):
        raise Rejected("LOCAL_IMAGE_INVALID")
    return (VERSION, "sha-" + revision[:12], "latest")


def image_identity(raw: object, revision: str) -> dict:
    try:
        if not SHA_RE.fullmatch(revision) or not isinstance(raw, dict):
            raise ValueError
        labels = raw["Config"]["Labels"]
        image_id = raw["Id"]
        layers = raw["RootFS"]["Layers"]
        if not DIGEST_RE.fullmatch(image_id) or raw["Os"] != "linux" or raw["Architecture"] != "amd64":
            raise ValueError
        if labels["org.opencontainers.image.revision"] != revision or labels["org.opencontainers.image.source"] != SOURCE or labels["org.opencontainers.image.version"] != VERSION:
            raise ValueError
        if not isinstance(layers, list) or not layers or any(not isinstance(v, str) or not DIGEST_RE.fullmatch(v) for v in layers):
            raise ValueError
        return {"image_id": image_id, "revision": revision, "version": VERSION, "source": SOURCE,
                "platform": "linux/amd64", "rootfs_diff_ids": layers}
    except Exception:
        raise Rejected("LOCAL_IMAGE_INVALID") from None


def read_evidence(path: Path, *, sealed: bool = True) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        required = {"image_id", "revision", "version", "source", "platform", "rootfs_diff_ids", "smoke_passed"}
        if not isinstance(data, dict) or set(data) != required or type(data["smoke_passed"]) is not bool:
            raise ValueError
        identity = image_identity({"Id": data["image_id"], "Os": data["platform"].split("/")[0],
            "Architecture": data["platform"].split("/")[1], "RootFS": {"Layers": data["rootfs_diff_ids"]},
            "Config": {"Labels": {"org.opencontainers.image.revision": data["revision"],
            "org.opencontainers.image.source": data["source"], "org.opencontainers.image.version": data["version"]}}}, data["revision"])
        if identity != {k: v for k, v in data.items() if k != "smoke_passed"}:
            raise ValueError
        if sealed and not data["smoke_passed"]:
            raise Rejected("SMOKE_NOT_PASSED")
        return data
    except Rejected:
        raise
    except Exception:
        raise Rejected("LOCAL_IMAGE_INVALID") from None


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


class Docker:
    def __init__(self, config: Path, revision: str):
        self.config, self.revision = config, revision

    def command(self, args: list[str], *, stdin: str | None = None) -> str:
        # No token, other account, proxy, DOCKER_HOST or inherited Docker config
        # reaches a subprocess. The login password travels only through stdin.
        allowed = ("PATH", "HOME", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP")
        env = {key: os.environ[key] for key in allowed if key in os.environ}
        env["DOCKER_CONFIG"] = str(self.config)
        try:
            result = subprocess.run(args, input=stdin, text=True, encoding="utf-8", errors="replace",
                                    capture_output=True, check=False, timeout=1800, env=env)
            if result.returncode != 0 or len(result.stdout) > 1_000_000:
                raise Rejected("DOCKER_COMMAND_FAILED")
            return result.stdout
        except Exception:
            raise Rejected("DOCKER_COMMAND_FAILED") from None

    def assert_current_main(self) -> None:
        if os.environ.get("GITHUB_REPOSITORY") != "ad-fiverr/krig-salad" or os.environ.get("GITHUB_REF") != "refs/heads/main" or os.environ.get("GITHUB_SHA") != self.revision:
            raise Rejected("CI_SCOPE_INVALID")
        output = self.command(["git", "ls-remote", "--exit-code", "origin", "refs/heads/main"])
        if output.strip() != self.revision + "\trefs/heads/main":
            raise Rejected("NOT_CURRENT_MAIN")

    def inspect(self, reference: str) -> dict:
        try:
            rows = json.loads(self.command(["docker", "image", "inspect", reference]))
            if not isinstance(rows, list) or len(rows) != 1:
                raise ValueError
            return image_identity(rows[0], self.revision)
        except Rejected:
            raise
        except Exception:
            raise Rejected("LOCAL_IMAGE_INVALID") from None

    def login(self, username: str, token: str) -> None:
        self.command(["docker", "login", "docker.io", "--username", username, "--password-stdin"], stdin=token + "\n")

    def logout(self) -> None:
        self.command(["docker", "logout", "docker.io"])

    def push(self, image_id: str, reference: str) -> None:
        self.command(["docker", "image", "tag", image_id, reference])
        self.command(["docker", "image", "push", "--quiet", reference])

    def pull(self, reference: str) -> None:
        self.command(["docker", "image", "pull", "--platform", "linux/amd64", "--quiet", reference])


@dataclass(frozen=True)
class Manifest:
    digest: str
    config: str
    content_hash: str


def parse_manifest(body: bytes, digest: str) -> Manifest:
    try:
        if not DIGEST_RE.fullmatch(digest) or "sha256:" + hashlib.sha256(body).hexdigest() != digest:
            raise ValueError
        data = json.loads(body)
        if type(data["schemaVersion"]) is not int or data["schemaVersion"] != 2 or "manifests" in data or data.get("mediaType") not in {
            "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json",
        }:
            raise ValueError
        config = data["config"]["digest"]
        if (not DIGEST_RE.fullmatch(config) or type(data["config"]["size"]) is not int or data["config"]["size"] <= 0
                or data["config"]["mediaType"] not in {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}
                or not isinstance(data["layers"], list) or not 1 <= len(data["layers"]) <= 256):
            raise ValueError
        layers = []
        for layer in data["layers"]:
            if (not DIGEST_RE.fullmatch(layer["digest"]) or type(layer["size"]) is not int or layer["size"] < 0
                    or layer["mediaType"] not in {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
                        "application/vnd.oci.image.layer.v1.tar+zstd", "application/vnd.docker.image.rootfs.diff.tar", "application/vnd.docker.image.rootfs.diff.tar.gzip"}):
                raise ValueError
            layers.append([layer["digest"], layer["size"]])
        content = json.dumps([config, layers], separators=(",", ":")).encode()
        return Manifest(digest, config, hashlib.sha256(content).hexdigest())
    except Exception:
        raise Rejected("MANIFEST_INVALID") from None


class Registry:
    """Fixed HTTPS GETs, bounded responses, no redirects or automatic retries."""

    def __init__(self, target: Target, username: str, token: str):
        self.target, self.username, self.token = target, username, token
        self.bearer: str | None = None

    def _get(self, host: str, path: str, headers: dict) -> tuple[int, dict, bytes]:
        if host not in {"auth.docker.io", "registry-1.docker.io"}:
            raise Rejected("REGISTRY_REQUEST_FAILED")
        connection = None
        try:
            connection = http.client.HTTPSConnection(host, 443, timeout=15, context=ssl.create_default_context())
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            body = response.read(1_000_001)
            if len(body) > 1_000_000:
                raise ValueError
            return response.status, {key.lower(): value for key, value in response.getheaders()}, body
        except Exception:
            raise Rejected("REGISTRY_REQUEST_FAILED") from None
        finally:
            if connection is not None:
                connection.close()

    def manifest(self, tag: str) -> Manifest | None:
        if tag not in tags(os.environ.get("GITHUB_SHA", "")):
            raise Rejected("MANIFEST_INVALID")
        if self.bearer is None:
            path = "/token?" + urlencode({"service": "registry.docker.io", "scope": "repository:" + self.target.repository + ":pull"})
            basic = base64.b64encode((self.username + ":" + self.token).encode("ascii")).decode("ascii")
            status, _, body = self._get("auth.docker.io", path, {"Authorization": "Basic " + basic, "Accept": "application/json"})
            if status != 200:
                raise Rejected("REGISTRY_STATUS_REJECTED")
            try:
                data = json.loads(body)
                value = data.get("token", data.get("access_token"))
                if not isinstance(value, str) or not 1 <= len(value) <= 16384 or any(not 33 <= ord(c) <= 126 for c in value):
                    raise ValueError
                if "token" in data and "access_token" in data and data["token"] != data["access_token"]:
                    raise ValueError
                self.bearer = value
            except Exception:
                raise Rejected("REGISTRY_RESPONSE_INVALID") from None
        status, headers, body = self._get("registry-1.docker.io", "/v2/" + self.target.repository + "/manifests/" + tag,
            {"Authorization": "Bearer " + self.bearer, "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
        if status == 404:
            if headers.get("docker-content-digest"):
                raise Rejected("REGISTRY_RESPONSE_INVALID")
            return None
        if status != 200:
            raise Rejected("REGISTRY_STATUS_REJECTED")
        return parse_manifest(body, headers.get("docker-content-digest", ""))


def publish(target: Target, evidence: dict, username: str, token: str, *, docker, registry) -> dict:
    target_tags = tags(evidence["revision"])
    result = {"target": target.id, "repository": target.image, "revision": evidence["revision"],
        "status": "PENDING", "failure_code": None, "image_id": evidence["image_id"],
        "previous_version_status": "UNKNOWN", "previous_version_digest": None,
        "manifest_digest": None, "content_hash": None,
        "tags": {tag: {"status": "PENDING", "digest": None} for tag in target_tags}}
    entered = False
    try:
        credentials(target, username, token)
        if evidence.get("smoke_passed") is not True:
            raise Rejected("SMOKE_NOT_PASSED")
        docker.assert_current_main()
        if docker.inspect(evidence["image_id"]) != {k: v for k, v in evidence.items() if k != "smoke_passed"}:
            raise Rejected("LOCAL_IMAGE_CHANGED")
        entered = True
        docker.login(username, token)
        previous = {tag: registry.manifest(tag) for tag in target_tags}
        result["previous_version_digest"] = previous[VERSION].digest if previous[VERSION] else None
        result["previous_version_status"] = "FOUND" if previous[VERSION] else "ABSENT_HTTP404"
        commit_tag = target_tags[1]
        if previous[commit_tag] and previous[commit_tag].config != evidence["image_id"]:
            raise Rejected("COMMIT_TAG_CONFLICT")
        expected: Manifest | None = previous[commit_tag]
        for tag in (commit_tag, VERSION, "latest"):
            docker.assert_current_main()
            current = previous[tag]
            if current is not None and expected is not None and current == expected:
                observed = current
                status = "ALREADY_PRESENT"
            else:
                docker.push(evidence["image_id"], target.image + ":" + tag)
                observed = registry.manifest(tag)
                status = "PUBLISHED"
            if observed is None or observed.config != evidence["image_id"]:
                raise Rejected("IMAGE_CONTENT_MISMATCH")
            if expected is not None and observed != expected:
                raise Rejected("TAG_DIGEST_MISMATCH")
            expected = observed
            result["tags"][tag] = {"status": status, "digest": observed.digest}
        # Read all tags again: a successful push command alone is not evidence.
        for tag in target_tags:
            if registry.manifest(tag) != expected:
                raise Rejected("TAG_DIGEST_MISMATCH")
        immutable = target.image + "@" + expected.digest
        docker.pull(immutable)
        if docker.inspect(immutable) != {k: v for k, v in evidence.items() if k != "smoke_passed"}:
            raise Rejected("IMAGE_CONTENT_MISMATCH")
        result.update(status="PUBLISHED", manifest_digest=expected.digest, content_hash=expected.content_hash)
    except Rejected as exc:
        result.update(status="FAILED", failure_code=exc.code)
    except Exception:
        result.update(status="FAILED", failure_code="INTERNAL_FAILURE")
    finally:
        if entered:
            try:
                docker.logout()
            except Exception:
                result.update(status="FAILED", failure_code="LOGOUT_FAILED")
    return result


def summarize(targets: tuple[Target, ...], evidence: dict | None, results: dict[str, dict]) -> tuple[str, bool]:
    rows = ["## Fl4shMiner Docker Hub fanout", ""]
    if evidence is not None:
        rows.extend(["OCI revision: " + evidence["revision"], "Tested config digest: " + evidence["image_id"], ""])
    rows.extend(["| Destination | Result | Per-tag evidence | Immutable image | Previous version digest |", "|---|---|---|---|---|"])
    all_ok = evidence is not None and evidence.get("smoke_passed") is True
    common_content = None
    for target in targets:
        row = results.get(target.id)
        valid = isinstance(row, dict) and row.get("target") == target.id and row.get("repository") == target.image
        status = "SKIPPED" if evidence is not None and evidence.get("smoke_passed") is not True else "PENDING"
        immutable, tag_note, prior = "—", "not verified", "UNKNOWN"
        if valid and evidence is not None and row.get("revision") == evidence["revision"] and row.get("image_id") == evidence["image_id"]:
            status = row.get("status") if row.get("status") in {"PUBLISHED", "FAILED", "SKIPPED", "PENDING"} else "FAILED"
            digest = row.get("manifest_digest")
            entries = row.get("tags", {})
            expected_tags = tags(evidence["revision"])
            if isinstance(entries, dict) and set(entries) == set(expected_tags):
                safe_tags = []
                for tag in expected_tags:
                    value = entries[tag]
                    state = value.get("status") if isinstance(value, dict) else None
                    tag_digest = value.get("digest") if isinstance(value, dict) else None
                    if state in {"PUBLISHED", "ALREADY_PRESENT", "PENDING"} and (tag_digest is None or isinstance(tag_digest, str) and DIGEST_RE.fullmatch(tag_digest)):
                        safe_tags.append(tag + "=" + state + ("@" + tag_digest if tag_digest else ""))
                if len(safe_tags) == len(expected_tags):
                    tag_note = "<br>".join(safe_tags)
            prior_value = row.get("previous_version_digest")
            if row.get("previous_version_status") == "FOUND" and isinstance(prior_value, str) and DIGEST_RE.fullmatch(prior_value):
                prior = prior_value
            elif row.get("previous_version_status") == "ABSENT_HTTP404" and prior_value is None:
                prior = "ABSENT (HTTP 404)"
            verified = status == "PUBLISHED" and isinstance(digest, str) and bool(DIGEST_RE.fullmatch(digest)) and isinstance(entries, dict) and set(entries) == set(expected_tags)
            verified = verified and all(isinstance(v, dict) and v.get("digest") == digest and v.get("status") in {"PUBLISHED", "ALREADY_PRESENT"} for v in entries.values())
            content = row.get("content_hash")
            verified = verified and isinstance(content, str) and bool(re.fullmatch(r"[0-9a-f]{64}", content))
            if verified:
                if common_content is None:
                    common_content = content
                if content != common_content:
                    verified = False
                else:
                    immutable = target.image + "@" + digest
            if status == "PUBLISHED" and not verified:
                status = "FAILED"
            all_ok = all_ok and verified
        else:
            all_ok = False
        failure = row.get("failure_code") if valid else None
        if status == "FAILED" and isinstance(failure, str) and failure in FAILURES:
            status += " (" + failure + ")"
        rows.append(f"| {target.image} | {status} | {tag_note} | {immutable} | {prior} |")
    rows.extend(["", "Result: " + ("ALL_TARGETS_VERIFIED" if all_ok else "INCOMPLETE_OR_FAILED"),
        "Each repository's three tags must share one digest. Across repositories, config and layer content are compared; manifest digests are reported individually.",
        "Publishing a tag does not update running Salad containers."])
    return "\n".join(rows) + "\n", all_ok


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("validate-targets", "base-login", "base-logout", "capture", "image-id", "seal", "publish", "summary"))
    parser.add_argument("--targets", type=Path, default=Path(".github/fl4sh-publish-targets.json"))
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--results", type=Path)
    parser.add_argument("--target")
    args = parser.parse_args()
    try:
        targets = load_targets(args.targets)
        revision = os.environ.get("GITHUB_SHA", "")
        if args.operation == "validate-targets":
            print("TARGET_ALLOWLIST_OK six_targets twelve_secret_aliases")
            return 0
        if args.operation in {"base-login", "base-logout"}:
            docker = Docker(Path(os.environ["DOCKER_CONFIG"]), revision)
            if args.operation == "base-login":
                username, token = os.environ.get("FANOUT_USERNAME", ""), os.environ.get("FANOUT_TOKEN", "")
                credentials(targets[0], username, token)
                docker.login(username, token)
            else:
                docker.logout()
            return 0
        if args.operation == "capture":
            docker = Docker(Path(os.environ["DOCKER_CONFIG"]), revision)
            write_json(args.evidence, {**docker.inspect(LOCAL_IMAGE), "smoke_passed": False})
            return 0
        if args.operation in {"image-id", "seal"}:
            evidence = read_evidence(args.evidence, sealed=False)
            if args.operation == "image-id":
                print(evidence["image_id"])
            else:
                docker = Docker(Path(os.environ["DOCKER_CONFIG"]), revision)
                if docker.inspect(evidence["image_id"]) != {k: v for k, v in evidence.items() if k != "smoke_passed"}:
                    raise Rejected("LOCAL_IMAGE_CHANGED")
                write_json(args.evidence, {**evidence, "smoke_passed": True})
            return 0
        if args.operation == "publish":
            target = next(row for row in targets if row.id == args.target)
            evidence = read_evidence(args.evidence)
            username, token = os.environ.get("FANOUT_USERNAME", ""), os.environ.get("FANOUT_TOKEN", "")
            with tempfile.TemporaryDirectory(prefix="fl4sh-publish-", dir=os.environ.get("RUNNER_TEMP")) as private:
                config = Path(private)
                (config / "config.json").write_text("{}", encoding="utf-8")
                result = publish(target, evidence, username, token, docker=Docker(config, revision), registry=Registry(target, username, token))
            write_json(args.results / (target.id + ".json"), result)
            print(json.dumps({"target": target.id, "status": result["status"], "failure_code": result["failure_code"]}))
            return 0 if result["status"] == "PUBLISHED" else 1
        try:
            evidence = read_evidence(args.evidence, sealed=False) if args.evidence and args.evidence.is_file() else None
        except Rejected:
            evidence = None
        results = {}
        for target in targets:
            path = args.results / (target.id + ".json")
            if path.is_file():
                try:
                    results[target.id] = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    pass
        summary, ok = summarize(targets, evidence, results)
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
        print("ALL_TARGETS_VERIFIED" if ok else "INCOMPLETE_OR_FAILED")
        return 0 if ok else 1
    except Exception:
        print("FANOUT_OPERATION_REJECTED")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
