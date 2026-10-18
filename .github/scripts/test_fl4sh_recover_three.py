#!/usr/bin/env python3
"""Offline contract tests for the fixed three-target image recovery workflow."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import fl4sh_publish as publisher
import fl4sh_recover_three as recovery


ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_USERNAME = "naxter1234"
SYNTHETIC_TOKEN = "synthetic-token-never-use-remotely"
CONTENT_HASH = "a" * 64
DIFF_IDS = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]


def config(*, revision=recovery.SOURCE_REVISION, architecture="amd64", os_name="linux"):
    return {
        "architecture": architecture,
        "os": os_name,
        "config": {"Labels": {
            "org.opencontainers.image.revision": revision,
            "org.opencontainers.image.source": recovery.SOURCE_URL,
            "org.opencontainers.image.version": recovery.VERSION,
        }},
        "rootfs": {"type": "layers", "diff_ids": list(DIFF_IDS)},
    }


def manifest_body(*, config_digest=recovery.SOURCE_CONFIG_DIGEST):
    value = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "size": 500, "digest": config_digest},
        "layers": [
            {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
             "size": 100, "digest": "sha256:" + "3" * 64},
            {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
             "size": 200, "digest": "sha256:" + "4" * 64},
        ],
    }
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    parsed = publisher.parse_manifest(body, digest)
    return body, recovery.ManifestState(parsed.digest, parsed.config, parsed.content_hash, 2)


SOURCE_BODY, SOURCE_PARSED_STATE = manifest_body()
SOURCE_STATE = recovery.ManifestState(
    recovery.SOURCE_DIGEST, recovery.SOURCE_CONFIG_DIGEST,
    SOURCE_PARSED_STATE.content_hash, SOURCE_PARSED_STATE.layer_count)


class FakeWorld:
    def __init__(self):
        self.source_state = SOURCE_STATE
        self.config_value = config()
        self.tags = {target.repository: {tag: None for tag in recovery.TAGS}
                     for target in recovery.WRITE_TARGETS}
        self.tags[recovery.SOURCE_REPOSITORY] = {recovery.SOURCE_DIGEST: SOURCE_STATE}
        self.tags.update({target.repository: {tag: SOURCE_STATE for tag in recovery.TAGS}
                          for target in recovery.READ_TARGETS[:3]})
        self.registry_reads = []
        self.copy_calls = []
        self.fail_copy_tag = None
        self.inject_competing_tag_after_first_copy = False
        self.competing_tag_visible = False
        self.config_revision = recovery.SOURCE_REVISION
        self.source_digest_corrupt = False

    def registry_factory(self, credentials=None):
        return FakeRegistry(self)

    def get(self, repository, reference):
        self.registry_reads.append((repository, reference))
        if repository == recovery.SOURCE_REPOSITORY and reference == recovery.SOURCE_DIGEST:
            if self.source_digest_corrupt:
                return recovery.ManifestState("sha256:" + "f" * 64,
                                               SOURCE_STATE.config,
                                               SOURCE_STATE.content_hash,
                                               SOURCE_STATE.layer_count)
            return self.source_state
        if (repository == "naxter1234/traning_lora" and reference == recovery.TAGS[1]
                and self.competing_tag_visible):
            return recovery.ManifestState("sha256:" + "f" * 64, "sha256:" + "e" * 64,
                                          "competing-content", 2)
        return self.tags.get(repository, {}).get(reference)

    def put_from_copy(self, destination, tag):
        self.copy_calls.append((destination, tag))
        if tag == self.fail_copy_tag:
            raise recovery.RecoveryError("SKOPEO_COPY_FAILED")
        repository = destination.removeprefix("docker://docker.io/").rsplit(":", 1)[0]
        self.tags[repository][tag] = SOURCE_STATE
        if tag == recovery.TAGS[0] and self.inject_competing_tag_after_first_copy:
            self.competing_tag_visible = True


class FakeRegistry:
    def __init__(self, world):
        self.world = world

    def manifest(self, repository, reference, actions=("pull",)):
        if repository not in {target.repository for target in recovery.READ_TARGETS}:
            raise recovery.RecoveryError("ARGUMENT_INVALID")
        if tuple(actions) not in {("pull",), ("pull", "push")}:
            raise recovery.RecoveryError("ARGUMENT_INVALID")
        return self.world.get(repository, reference)


class FakeSkopeo:
    def __init__(self, workspace, world):
        self.workspace = workspace
        self.world = world
        self.calls = []

    def validate(self):
        self.calls.append(("validate",))

    def login(self, credentials):
        self.calls.append(("authfile",))
        self.workspace.write_destination_auth(credentials)

    def inspect_config(self, reference, authfile):
        self.calls.append(("inspect", reference))
        return config(revision=self.world.config_revision)

    def copy(self, source, destination, digestfile, source_auth, dest_auth):
        self.calls.append(("copy", source, destination))
        tag = destination.rsplit(":", 1)[1]
        self.world.put_from_copy(destination, tag)
        digestfile.write_text(recovery.SOURCE_DIGEST, encoding="ascii")
        return recovery.SOURCE_DIGEST


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.socket_guard = patch.object(socket, "socket", side_effect=AssertionError("network socket forbidden"))
        self.socket_guard.start()
        self.addCleanup(self.socket_guard.stop)
        self.subprocess_guard = patch.object(subprocess, "run", side_effect=AssertionError("subprocess forbidden"))
        self.subprocess_guard.start()
        self.addCleanup(self.subprocess_guard.stop)
        self.world = FakeWorld()
        self.temp = tempfile.TemporaryDirectory(prefix="fl4sh-recovery-test-")
        self.addCleanup(self.temp.cleanup)
        self.results = Path(self.temp.name) / "results.json"
        recovery._write_results(self.results, recovery._new_results("offline-run-1", "1"))
        self.controller = recovery.RecoveryController(
            registry_factory=self.world.registry_factory,
            skopeo_factory=lambda workspace: FakeSkopeo(workspace, self.world),
        )

    def credentials(self, target_id):
        target = recovery.READ_BY_ID[target_id]
        return target.username, SYNTHETIC_TOKEN

    def preflight_all(self):
        for target_id in recovery.TARGET_IDS:
            self.controller.preflight(target_id, self.results, *self.credentials(target_id))

    def verify_protected_targets(self):
        for target_id in recovery.PROTECTED_TARGET_IDS:
            self.controller.verify_target(target_id, self.results)

    def run_verification_all(self):
        for target in recovery.READ_TARGETS:
            pair = self.credentials(target.id)
            self.controller.verify_target(target.id, self.results, *pair)

    def test_write_allowlist_is_exactly_targets_four_to_six(self):
        self.assertEqual(recovery.TARGET_IDS, ("naxter1234", "ardevsolutions", "boeing787"))
        self.assertEqual(tuple(target.repository for target in recovery.WRITE_TARGETS), (
            "naxter1234/traning_lora", "ardevsolutions/comfyui_video_wan2.5",
            "boeing787/model_funning_tuning"))
        with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
            recovery._target("primary", write_only=True)
        with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
            recovery._target("loboeldrin", write_only=True)
        with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
            recovery._target("adrianfiverr", write_only=True)

    def test_fixed_source_revision_digest_and_tags(self):
        self.assertEqual(recovery.SOURCE_DIGEST,
                         "sha256:4091b611ea99c64abdc854a4cfe2d5b95b6202adf12a6e2ab7437a62a1325217")
        self.assertEqual(recovery.SOURCE_REVISION, "e66ba5e17bafd105c6ef89acf7ff38c1f87e3542")
        self.assertEqual(recovery.TAGS, ("sha-e66ba5e17baf", "1.5.2", "latest"))

    def test_wrong_source_manifest_digest_blocks_before_copy(self):
        self.world.source_digest_corrupt = True
        with self.assertRaisesRegex(recovery.RecoveryError, "SOURCE_IDENTITY_INVALID"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])
        row = recovery._read_results(self.results)["preflight"]["naxter1234"]
        self.assertEqual(row["failure_code"], "SOURCE_IDENTITY_INVALID")

    def test_wrong_source_revision_blocks_before_copy(self):
        self.world.config_revision = "0" * 40
        with self.assertRaisesRegex(recovery.RecoveryError, "IMAGE_IDENTITY_INVALID"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])

    def test_wrong_platform_blocks_before_copy(self):
        # The image inspection must fail closed for a non-amd64 source.
        original_factory = self.controller.skopeo_factory
        self.controller.skopeo_factory = lambda workspace: _WrongPlatformSkopeo(workspace, self.world)
        with self.assertRaisesRegex(recovery.RecoveryError, "IMAGE_IDENTITY_INVALID"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.controller.skopeo_factory = original_factory
        self.assertEqual(self.world.copy_calls, [])

    def test_layer_count_mismatch_blocks_before_copy(self):
        self.world.source_state = recovery.ManifestState(
            recovery.SOURCE_DIGEST, recovery.SOURCE_CONFIG_DIGEST, CONTENT_HASH, 3)
        with self.assertRaisesRegex(recovery.RecoveryError, "IMAGE_IDENTITY_INVALID"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])

    def test_existing_conflicting_sha_tag_blocks_without_writes(self):
        self.world.tags["naxter1234/traning_lora"][recovery.TAGS[0]] = recovery.ManifestState(
            "sha256:" + "f" * 64, "sha256:" + "e" * 64, "bad-content", 2)
        with self.assertRaisesRegex(recovery.RecoveryError, "TAG_CONFLICT"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])

    def test_verification_preserves_authorized_404_as_absence_not_unknown_error(self):
        result = self.controller.verify_target("naxter1234", self.results)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["failure_code"])
        self.assertTrue(all(result["tags"][tag] == {"status": "ABSENT_HTTP404", "digest": None}
                            for tag in recovery.TAGS))
        row = recovery._read_results(self.results)["verification"]["naxter1234"]
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertEqual(self.world.copy_calls, [])

    def test_recovery_only_changes_selected_allowed_destination(self):
        before = {repo: dict(tags) for repo, tags in self.world.tags.items()}
        self.preflight_all()
        self.verify_protected_targets()
        result = self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(result["status"], "TARGET_VERIFIED")
        self.assertEqual([tag for _repo, tag in self.world.copy_calls], list(recovery.TAGS))
        for target in recovery.READ_TARGETS[:3]:
            self.assertEqual(self.world.tags[target.repository], before[target.repository])
        for target in recovery.WRITE_TARGETS[1:]:
            self.assertEqual(self.world.tags[target.repository], before[target.repository])
        self.assertTrue(all(self.world.tags["naxter1234/traning_lora"][tag] == SOURCE_STATE
                            for tag in recovery.TAGS))

    def test_sha_conflict_during_recovery_blocks_without_overwrite(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.tags["naxter1234/traning_lora"][recovery.TAGS[0]] = recovery.ManifestState(
            "sha256:" + "f" * 64, "sha256:" + "e" * 64, "competing-content", 2)
        with self.assertRaisesRegex(recovery.RecoveryError, "TAG_CONFLICT"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])

    def test_competing_tag_after_first_copy_is_recorded_as_partial_and_not_overwritten(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.inject_competing_tag_after_first_copy = True
        with self.assertRaisesRegex(recovery.RecoveryError, "TAG_CONFLICT"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual([tag for _repo, tag in self.world.copy_calls], [recovery.TAGS[0]])
        row = recovery._read_results(self.results)["targets"]["naxter1234"]
        self.assertEqual(row["status"], "PARTIAL_PUBLICATION")
        self.assertEqual(row["tags"][recovery.TAGS[1]]["status"], "CONFLICT")

    def test_current_three_of_six_remote_state_is_partial_not_blocked_or_success(self):
        self.run_verification_all()
        summary = recovery._summary(recovery._read_results(self.results))
        self.assertEqual(summary["status"], "PARTIAL_PUBLICATION")
        self.assertEqual(summary["published_targets"], 3)

    def test_partial_copy_is_recorded_and_never_retried(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.fail_copy_tag = recovery.TAGS[1]
        with self.assertRaisesRegex(recovery.RecoveryError, "SKOPEO_COPY_FAILED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual([tag for _repo, tag in self.world.copy_calls], list(recovery.TAGS[:2]))
        row = recovery._read_results(self.results)["targets"]["naxter1234"]
        self.assertEqual(row["status"], "PARTIAL_PUBLICATION")
        self.assertTrue(row["attempted"])
        self.assertEqual(row["tags"][recovery.TAGS[1]]["status"], "UNKNOWN")
        with self.assertRaisesRegex(recovery.RecoveryError, "RUN_ALREADY_ATTEMPTED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(len(self.world.copy_calls), 2)

    def test_later_target_is_blocked_after_previous_target_partial_failure(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.fail_copy_tag = recovery.TAGS[1]
        with self.assertRaisesRegex(recovery.RecoveryError, "SKOPEO_COPY_FAILED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        writes_before = list(self.world.copy_calls)
        with self.assertRaisesRegex(recovery.RecoveryError, "RECOVERY_SEQUENCE_BLOCKED"):
            self.controller.recover("ardevsolutions", self.results, *self.credentials("ardevsolutions"))
        self.assertEqual(self.world.copy_calls, writes_before)
        self.assertFalse(recovery._read_results(self.results)["targets"]["ardevsolutions"]["attempted"])

    def test_recovery_requires_protected_targets_verified_before_any_write(self):
        self.preflight_all()
        with self.assertRaisesRegex(recovery.RecoveryError, "PROTECTED_TARGETS_UNVERIFIED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])

    def test_protected_target_drift_is_rechecked_before_each_recovery_target(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.tags[recovery.READ_BY_ID["primary"].repository][recovery.TAGS[0]] = None
        with self.assertRaisesRegex(recovery.RecoveryError, "PROTECTED_TARGET_DRIFT"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])

    def test_recovery_requires_all_three_preflights(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "PREFLIGHT_INCOMPLETE"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.copy_calls, [])

    def test_all_six_targets_require_exact_three_tags_for_6_of_6(self):
        original_first_three = {target.repository: dict(self.world.tags[target.repository])
                                for target in recovery.READ_TARGETS[:3]}
        self.preflight_all()
        self.verify_protected_targets()
        for target_id in recovery.TARGET_IDS:
            self.controller.recover(target_id, self.results, *self.credentials(target_id))
        for repository, old_tags in original_first_three.items():
            self.assertEqual(self.world.tags[repository], old_tags)
        self.run_verification_all()
        self.assertEqual(recovery._summary(recovery._read_results(self.results))["status"], "6_OF_6_VERIFIED")

    def test_authfile_is_private_and_secret_is_never_in_arguments_or_results(self):
        with recovery.PrivateWorkspace() as workspace:
            credentials = recovery.Credentials(SYNTHETIC_USERNAME, SYNTHETIC_TOKEN)
            workspace.write_destination_auth(credentials)
            raw_auth = workspace.dest_auth.read_text(encoding="ascii")
            self.assertNotIn(SYNTHETIC_TOKEN, raw_auth)
            self.assertEqual(json.loads(raw_auth)["auths"]["docker.io"]["auth"],
                             base64.b64encode((SYNTHETIC_USERNAME + ":" + SYNTHETIC_TOKEN).encode()).decode())
            self.assertNotIn(SYNTHETIC_TOKEN, repr(credentials))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(workspace.dest_auth.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(workspace.path.stat().st_mode), 0o700)
        self.assertFalse(workspace.path.exists())
        output = self.results.read_text(encoding="utf-8")
        self.assertNotIn(SYNTHETIC_TOKEN, output)
        self.assertNotIn(SYNTHETIC_USERNAME + ":" + SYNTHETIC_TOKEN, output)

    def test_authfile_is_removed_when_operation_raises(self):
        workspace_path = None
        with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
            with recovery.PrivateWorkspace() as workspace:
                workspace_path = workspace.path
                workspace.write_destination_auth(recovery.Credentials(SYNTHETIC_USERNAME, SYNTHETIC_TOKEN))
                raise RuntimeError("synthetic failure")
        self.assertFalse(workspace_path.exists())

    def test_secrets_are_not_passed_to_skopeo_argv_or_environment(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.Skopeo(workspace)
            seen = {}

            def fake_run(args, **kwargs):
                seen["args"] = list(args)
                seen["env"] = dict(kwargs["env"])
                return subprocess.CompletedProcess(args, 0, stdout="safe", stderr="")

            with patch.object(subprocess, "run", side_effect=fake_run):
                runner.command(["inspect", "docker://docker.io/public/image:tag"])
            self.assertNotIn(SYNTHETIC_TOKEN, repr(seen["args"]))
            self.assertNotIn(SYNTHETIC_TOKEN, repr(seen["env"]))
            self.assertNotIn("RECOVERY_TOKEN", seen["env"])

    def test_sensitive_subprocess_output_and_errors_are_suppressed(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.Skopeo(workspace)
            private = "synthetic-output-secret-never-print"
            for result, code in [
                (subprocess.CompletedProcess([], 7, stdout=private, stderr=private), "SKOPEO_INSPECT_FAILED"),
                (subprocess.CompletedProcess([], 0, stdout="x" * (recovery.MAX_TOOL_OUTPUT + 1), stderr=""), "SKOPEO_OUTPUT_LIMIT"),
            ]:
                capture = io.StringIO()
                with patch.object(subprocess, "run", return_value=result), contextlib.redirect_stdout(capture):
                    with self.assertRaises(recovery.RecoveryError) as raised:
                        runner.command(["inspect"], code=code)
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn(private, str(raised.exception))
                self.assertNotIn(private, capture.getvalue())

    def test_skopeo_timeout_and_spawn_failures_are_fixed_codes(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.Skopeo(workspace)
            with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("skopeo", 1, output="secret")):
                with self.assertRaisesRegex(recovery.RecoveryError, "SKOPEO_TIMEOUT"):
                    runner.command(["inspect"])
            with patch.object(subprocess, "run", side_effect=OSError("synthetic secret")):
                with self.assertRaisesRegex(recovery.RecoveryError, "SKOPEO_SPAWN_FAILED") as raised:
                    runner.command(["inspect"])
                self.assertNotIn("synthetic secret", str(raised.exception))

    def test_skopeo_copy_uses_exact_source_preserve_digest_no_retry_and_digest_file(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.Skopeo(workspace)
            destination = recovery._tag_reference("naxter1234/traning_lora", recovery.TAGS[0])
            digestfile = workspace.path / "copy.digest"
            seen = {}

            def fake_run(args, **kwargs):
                seen["args"] = list(args)
                digest_path = Path(args[args.index("--digestfile") + 1])
                digest_path.write_text(recovery.SOURCE_DIGEST, encoding="ascii")
                return subprocess.CompletedProcess(args, 0, stdout="synthetic output", stderr="")

            with patch.object(subprocess, "run", side_effect=fake_run):
                digest = runner.copy(recovery._source_reference(), destination, digestfile,
                                     workspace.source_auth, workspace.dest_auth)
            self.assertEqual(digest, recovery.SOURCE_DIGEST)
            self.assertEqual(seen["args"][1], "copy")
            self.assertIn("--preserve-digests", seen["args"])
            self.assertEqual(seen["args"][seen["args"].index("--retry-times") + 1], "0")
            self.assertIn(recovery._source_reference(), seen["args"])
            self.assertIn(destination, seen["args"])
            self.assertNotIn(SYNTHETIC_TOKEN, repr(seen["args"]))

    def test_skopeo_version_and_required_flags_are_validated_without_running_binary(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.Skopeo(workspace)
            required = {
                "copy --help": "--src-authfile --dest-authfile --preserve-digests --retry-times --digestfile",
                "inspect --help": "--config --authfile --retry-times",
            }

            def compatible(args, **kwargs):
                rendered = " ".join(args[1:])
                if rendered == "--version":
                    output = "skopeo version 1.4.1"
                else:
                    output = required[rendered]
                return subprocess.CompletedProcess(args, 0, stdout=output, stderr="")

            with patch.object(subprocess, "run", side_effect=compatible):
                runner.validate()

            def incompatible(args, **kwargs):
                rendered = " ".join(args[1:])
                output = "skopeo version 9.9.9" if rendered == "--version" else required[rendered]
                return subprocess.CompletedProcess(args, 0, stdout=output, stderr="")

            with patch.object(subprocess, "run", side_effect=incompatible):
                with self.assertRaisesRegex(recovery.RecoveryError, "SKOPEO_VERSION_UNSUPPORTED"):
                    runner.validate()

    def test_authfile_credential_validation_and_source_revision_are_strict(self):
        for token in ("", "space invalid", "newline\ninvalid", "naïve"):
            with self.assertRaisesRegex(recovery.RecoveryError, "CREDENTIALS_INVALID"):
                recovery._validate_credentials(recovery.WRITE_BY_ID["naxter1234"], "naxter1234", token)
        with self.assertRaisesRegex(recovery.RecoveryError, "CREDENTIALS_INVALID"):
            recovery._validate_credentials(recovery.WRITE_BY_ID["naxter1234"], "other", SYNTHETIC_TOKEN)
        with self.assertRaisesRegex(recovery.RecoveryError, "DISPATCH_NOT_AUTHORIZED"):
            recovery._workflow_context("wrong")

    def test_workflow_gate_requires_exact_repository_main_and_first_attempt(self):
        env = {"GITHUB_REPOSITORY": "ad-fiverr/krig-salad", "GITHUB_REF": "refs/heads/main",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_NUMBER": "1",
               "GITHUB_EVENT_NAME": "workflow_dispatch"}
        with patch.dict(os.environ, env, clear=True):
            if os.name == "posix":
                recovery._workflow_context(recovery.CONFIRMATION)
            else:
                with self.assertRaisesRegex(recovery.RecoveryError, "DISPATCH_NOT_AUTHORIZED"):
                    recovery._workflow_context(recovery.CONFIRMATION)
        for invalid in (
            {**env, "GITHUB_REPOSITORY": "someone/else"},
            {**env, "GITHUB_REF": "refs/heads/not-main"},
            {**env, "GITHUB_EVENT_NAME": "push"},
            {**env, "GITHUB_RUN_ATTEMPT": "2"},
            {**env, "GITHUB_RUN_NUMBER": "2"},
        ):
            with patch.dict(os.environ, invalid, clear=True):
                with self.assertRaises(recovery.RecoveryError):
                    recovery._workflow_context(recovery.CONFIRMATION)

    def test_ambiguous_unauthorized_404_is_not_absence(self):
        registry = recovery.RegistryV2()
        with patch.object(recovery.RegistryV2, "_request", return_value=recovery.HttpResult(404, {}, b"")):
            with self.assertRaisesRegex(recovery.RecoveryError, "REGISTRY_UNKNOWN"):
                registry.manifest("naxter1234/traning_lora", "latest")

    def test_authenticated_404_is_absence_only_after_scope_verified(self):
        repository = "naxter1234/traning_lora"
        challenge = (f'Bearer realm="https://auth.docker.io/token", service="registry.docker.io", '
                     f'scope="repository:{repository}:pull,push"')
        token_body = json.dumps({"token": "synthetic-bearer-token", "access": [{
            "type": "repository", "name": repository, "actions": ["pull", "push"]
        }]}).encode()
        responses = [
            recovery.HttpResult(401, {"www-authenticate": challenge}, b""),
            recovery.HttpResult(200, {}, token_body),
            recovery.HttpResult(404, {}, b""),
        ]
        registry = recovery.RegistryV2(recovery.Credentials("naxter1234", SYNTHETIC_TOKEN))
        with patch.object(recovery.RegistryV2, "_request", side_effect=responses) as request:
            self.assertIsNone(registry.manifest(repository, "latest", ("pull", "push")))
        self.assertEqual(request.call_count, 3)
        first = request.call_args_list[1].args
        self.assertEqual(first[0], "auth.docker.io")
        self.assertNotIn(SYNTHETIC_TOKEN, repr(request.call_args_list))

    def test_public_404_is_rechecked_with_account_scope_before_absence(self):
        repository = "naxter1234/traning_lora"
        token_body = json.dumps({"token": "synthetic-bearer-token", "access": [{
            "type": "repository", "name": repository, "actions": ["pull", "push"]
        }]}).encode()
        responses = [
            recovery.HttpResult(404, {}, b""),
            recovery.HttpResult(200, {}, token_body),
            recovery.HttpResult(404, {}, b""),
        ]
        registry = recovery.RegistryV2(recovery.Credentials("naxter1234", SYNTHETIC_TOKEN))
        with patch.object(recovery.RegistryV2, "_request", side_effect=responses) as request:
            self.assertIsNone(registry.manifest(repository, "latest", ("pull", "push")))
        self.assertEqual(request.call_count, 3)

    def test_registry_401_403_429_and_unknown_are_distinct(self):
        registry = recovery.RegistryV2()
        cases = [(401, "REGISTRY_CHALLENGE_INVALID"), (403, "REGISTRY_FORBIDDEN"),
                 (429, "REGISTRY_RATE_LIMITED"), (500, "REGISTRY_UNKNOWN")]
        for status, expected in cases:
            with self.subTest(status=status):
                with patch.object(recovery.RegistryV2, "_request",
                                  return_value=recovery.HttpResult(status, {}, b"synthetic provider body")):
                    with self.assertRaises(recovery.RecoveryError) as raised:
                        registry.manifest("naxter1234/traning_lora", "latest")
                self.assertEqual(raised.exception.code, expected)
                self.assertNotIn("synthetic provider body", str(raised.exception))

    def test_auth_service_401_is_not_misreported_as_missing_repository(self):
        repository = "naxter1234/traning_lora"
        challenge = (f'Bearer realm="https://auth.docker.io/token", service="registry.docker.io", '
                     f'scope="repository:{repository}:pull,push"')
        registry = recovery.RegistryV2(recovery.Credentials("naxter1234", SYNTHETIC_TOKEN))
        with patch.object(recovery.RegistryV2, "_request", side_effect=[
                recovery.HttpResult(401, {"www-authenticate": challenge}, b""),
                recovery.HttpResult(401, {}, b"synthetic-auth-body")]):
            with self.assertRaisesRegex(recovery.RecoveryError, "REGISTRY_AUTH_REJECTED"):
                registry.manifest(repository, "latest", ("pull", "push"))

    def test_registry_rejects_wrong_challenge_scope_and_insufficient_token_scope(self):
        repository = "naxter1234/traning_lora"
        wrong_challenge = 'Bearer realm="https://evil.invalid/token", service="registry.docker.io", scope="repository:naxter1234/traning_lora:pull,push"'
        registry = recovery.RegistryV2(recovery.Credentials("naxter1234", SYNTHETIC_TOKEN))
        with patch.object(recovery.RegistryV2, "_request",
                          return_value=recovery.HttpResult(401, {"www-authenticate": wrong_challenge}, b"")):
            with self.assertRaisesRegex(recovery.RecoveryError, "REGISTRY_CHALLENGE_INVALID"):
                registry.manifest(repository, "latest", ("pull", "push"))
        challenge = (f'Bearer realm="https://auth.docker.io/token", service="registry.docker.io", '
                     f'scope="repository:{repository}:pull,push"')
        body = json.dumps({"token": "synthetic-bearer-token", "access": [{
            "type": "repository", "name": repository, "actions": ["pull"]
        }]}).encode()
        with patch.object(recovery.RegistryV2, "_request", side_effect=[
                recovery.HttpResult(401, {"www-authenticate": challenge}, b""),
                recovery.HttpResult(200, {}, body)]):
            with self.assertRaisesRegex(recovery.RecoveryError, "AUTH_SCOPE_INSUFFICIENT"):
                registry.manifest(repository, "latest", ("pull", "push"))

    def test_registry_manifest_requires_digest_and_layer_structure(self):
        repository = "naxter1234/traning_lora"
        digest = SOURCE_PARSED_STATE.digest
        registry = recovery.RegistryV2()
        response = recovery.HttpResult(200, {"docker-content-digest": digest}, SOURCE_BODY)
        with patch.object(recovery.RegistryV2, "_request", return_value=response):
            value = registry.manifest(repository, "latest")
        self.assertEqual(value, SOURCE_PARSED_STATE)
        altered = SOURCE_BODY + b" "
        with patch.object(recovery.RegistryV2, "_request",
                          return_value=recovery.HttpResult(200, {"docker-content-digest": digest}, altered)):
            with self.assertRaisesRegex(recovery.RecoveryError, "REGISTRY_RESPONSE_INVALID"):
                registry.manifest(repository, "latest")

    def test_workflow_is_manual_only_fixed_scope_and_does_not_match_existing_push_triggers(self):
        workflow = (ROOT / ".github/workflows/fl4sh-three-target-recovery.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^on:\s*\n\s+workflow_dispatch:\s*$")
        self.assertNotRegex(workflow, r"(?m)^\s+(push|pull_request):")
        self.assertIn("group: build-fl4shminer-salad-main", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("skopeo=1.4.1+ds1-1ubuntu0.1", workflow)
        for target in recovery.WRITE_TARGETS:
            self.assertIn(target.repository, (ROOT / ".github/scripts/fl4sh_recover_three.py").read_text(encoding="utf-8"))
            self.assertIn("secrets." + target.username_secret, workflow)
            self.assertIn("secrets." + target.token_secret, workflow)
        for target in recovery.READ_TARGETS[:3]:
            self.assertNotIn("secrets." + target.username_secret + " }}", workflow)
            self.assertNotIn("secrets." + target.token_secret + " }}", workflow)
        first_recovery = workflow.index("id: recover_naxter1234")
        first_protected_check = workflow.index("id: verify_primary_before")
        self.assertLess(first_protected_check, first_recovery)
        self.assertLess(workflow.index("id: verify_loboeldrin_before"), first_recovery)
        self.assertLess(workflow.index("id: verify_adrianfiverr_before"), first_recovery)
        ardev_step = workflow[workflow.index("- name: Recover ardevsolutions"):workflow.index("- name: Recover boeing787")]
        boeing_step = workflow[workflow.index("- name: Recover boeing787"):workflow.index("- name: Verify published primary")]
        self.assertIn("steps.recover_naxter1234.outcome == 'success'", ardev_step)
        self.assertIn("steps.recover_naxter1234.outcome == 'success'", boeing_step)
        self.assertIn("steps.recover_ardevsolutions.outcome == 'success'", boeing_step)
        self.assertEqual(workflow.count("verify-target --target primary"), 2)
        self.assertEqual(workflow.count("verify-target --target loboeldrin"), 2)
        self.assertEqual(workflow.count("verify-target --target adrianfiverr"), 2)
        self.assertNotIn("docker build", workflow.lower())
        self.assertNotIn("docker push", workflow.lower())
        for path in (".github/workflows/build-fl4shminer.yml", ".github/workflows/build-krig.yml"):
            existing = (ROOT / path).read_text(encoding="utf-8")
            self.assertNotIn(".github/workflows/fl4sh-three-target-recovery.yml", existing)
            self.assertNotIn(".github/scripts/fl4sh_recover_three.py", existing)
            self.assertNotIn(".github/scripts/test_fl4sh_recover_three.py", existing)

    def test_workflow_initializes_results_ledger_before_all_consumers_without_runner_context_in_job_env(self):
        workflow = (ROOT / ".github/workflows/fl4sh-three-target-recovery.yml").read_text(encoding="utf-8")
        job_env = re.search(r"(?ms)^    env:\n(?P<body>(?:^      [^\n]*\n)*)", workflow)
        if job_env:
            self.assertNotRegex(job_env.group("body"), r"\$\{\{\s*runner\.")
        self.assertNotIn("${{ runner.temp }}", workflow)

        initialize = workflow.index("- name: Initialize one-shot recovery ledger")
        first_preflight = workflow.index("- name: Preflight naxter1234")
        init_step = workflow[initialize:first_preflight]
        self.assertIn(
            "printf 'RECOVERY_RESULTS=%s/fl4sh-three-target-recovery.json\\n' \"$RUNNER_TEMP\" >> \"$GITHUB_ENV\"",
            init_step,
        )
        self.assertIn(
            'init \\\n            --results "$RUNNER_TEMP/fl4sh-three-target-recovery.json"',
            init_step,
        )

        consumers = [match.start() for match in re.finditer(r'--results "\$RECOVERY_RESULTS"', workflow)]
        self.assertTrue(consumers)
        self.assertTrue(all(position > first_preflight for position in consumers))
        self.assertLess(initialize, first_preflight)

    def test_no_publisher_or_build_dependency_is_used_for_writes(self):
        source = (ROOT / ".github/scripts/fl4sh_recover_three.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?i)docker\s+(build|push|tag)\b")
        self.assertIn("--preserve-digests", source)
        self.assertIn('"--retry-times", "0"', source)
        self.assertIn("SOURCE_DIGEST", source)
        self.assertEqual(recovery.WRITE_TARGETS, tuple(recovery.READ_TARGETS[3:]))

    def test_low_level_copy_rejects_any_repository_outside_write_allowlist(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.Skopeo(workspace)
            with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
                recovery._tag_reference("myblockchaincompany/fl4shminer-salad", "latest")
            with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
                runner.copy(recovery._source_reference(),
                            "docker://docker.io/myblockchaincompany/fl4shminer-salad:latest",
                            workspace.path / "copy.digest", workspace.source_auth, workspace.dest_auth)


class _WrongPlatformSkopeo(FakeSkopeo):
    def inspect_config(self, reference, authfile):
        return config(architecture="arm64")


class RegistryTransportTests(unittest.TestCase):
    def setUp(self):
        self.guard = patch.object(socket, "socket", side_effect=AssertionError("network socket forbidden"))
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def test_https_transport_is_fixed_host_tls_get_and_blocks_redirect(self):
        seen = {}

        class Response:
            status = 302

            def read(self, _limit):
                return b""

            def getheaders(self):
                return [("Location", "https://evil.invalid")]

        class Connection:
            def __init__(self, host, port, *, timeout, context):
                seen["host"] = host
                seen["port"] = port
                seen["timeout"] = timeout
                seen["tls"] = isinstance(context, type(recovery.ssl.create_default_context()))

            def request(self, method, path, *, headers):
                seen["method"] = method
                seen["path"] = path

            def getresponse(self):
                return Response()

            def close(self):
                pass

        with patch.object(recovery.http.client, "HTTPSConnection", Connection):
            with self.assertRaisesRegex(recovery.RecoveryError, "REGISTRY_REDIRECT_BLOCKED"):
                recovery.RegistryV2._request("registry-1.docker.io", "/v2/example/image/manifests/tag", {})
        self.assertEqual(seen["host"], "registry-1.docker.io")
        self.assertEqual(seen["port"], 443)
        self.assertEqual(seen["method"], "GET")
        with self.assertRaisesRegex(recovery.RecoveryError, "REGISTRY_UNKNOWN"):
            recovery.RegistryV2._request("evil.invalid", "/v2/anything", {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
