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
        self.docker_calls = []
        self.write_calls = []
        self.fail_push_tag = None
        self.fail_tag_tag = None
        self.fail_login = False
        self.fail_logout = False
        self.inject_competing_tag_after_first_push = False
        self.competing_tag_visible = False
        self.mutate_tag_on_read = None
        self.mutate_tag_read_number = 3
        self.tag_read_counts = {}
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
        key = (repository, reference)
        self.tag_read_counts[key] = self.tag_read_counts.get(key, 0) + 1
        if (key == self.mutate_tag_on_read
                and self.tag_read_counts[key] == self.mutate_tag_read_number):
            return recovery.ManifestState("sha256:" + "f" * 64, "sha256:" + "e" * 64,
                                          "competing-content", 2)
        return self.tags.get(repository, {}).get(reference)

    def put_from_push(self, destination, tag):
        self.write_calls.append((destination, tag))
        if tag == self.fail_push_tag:
            raise recovery.RecoveryError("DOCKER_PUSH_FAILED", phase="DOCKER_PUSH",
                                         failure_class="NONZERO_EXIT")
        repository = destination.removeprefix("docker.io/").rsplit(":", 1)[0]
        self.tags[repository][tag] = SOURCE_STATE
        if tag == recovery.TAGS[0] and self.inject_competing_tag_after_first_push:
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


def docker_image(*, revision=recovery.SOURCE_REVISION, architecture="amd64", os_name="linux"):
    return {
        "Id": recovery.SOURCE_CONFIG_DIGEST,
        "Os": os_name,
        "Architecture": architecture,
        "Config": {"Labels": {
            "org.opencontainers.image.revision": revision,
            "org.opencontainers.image.source": recovery.SOURCE_URL,
            "org.opencontainers.image.version": recovery.VERSION,
        }},
        "RootFS": {"Type": "layers", "Layers": list(DIFF_IDS)},
        "RepoDigests": [recovery.SOURCE_REPOSITORY + "@" + recovery.SOURCE_DIGEST],
    }


class FakeDocker:
    def __init__(self, workspace, world, config_path=None):
        self.workspace = workspace
        self.world = world
        self.config_path = config_path or workspace.source_config

    def pull_source(self, reference):
        self.world.docker_calls.append(("pull", reference))
        if reference != recovery._source_reference():
            raise recovery.RecoveryError("SOURCE_IDENTITY_INVALID")

    def inspect_source(self, reference):
        self.world.docker_calls.append(("inspect", reference))
        return docker_image(revision=self.world.config_revision)

    def login(self, credentials):
        self.world.docker_calls.append(("login", credentials.username))
        if self.world.fail_login:
            raise recovery.RecoveryError("DOCKER_LOGIN_FAILED", phase="DOCKER_LOGIN",
                                         failure_class="NONZERO_EXIT")

    def tag(self, image_id, destination):
        self.world.docker_calls.append(("tag", image_id, destination))
        if image_id != recovery.SOURCE_CONFIG_DIGEST:
            raise recovery.RecoveryError("IMAGE_IDENTITY_INVALID")
        tag = destination.rsplit(":", 1)[1]
        if tag == self.world.fail_tag_tag:
            raise recovery.RecoveryError("DOCKER_TAG_FAILED", phase="DOCKER_TAG",
                                         failure_class="NONZERO_EXIT")

    def push(self, destination):
        self.world.docker_calls.append(("push", destination))
        tag = destination.rsplit(":", 1)[1]
        self.world.put_from_push(destination, tag)

    def logout(self):
        self.world.docker_calls.append(("logout",))
        if self.world.fail_logout:
            raise recovery.RecoveryError("DOCKER_LOGOUT_FAILED", phase="DOCKER_LOGOUT",
                                         failure_class="NONZERO_EXIT")


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
            docker_factory=lambda workspace, config_path=None: FakeDocker(workspace, self.world, config_path),
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
        self.assertEqual(self.world.write_calls, [])
        row = recovery._read_results(self.results)["preflight"]["naxter1234"]
        self.assertEqual(row["failure_code"], "SOURCE_IDENTITY_INVALID")

    def test_wrong_source_revision_blocks_before_copy(self):
        self.world.config_revision = "0" * 40
        with self.assertRaisesRegex(recovery.RecoveryError, "IMAGE_IDENTITY_INVALID"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])

    def test_wrong_platform_blocks_before_copy(self):
        # The image inspection must fail closed for a non-amd64 source.
        original_factory = self.controller.docker_factory
        self.controller.docker_factory = lambda workspace, config_path=None: _WrongPlatformDocker(workspace, self.world, config_path)
        with self.assertRaisesRegex(recovery.RecoveryError, "IMAGE_IDENTITY_INVALID"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.controller.docker_factory = original_factory
        self.assertEqual(self.world.write_calls, [])

    def test_layer_count_mismatch_blocks_before_copy(self):
        self.world.source_state = recovery.ManifestState(
            recovery.SOURCE_DIGEST, recovery.SOURCE_CONFIG_DIGEST, CONTENT_HASH, 3)
        with self.assertRaisesRegex(recovery.RecoveryError, "IMAGE_IDENTITY_INVALID"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])

    def test_existing_conflicting_sha_tag_blocks_without_writes(self):
        self.world.tags["naxter1234/traning_lora"][recovery.TAGS[0]] = recovery.ManifestState(
            "sha256:" + "f" * 64, "sha256:" + "e" * 64, "bad-content", 2)
        with self.assertRaisesRegex(recovery.RecoveryError, "TAG_CONFLICT"):
            self.controller.preflight("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])

    def test_equivalent_reencoded_manifest_is_already_present_without_rewrite(self):
        repository = "naxter1234/traning_lora"
        reencoded = recovery.ManifestState("sha256:" + "9" * 64, SOURCE_STATE.config,
                                           SOURCE_STATE.content_hash, SOURCE_STATE.layer_count)
        self.world.tags[repository][recovery.TAGS[0]] = reencoded
        preflight = self.controller.preflight("naxter1234", self.results,
                                              *self.credentials("naxter1234"))
        self.assertEqual(preflight["tags"][recovery.TAGS[0]], {
            "status": "ALREADY_PRESENT", "digest": reencoded.digest,
        })
        for target_id in recovery.TARGET_IDS[1:]:
            self.controller.preflight(target_id, self.results, *self.credentials(target_id))
        self.verify_protected_targets()
        result = self.controller.recover("naxter1234", self.results,
                                         *self.credentials("naxter1234"))
        self.assertEqual(result["status"], "TARGET_VERIFIED")
        self.assertEqual(len(self.world.write_calls), 2)
        target_row = recovery._read_results(self.results)["targets"]["naxter1234"]
        self.assertEqual(target_row["tags"][recovery.TAGS[0]]["status"], "ALREADY_PRESENT")
        self.assertEqual(target_row["tags"][recovery.TAGS[0]]["digest"], reencoded.digest)

    def test_protected_tag_with_reencoded_manifest_digest_fails_exact_digest_check(self):
        target = recovery.READ_BY_ID["primary"]
        self.world.tags[target.repository][recovery.TAGS[0]] = recovery.ManifestState(
            "sha256:" + "9" * 64, SOURCE_STATE.config,
            SOURCE_STATE.content_hash, SOURCE_STATE.layer_count)

        result = self.controller.verify_target("primary", self.results)

        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(result["tags"][recovery.TAGS[0]]["status"], "CONFLICT")
        self.assertEqual(self.world.write_calls, [])

    def test_protected_digest_drift_blocks_recovery_before_destination_push(self):
        self.preflight_all()
        self.verify_protected_targets()
        protected = recovery.READ_BY_ID["loboeldrin"]
        self.world.tags[protected.repository][recovery.TAGS[1]] = recovery.ManifestState(
            "sha256:" + "8" * 64, SOURCE_STATE.config,
            SOURCE_STATE.content_hash, SOURCE_STATE.layer_count)

        with self.assertRaisesRegex(recovery.RecoveryError, "PROTECTED_TARGET_DRIFT"):
            self.controller.recover("naxter1234", self.results,
                                    *self.credentials("naxter1234"))

        self.assertEqual(self.world.write_calls, [])

    def test_protected_snapshot_ledger_requires_exact_source_digest(self):
        self.preflight_all()
        self.verify_protected_targets()
        data = recovery._read_results(self.results)
        data["verification"]["primary"]["tags"][recovery.TAGS[0]]["digest"] = "sha256:" + "9" * 64
        recovery._write_results(self.results, data)

        with self.assertRaisesRegex(recovery.RecoveryError, "PROTECTED_TARGETS_UNVERIFIED"):
            self.controller.recover("naxter1234", self.results,
                                    *self.credentials("naxter1234"))

        self.assertEqual(self.world.write_calls, [])

    def test_final_six_target_audit_rejects_protected_digest_changes(self):
        for target in recovery.WRITE_TARGETS:
            self.world.tags[target.repository] = {
                tag: SOURCE_STATE for tag in recovery.TAGS
            }
        protected = recovery.READ_BY_ID["adrianfiverr"]
        self.world.tags[protected.repository][recovery.TAGS[2]] = recovery.ManifestState(
            "sha256:" + "7" * 64, SOURCE_STATE.config,
            SOURCE_STATE.content_hash, SOURCE_STATE.layer_count)

        self.run_verification_all()
        results = recovery._read_results(self.results)

        self.assertEqual(results["verification"]["adrianfiverr"]["status"], "BLOCKED")
        self.assertEqual(recovery._summary(results)["status"], "BLOCKED")
        self.assertEqual(self.world.write_calls, [])

    def test_concurrent_change_to_initially_present_tag_stops_without_later_pushes(self):
        self.preflight_all()
        self.verify_protected_targets()
        repository = recovery.WRITE_BY_ID["naxter1234"].repository
        for tag in recovery.TAGS[:2]:
            self.world.tags[repository][tag] = recovery.ManifestState(
                "sha256:" + "9" * 64, SOURCE_STATE.config,
                SOURCE_STATE.content_hash, SOURCE_STATE.layer_count)
        self.world.mutate_tag_on_read = (repository, recovery.TAGS[1])

        with self.assertRaisesRegex(recovery.RecoveryError, "TAG_CONFLICT"):
            self.controller.recover("naxter1234", self.results,
                                    *self.credentials("naxter1234"))

        row = recovery._read_results(self.results)["targets"]["naxter1234"]
        self.assertEqual(self.world.write_calls, [])
        self.assertEqual(row["tags"][recovery.TAGS[0]]["status"], "ALREADY_PRESENT")
        self.assertEqual(row["tags"][recovery.TAGS[0]]["digest"], "sha256:" + "9" * 64)
        self.assertEqual(row["tags"][recovery.TAGS[1]]["status"], "CONFLICT")
        self.assertEqual(row["status"], "PARTIAL_PUBLICATION")

    def test_verification_preserves_authorized_404_as_absence_not_unknown_error(self):
        result = self.controller.verify_target("naxter1234", self.results)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertIsNone(result["failure_code"])
        self.assertTrue(all(result["tags"][tag] == {"status": "ABSENT_HTTP404", "digest": None}
                            for tag in recovery.TAGS))
        row = recovery._read_results(self.results)["verification"]["naxter1234"]
        self.assertEqual(row["status"], "UNKNOWN")
        self.assertEqual(self.world.write_calls, [])

    def test_recovery_only_changes_selected_allowed_destination(self):
        before = {repo: dict(tags) for repo, tags in self.world.tags.items()}
        self.preflight_all()
        self.verify_protected_targets()
        result = self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(result["status"], "TARGET_VERIFIED")
        self.assertEqual([tag for _repo, tag in self.world.write_calls], list(recovery.TAGS))
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
        self.assertEqual(self.world.write_calls, [])

    def test_competing_tag_after_first_copy_is_recorded_as_partial_and_not_overwritten(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.inject_competing_tag_after_first_push = True
        with self.assertRaisesRegex(recovery.RecoveryError, "TAG_CONFLICT"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual([tag for _repo, tag in self.world.write_calls], [recovery.TAGS[0]])
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
        self.world.fail_push_tag = recovery.TAGS[1]
        with self.assertRaisesRegex(recovery.RecoveryError, "DOCKER_PUSH_FAILED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual([tag for _repo, tag in self.world.write_calls], list(recovery.TAGS[:2]))
        row = recovery._read_results(self.results)["targets"]["naxter1234"]
        self.assertEqual(row["status"], "PARTIAL_PUBLICATION")
        self.assertTrue(row["attempted"])
        self.assertEqual(row["tags"][recovery.TAGS[1]]["status"], "UNKNOWN")
        with self.assertRaisesRegex(recovery.RecoveryError, "RUN_ALREADY_ATTEMPTED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(len(self.world.write_calls), 2)

    def test_later_target_is_blocked_after_previous_target_partial_failure(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.fail_push_tag = recovery.TAGS[1]
        with self.assertRaisesRegex(recovery.RecoveryError, "DOCKER_PUSH_FAILED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        writes_before = list(self.world.write_calls)
        with self.assertRaisesRegex(recovery.RecoveryError, "RECOVERY_SEQUENCE_BLOCKED"):
            self.controller.recover("ardevsolutions", self.results, *self.credentials("ardevsolutions"))
        self.assertEqual(self.world.write_calls, writes_before)
        self.assertFalse(recovery._read_results(self.results)["targets"]["ardevsolutions"]["attempted"])

    def test_recovery_requires_protected_targets_verified_before_any_write(self):
        self.preflight_all()
        with self.assertRaisesRegex(recovery.RecoveryError, "PROTECTED_TARGETS_UNVERIFIED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])

    def test_protected_target_drift_is_rechecked_before_each_recovery_target(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.tags[recovery.READ_BY_ID["primary"].repository][recovery.TAGS[0]] = None
        with self.assertRaisesRegex(recovery.RecoveryError, "PROTECTED_TARGET_DRIFT"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])

    def test_recovery_requires_all_three_preflights(self):
        with self.assertRaisesRegex(recovery.RecoveryError, "PREFLIGHT_INCOMPLETE"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])

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

    def test_destination_configs_are_isolated_private_and_cleaned(self):
        with recovery.PrivateWorkspace() as workspace:
            first = workspace.destination_config("naxter1234")
            second = workspace.destination_config("ardevsolutions")
            self.assertNotEqual(first, second)
            self.assertEqual(first.parent, workspace.path)
            self.assertEqual(second.parent, workspace.path)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o700)
            first_path = first
            workspace_path = workspace.path
        self.assertFalse(workspace_path.exists())
        self.assertFalse(first_path.exists())

    def test_docker_login_secret_uses_stdin_not_argv_or_environment(self):
        with recovery.PrivateWorkspace() as workspace:
            config_path = workspace.destination_config("naxter1234")
            runner = recovery.DockerCLI(workspace, config_path)
            seen = {}

            def fake_run(args, **kwargs):
                seen["args"] = list(args)
                seen["env"] = dict(kwargs["env"])
                seen["stdin"] = kwargs["input"]
                return subprocess.CompletedProcess(args, 0, stdout="safe", stderr="")

            with patch.object(subprocess, "run", side_effect=fake_run):
                runner.login(recovery.Credentials(SYNTHETIC_USERNAME, SYNTHETIC_TOKEN))
            self.assertEqual(seen["args"][:3], ["docker", "login", "docker.io"])
            self.assertNotIn(SYNTHETIC_TOKEN, repr(seen["args"]))
            self.assertNotIn(SYNTHETIC_TOKEN, repr(seen["env"]))
            self.assertNotIn("RECOVERY_TOKEN", seen["env"])
            self.assertNotIn("DOCKER_HOST", seen["env"])
            self.assertEqual(seen["stdin"], SYNTHETIC_TOKEN + "\n")
            self.assertEqual(seen["env"]["DOCKER_CONFIG"], str(config_path))
        self.assertFalse(config_path.exists())

    def test_docker_source_pull_uses_exact_digest_and_inspect_validates_identity(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.DockerCLI(workspace)
            seen = []

            def fake_run(args, **kwargs):
                seen.append(list(args))
                if args[1] == "image":
                    return subprocess.CompletedProcess(args, 0,
                        stdout=json.dumps(docker_image()), stderr="")
                return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

            with patch.object(subprocess, "run", side_effect=fake_run):
                runner.pull_source(recovery._source_reference())
                image = runner.inspect_source(recovery._source_reference())
                identity = recovery._docker_image_identity(image)
            self.assertEqual(seen[0], ["docker", "pull", "--platform", "linux/amd64", "--quiet",
                                       recovery._source_reference()])
            self.assertIn(recovery.SOURCE_DIGEST, seen[0][-1])
            self.assertEqual(identity["config_digest"], recovery.SOURCE_CONFIG_DIGEST)
            with self.assertRaisesRegex(recovery.RecoveryError, "SOURCE_IDENTITY_INVALID"):
                runner.pull_source("docker.io/myblockchaincompany/fl4shminer-salad:latest")

    def test_docker_subprocess_failure_classes_are_fixed_and_redacted(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.DockerCLI(workspace)
            private = "synthetic-output-secret-never-print"
            cases = [
                (subprocess.CompletedProcess([], 7, stdout=private, stderr=private),
                 "DOCKER_PUSH_FAILED", "NONZERO_EXIT"),
                (subprocess.CompletedProcess([], 0, stdout="x" * (recovery.MAX_TOOL_OUTPUT + 1), stderr=""),
                 "DOCKER_OUTPUT_LIMIT", "OUTPUT_LIMIT"),
            ]
            for result, code, failure_class in cases:
                capture = io.StringIO()
                with patch.object(subprocess, "run", return_value=result), contextlib.redirect_stdout(capture):
                    with self.assertRaises(recovery.RecoveryError) as raised:
                        runner.command(["docker", "push", "synthetic"], phase="DOCKER_PUSH")
                self.assertEqual((raised.exception.code, raised.exception.phase,
                                  raised.exception.failure_class), (code, "DOCKER_PUSH", failure_class))
                self.assertNotIn(private, str(raised.exception))
                self.assertNotIn(private, capture.getvalue())

            with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("docker", 1, output=private)):
                with self.assertRaises(recovery.RecoveryError) as raised:
                    runner.command(["docker", "push", "synthetic"], phase="DOCKER_PUSH")
            self.assertEqual(raised.exception.failure_class, "TIMEOUT")
            with patch.object(subprocess, "run", side_effect=OSError(private)):
                with self.assertRaises(recovery.RecoveryError) as raised:
                    runner.command(["docker", "push", "synthetic"], phase="DOCKER_PUSH")
            self.assertEqual(raised.exception.failure_class, "SPAWN_ERROR")
            self.assertNotIn(private, str(raised.exception))
            with patch.object(subprocess, "run", side_effect=RuntimeError(private)):
                with self.assertRaises(recovery.RecoveryError) as raised:
                    runner.command(["docker", "push", "synthetic"], phase="DOCKER_PUSH")
            self.assertEqual(raised.exception.failure_class, "UNKNOWN")
            self.assertNotIn(private, str(raised.exception))

    def test_docker_login_tag_push_logout_keep_phase_specific_codes(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.DockerCLI(workspace)
            for phase, method, expected in (
                ("DOCKER_LOGIN", lambda: runner.login(recovery.Credentials(SYNTHETIC_USERNAME, SYNTHETIC_TOKEN)), "DOCKER_LOGIN_FAILED"),
                ("DOCKER_TAG", lambda: runner.tag(recovery.SOURCE_CONFIG_DIGEST,
                    recovery._tag_reference("naxter1234/traning_lora", "latest")), "DOCKER_TAG_FAILED"),
                ("DOCKER_PUSH", lambda: runner.push(recovery._tag_reference("naxter1234/traning_lora", "latest")), "DOCKER_PUSH_FAILED"),
                ("DOCKER_LOGOUT", runner.logout, "DOCKER_LOGOUT_FAILED"),
            ):
                with self.subTest(phase=phase), patch.object(subprocess, "run",
                        return_value=subprocess.CompletedProcess([], 1, stdout="private", stderr="private")):
                    with self.assertRaises(recovery.RecoveryError) as raised:
                        method()
                self.assertEqual(raised.exception.code, expected)
                self.assertEqual(raised.exception.phase, phase)
                self.assertEqual(raised.exception.failure_class, "NONZERO_EXIT")

    def test_logout_failure_never_replaces_primary_push_failure(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.fail_push_tag = recovery.TAGS[1]
        self.world.fail_logout = True
        with self.assertRaises(recovery.RecoveryError) as raised:
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(raised.exception.code, "DOCKER_PUSH_FAILED")
        self.assertEqual(raised.exception.phase, "DOCKER_PUSH")
        self.assertEqual(raised.exception.secondary_failure_code, "DOCKER_LOGOUT_FAILED")
        row = recovery._read_results(self.results)["targets"]["naxter1234"]
        self.assertEqual(row["failure_code"], "DOCKER_PUSH_FAILED")
        self.assertEqual(row["logout_failure_code"], "DOCKER_LOGOUT_FAILED")
        self.assertNotIn(SYNTHETIC_TOKEN, self.results.read_text(encoding="utf-8"))

    def test_login_failure_stops_before_destination_writes_and_cleanup_runs(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.fail_login = True
        with self.assertRaisesRegex(recovery.RecoveryError, "DOCKER_LOGIN_FAILED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])
        self.assertEqual(self.world.docker_calls[-1], ("logout",))

    def test_tag_failure_is_distinct_and_does_not_start_push(self):
        self.preflight_all()
        self.verify_protected_targets()
        self.world.fail_tag_tag = recovery.TAGS[0]
        with self.assertRaisesRegex(recovery.RecoveryError, "DOCKER_TAG_FAILED"):
            self.controller.recover("naxter1234", self.results, *self.credentials("naxter1234"))
        self.assertEqual(self.world.write_calls, [])
        self.assertFalse(any(call[0] == "push" for call in self.world.docker_calls))

    def test_no_skopeo_or_build_dependency_remains(self):
        source = (ROOT / ".github/scripts/fl4sh_recover_three.py").read_text(encoding="utf-8").lower()
        workflow = (ROOT / ".github/workflows/fl4sh-three-target-recovery.yml").read_text(encoding="utf-8").lower()
        self.assertNotIn("skopeo", source)
        self.assertNotIn("skopeo", workflow)
        self.assertNotRegex(source, r"docker\s+(build|buildx)\b")
        self.assertNotRegex(workflow, r"docker\s+(build|buildx|push|tag)\b")

    def test_credential_validation_and_source_revision_are_strict(self):
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
                with patch.dict(os.environ, {**env, "GITHUB_RUN_NUMBER": "42"}, clear=True):
                    recovery._workflow_context(recovery.CONFIRMATION)
            else:
                with self.assertRaisesRegex(recovery.RecoveryError, "DISPATCH_NOT_AUTHORIZED"):
                    recovery._workflow_context(recovery.CONFIRMATION)
        for invalid in (
            {**env, "GITHUB_REPOSITORY": "someone/else"},
            {**env, "GITHUB_REF": "refs/heads/not-main"},
            {**env, "GITHUB_EVENT_NAME": "push"},
            {**env, "GITHUB_RUN_ATTEMPT": "2"},
            {**env, "GITHUB_RUN_NUMBER": "0"},
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
        self.assertNotIn("skopeo", workflow.lower())
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

    def test_only_docker_cli_source_and_fixed_write_allowlist_are_used(self):
        source = (ROOT / ".github/scripts/fl4sh_recover_three.py").read_text(encoding="utf-8")
        self.assertNotRegex(source, r"(?i)docker\s+(build|buildx)\b")
        self.assertNotIn("skopeo", source.lower())
        self.assertIn('["docker", "push", "--quiet", destination]', source)
        self.assertIn('["docker", "tag", image_id, destination]', source)
        self.assertIn("SOURCE_DIGEST", source)
        self.assertEqual(recovery.WRITE_TARGETS, tuple(recovery.READ_TARGETS[3:]))

    def test_low_level_docker_tag_and_push_reject_protected_repositories(self):
        with recovery.PrivateWorkspace() as workspace:
            runner = recovery.DockerCLI(workspace)
            with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
                recovery._tag_reference("myblockchaincompany/fl4shminer-salad", "latest")
            with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
                runner.tag(recovery.SOURCE_CONFIG_DIGEST,
                           "docker.io/myblockchaincompany/fl4shminer-salad:latest")
            with self.assertRaisesRegex(recovery.RecoveryError, "TARGET_NOT_ALLOWED"):
                runner.push("docker.io/myblockchaincompany/fl4shminer-salad:latest")


class _WrongPlatformDocker(FakeDocker):
    def inspect_source(self, reference):
        return docker_image(architecture="arm64")


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
