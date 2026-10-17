#!/usr/bin/env python3
"""Offline fanout acceptance. No real Docker command or socket is allowed."""

from __future__ import annotations

from copy import deepcopy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("fl4sh_publish", ROOT / ".github/scripts/fl4sh_publish.py")
P = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = P
SPEC.loader.exec_module(P)
REVISION = "1" * 40
IMAGE_ID = "sha256:" + "2" * 64
DIFF_ID = "sha256:" + "3" * 64
SYNTHETIC_TOKEN = "synthetic-private-token-never-send"
CONFIG = ROOT / ".github/fl4sh-publish-targets.json"


def raw_image():
    return {"Id": IMAGE_ID, "Os": "linux", "Architecture": "amd64", "RootFS": {"Layers": [DIFF_ID]},
        "Config": {"Labels": {"org.opencontainers.image.revision": REVISION,
        "org.opencontainers.image.source": P.SOURCE, "org.opencontainers.image.version": P.VERSION}}}


def evidence():
    return {**P.image_identity(raw_image(), REVISION), "smoke_passed": True}


def manifest(*, config=IMAGE_ID, padding=False, layer="4"):
    data = {"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"digest": config, "size": 500, "mediaType": "application/vnd.docker.container.image.v1+json"},
        "layers": [{"digest": "sha256:" + layer * 64, "size": 1000, "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip"}]}
    body = json.dumps(data, indent=2 if padding else None).encode()
    import hashlib
    return body, "sha256:" + hashlib.sha256(body).hexdigest()


class FakeRegistry:
    def __init__(self, *, padding=False):
        self.expected = P.parse_manifest(*manifest(padding=padding))
        self.entries = {tag: None for tag in P.tags(REVISION)}
        self.calls = []
        self.error = None

    def manifest(self, tag):
        self.calls.append(tag)
        if self.error:
            raise self.error
        return self.entries[tag]


class FakeDocker:
    def __init__(self, registry):
        self.registry = registry
        self.calls = []
        self.identity = {k: v for k, v in evidence().items() if k != "smoke_passed"}
        self.stale_at = None
        self.main_checks = 0
        self.fail_tag = None
        self.login_failure = False
        self.pull_identity_invalid = False
        self.logout_failure = False

    def assert_current_main(self):
        self.main_checks += 1
        self.calls.append(("main",))
        if self.stale_at == self.main_checks:
            raise P.Rejected("NOT_CURRENT_MAIN")

    def inspect(self, ref):
        self.calls.append(("inspect", ref))
        identity = deepcopy(self.identity)
        if "@" in ref and self.pull_identity_invalid:
            identity["source"] = "synthetic-wrong-source"
        return identity

    def login(self, username, token):
        self.calls.append(("login", username))
        if self.login_failure:
            raise RuntimeError(SYNTHETIC_TOKEN)

    def logout(self):
        self.calls.append(("logout",))
        if self.logout_failure:
            raise RuntimeError(SYNTHETIC_TOKEN)

    def push(self, image_id, ref):
        self.calls.append(("push", image_id, ref))
        tag = ref.rsplit(":", 1)[1]
        if self.fail_tag == tag:
            raise RuntimeError(SYNTHETIC_TOKEN)
        self.registry.entries[tag] = self.registry.expected

    def pull(self, ref):
        self.calls.append(("pull", ref))


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch("socket.socket", side_effect=AssertionError("offline test attempted a socket")).start()
        patch.object(subprocess, "run", side_effect=AssertionError("offline test attempted a subprocess")).start()
        patch.dict(os.environ, {"GITHUB_SHA": REVISION}, clear=False).start()
        self.targets = P.load_targets(CONFIG)

    def run_target(self, target=None, *, registry=None, docker=None, data=None, username=None, token=SYNTHETIC_TOKEN):
        target = target or self.targets[0]
        registry = registry or FakeRegistry()
        docker = docker or FakeDocker(registry)
        result = P.publish(target, data or evidence(), target.username if username is None else username, token,
            docker=docker, registry=registry)
        self.assertNotIn(SYNTHETIC_TOKEN, json.dumps(result))
        return result, docker, registry

    def test_exact_six_destinations_twelve_unique_aliases_and_original_primary(self):
        self.assertEqual(len(self.targets), 6)
        self.assertEqual(self.targets[0].image, "docker.io/myblockchaincompany/fl4shminer-salad")
        self.assertEqual((self.targets[0].username_secret, self.targets[0].token_secret), ("DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"))
        self.assertEqual(len({v for t in self.targets for v in (t.username_secret, t.token_secret)}), 12)

    def test_duplicate_unapproved_repo_wrong_alias_and_account_fail_closed(self):
        for mutation in ("duplicate", "repo", "alias", "username", "extra", "schema"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                data = json.loads(CONFIG.read_text())
                if mutation == "duplicate": data["targets"][1] = data["targets"][0]
                if mutation == "repo": data["targets"][1]["repository"] = "other/unapproved"
                if mutation == "alias": data["targets"][1]["token_secret"] = "DOCKERHUB_TOKEN"
                if mutation == "username": data["targets"][1]["username"] = "other"
                if mutation == "extra": data["targets"].append(data["targets"][0])
                if mutation == "schema": data["schema_version"] = True
                path = Path(temporary) / "targets.json"
                path.write_text(json.dumps(data))
                with self.assertRaisesRegex(ValueError, "^TARGET_ALLOWLIST_INVALID$"):
                    P.load_targets(path)

    def test_six_accounts_reuse_identical_tested_image_no_build_and_report_distinct_manifests(self):
        results = {}
        manifests = set()
        for index, target in enumerate(self.targets):
            registry = FakeRegistry(padding=index % 2 == 1)
            result, docker, _ = self.run_target(target, registry=registry)
            self.assertEqual(result["status"], "PUBLISHED")
            self.assertEqual(list(result["tags"]), list(P.tags(REVISION)))
            self.assertEqual({v["digest"] for v in result["tags"].values()}, {result["manifest_digest"]})
            self.assertEqual(len([v for v in docker.calls if v[0] == "push"]), 3)
            self.assertTrue(all(v[1] == IMAGE_ID for v in docker.calls if v[0] == "push"))
            self.assertFalse(any(v[0] in {"build", "smoke"} for v in docker.calls))
            self.assertEqual(docker.calls[-1], ("logout",))
            results[target.id] = result
            manifests.add(result["manifest_digest"])
        summary, ok = P.summarize(self.targets, evidence(), results)
        self.assertTrue(ok)
        self.assertEqual(len(manifests), 2, "equivalent config/layers need not have identical manifest encoding")
        for target in self.targets: self.assertIn(target.image, summary)

    def test_missing_wrong_or_invalid_credentials_do_not_login_push_or_query_registry(self):
        for username, token, code in (("", "", "CREDENTIALS_MISSING"), ("wrong", SYNTHETIC_TOKEN, "USERNAME_MISMATCH"),
            (self.targets[0].username, "", "CREDENTIALS_MISSING"), (self.targets[0].username, "a b", "CREDENTIALS_INVALID"),
            (self.targets[0].username, "bad\nvalue", "CREDENTIALS_INVALID"), (self.targets[0].username, "no-ASCII-é", "CREDENTIALS_INVALID")):
            with self.subTest(code=code):
                result, docker, registry = self.run_target(username=username, token=token)
                self.assertEqual(result["failure_code"], code)
                self.assertEqual(docker.calls, [])
                self.assertEqual(registry.calls, [])

    def test_unsealed_or_changed_image_never_publishes(self):
        data = evidence(); data["smoke_passed"] = False
        result, docker, _ = self.run_target(data=data)
        self.assertEqual(result["failure_code"], "SMOKE_NOT_PASSED")
        registry = FakeRegistry(); docker = FakeDocker(registry); docker.identity["image_id"] = "sha256:" + "9" * 64
        result, docker, _ = self.run_target(registry=registry, docker=docker)
        self.assertEqual(result["failure_code"], "LOCAL_IMAGE_CHANGED")
        self.assertFalse(any(c[0] == "login" for c in docker.calls))

    def test_platform_oci_revision_source_and_version_are_mandatory(self):
        changes = (("Os", "windows"), ("Architecture", "arm64"), ("Id", "invalid"))
        for field, value in changes:
            raw = raw_image(); raw[field] = value
            with self.assertRaises(P.Rejected): P.image_identity(raw, REVISION)
        for field in ("revision", "source", "version"):
            raw = raw_image(); raw["Config"]["Labels"]["org.opencontainers.image." + field] = "wrong"
            with self.assertRaisesRegex(P.Rejected, "LOCAL_IMAGE_INVALID"): P.image_identity(raw, REVISION)

    def test_stale_run_cannot_authenticate_or_change_tags(self):
        registry = FakeRegistry(); docker = FakeDocker(registry); docker.stale_at = 1
        result, docker, registry = self.run_target(docker=docker, registry=registry)
        self.assertEqual(result["failure_code"], "NOT_CURRENT_MAIN")
        self.assertEqual(docker.calls, [("main",)])
        self.assertEqual(registry.calls, [])

    def test_main_is_revalidated_before_each_tag_and_partial_state_is_retained(self):
        registry = FakeRegistry(); docker = FakeDocker(registry); docker.stale_at = 3
        result, docker, _ = self.run_target(docker=docker, registry=registry)
        self.assertEqual(result["failure_code"], "NOT_CURRENT_MAIN")
        self.assertEqual(result["tags"][P.tags(REVISION)[1]]["status"], "PUBLISHED")
        self.assertEqual(result["tags"][P.VERSION]["status"], "PENDING")
        self.assertEqual(len([v for v in docker.calls if v[0] == "push"]), 1)

    def test_exact_content_retry_is_idempotent_without_repush(self):
        registry = FakeRegistry(); registry.entries = {tag: registry.expected for tag in P.tags(REVISION)}
        result, docker, _ = self.run_target(registry=registry)
        self.assertEqual(result["status"], "PUBLISHED")
        self.assertEqual({v["status"] for v in result["tags"].values()}, {"ALREADY_PRESENT"})
        self.assertEqual(result["previous_version_digest"], result["manifest_digest"])
        self.assertEqual(result["previous_version_status"], "FOUND")
        self.assertFalse(any(v[0] == "push" for v in docker.calls))

    def test_absent_prior_version_is_explicit_and_auth_failure_is_not_absence(self):
        result, _, _ = self.run_target()
        self.assertEqual(result["previous_version_status"], "ABSENT_HTTP404")
        self.assertIsNone(result["previous_version_digest"])
        registry = FakeRegistry(); registry.error = P.Rejected("REGISTRY_STATUS_REJECTED")
        result, _, _ = self.run_target(registry=registry)
        self.assertEqual(result["previous_version_status"], "UNKNOWN")
        self.assertEqual(result["status"], "FAILED")

    def test_existing_commit_tag_with_different_config_is_never_replaced(self):
        registry = FakeRegistry(); registry.entries[P.tags(REVISION)[1]] = P.parse_manifest(*manifest(config="sha256:" + "5" * 64))
        result, docker, _ = self.run_target(registry=registry)
        self.assertEqual(result["failure_code"], "COMMIT_TAG_CONFLICT")
        self.assertFalse(any(v[0] == "push" for v in docker.calls))

    def test_secondary_partial_failure_keeps_primary_and_attempts_all_targets(self):
        results = {}
        for index, target in enumerate(self.targets):
            registry = FakeRegistry(); docker = FakeDocker(registry)
            if index == 1: docker.fail_tag = P.VERSION
            results[target.id], _, _ = self.run_target(target, registry=registry, docker=docker)
        self.assertEqual(results["primary"]["status"], "PUBLISHED")
        self.assertEqual(results["loboeldrin"]["status"], "FAILED")
        self.assertEqual(results["boeing787"]["status"], "PUBLISHED")
        summary, ok = P.summarize(self.targets, evidence(), results)
        self.assertFalse(ok)
        self.assertEqual(sum(line.startswith("| docker.io/") for line in summary.splitlines()), 6)
        self.assertNotIn(SYNTHETIC_TOKEN, summary)
        results["loboeldrin"]["status"] = "FAILED"
        results["loboeldrin"]["failure_code"] = {"unsafe": SYNTHETIC_TOKEN}
        summary, ok = P.summarize(self.targets, evidence(), results)
        self.assertFalse(ok)
        self.assertNotIn(SYNTHETIC_TOKEN, summary)

    def test_registry_error_cleanup_and_pull_identity_failure_are_sanitized(self):
        registry = FakeRegistry(); registry.error = RuntimeError(SYNTHETIC_TOKEN)
        result, docker, _ = self.run_target(registry=registry)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(docker.calls[-1], ("logout",))
        registry = FakeRegistry(); docker = FakeDocker(registry); docker.pull_identity_invalid = True
        result, _, _ = self.run_target(registry=registry, docker=docker)
        self.assertEqual(result["failure_code"], "IMAGE_CONTENT_MISMATCH")
        registry = FakeRegistry(); docker = FakeDocker(registry); docker.logout_failure = True
        result, _, _ = self.run_target(registry=registry, docker=docker)
        self.assertEqual(result["failure_code"], "LOGOUT_FAILED")

    def test_remote_content_and_tag_digest_mismatches_fail(self):
        registry = FakeRegistry(); registry.expected = P.parse_manifest(*manifest(config="sha256:" + "5" * 64))
        result, _, _ = self.run_target(registry=registry)
        self.assertEqual(result["failure_code"], "IMAGE_CONTENT_MISMATCH")
        registry = FakeRegistry(); original = registry.manifest
        def mutated(tag):
            value = original(tag)
            if value and tag == P.VERSION: return P.parse_manifest(*manifest(padding=True))
            return value
        registry.manifest = mutated
        result, _, _ = self.run_target(registry=registry)
        self.assertEqual(result["failure_code"], "TAG_DIGEST_MISMATCH")

    def test_aggregate_rejects_missing_failed_stale_and_conflicting_content_evidence(self):
        rows = {target.id: self.run_target(target)[0] for target in self.targets}
        for mutation in ("missing", "failed", "stale", "content", "tag"):
            changed = deepcopy(rows)
            if mutation == "missing": changed.pop("boeing787")
            if mutation == "failed": changed["boeing787"]["status"] = "FAILED"
            if mutation == "stale": changed["boeing787"]["revision"] = "9" * 40
            if mutation == "content": changed["boeing787"]["content_hash"] = "9" * 64
            if mutation == "tag": changed["boeing787"]["tags"]["latest"]["digest"] = "sha256:" + "8" * 64
            with self.subTest(mutation=mutation): self.assertFalse(P.summarize(self.targets, evidence(), changed)[1])

    def test_docker_subprocess_never_inherits_account_secrets_or_proxy_and_never_echoes_errors(self):
        completed = subprocess.CompletedProcess([], 1, stdout=SYNTHETIC_TOKEN, stderr=SYNTHETIC_TOKEN)
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"FANOUT_TOKEN": SYNTHETIC_TOKEN,
            "DOCKERHUB_TOKEN_OTHER": "synthetic-other-account", "HTTPS_PROXY": "synthetic-private-proxy"}), \
            patch.object(P.subprocess, "run", return_value=completed) as run, contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            docker = P.Docker(Path(temporary), REVISION)
            with self.assertRaisesRegex(P.Rejected, "^DOCKER_COMMAND_FAILED$") as caught:
                docker.login(self.targets[0].username, SYNTHETIC_TOKEN)
            command = run.call_args.args[0]; kwargs = run.call_args.kwargs
            self.assertNotIn(SYNTHETIC_TOKEN, repr(command))
            self.assertEqual(kwargs["input"], SYNTHETIC_TOKEN + "\n")
            self.assertEqual(kwargs["env"]["DOCKER_CONFIG"], temporary)
            for name in ("FANOUT_TOKEN", "DOCKERHUB_TOKEN_OTHER", "HTTPS_PROXY"): self.assertNotIn(name, kwargs["env"])
            self.assertEqual(out.getvalue() + err.getvalue(), "")
            self.assertNotIn(SYNTHETIC_TOKEN, str(caught.exception))

    def test_real_main_guard_checks_exact_repo_ref_and_remote_sha_without_building(self):
        docker = P.Docker(Path("synthetic-private-config"), REVISION)
        good = {"GITHUB_REPOSITORY": "ad-fiverr/krig-salad", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": REVISION}
        with patch.dict(os.environ, good), patch.object(docker, "command", return_value=REVISION + "\trefs/heads/main\n"):
            docker.assert_current_main()
        with patch.dict(os.environ, {**good, "GITHUB_REF": "refs/heads/other"}), self.assertRaisesRegex(P.Rejected, "CI_SCOPE_INVALID"):
            docker.assert_current_main()
        with patch.dict(os.environ, good), patch.object(docker, "command", return_value="9" * 40 + "\trefs/heads/main\n"), self.assertRaisesRegex(P.Rejected, "NOT_CURRENT_MAIN"):
            docker.assert_current_main()

    def test_registry_auth_fixed_gets_and_404_are_not_generic_error_fallback(self):
        for status in (301, 401, 403, 429, 500):
            reader = P.Registry(self.targets[0], self.targets[0].username, SYNTHETIC_TOKEN)
            reader.bearer = "synthetic-bearer"
            with patch.object(reader, "_get", return_value=(status, {}, b"synthetic-private-provider-body")) as get:
                with self.assertRaisesRegex(P.Rejected, "^REGISTRY_STATUS_REJECTED$"):
                    reader.manifest(P.VERSION)
                self.assertEqual(get.call_count, 1)
        reader = P.Registry(self.targets[0], self.targets[0].username, SYNTHETIC_TOKEN)
        with patch.object(reader, "_get", side_effect=[(200, {}, b'{"token":"synthetic-bearer"}'), (404, {}, b"not found")]) as get:
            self.assertIsNone(reader.manifest(P.VERSION))
            self.assertEqual(get.call_count, 2)
            self.assertEqual(get.call_args_list[0].args[0], "auth.docker.io")
            self.assertIn("scope=repository%3Amyblockchaincompany%2Ffl4shminer-salad%3Apull", get.call_args_list[0].args[1])
            self.assertEqual(get.call_args_list[1].args[0], "registry-1.docker.io")

    def test_registry_tls_get_has_timeout_bound_and_no_redirect_or_proxy_path(self):
        class Response:
            status = 302
            def read(self, amount):
                self.amount = amount
                return b"synthetic-private-body"
            def getheaders(self): return [("Location", "https://unapproved.invalid")]
        response = Response()
        class Connection:
            def request(self, method, path, headers): self.method, self.path = method, path
            def getresponse(self): return response
            def close(self): self.closed = True
        connection = Connection()
        reader = P.Registry(self.targets[0], self.targets[0].username, SYNTHETIC_TOKEN)
        reader.bearer = "synthetic-bearer"
        with patch.object(P.http.client, "HTTPSConnection", return_value=connection) as create:
            with self.assertRaisesRegex(P.Rejected, "REGISTRY_STATUS_REJECTED"): reader.manifest(P.VERSION)
            self.assertEqual(create.call_count, 1)
            self.assertEqual(create.call_args.args, ("registry-1.docker.io", 443))
            self.assertEqual(create.call_args.kwargs["timeout"], 15)
            self.assertTrue(create.call_args.kwargs["context"].check_hostname)
            self.assertEqual(connection.method, "GET")
            self.assertEqual(response.amount, 1_000_001)
            self.assertTrue(connection.closed)

    def test_manifest_hash_and_schema_fail_closed(self):
        body, digest = manifest()
        self.assertEqual(P.parse_manifest(body, digest).config, IMAGE_ID)
        for bad_body, bad_digest in ((body, "sha256:" + "0" * 64), (b"not-json", digest), (b"{}", digest)):
            with self.assertRaisesRegex(P.Rejected, "MANIFEST_INVALID"): P.parse_manifest(bad_body, bad_digest)

    def test_failed_smoke_skips_all_targets_and_corrupt_results_do_not_hide_other_rows(self):
        data = evidence(); data["smoke_passed"] = False
        summary, ok = P.summarize(self.targets, data, {})
        self.assertFalse(ok)
        self.assertEqual(summary.count("| SKIPPED |"), 6)
        rows = {target.id: self.run_target(target)[0] for target in self.targets}
        rows["loboeldrin"]["tags"] = [SYNTHETIC_TOKEN]
        summary, ok = P.summarize(self.targets, evidence(), rows)
        self.assertFalse(ok)
        self.assertEqual(sum(line.startswith("| docker.io/") for line in summary.splitlines()), 6)
        self.assertNotIn(SYNTHETIC_TOKEN, summary)

    def test_failed_login_removes_the_private_cli_config_and_does_not_query_registry(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary); data_path = temporary / "image.json"; results = temporary / "results"
            P.write_json(data_path, evidence()); configs = []; registry = FakeRegistry()
            def fake_docker(config, revision):
                configs.append(config); result = FakeDocker(registry); result.login_failure = True
                return result
            argv = ["fanout", "publish", "--targets", str(CONFIG), "--target", "primary", "--evidence", str(data_path), "--results", str(results)]
            env = {"RUNNER_TEMP": str(temporary), "FANOUT_USERNAME": self.targets[0].username, "FANOUT_TOKEN": SYNTHETIC_TOKEN}
            with patch.object(sys, "argv", argv), patch.dict(os.environ, env), patch.object(P, "Docker", side_effect=fake_docker), \
                patch.object(P, "Registry", return_value=registry), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.main(), 1)
            self.assertFalse(configs[0].exists())
            self.assertEqual(registry.calls, [])
            self.assertNotIn(SYNTHETIC_TOKEN, output.getvalue())
            self.assertEqual(json.loads((results / "primary.json").read_text())["status"], "FAILED")

    def test_cli_publish_cleans_private_config_and_never_persists_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary); data_path = temporary / "image.json"; results = temporary / "results"
            P.write_json(data_path, evidence())
            configs = []
            def fake_docker(config, revision):
                self.assertTrue(config.is_dir()); self.assertEqual((config / "config.json").read_text(), "{}")
                configs.append(config)
                return FakeDocker(registry)
            registry = FakeRegistry()
            argv = ["fanout", "publish", "--targets", str(CONFIG), "--target", "primary", "--evidence", str(data_path), "--results", str(results)]
            env = {"RUNNER_TEMP": str(temporary), "FANOUT_USERNAME": self.targets[0].username, "FANOUT_TOKEN": SYNTHETIC_TOKEN}
            with patch.object(sys, "argv", argv), patch.dict(os.environ, env), patch.object(P, "Docker", side_effect=fake_docker), \
                patch.object(P, "Registry", return_value=registry), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(P.main(), 0)
            self.assertFalse(configs[0].exists())
            self.assertNotIn(SYNTHETIC_TOKEN, output.getvalue())
            self.assertNotIn(SYNTHETIC_TOKEN, (results / "primary.json").read_text())

    def test_evidence_round_trip_rejects_unsealed_and_wrong_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image.json"
            P.write_json(path, evidence()); self.assertEqual(P.read_evidence(path), evidence())
            data = evidence(); data["smoke_passed"] = False; P.write_json(path, data)
            with self.assertRaisesRegex(P.Rejected, "SMOKE_NOT_PASSED"): P.read_evidence(path)
            data = evidence(); data["credential"] = SYNTHETIC_TOKEN; P.write_json(path, data)
            with self.assertRaisesRegex(P.Rejected, "LOCAL_IMAGE_INVALID"): P.read_evidence(path)

    def test_workflow_exact_static_secret_mapping_one_build_one_smoke_and_final_failure_gate(self):
        workflow = (ROOT / ".github/workflows/build-fl4shminer.yml").read_text()
        self.assertEqual(workflow.count("docker buildx build"), 1)
        self.assertEqual(workflow.count("docker run --rm --network none"), 1)
        self.assertNotIn("--push", workflow)
        self.assertNotIn("secrets[", workflow)
        steps = re.split(r"(?m)^      - name: ", workflow)[1:]
        publishers = [step for step in steps if "fl4sh_publish.py publish --target" in step]
        self.assertEqual(len(publishers), 6)
        for target, step in zip(self.targets, publishers):
            self.assertIn("--target " + target.id + " --evidence", step)
            self.assertEqual(re.findall(r"\$\{\{ secrets\.([A-Z0-9_]+) \}\}", step), [target.username_secret, target.token_secret])
            self.assertIn("continue-on-error: true", step)
            self.assertIn("if: github.ref == 'refs/heads/main'", step)
        self.assertIn("if: always() && github.ref == 'refs/heads/main'", steps[-1])
        self.assertIn("fl4sh_publish.py summary", steps[-1])
        positions = [workflow.index(v) for v in ("fl4sh_publish.py base-login", "docker buildx build", "fl4sh_publish.py base-logout",
            "docker run --rm --network none", "fl4sh_publish.py seal", "fl4sh_publish.py publish")]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("IMAGE: docker.io/myblockchaincompany/fl4shminer-salad", workflow)
        self.assertIn("VERSION: 1.5.2", workflow)

    def test_source_smoke_enforces_new_contract(self):
        spec = importlib.util.spec_from_file_location("fleet_smoke", ROOT / "gpu-mining/runtime/fl4shminer/ci-fleet-image-smoke.py")
        smoke = importlib.util.module_from_spec(spec); spec.loader.exec_module(smoke)
        smoke.check_workflow(ROOT)
        source = (ROOT / ".github/workflows/build-fl4shminer.yml").read_text()
        for changed in (source + "\n# docker buildx build\n", source.replace("secrets.DOCKERHUB_TOKEN_LOBOELDRIN", "secrets.DOCKERHUB_TOKEN")):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); path = root / ".github/workflows/build-fl4shminer.yml"; path.parent.mkdir(parents=True)
                path.write_text(changed)
                with self.assertRaises(SystemExit): smoke.check_workflow(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
