#!/usr/bin/env python3
"""Offline package-boundary and inert-startup smoke for the central watcher."""

from __future__ import annotations

import argparse
import ast
import builtins
import contextlib
import getpass
import http.client
import importlib
import io
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import threading
import urllib.request


LOG_ALERT_MODULES = (
    "__init__.py",
    "central_telegram.py",
    "contract.py",
    "cuda_guard.py",
    "delivery.py",
    "engine.py",
    "fleet_targets.py",
    "fleet_watcher.py",
    "ledger.py",
    "list_instances_lookup.py",
    "live_adapter.py",
    "live_capability.py",
    "live_cli.py",
    "live_controller.py",
    "live_transport.py",
    "normalize.py",
    "startup_guard.py",
)

RUNTIME_INPUTS = (
    "gpu-mining/runtime/fl4shminer/fl4sh-release.lock",
    "gpu-mining/runtime/fl4shminer/verify-artifact.sh",
    "gpu-mining/runtime/fl4shminer/fl4sh-entrypoint.sh",
    "gpu-mining/runtime/fl4shminer/fl4sh-healthcheck.sh",
    "gpu-mining/runtime/fl4shminer/ci-smoke-test.sh",
    "gpu-mining/runtime/fl4shminer/fl4sh-runtime-monitor.py",
    "gpu-mining/runtime/fl4shminer/ci-fleet-image-smoke.py",
    "gpu-mining/runtime/fl4shminer/README.md",
)

WATCHER_INPUTS = tuple(
    f"gpu-mining/telemetry/log_alerts/{name}" for name in LOG_ALERT_MODULES
) + (
    "gpu-mining/telemetry/collector/g4a_salad_get.py",
    "gpu-mining/g4c-live/live_secret_boundary.py",
)

COPY_INPUTS = frozenset(RUNTIME_INPUTS + WATCHER_INPUTS)

ALLOWED_DIRECTORIES = frozenset(
    {
        "gpu-mining",
        "gpu-mining/runtime",
        "gpu-mining/runtime/fl4shminer",
        "gpu-mining/telemetry",
        "gpu-mining/telemetry/log_alerts",
        "gpu-mining/telemetry/collector",
        "gpu-mining/g4c-live",
    }
)

WORKFLOW_TRIGGERS = frozenset(
    {
        "gpu-mining/runtime/fl4shminer/**",
        "gpu-mining/telemetry/log_alerts/**",
        "gpu-mining/telemetry/collector/g4a_salad_get.py",
        "gpu-mining/g4c-live/live_secret_boundary.py",
        ".github/workflows/build-fl4shminer.yml",
    }
)

REGISTRY_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


BLOCKED_MODULE_ROOTS = frozenset(
    {
        "firebase",
        "firebase_admin",
        "action_ledger",
        "firebase_sink",
        "reallocation_controller",
        "salad_action_policy",
        "salad_action_transport",
        "salad_reallocation_adapter",
    }
)


def fail(message: str) -> None:
    raise SystemExit(f"ci-fleet-image-smoke: {message}")


def block_external_io(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("offline watcher smoke attempted external I/O or a prompt")


def classify_registry_manifest_response(status_code: str, digest: str) -> str:
    if not re.fullmatch(r"[0-9]{3}", status_code):
        raise ValueError("registry returned an invalid HTTP status")
    if status_code == "404":
        if digest:
            raise ValueError("registry 404 unexpectedly included a manifest digest")
        return "NOT_FOUND"
    if status_code != "200":
        raise ValueError("registry manifest lookup failed; publication must stop")
    if not REGISTRY_DIGEST_RE.fullmatch(digest):
        raise ValueError("registry 200 response did not include a valid manifest digest")
    return digest


def check_registry_manifest_response_classifier() -> None:
    digest = "sha256:" + "1" * 64
    if classify_registry_manifest_response("404", "") != "NOT_FOUND":
        fail("confirmed Registry V2 404 was not classified as an absent prior tag")
    if classify_registry_manifest_response("200", digest) != digest:
        fail("valid Registry V2 manifest digest was not preserved")
    for status in ("000", "301", "401", "403", "429", "500", "503"):
        try:
            classify_registry_manifest_response(status, "")
        except ValueError:
            continue
        fail(f"registry HTTP {status} did not fail closed")
    for status, invalid_digest in (("200", ""), ("200", "sha256:bad"), ("404", digest)):
        try:
            classify_registry_manifest_response(status, invalid_digest)
        except ValueError:
            continue
        fail("malformed registry response did not fail closed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source", action="store_true")
    mode.add_argument("--image", action="store_true")
    mode.add_argument("--registry-manifest-response", nargs=2, metavar=("HTTP_STATUS", "DIGEST"))
    parser.add_argument("--repo-root", type=Path)
    return parser.parse_args()


def root_for(args: argparse.Namespace) -> Path:
    if args.image:
        if args.repo_root is not None:
            fail("--repo-root is not valid in image mode")
        return Path(__file__).resolve().parent
    if args.repo_root is None:
        fail("source mode requires --repo-root")
    root = args.repo_root.resolve()
    if not (root / ".git").exists() and not (root / ".git").is_file():
        fail("source repository root is not a Git checkout")
    return root


def expected_image_files(root: Path) -> set[str]:
    return {
        Path(item).relative_to(root).as_posix()
        for item in COPY_INPUTS
    }


def check_sources_exist(root: Path) -> None:
    missing = sorted(item for item in COPY_INPUTS if not (root / item).is_file())
    if missing:
        fail("packaged source is missing: " + ", ".join(missing))
    log_alerts_root = root / "gpu-mining/telemetry/log_alerts"
    expected_modules = {
        Path(item).relative_to("gpu-mining/telemetry/log_alerts").as_posix()
        for item in WATCHER_INPUTS
        if item.startswith("gpu-mining/telemetry/log_alerts/")
    }
    actual_modules = {
        item.relative_to(log_alerts_root).as_posix()
        for item in log_alerts_root.rglob("*.py")
    }
    if actual_modules != expected_modules:
        missing_modules = sorted(expected_modules - actual_modules)
        unreviewed_modules = sorted(actual_modules - expected_modules)
        fail(
            "watcher Python source inventory changed; update the explicit "
            f"image manifest (missing={missing_modules}, unreviewed={unreviewed_modules})"
        )


def check_dockerfile_manifest(root: Path) -> None:
    dockerfile_path = root / "gpu-mining/runtime/fl4shminer/Dockerfile"
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    copy_sources: set[str] = set()
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if not stripped.startswith("COPY "):
            continue
        tokens = shlex.split(stripped)
        if any(token.startswith("--from=") for token in tokens[1:]):
            continue
        if len(tokens) < 3:
            fail("Dockerfile contains a malformed COPY instruction")
        sources = [token for token in tokens[1:-1] if not token.startswith("--")]
        if any("*" in item or item in {".", "./"} for item in sources):
            fail("Dockerfile uses a broad or wildcard COPY source")
        copy_sources.update(sources)
    if copy_sources != COPY_INPUTS:
        missing = sorted(COPY_INPUTS - copy_sources)
        extra = sorted(copy_sources - COPY_INPUTS)
        fail(f"Dockerfile COPY manifest differs (missing={missing}, extra={extra})")
    if "ENV PYTHONPATH=/opt/fl4shminer/gpu-mining/telemetry" not in dockerfile:
        fail("image does not expose the repository-shaped watcher modules on PYTHONPATH")

    ignore_path = root / "gpu-mining/runtime/fl4shminer/Dockerfile.dockerignore"
    lines = [
        line.strip()
        for line in ignore_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines or lines[0] != "**":
        fail("Dockerfile-specific ignore must exclude the root context by default")
    includes = [line[1:].rstrip("/") for line in lines[1:] if line.startswith("!")]
    if any(not line.startswith("!") for line in lines[1:]):
        fail("Dockerfile-specific ignore contains an unreviewed exclusion rule")
    if len(includes) != len(set(includes)):
        fail("Dockerfile-specific ignore contains duplicate allowlist entries")
    expected = set(COPY_INPUTS) | set(ALLOWED_DIRECTORIES)
    if set(includes) != expected:
        missing = sorted(expected - set(includes))
        extra = sorted(set(includes) - expected)
        fail(f"Dockerfile context allowlist differs (missing={missing}, extra={extra})")


def check_workflow(root: Path) -> None:
    workflow = (root / ".github/workflows/build-fl4shminer.yml").read_text(
        encoding="utf-8"
    )
    push = re.search(r"(?ms)^  push:\n(.*?)(?=^  workflow_dispatch:)", workflow)
    if push is None:
        fail("workflow push trigger block is missing")
    path_block = re.search(r"(?ms)^    paths:\n((?:^      - .*\n?)+)", push.group(1))
    if path_block is None:
        fail("workflow push.paths block is missing")
    triggers = {
        line.strip()[2:].strip("\"'")
        for line in path_block.group(1).splitlines()
        if line.strip().startswith("-")
    }
    if triggers != WORKFLOW_TRIGGERS:
        fail(
            "workflow path triggers differ "
            f"(missing={sorted(WORKFLOW_TRIGGERS - triggers)}, extra={sorted(triggers - WORKFLOW_TRIGGERS)})"
        )

    previous_step = re.search(
        r"(?ms)^      - name: Capture the previously published version digest\n(?P<body>.*?)(?=^      - name: )",
        workflow,
    )
    if previous_step is None:
        fail("previous image digest verification step is missing")
    previous_body = previous_step.group("body")
    required_probe_parts = (
        "https://auth.docker.io/token?",
        "https://registry-1.docker.io/v2/",
        "--request HEAD",
        "--dump-header -",
        "--write-out",
        "--registry-manifest-response",
    )
    if any(part not in previous_body for part in required_probe_parts):
        fail("previous digest lookup is missing its authenticated HTTPS Registry V2 probe")
    if "imagetools inspect" in previous_body or "|| true" in previous_body:
        fail("previous digest lookup must not mask registry failures")
    if "--location" in previous_body or re.search(r"(?m)^\s+-L(?:\s|$)", previous_body):
        fail("previous digest lookup must not follow redirects")
    if "PREVIOUS_FOUND" not in workflow or "HTTP 404" not in workflow:
        fail("workflow must carry the explicit prior-tag presence result and document confirmed absence")
    check_registry_manifest_response_classifier()

    required_paths = (
        "gpu-mining/runtime/fl4shminer/Dockerfile",
        '--build-arg "IMAGE_REVISION=$GITHUB_SHA"',
    )
    if workflow.count(required_paths[0]) < 2 or workflow.count(required_paths[1]) < 2:
        fail("both root-context builds must use the explicit Dockerfile and full GITHUB_SHA")
    if not re.search(r"(?m)^\s+\.\s*$", workflow):
        fail("workflow does not use the repository root as a build context")
    if re.search(r"(?m)^\s+gpu-mining/runtime/fl4shminer\s*$", workflow):
        fail("workflow still uses the runtime directory as a build context")

    representative_paths = {
        "gpu-mining/runtime/fl4shminer/Dockerfile": True,
        "gpu-mining/runtime/fl4shminer/README.md": True,
        "gpu-mining/telemetry/log_alerts/fleet_watcher.py": True,
        "gpu-mining/telemetry/collector/g4a_salad_get.py": True,
        "gpu-mining/g4c-live/live_secret_boundary.py": True,
        ".github/workflows/build-fl4shminer.yml": True,
        "gpu-mining/telemetry/collector/continuous.py": False,
        "gpu-mining/telemetry/tests/test_g4a_salad_get.py": False,
        "gpu-mining/tools/unrelated.py": False,
        "gpu-mining/runtime/krig/Dockerfile": False,
    }
    for path, should_build in representative_paths.items():
        matches = any(
            path.startswith(pattern[:-2]) if pattern.endswith("/**") else path == pattern
            for pattern in triggers
        )
        if matches is not should_build:
            fail(f"workflow path classification is wrong for {path}")


def check_source_boundaries(root: Path, *, image: bool) -> None:
    if image:
        source_paths = {
            *(Path(item).name for item in RUNTIME_INPUTS if item.endswith(".py")),
            *WATCHER_INPUTS,
        }
    else:
        source_paths = COPY_INPUTS
    for relative in source_paths:
        path = root / relative
        if path.suffix != ".py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (SyntaxError, UnicodeDecodeError) as exc:
            fail(f"Python source is invalid: {relative} ({type(exc).__name__})")
        for node in ast.walk(tree):
            imported: list[str] = []
            if isinstance(node, ast.Import):
                imported.extend(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module.split(".", 1)[0])
            blocked = sorted(set(imported) & BLOCKED_MODULE_ROOTS)
            if blocked:
                fail(f"packaged source imports blocked module in {relative}: {blocked[0]}")


def check_image_tree(root: Path) -> None:
    if root.name != "fl4shminer":
        fail("image smoke must run from the installed /opt/fl4shminer directory")
    missing = sorted(item for item in WATCHER_INPUTS if not (root / item).is_file())
    if missing:
        fail("installed watcher source is missing: " + ", ".join(missing))
    actual_files = {
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and "__pycache__" not in item.parts
    }
    expected = set(WATCHER_INPUTS)
    expected.update(Path(item).name for item in RUNTIME_INPUTS)
    expected.add("fl4shminer")
    if actual_files != expected:
        missing = sorted(expected - actual_files)
        extra = sorted(actual_files - expected)
        fail(f"installed image file inventory differs (missing={missing}, extra={extra})")

    telemetry = root / "gpu-mining/telemetry"
    if {entry.name for entry in telemetry.iterdir()} != {"log_alerts", "collector"}:
        fail("image contains telemetry outside the reviewed watcher package")
    collector = telemetry / "collector"
    if {entry.name for entry in collector.iterdir()} != {"g4a_salad_get.py"}:
        fail("image collector directory contains files beyond the exact G4A validator")
    g4c = root / "gpu-mining/g4c-live"
    if {entry.name for entry in g4c.iterdir()} != {"live_secret_boundary.py"}:
        fail("image G4C directory contains files beyond the approved secret boundary")


def block_external_boundaries() -> None:
    socket.socket = block_external_io  # type: ignore[assignment]
    socket.create_connection = block_external_io  # type: ignore[assignment]
    socket.getaddrinfo = block_external_io  # type: ignore[assignment]
    socket.gethostbyname = block_external_io  # type: ignore[assignment]
    socket.gethostbyaddr = block_external_io  # type: ignore[assignment]
    getpass.getpass = block_external_io
    builtins.input = block_external_io
    urllib.request.urlopen = block_external_io
    http.client.HTTPConnection.connect = block_external_io  # type: ignore[assignment]
    http.client.HTTPSConnection.connect = block_external_io  # type: ignore[assignment]


def check_imports_and_inert_startup(root: Path, *, image: bool) -> None:
    telemetry_path = root / "gpu-mining/telemetry"
    mining_root = root / "gpu-mining"
    if image and os.environ.get("PYTHONPATH") != str(telemetry_path):
        fail("image PYTHONPATH does not expose the packaged watcher CLI")
    sys.path.insert(0, str(mining_root))
    sys.path.insert(0, str(telemetry_path))
    before_modules = set(sys.modules)
    before_threads = {thread.ident for thread in threading.enumerate()}
    block_external_boundaries()

    live_cli = importlib.import_module("log_alerts.live_cli")
    importlib.import_module("log_alerts.fleet_watcher")
    importlib.import_module("log_alerts.list_instances_lookup")
    transport = importlib.import_module("log_alerts.live_transport")
    from collector.g4a_salad_get import normalize_instance_list_response

    if not callable(normalize_instance_list_response):
        fail("G4A instance response normalizer is unavailable")
    if transport.PRODUCTION_NETWORK_ALLOWED is not False:
        fail("Salad HTTPS transport is not disabled by default")
    boundary_path = (mining_root / "g4c-live/live_secret_boundary.py").resolve()
    interactive_type, synthetic_type, material_type = transport.secret_boundary_types()
    if not all(
        getattr(item, "__name__", "") == expected
        for item, expected in (
            (interactive_type, "InteractiveSecretProvider"),
            (synthetic_type, "SyntheticSecretProvider"),
            (material_type, "SecretMaterial"),
        )
    ):
        fail("approved secret provider classes are incomplete")
    if Path(sys.modules[interactive_type.__module__].__file__).resolve() != boundary_path:
        fail("secret provider did not resolve to the exact packaged G4C boundary")

    loaded = set(sys.modules) - before_modules
    for name in loaded:
        root_name = name.split(".", 1)[0]
        if root_name in BLOCKED_MODULE_ROOTS:
            fail(f"watcher import pulled a blocked dependency: {root_name}")

    output = io.StringIO()
    provider_calls: list[str] = []

    def unexpected_secret_provider() -> object:
        provider_calls.append("called")
        raise AssertionError("live-read gate must block before secret acquisition")

    original_provider_loader = live_cli._load_interactive_salad_provider
    live_cli._load_interactive_salad_provider = unexpected_secret_provider
    try:
        with contextlib.redirect_stdout(output):
            status = live_cli.main(
                [
                    "--live-alert-once",
                    "--organization",
                    "synthetic-org",
                    "--query",
                    "resource.labels.container_group_name=fl4shminer",
                ]
            )
    finally:
        live_cli._load_interactive_salad_provider = original_provider_loader
    if status != 2 or "STATUS=BLOCKED LIVE_READ_GATE=OFF" not in output.getvalue():
        fail("watcher did not remain disabled by default")
    if provider_calls:
        fail("watcher acquired a secret before the live-read gate")
    if {thread.ident for thread in threading.enumerate()} != before_threads:
        fail("watcher import or disabled invocation started a background thread")
    if image:
        child_environment = os.environ.copy()
        for key in (
            "SALAD_API_KEY",
            "SALAD_API_TOKEN",
            "TELEGRAM_BOT_TOKEN",
            "TELEGRAM_CHAT_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "FIREBASE_CONFIG",
        ):
            child_environment.pop(key, None)
        try:
            cli = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "log_alerts.live_cli",
                    "--live-alert-once",
                    "--organization",
                    "synthetic-org",
                    "--query",
                    "resource.labels.container_group_name=fl4shminer",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                stdin=subprocess.DEVNULL,
                env=child_environment,
            )
        except (OSError, subprocess.TimeoutExpired):
            fail("default-off watcher module CLI did not terminate safely")
        if (
            cli.returncode != 2
            or cli.stdout.strip() != "STATUS=BLOCKED LIVE_READ_GATE=OFF"
            or cli.stderr
        ):
            fail("default-off watcher module CLI did not block before live access")
    print("CENTRAL_WATCHER_IMPORT_OK")
    print(f"SECRET_BOUNDARY_PATH_OK path={boundary_path.as_posix()}")
    print("WATCHER_DEFAULT_OFF_OFFLINE_OK")
    if image:
        print("WATCHER_MODULE_CLI_DEFAULT_OFF_OK")


def main() -> int:
    args = parse_args()
    if args.registry_manifest_response is not None:
        status_code, digest = args.registry_manifest_response
        try:
            print(classify_registry_manifest_response(status_code, digest))
        except ValueError as exc:
            fail(str(exc))
        return 0
    root = root_for(args)
    if args.source:
        check_sources_exist(root)
        check_dockerfile_manifest(root)
        check_workflow(root)
        check_source_boundaries(root, image=False)
    else:
        check_image_tree(root)
        check_source_boundaries(root, image=True)
    check_imports_and_inert_startup(root, image=args.image)
    print("fleet image smoke passed: exact source allowlist, G4A resolver, G4C identity, imports, and disabled/offline startup")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
