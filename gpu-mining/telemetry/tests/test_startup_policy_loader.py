"""Parity and import-boundary checks for the packaged read-only G5 policy loader."""

from __future__ import annotations

import os
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from g5_control_plane.config import (  # noqa: E402
    FLOORS,
    G5Config,
    G5ConfigError,
    load_config,
)
from g5_control_plane.service import G5ControlPlaneService  # noqa: E402
from g5_control_plane.startup_policy import (  # noqa: E402
    build_guard_policy,
    build_startup_policy_snapshot,
    load_startup_policy_snapshot,
)
from collector.guards import hash_guard_policy  # noqa: E402


class StartupPolicyLoaderTests(unittest.TestCase):
    def assert_snapshot_matches_service(self, config, loader_snapshot):
        service = G5ControlPlaneService(config)
        try:
            expected = service.startup_policy_snapshot()
            self.assertEqual(
                replace(loader_snapshot, loaded_at_utc=expected.loaded_at_utc),
                expected,
            )
        finally:
            service.close()

    def test_shared_policy_and_snapshot_are_identical_to_g5_service(self):
        config = load_config(None, environ={})
        service = G5ControlPlaneService(config)
        try:
            guard_policy = build_guard_policy(config)
            self.assertEqual(guard_policy, service.guard_policy)
            self.assertEqual(hash_guard_policy(guard_policy), service.monitor.policy_hash)

            service_snapshot = service.startup_policy_snapshot()
            loader_snapshot = build_startup_policy_snapshot(
                config, loaded_at_utc=service_snapshot.loaded_at_utc,
            )
            self.assertEqual(loader_snapshot, service_snapshot)
        finally:
            service.close()

    def test_read_only_loader_matches_service_with_environment_overrides(self):
        environment = {
            "SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS": "111",
            "SALAD_G5_PEARL_STARTUP_FLOORS_JSON": '{"RTX_4070_TI_LAPTOP":100}',
        }
        service_config = load_config(None, environ=environment)
        with tempfile.TemporaryDirectory(prefix="startup-policy-loader-") as directory:
            config_path = Path(directory) / "g5.json"
            config_path.write_text("{}", encoding="utf-8")
            loader_snapshot = load_startup_policy_snapshot(config_path, environ=environment)
        self.assert_snapshot_matches_service(service_config, loader_snapshot)
        self.assertEqual(loader_snapshot.policy.floors_ths["RTX_5080_LAPTOP"], 111.0)
        self.assertEqual(loader_snapshot.policy.floors_ths["RTX_4070_TI_LAPTOP"], 100.0)
        self.assertEqual(loader_snapshot.floor_sources["RTX_5080_LAPTOP"], "LEGACY_ENV")
        self.assertEqual(loader_snapshot.floor_sources["RTX_4070_TI_LAPTOP"], "ENV")

    def test_loader_and_service_match_for_legacy_json_and_explicit_pearl_catalog(self):
        legacy_key = "RTX 5080|laptop|salad_json_log_gpu_class_name"
        config_value = {
            "gpu_floors_ths": {legacy_key: 123},
            "pearl_startup_floors_ths": {"RTX_4070_TI_LAPTOP": 97},
        }
        with tempfile.TemporaryDirectory(prefix="startup-policy-json-parity-") as directory:
            config_path = Path(directory) / "g5.json"
            config_path.write_text(json.dumps(config_value), encoding="utf-8")
            config = load_config(config_path, environ={})
            loader_snapshot = load_startup_policy_snapshot(config_path, environ={})
        self.assert_snapshot_matches_service(config, loader_snapshot)
        self.assertEqual(loader_snapshot.policy.floors_ths["RTX_5080_LAPTOP"], 123.0)
        self.assertEqual(loader_snapshot.floor_sources["RTX_5080_LAPTOP"], "LEGACY_JSON")
        self.assertEqual(loader_snapshot.policy.floors_ths["RTX_4070_TI_LAPTOP"], 97.0)
        self.assertEqual(loader_snapshot.floor_sources["RTX_4070_TI_LAPTOP"], "JSON")

    def test_loader_and_service_match_for_direct_g5_config(self):
        legacy_key = "RTX 5080|laptop|salad_json_log_gpu_class_name"
        floors = dict(FLOORS)
        floors[legacy_key] = 119
        config = G5Config(gpu_floors_ths=floors)
        snapshot = build_startup_policy_snapshot(config)
        self.assert_snapshot_matches_service(config, snapshot)
        self.assertEqual(snapshot.policy.floors_ths["RTX_5080_LAPTOP"], 119.0)
        self.assertEqual(snapshot.floor_sources["RTX_5080_LAPTOP"], "PYTHON")

    def test_json_environment_duplicate_pearl_floor_fails_closed_in_both_loaders(self):
        config_value = {
            "pearl_startup_floors_ths": {"RTX_4070_TI_LAPTOP": 97},
        }
        environment = {
            "SALAD_G5_PEARL_STARTUP_FLOORS_JSON": '{"RTX_4070_TI_LAPTOP":98}',
        }
        with tempfile.TemporaryDirectory(prefix="startup-policy-conflict-") as directory:
            config_path = Path(directory) / "g5.json"
            config_path.write_text(json.dumps(config_value), encoding="utf-8")
            with self.assertRaisesRegex(G5ConfigError, "multiple explicit sources"):
                load_config(config_path, environ=environment)
            with self.assertRaisesRegex(G5ConfigError, "multiple explicit sources"):
                load_startup_policy_snapshot(config_path, environ=environment)

    def test_packaged_policy_import_does_not_eagerly_import_control_service(self):
        code = (
            "import sys; "
            f"sys.path.insert(0, {str(TELEMETRY_ROOT)!r}); "
            "from g5_control_plane.startup_policy import load_startup_policy_snapshot; "
            "assert 'g5_control_plane.service' not in sys.modules; "
            "snapshot = load_startup_policy_snapshot(None, environ={}); "
            "assert len(snapshot.policy.policy_hash) == 64; "
            "assert 'g5_control_plane.service' not in sys.modules"
        )
        environment = {
            key: value for key, value in os.environ.items()
            if key in {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP"}
        }
        result = subprocess.run(
            [sys.executable, "-B", "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_public_service_export_remains_lazy_and_compatible(self):
        code = (
            "import sys; "
            f"sys.path.insert(0, {str(TELEMETRY_ROOT)!r}); "
            "import g5_control_plane; "
            "assert 'g5_control_plane.service' not in sys.modules; "
            "from g5_control_plane import G5ControlPlaneService; "
            "assert G5ControlPlaneService.__name__ == 'G5ControlPlaneService'"
        )
        result = subprocess.run(
            [sys.executable, "-B", "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
