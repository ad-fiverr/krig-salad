#!/usr/bin/env python3
"""Offline regression tests for the optional Fl4shMiner log monitor."""

from __future__ import annotations

import contextlib
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "fl4sh_runtime_monitor", ROOT / "fl4sh-runtime-monitor.py"
)
assert SPEC is not None and SPEC.loader is not None
MONITOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MONITOR
SPEC.loader.exec_module(MONITOR)

POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP = (
    f"{MONITOR.POOL_CONNECTION_FAILED_LINE}; reconnecting; retrying in 10s"
)
POOL_CONNECTION_FAILED_WITH_TIMESTAMP = (
    "2026/10/12 22:04:33 " + POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP
)


def make_config(**overrides: str) -> MONITOR.MonitorConfig:
    values = {
        "FL4SH_MONITOR_ENABLED": "1",
        "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
        "SALAD_G5_WARMUP_SECONDS": "0",
        "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "10",
        "SALAD_G5_HASH_WINDOW_SECONDS": "20",
        "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
        "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
        "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "10",
        "SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO": "0.8",
        "SALAD_G5_CONSECUTIVE_BAD_WINDOWS": "2",
    }
    values.update(overrides)
    return MONITOR.MonitorConfig.from_env(values, require_enabled=True)


def make_auto_config(**overrides: str) -> MONITOR.MonitorConfig:
    values = {
        "FL4SH_MONITOR_ENABLED": "1",
        "FL4SH_MONITOR_PROFILE": "",
        "SALAD_G5_WARMUP_SECONDS": "0",
        "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "10",
        "SALAD_G5_HASH_WINDOW_SECONDS": "20",
        "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
        "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
        "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "10",
        "SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO": "0.8",
        "SALAD_G5_CONSECUTIVE_BAD_WINDOWS": "1",
    }
    values.update(overrides)
    return MONITOR.MonitorConfig.from_env(values, require_enabled=True)


def line(rate: float, *, device: int = 1, stale: str = "0/0 (0.0%)") -> str:
    return f"Device [{device}] hashRate: {rate:.2f} TH/s, stale: {stale}, warm: 0"


def make_telegram_config(**overrides: str) -> MONITOR.TelegramConfig:
    values = {
        "FL4SH_TELEGRAM_ENABLED": "1",
        "FL4SH_TELEGRAM_BOT_TOKEN": "synthetic:telegram_test_token",
        "FL4SH_TELEGRAM_CHAT_ID": "-1001234567890",
    }
    values.update(overrides)
    return MONITOR.TelegramConfig.from_env(values)


class MonitorConfigTests(unittest.TestCase):
    def test_monitor_is_off_by_default(self) -> None:
        config = MONITOR.MonitorConfig.from_env({})
        self.assertFalse(config.enabled)
        self.assertIsNone(config.floor_ths)
        self.assertEqual(config.floor_source, "UNCONFIGURED")

    def test_exact_profiles_keep_laptop_and_desktop_floors_separate(self) -> None:
        cases = {
            "RTX_5080_LAPTOP": ("SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS", 120),
            "RTX_5090_LAPTOP": ("SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS", 120),
            "RTX_5080_DESKTOP": ("SALAD_G5_GPU_FLOOR_RTX_5080_DESKTOP_THS", 209),
            "RTX_5090_DESKTOP": ("SALAD_G5_GPU_FLOOR_RTX_5090_DESKTOP_THS", 350),
        }
        for profile, (env_key, default) in cases.items():
            with self.subTest(profile=profile):
                config = MONITOR.MonitorConfig.from_env(
                    {
                        "FL4SH_MONITOR_ENABLED": "1",
                        "FL4SH_MONITOR_PROFILE": profile,
                        env_key: "111.5",
                    },
                    require_enabled=True,
                )
                self.assertEqual(config.floor_ths, 111.5)
                self.assertEqual(config.floor_source, "ENV")
                self.assertEqual(
                    MONITOR.PROFILE_FLOORS[profile][1], default
                )
        with self.assertRaises(MONITOR.MonitorConfigError):
            MONITOR.MonitorConfig.from_env(
                {"FL4SH_MONITOR_ENABLED": "1", "FL4SH_MONITOR_PROFILE": "GPU__5090"},
                require_enabled=True,
            )

    def test_invalid_or_incoherent_values_are_rejected_without_echoing_them(self) -> None:
        for raw in ("0", "-1", "nan", "inf", "secret-value"):
            with self.subTest(raw=raw):
                with self.assertRaises(MONITOR.MonitorConfigError) as caught:
                    make_config(SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS=raw)
                if raw == "secret-value":
                    self.assertNotIn(raw, str(caught.exception))
        with self.assertRaises(MONITOR.MonitorConfigError):
            make_config(SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO="1.1")
        with self.assertRaises(MONITOR.MonitorConfigError):
            make_config(SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="99")

    def test_g5_sample_and_gap_policy_boundaries_match_runtime_validation(self) -> None:
        for minimum in ("1", "3"):
            with self.subTest(minimum=minimum):
                with self.assertRaises(MONITOR.MonitorConfigError):
                    make_config(
                        SALAD_G5_HASH_WINDOW_SECONDS="20",
                        SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS="10",
                        SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW=minimum,
                    )

        accepted = make_config(
            SALAD_G5_HASH_WINDOW_SECONDS="20",
            SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS="10",
            SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="2",
            SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="30",
        )
        self.assertEqual(accepted.minimum_samples_per_window, 2)
        self.assertEqual(accepted.maximum_sample_gap_seconds, 30)

        with self.assertRaises(MONITOR.MonitorConfigError):
            make_config(
                SALAD_G5_HASH_WINDOW_SECONDS="20",
                SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS="10",
                SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="2",
                SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="9",
            )

    def test_policy_hash_changes_when_floor_or_timing_changes(self) -> None:
        first = make_config()
        changed_floor = make_config(SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS="115")
        changed_window = make_config(SALAD_G5_HASH_WINDOW_SECONDS="30")
        changed_tolerance = make_config(FL4SH_MONITOR_FLOOR_TOLERANCE_THS="2.5")
        self.assertNotEqual(first.policy_hash, changed_floor.policy_hash)
        self.assertNotEqual(first.policy_hash, changed_window.policy_hash)
        self.assertNotEqual(first.policy_hash, changed_tolerance.policy_hash)

    def test_floor_tolerance_and_renotify_configuration_is_bounded_and_visible(self) -> None:
        config = make_config(
            FL4SH_MONITOR_FLOOR_TOLERANCE_THS="2.5",
            FL4SH_MONITOR_REALLOCATE_RENOTIFY_DROP_THS="4.25",
        )
        self.assertEqual(config.floor_tolerance_ths, 2.5)
        self.assertEqual(config.reallocate_renotify_drop_ths, 4.25)
        rendered = MONITOR.format_config(config)
        self.assertIn("floor_tolerance_ths=2.5", rendered)
        self.assertIn("reallocate_renotify_drop_ths=4.25", rendered)
        for value in ("0", "0.5", "3.01", "nan", "inf", "secret-floor"):
            with self.subTest(value=value), self.assertRaises(MONITOR.MonitorConfigError):
                make_config(FL4SH_MONITOR_FLOOR_TOLERANCE_THS=value)
        for value in ("0", "nan", "inf", "1001", "secret-drop"):
            with self.subTest(value=value), self.assertRaises(MONITOR.MonitorConfigError):
                make_config(FL4SH_MONITOR_REALLOCATE_RENOTIFY_DROP_THS=value)

    def test_configuration_failure_output_uses_only_allowlisted_reason_codes(self) -> None:
        secret_json = '{"RTX_5080_LAPTOP":110,"token":"synthetic-secret"}'
        with mock.patch.dict(
            MONITOR.os.environ,
            {"FL4SH_MONITOR_ENABLED": "1", "FL4SH_MONITOR_GPU_FLOORS_JSON": secret_json},
            clear=True,
        ):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                result = MONITOR._check_config()
        self.assertEqual(result, 64)
        self.assertEqual(output.getvalue().strip(),
                         "FL4SH_MONITOR configuration invalid: INVALID_GPU_FLOORS_JSON")
        self.assertNotIn("synthetic-secret", output.getvalue())

        for env, expected in (
            ({"FL4SH_MONITOR_ENABLED": "1", "FL4SH_TELEGRAM_ENABLED": "1"}, "MISSING_TELEGRAM_TOKEN"),
            ({"FL4SH_MONITOR_ENABLED": "1", "FL4SH_TELEGRAM_ENABLED": "1",
              "FL4SH_TELEGRAM_BOT_TOKEN": "synthetic:valid-token"}, "MISSING_TELEGRAM_CHAT_ID"),
        ):
            with self.subTest(expected=expected), mock.patch.dict(MONITOR.os.environ, env, clear=True):
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    result = MONITOR._check_config()
                self.assertEqual(result, 64)
                self.assertIn(f"configuration invalid: {expected}", output.getvalue())

    def test_effective_policy_and_hash_are_visible_without_secrets(self) -> None:
        config = make_config(
            SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS="115",
            SALAD_G5_HASH_WINDOW_SECONDS="30",
        )
        rendered = MONITOR.format_config(config)
        self.assertIn("floor=115 floor_source=ENV", rendered)
        self.assertIn("hash_window_seconds=30", rendered)
        self.assertIn(f"policy_hash={config.policy_hash}", rendered)
        self.assertIn("actions_performed=false", rendered)
        self.assertIn("provider_binding=UNKNOWN", rendered)
        self.assertNotIn("FL4SH_MINING_ID", rendered)


    def test_dynamic_floor_registry_overrides_defaults_and_supports_new_gpu_keys(self) -> None:
        config = make_auto_config(
            SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS="125",
            FL4SH_MONITOR_GPU_FLOORS_JSON=(
                '{"RTX_5080_LAPTOP":110,"RTX_5090_LAPTOP":115,'
                '"RTX_5070_TI_LAPTOP":100}'
            ),
        )
        registry = dict(config.floor_registry)
        sources = dict(config.floor_registry_sources)
        self.assertEqual(registry["RTX_5080_LAPTOP"], 110)
        self.assertEqual(sources["RTX_5080_LAPTOP"], "ENV_REGISTRY")
        self.assertEqual(registry["RTX_5070_TI_LAPTOP"], 100)
        self.assertEqual(registry["RTX_5080_DESKTOP"], 209)
        self.assertIsNone(config.floor_ths)
        self.assertIn("FL4SH_MONITOR_GPU_FLOORS_JSON", MONITOR.format_config(config))

    def test_dynamic_registry_json_fails_closed_without_echoing_content(self) -> None:
        invalid = (
            "not-json synthetic-secret-123",
            "[]",
            "null",
            '{"RTX_5080_LAPTOP":true}',
            '{"RTX_5080_LAPTOP":"110"}',
            '{"RTX_5080_LAPTOP":0}',
            '{"RTX_5080_LAPTOP":-1}',
            '{"RTX_5080_LAPTOP":10001}',
            '{"RTX_5080_LAPTOP":NaN}',
            '{"RTX_5080_LAPTOP":Infinity}',
            '{"GPU__5080":110}',
            '{"rtx_5080_laptop":110}',
            '{"RTX_5080_LAPTOP":110,"RTX_5080_LAPTOP":111}',
            '{"RTX_5080_LAPTOP":110,"rtx_5080_laptop":111}',
        )
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(MONITOR.MonitorConfigError) as caught:
                    make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON=raw)
                self.assertNotIn("synthetic-secret-123", str(caught.exception))

    def test_registry_hash_changes_when_any_dynamic_floor_changes(self) -> None:
        one = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110,"RTX_5070_TI_LAPTOP":100}'
        )
        two = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110,"RTX_5070_TI_LAPTOP":101}'
        )
        self.assertNotEqual(one.policy_hash, two.policy_hash)

    def test_neutral_gpu_floor_keys_are_valid_and_change_policy_hash(self) -> None:
        neutral_110 = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_3090_TI":110}'
        )
        neutral_111 = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_3090_TI":111}'
        )
        self.assertEqual(dict(neutral_110.floor_registry)["RTX_3090_TI"], 110)
        self.assertNotEqual(neutral_110.policy_hash, neutral_111.policy_hash)

    def test_legacy_profile_can_select_dynamic_gpu_key_and_keeps_floor_source(self) -> None:
        config = make_config(
            FL4SH_MONITOR_PROFILE="RTX_5080_LAPTOP",
            FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110}',
        )
        self.assertEqual(config.profile, "RTX_5080_LAPTOP")
        self.assertEqual(config.floor_ths, 110)
        self.assertEqual(config.floor_source, "ENV_REGISTRY")


class GenericGpuContractTests(unittest.TestCase):
    """Operator registry numbers below are SYNTHETIC TEST ONLY."""

    def assert_registry_key(self, key: str) -> None:
        config = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON=MONITOR.json.dumps({key: 45}))
        self.assertEqual(dict(config.floor_registry)[key], 45)

    def test_01_rtx_3060_registry_key(self) -> None:
        self.assert_registry_key("RTX_3060")

    def test_02_rtx_a4000_registry_key(self) -> None:
        self.assert_registry_key("RTX_A4000")

    def test_03_rtx_a5000_registry_key(self) -> None:
        self.assert_registry_key("RTX_A5000")

    def test_04_a100_registry_key(self) -> None:
        self.assert_registry_key("A100_SXM4_80GB")

    def test_05_accelerator_registry_keys_independently(self) -> None:
        for key in ("L40S", "A10", "T4", "H100_SXM"):
            with self.subTest(key=key):
                self.assert_registry_key(key)

    def test_06_lowercase_keys_fail_closed(self) -> None:
        for key in ("rtx_a4000", "Rtx_A4000", "l40s", "A100_sxm4_80gb"):
            with self.subTest(key=key), self.assertRaises(MONITOR.MonitorConfigError):
                make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON=MONITOR.json.dumps({key: 45}))

    def test_07_duplicates_and_case_aliases_fail_closed(self) -> None:
        for raw in ('{"RTX_A4000":45,"RTX_A4000":46}', '{"RTX_A4000":45,"rtx_a4000":46}'):
            with self.subTest(raw=raw), self.assertRaises(MONITOR.MonitorConfigError) as caught:
                make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON=raw)
            self.assertNotIn(raw, str(caught.exception))

    def test_08_malformed_keys_and_raw_names_fail_closed(self) -> None:
        for key in ("A__10", "_A10", "A10_", "A10.T4", "A10/T4", "A10\n", "A10\x00"):
            with self.subTest(key=key), self.assertRaises(MONITOR.MonitorConfigError):
                self.assert_registry_key(key)
        for raw in ("NVIDIA RTX A4000/A5000", "NVIDIA A10\x00", "NVIDIA RTX A4000 + A5000",
                    "NVIDIA RTX A4000 A5000", "NVIDIA A10 T4", "NVIDIA RTX A4000 RTX A5000",
                    "NVIDIA A10 NVIDIA T4", "NVIDIA GeForce RTX 3060 Series", "RTX A4000"):
            with self.subTest(raw=raw):
                self.assertIsNone(MONITOR.normalize_gpu_identity(raw))

    def test_09_key_length_is_bounded_before_conversion(self) -> None:
        key = "A" + "1" * 127
        self.assert_registry_key(key)
        self.assertEqual(MONITOR.normalize_gpu_identity("NVIDIA " + key), key)
        for invalid in (key + "1", "RTX_3060_" + "TI_" * 40 + "TI"):
            with self.subTest(key=invalid), self.assertRaises(MONITOR.MonitorConfigError):
                self.assert_registry_key(invalid)
            self.assertIsNone(MONITOR.normalize_gpu_identity("NVIDIA " + invalid))

    def test_10_nvidia_professional_names(self) -> None:
        cases = {
            "NVIDIA RTX A4000": "RTX_A4000", "NVIDIA RTX A5000": "RTX_A5000",
            "NVIDIA RTX 4000 Ada Generation": "RTX_4000_ADA_GENERATION",
            "NVIDIA A100-SXM4-80GB": "A100_SXM4_80GB", "NVIDIA L40S": "L40S",
            "NVIDIA A10": "A10", "NVIDIA T4": "T4", "NVIDIA H100-SXM": "H100_SXM",
        }
        for raw, key in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(MONITOR.normalize_gpu_identity(raw), key)

    def test_11_geforce_3060_normalizes_without_desktop_inference(self) -> None:
        self.assertEqual(MONITOR.normalize_gpu_identity("NVIDIA GeForce RTX 3060"), "RTX_3060")

    def test_12_explicit_form_factors(self) -> None:
        for marker, suffix in (("Laptop", "LAPTOP"), ("Notebook", "LAPTOP"), ("Mobile", "LAPTOP"), ("Desktop", "DESKTOP")):
            with self.subTest(marker=marker):
                self.assertEqual(MONITOR.normalize_gpu_identity(f"NVIDIA RTX A4000 {marker} GPU"), f"RTX_A4000_{suffix}")

    def test_13_no_variant_or_model_floor_fallback(self) -> None:
        config = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_3060_LAPTOP":45,"RTX_3060_DESKTOP":50,"RTX_A5000":55}')
        for raw, key in (("NVIDIA GeForce RTX 3060", "RTX_3060"), ("NVIDIA RTX A4000", "RTX_A4000")):
            with self.subTest(key=key):
                monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
                event = monitor.observe_line(f"Device [1] {raw}: Initialized", now=0)[0]
                self.assertEqual(event["gpu_key"], key)
                self.assertIsNone(event["floor_ths"])
        neutral_only = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_A4000":45}')
        for form in ("Laptop", "Desktop"):
            monitor = MONITOR.Fl4shMonitor(neutral_only, start_monotonic=0)
            self.assertIsNone(monitor.observe_line(f"Device [1] NVIDIA RTX A4000 {form} GPU: Initialized", now=0)[0]["floor_ths"])

    def test_14_contradictory_form_factors_are_unknown(self) -> None:
        for markers in ("Laptop Desktop", "Notebook Mobile", "Desktop Laptop", "Laptop Laptop"):
            with self.subTest(markers=markers):
                self.assertIsNone(MONITOR.normalize_gpu_identity(f"NVIDIA RTX A4000 {markers} GPU"))

    def test_15_exact_5080_5090_exceptions_only(self) -> None:
        for model in ("5080", "5090"):
            self.assertEqual(MONITOR.normalize_gpu_identity(f"NVIDIA GeForce RTX {model}"), f"RTX_{model}_DESKTOP")
            self.assertEqual(MONITOR.normalize_gpu_identity(f"NVIDIA GeForce RTX {model} Laptop GPU"), f"RTX_{model}_LAPTOP")
            self.assertEqual(MONITOR.normalize_gpu_identity(f"NVIDIA RTX {model}"), f"RTX_{model}")
        self.assertEqual(MONITOR.normalize_gpu_identity("NVIDIA GeForce RTX 3060 GPU"), "RTX_3060")

    def test_16_all_generic_sources_corroborate_without_promoting_secondary(self) -> None:
        config = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_A4000":45}')
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        pearl = "GPU=NVIDIA RTX A4000 Pearl autotune hashrate = 9999 TH/s"
        solutions = "Solutions accepted: 1-NVIDIA RTX A4000, 0 stale"
        monitor.observe_line(solutions, now=0)
        monitor.observe_line(pearl, now=1)
        state = monitor.devices[1]
        self.assertFalse(state.identity_primary_seen)
        self.assertIsNone(state.gpu_key)
        self.assertIsNone(monitor._effective_floor(state)[0])
        self.assertEqual(len(state.samples), 0)
        detected = monitor.observe_line("Device [1] NVIDIA RTX A4000: Initialized", now=2)[0]
        self.assertEqual((detected["gpu_key"], detected["floor_ths"]), ("RTX_A4000", 45))
        monitor.observe_line(pearl, now=3)
        monitor.observe_line(solutions, now=4)
        self.assertEqual(state.identity_sources, {"device_initialized", "pearl_autotune_model", "solutions_accepted_model"})
        self.assertEqual(len(state.samples), 0)
        conflict = monitor.observe_line("Solutions accepted: 1-NVIDIA RTX A5000, 0 stale", now=5)[0]
        self.assertEqual(conflict["state"], "GPU_IDENTITY_CONFLICT")
        self.assertIsNone(conflict["floor_ths"])
        self.assertFalse(conflict["actions_performed"])

    def test_17_professional_solution_recovers_pool_once_with_evidence_hash(self) -> None:
        emitted: list[tuple[str, dict]] = []
        audit: list[str] = []
        notifier = SimpleNamespace(audit=audit.append, submit=lambda name, event, **_kwargs: emitted.append((name, event)))
        now = [0.0]
        coordinator = MONITOR.TelegramAlertCoordinator(notifier, make_telegram_config(), monotonic=lambda: now[0],
                                                     monitor_session_id="44444444-4444-4444-8444-444444444444")
        monitor = MONITOR.Fl4shMonitor(make_auto_config(), start_monotonic=0)
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, monitor)
        now[0] = 10.0
        accepted = "Solutions accepted: 1-NVIDIA RTX A4000, 0 stale"
        coordinator.stdout_line(accepted, monitor)
        coordinator.stdout_line(accepted, monitor)
        self.assertEqual([name for name, _ in emitted], ["POOL_CONNECTION_FAILED", "POOL_CONNECTION_RECOVERED"])
        recovered = emitted[-1][1]
        self.assertEqual(recovered["solutions_evidence_sha256"], MONITOR.hashlib.sha256(accepted.encode()).hexdigest())
        self.assertEqual(recovered["pool_alert_sequence"], 2)
        self.assertFalse(recovered["actions_performed"])
        self.assertEqual(sum("state=POOL_RECOVERY_EVIDENCE" in entry for entry in audit), 1)
        for invalid in ("Solutions accepted: 1-NVIDIA arbitrary", "Solutions accepted: 1-NVIDIA RTX A4000 A5000",
                        "Solutions accepted: 1-NVIDIA RTX A4000 Laptop Desktop GPU", "Solutions accepted: 1-NVIDIA RTX A4000; extra"):
            with self.subTest(line=invalid):
                self.assertFalse(MONITOR._is_solutions_accepted_recovery_line(invalid))

    def test_19_generic_identity_without_floor_never_recommends(self) -> None:
        config = make_auto_config()
        self.assertNotIn("RTX_A4000", dict(config.floor_registry))
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        monitor.observe_line("Device [1] NVIDIA RTX A4000: Initialized", now=0)
        events = []
        for instant in (0, 10, 20, 30):
            events.extend(monitor.observe_line(line(1), now=instant))
        self.assertTrue(any(event["state"] == "NO_FLOOR_CONFIGURED" for event in events))
        self.assertFalse(any(event["state"] == "REALLOCATE_RECOMMENDED" for event in events))

    def test_20_generic_floor_changes_policy_hash(self) -> None:
        one = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_A4000":45}')
        two = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_A4000":46}')
        self.assertNotEqual(one.policy_hash, two.policy_hash)

    def test_synthetic_operator_ten_key_registry_and_existing_limits(self) -> None:
        registry = {"RTX_3060":25, "RTX_A4000":45, "RTX_3090":110, "RTX_3090_TI":110,
                    "RTX_5070":120, "RTX_5070_TI":165, "RTX_5080_LAPTOP":105, "RTX_5090_LAPTOP":110,
                    "RTX_5080_DESKTOP":209, "RTX_5090_DESKTOP":350}
        config = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON=MONITOR.json.dumps(registry))
        self.assertEqual(dict(config.floor_registry), registry)
        for raw in (MONITOR.json.dumps({f"GPU_{index}":45 for index in range(65)}),
                    " " * (16 * 1024 + 1), '{"RTX_A4000":true}', '{"RTX_A4000":10001}'):
            with self.subTest(size=len(raw)), self.assertRaises(MONITOR.MonitorConfigError):
                make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON=raw)

    def test_generic_supervisor_preserves_original_stdout(self) -> None:
        raw_lines = ["Device [1] NVIDIA RTX A4000: Initialized",
                     "GPU=NVIDIA RTX A4000 Pearl autotune hashrate = 9999 TH/s",
                     "Solutions accepted: 1-NVIDIA RTX A4000, 0 stale",
                     "Device [1] hashRate: 46.00 TH/s"]
        environment = {
            "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
            "FL4SH_MONITOR_ENABLED":"1", "FL4SH_MONITOR_GPU_FLOORS_JSON":'{"RTX_A4000":45}',
        }
        child = "\n".join(f"print({raw!r}, flush=True)" for raw in raw_lines)
        completed = subprocess.run([sys.executable, str(ROOT / "fl4sh-runtime-monitor.py"), "--",
                                    sys.executable, "-c", child], env=environment, capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        output = completed.stdout.decode("utf-8", "replace")
        for raw in raw_lines:
            self.assertEqual(output.splitlines().count(raw), 1)
        self.assertIn("gpu_key=RTX_A4000", output)
        self.assertIn("floor_ths=45", output)
        self.assertNotIn("machine_id=", output)
        self.assertNotIn("REALLOCATE_RECOMMENDED", output)


class TelegramAuditTests(unittest.TestCase):
    def test_default_disabled_creates_no_worker_and_never_calls_sender(self) -> None:
        audit: list[str] = []
        notifier = MONITOR.TelegramNotifier(
            MONITOR.TelegramConfig.from_env({}),
            audit=audit.append,
            sender=lambda *_args: self.fail("disabled notifier called sender"),
        )
        self.assertIsNone(notifier._worker)
        self.assertIsNone(notifier._queue)
        self.assertIsNone(
            notifier.submit("POOL_CONNECTION_FAILED", {}, monitor_session_id="synthetic-session")
        )
        self.assertEqual(audit, [])
        notifier.close()

    def test_enabled_requires_token_and_chat_without_echoing_token(self) -> None:
        token = "synthetic_sensitive_bot_token"
        with self.assertRaises(MONITOR.TelegramConfigError) as caught:
            MONITOR.TelegramConfig.from_env(
                {"FL4SH_TELEGRAM_ENABLED": "1", "FL4SH_TELEGRAM_BOT_TOKEN": token}
            )
        self.assertNotIn(token, str(caught.exception))
        with self.assertRaises(MONITOR.TelegramConfigError):
            MONITOR.TelegramConfig.from_env(
                {
                    "FL4SH_TELEGRAM_ENABLED": "1",
                    "FL4SH_TELEGRAM_BOT_TOKEN": token,
                    "FL4SH_TELEGRAM_CHAT_ID": "invalid chat id",
                }
            )
        self.assertNotIn(token, repr(make_telegram_config()))
        with self.assertRaises(MONITOR.TelegramConfigError) as label_error:
            make_telegram_config(FL4SH_MONITOR_LABEL="lab synthetic:telegram_test_token")
        self.assertNotIn("synthetic:telegram_test_token", str(label_error.exception))

    def test_token_and_chat_are_not_in_monitor_config_or_policy_hash(self) -> None:
        token = "synthetic_sensitive_bot_token"
        baseline = {
            "FL4SH_MONITOR_ENABLED": "1",
            "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
            "SALAD_G5_WARMUP_SECONDS": "0",
            "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "10",
            "SALAD_G5_HASH_WINDOW_SECONDS": "20",
            "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
            "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
            "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "10",
            "SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO": "0.8",
            "SALAD_G5_CONSECUTIVE_BAD_WINDOWS": "2",
        }
        first = MONITOR.MonitorConfig.from_env(baseline, require_enabled=True)
        with_secrets = dict(baseline)
        with_secrets.update(
            FL4SH_TELEGRAM_ENABLED="1",
            FL4SH_TELEGRAM_BOT_TOKEN=token,
            FL4SH_TELEGRAM_CHAT_ID="-1001234567890",
        )
        second = MONITOR.MonitorConfig.from_env(
            with_secrets, require_enabled=True
        )
        self.assertEqual(first.policy_hash, second.policy_hash)
        self.assertNotIn("telegram_enabled=", MONITOR.format_config(first))
        self.assertNotIn(token, MONITOR.format_config(second, telegram_enabled=True))
        self.assertNotIn("-1001234567890", MONITOR.format_config(second, telegram_enabled=True))

    def test_message_has_same_valid_alert_id_fields_and_optional_session(self) -> None:
        import uuid

        alert_id = str(uuid.uuid4())
        event = {
            "gpu_key": "RTX_5080_LAPTOP",
            "device": "fl4shminer_device:1",
            "floor_ths": 110.0,
            "observed_window_mean_ths": 104.25,
            "consecutive_bad_windows": 2,
            "consecutive_bad_windows_required": 2,
            "stale_counter": {
                "numerator": 3,
                "denominator": 80,
                "reported_percent": 3.75,
            },
            "timestamp_utc": "2026-10-12T12:30:00+00:00",
        }
        message = MONITOR.format_telegram_message(
            "REALLOCATE_RECOMMENDED", event,
            alert_id=alert_id, monitor_session_id=None, label="lab one",
        )
        self.assertIn(f"alert_id: {alert_id}", message)
        self.assertIn("monitor_session_id: unknown", message)
        self.assertIn("label: lab one", message)
        self.assertIn("GPU: RTX_5080_LAPTOP", message)
        self.assertIn("device: fl4shminer_device:1", message)
        self.assertIn("floor_ths: 110", message)
        self.assertIn("observed_window_mean_ths: 104.25", message)
        self.assertIn("bad_windows: 2/2", message)
        self.assertIn("stale_counter: 3/80 (3.75%)", message)
        self.assertIn("actions_performed: false", message)
        self.assertIn("Provider Machine ID: unavailable in local container", message)
        self.assertIn("Identity source: LOCAL_MONITOR_ONLY", message)
        self.assertNotIn("Machine ID: correlate", message)

    def test_message_marks_stale_percentage_unknown_when_not_reported(self) -> None:
        message = MONITOR.format_telegram_message(
            "REALLOCATE_RECOMMENDED",
            {"stale_counter": {"numerator": 3, "denominator": 80}},
            alert_id="synthetic-alert",
            monitor_session_id=None,
            label=None,
        )
        self.assertIn("stale_counter: 3/80 (unknown)", message)

    def test_https_sender_uses_only_fixed_host_tls_and_one_post(self) -> None:
        config = make_telegram_config()
        captured: dict[str, object] = {}

        class Response:
            status = 200

            def read(self, size: int) -> bytes:
                captured["response_limit"] = size
                return b'{"ok":true}'

        class Connection:
            def __init__(self, host: str, port: int, **kwargs: object) -> None:
                captured.update(host=host, port=port, **kwargs)

            def request(self, method: str, target: str, **kwargs: object) -> None:
                captured.update(method=method, target=target, request=kwargs)

            def getresponse(self) -> Response:
                captured["getresponse_count"] = int(captured.get("getresponse_count", 0)) + 1
                return Response()

            def close(self) -> None:
                captured["closed"] = True

        self.assertTrue(
            MONITOR._send_telegram_message(
                config, "synthetic message", connection_factory=Connection
            )
        )
        self.assertEqual(captured["host"], "api.telegram.org")
        self.assertEqual(captured["port"], 443)
        self.assertEqual(captured["timeout"], MONITOR.TELEGRAM_TIMEOUT_SECONDS)
        self.assertEqual(captured["context"].verify_mode, MONITOR.ssl.CERT_REQUIRED)
        self.assertTrue(captured["context"].check_hostname)
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(
            captured["target"],
            f"/bot{config.bot_token}/sendMessage",
        )
        self.assertEqual(captured["getresponse_count"], 1)
        self.assertEqual(captured["response_limit"], MONITOR.TELEGRAM_MAX_RESPONSE_BYTES + 1)
        self.assertTrue(captured["closed"])

    def test_https_exception_with_secret_url_is_sanitized_and_not_retried(self) -> None:
        config = make_telegram_config()
        token = config.bot_token
        calls: list[int] = []

        class Connection:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                return None

            def request(self, *_args: object, **_kwargs: object) -> None:
                calls.append(1)
                raise OSError(f"synthetic failure /bot{token}/sendMessage")

            def close(self) -> None:
                return None

        self.assertFalse(
            MONITOR._send_telegram_message(
                config, "synthetic message", connection_factory=Connection
            )
        )
        self.assertEqual(calls, [1])

    def test_https_redirect_is_a_failure_without_following_another_request(self) -> None:
        config = make_telegram_config()
        calls: list[str] = []

        class Response:
            status = 302

            def read(self, _size: int) -> bytes:
                return b'{"ok":true}'

        class Connection:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                return None

            def request(self, method: str, target: str, **_kwargs: object) -> None:
                calls.append(f"{method} {target}")

            def getresponse(self) -> Response:
                return Response()

            def close(self) -> None:
                return None

        self.assertFalse(
            MONITOR._send_telegram_message(
                config, "synthetic message", connection_factory=Connection
            )
        )
        self.assertEqual(len(calls), 1)

    def test_recommendation_is_once_per_episode_and_rearmed_by_recovery(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[str] = []

            def submit(self, event_name: str, _event: object, *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append(event_name)
                self.assert_session = monitor_session_id
                return "synthetic-alert-id"

        fake = FakeNotifier()
        config = make_telegram_config()
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake, config, monotonic=lambda: 0.0, monitor_session_id="session-local"
        )
        recommendation = {
            "state": "REALLOCATE_RECOMMENDED",
            "device": "fl4shminer_device:1",
        }
        coordinator.monitor_events([recommendation, recommendation])
        coordinator.monitor_events([{"state": "RECOVERED", "device": "fl4shminer_device:1"}])
        coordinator.monitor_events([recommendation])
        self.assertEqual(fake.events, ["REALLOCATE_RECOMMENDED", "REALLOCATE_RECOMMENDED"])
        self.assertEqual(fake.assert_session, "session-local")

    def test_recommendation_allows_deduplicated_sequences_in_one_episode(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return "synthetic-alert-id"

        fake = FakeNotifier()
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake, make_telegram_config(), monotonic=lambda: 0.0, monitor_session_id="session-local"
        )
        episode = "11111111-1111-4111-8111-111111111111"
        first = {"state": "REALLOCATE_RECOMMENDED", "device": "fl4shminer_device:1",
                 "degradation_episode_id": episode, "alert_sequence": 1}
        second = {**first, "alert_sequence": 2}
        third = {**first, "alert_sequence": 3}
        coordinator.monitor_events([first, first, second, second, third])
        self.assertEqual([item[0] for item in fake.events], [
            "REALLOCATE_RECOMMENDED", "REALLOCATE_RECOMMENDED", "REALLOCATE_RECOMMENDED",
        ])
        coordinator.monitor_events([{"state": "RECOVERED", "device": "fl4shminer_device:1"}])
        coordinator.monitor_events([{**first, "degradation_episode_id": "22222222-2222-4222-8222-222222222222"}])
        self.assertEqual(len(fake.events), 4)

    def test_pool_failures_form_one_episode_and_escalate_after_five_minutes(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []
                self.audit_lines: list[str] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return alert_id or "synthetic-alert-id"

            def audit(self, line_text: str) -> None:
                self.audit_lines.append(line_text)

        current = [0.0]
        base_utc = datetime(2026, 10, 13, 17, 43, 30, tzinfo=timezone.utc)
        fake = FakeNotifier()
        config = make_telegram_config(FL4SH_TELEGRAM_POOL_ERROR_COOLDOWN_SECONDS="300")
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0.0)
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake, config, monotonic=lambda: current[0],
            monitor_session_id="11111111-1111-4111-8111-111111111111",
            utc_now=lambda: base_utc + timedelta(seconds=current[0]),
        )
        monitor.observe_line(line(90, stale="3/80 (3.75%)"), now=1.0)
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, monitor)
        current[0] = 300.0
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, monitor)
        current[0] = 600.0
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, monitor)
        self.assertEqual([name for name, _event in fake.events], [
            "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
        ])
        failed = fake.events[0][1]
        unstable = fake.events[1][1]
        self.assertEqual(failed["failure_count"], 1)
        self.assertEqual(failed["pool_alert_sequence"], 1)
        self.assertEqual(unstable["failure_count"], 2)
        self.assertEqual(unstable["pool_alert_sequence"], 2)
        self.assertEqual(unstable["notification_reason"], "PERSISTENT_FAILURES")
        self.assertEqual(unstable["first_failure_utc"], "2026-10-13T17:43:30Z")
        self.assertEqual(unstable["latest_failure_utc"], "2026-10-13T17:48:30Z")
        self.assertEqual(failed["pool_episode_id"], unstable["pool_episode_id"])
        self.assertEqual(
            failed["stale_counter"],
            {"numerator": 3, "denominator": 80, "reported_percent": 3.75},
        )
        message = MONITOR.format_telegram_message(
            "POOL_CONNECTION_UNSTABLE",
            unstable,
            alert_id="synthetic-alert",
            monitor_session_id="11111111-1111-4111-8111-111111111111",
            label=None,
        )
        self.assertIn("reason: MINING_AUTHORIZE_RESPONSE_TIMEOUT", message)
        self.assertIn("notification_reason: PERSISTENT_FAILURES", message)
        self.assertIn("Recommendation: CHECK_POOL_OR_NETWORK", message)
        self.assertNotIn(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, message)
        self.assertNotIn(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, message)
        self.assertNotIn("retry_seconds", message)
        self.assertEqual(len(fake.audit_lines), 2)
        self.assertTrue(all("actions_performed=false" in line_text for line_text in fake.audit_lines))

    def test_three_exact_pool_timeouts_escalate_as_burst_once(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []
                self.audit_lines: list[str] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return alert_id or "synthetic-alert-id"

            def audit(self, line_text: str) -> None:
                self.audit_lines.append(line_text)

        current = [0.0]
        base_utc = datetime(2026, 10, 13, 17, 43, 30, tzinfo=timezone.utc)
        fake = FakeNotifier()
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake, make_telegram_config(), monotonic=lambda: current[0],
            monitor_session_id="22222222-2222-4222-8222-222222222222",
            utc_now=lambda: base_utc + timedelta(seconds=current[0]),
        )
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        for elapsed in (0.0, 30.0, 89.0):
            current[0] = elapsed
            coordinator.stdout_line(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, monitor)
        self.assertEqual([name for name, _event in fake.events], [
            "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
        ])
        unstable = fake.events[-1][1]
        self.assertEqual(unstable["failure_count"], 3)
        self.assertEqual(unstable["recent_failure_count"], 3)
        self.assertEqual(unstable["notification_reason"], "BURST_FAILURES")
        message = MONITOR.format_telegram_message(
            "POOL_CONNECTION_UNSTABLE", unstable,
            alert_id="synthetic-alert", monitor_session_id="22222222-2222-4222-8222-222222222222", label=None,
        )
        self.assertIn("notification_reason: BURST_FAILURES", message)
        self.assertNotIn("Pool connection failed", message)
        self.assertEqual(len(fake.audit_lines), 2)
        self.assertIn("state=POOL_CONNECTION_UNSTABLE", fake.audit_lines[-1])

    def test_unstable_reminder_requires_elapsed_cooldown_and_new_failure(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []
                self.audit_lines: list[str] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return alert_id or "synthetic-alert-id"

            def audit(self, line_text: str) -> None:
                self.audit_lines.append(line_text)

        current = [0.0]
        base_utc = datetime(2026, 10, 13, 17, 43, 30, tzinfo=timezone.utc)
        fake = FakeNotifier()
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake, make_telegram_config(), monotonic=lambda: current[0],
            monitor_session_id="33333333-3333-4333-8333-333333333333",
            utc_now=lambda: base_utc + timedelta(seconds=current[0]),
        )
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        for elapsed in (0.0, 30.0, 60.0):
            current[0] = elapsed
            coordinator.stdout_line(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, monitor)
        # Time alone never emits a reminder.
        current[0] = 960.0
        self.assertEqual(len(fake.events), 2)
        current[0] = 959.9
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, monitor)
        self.assertEqual([name for name, _event in fake.events].count("POOL_CONNECTION_UNSTABLE"), 1)
        current[0] = 960.0
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, monitor)
        reminders = [event for name, event in fake.events if name == "POOL_CONNECTION_UNSTABLE"]
        self.assertEqual(len(reminders), 2)
        self.assertEqual(reminders[-1]["notification_reason"], "STILL_UNSTABLE")
        self.assertEqual(reminders[-1]["pool_alert_sequence"], 3)
        self.assertEqual(reminders[-1]["failure_count"], 5)

    def test_solutions_accepted_recovers_once_and_next_timeout_starts_new_episode(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []
                self.audit_lines: list[str] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return alert_id or "synthetic-alert-id"

            def audit(self, line_text: str) -> None:
                self.audit_lines.append(line_text)

        current = [0.0]
        base_utc = datetime(2026, 10, 13, 17, 43, 30, tzinfo=timezone.utc)
        fake = FakeNotifier()
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake, make_telegram_config(), monotonic=lambda: current[0],
            monitor_session_id="44444444-4444-4444-8444-444444444444",
            utc_now=lambda: base_utc + timedelta(seconds=current[0]),
        )
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, monitor)
        first_episode = fake.events[0][1]["pool_episode_id"]
        current[0] = 300.0
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, monitor)
        self.assertEqual(fake.events[-1][0], "POOL_CONNECTION_UNSTABLE")
        self.assertEqual(fake.events[-1][1]["pool_alert_sequence"], 2)
        accepted_line = "Solutions accepted: 5-NVIDIA GeForce RTX 5090 Laptop GPU, 0 stale"
        current[0] = 305.0
        coordinator.stdout_line(accepted_line, monitor)
        coordinator.stdout_line("Solutions accepted: 5-NVIDIA GeForce RTX 5090 Laptop GPU, 0 stale", monitor)
        recovered = [event for name, event in fake.events if name == "POOL_CONNECTION_RECOVERED"]
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["pool_episode_id"], first_episode)
        self.assertEqual(recovered[0]["pool_alert_sequence"], 3)
        self.assertEqual(recovered[0]["prior_failure_count"], 2)
        self.assertEqual(recovered[0]["failure_count"], 2)
        self.assertEqual(recovered[0]["retry_seconds"], 10)
        evidence_marker = next(line_text for line_text in fake.audit_lines if "state=POOL_RECOVERY_EVIDENCE" in line_text)
        self.assertEqual(sum("state=POOL_RECOVERY_EVIDENCE" in line_text for line_text in fake.audit_lines), 1)
        self.assertIn("pool_alert_sequence=3", evidence_marker)
        self.assertIn(
            "solutions_evidence_sha256=" + MONITOR.hashlib.sha256(accepted_line.encode("utf-8")).hexdigest(),
            evidence_marker,
        )
        self.assertEqual(recovered[0]["recovery_signal"], "SOLUTIONS_ACCEPTED")
        recovery_message = MONITOR.format_telegram_message(
            "POOL_CONNECTION_RECOVERED", recovered[0], alert_id="synthetic-alert",
            monitor_session_id=coordinator.monitor_session_id, label=None,
        )
        self.assertIn("recovery_signal: SOLUTIONS_ACCEPTED", recovery_message)
        self.assertIn("pool_alert_sequence: 3", recovery_message)
        self.assertIn("failure_count: 2", recovery_message)
        self.assertIn("retry reported by miner: 10s", recovery_message)
        self.assertIn("timestamp_utc: 2026-10-13T17:48:35Z", recovery_message)
        self.assertNotIn("Machine ID: correlate", recovery_message)
        self.assertEqual([name for name, _event in fake.events], [
            "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE", "POOL_CONNECTION_RECOVERED",
        ])
        current[0] = 306.0
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, monitor)
        next_episode = fake.events[-1][1]["pool_episode_id"]
        self.assertNotEqual(first_episode, next_episode)
        self.assertEqual(fake.events[-1][1]["pool_alert_sequence"], 1)

    def test_delayed_first_failure_does_not_reject_a_later_valid_burst_window(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return alert_id or "synthetic-alert-id"

            def audit(self, _line_text: str) -> None:
                return None

        current = [0.0]
        base_utc = datetime(2026, 10, 13, 17, 43, 30, tzinfo=timezone.utc)
        fake = FakeNotifier()
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake, make_telegram_config(), monotonic=lambda: current[0],
            monitor_session_id="77777777-7777-4777-8777-777777777777",
            utc_now=lambda: base_utc + timedelta(seconds=current[0]),
        )
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        for elapsed in (0.0, 200.0, 210.0, 220.0):
            current[0] = elapsed
            coordinator.stdout_line(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, monitor)

        unstable = [event for name, event in fake.events if name == "POOL_CONNECTION_UNSTABLE"]
        self.assertEqual(len(unstable), 1)
        self.assertEqual(unstable[0]["notification_reason"], "BURST_FAILURES")
        self.assertEqual(unstable[0]["recent_failure_count"], 3)
        self.assertEqual(unstable[0]["recent_failure_window_start_utc"], "2026-10-13T17:46:50Z")
        self.assertEqual(unstable[0]["latest_failure_utc"], "2026-10-13T17:47:10Z")

    def test_hashrate_does_not_recover_pool_and_new_monitor_session_has_no_episode(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return alert_id or "synthetic-alert-id"

            def audit(self, _line_text: str) -> None:
                return None

        fake = FakeNotifier()
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        first = MONITOR.TelegramAlertCoordinator(
            fake, make_telegram_config(), monotonic=lambda: 0.0,
            monitor_session_id="55555555-5555-4555-8555-555555555555",
        )
        first.stdout_line(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, monitor)
        first.stdout_line(line(150), monitor)
        self.assertEqual([name for name, _event in fake.events], ["POOL_CONNECTION_FAILED"])
        restarted = MONITOR.TelegramAlertCoordinator(
            fake, make_telegram_config(), monotonic=lambda: 1.0,
            monitor_session_id="66666666-6666-4666-8666-666666666666",
        )
        restarted.stdout_line("Solutions accepted: 5-NVIDIA GeForce RTX 5090 Laptop GPU, 0 stale", monitor)
        self.assertEqual([name for name, _event in fake.events], ["POOL_CONNECTION_FAILED"])

    def test_pool_alert_rejects_nonmatching_errors_and_out_of_bounds_retries(self) -> None:
        class FakeNotifier:
            def __init__(self) -> None:
                self.events: list[tuple[str, dict[str, object]]] = []

            def submit(self, event_name: str, event: dict[str, object], *, monitor_session_id: str, alert_id: str | None = None) -> str:
                self.events.append((event_name, event))
                return "synthetic-alert-id"

        fake = FakeNotifier()
        coordinator = MONITOR.TelegramAlertCoordinator(
            fake,
            make_telegram_config(),
            monotonic=lambda: 0.0,
            monitor_session_id="session-local",
        )
        monitor = MONITOR.Fl4shMonitor(make_config())
        nonmatching_lines = [
            "Pool connection failed: connection refused",
            "mining.authorize rejected",
            "arbitrary text containing response timeout",
            MONITOR.POOL_CONNECTION_FAILED_LINE,
            "Pool connection failed: mining.authorize response timeout; reconnecting; retrying in 0s",
            "Pool connection failed: mining.authorize response timeout; reconnecting; retrying in 86401s",
            "Pool connection failed: mining.authorize response timeout; reconnecting; retrying in 999999s",
            "2026/13/12 22:04:33 " + POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP,
            "Pool connection failed: mining.authorize response timeout; reconnecting after 10s",
        ]
        for candidate in nonmatching_lines:
            coordinator.stdout_line(candidate, monitor)
        self.assertEqual(fake.events, [])
        coordinator.stdout_line(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, monitor)
        self.assertEqual(len(fake.events), 1)
        event_name, event = fake.events[0]
        self.assertEqual(event["retry_seconds"], 10)
        message = MONITOR.format_telegram_message(
            event_name,
            event,
            alert_id="synthetic-alert",
            monitor_session_id="session-local",
            label=None,
        )
        self.assertIn("reason: MINING_AUTHORIZE_RESPONSE_TIMEOUT", message)
        self.assertIn("retry: 10s", message)
        self.assertNotIn(POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP, message)
        self.assertNotIn("retry_seconds", message)
        self.assertNotIn("raw_line", event)

    def test_notifier_transport_failure_is_nonfatal_and_sanitized(self) -> None:
        secret = "synthetic_sensitive_bot_token"
        config = make_telegram_config(FL4SH_TELEGRAM_BOT_TOKEN=secret)
        audit: list[str] = []
        done = threading.Event()

        def capture(line_text: str) -> None:
            audit.append(line_text)
            if "TELEGRAM_NOTIFY_FAILED" in line_text:
                done.set()

        def failure(_config: object, _message: str) -> bool:
            raise OSError(f"synthetic /bot{secret}/sendMessage failure")

        notifier = MONITOR.TelegramNotifier(config, audit=capture, sender=failure)
        alert_id = notifier.submit(
            "POOL_CONNECTION_FAILED", {}, monitor_session_id="session-local"
        )
        self.assertTrue(done.wait(timeout=2.0))
        notifier.close()
        rendered = "\n".join(audit)
        self.assertIsNotNone(alert_id)
        self.assertIn(f"alert_id={alert_id}", rendered)
        self.assertIn("reason=TRANSPORT", rendered)
        self.assertNotIn(secret, rendered)

    def test_bounded_queue_reports_full_without_blocking_submitter(self) -> None:
        config = make_telegram_config()
        started = threading.Event()
        release = threading.Event()
        audit: list[str] = []

        def slow_sender(_config: object, _message: str) -> bool:
            started.set()
            release.wait(timeout=2.0)
            return False

        notifier = MONITOR.TelegramNotifier(
            config, audit=audit.append, sender=slow_sender, queue_capacity=1
        )
        notifier.submit("POOL_CONNECTION_FAILED", {}, monitor_session_id="session")
        self.assertTrue(started.wait(timeout=1.0))
        notifier.submit("POOL_CONNECTION_FAILED", {}, monitor_session_id="session")
        notifier.submit("POOL_CONNECTION_FAILED", {}, monitor_session_id="session")
        self.assertTrue(any("reason=QUEUE_FULL" in line_text for line_text in audit))
        release.set()
        notifier.close()

    def test_sender_error_does_not_change_harmless_child_exit_status(self) -> None:
        secret = "synthetic_sensitive_bot_token"
        telegram = make_telegram_config(FL4SH_TELEGRAM_BOT_TOKEN=secret)
        code = f"print({POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP!r}, flush=True); raise SystemExit(7)"
        output = io.BytesIO()
        error = io.BytesIO()
        fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))

        def fail_sender(_config: object, _message: str) -> bool:
            raise OSError(f"do not expose /bot{secret}/sendMessage")

        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            MONITOR, "sys", fake_sys
        ), mock.patch.dict(
            MONITOR.os.environ,
            {
                "FL4SH_TELEGRAM_ENABLED": "1",
                "FL4SH_TELEGRAM_BOT_TOKEN": secret,
                "FL4SH_TELEGRAM_CHAT_ID": "-1001234567890",
            },
            clear=False,
        ):
            result = MONITOR.run_supervisor(
                make_config(),
                [sys.executable, "-c", code],
                telegram_config=telegram,
                telegram_sender=fail_sender,
            )
        log_output = (output.getvalue() + error.getvalue()).decode("utf-8", "replace")
        self.assertEqual(result, 7)
        self.assertIn("TELEGRAM_NOTIFY_FAILED", log_output)
        self.assertNotIn(secret, log_output)

    def test_supervisor_keeps_credentials_out_of_child_and_alert_id_matches_payload(self) -> None:
        config = make_config()
        telegram = make_telegram_config(FL4SH_MONITOR_LABEL="synthetic lab")
        token = telegram.bot_token or ""
        chat_id = telegram.chat_id or ""
        child_code = (
            "import os; print('child_secret_env=' + repr((os.getenv('FL4SH_TELEGRAM_BOT_TOKEN'), "
            "os.getenv('FL4SH_TELEGRAM_CHAT_ID'))), flush=True); "
            f"print('synthetic echo {token}', flush=True); "
            f"print({POOL_CONNECTION_FAILED_WITH_TIMESTAMP!r}, flush=True); "
            "print('Device [1] hashRate: 1.00 TH/s', flush=True)"
        )
        output = io.BytesIO()
        error = io.BytesIO()
        fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))
        messages: list[str] = []
        sent = threading.Event()

        def sender(_config: object, message: str) -> bool:
            messages.append(message)
            sent.set()
            return True

        environment = {
            "FL4SH_TELEGRAM_BOT_TOKEN": token,
            "FL4SH_TELEGRAM_CHAT_ID": chat_id,
            "FL4SH_TELEGRAM_ENABLED": "1",
            "FL4SH_TELEGRAM_POOL_ERROR_COOLDOWN_SECONDS": "300",
            "FL4SH_MONITOR_LABEL": "synthetic lab",
        }
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            MONITOR, "sys", fake_sys
        ), mock.patch.dict(MONITOR.os.environ, environment, clear=False):
            result = MONITOR.run_supervisor(
                config,
                [sys.executable, "-c", child_code],
                telegram_config=telegram,
                telegram_sender=sender,
            )
        self.assertEqual(result, 0)
        self.assertTrue(sent.wait(timeout=0.1))
        log_output = (output.getvalue() + error.getvalue()).decode("utf-8", "replace")
        self.assertNotIn(token, log_output)
        self.assertNotIn(chat_id, log_output)
        self.assertNotIn(token, repr(messages))
        self.assertNotIn(chat_id, repr(messages))
        self.assertIn("child_secret_env=(None, None)", log_output)
        self.assertIn("[REDACTED]", log_output)
        self.assertIn(POOL_CONNECTION_FAILED_WITH_TIMESTAMP, log_output.splitlines())
        alert_lines = [line_text for line_text in log_output.splitlines() if "state=TELEGRAM_ALERT" in line_text]
        self.assertEqual(len(alert_lines), 1)
        import re
        alert_id_match = re.search(r"alert_id=([0-9a-f-]{36})", alert_lines[0])
        self.assertIsNotNone(alert_id_match)
        assert alert_id_match is not None
        self.assertIn(f"alert_id: {alert_id_match.group(1)}", messages[0])
        self.assertIn("event: POOL_CONNECTION_FAILED", messages[0])
        self.assertIn("monitor_session_id: ", messages[0])
        self.assertIn("Provider Machine ID: unavailable in local container", messages[0])
        self.assertIn("Identity source: LOCAL_MONITOR_ONLY", messages[0])
        self.assertNotIn("Machine ID: correlate", messages[0])
        self.assertIn("TELEGRAM_NOTIFY_SENT", log_output)

    def test_telegram_disabled_preserves_original_popen_kwargs_inheritance_and_exit_code(self) -> None:
        config = make_config()
        telegram = MONITOR.TelegramConfig.from_env({"FL4SH_TELEGRAM_ENABLED": "0"})
        captured: dict[str, object] = {}
        output = io.BytesIO()
        error = io.BytesIO()
        fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))
        child_code = (
            "import os; print('inherited=' + os.environ.get('FL4SH_TEST_INHERITED', 'missing'), flush=True); "
            "raise SystemExit(7)"
        )
        real_popen = subprocess.Popen

        def capture_popen(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            captured["command"] = list(command)
            captured["kwargs"] = dict(kwargs)
            return real_popen(command, **kwargs)

        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            MONITOR, "sys", fake_sys
        ), mock.patch.dict(
            MONITOR.os.environ,
            {
                "FL4SH_TELEGRAM_ENABLED": "0",
                "FL4SH_TEST_INHERITED": "available",
            },
            clear=False,
        ):
            result = MONITOR.run_supervisor(
                config,
                [sys.executable, "-c", child_code],
                telegram_config=telegram,
                popen_factory=capture_popen,
            )

        self.assertEqual(result, 7)
        self.assertEqual(captured["command"], [sys.executable, "-c", child_code])
        self.assertEqual(
            captured["kwargs"],
            {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "bufsize": 0},
        )
        self.assertIn(b"inherited=available", output.getvalue())

    def test_pool_episode_audit_records_are_emitted_when_direct_telegram_is_off(self) -> None:
        config = make_config()
        telegram = MONITOR.TelegramConfig.from_env({"FL4SH_TELEGRAM_ENABLED": "0"})
        accepted = "Solutions accepted: 5-NVIDIA GeForce RTX 5090 Laptop GPU, 0 stale"
        child_code = (
            f"print({POOL_CONNECTION_FAILED_WITHOUT_TIMESTAMP!r}, flush=True); "
            f"print({accepted!r}, flush=True); "
            "print('Device [1] hashRate: 1.00 TH/s', flush=True)"
        )
        output = io.BytesIO()
        error = io.BytesIO()
        fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            MONITOR, "sys", fake_sys
        ), mock.patch.dict(MONITOR.os.environ, {"FL4SH_TELEGRAM_ENABLED": "0"}, clear=False):
            result = MONITOR.run_supervisor(
                config,
                [sys.executable, "-c", child_code],
                telegram_config=telegram,
            )
        log_output = (output.getvalue() + error.getvalue()).decode("utf-8", "replace")
        self.assertEqual(result, 0)
        failed = [line_text for line_text in log_output.splitlines() if "state=POOL_CONNECTION_FAILED" in line_text]
        recovered = [line_text for line_text in log_output.splitlines() if "state=POOL_CONNECTION_RECOVERED" in line_text]
        self.assertEqual(len(failed), 1)
        self.assertEqual(len(recovered), 1)
        self.assertNotIn("state=TELEGRAM_ALERT", log_output)
        import re
        episode_match = re.search(r"pool_episode_id=([0-9a-f-]{36})", failed[0])
        self.assertIsNotNone(episode_match)
        assert episode_match is not None
        self.assertIn(f"pool_episode_id={episode_match.group(1)}", recovered[0])
        self.assertIn("recovery_signal=SOLUTIONS_ACCEPTED", recovered[0])
        self.assertIn("actions_performed=false", failed[0])
        self.assertIn("actions_performed=false", recovered[0])

    def test_enabled_telegram_config_is_rejected_before_child_launch(self) -> None:
        secret = "synthetic_sensitive_bot_token"
        called = False

        def should_not_start(*_args: object, **_kwargs: object) -> object:
            nonlocal called
            called = True
            raise AssertionError("child must not start with invalid notifier config")

        captured = io.StringIO()
        with contextlib.redirect_stderr(captured), mock.patch.dict(
            MONITOR.os.environ,
            {"FL4SH_TELEGRAM_ENABLED": "1", "FL4SH_TELEGRAM_BOT_TOKEN": secret},
            clear=False,
        ):
            result = MONITOR.run_supervisor(make_config(), ["stub"], popen_factory=should_not_start)
        self.assertEqual(result, 64)
        self.assertFalse(called)
        self.assertNotIn(secret, captured.getvalue())



class ParsingAndWindowTests(unittest.TestCase):
    def test_only_device_hashrate_lines_are_observed(self) -> None:
        parsed = MONITOR.parse_device_hashrate(
            "2026-10-12 INFO " + line(217.81, device=1, stale="2/80 (2.5%)")
        )
        self.assertEqual(parsed.device_index, 1)
        self.assertEqual(parsed.hashrate_ths, 217.81)
        self.assertEqual((parsed.stale_count, parsed.stale_total), (2, 80))
        bare_rate = MONITOR.parse_device_hashrate(
            "Device [1] hashRate: 217.81 TH/s"
        )
        self.assertEqual(bare_rate.hashrate_ths, 217.81)
        self.assertIsNone(bare_rate.stale_count)
        self.assertIsNone(
            MONITOR.parse_device_hashrate("Pearl autotune hashrate: 217.81 TH/s")
        )
        self.assertIsNone(
            MONITOR.parse_device_hashrate(
                "CUDA autotune (measured pool-equivalent): 217.81 TH/s"
            )
        )

    def test_gpu_name_normalization_preserves_neutral_and_explicit_forms(self) -> None:
        cases = {
            "NVIDIA GeForce RTX 5080 Laptop GPU": "RTX_5080_LAPTOP",
            "NVIDIA GeForce RTX 5090 Laptop GPU": "RTX_5090_LAPTOP",
            "NVIDIA GeForce RTX 5080": "RTX_5080_DESKTOP",
            "NVIDIA GeForce RTX 5070 Ti Laptop GPU": "RTX_5070_TI_LAPTOP",
            "NVIDIA GeForce RTX 5070 Ti": "RTX_5070_TI",
            "NVIDIA GeForce RTX 3090 Ti": "RTX_3090_TI",
            "NVIDIA GeForce RTX 3090 Ti Laptop GPU": "RTX_3090_TI_LAPTOP",
            "NVIDIA GeForce RTX 3090 Ti Desktop GPU": "RTX_3090_TI_DESKTOP",
        }
        for raw_name, expected in cases.items():
            with self.subTest(raw_name=raw_name):
                self.assertEqual(MONITOR.normalize_gpu_identity(raw_name), expected)
        self.assertIsNone(MONITOR.normalize_gpu_identity("RTX 5080"))

    def test_neutral_3090_ti_selects_only_its_exact_floor_key(self) -> None:
        configured = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_3090_TI":110}'
        )
        monitor = MONITOR.Fl4shMonitor(configured, start_monotonic=0)
        detected = monitor.observe_line(
            "Device [3] NVIDIA GeForce RTX 3090 Ti: Initialized", now=0
        )[0]
        self.assertEqual(detected["gpu_key"], "RTX_3090_TI")
        self.assertEqual(detected["floor_ths"], 110)
        self.assertEqual(detected["floor_source"], "ENV_REGISTRY")

        form_specific_only = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON=(
                '{"RTX_3090_TI_LAPTOP":120,"RTX_3090_TI_DESKTOP":209}'
            )
        )
        monitor_without_neutral = MONITOR.Fl4shMonitor(
            form_specific_only, start_monotonic=0
        )
        neutral_identity = monitor_without_neutral.observe_line(
            "Device [4] NVIDIA GeForce RTX 3090 Ti: Initialized", now=0
        )[0]
        self.assertEqual(neutral_identity["state"], "GPU_DETECTED")
        self.assertEqual(neutral_identity["gpu_key"], "RTX_3090_TI")
        self.assertIsNone(neutral_identity["floor_ths"])
        self.assertEqual(neutral_identity["floor_source"], "UNCONFIGURED")
        no_floor = monitor_without_neutral.observe_line(line(1, device=4), now=1)[0]
        self.assertEqual(no_floor["state"], "NO_FLOOR_CONFIGURED")
        self.assertIsNone(no_floor["floor_ths"])

    def test_autodetected_laptops_select_their_json_floors_without_profile(self) -> None:
        config = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON=(
                '{"RTX_5080_LAPTOP":110,"RTX_5090_LAPTOP":115}'
            )
        )
        cases = (
            ("NVIDIA GeForce RTX 5080 Laptop GPU", "RTX_5080_LAPTOP", 110),
            ("NVIDIA GeForce RTX 5090 Laptop GPU", "RTX_5090_LAPTOP", 115),
        )
        for raw_name, key, floor in cases:
            with self.subTest(key=key):
                monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
                events = monitor.observe_line(
                    f"Device [7] {raw_name}: Initialized", now=0
                )
                self.assertEqual(events[0]["state"], "GPU_DETECTED")
                self.assertEqual(events[0]["device"], "fl4shminer_device:7")
                self.assertEqual(events[0]["gpu_key"], key)
                self.assertEqual(events[0]["gpu_raw"], raw_name)
                self.assertEqual(events[0]["floor_ths"], floor)
                self.assertEqual(events[0]["floor_source"], "ENV_REGISTRY")
                self.assertFalse(events[0]["gpu_identity_verified"])
                sample_events = monitor.observe_line(line(130, device=7), now=1)
                self.assertEqual(sample_events[0]["floor_ths"], floor)
                self.assertFalse(any("machine_id" in event for event in sample_events))

    def test_laptop_and_desktop_floor_resolution_is_device_scoped(self) -> None:
        config = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON=(
                '{"RTX_5080_LAPTOP":110,"RTX_5080_DESKTOP":209}'
            )
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        laptop = monitor.observe_line(
            "Device [2] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized", now=0
        )[0]
        desktop = monitor.observe_line(
            "Device [9] NVIDIA GeForce RTX 5080: Initialized", now=0
        )[0]
        self.assertEqual((laptop["gpu_key"], laptop["floor_ths"]), ("RTX_5080_LAPTOP", 110))
        self.assertEqual((desktop["gpu_key"], desktop["floor_ths"]), ("RTX_5080_DESKTOP", 209))
        self.assertEqual(laptop["device"], "fl4shminer_device:2")
        self.assertEqual(desktop["device"], "fl4shminer_device:9")

    def test_new_gpu_profile_is_added_by_registry_without_source_changes(self) -> None:
        config = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5070_TI_LAPTOP":100}'
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        event = monitor.observe_line(
            "Device [4] NVIDIA GeForce RTX 5070 Ti Laptop GPU: Initialized", now=0
        )[0]
        self.assertEqual(event["gpu_key"], "RTX_5070_TI_LAPTOP")
        self.assertEqual(event["floor_ths"], 100)
        self.assertEqual(event["floor_source"], "ENV_REGISTRY")

    def test_neutral_identity_without_floor_never_recommends(self) -> None:
        config = make_auto_config()
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        identity = monitor.observe_line(
            "Device [3] NVIDIA GeForce RTX 5070 Ti: Initialized", now=0
        )[0]
        self.assertEqual(identity["state"], "GPU_DETECTED")
        self.assertEqual(identity["gpu_key"], "RTX_5070_TI")
        self.assertIsNone(identity["floor_ths"])
        first_sample = monitor.observe_line(line(1, device=3), now=0)[0]
        self.assertEqual(first_sample["state"], "NO_FLOOR_CONFIGURED")
        for instant in (10, 20, 30):
            monitor.observe_line(line(1, device=3), now=instant)
        events = monitor.tick(now=30)
        self.assertFalse(any(event["state"] == "REALLOCATE_RECOMMENDED" for event in events))
        self.assertIsNone(monitor._event(monitor.devices[3], "NO_FLOOR_CONFIGURED", observed=1)["floor_ths"])

    def test_identity_conflict_disables_floor_recommendation(self) -> None:
        config = make_auto_config(
            FL4SH_MONITOR_GPU_FLOORS_JSON=(
                '{"RTX_5080_LAPTOP":110,"RTX_5090_LAPTOP":115}'
            )
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        monitor.observe_line(
            "Device [5] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized", now=0
        )
        conflict = monitor.observe_line(
            "Solutions accepted: 5-NVIDIA GeForce RTX 5090 Laptop GPU, 0 stale", now=1
        )
        self.assertEqual(conflict[0]["state"], "GPU_IDENTITY_CONFLICT")
        self.assertEqual(set(conflict[0]["gpu_identity_candidates"]), {
            "RTX_5080_LAPTOP", "RTX_5090_LAPTOP"
        })
        for instant in (2, 12, 22, 32):
            monitor.observe_line(line(1, device=5), now=instant)
        events = monitor.tick(now=32)
        self.assertFalse(any(event["state"] == "REALLOCATE_RECOMMENDED" for event in events))
        self.assertIsNone(monitor._effective_floor(monitor.devices[5])[0])

    def test_ambiguous_corroboration_invalidates_prior_floor_and_episode(self) -> None:
        config = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110}')
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        monitor.observe_line(
            "Device [5] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized", now=0
        )
        state = monitor.devices[5]
        state.consecutive_bad_windows = 1
        state.recommendation_emitted = True
        state.last_state = "BELOW_FLOOR"

        events = monitor.observe_line(
            "Solutions accepted: 5-NVIDIA GeForce RTX 5080 Series, stale=0", now=1
        )
        self.assertEqual(events[0]["state"], "GPU_IDENTITY_CONFLICT")
        self.assertIsNone(events[0]["floor_ths"])
        self.assertIsNone(state.gpu_key)
        self.assertEqual(state.gpu_identity_status, "CONFLICT")
        self.assertEqual(state.consecutive_bad_windows, 0)
        self.assertFalse(state.recommendation_emitted)
        self.assertIsNone(monitor._effective_floor(state)[0])

        for instant in (2, 12, 22, 32):
            monitor.observe_line(line(1, device=5), now=instant)
        self.assertFalse(any(
            event["state"] == "REALLOCATE_RECOMMENDED" for event in monitor.tick(now=32)
        ))

    def test_autotune_and_solutions_cannot_establish_identity_without_primary(self) -> None:
        config = make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110}')
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        monitor.observe_line(line(1, device=1), now=0)

        # The unindexed Pearl line is ignored until Device [N] Initialized exists.
        self.assertEqual(
            monitor.observe_line(
                "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 9999 TH/s",
                now=1,
            ),
            [],
        )
        secondary = monitor.observe_line(
            "Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, stale=0", now=2
        )
        state = monitor.devices[1]
        self.assertTrue(any(event["state"] == "GPU_IDENTITY_UNKNOWN" for event in secondary))
        self.assertFalse(state.identity_primary_seen)
        self.assertIsNone(state.gpu_key)
        self.assertEqual(state.gpu_identity_status, "UNKNOWN")
        self.assertIsNone(monitor._effective_floor(state)[0])
        self.assertEqual(len(state.samples), 1)

        primary = monitor.observe_line(
            "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized", now=3
        )
        self.assertEqual(primary[0]["state"], "GPU_DETECTED")
        self.assertTrue(state.identity_primary_seen)
        self.assertEqual(primary[0]["gpu_key"], "RTX_5080_LAPTOP")
        self.assertEqual(primary[0]["floor_ths"], 110)

    def test_autotune_and_solutions_lines_only_corroborate_identity(self) -> None:
        monitor = MONITOR.Fl4shMonitor(
            make_auto_config(FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110}'),
            start_monotonic=0,
        )
        monitor.observe_line(
            "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized", now=0
        )
        pearl_events = monitor.observe_line(
            "GPU=NVIDIA GeForce RTX 5080 Laptop GPU Pearl autotune hashrate = 9999 TH/s", now=1
        )
        self.assertEqual(pearl_events, [])
        self.assertEqual(len(monitor.devices[1].samples), 0)
        monitor.observe_line(
            "Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, stale=0", now=2
        )
        self.assertEqual(monitor.devices[1].gpu_key, "RTX_5080_LAPTOP")
        self.assertEqual(monitor.devices[1].identity_sources, {
            "device_initialized", "pearl_autotune_model", "solutions_accepted_model"
        })
        self.assertEqual(len(monitor.devices[1].samples), 0)

    def test_profile_override_match_is_compatible_and_mismatch_is_blocked(self) -> None:
        compatible = MONITOR.Fl4shMonitor(
            make_config(
                FL4SH_MONITOR_PROFILE="RTX_5080_LAPTOP",
                FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110}',
            ),
            start_monotonic=0,
        )
        match = compatible.observe_line(
            "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized", now=0
        )[0]
        self.assertEqual(match["state"], "GPU_DETECTED")
        self.assertEqual(match["floor_ths"], 110)
        self.assertEqual(match["floor_source"], "PROFILE_OVERRIDE")

        mismatch = MONITOR.Fl4shMonitor(
            make_config(FL4SH_MONITOR_PROFILE="RTX_5090_LAPTOP"), start_monotonic=0
        )
        event = mismatch.observe_line(
            "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized", now=0
        )[0]
        self.assertEqual(event["state"], "GPU_PROFILE_MISMATCH")
        self.assertIsNone(event["floor_ths"])
        for instant in (1, 11, 21, 31):
            mismatch.observe_line(line(1, device=1), now=instant)
        self.assertFalse(any(
            event["state"] == "REALLOCATE_RECOMMENDED" for event in mismatch.tick(now=31)
        ))

    def test_device_numbers_are_namespaced_and_not_machine_identity(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        monitor.observe_line(line(150, device=0), now=0)
        monitor.observe_line(line(151, device=1), now=10)
        self.assertEqual(set(monitor.devices), {0, 1})
        event = monitor._event(monitor.devices[1], "HEALTHY", observed=151)
        self.assertEqual(event["device"], "fl4shminer_device:1")
        self.assertEqual(event["device_namespace"], "fl4shminer_device")
        self.assertFalse(event["gpu_identity_verified"])
        self.assertEqual(event["provider_binding_status"], "UNKNOWN")
        self.assertEqual(event["billing_status"], "UNKNOWN")
        self.assertFalse(event["actions_performed"])

    def test_desktop_profiles_use_their_own_physical_floors(self) -> None:
        cases = (
            ("RTX_5090_DESKTOP", 320, "REALLOCATE_RECOMMENDED"),
            ("RTX_5080_DESKTOP", 215, "HEALTHY"),
        )
        for profile, rate, expected_state in cases:
            with self.subTest(profile=profile):
                config = make_config(
                    FL4SH_MONITOR_PROFILE=profile,
                    SALAD_G5_HASH_WINDOW_SECONDS="10",
                    SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS="5",
                    SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="5",
                    SALAD_G5_REEVALUATION_INTERVAL_SECONDS="1",
                    SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="2",
                    SALAD_G5_CONSECUTIVE_BAD_WINDOWS="1",
                )
                monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
                for instant in (0, 5, 10):
                    monitor.observe_line(line(rate), now=instant)
                result = monitor.tick(now=10)
                self.assertEqual(result[0]["state"], expected_state)

    def test_unknown_gpu_profile_has_no_inferred_floor(self) -> None:
        config = make_config(FL4SH_MONITOR_PROFILE="")
        self.assertIsNone(config.floor_ths)
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        event = monitor.observe_line(line(150), now=0)[0]
        self.assertEqual(event["state"], "NO_FLOOR_CONFIGURED")
        self.assertIsNone(event["floor_ths"])

    def test_time_weighted_mean_uses_sample_duration(self) -> None:
        config = make_config(
            SALAD_G5_HASH_WINDOW_SECONDS="10",
            SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS="5",
            SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="5",
            SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="2",
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        for instant, rate in ((0, 100), (5, 200), (10, 200)):
            monitor.observe_line(line(rate), now=instant)
        stats = monitor._window_stats(monitor.devices[1], 10)
        self.assertTrue(stats["valid"])
        self.assertAlmostEqual(stats["mean_ths"], 150.0)
        self.assertAlmostEqual(stats["coverage_ratio"], 1.0)

    def test_expected_cadence_bounds_hold_forward_across_thirty_second_gap(self) -> None:
        config = make_config(
            SALAD_G5_WARMUP_SECONDS="0",
            SALAD_G5_HASH_WINDOW_SECONDS="120",
            SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="10",
            SALAD_G5_REEVALUATION_INTERVAL_SECONDS="10",
            SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="30",
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        for instant in range(0, 121, 10):
            if instant in {10, 20}:
                continue
            monitor.observe_line(line(150), now=instant)
        stats = monitor._window_stats(monitor.devices[1], 120)
        self.assertEqual(stats["maximum_observed_gap_seconds"], 30)
        self.assertAlmostEqual(stats["covered_seconds"], 100)
        self.assertAlmostEqual(stats["coverage_ratio"], 100 / 120)
        self.assertTrue(stats["valid"])

    def test_bad_gap_and_incomplete_data_do_not_become_full_coverage(self) -> None:
        config = make_config(
            SALAD_G5_WARMUP_SECONDS="0",
            SALAD_G5_HASH_WINDOW_SECONDS="120",
            SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="10",
            SALAD_G5_REEVALUATION_INTERVAL_SECONDS="10",
            SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="30",
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        for instant in range(0, 121, 10):
            if instant in {10, 20, 50, 60}:
                continue
            monitor.observe_line(line(150), now=instant)
        stats = monitor._window_stats(monitor.devices[1], 120)
        self.assertEqual(stats["maximum_observed_gap_seconds"], 30)
        self.assertLess(stats["coverage_ratio"], config.minimum_window_coverage_ratio)
        self.assertFalse(stats["valid"])

    def test_repeated_timestamps_do_not_inflate_sample_count(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        monitor.observe_line(line(110), now=0)
        monitor.observe_line(line(110), now=10)
        monitor.observe_line(line(110), now=10)
        state = monitor.devices[1]
        self.assertEqual(len(state.samples), 2)
        self.assertEqual(state.duplicate_timestamps, 1)


class PolicyTransitionTests(unittest.TestCase):
    def test_default_first_evaluation_waits_for_full_post_warmup_window(self) -> None:
        config = make_config(
            SALAD_G5_WARMUP_SECONDS="90",
            SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS="10",
            SALAD_G5_HASH_WINDOW_SECONDS="120",
            SALAD_G5_REEVALUATION_INTERVAL_SECONDS="30",
            SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="10",
            SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="30",
            SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO="0.8",
            SALAD_G5_CONSECUTIVE_BAD_WINDOWS="2",
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        for instant in range(0, 101, 10):
            monitor.observe_line(line(90), now=instant)
        partial = monitor.tick(now=100)
        self.assertEqual([event["state"] for event in partial], ["INSUFFICIENT_DATA"])
        self.assertEqual(monitor.devices[1].consecutive_bad_windows, 0)

        for instant in range(110, 211, 10):
            monitor.observe_line(line(90), now=instant)
        first_complete = monitor.tick(now=210)
        self.assertEqual([event["state"] for event in first_complete], ["BELOW_FLOOR"])
        self.assertEqual(monitor.devices[1].consecutive_bad_windows, 1)

    def test_sustained_low_rate_emits_one_advisory_after_two_valid_windows(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        for instant in (0, 10, 20):
            monitor.observe_line(line(90), now=instant)
        first = monitor.tick(now=20)
        self.assertEqual(first[0]["state"], "BELOW_FLOOR")
        for instant in (30, 40):
            monitor.observe_line(line(90), now=instant)
        second = monitor.tick(now=40)
        self.assertEqual(second[0]["state"], "REALLOCATE_RECOMMENDED")
        self.assertFalse(second[0]["actions_performed"])
        self.assertEqual(second[0]["provider_binding_status"], "UNKNOWN")
        self.assertEqual(monitor.tick(now=40), [])

    def test_floor_tolerance_band_is_non_actionable_and_exact_threshold_is_not_low(self) -> None:
        config = make_config(SALAD_G5_CONSECUTIVE_BAD_WINDOWS="1")
        for rate in (118.0, 118.5, 119.9):
            with self.subTest(rate=rate):
                monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
                monitor.observe_line(line(rate), now=0)
                monitor.observe_line(line(rate), now=10)
                events = monitor.tick(now=20)
                self.assertEqual([event["state"] for event in events], ["WITHIN_FLOOR_TOLERANCE"])
                self.assertFalse(any(event["state"] == "REALLOCATE_RECOMMENDED" for event in events))
                self.assertEqual(events[0]["floor_tolerance_ths"], 2.0)
                self.assertEqual(events[0]["decision_threshold_ths"], 118.0)

        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        monitor.observe_line(line(117.99), now=0)
        monitor.observe_line(line(117.99), now=10)
        result = monitor.tick(now=20)
        self.assertEqual(result[0]["state"], "REALLOCATE_RECOMMENDED")

    def test_realerts_follow_new_windows_and_configured_drop_from_previous_alert(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        observations = [
            107.8, 107.8, 107.1, 105.2, 104.7, 102.5, 101.6,
        ]
        monitor.observe_line(line(150), now=0)
        means = iter(observations)
        monitor._window_stats = lambda _state, _now: {
            "mean_ths": next(means), "coverage_ratio": 1.0, "sample_count": 4,
            "covered_seconds": 20.0, "maximum_observed_gap_seconds": 10.0, "valid": True,
        }
        emitted: list[dict[str, object]] = []
        for index, rate in enumerate(observations):
            now = 20 + index * 10
            monitor.observe_line(line(rate), now=now)
            emitted.extend(monitor.tick(now=now))
        recommendations = [event for event in emitted if event["state"] == "REALLOCATE_RECOMMENDED"]
        self.assertEqual([event["alert_sequence"] for event in recommendations], [1, 2, 3])
        self.assertEqual([event["observed_window_mean_ths"] for event in recommendations], [107.8, 104.7, 101.6])
        self.assertEqual(recommendations[0]["notification_reason"], "INITIAL_THRESHOLD_CROSSING")
        self.assertEqual(recommendations[1]["notification_reason"], "WORSENED")
        self.assertEqual(recommendations[1]["previous_alert_mean_ths"], 107.8)
        self.assertAlmostEqual(recommendations[1]["deterioration_since_previous_alert_ths"], 3.1)
        self.assertEqual(recommendations[2]["previous_alert_mean_ths"], 104.7)
        for event in recommendations:
            self.assertNotIn("alert_reason", event)
            self.assertNotIn("deterioration_ths", event)

        formatted = MONITOR.format_event(recommendations[1])
        self.assertIn("notification_reason=WORSENED", formatted)
        self.assertIn("previous_alert_mean_ths=107.8", formatted)
        self.assertIn("deterioration_since_previous_alert_ths=3.1", formatted)
        self.assertNotIn("alert_reason=", formatted)
        self.assertNotIn("deterioration_ths=", formatted)
        telegram = MONITOR.format_telegram_message(
            "REALLOCATE_RECOMMENDED", recommendations[1], alert_id="synthetic-alert",
            monitor_session_id="synthetic-session", label=None,
        )
        self.assertIn("notification_reason: WORSENED", telegram)
        self.assertIn("previous_alert_mean_ths: 107.8", telegram)
        self.assertIn("deterioration_since_previous_alert_ths: 3.1", telegram)
        self.assertNotIn("alert_reason:", telegram)
        self.assertNotIn("deterioration_ths:", telegram)

    def test_recovery_resets_episode_and_later_breach_gets_new_episode_id(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(SALAD_G5_CONSECUTIVE_BAD_WINDOWS="1"), start_monotonic=0)
        monitor.observe_line(line(150), now=0)
        means = iter((90.0, 118.0, 90.0))
        monitor._window_stats = lambda _state, _now: {
            "mean_ths": next(means), "coverage_ratio": 1.0, "sample_count": 4,
            "covered_seconds": 20.0, "maximum_observed_gap_seconds": 10.0, "valid": True,
        }
        monitor.observe_line(line(90), now=20)
        first = monitor.tick(now=20)
        first_id = first[0]["degradation_episode_id"]
        monitor.observe_line(line(118), now=30)
        recovery = monitor.tick(now=30)
        self.assertEqual([event["state"] for event in recovery], ["RECOVERED", "WITHIN_FLOOR_TOLERANCE"])
        monitor.observe_line(line(90), now=40)
        second = monitor.tick(now=40)
        self.assertEqual(second[0]["state"], "REALLOCATE_RECOMMENDED")
        self.assertNotEqual(first_id, second[0]["degradation_episode_id"])

    def test_healthy_window_reports_current_observed_rate_on_each_reevaluation(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        for instant in (0, 10, 20):
            monitor.observe_line(line(150), now=instant)
        initial = monitor.tick(now=20)
        self.assertEqual(initial[0]["state"], "HEALTHY")
        monitor.observe_line(line(151), now=30)
        update = monitor.tick(now=30)
        self.assertEqual(update[0]["state"], "HEALTHY")
        self.assertIsNotNone(update[0]["observed_window_mean_ths"])
        formatted = MONITOR.format_event(update[0])
        self.assertIn("FL4SH_MONITOR state=HEALTHY", formatted)
        self.assertIn("observed=", formatted)

    def test_transient_twenty_second_dip_does_not_recommend(self) -> None:
        config = make_config(
            SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS="120",
            SALAD_G5_HASH_WINDOW_SECONDS="120",
            SALAD_G5_REEVALUATION_INTERVAL_SECONDS="10",
            SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW="10",
        )
        monitor = MONITOR.Fl4shMonitor(config, start_monotonic=0)
        observed_events: list[dict[str, object]] = []
        for instant in range(0, 241, 10):
            rate = 90 if instant in (130, 140) else (155 if instant >= 150 else 150)
            monitor.observe_line(line(rate), now=instant)
            observed_events.extend(monitor.tick(now=instant))
        states = [event["state"] for event in observed_events]
        self.assertNotIn("REALLOCATE_RECOMMENDED", states)
        self.assertTrue(any(state in {"HEALTHY", "RECOVERED"} for state in states))

    def test_late_degradation_is_detected_after_prior_healthy_state(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        events: list[dict[str, object]] = []
        for instant in range(0, 181):
            now = instant * 10
            rate = 170 if now < 1800 else 90
            monitor.observe_line(line(rate), now=now)
            events.extend(monitor.tick(now=now))
        # Let the low segment fill a complete, well-covered window and be
        # reevaluated twice, proving monitoring does not stop after initial PASS.
        for now in range(1820, 1901, 10):
            monitor.observe_line(line(90), now=now)
            events.extend(monitor.tick(now=now))
        states = [event["state"] for event in events]
        self.assertIn("HEALTHY", states)
        self.assertIn("REALLOCATE_RECOMMENDED", states)

    def test_absent_or_stale_telemetry_is_never_zero_hashrate(self) -> None:
        monitor = MONITOR.Fl4shMonitor(
            make_config(SALAD_G5_WARMUP_SECONDS="90"), start_monotonic=0
        )
        self.assertEqual(monitor.tick(now=0)[0]["state"], "WARMUP")
        self.assertEqual(monitor.tick(now=90)[0]["state"], "INSUFFICIENT_DATA")
        self.assertEqual(monitor.tick(now=120)[0]["state"], "TELEMETRY_STALE")
        self.assertIsNone(monitor._event(None, "TELEMETRY_STALE", observed=None)["latest_device_hashrate_ths"])

    def test_recovery_clears_episode_and_reports_recovered(self) -> None:
        monitor = MONITOR.Fl4shMonitor(make_config(), start_monotonic=0)
        for instant in (0, 10, 20, 30, 40):
            monitor.observe_line(line(90), now=instant)
        monitor.tick(now=20)
        recommendation = monitor.tick(now=40)
        self.assertEqual(recommendation[0]["state"], "REALLOCATE_RECOMMENDED")
        for instant in (50, 60, 70):
            monitor.observe_line(line(155), now=instant)
        recovered = monitor.tick(now=70)
        self.assertEqual(recovered[0]["state"], "RECOVERED")
        self.assertEqual(monitor.devices[1].consecutive_bad_windows, 0)
        self.assertFalse(monitor.devices[1].recommendation_emitted)


class RedactionAndSupervisorTests(unittest.TestCase):
    def test_streaming_redactor_handles_secret_split_across_chunks(self) -> None:
        redactor = MONITOR.StreamingRedactor(["wallet-secret.123"])
        first = redactor.feed(b"login=wallet-se")
        second = redactor.feed(b"cret.123 status=ok", final=True)
        self.assertNotIn(b"wallet-secret.123", first + second)
        self.assertIn(b"[REDACTED]", first + second)

    def test_gpu_identity_events_and_both_streams_redact_mining_identifier(self) -> None:
        secret = "synthetic-gpu-credential"
        raw_line = (
            "Device [7] NVIDIA GeForce RTX 5080 Laptop GPU "
            f"{secret}: Initialized"
        )
        with mock.patch.dict(MONITOR.os.environ, {"FL4SH_MINING_ID": secret}, clear=False):
            monitor = MONITOR.Fl4shMonitor(make_auto_config(), start_monotonic=0)
            events = monitor.observe_line(raw_line, now=0)
            self.assertTrue(events)
            self.assertNotIn(secret, repr(events))
            self.assertIn("[REDACTED]", events[0]["gpu_raw"])
            self.assertNotIn(secret, MONITOR.format_event(events[0]))

        environment = os.environ.copy()
        environment.update(
            {
                "FL4SH_MONITOR_ENABLED": "1",
                "FL4SH_MONITOR_PROFILE": "",
                "FL4SH_MONITOR_GPU_FLOORS_JSON": "{}",
                "FL4SH_MINING_ID": secret,
                "SALAD_G5_WARMUP_SECONDS": "0",
                "SALAD_G5_HASH_WINDOW_SECONDS": "10",
                "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "5",
                "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
                "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
                "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "5",
            }
        )
        child_code = (
            f"print({raw_line!r}, flush=True); "
            "print('Device [7] hashRate: 1.00 TH/s', flush=True); "
            f"import sys; print('stderr={secret}', file=sys.stderr, flush=True)"
        )
        completed = subprocess.run(
            [sys.executable, str(ROOT / "fl4sh-runtime-monitor.py"), "--", sys.executable, "-c", child_code],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        combined = completed.stdout + completed.stderr
        self.assertNotIn(secret.encode(), combined)
        self.assertIn(b"[REDACTED]", completed.stdout)
        self.assertIn(b"[REDACTED]", completed.stderr)

    def test_bounded_parser_drops_overlong_lines_and_recovers_at_newline(self) -> None:
        parser = MONITOR.BoundedLineParser(max_line_bytes=64)
        self.assertEqual(parser.feed(b"x" * 100), [])
        self.assertEqual(len(parser.buffer), 0)
        self.assertEqual(parser.feed(b"still-long\n"), [])
        record = "Device [1] hashRate: 150 TH/s"
        self.assertEqual(parser.feed((record + "\n").encode()), [record])
        self.assertLessEqual(len(parser.buffer), parser.max_line_bytes)

    def test_supervisor_uses_stub_process_and_propagates_exit_without_mining(self) -> None:
        output = io.BytesIO()
        error = io.BytesIO()
        fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))

        class FakeChild:
            stdout = io.BytesIO(
                (line(150) + " wallet=synthetic-wallet.worker\n").encode()
            )
            stderr = io.BytesIO(b"synthetic child stderr\n")
            returncode: int | None = None
            sent_signals: list[int] = []

            def poll(self) -> int:
                return self.returncode

            def wait(self) -> int:
                self.returncode = 7
                return 7

            def send_signal(self, signum: int) -> None:
                self.sent_signals.append(signum)

        captured: dict[str, object] = {}

        def fake_popen(command: list[str], **kwargs: object) -> FakeChild:
            captured["command"] = command
            captured["kwargs"] = kwargs
            for signum in (MONITOR.signal.SIGTERM, MONITOR.signal.SIGINT):
                handler = MONITOR.signal.getsignal(signum)
                handler(signum, None)
            return FakeChild()

        config = make_config()
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
            MONITOR, "sys", fake_sys
        ), mock.patch.dict(
            MONITOR.os.environ,
            {"FL4SH_MINING_ID": "synthetic-wallet.worker"},
            clear=False,
        ):
            result = MONITOR.run_supervisor(
                config,
                ["/synthetic/not-executed/fl4shminer", "-a", "pearlhash"],
                monotonic=lambda: 0.0,
                popen_factory=fake_popen,
            )
        self.assertEqual(result, 7)
        self.assertEqual(
            captured["command"], ["/synthetic/not-executed/fl4shminer", "-a", "pearlhash"]
        )
        self.assertEqual(captured["kwargs"]["stdout"], MONITOR.subprocess.PIPE)
        self.assertIn(b"FL4SH_MONITOR", output.getvalue())
        self.assertNotIn(b"synthetic-wallet.worker", output.getvalue() + error.getvalue())
        self.assertIn(b"[REDACTED]", output.getvalue())
        self.assertIn(b"synthetic child stderr", error.getvalue())
        # Signals raised while Popen is returning are coalesced as the most
        # recent pending signal, then forwarded once after child assignment.
        self.assertEqual(FakeChild.sent_signals, [MONITOR.signal.SIGINT])

    def test_signal_terminated_child_uses_shell_status_without_resignaling_supervisor(self) -> None:
        class KilledChild:
            stdout = io.BytesIO()
            stderr = io.BytesIO()

            def poll(self) -> int | None:
                return -9

            def wait(self) -> int:
                return -9

            def send_signal(self, _signum: int) -> None:
                raise AssertionError("no signal forwarding expected")

        output = io.BytesIO()
        error = io.BytesIO()
        fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(MONITOR, "sys", fake_sys):
            result = MONITOR.run_supervisor(
                make_config(), ["stub"], monotonic=lambda: 0.0,
                popen_factory=lambda *_args, **_kwargs: KilledChild(),
            )
        self.assertEqual(result, 137)

    def test_real_harmless_child_exit_codes_are_preserved(self) -> None:
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code):
                environment = os.environ.copy()
                environment.update(
                    {
                        "FL4SH_MONITOR_ENABLED": "1",
                        "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
                        "SALAD_G5_WARMUP_SECONDS": "0",
                        "SALAD_G5_HASH_WINDOW_SECONDS": "10",
                        "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "5",
                        "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
                        "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
                        "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "5",
                    }
                )
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "fl4sh-runtime-monitor.py"),
                        "--",
                        sys.executable,
                        "-c",
                        (
                            "print('Device [1] hashRate: 1.00 TH/s', flush=True); "
                            if exit_code == 0 else ""
                        ) + f"raise SystemExit({exit_code})",
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, exit_code)
                self.assertIn(b"FL4SH_MONITOR state=CONFIG", completed.stdout)

    def test_real_supervisor_preserves_gpu_identity_stdout(self) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "FL4SH_MONITOR_ENABLED": "1",
                "FL4SH_MONITOR_GPU_FLOORS_JSON": '{"RTX_5080_LAPTOP":110}',
                "FL4SH_MONITOR_PROFILE": "",
                "SALAD_G5_WARMUP_SECONDS": "0",
                "SALAD_G5_HASH_WINDOW_SECONDS": "10",
                "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "5",
                "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
                "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
                "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "5",
            }
        )
        child_code = (
            "print('Device [7] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized', flush=True); "
            "print('Device [7] hashRate: 120.00 TH/s', flush=True)"
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "fl4sh-runtime-monitor.py"),
                "--",
                sys.executable,
                "-c",
                child_code,
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        output = completed.stdout.decode("utf-8", "replace")
        raw_line = "Device [7] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized"
        self.assertEqual(output.count(raw_line), 1)
        self.assertIn("state=GPU_DETECTED", output)
        self.assertIn("gpu_key=RTX_5080_LAPTOP", output)
        self.assertIn("floor_ths=110", output)
        self.assertIn("floor_source=ENV_REGISTRY", output)
        self.assertIn("actions_performed=false", output)

    def test_real_supervisor_relays_partial_bytes_and_redacts_chunk_boundaries(self) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "FL4SH_MONITOR_ENABLED": "1",
                "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
                "FL4SH_MINING_ID": "split-secret",
                "SALAD_G5_WARMUP_SECONDS": "0",
                "SALAD_G5_HASH_WINDOW_SECONDS": "10",
                "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "5",
                "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
                "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
                "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "5",
            }
        )
        child_code = (
            "import sys,time; "
            "print('Device [1] hashRate: 1.00 TH/s', flush=True); "
            "sys.stdout.buffer.write(b'prefix=split-'); sys.stdout.flush(); "
            "sys.stderr.buffer.write(b'parallel-stderr\\n'); sys.stderr.flush(); "
            "time.sleep(0.4); "
            "sys.stdout.buffer.write(b'secret tail no-newline'); sys.stdout.flush(); "
            "time.sleep(1.0)"
        )
        process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "fl4sh-runtime-monitor.py"),
                "--",
                sys.executable,
                "-c",
                child_code,
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        assert process.stdout is not None and process.stderr is not None
        stdout_data = bytearray()
        stderr_data = bytearray()
        output_lock = threading.Lock()
        partial_output_seen = threading.Event()

        def collect(stream: Any, destination: bytearray, *, watch_partial: bool) -> None:
            while True:
                chunk = os.read(stream.fileno(), 4096)
                if not chunk:
                    return
                with output_lock:
                    destination.extend(chunk)
                    if watch_partial and b"tail no-newline" in destination:
                        partial_output_seen.set()

        readers = [
            threading.Thread(target=collect, args=(process.stdout, stdout_data), kwargs={"watch_partial": True}),
            threading.Thread(target=collect, args=(process.stderr, stderr_data), kwargs={"watch_partial": False}),
        ]
        for reader in readers:
            reader.start()
        try:
            self.assertTrue(partial_output_seen.wait(timeout=1.0), "unterminated child bytes were not relayed promptly")
            self.assertIsNone(process.poll(), "child exited before the partial output was observed")
            self.assertEqual(process.wait(timeout=10), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=5)
            process.stdout.close()
            process.stderr.close()
        self.assertFalse(any(reader.is_alive() for reader in readers))
        self.assertNotIn(b"split-secret", stdout_data + stderr_data)
        self.assertIn(b"[REDACTED]", stdout_data)
        self.assertIn(b"tail no-newline", stdout_data)
        self.assertIn(b"parallel-stderr", stderr_data)

    def test_signal_handler_forwards_to_actual_harmless_child(self) -> None:
        for signum in (MONITOR.signal.SIGTERM, MONITOR.signal.SIGINT):
            with self.subTest(signum=signum):
                output = io.BytesIO()
                error = io.BytesIO()
                fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))

                def start_and_signal(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
                    child = subprocess.Popen(command, **kwargs)
                    current_handler = MONITOR.signal.getsignal(signum)
                    current_handler(signum, None)
                    return child

                with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(MONITOR, "sys", fake_sys):
                    result = MONITOR.run_supervisor(
                        make_config(),
                        [sys.executable, "-c", "import time; time.sleep(10)"],
                        monotonic=lambda: 0.0,
                        popen_factory=start_and_signal,
                    )
                self.assertNotEqual(result, 0)

    @unittest.skipUnless(os.name == "posix", "SIGKILL child status requires POSIX process signals")
    def test_actual_sigkill_child_maps_to_shell_status(self) -> None:
        output = io.BytesIO()
        error = io.BytesIO()
        fake_sys = SimpleNamespace(stdout=SimpleNamespace(buffer=output), stderr=SimpleNamespace(buffer=error))

        def start_and_kill(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            child = subprocess.Popen(command, **kwargs)
            child.kill()
            return child

        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(MONITOR, "sys", fake_sys):
            result = MONITOR.run_supervisor(
                make_config(),
                [sys.executable, "-c", "import time; time.sleep(10)"],
                monotonic=lambda: 0.0,
                popen_factory=start_and_kill,
            )
        self.assertEqual(result, 137)

    def test_pipe_consumer_failure_does_not_interrupt_child_drain_or_result(self) -> None:
        class BrokenSink:
            def write(self, _content: bytes) -> int:
                raise BrokenPipeError()

            def flush(self) -> None:
                return None

        payload = (line(150) + "\n").encode()

        class CountingPipe:
            def __init__(self, data: bytes) -> None:
                self._stream = io.BytesIO(data)
                self.bytes_read = 0

            def read(self, size: int) -> bytes:
                chunk = self._stream.read(size)
                self.bytes_read += len(chunk)
                return chunk

            def close(self) -> None:
                self._stream.close()

        class Child:
            def __init__(self) -> None:
                self.stdout = CountingPipe(payload)
                self.stderr = CountingPipe(b"still-drained\n")
                self.returncode: int | None = None

            def poll(self) -> int | None:
                return self.returncode

            def wait(self) -> int:
                self.returncode = 0
                return 0

            def send_signal(self, _signum: int) -> None:
                return None

        child = Child()
        fake_sys = SimpleNamespace(
            stdout=SimpleNamespace(buffer=BrokenSink()),
            stderr=SimpleNamespace(buffer=BrokenSink()),
        )
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(MONITOR, "sys", fake_sys):
            result = MONITOR.run_supervisor(
                make_config(), ["stub"], monotonic=lambda: 0.0,
                popen_factory=lambda *_args, **_kwargs: child,
            )
        self.assertEqual(result, 0)
        self.assertEqual(child.stdout.bytes_read, len(payload))
        self.assertEqual(child.stderr.bytes_read, len(b"still-drained\n"))


class ProductiveReadinessTests(unittest.TestCase):
    SESSION_ID = "01234567-89ab-cdef-0123-456789abcdef"

    def test_readiness_requires_fresh_positive_sample_matching_process_and_policy(self) -> None:
        config = make_config(SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="10")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "readiness.json")
            MONITOR._write_readiness_file(
                path,
                session_id=self.SESSION_ID,
                supervisor_pid=321,
                miner_pid=654,
                policy_hash=config.policy_hash,
                device_samples={1: (1.25, 1_000.0)},
                generated_at_epoch=1_000.0,
            )
            self.assertTrue(MONITOR._readiness_is_healthy(
                path, config=config, supervisor_pid=321, miner_pid=654, now_epoch=1_005.0,
            ))
            self.assertFalse(MONITOR._readiness_is_healthy(
                path, config=config, supervisor_pid=321, miner_pid=655, now_epoch=1_005.0,
            ))
            self.assertFalse(MONITOR._readiness_is_healthy(
                path, config=config, supervisor_pid=321, miner_pid=654, now_epoch=1_011.0,
            ))
            self.assertFalse(MONITOR._readiness_is_healthy(
                path,
                config=make_config(
                    SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS="9",
                    SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="9",
                ),
                supervisor_pid=321,
                miner_pid=654,
                now_epoch=1_005.0,
            ))

    def test_zero_hashrate_and_old_session_artifacts_are_not_healthy(self) -> None:
        config = make_config(SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="10")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "readiness.json")
            MONITOR._write_readiness_file(
                path,
                session_id=self.SESSION_ID,
                supervisor_pid=1,
                miner_pid=77,
                policy_hash=config.policy_hash,
                device_samples={1: (0.0, 1_000.0)},
                generated_at_epoch=1_000.0,
            )
            self.assertFalse(MONITOR._readiness_is_healthy(
                path, config=config, miner_pid=77, now_epoch=1_001.0,
            ))
            MONITOR._clear_readiness_file(path)
            self.assertFalse(os.path.exists(path))

    def test_readiness_cli_accepts_only_matching_fresh_pid_and_policy(self) -> None:
        config = make_config(SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS="10")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "readiness.json")
            MONITOR._write_readiness_file(
                path,
                session_id=self.SESSION_ID,
                supervisor_pid=1,
                miner_pid=77,
                policy_hash=config.policy_hash,
                device_samples={1: (10.0, MONITOR.time.time())},
                generated_at_epoch=MONITOR.time.time(),
            )
            with mock.patch.object(MONITOR, "READINESS_PATH", path), mock.patch.dict(
                MONITOR.os.environ,
                {
                    "FL4SH_MONITOR_ENABLED": "1",
                    "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
                    "SALAD_G5_WARMUP_SECONDS": "0",
                    "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "10",
                    "SALAD_G5_HASH_WINDOW_SECONDS": "20",
                    "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
                    "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
                    "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "10",
                    "SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO": "0.8",
                    "SALAD_G5_CONSECUTIVE_BAD_WINDOWS": "2",
                },
                clear=True,
            ):
                self.assertEqual(MONITOR.main(["--check-readiness", "--miner-pid", "77"]), 0)
                self.assertNotEqual(MONITOR.main(["--check-readiness", "--miner-pid", "78"]), 0)
                self.assertEqual(MONITOR.main(["--check-readiness", "--miner-pid", "0"]), 64)

    def test_startup_watchdog_fails_closed_without_positive_device_hashrate(self) -> None:
        environment = os.environ.copy()
        environment.update({
            "FL4SH_MONITOR_ENABLED": "1",
            "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
            "FL4SH_STARTUP_HASHRATE_TIMEOUT_SECONDS": "1",
            "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "5",
            "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "5",
        })
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "fl4sh-runtime-monitor.py"),
                "--", sys.executable, "-c", "import time; time.sleep(10)",
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 70, completed.stderr.decode("utf-8", "replace"))
        output = completed.stdout.decode("utf-8", "replace")
        self.assertIn("state=STARTUP_HASHRATE_TIMEOUT", output)
        self.assertIn("reason=NO_POSITIVE_DEVICE_HASHRATE", output)
        self.assertIn("actions_performed=false", output)
        self.assertNotIn("api_key", output.lower())
        self.assertFalse(os.path.exists(MONITOR.READINESS_PATH))

    def test_clean_miner_exit_before_hashrate_is_not_healthy(self) -> None:
        environment = os.environ.copy()
        environment.update({
            "FL4SH_MONITOR_ENABLED": "1",
            "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
            "FL4SH_STARTUP_HASHRATE_TIMEOUT_SECONDS": "30",
        })
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "fl4sh-runtime-monitor.py"),
                "--", sys.executable, "-c", "print('CUDA initialized only', flush=True)",
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 70)
        self.assertIn(b"state=STARTUP_HASHRATE_FAILED", completed.stdout)
        self.assertIn(b"reason=MINER_EXITED_BEFORE_HASHRATE", completed.stdout)

    def test_positive_hashrate_sample_is_atomically_published_while_child_runs(self) -> None:
        environment = os.environ.copy()
        environment.update({
            "FL4SH_MONITOR_ENABLED": "1",
            "FL4SH_MONITOR_PROFILE": "RTX_5090_LAPTOP",
            "FL4SH_STARTUP_HASHRATE_TIMEOUT_SECONDS": "3",
            "SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS": "1",
            "SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS": "1",
            "SALAD_G5_HASH_WINDOW_SECONDS": "10",
            "SALAD_G5_REEVALUATION_INTERVAL_SECONDS": "5",
            "SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW": "2",
        })
        process = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "fl4sh-runtime-monitor.py"),
                "--", sys.executable, "-c",
                "import time; print('Device [1] hashRate: 12.5 TH/s', flush=True); time.sleep(2)",
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 2.0
            record: dict[str, object] | None = None
            while time.monotonic() < deadline:
                try:
                    with open(MONITOR.READINESS_PATH, "r", encoding="utf-8") as stream:
                        candidate = MONITOR.json.load(stream)
                    if isinstance(candidate, dict) and candidate.get("miner_pid"):
                        record = candidate
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.05)
            self.assertIsNotNone(record, "positive sample readiness file was not published")
            assert record is not None
            self.assertEqual(record["supervisor_pid"], process.pid)
            config = MONITOR.MonitorConfig.from_env(environment, require_enabled=True)
            self.assertTrue(MONITOR._readiness_is_healthy(
                MONITOR.READINESS_PATH,
                config=config,
                supervisor_pid=process.pid,
                miner_pid=int(record["miner_pid"]),
                now_epoch=MONITOR.time.time(),
            ))
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        self.assertFalse(os.path.exists(MONITOR.READINESS_PATH))


if __name__ == "__main__":
    unittest.main(verbosity=2)
