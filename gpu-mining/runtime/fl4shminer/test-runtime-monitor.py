#!/usr/bin/env python3
"""Offline regression tests for the optional Fl4shMiner log monitor."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import threading
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


def line(rate: float, *, device: int = 1, stale: str = "0/0 (0.0%)") -> str:
    return f"Device [{device}] hashRate: {rate:.2f} TH/s, stale: {stale}, warm: 0"


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
                {"FL4SH_MONITOR_ENABLED": "1", "FL4SH_MONITOR_PROFILE": "RTX_5090"},
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
        self.assertNotEqual(first.policy_hash, changed_floor.policy_hash)
        self.assertNotEqual(first.policy_hash, changed_window.policy_hash)

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
                        f"raise SystemExit({exit_code})",
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, exit_code)
                self.assertIn(b"FL4SH_MONITOR state=CONFIG", completed.stdout)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
