"""Offline regression tests for Salad log alert enrichment."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
import uuid


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from log_alerts.contract import (  # noqa: E402
    DATA_CLASSIFICATION,
    DENIED,
    PROVIDER_OBSERVED,
    READ_LOG_QUERY,
    FixtureLogQueryTransport,
    IncompleteFixtureQuery,
    LogQueryPage,
    LogQueryPolicy,
    QueryLimits,
)
from log_alerts.engine import LogAlertEnricher, UnsafeQueryCycle  # noqa: E402
from log_alerts.ledger import SQLiteAlertLedger  # noqa: E402
from log_alerts.normalize import CUDA_FATAL_LINE, LogRecordError, normalize_log_entry  # noqa: E402
from log_alerts.startup_guard import StartupGuard  # noqa: E402


ORG = "adrianfiverr"
PROJECT = "miners"
EVENT_TIME = "2026-10-13T12:00:00Z"
END_TIME = "2026-10-13T12:01:00Z"
POLICY_HASH = "a" * 64
ALERT_ID = "11111111-1111-4111-8111-111111111111"
POOL_SESSION_ID = "22222222-2222-4222-8222-222222222222"
POOL_EPISODE_ID = "33333333-3333-4333-8333-333333333333"
SOLUTION_EVIDENCE_LINE = "Solutions accepted: 5-NVIDIA GeForce RTX 5080 Laptop GPU, 0 stale"
SOLUTION_EVIDENCE_SHA256 = hashlib.sha256(SOLUTION_EVIDENCE_LINE.encode("utf-8")).hexdigest()
CUDA_FATAL_CONTRACT_SAMPLE = (
    "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is "
    "insufficient for CUDA runtime version, OpenCL: <nil>)."
)


def pool_monitor_line(
    event_type: str,
    *,
    session_id: str = POOL_SESSION_ID,
    episode_id: str = POOL_EPISODE_ID,
    sequence: int = 1,
    first_failure: str = "2026-10-13T12:00:00Z",
    latest_failure: str = "2026-10-13T12:00:00Z",
    failure_count: int = 1,
    recent_failure_count: int = 1,
    retry_seconds: int = 10,
    notification_reason: str | None = None,
    unstable_duration_seconds: int = 0,
    prior_failure_count: int = 1,
    recovered_at: str = "2026-10-13T12:00:30Z",
    recent_failure_window_start: str | None = None,
    solutions_evidence_sha256: str = "a" * 64,
    alert_id: str | None = None,
) -> str:
    if event_type == "POOL_CONNECTION_RECOVERED" and sequence == 1:
        sequence = 2
    fields = [
        "FL4SH_MONITOR",
        f"state={event_type}",
        f"monitor_session_id={session_id}",
        f"pool_episode_id={episode_id}",
        f"pool_alert_sequence={sequence}",
        "reason=MINING_AUTHORIZE_RESPONSE_TIMEOUT",
        f"retry_seconds={retry_seconds}",
        f"first_failure_utc={first_failure}",
        f"latest_failure_utc={latest_failure}",
        "gpu_key=RTX_5080_LAPTOP",
        "device=fl4shminer_device:1",
        "actions_performed=false",
    ]
    if alert_id:
        fields.append(f"alert_id={alert_id}")
    if event_type == "POOL_CONNECTION_FAILED":
        fields.append(f"failure_count={failure_count}")
    elif event_type == "POOL_CONNECTION_UNSTABLE":
        fields.extend([
            f"failure_count={failure_count}",
            f"recent_failure_count={recent_failure_count}",
            f"notification_reason={notification_reason or 'BURST_FAILURES'}",
            f"unstable_duration_seconds={unstable_duration_seconds}",
            f"recent_failure_window_start_utc={recent_failure_window_start or latest_failure}",
        ])
    elif event_type == "POOL_CONNECTION_RECOVERED":
        fields.extend([
            f"failure_count={prior_failure_count}",
            f"prior_failure_count={prior_failure_count}",
            f"timestamp_utc={recovered_at}",
            "recovery_signal=SOLUTIONS_ACCEPTED",
            f"recovered_at_utc={recovered_at}",
            f"solutions_evidence_sha256={solutions_evidence_sha256}",
        ])
    return " ".join(fields)


def pool_recovery_evidence_line(
    *, session_id: str = POOL_SESSION_ID, episode_id: str = POOL_EPISODE_ID,
    sequence: int = 2, timestamp: str = "2026-10-13T12:00:20Z",
    evidence_sha256: str = SOLUTION_EVIDENCE_SHA256,
) -> str:
    return " ".join((
        "FL4SH_MONITOR state=POOL_RECOVERY_EVIDENCE",
        f"monitor_session_id={session_id}",
        f"pool_episode_id={episode_id}",
        f"pool_alert_sequence={sequence}",
        "recovery_signal=SOLUTIONS_ACCEPTED",
        f"timestamp_utc={timestamp}",
        f"solutions_evidence_sha256={evidence_sha256}",
        "actions_performed=false",
    ))


def reallocation_line(
    *, alert_id: str | None = None, gpu_raw: str = "RTX 5080 Laptop",
    episode_id: str | None = None, alert_sequence: int | None = None,
) -> str:
    parts = [
        "FL4SH_MONITOR",
        "state=REALLOCATE_RECOMMENDED",
        "profile=RTX_5080_LAPTOP",
        "device=fl4shminer_device:1",
        "gpu_key=RTX_5080_LAPTOP",
        "gpu_candidates=RTX_5080_LAPTOP",
        f'gpu_raw="{gpu_raw}"',
        "floor=105",
        "floor_ths=105",
        "floor_source=ENV_REGISTRY",
        "observed=98.94",
        "bad_windows=2/2",
        "coverage=0.91",
        "window_samples=12",
        "stale=7/591",
        "stale_pct=1.2%",
        "provider_binding=UNKNOWN",
        "gpu_identity_verified=false",
        "billing=UNKNOWN",
        "actions_performed=false",
        f"policy_hash={POLICY_HASH}",
        f"timestamp={EVENT_TIME}",
    ]
    if alert_id is not None:
        parts.append(f"alert_id={alert_id}")
    if episode_id is not None:
        sequence = alert_sequence or 1
        reason = "INITIAL_THRESHOLD_CROSSING" if sequence == 1 else "WORSENED"
        parts.extend([
            "tolerance_ths=2", "decision_threshold_ths=103",
            f"episode_id={episode_id}", f"alert_sequence={sequence}", f"notification_reason={reason}",
        ])
        if sequence > 1:
            parts.extend([
                "previous_alert_mean_ths=104",
                "deterioration_since_previous_alert_ths=5",
            ])
    return " ".join(parts)


def lifecycle_entry(signal: str, *, event_time: str, labels=None, log_id=None):
    messages = {
        "running": "Instance Running",
        "ready": "Instance Ready (Readiness Probe Passed)",
        "config": "FL4SH_MONITOR state=CONFIG enabled=true actions_performed=false",
        "gpu": "FL4SH_MONITOR state=GPU_DETECTED device=fl4shminer_device:1 actions_performed=false",
        "initialized": "Device [1] NVIDIA GeForce RTX 5080 Laptop GPU: Initialized",
        "hashrate": "Device [1] hashRate: 217.81 TH/s, stale: 0/0 (0.0%), warm: 0",
    }
    fixture_lifecycle_observation = None
    if signal == "running":
        fixture_lifecycle_observation = {
            "source": "SYNTHETIC_PROVIDER_LIFECYCLE_FIXTURE",
            "event": "INSTANCE_RUNNING",
        }
    elif signal == "ready":
        fixture_lifecycle_observation = {
            "source": "SYNTHETIC_PROVIDER_LIFECYCLE_FIXTURE",
            "event": "INSTANCE_READY",
        }
    return log_entry(
        text_log=messages[signal],
        labels=labels or provider_labels(),
        log_id=log_id or f"{signal}-{event_time}",
        event_time=event_time,
        fixture_lifecycle_observation=fixture_lifecycle_observation,
    )


def cuda_fatal_entry(*, labels=None, log_id="cuda-fatal", event_time=EVENT_TIME, timestamp=None):
    prefix = f"{timestamp} " if timestamp else ""
    return log_entry(
        text_log=prefix + CUDA_FATAL_LINE,
        labels=labels or provider_labels(),
        log_id=log_id,
        event_time=event_time,
    )


def cuda_exit_entry(*, labels=None, log_id="miner-exit", event_time="2026-10-13T12:00:30Z", timestamp=None):
    prefix = f"{timestamp} " if timestamp else ""
    return log_entry(
        text_log=prefix + "Fl4shMiner stopped: exit status 1",
        labels=labels or provider_labels(),
        log_id=log_id,
        event_time=event_time,
    )


def provider_labels(
    machine_id: str = "machine-1",
    instance_id: str = "instance-1",
    group: str = "fl4shminer",
) -> dict[str, str]:
    return {
        "machine_id": machine_id,
        "instance_id": instance_id,
        "container_group_name": group,
        "organization_name": ORG,
        "project_name": PROJECT,
    }


def log_entry(
    *,
    text_log: str | None = None,
    structured_message=None,
    labels: dict[str, object] | None = None,
    log_id: str | None = "log-1",
    event_time: str = EVENT_TIME,
    fixture_lifecycle_observation: dict[str, str] | None = None,
) -> dict[str, object]:
    result = {
        "data_classification": DATA_CLASSIFICATION,
        "log_id": log_id,
        "event_time_utc": event_time,
        "resource": {"type": "salad.container_group_instance", "labels": labels or provider_labels()},
        "text_log": text_log,
        "structured_message": structured_message,
    }
    if fixture_lifecycle_observation is not None:
        result["fixture_lifecycle_observation"] = fixture_lifecycle_observation
    return result


def make_enricher(
    entries,
    *,
    ledger: SQLiteAlertLedger | None = None,
    pages=None,
    limits: QueryLimits | None = None,
):
    policy = LogQueryPolicy(ORG)
    transport = FixtureLogQueryTransport(
        pages if pages is not None else [LogQueryPage(tuple(entries))],
        policy=policy,
    )
    store = ledger or SQLiteAlertLedger()
    return LogAlertEnricher(
        approved_organization=ORG,
        transport=transport,
        ledger=store,
        limits=limits,
    ), transport, store


def same_time_running_ready_pair_with_ready_hash_first():
    event_time = "2026-10-13T12:00:00Z"
    for index in range(2_048):
        running = lifecycle_entry("running", event_time=event_time, log_id=f"running-{index}")
        ready = lifecycle_entry("ready", event_time=event_time, log_id=f"ready-{index}")
        if normalize_log_entry(ready).evidence_sha256 < normalize_log_entry(running).evidence_sha256:
            return running, ready
    raise AssertionError("could not construct deterministic Ready-first evidence hashes")


def run_startup_guard(entries, *, end_time_utc, prior_states=None):
    return StartupGuard().process(
        [normalize_log_entry(entry) for entry in entries],
        prior_states=prior_states or {},
        end_time_utc=end_time_utc,
    )


class LogAlertNormalizerTests(unittest.TestCase):
    def test_fixture_cannot_claim_provider_observed_classification(self):
        raw = log_entry(text_log="ordinary synthetic log")
        raw["data_classification"] = PROVIDER_OBSERVED
        with self.assertRaisesRegex(LogRecordError, "provenance"):
            normalize_log_entry(raw)

    def test_exact_reallocation_record_preserves_source_and_provider_labels(self):
        raw = log_entry(text_log=reallocation_line(), structured_message=None)
        parsed = normalize_log_entry(raw)
        self.assertEqual(parsed.data_classification, "SYNTHETIC/UNVERIFIED")
        self.assertEqual(parsed.alert.event_type, "REALLOCATE_RECOMMENDED")
        self.assertEqual(parsed.alert.fields["gpu_key"], "RTX_5080_LAPTOP")
        self.assertEqual(parsed.alert.fields["observed_window_mean_ths"], 98.94)
        self.assertEqual(parsed.alert.fields["stale"], {
            "numerator": 7, "denominator": 591, "reported_percent": 1.2,
        })
        self.assertEqual(parsed.alert_source, "text_log")
        self.assertEqual(parsed.text_log, raw["text_log"])
        self.assertEqual(parsed.identity.machine_id, "machine-1")
        self.assertEqual(parsed.identity.instance_id, "instance-1")
        self.assertEqual(parsed.identity.container_group_name, "fl4shminer")

    def test_monitor_event_tolerance_episode_and_realert_fields_are_bounded(self):
        episode = "44444444-4444-4444-8444-444444444444"
        parsed = normalize_log_entry(log_entry(
            text_log=reallocation_line(episode_id=episode, alert_sequence=2),
        ))
        self.assertEqual(parsed.alert.fields["floor_tolerance_ths"], 2.0)
        self.assertEqual(parsed.alert.fields["decision_threshold_ths"], 103.0)
        self.assertEqual(parsed.alert.fields["degradation_episode_id"], episode)
        self.assertEqual(parsed.alert.fields["alert_sequence"], 2)
        self.assertEqual(parsed.alert.fields["notification_reason"], "WORSENED")
        self.assertEqual(parsed.alert.fields["previous_alert_mean_ths"], 104.0)
        self.assertEqual(parsed.alert.fields["deterioration_since_previous_alert_ths"], 5.0)
        self.assertNotIn("alert_reason", parsed.alert.fields)
        self.assertNotIn("deterioration_ths", parsed.alert.fields)
        invalid = reallocation_line(episode_id=episode, alert_sequence=2).replace(
            "decision_threshold_ths=103", "decision_threshold_ths=104"
        )
        with self.assertRaises(LogRecordError):
            normalize_log_entry(log_entry(text_log=invalid))

        unapproved_aliases = reallocation_line(episode_id=episode, alert_sequence=2)
        unapproved_aliases = unapproved_aliases.replace(
            "notification_reason=WORSENED", "alert_reason=SUSTAINED_DEGRADATION"
        ).replace(
            "deterioration_since_previous_alert_ths=5", "deterioration_ths=5"
        )
        self.assertIsNone(normalize_log_entry(log_entry(text_log=unapproved_aliases)).alert)

    def test_startup_and_progress_signals_are_exact_and_not_alert_identity(self):
        expected = {
            "running": "INSTANCE_RUNNING", "ready": "INSTANCE_READY",
            "config": "MONITOR_CONFIG", "gpu": "GPU_DETECTED",
            "initialized": "DEVICE_INITIALIZED", "hashrate": "DEVICE_HASHRATE",
        }
        for name, signal in expected.items():
            parsed = normalize_log_entry(lifecycle_entry(name, event_time=EVENT_TIME))
            self.assertEqual(parsed.startup_signal, signal)
            if name in {"running", "ready"}:
                self.assertEqual(parsed.startup_signal_source, "SYNTHETIC_PROVIDER_LIFECYCLE_FIXTURE")
            self.assertIsNone(parsed.alert)
        for line in (
            "Device [1] hashRate: NaN TH/s",
            "GPU autotune hashRate: 900 TH/s",
            "some unrelated Instance Running words",
        ):
            parsed = normalize_log_entry(log_entry(text_log=line))
            self.assertIsNone(parsed.startup_signal)
        # Miner-owned text that resembles provider lifecycle output is not
        # accepted as Running/Ready without the explicit synthetic fixture envelope.
        for line in ("Instance Running", "Instance Ready (Readiness Probe Passed)"):
            parsed = normalize_log_entry(log_entry(text_log=line))
            self.assertIsNone(parsed.startup_signal)

    def test_exact_cuda_driver_failure_and_timestamp_are_bounded(self):
        self.assertEqual(CUDA_FATAL_LINE, CUDA_FATAL_CONTRACT_SAMPLE)
        for text in (
            CUDA_FATAL_CONTRACT_SAMPLE,
            "2026/10/13 12:00:00 " + CUDA_FATAL_CONTRACT_SAMPLE,
        ):
            entry = log_entry(text_log=text, labels=provider_labels())
            with self.subTest(text=entry["text_log"]):
                parsed = normalize_log_entry(entry)
                self.assertEqual(parsed.alert.event_type, "CUDA_DRIVER_INCOMPATIBLE")
                self.assertEqual(parsed.alert.fields["reason"], "CUDA_DRIVER_VERSION_INSUFFICIENT")
                self.assertIs(parsed.alert.fields["gpu_initialized"], False)
                self.assertEqual(parsed.alert.fields["miner_exit_status"], "UNKNOWN")
                self.assertIs(parsed.alert.fields["exit_status_confirmed"], False)
                self.assertEqual(parsed.alert.fields["recommendation"], "REALLOCATE")
                self.assertIs(parsed.alert.fields["actions_performed"], False)
                self.assertEqual(parsed.cuda_signal, "CUDA_DRIVER_INCOMPATIBLE")

    def test_structured_cuda_fatal_is_recognized_without_trusting_raw_type(self):
        raw = log_entry(text_log=None, structured_message={"type": "container-stderr", "message": CUDA_FATAL_LINE})
        parsed = normalize_log_entry(raw)
        self.assertEqual(parsed.alert.event_type, "CUDA_DRIVER_INCOMPATIBLE")
        self.assertEqual(parsed.alert_source, "structured_message")
        self.assertEqual(parsed.cuda_signal, "CUDA_DRIVER_INCOMPATIBLE")

    def test_cuda_exit_and_nearby_errors_are_not_fatal_alerts(self):
        exit_record = normalize_log_entry(cuda_exit_entry())
        self.assertIsNone(exit_record.alert)
        self.assertEqual(exit_record.cuda_signal, "MINER_EXIT_STATUS_1")
        for line in (
            "No supported GPUs found (CUDA: generic error, OpenCL: <nil>)",
            "No supported GPUs found (CUDA: cudaGetDeviceCount: unknown, OpenCL: <nil>)",
            "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is insufficient for CUDA runtime version, OpenCL: <nil>)",
            "CUDA driver version is insufficient for CUDA runtime version",
            "nvidia-smi diagnostic succeeded",
            "No supported GPUs found due to out of memory",
        ):
            with self.subTest(line=line):
                parsed = normalize_log_entry(log_entry(text_log=line))
                self.assertIsNone(parsed.alert)
                self.assertIsNone(parsed.cuda_signal)

    def test_lifecycle_fixture_requires_explicit_unambiguous_provenance(self):
        for observation in (
            None,
            {"source": "UNKNOWN", "event": "INSTANCE_RUNNING"},
            {"source": "SYNTHETIC_PROVIDER_LIFECYCLE_FIXTURE", "event": "Instance Running"},
            {"source": "SYNTHETIC_PROVIDER_LIFECYCLE_FIXTURE", "event": {"state": "Running"}},
        ):
            with self.subTest(observation=observation):
                raw = log_entry(text_log="Instance Running")
                if observation is not None:
                    raw["fixture_lifecycle_observation"] = observation
                self.assertIsNone(normalize_log_entry(raw).startup_signal)

    def test_monitor_configuration_invalid_reason_is_allowlisted_and_secret_free(self):
        for reason in ("INVALID_GPU_FLOORS_JSON", "INVALID_ENTRYPOINT_CONFIGURATION"):
            with self.subTest(reason=reason):
                parsed = normalize_log_entry(log_entry(
                    text_log=f"FL4SH_MONITOR configuration invalid: {reason}"
                ))
                self.assertEqual(parsed.alert.event_type, "MONITOR_CONFIGURATION_INVALID")
                self.assertEqual(parsed.alert.fields["reason"], reason)
                self.assertEqual(parsed.alert.fields["suggestion"], "CHECK_CONFIGURATION")
        self.assertIsNone(normalize_log_entry(log_entry(
            text_log="FL4SH_MONITOR configuration invalid: UNKNOWN_REASON"
        )).alert)

    def test_no_floor_event_keeps_floor_unknown_and_actions_disabled(self):
        line = (
            "FL4SH_MONITOR state=NO_FLOOR_CONFIGURED device=fl4shminer_device:1 "
            "gpu_key=RTX_5070_LAPTOP floor=unknown floor_ths=unknown floor_source=UNCONFIGURED "
            "observed=99 bad_windows=0/2 actions_performed=false"
        )
        parsed = normalize_log_entry(log_entry(text_log=line))
        self.assertEqual(parsed.alert.event_type, "NO_FLOOR_CONFIGURED")
        self.assertIsNone(parsed.alert.fields.get("floor_ths"))
        self.assertEqual(parsed.alert.fields["suggestion"], "CHECK_GPU_FLOOR_CONFIG")

    def test_structured_message_source_is_preserved_and_not_confused_with_text(self):
        structured = {
            "type": "FL4SH_MONITOR",
            "state": "REALLOCATE_RECOMMENDED",
            "fields": {
                "device": "fl4shminer_device:1",
                "gpu_key": "RTX_5080_LAPTOP",
                "floor_ths": 105,
                "observed": 98.94,
                "bad_windows": "2/2",
                "policy_hash": POLICY_HASH,
                "timestamp": EVENT_TIME,
                "actions_performed": False,
            },
        }
        parsed = normalize_log_entry(log_entry(structured_message=structured))
        self.assertEqual(parsed.alert.event_type, "REALLOCATE_RECOMMENDED")
        self.assertEqual(parsed.alert_source, "structured_message")
        self.assertEqual(parsed.structured_message, structured)

    def test_matching_text_and_structured_alert_reports_both_sources(self):
        line = reallocation_line()
        parsed = normalize_log_entry(log_entry(
            text_log=line,
            structured_message={"message": line},
        ))
        self.assertEqual(parsed.alert_source, "text_log+structured_message")

    def test_provider_identity_missing_ids_is_unknown_and_never_inferred(self):
        parsed = normalize_log_entry(log_entry(
            text_log=reallocation_line(gpu_raw="machine_id=forged"),
            labels={"container_group_name": "fl4shminer", "project_name": PROJECT},
        ))
        self.assertEqual(parsed.identity.status, "UNKNOWN")
        self.assertIsNone(parsed.identity.machine_id)
        self.assertIsNone(parsed.identity.instance_id)
        self.assertIsNone(parsed.identity.public_fields()["machine_id"])

    def test_conflicting_provider_label_aliases_block_enriched_identity(self):
        labels = provider_labels()
        labels["machine id"] = "machine-other"
        parsed = normalize_log_entry(log_entry(text_log=reallocation_line(), labels=labels))
        self.assertEqual(parsed.identity.status, "CONFLICTING")
        public = parsed.identity.public_fields()
        self.assertIsNone(public["machine_id"])
        self.assertIsNone(public["instance_id"])
        self.assertIsNone(public["container_group_name"])

    def test_bad_provider_label_shape_fails_closed(self):
        with self.assertRaises(LogRecordError):
            normalize_log_entry(log_entry(text_log=reallocation_line(), labels={"machine_id": ["m1", "m2"]}))
        with self.assertRaises(LogRecordError):
            normalize_log_entry(log_entry(text_log=reallocation_line(), labels={"long": "x" * 1_025}))

    def test_credential_like_fixture_is_rejected_without_echoing_value(self):
        secret = "synthetic-private-credential-971a"
        raw = log_entry(text_log=reallocation_line(), labels=provider_labels())
        raw["resource"]["labels"]["Authorization"] = f"Bearer {secret}"
        with self.assertRaises(LogRecordError) as caught:
            normalize_log_entry(raw)
        self.assertNotIn(secret, str(caught.exception))


class LogAlertEngineTests(unittest.TestCase):
    def test_exact_pool_timeout_is_normalized_and_raw_line_not_in_telegram_text(self):
        raw_line = (
            "2026/10/12 22:04:33 Pool connection failed: mining.authorize response timeout; "
            "reconnecting; retrying in 10s"
        )
        enricher, _, ledger = make_enricher([log_entry(text_log=raw_line)])
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.prepared_count, 1)
        message = ledger.list_outbox()[0]["message_text"]
        payload = ledger.list_outbox()[0]["payload"]
        self.assertIn("Reason: MINING_AUTHORIZE_RESPONSE_TIMEOUT", message)
        self.assertIn("Retry: 10s", message)
        self.assertNotIn(raw_line, message)
        self.assertNotIn("response timeout", message)
        self.assertEqual(payload["event_fields"], {
            "reason": "MINING_AUTHORIZE_RESPONSE_TIMEOUT",
            "retry_seconds": 10,
            "actions_performed": False,
        })
        self.assertEqual(result.evidence[0].text_log, raw_line)
        ledger.close()

    def test_pool_timeout_without_timestamp_also_matches(self):
        line = "Pool connection failed: mining.authorize response timeout; reconnecting; retrying in 7s"
        enricher, _, ledger = make_enricher([log_entry(text_log=line)])
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.prepared_count, 1)
        self.assertIn("Retry: 7s", ledger.list_outbox()[0]["message_text"])
        ledger.close()

    def test_pool_unstable_monitor_event_is_normalized_without_raw_miner_text(self):
        unstable = (
            "FL4SH_MONITOR state=POOL_CONNECTION_UNSTABLE "
            "reason=MINING_AUTHORIZE_RESPONSE_TIMEOUT failure_count=3 window_seconds=90 "
            "first_failure_utc=2026-10-13T12:00:01Z latest_failure_utc=2026-10-13T12:01:20Z "
            "gpu_key=RTX_5080_LAPTOP device=fl4shminer_device:1 actions_performed=false"
        )
        enricher, _, ledger = make_enricher([log_entry(text_log=unstable)])
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.prepared_count, 1)
        outbox = ledger.list_outbox()[0]
        self.assertEqual(outbox["payload"]["event_type"], "POOL_CONNECTION_UNSTABLE")
        self.assertIn("Failures: 3 in 90s", outbox["message_text"])
        self.assertNotIn("Pool connection failed", outbox["message_text"])
        self.assertFalse(outbox["payload"]["actions_performed"])
        ledger.close()

    def test_pool_episode_events_normalize_canonical_fields_and_reject_invalid_recovery(self):
        failed = normalize_log_entry(log_entry(
            text_log=pool_monitor_line("POOL_CONNECTION_FAILED"),
        ))
        self.assertEqual(failed.alert.event_type, "POOL_CONNECTION_FAILED")
        self.assertEqual(failed.alert.fields["pool_episode_id"], POOL_EPISODE_ID)
        self.assertEqual(failed.alert.fields["pool_alert_sequence"], 1)
        unstable_line = pool_monitor_line(
            "POOL_CONNECTION_UNSTABLE", sequence=2,
            first_failure="2026-10-13T12:00:00Z",
            latest_failure="2026-10-13T12:05:00Z",
            failure_count=2, recent_failure_count=1,
            notification_reason="PERSISTENT_FAILURES", unstable_duration_seconds=300,
        )
        unstable = normalize_log_entry(log_entry(text_log=unstable_line))
        self.assertEqual(unstable.alert.fields["notification_reason"], "PERSISTENT_FAILURES")
        recovery_line = pool_monitor_line(
            "POOL_CONNECTION_RECOVERED", sequence=2,
            first_failure="2026-10-13T12:00:00Z",
            latest_failure="2026-10-13T12:05:00Z",
            prior_failure_count=2, recovered_at="2026-10-13T12:05:30Z",
        )
        recovered = normalize_log_entry(log_entry(text_log=recovery_line))
        self.assertEqual(recovered.alert.event_type, "POOL_CONNECTION_RECOVERED")
        self.assertEqual(recovered.alert.fields["recovery_signal"], "SOLUTIONS_ACCEPTED")
        self.assertEqual(recovered.alert.fields["failure_count"], 2)
        self.assertEqual(recovered.alert.fields["retry_seconds"], 10)
        self.assertEqual(recovered.alert.fields["timestamp_utc"], "2026-10-13T12:05:30.000000Z")
        invalid = recovery_line.replace("recovery_signal=SOLUTIONS_ACCEPTED", "recovery_signal=HASHRATE")
        with self.assertRaises(LogRecordError):
            normalize_log_entry(log_entry(text_log=invalid))

    def test_burst_uses_rolling_window_even_when_episode_started_over_90_seconds_earlier(self):
        event = normalize_log_entry(log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_UNSTABLE", sequence=2,
                first_failure="2026-10-13T12:00:00Z",
                recent_failure_window_start="2026-10-13T12:03:20Z",
                latest_failure="2026-10-13T12:03:40Z",
                failure_count=4, recent_failure_count=3,
                notification_reason="BURST_FAILURES", unstable_duration_seconds=220,
            ),
        ))
        self.assertEqual(event.alert.fields["notification_reason"], "BURST_FAILURES")
        self.assertEqual(event.alert.fields["recent_failure_window_start_utc"], "2026-10-13T12:03:20.000000Z")

    def test_pool_alert_marker_requires_same_session_episode_sequence_and_resource(self):
        event_line = pool_monitor_line("POOL_CONNECTION_FAILED")
        marker = (
            "FL4SH_MONITOR state=TELEGRAM_ALERT alert_id=44444444-4444-4444-8444-444444444444 "
            "event=POOL_CONNECTION_FAILED monitor_session_id=" + POOL_SESSION_ID
            + " pool_episode_id=" + POOL_EPISODE_ID
            + " pool_alert_sequence=1 actions_performed=false"
        )
        entries = [
            log_entry(text_log=event_line, labels=provider_labels("machine-a", "instance-a"), log_id="pool-event"),
            log_entry(text_log=marker, labels=provider_labels("machine-b", "instance-b"), log_id="wrong-machine-marker",
                      event_time="2026-10-13T12:00:05Z"),
        ]
        enricher, _, ledger = make_enricher(entries)
        enricher.run_once(end_time_utc=END_TIME)
        outbox = ledger.list_outbox()
        self.assertEqual(len(outbox), 1)
        self.assertIsNone(outbox[0]["payload"]["alert_id"])
        self.assertIn("Machine ID: machine-a", outbox[0]["message_text"])
        self.assertNotIn("machine-b", outbox[0]["message_text"])
        ledger.close()

    def test_pool_recovery_requires_same_resource_new_solution_and_durable_open_episode(self):
        labels = provider_labels("pool-machine", "pool-instance", "fl4shminer-2")
        failed = log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_FAILED",
                first_failure="2026-10-13T17:43:30Z",
                latest_failure="2026-10-13T17:43:30Z",
            ),
            labels=labels, log_id="pool-failed", event_time="2026-10-13T17:43:30Z",
        )
        unstable = log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_UNSTABLE", sequence=2,
                first_failure="2026-10-13T17:43:30Z",
                latest_failure="2026-10-13T17:48:30Z",
                failure_count=2, recent_failure_count=1,
                notification_reason="PERSISTENT_FAILURES", unstable_duration_seconds=300,
            ),
            labels=labels, log_id="pool-unstable", event_time="2026-10-13T17:48:30Z",
        )
        accepted = log_entry(
            text_log=SOLUTION_EVIDENCE_LINE,
            labels=labels, log_id="accepted", event_time="2026-10-13T17:48:52Z",
        )
        recovered = log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_RECOVERED", sequence=3,
                first_failure="2026-10-13T17:43:30Z",
                latest_failure="2026-10-13T17:48:30Z",
                prior_failure_count=2, recovered_at="2026-10-13T17:48:50Z",
                solutions_evidence_sha256=SOLUTION_EVIDENCE_SHA256,
            ),
            labels=labels, log_id="pool-recovered", event_time="2026-10-13T17:48:51Z",
        )
        recovery_marker = log_entry(
            text_log=pool_recovery_evidence_line(
                sequence=3, timestamp="2026-10-13T17:48:50Z",
                evidence_sha256=SOLUTION_EVIDENCE_SHA256,
            ),
            labels=labels, log_id="pool-recovery-marker", event_time="2026-10-13T17:48:50.500000Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pool-ledger.sqlite"
            ledger = SQLiteAlertLedger(path)
            first, _, ledger = make_enricher([failed], ledger=ledger)
            result = first.run_once(end_time_utc="2026-10-13T17:43:40Z")
            self.assertEqual(result.prepared_count, 1)
            ledger.close()

            reopened = SQLiteAlertLedger(path)
            second, _, reopened = make_enricher([unstable, recovery_marker, recovered, accepted], ledger=reopened)
            result = second.run_once(end_time_utc="2026-10-13T17:49:00Z")
            self.assertEqual(result.prepared_count, 2)
            history = reopened.list_outbox()
            self.assertEqual([row["payload"]["event_type"] for row in history], [
                "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE", "POOL_CONNECTION_RECOVERED",
            ])
            recovery_row = next(row for row in history if row["payload"]["event_type"] == "POOL_CONNECTION_RECOVERED")
            recovery_message = recovery_row["message_text"]
            self.assertIn("Machine ID: pool-machine", recovery_message)
            self.assertIn("Instance ID: pool-instance", recovery_message)
            self.assertIn("Container Group: fl4shminer-2", recovery_message)
            self.assertIn("Failures: 2", recovery_message)
            self.assertIn("Retry reported by miner: 10s", recovery_message)
            self.assertIn("Timestamp: 2026-10-13T17:48:50.000000Z", recovery_message)
            self.assertNotIn("Solutions accepted", recovery_message)
            self.assertNotIn("Machine ID: correlate", recovery_message)
            replay, _, _ = make_enricher([unstable, accepted, recovery_marker, recovered], ledger=reopened)
            duplicate = replay.run_once(end_time_utc="2026-10-13T17:49:00Z")
            self.assertEqual(duplicate.prepared_count, 0)
            self.assertEqual(reopened.alert_count(), 3)
            reopened.close()

    def test_pool_recovery_marker_must_match_session_episode_sequence_hash_and_resource(self):
        labels = provider_labels("bound-machine", "bound-instance", "fl4shminer")
        failed = log_entry(
            text_log=pool_monitor_line("POOL_CONNECTION_FAILED"),
            labels=labels, log_id="bound-failed", event_time="2026-10-13T12:00:00Z",
        )
        accepted = log_entry(
            text_log=SOLUTION_EVIDENCE_LINE,
            labels=labels, log_id="bound-solutions", event_time="2026-10-13T12:00:32Z",
        )
        recovered = log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_RECOVERED", sequence=2,
                recovered_at="2026-10-13T12:00:30Z",
                solutions_evidence_sha256=SOLUTION_EVIDENCE_SHA256,
            ),
            labels=labels, log_id="bound-recovered", event_time="2026-10-13T12:00:31Z",
        )
        invalid_marker_specs = (
            None,
            {"session_id": "99999999-9999-4999-8999-999999999999"},
            {"episode_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
            {"sequence": 3},
            {"evidence_sha256": "b" * 64},
            {"timestamp": "2026-10-13T12:00:19Z"},
        )
        for index, marker_options in enumerate(invalid_marker_specs):
            with self.subTest(marker=marker_options):
                entries = [failed, accepted, recovered]
                if marker_options is not None:
                    entries.insert(2, log_entry(
                        text_log=pool_recovery_evidence_line(**marker_options),
                        labels=labels, log_id=f"bad-recovery-marker-{index}",
                        event_time="2026-10-13T12:00:30.500000Z",
                    ))
                enricher, _, ledger = make_enricher(entries)
                result = enricher.run_once(end_time_utc="2026-10-13T12:01:00Z")
                self.assertEqual(result.prepared_count, 1)
                self.assertEqual([row["payload"]["event_type"] for row in ledger.list_outbox()], [
                    "POOL_CONNECTION_FAILED",
                ])
                ledger.close()

        wrong_resource_marker = log_entry(
            text_log=pool_recovery_evidence_line(),
            labels=provider_labels("other-machine", "other-instance", "fl4shminer"),
            log_id="wrong-resource-recovery-marker", event_time="2026-10-13T12:00:30.500000Z",
        )
        enricher, _, ledger = make_enricher([failed, accepted, wrong_resource_marker, recovered])
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:00Z")
        self.assertEqual(result.prepared_count, 1)
        self.assertEqual([row["payload"]["event_type"] for row in ledger.list_outbox()], [
            "POOL_CONNECTION_FAILED",
        ])
        ledger.close()

        combined_signal_and_marker = log_entry(
            text_log=SOLUTION_EVIDENCE_LINE,
            structured_message={"message": pool_recovery_evidence_line(timestamp="2026-10-13T12:00:30Z")},
            labels=labels, log_id="combined-signal-marker", event_time="2026-10-13T12:00:30.500000Z",
        )
        enricher, _, ledger = make_enricher([failed, combined_signal_and_marker, recovered])
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:00Z")
        self.assertEqual(result.prepared_count, 1)
        self.assertEqual([row["payload"]["event_type"] for row in ledger.list_outbox()], [
            "POOL_CONNECTION_FAILED",
        ])
        ledger.close()

        early_signal = log_entry(
            text_log=SOLUTION_EVIDENCE_LINE,
            labels=labels, log_id="early-solutions", event_time="2026-10-13T12:00:20Z",
        )
        valid_marker = log_entry(
            text_log=pool_recovery_evidence_line(timestamp="2026-10-13T12:00:30Z"),
            labels=labels, log_id="ordered-recovery-marker",
            event_time="2026-10-13T12:00:30.500000Z",
        )
        later_recovery = log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_RECOVERED", sequence=2,
                recovered_at="2026-10-13T12:00:30Z",
                solutions_evidence_sha256=SOLUTION_EVIDENCE_SHA256,
            ),
            labels=labels, log_id="ordered-recovery", event_time="2026-10-13T12:00:31Z",
        )
        enricher, _, ledger = make_enricher([failed, valid_marker, later_recovery, early_signal])
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:00Z")
        self.assertEqual(result.prepared_count, 1)
        self.assertEqual(
            [row["payload"]["event_type"] for row in ledger.list_outbox()],
            ["POOL_CONNECTION_FAILED"],
        )
        ledger.close()

    def test_runtime_delayed_burst_flows_through_normalizer_to_central_alert(self):
        runtime_path = TELEMETRY_ROOT.parent / "runtime" / "fl4shminer" / "fl4sh-runtime-monitor.py"
        spec = importlib.util.spec_from_file_location("fl4sh_runtime_monitor_pool_e2e", runtime_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        runtime = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = runtime
        spec.loader.exec_module(runtime)

        class FakeNotifier:
            def __init__(self):
                self.events = []
                self.audit_lines = []

            def submit(self, event_name, event, *, monitor_session_id, alert_id=None):
                self.events.append((event_name, event))
                return alert_id or "synthetic-alert-id"

            def audit(self, line_text):
                self.audit_lines.append(line_text)

        current = [0.0]
        base_utc = datetime(2026, 10, 13, 17, 43, 30, tzinfo=timezone.utc)
        runtime_config = runtime.MonitorConfig.from_env({"FL4SH_MONITOR_ENABLED": "1"}, require_enabled=True)
        monitor = runtime.Fl4shMonitor(runtime_config, start_monotonic=0.0)
        notifier = FakeNotifier()
        coordinator = runtime.TelegramAlertCoordinator(
            notifier, runtime.TelegramConfig.from_env({}),
            monotonic=lambda: current[0],
            monitor_session_id=POOL_SESSION_ID,
            utc_now=lambda: base_utc + timedelta(seconds=current[0]),
        )
        failure_line = runtime.POOL_CONNECTION_FAILED_LINE + "; reconnecting; retrying in 10s"
        for elapsed in (0.0, 200.0, 210.0, 220.0):
            current[0] = elapsed
            coordinator.stdout_line(failure_line, monitor)
        self.assertEqual([name for name, _ in notifier.events], [
            "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
        ])
        self.assertEqual(notifier.events[-1][1]["notification_reason"], "BURST_FAILURES")
        self.assertEqual(notifier.events[-1][1]["recent_failure_count"], 3)

        labels = provider_labels("delayed-burst-machine", "delayed-burst-instance", "fl4shminer-3")
        provider_entries = []
        for index, line_text in enumerate(notifier.audit_lines):
            fields = dict(token.split("=", 1) for token in line_text.split()[2:] if "=" in token)
            provider_entries.append(log_entry(
                text_log=line_text, labels=labels, log_id=f"runtime-pool-event-{index}",
                event_time=fields["latest_failure_utc"],
            ))
        enricher, _, ledger = make_enricher(provider_entries)
        result = enricher.run_once(end_time_utc="2026-10-13T17:48:00Z")
        self.assertEqual(result.prepared_count, 2)
        self.assertCountEqual([row["payload"]["event_type"] for row in ledger.list_outbox()], [
            "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
        ])
        unstable_message = next(
            row["message_text"] for row in ledger.list_outbox()
            if row["payload"]["event_type"] == "POOL_CONNECTION_UNSTABLE"
        )
        self.assertIn("Machine ID: delayed-burst-machine", unstable_message)
        self.assertIn("Container Group: fl4shminer-3", unstable_message)
        ledger.close()

    def test_real_supervisor_recovery_stdout_normalizes_and_replays_across_sqlite_cycles(self):
        runtime_path = TELEMETRY_ROOT.parent / "runtime" / "fl4shminer" / "fl4sh-runtime-monitor.py"
        spec = importlib.util.spec_from_file_location("fl4sh_runtime_monitor_pool_replay", runtime_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        runtime = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = runtime
        spec.loader.exec_module(runtime)

        accepted_line = SOLUTION_EVIDENCE_LINE
        child_code = (
            "import time; "
            f"print({(runtime.POOL_CONNECTION_FAILED_LINE + '; reconnecting; retrying in 10s')!r}, flush=True); "
            "time.sleep(1.1); "
            f"print({accepted_line!r}, flush=True)"
        )
        stdout_bytes = io.BytesIO()
        stderr_bytes = io.BytesIO()
        fake_sys = SimpleNamespace(
            stdout=SimpleNamespace(buffer=stdout_bytes, flush=stdout_bytes.flush),
            stderr=SimpleNamespace(buffer=stderr_bytes, flush=stderr_bytes.flush),
        )
        runtime_config = runtime.MonitorConfig.from_env(
            {"FL4SH_MONITOR_ENABLED": "1"}, require_enabled=True
        )
        telegram_config = runtime.TelegramConfig.from_env({"FL4SH_TELEGRAM_ENABLED": "0"})
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(runtime, "sys", fake_sys):
            return_code = runtime.run_supervisor(
                runtime_config,
                [sys.executable, "-c", child_code],
                telegram_config=telegram_config,
            )

        self.assertEqual(return_code, 0)
        emitted_lines = stdout_bytes.getvalue().decode("utf-8", "replace").splitlines()
        failed_line = next(line for line in emitted_lines if "state=POOL_CONNECTION_FAILED" in line)
        marker_line = next(line for line in emitted_lines if "state=POOL_RECOVERY_EVIDENCE" in line)
        recovered_line = next(line for line in emitted_lines if "state=POOL_CONNECTION_RECOVERED" in line)
        accepted_index = emitted_lines.index(accepted_line)
        self.assertLess(emitted_lines.index(failed_line), emitted_lines.index(marker_line))
        self.assertLess(emitted_lines.index(marker_line), emitted_lines.index(recovered_line))
        self.assertLess(emitted_lines.index(recovered_line), accepted_index)
        self.assertEqual(recovered_line.split().count("retry_seconds=10"), 1)

        labels = provider_labels("runtime-machine", "runtime-instance", "fl4shminer-2")

        def fields_for(line_text):
            return dict(
                token.split("=", 1)
                for token in line_text.split()[2:]
                if "=" in token
            )

        failed_fields = fields_for(failed_line)
        marker_fields = fields_for(marker_line)
        recovered_fields = fields_for(recovered_line)
        recovered_at = datetime.fromisoformat(
            recovered_fields["recovered_at_utc"].replace("Z", "+00:00")
        )
        recovery_time = recovered_at.isoformat(timespec="microseconds").replace("+00:00", "Z")
        accepted_time = (recovered_at + timedelta(seconds=1)).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")

        # This uses the exact audit line emitted by the supervisor, not a hand-built
        # pool_monitor_line fixture. It catches malformed real recovery records.
        actual_recovery = normalize_log_entry(log_entry(
            text_log=recovered_line,
            labels=labels,
            log_id="runtime-recovered",
            event_time=recovery_time,
        ))
        self.assertIsNotNone(actual_recovery.alert)
        self.assertEqual(actual_recovery.alert.event_type, "POOL_CONNECTION_RECOVERED")
        self.assertEqual(actual_recovery.alert.fields["retry_seconds"], 10)

        failed_entry = log_entry(
            text_log=failed_line,
            labels=labels,
            log_id="runtime-failed",
            event_time=failed_fields["latest_failure_utc"],
        )
        marker_entry = log_entry(
            text_log=marker_line,
            labels=labels,
            log_id="runtime-marker",
            event_time=marker_fields["timestamp_utc"],
        )
        recovered_entry = log_entry(
            text_log=recovered_line,
            labels=labels,
            log_id="runtime-recovered",
            event_time=recovery_time,
        )
        accepted_entry = log_entry(
            text_log=accepted_line,
            labels=labels,
            log_id="runtime-solutions",
            event_time=accepted_time,
        )

        with tempfile.TemporaryDirectory() as directory:
            ledger_path = Path(directory) / "runtime-recovery.sqlite"
            first_ledger = SQLiteAlertLedger(ledger_path)
            first, _, first_ledger = make_enricher(
                [failed_entry, marker_entry, recovered_entry], ledger=first_ledger
            )
            first_result = first.run_once(end_time_utc=recovery_time)
            self.assertEqual(first_result.prepared_count, 1)
            self.assertEqual(
                [row["payload"]["event_type"] for row in first_ledger.list_outbox()],
                ["POOL_CONNECTION_FAILED"],
            )
            first_ledger.close()

            reopened = SQLiteAlertLedger(ledger_path)
            second_entries = [marker_entry, recovered_entry, accepted_entry]
            second, _, reopened = make_enricher(second_entries, ledger=reopened)
            second_result = second.run_once(end_time_utc=accepted_time)
            self.assertEqual(second_result.prepared_count, 1)
            recovery_row = next(
                row for row in reopened.list_outbox()
                if row["payload"]["event_type"] == "POOL_CONNECTION_RECOVERED"
            )
            self.assertIn("Machine ID: runtime-machine", recovery_row["message_text"])
            self.assertIn("Instance ID: runtime-instance", recovery_row["message_text"])
            self.assertIn("Container Group: fl4shminer-2", recovery_row["message_text"])

            replay, _, _ = make_enricher(second_entries, ledger=reopened)
            replay_result = replay.run_once(end_time_utc=accepted_time)
            self.assertEqual(replay_result.prepared_count, 0)
            self.assertEqual(reopened.alert_count(), 2)
            reopened.close()

    def test_recovery_signal_before_failure_or_from_another_machine_is_rejected(self):
        labels_a = provider_labels("machine-a", "instance-a")
        labels_b = provider_labels("machine-b", "instance-b")
        recovery = log_entry(
            text_log=pool_monitor_line("POOL_CONNECTION_RECOVERED", recovered_at="2026-10-13T12:00:30Z"),
            labels=labels_a, log_id="recovered", event_time="2026-10-13T12:00:30Z",
        )
        old_accepted = log_entry(
            text_log="Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, stale=0",
            labels=labels_a, log_id="old-accepted", event_time="2026-10-13T11:59:59Z",
        )
        other_accepted = log_entry(
            text_log="Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, stale=0",
            labels=labels_b, log_id="other-accepted", event_time="2026-10-13T12:00:20Z",
        )
        for evidence in ([old_accepted, recovery], [other_accepted, recovery]):
            with self.subTest(evidence=evidence[0]["log_id"]):
                enricher, _, ledger = make_enricher(evidence)
                result = enricher.run_once(end_time_utc=END_TIME)
                self.assertEqual(result.prepared_count, 0)
                self.assertEqual(ledger.alert_count(), 0)
                ledger.close()

    def test_recovery_from_a_new_monitor_session_cannot_close_old_episode(self):
        labels = provider_labels("session-machine", "session-instance", "fl4shminer-4")
        failed = log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_FAILED", session_id=POOL_SESSION_ID,
            ),
            labels=labels, log_id="old-session-failed", event_time="2026-10-13T12:00:00Z",
        )
        new_session = "99999999-9999-4999-8999-999999999999"
        accepted = log_entry(
            text_log="Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, 0 stale",
            labels=labels, log_id="new-session-accepted", event_time="2026-10-13T12:00:20Z",
        )
        recovery = log_entry(
            text_log=pool_monitor_line(
                "POOL_CONNECTION_RECOVERED", session_id=new_session,
                recovered_at="2026-10-13T12:00:30Z",
            ),
            labels=labels, log_id="new-session-recovery", event_time="2026-10-13T12:00:30Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session-ledger.sqlite"
            ledger = SQLiteAlertLedger(path)
            first, _, ledger = make_enricher([failed], ledger=ledger)
            self.assertEqual(first.run_once(end_time_utc="2026-10-13T12:00:10Z").prepared_count, 1)
            second, _, ledger = make_enricher([accepted, recovery], ledger=ledger)
            self.assertEqual(second.run_once(end_time_utc="2026-10-13T12:00:40Z").prepared_count, 0)
            self.assertEqual([row["payload"]["event_type"] for row in ledger.list_outbox()], [
                "POOL_CONNECTION_FAILED",
            ])
            ledger.close()

    def test_recovery_with_valid_solution_but_no_committed_episode_is_not_notified(self):
        entries = [
            log_entry(
                text_log="Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, 0 stale",
                log_id="accepted", event_time="2026-10-13T12:00:20Z",
            ),
            log_entry(
                text_log=pool_monitor_line("POOL_CONNECTION_RECOVERED", recovered_at="2026-10-13T12:00:30Z"),
                log_id="orphan-recovery", event_time="2026-10-13T12:00:30Z",
            ),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.recognized_alerts, 0)
        self.assertEqual(result.prepared_count, 0)
        self.assertEqual(ledger.alert_count(), 0)
        ledger.close()

    def test_no_floor_and_config_invalid_warnings_deduplicate_per_provider_resource(self):
        no_floor = (
            "FL4SH_MONITOR state=NO_FLOOR_CONFIGURED device=fl4shminer_device:1 "
            "gpu_key=RTX_5070_LAPTOP floor=unknown floor_ths=unknown "
            "floor_source=UNCONFIGURED observed=99 bad_windows=0/2 actions_performed=false"
        )
        config_invalid = "FL4SH_MONITOR configuration invalid: INVALID_GPU_FLOORS_JSON"
        entries = [
            log_entry(text_log=no_floor, log_id="nofloor-a", event_time=EVENT_TIME),
            log_entry(text_log=no_floor.replace("observed=99", "observed=98"), log_id="nofloor-b", event_time="2026-10-13T12:00:10Z"),
            log_entry(text_log=config_invalid, log_id="config-a", event_time=EVENT_TIME),
            log_entry(text_log=config_invalid, log_id="config-b", event_time="2026-10-13T12:00:10Z"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.recognized_alerts, 4)
        self.assertEqual(result.prepared_count, 2)
        self.assertEqual({item["payload"]["event_type"] for item in ledger.list_outbox()}, {
            "NO_FLOOR_CONFIGURED", "MONITOR_CONFIGURATION_INVALID",
        })
        messages = {item["payload"]["event_type"]: item["message_text"] for item in ledger.list_outbox()}
        self.assertIn("Floor: UNKNOWN", messages["NO_FLOOR_CONFIGURED"])
        self.assertIn("Suggestion: CHECK_GPU_FLOOR_CONFIG", messages["NO_FLOOR_CONFIGURED"])
        self.assertIn("Reason: INVALID_GPU_FLOORS_JSON", messages["MONITOR_CONFIGURATION_INVALID"])
        ledger.close()

    def test_config_restart_loop_dedup_is_bounded_to_five_minute_cooldown(self):
        line = "FL4SH_MONITOR configuration invalid: INVALID_GPU_FLOORS_JSON"
        entries = [
            log_entry(text_log=line, log_id="config-first", event_time="2026-10-13T12:00:00Z"),
            log_entry(text_log=line, log_id="config-overlap", event_time="2026-10-13T12:00:10Z"),
            log_entry(text_log=line, log_id="config-rearmed", event_time="2026-10-13T12:05:01Z"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc="2026-10-13T12:06:00Z")
        alerts = [item for item in ledger.list_outbox()
                  if item["payload"]["event_type"] == "MONITOR_CONFIGURATION_INVALID"]
        self.assertEqual(result.recognized_alerts, 3)
        self.assertEqual(result.prepared_count, 2)
        self.assertEqual(
            sorted(item["payload"]["event_time_utc"] for item in alerts),
            sorted(("2026-10-13T12:00:00.000000Z", "2026-10-13T12:05:01.000000Z")),
        )
        ledger.close()

    def test_no_floor_warning_rearms_when_effective_policy_hash_changes(self):
        template = (
            "FL4SH_MONITOR state=NO_FLOOR_CONFIGURED device=fl4shminer_device:1 "
            "gpu_key=RTX_5070_TI floor=unknown floor_ths=unknown "
            "floor_source=UNCONFIGURED observed=99 bad_windows=0/2 "
            "actions_performed=false policy_hash={}"
        )
        entries = [
            log_entry(text_log=template.format("a" * 64), log_id="no-floor-policy-a"),
            log_entry(text_log=template.format("b" * 64), log_id="no-floor-policy-b",
                      event_time="2026-10-13T12:00:10Z"),
        ]
        enricher, _, ledger = make_enricher(entries)
        enricher.run_once(end_time_utc=END_TIME)
        alerts = [item for item in ledger.list_outbox()
                  if item["payload"]["event_type"] == "NO_FLOOR_CONFIGURED"]
        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            {item["payload"]["event_fields"]["policy_hash"] for item in alerts},
            {"a" * 64, "b" * 64},
        )
        ledger.close()

    def test_realert_markers_correlate_by_episode_and_sequence(self):
        episode = "55555555-5555-4555-8555-555555555555"
        first_id = "66666666-6666-4666-8666-666666666666"
        second_id = "77777777-7777-4777-8777-777777777777"
        entries = [
            log_entry(text_log=reallocation_line(episode_id=episode, alert_sequence=1), log_id="alert-1"),
            log_entry(
                text_log=(f"FL4SH_MONITOR state=TELEGRAM_ALERT alert_id={first_id} "
                          f"event=REALLOCATE_RECOMMENDED episode_id={episode} alert_sequence=1 actions_performed=false"),
                log_id="marker-1", event_time="2026-10-13T12:00:05Z",
            ),
            log_entry(
                text_log=reallocation_line(episode_id=episode, alert_sequence=2), log_id="alert-2",
                event_time="2026-10-13T12:00:20Z",
            ),
            log_entry(
                text_log=(f"FL4SH_MONITOR state=TELEGRAM_ALERT alert_id={second_id} "
                          f"event=REALLOCATE_RECOMMENDED episode_id={episode} alert_sequence=2 actions_performed=false"),
                log_id="marker-2", event_time="2026-10-13T12:00:25Z",
            ),
        ]
        enricher, _, ledger = make_enricher(entries)
        enricher.run_once(end_time_utc=END_TIME)
        alerts = [item for item in ledger.list_outbox() if item["payload"]["event_type"] == "REALLOCATE_RECOMMENDED"]
        self.assertEqual(len(alerts), 2)
        self.assertEqual({item["payload"]["alert_id"] for item in alerts}, {first_id, second_id})
        self.assertTrue(all("Degradation episode:" in item["message_text"] for item in alerts))
        sequence_one = next(item for item in alerts if item["payload"]["event_fields"]["alert_sequence"] == 1)
        sequence_two = next(item for item in alerts if item["payload"]["event_fields"]["alert_sequence"] == 2)
        self.assertIn("Notification reason: INITIAL_THRESHOLD_CROSSING", sequence_one["message_text"])
        self.assertIn("Notification reason: WORSENED", sequence_two["message_text"])
        self.assertIn("Previous alert mean: 104 TH/s", sequence_two["message_text"])
        self.assertIn("Deterioration since previous alert: 5 TH/s", sequence_two["message_text"])
        for item in alerts:
            self.assertNotIn("Alert reason:", item["message_text"])
            self.assertNotIn("Deterioration: ", item["message_text"])
        ledger.close()

    def test_startup_guard_alerts_after_both_provider_events_and_grace(self):
        entries = [
            lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", log_id="running"),
            lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", log_id="ready"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:41Z")
        self.assertEqual(result.prepared_count, 1)
        alert = ledger.list_outbox()[0]
        self.assertEqual(alert["payload"]["event_type"], "RUNNING_READY_BUT_MINER_NOT_STARTED")
        self.assertTrue(alert["message_text"].startswith("🚨 RUNNING_READY_BUT_MINER_NOT_STARTED"))
        self.assertEqual(alert["payload"]["identity"]["machine_id"], "machine-1")
        self.assertEqual(alert["payload"]["identity"]["instance_id"], "instance-1")
        self.assertEqual(alert["payload"]["identity"]["container_group_name"], "fl4shminer")
        self.assertIn("Elapsed since Ready: 90s", alert["message_text"])
        self.assertEqual(alert["payload"]["event_fields"]["provider_state"], "Running / Ready")
        self.assertFalse(alert["payload"]["event_fields"]["miner_started"])
        self.assertFalse(alert["payload"]["event_fields"]["gpu_detected"])
        self.assertEqual(alert["payload"]["event_fields"]["hashrate_samples"], 0)
        self.assertEqual(alert["payload"]["event_fields"]["elapsed_since_ready_seconds"], 90)
        self.assertEqual(alert["payload"]["event_fields"]["recommendation"], "REALLOCATE")
        self.assertIn("Provider state: Running / Ready", alert["message_text"])
        self.assertIn("Miner started: false", alert["message_text"])
        self.assertIn("GPU detected: false", alert["message_text"])
        self.assertIn("Hashrate samples: 0", alert["message_text"])
        self.assertIn("Elapsed since Ready: 90s", alert["message_text"])
        self.assertIn("Recommendation: REALLOCATE", alert["message_text"])
        self.assertIn("Actions performed: false", alert["message_text"])
        state = next(iter(ledger.get_startup_states().values()))
        self.assertEqual(state["status"], "RUNNING_READY_BUT_MINER_NOT_STARTED")
        ledger.close()

    def test_same_timestamp_running_then_ready_alerts_once_after_grace(self):
        event_time = "2026-10-13T12:00:00Z"
        entries = [
            lifecycle_entry("running", event_time=event_time, log_id="running-first"),
            lifecycle_entry("ready", event_time=event_time, log_id="ready-second"),
        ]
        events, _states = run_startup_guard(entries, end_time_utc="2026-10-13T12:01:31Z")
        self.assertEqual([event["event_type"] for event in events], [
            "RUNNING_READY_BUT_MINER_NOT_STARTED",
        ])
        self.assertEqual(events[0]["event_fields"]["running_time_utc"],
                         "2026-10-13T12:00:00.000000Z")
        self.assertEqual(events[0]["event_fields"]["ready_time_utc"],
                         "2026-10-13T12:00:00.000000Z")

    def test_same_timestamp_ready_then_running_alerts_once_after_grace(self):
        event_time = "2026-10-13T12:00:00Z"
        entries = [
            lifecycle_entry("ready", event_time=event_time, log_id="ready-first"),
            lifecycle_entry("running", event_time=event_time, log_id="running-second"),
        ]
        events, _states = run_startup_guard(entries, end_time_utc="2026-10-13T12:01:31Z")
        self.assertEqual([event["event_type"] for event in events], [
            "RUNNING_READY_BUT_MINER_NOT_STARTED",
        ])
        self.assertEqual(events[0]["event_fields"]["running_time_utc"],
                         "2026-10-13T12:00:00.000000Z")
        self.assertEqual(events[0]["event_fields"]["ready_time_utc"],
                         "2026-10-13T12:00:00.000000Z")

    def test_engine_hash_sort_ready_first_keeps_same_instant_lifecycle_and_alerts_once(self):
        running, ready = same_time_running_ready_pair_with_ready_hash_first()
        normalized_running = normalize_log_entry(running)
        normalized_ready = normalize_log_entry(ready)
        self.assertEqual(normalized_running.event_time_utc, normalized_ready.event_time_utc)
        self.assertLess(normalized_ready.evidence_sha256, normalized_running.evidence_sha256)

        enricher, _, ledger = make_enricher([running, ready])
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:31Z")
        alerts = [item for item in ledger.list_outbox()
                  if item["payload"]["event_type"] == "RUNNING_READY_BUT_MINER_NOT_STARTED"]
        self.assertEqual(result.prepared_count, 1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["payload"]["identity"]["machine_id"], "machine-1")
        ledger.close()

    def test_ready_before_running_on_prior_page_is_retained_for_compatible_timestamp(self):
        event_time = "2026-10-13T12:00:00Z"
        ready_events, ready_states = run_startup_guard(
            [lifecycle_entry("ready", event_time=event_time, log_id="ready-prior-page")],
            end_time_utc="2026-10-13T12:00:05Z",
        )
        self.assertEqual(ready_events, [])
        self.assertEqual(next(iter(ready_states.values()))["ready_time_utc"],
                         "2026-10-13T12:00:00.000000Z")

        running_events, _states = run_startup_guard(
            [lifecycle_entry("running", event_time=event_time, log_id="running-next-page")],
            prior_states=ready_states,
            end_time_utc="2026-10-13T12:01:31Z",
        )
        self.assertEqual([event["event_type"] for event in running_events], [
            "RUNNING_READY_BUT_MINER_NOT_STARTED",
        ])

    def test_same_timestamp_running_ready_progress_suppresses_timeout_in_both_orders(self):
        event_time = "2026-10-13T12:00:00Z"
        running = lifecycle_entry("running", event_time=event_time, log_id="running")
        ready = lifecycle_entry("ready", event_time=event_time, log_id="ready")
        progress = lifecycle_entry(
            "hashrate", event_time="2026-10-13T12:01:00Z", log_id="progress-before-deadline",
        )
        for lifecycle in ((running, ready), (ready, running)):
            with self.subTest(first=lifecycle[0]["fixture_lifecycle_observation"]["event"]):
                events, states = run_startup_guard(
                    [*lifecycle, progress], end_time_utc="2026-10-13T12:01:31Z",
                )
                self.assertEqual(events, [])
                state = next(iter(states.values()))
                self.assertEqual(state["progress_signal"], "DEVICE_HASHRATE")
                self.assertEqual(state["status"], "STARTUP_PROGRESS_OBSERVED")

    def test_newer_running_resets_prior_ready_and_progress_generation_evidence(self):
        t0 = "2026-10-13T12:00:00Z"
        first_entries = [
            lifecycle_entry("running", event_time=t0, log_id="old-running"),
            lifecycle_entry("ready", event_time=t0, log_id="old-ready"),
            lifecycle_entry("hashrate", event_time="2026-10-13T12:00:30Z", log_id="old-progress"),
        ]
        first_events, first_states = run_startup_guard(
            first_entries, end_time_utc="2026-10-13T12:00:40Z",
        )
        self.assertEqual(first_events, [])
        first_state = next(iter(first_states.values()))
        first_generation_id = first_state["generation_id"]
        self.assertIsNotNone(first_state["ready_time_utc"])
        self.assertIsNotNone(first_state["progress_time_utc"])

        new_running_time = "2026-10-13T12:01:00Z"
        _events, after_running = run_startup_guard(
            [lifecycle_entry("running", event_time=new_running_time, log_id="new-running")],
            prior_states=first_states,
            end_time_utc="2026-10-13T12:01:05Z",
        )
        state_after_running = next(iter(after_running.values()))
        self.assertNotEqual(state_after_running["generation_id"], first_generation_id)
        self.assertIsNone(state_after_running["ready_time_utc"])
        self.assertIsNone(state_after_running["progress_time_utc"])

        timeout_events, final_states = run_startup_guard(
            [lifecycle_entry("ready", event_time=new_running_time, log_id="new-ready")],
            prior_states=after_running,
            end_time_utc="2026-10-13T12:02:31Z",
        )
        self.assertEqual([event["event_type"] for event in timeout_events], [
            "RUNNING_READY_BUT_MINER_NOT_STARTED",
        ])
        self.assertIsNone(next(iter(final_states.values()))["progress_time_utc"])

    def test_late_older_running_in_overlap_cannot_roll_back_sqlite_generation_or_realert(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "late-running.sqlite3"
            first_ledger = SQLiteAlertLedger(db_path)
            current_running_time = "2026-10-13T12:01:00Z"
            first, _, _ = make_enricher(
                [
                    lifecycle_entry("running", event_time=current_running_time, log_id="current-running"),
                    lifecycle_entry("ready", event_time=current_running_time, log_id="current-ready"),
                ],
                ledger=first_ledger,
            )
            first_result = first.run_once(end_time_utc="2026-10-13T12:02:31Z")
            self.assertEqual(first_result.prepared_count, 1)
            self.assertEqual(first_ledger.alert_count(), 1)
            original_state = next(iter(first_ledger.get_startup_states().values()))
            original_generation = original_state["generation_id"]
            self.assertEqual(original_state["running_time_utc"], "2026-10-13T12:01:00.000000Z")
            first_ledger.close()

            # Reopen SQLite to exercise durable state. The second bounded
            # query overlaps the cursor and receives a delayed, older Running
            # record for the same fully identified provider resource.
            reopened = SQLiteAlertLedger(db_path)
            second, transport, _ = make_enricher(
                [lifecycle_entry(
                    "running", event_time="2026-10-13T12:00:55Z", log_id="late-old-running",
                )],
                ledger=reopened,
            )
            second_result = second.run_once(end_time_utc="2026-10-13T12:02:40Z")

            self.assertLessEqual(
                transport.page_requests[0].start_time_utc,
                "2026-10-13T12:00:55.000000Z",
            )
            self.assertEqual(second_result.prepared_count, 0)
            self.assertEqual(second_result.recognized_alerts, 0)
            self.assertEqual(reopened.alert_count(), 1)
            self.assertEqual(len(reopened.list_outbox()), 1)
            final_state = next(iter(reopened.get_startup_states().values()))
            self.assertEqual(final_state["generation_id"], original_generation)
            self.assertEqual(final_state["running_time_utc"], "2026-10-13T12:01:00.000000Z")
            self.assertEqual(final_state["ready_time_utc"], "2026-10-13T12:01:00.000000Z")
            self.assertEqual(final_state["status"], "RUNNING_READY_BUT_MINER_NOT_STARTED")
            reopened.close()

    def test_healthy_gpu_logs_do_not_cross_attribute_another_machine_pool_failure(self):
        healthy_labels = provider_labels("healthy-machine", "healthy-instance", "fl4shminer")
        failing_labels = provider_labels("failing-machine", "failing-instance", "fl4shminer-3")
        entries = [
            log_entry(
                text_log="Device [1] hashRate: 217.81 TH/s, stale: 0/0 (0.0%), warm: 0",
                labels=healthy_labels, log_id="healthy-hashrate",
            ),
            log_entry(
                text_log="Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, 2 accepted",
                labels=healthy_labels, log_id="healthy-share",
                event_time="2026-10-13T12:00:05Z",
            ),
            log_entry(
                text_log=("2026/10/13 12:00:30 Pool connection failed: "
                          "mining.authorize response timeout; reconnecting; retrying in 10s"),
                labels=failing_labels, log_id="failing-pool",
                event_time="2026-10-13T12:00:30Z",
            ),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.recognized_alerts, 1)
        self.assertEqual(result.prepared_count, 1)
        alert = ledger.list_outbox()[0]
        self.assertEqual(alert["payload"]["event_type"], "POOL_CONNECTION_FAILED")
        self.assertEqual(alert["payload"]["identity"]["machine_id"], "failing-machine")
        self.assertEqual(alert["payload"]["identity"]["instance_id"], "failing-instance")
        self.assertEqual(alert["payload"]["identity"]["container_group_name"], "fl4shminer-3")
        self.assertNotIn("healthy-machine", alert["message_text"])
        self.assertNotIn("healthy-instance", alert["message_text"])
        self.assertIn("Machine ID: failing-machine", alert["message_text"])
        ledger.close()

    def test_two_machine_pool_episodes_stay_independent_and_provider_identity_is_exact(self):
        shared_episode = "77777777-7777-4777-8777-777777777777"
        entries = [
            log_entry(
                text_log=pool_monitor_line(
                    "POOL_CONNECTION_FAILED", episode_id=shared_episode,
                    session_id="88888888-8888-4888-8888-888888888888",
                ),
                labels=provider_labels("machine-a", "instance-a", "fl4shminer"),
                log_id="machine-a-pool", event_time="2026-10-13T12:00:01Z",
            ),
            log_entry(
                text_log=pool_monitor_line(
                    "POOL_CONNECTION_FAILED", episode_id=shared_episode,
                    session_id="88888888-8888-4888-8888-888888888888",
                ),
                labels=provider_labels("machine-b", "instance-b", "fl4shminer-3"),
                log_id="machine-b-pool", event_time="2026-10-13T12:00:02Z",
            ),
            log_entry(
                text_log="Solutions accepted: 1-NVIDIA GeForce RTX 5080 Laptop GPU, 0 stale",
                labels=provider_labels("machine-a", "instance-a", "fl4shminer"),
                log_id="machine-a-accepted", event_time="2026-10-13T12:00:03Z",
            ),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc=END_TIME)
        outbox = ledger.list_outbox()
        self.assertEqual(result.prepared_count, 2)
        self.assertEqual(
            {row["payload"]["identity"]["machine_id"] for row in outbox},
            {"machine-a", "machine-b"},
        )
        self.assertEqual(
            {row["payload"]["identity"]["instance_id"] for row in outbox},
            {"instance-a", "instance-b"},
        )
        self.assertEqual(
            {row["payload"]["identity"]["container_group_name"] for row in outbox},
            {"fl4shminer", "fl4shminer-3"},
        )
        for row in outbox:
            self.assertIn(f"Machine ID: {row['payload']['identity']['machine_id']}", row["message_text"])
        ledger.close()

    def test_startup_guard_does_not_alert_before_deadline_or_when_progress_arrives(self):
        base = [
            lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", log_id="running"),
            lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", log_id="ready"),
        ]
        for signal in ("config", "gpu", "initialized", "hashrate"):
            with self.subTest(signal=signal):
                entries = [*base, lifecycle_entry(
                    signal, event_time="2026-10-13T12:01:39Z", log_id=f"progress-{signal}"
                )]
                enricher, _, ledger = make_enricher(entries)
                result = enricher.run_once(end_time_utc="2026-10-13T12:02:00Z")
                self.assertEqual(result.prepared_count, 0)
                self.assertEqual(ledger.list_outbox(), [])
                ledger.close()

        enricher, _, ledger = make_enricher(base)
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:39Z")
        self.assertEqual(result.prepared_count, 0)
        ledger.close()

    def test_startup_progress_from_another_machine_does_not_satisfy_guard(self):
        entries = [
            lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", labels=provider_labels("machine-a", "instance-a"), log_id="running-a"),
            lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", labels=provider_labels("machine-a", "instance-a"), log_id="ready-a"),
            lifecycle_entry("hashrate", event_time="2026-10-13T12:00:20Z", labels=provider_labels("machine-b", "instance-b"), log_id="rate-b"),
        ]
        enricher, _, ledger = make_enricher(entries)
        enricher.run_once(end_time_utc="2026-10-13T12:01:41Z")
        alerts = ledger.list_outbox()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["payload"]["identity"]["machine_id"], "machine-a")
        ledger.close()

    def test_startup_guard_identity_missing_or_conflicting_stays_unverified(self):
        label_cases = [
            ({"container_group_name": "fl4shminer"}, "UNKNOWN"),
            ({**provider_labels(), "machine id": "machine-other"}, "CONFLICTING"),
        ]
        for labels, expected in label_cases:
            with self.subTest(expected=expected):
                entries = [
                    lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", labels=labels, log_id="running"),
                    lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", labels=labels, log_id="ready"),
                ]
                enricher, _, ledger = make_enricher(entries)
                result = enricher.run_once(end_time_utc="2026-10-13T12:01:41Z")
                self.assertEqual(result.prepared_count, 0)
                self.assertEqual(ledger.list_outbox(), [])
                persisted = repr(ledger.get_startup_states())
                self.assertNotIn("resource_labels", persisted)
                ledger.close()

    def test_two_resources_with_shared_partial_group_labels_are_not_joined(self):
        running_labels = {"container_group_name": "fl4shminer", "machine_id": "machine-a"}
        ready_labels = {"container_group_name": "fl4shminer", "instance_id": "instance-b"}
        entries = [
            lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", labels=running_labels, log_id="partial-running-a"),
            lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", labels=ready_labels, log_id="partial-ready-b"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:41Z")
        self.assertEqual(result.prepared_count, 0)
        self.assertEqual(ledger.list_outbox(), [])
        self.assertEqual(ledger.get_startup_states(), {})
        ledger.close()

    def test_miner_spoofed_running_ready_text_does_not_trigger_startup_alert(self):
        entries = [
            log_entry(text_log="Instance Running", log_id="miner-running"),
            log_entry(text_log="Instance Ready (Readiness Probe Passed)", log_id="miner-ready", event_time="2026-10-13T12:00:10Z"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:41Z")
        self.assertEqual(result.prepared_count, 0)
        self.assertEqual(ledger.list_outbox(), [])
        self.assertEqual(ledger.get_startup_states(), {})
        ledger.close()

    def test_legacy_text_lifecycle_state_is_discarded_after_provenance_upgrade(self):
        identity = normalize_log_entry(lifecycle_entry(
            "ready", event_time="2026-10-13T12:00:10Z", log_id="ready"
        )).identity.public_fields()
        legacy_key = "d" * 64
        legacy_state = {
            "resource_type": "salad.container_group_instance",
            "identity": identity,
            "running_time_utc": "2026-10-13T12:00:00.000000Z",
            "ready_time_utc": "2026-10-13T12:00:10.000000Z",
            "running_evidence_sha256": "a" * 64,
            "ready_evidence_sha256": "b" * 64,
            "generation_id": "c" * 64,
            "progress_time_utc": None,
            "progress_signal": None,
            "status": "OBSERVING",
            "alerted_at_utc": None,
            "resolved_at_utc": None,
            "last_event_time_utc": "2026-10-13T12:00:10.000000Z",
            "running_source": "text_log",
            "ready_source": "text_log",
            "progress_source": None,
        }

        events, states = StartupGuard().process(
            [normalize_log_entry(lifecycle_entry(
                "ready", event_time="2026-10-13T12:00:10Z", log_id="ready"
            ))],
            prior_states={legacy_key: legacy_state},
            end_time_utc="2026-10-13T12:02:00Z",
        )

        self.assertEqual(events, [])
        self.assertNotIn(legacy_key, states)
        self.assertTrue(all(state.get("running_time_utc") is None for state in states.values()))

    def test_startup_alert_dedup_survives_restart_and_late_progress_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "startup.sqlite3"
            store = SQLiteAlertLedger(db_path)
            lifecycle = [
                lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", log_id="running"),
                lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", log_id="ready"),
            ]
            first, _, _ = make_enricher(lifecycle, ledger=store)
            initial = first.run_once(end_time_utc="2026-10-13T12:01:41Z")
            self.assertEqual(initial.prepared_count, 1)
            store.close()

            reopened = SQLiteAlertLedger(db_path)
            late_progress = lifecycle_entry(
                "hashrate", event_time="2026-10-13T12:01:50Z", log_id="late-progress"
            )
            second, _, _ = make_enricher([*lifecycle, late_progress], ledger=reopened)
            repeated = second.run_once(end_time_utc="2026-10-13T12:02:00Z")
            self.assertEqual(repeated.prepared_count, 1)
            outbox = reopened.list_outbox()
            self.assertEqual({item["payload"]["event_type"] for item in outbox}, {
                "RUNNING_READY_BUT_MINER_NOT_STARTED", "MINER_STARTUP_RECOVERED",
            })
            state = next(iter(reopened.get_startup_states().values()))
            self.assertEqual(state["status"], "MINER_STARTUP_RECOVERED")
            reopened.close()

    def test_delayed_pre_deadline_progress_resolves_an_already_sent_startup_alert(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "startup-delayed-progress.sqlite3"
            store = SQLiteAlertLedger(db_path)
            lifecycle = [
                lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", log_id="running"),
                lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", log_id="ready"),
            ]
            first, _, _ = make_enricher(lifecycle, ledger=store)
            initial = first.run_once(end_time_utc="2026-10-13T12:01:41Z")
            self.assertEqual(initial.prepared_count, 1)
            store.close()

            reopened = SQLiteAlertLedger(db_path)
            delayed_progress = lifecycle_entry(
                "hashrate", event_time="2026-10-13T12:01:30Z", log_id="delayed-progress"
            )
            second, _, _ = make_enricher([*lifecycle, delayed_progress], ledger=reopened)
            resolved = second.run_once(end_time_utc="2026-10-13T12:02:00Z")
            self.assertEqual(resolved.prepared_count, 1)
            recovered = next(
                item for item in reopened.list_outbox()
                if item["payload"]["event_type"] == "MINER_STARTUP_RECOVERED"
            )
            self.assertEqual(recovered["payload"]["event_time_utc"], "2026-10-13T12:02:00.000000Z")
            self.assertEqual(
                recovered["payload"]["event_fields"]["progress_event_time_utc"],
                "2026-10-13T12:01:30.000000Z",
            )
            state = next(iter(reopened.get_startup_states().values()))
            self.assertEqual(state["status"], "MINER_STARTUP_RECOVERED")
            self.assertEqual(state["resolved_at_utc"], "2026-10-13T12:02:00.000000Z")
            reopened.close()

    def test_progress_after_grace_in_same_page_emits_timeout_snapshot_then_recovery(self):
        entries = [
            lifecycle_entry("running", event_time="2026-10-13T12:00:00Z", log_id="running"),
            lifecycle_entry("ready", event_time="2026-10-13T12:00:10Z", log_id="ready"),
            lifecycle_entry("hashrate", event_time="2026-10-13T12:01:50Z", log_id="late-rate"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc="2026-10-13T12:02:00Z")
        outbox = ledger.list_outbox()
        by_type = {item["payload"]["event_type"]: item for item in outbox}
        self.assertEqual(result.prepared_count, 2)
        self.assertFalse(by_type["RUNNING_READY_BUT_MINER_NOT_STARTED"]["payload"]["event_fields"]["miner_started"])
        self.assertEqual(by_type["RUNNING_READY_BUT_MINER_NOT_STARTED"]["payload"]["event_fields"]["hashrate_samples"], 0)
        self.assertEqual(by_type["MINER_STARTUP_RECOVERED"]["payload"]["event_fields"]["progress_signal"], "DEVICE_HASHRATE")
        self.assertEqual(
            by_type["MINER_STARTUP_RECOVERED"]["payload"]["event_fields"]["progress_event_time_utc"],
            "2026-10-13T12:01:50.000000Z",
        )
        ledger.close()

    def test_similar_pool_errors_do_not_notify(self):
        lines = (
            "Pool connection failed: connection refused",
            "mining.authorize rejected",
            "arbitrary response timeout text",
        )
        enricher, _, ledger = make_enricher([log_entry(text_log=line, log_id=f"log-{i}") for i, line in enumerate(lines)])
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.recognized_alerts, 0)
        self.assertEqual(ledger.alert_count(), 0)
        ledger.close()

    def test_same_alert_type_and_id_on_two_machines_stays_distinct(self):
        entries = [
            log_entry(text_log=reallocation_line(alert_id=ALERT_ID), labels=provider_labels("machine-a", "instance-a"), log_id="same-alert"),
            log_entry(text_log=reallocation_line(alert_id=ALERT_ID), labels=provider_labels("machine-b", "instance-b"), log_id="same-alert"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc=END_TIME)
        outbox = ledger.list_outbox()
        self.assertEqual(result.prepared_count, 2)
        self.assertEqual({item["payload"]["identity"]["machine_id"] for item in outbox}, {"machine-a", "machine-b"})
        self.assertEqual(len({item["dedupe_key"] for item in outbox}), 2)
        self.assertTrue(all("Container Group: fl4shminer" in item["message_text"] for item in outbox))
        self.assertTrue(all(f"Alert ID: {ALERT_ID}" in item["message_text"] for item in outbox))
        ledger.close()

    def test_missing_or_conflicting_ids_are_not_claimed_in_message(self):
        entries = [
            log_entry(text_log=reallocation_line(), labels={"container_group_name": "fl4shminer"}, log_id="missing"),
            log_entry(text_log=reallocation_line(), labels={**provider_labels(), "machine id": "other"}, log_id="conflict"),
        ]
        enricher, _, ledger = make_enricher(entries)
        enricher.run_once(end_time_utc=END_TIME)
        outbox = ledger.list_outbox()
        self.assertEqual(len(outbox), 2)
        messages = [item["message_text"] for item in outbox]
        self.assertTrue(any("Identity status: UNKNOWN" in message for message in messages))
        self.assertTrue(any("Identity status: CONFLICTING" in message for message in messages))
        for message in messages:
            self.assertIn("Machine ID: UNKNOWN", message)
            self.assertIn("Instance ID: UNKNOWN", message)
        self.assertTrue(all("machine-1" not in message and "machine-other" not in message for message in messages))
        ledger.close()

    def test_ids_in_miner_text_are_not_identity_evidence(self):
        line = reallocation_line(gpu_raw="NVIDIA RTX 5080 machine_id=forged instance_id=forged")
        enricher, _, ledger = make_enricher([log_entry(text_log=line, labels={"container_group_name": "fl4shminer"})])
        enricher.run_once(end_time_utc=END_TIME)
        message = ledger.list_outbox()[0]["message_text"]
        self.assertIn("Identity status: UNKNOWN", message)
        self.assertIn("Machine ID: UNKNOWN", message)
        self.assertNotIn("forged", message)
        ledger.close()

    def test_alert_marker_correlates_only_with_same_provider_resource(self):
        line = reallocation_line()
        alert_id = "22222222-2222-4222-8222-222222222222"
        entries = [
            log_entry(text_log=line, labels=provider_labels("machine-a", "instance-a"), log_id="event"),
            log_entry(
                text_log=f"FL4SH_MONITOR state=TELEGRAM_ALERT alert_id={alert_id} "
                "event=REALLOCATE_RECOMMENDED actions_performed=false",
                labels=provider_labels("machine-a", "instance-a"), log_id="marker",
                event_time="2026-10-13T12:00:10Z",
            ),
        ]
        enricher, _, ledger = make_enricher(entries)
        enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(ledger.list_outbox()[0]["payload"]["alert_id"], alert_id)
        ledger.close()

    def test_duplicate_page_and_overlapping_window_prepare_one_notification(self):
        entry = log_entry(text_log=reallocation_line(), log_id="repeat")
        enricher, transport, ledger = make_enricher([entry])
        first = enricher.run_once(end_time_utc=END_TIME)
        second = enricher.run_once(end_time_utc=END_TIME)
        third = enricher.run_once(end_time_utc="2026-10-13T12:01:30Z")
        self.assertEqual(first.prepared_count, 1)
        self.assertEqual(second.prepared_count, 0)
        self.assertEqual(third.prepared_count, 0)
        self.assertEqual(ledger.alert_count(), 1)
        self.assertEqual(len(ledger.list_outbox()), 1)
        self.assertEqual(transport.organization_query_count, 3)
        ledger.close()

    def test_restart_uses_durable_cursor_and_dedup(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "alerts.sqlite3"
            ledger = SQLiteAlertLedger(db_path)
            entry = log_entry(text_log=reallocation_line(), log_id="restart")
            first, _, _ = make_enricher([entry], ledger=ledger)
            first_result = first.run_once(end_time_utc=END_TIME)
            durable_cursor = ledger.get_cursor()
            ledger.close()

            reopened = SQLiteAlertLedger(db_path)
            second, _, _ = make_enricher([entry], ledger=reopened)
            second_result = second.run_once(end_time_utc="2026-10-13T12:01:30Z")
            self.assertEqual(first_result.prepared_count, 1)
            self.assertEqual(second_result.prepared_count, 0)
            self.assertEqual(second_result.duplicate_count, 1)
            self.assertEqual(reopened.alert_count(), 1)
            self.assertGreaterEqual(reopened.get_cursor(), durable_cursor)
            reopened.close()

    def test_multi_hour_restart_catches_up_without_skipping_log_intervals(self):
        limits = QueryLimits(maximum_window_seconds=3_600, overlap_seconds=120)
        initial_cursor = "2026-10-13T12:00:00Z"
        requested_end = "2026-10-13T15:00:00Z"
        event_times = (
            "2026-10-13T12:30:00Z",
            "2026-10-13T13:30:00Z",
            "2026-10-13T14:30:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "catch-up.sqlite3"
            first_store = SQLiteAlertLedger(db_path)
            first_store.commit_cycle(
                [], cursor_time_utc=initial_cursor, committed_at_utc=initial_cursor,
            )
            first_store.close()

            # Reopening simulates a process restart after several hours offline.
            ledger = SQLiteAlertLedger(db_path)
            observed_requests = []
            results = []
            windows = [
                [log_entry(
                    text_log=reallocation_line(),
                    log_id=f"catch-up-{index}",
                    event_time=event_time,
                )]
                for index, event_time in enumerate(event_times)
            ]
            windows.append([])
            for entries in windows:
                enricher, transport, _ = make_enricher(
                    entries, ledger=ledger, limits=limits,
                )
                results.append(enricher.run_once(end_time_utc=requested_end))
                observed_requests.append(transport.page_requests[0])

            self.assertEqual(
                [(request.start_time_utc, request.end_time_utc) for request in observed_requests],
                [
                    ("2026-10-13T11:58:00.000000Z", "2026-10-13T12:58:00.000000Z"),
                    ("2026-10-13T12:56:00.000000Z", "2026-10-13T13:56:00.000000Z"),
                    ("2026-10-13T13:54:00.000000Z", "2026-10-13T14:54:00.000000Z"),
                    ("2026-10-13T14:52:00.000000Z", "2026-10-13T15:00:00.000000Z"),
                ],
            )
            self.assertEqual([result.prepared_count for result in results], [1, 1, 1, 0])
            self.assertEqual(ledger.alert_count(), 3)
            self.assertEqual(ledger.get_cursor(), "2026-10-13T15:00:00.000000Z")
            ledger.close()

    def test_late_alert_marker_enriches_existing_outbox_after_restart_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "late-marker.sqlite3"
            first_store = SQLiteAlertLedger(db_path)
            event = log_entry(text_log=reallocation_line(), log_id="late-marker-event")
            first, _, _ = make_enricher([event], ledger=first_store)
            initial = first.run_once(end_time_utc=END_TIME)
            self.assertEqual(initial.prepared_count, 1)
            self.assertIsNone(first_store.list_outbox()[0]["payload"]["alert_id"])
            first_store.close()

            reopened = SQLiteAlertLedger(db_path)
            late_id = "33333333-3333-4333-8333-333333333333"
            marker = log_entry(
                text_log=(
                    f"FL4SH_MONITOR state=TELEGRAM_ALERT alert_id={late_id} "
                    "event=REALLOCATE_RECOMMENDED actions_performed=false"
                ),
                labels=provider_labels(),
                log_id="late-marker-id",
                event_time="2026-10-13T12:00:10Z",
            )
            second, _, _ = make_enricher(
                [event, marker], ledger=reopened,
            )
            repeated = second.run_once(end_time_utc="2026-10-13T12:01:30Z")
            outbox = reopened.list_outbox()
            self.assertEqual(repeated.prepared_count, 0)
            self.assertEqual(repeated.duplicate_count, 1)
            self.assertEqual(reopened.alert_count(), 1)
            self.assertEqual(len(outbox), 1)
            self.assertEqual(outbox[0]["payload"]["alert_id"], late_id)
            self.assertIn(f"Alert ID: {late_id}", outbox[0]["message_text"])
            reopened.close()

    def test_hundred_synthetic_machines_use_one_organization_query(self):
        entries = []
        for index in range(100):
            machine = f"machine-{index:03d}"
            instance = f"instance-{index:03d}"
            alert_id = str(uuid.UUID(int=index + 1, version=4))
            entries.append(log_entry(
                text_log=reallocation_line(alert_id=alert_id),
                labels=provider_labels(machine, instance, f"fl4shminer-{index % 4 + 1}"),
                log_id=f"bulk-{index:03d}",
            ))
        enricher, transport, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.records_seen, 100)
        self.assertEqual(result.prepared_count, 100)
        self.assertEqual(transport.organization_query_count, 1)
        self.assertEqual(ledger.alert_count(), 100)
        self.assertTrue(all(item["payload"]["data_classification"] == DATA_CLASSIFICATION for item in ledger.list_outbox()))
        ledger.close()

    def test_incomplete_pagination_does_not_advance_cursor(self):
        entry = log_entry(text_log=reallocation_line())
        first_page = LogQueryPage((entry,), next_page_token="missing-page")
        enricher, _, ledger = make_enricher(
            [],
            pages=[first_page],
            limits=QueryLimits(page_size=1, maximum_pages=3),
        )
        with self.assertRaises(IncompleteFixtureQuery):
            enricher.run_once(end_time_utc=END_TIME)
        self.assertIsNone(ledger.get_cursor())
        self.assertEqual(ledger.alert_count(), 0)
        ledger.close()

    def test_credential_like_provider_data_is_rejected_without_persisting_or_echoing(self):
        secret = "synthetic-private-credential-971a"
        entry = log_entry(text_log=reallocation_line())
        entry["resource"]["labels"]["api_key"] = secret
        enricher, _, ledger = make_enricher([entry])
        with self.assertRaises(UnsafeQueryCycle) as caught:
            enricher.run_once(end_time_utc=END_TIME)
        self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(ledger.alert_count(), 0)
        self.assertEqual(ledger.list_outbox(), [])
        self.assertIsNone(ledger.get_cursor())
        ledger.close()

    def test_opaque_provider_label_is_preserved_in_memory_but_not_persisted_or_notified(self):
        opaque_value = "customer-record-opaque-2026-10-13-7cc68a"
        labels = provider_labels()
        labels["capture_note"] = opaque_value
        entry = log_entry(text_log=reallocation_line(), labels=labels)
        enricher, _, ledger = make_enricher([entry])
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.evidence[0].resource_labels["capture_note"], opaque_value)
        self.assertEqual(result.prepared_count, 1)
        outbox_text = repr(ledger.list_outbox())
        persisted_payloads = " ".join(
            row[0] for row in ledger._db.execute(
                "SELECT payload_json FROM log_alerts UNION ALL "
                "SELECT payload_json FROM log_alert_outbox"
            ).fetchall()
        )
        self.assertNotIn(opaque_value, outbox_text)
        self.assertNotIn(opaque_value, persisted_payloads)
        self.assertNotIn("resource_labels", outbox_text)
        ledger.close()

    def test_exact_read_log_query_route_is_the_only_post_classified(self):
        policy = LogQueryPolicy(ORG)
        self.assertEqual(policy.classify(method="POST", host="api.salad.com", port=443, path=policy.path), READ_LOG_QUERY)
        self.assertEqual(policy.classify(method="POST", host="api.salad.com", port=443, path=policy.path + "/reallocate"), DENIED)
        for mutation_path in (
            f"/organizations/{ORG}/projects/{PROJECT}/containers/fl4shminer/start",
            f"/organizations/{ORG}/projects/{PROJECT}/containers/fl4shminer/stop",
            f"/organizations/{ORG}/projects/{PROJECT}/containers/fl4shminer/instances/instance-1/reallocate",
        ):
            with self.subTest(mutation_path=mutation_path):
                self.assertEqual(policy.classify(method="POST", host="api.salad.com", port=443, path=mutation_path), DENIED)
        self.assertEqual(policy.classify(method="POST", host="example.com", port=443, path=policy.path), DENIED)
        self.assertEqual(policy.classify(method="GET", host="api.salad.com", port=443, path=policy.path), DENIED)
        self.assertEqual(policy.classify(method="POST", host="api.salad.com", port=80, path=policy.path), DENIED)
        for invalid_org in ("A1", "a", "org_name", "-org", "org-"):
            with self.subTest(invalid_org=invalid_org), self.assertRaises(ValueError):
                LogQueryPolicy(invalid_org)

    def test_ledger_cursor_is_durable_and_monotonic(self):
        ledger = SQLiteAlertLedger()
        ledger.commit_cycle([], cursor_time_utc=END_TIME, committed_at_utc=END_TIME)
        self.assertEqual(ledger.get_cursor(), "2026-10-13T12:01:00.000000Z")
        with self.assertRaisesRegex(ValueError, "cannot move backwards"):
            ledger.commit_cycle([], cursor_time_utc=EVENT_TIME, committed_at_utc=EVENT_TIME)
        self.assertEqual(ledger.get_cursor(), "2026-10-13T12:01:00.000000Z")
        ledger.close()

    def test_enricher_rejects_a_transport_that_is_not_the_offline_fixture(self):
        class PretendTransport:
            policy = LogQueryPolicy(ORG)

        ledger = SQLiteAlertLedger()
        with self.assertRaisesRegex(TypeError, "only FixtureLogQueryTransport"):
            LogAlertEnricher(
                approved_organization=ORG,
                transport=PretendTransport(),
                ledger=ledger,
            )
        ledger.close()

    def test_cuda_exact_fatal_and_same_instance_exit_prepare_one_sanitized_alert(self):
        fatal = cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal")
        stopped = cuda_exit_entry(event_time="2026-10-13T12:01:00Z", log_id="stopped")
        enricher, _, ledger = make_enricher([stopped, fatal])
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:00Z")
        self.assertEqual(result.recognized_alerts, 1)
        self.assertEqual(result.prepared_count, 1)
        outbox = ledger.list_outbox()
        self.assertEqual(len(outbox), 1)
        alert = outbox[0]
        self.assertEqual(alert["payload"]["event_type"], "CUDA_DRIVER_INCOMPATIBLE")
        self.assertEqual(alert["payload"]["identity"]["machine_id"], "machine-1")
        self.assertEqual(alert["payload"]["identity"]["instance_id"], "instance-1")
        self.assertEqual(alert["payload"]["identity"]["container_group_name"], "fl4shminer")
        fields = alert["payload"]["event_fields"]
        self.assertEqual(fields["reason"], "CUDA_DRIVER_VERSION_INSUFFICIENT")
        self.assertIs(fields["gpu_initialized"], False)
        self.assertEqual(fields["miner_exit_status"], 1)
        self.assertIs(fields["exit_status_confirmed"], True)
        self.assertEqual(fields["exit_status_event_time_utc"], "2026-10-13T12:01:00.000000Z")
        self.assertEqual(fields["recommendation"], "REALLOCATE")
        self.assertIs(fields["actions_performed"], False)
        for expected in (
            "🚨 CUDA_DRIVER_INCOMPATIBLE", "Machine ID: machine-1",
            "Instance ID (at detection): instance-1", "Container Group: fl4shminer",
            "Error: CUDA_DRIVER_VERSION_INSUFFICIENT", "GPU initialized: false",
            "Miner exit: 1", "Recommendation: REALLOCATE", "Actions performed: false",
        ):
            self.assertIn(expected, alert["message_text"])
        self.assertNotIn(CUDA_FATAL_LINE, alert["message_text"])
        self.assertNotIn("Current Instance ID", alert["message_text"])
        self.assertNotIn("RTX_", repr(alert["payload"]))
        ledger.close()

    def test_cuda_exit_competing_with_two_fatals_in_one_page_stays_unknown_and_audited(self):
        fatal_a = cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal-a")
        fatal_b = cuda_fatal_entry(event_time="2026-10-13T12:00:20Z", log_id="fatal-b")
        stopped = cuda_exit_entry(event_time="2026-10-13T12:00:40Z", log_id="stopped")
        fatal_hashes = {
            normalize_log_entry(fatal_a).evidence_sha256,
            normalize_log_entry(fatal_b).evidence_sha256,
        }
        exit_hash = normalize_log_entry(stopped).evidence_sha256
        enricher, _, ledger = make_enricher([fatal_b, stopped, fatal_a])

        enricher.run_once(end_time_utc="2026-10-13T12:01:00Z")

        outbox = ledger.list_outbox()
        self.assertEqual(len(outbox), 1)
        fields = outbox[0]["payload"]["event_fields"]
        self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
        self.assertIs(fields["exit_status_confirmed"], False)
        self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
        self.assertEqual(fields["exit_evidence_audit_sha256"], [exit_hash])
        self.assertEqual(fields["exit_candidate_fatal_sha256"], sorted(fatal_hashes))
        self.assertIn("Miner exit: UNKNOWN", outbox[0]["message_text"])
        ledger.close()

    def test_one_fatal_with_two_exits_in_same_page_stays_unknown(self):
        fatal = cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="single-fatal")
        exits = [
            cuda_exit_entry(event_time="2026-10-13T12:00:20Z", log_id="exit-a"),
            cuda_exit_entry(event_time="2026-10-13T12:00:30Z", log_id="exit-b"),
        ]
        exit_hashes = sorted(normalize_log_entry(entry).evidence_sha256 for entry in exits)
        fatal_hash = normalize_log_entry(fatal).evidence_sha256
        enricher, _, ledger = make_enricher([exits[1], fatal, exits[0]])

        enricher.run_once(end_time_utc="2026-10-13T12:01:00Z")

        alert = ledger.list_outbox()[0]
        fields = alert["payload"]["event_fields"]
        self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
        self.assertIs(fields["exit_status_confirmed"], False)
        self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
        self.assertEqual(fields["exit_evidence_audit_sha256"], exit_hashes)
        self.assertEqual(fields["exit_candidate_fatal_sha256"], [fatal_hash])
        self.assertIn("Miner exit: UNKNOWN", alert["message_text"])
        ledger.close()

    def test_one_fatal_two_exits_after_sqlite_restart_stays_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-two-exits-restart.sqlite3"
            first_store = SQLiteAlertLedger(db_path)
            first, _, _ = make_enricher(
                [cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal")],
                ledger=first_store,
            )
            self.assertEqual(
                first.run_once(end_time_utc="2026-10-13T12:00:10Z").prepared_count, 1,
            )
            first_store.close()

            exits = [
                cuda_exit_entry(event_time="2026-10-13T12:00:20Z", log_id="exit-a"),
                cuda_exit_entry(event_time="2026-10-13T12:00:30Z", log_id="exit-b"),
            ]
            exit_hashes = sorted(normalize_log_entry(entry).evidence_sha256 for entry in exits)
            reopened = SQLiteAlertLedger(db_path)
            second, _, _ = make_enricher(exits, ledger=reopened)
            self.assertEqual(
                second.run_once(end_time_utc="2026-10-13T12:01:00Z").prepared_count, 0,
            )

            self.assertEqual(reopened.alert_count(), 1)
            fields = reopened.list_outbox()[0]["payload"]["event_fields"]
            self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
            self.assertIs(fields["exit_status_confirmed"], False)
            self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
            self.assertEqual(fields["exit_evidence_audit_sha256"], exit_hashes)
            reopened.close()

    def test_late_fatal_downgrades_previously_confirmed_exit_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-late-fatal-invalidates-exit.sqlite3"
            first_store = SQLiteAlertLedger(db_path)
            first, _, _ = make_enricher(
                [
                    cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal-a"),
                    cuda_exit_entry(event_time="2026-10-13T12:00:20Z", log_id="exit-a"),
                ],
                ledger=first_store,
            )
            self.assertEqual(
                first.run_once(end_time_utc="2026-10-13T12:00:30Z").prepared_count, 1,
            )
            fields = first_store.list_outbox()[0]["payload"]["event_fields"]
            self.assertIs(fields["exit_status_confirmed"], True)
            fatal_a_hash = normalize_log_entry(
                cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal-a")
            ).evidence_sha256
            first_store.close()

            reopened = SQLiteAlertLedger(db_path)
            late_fatal = cuda_fatal_entry(
                event_time="2026-10-13T12:00:10Z", log_id="fatal-b",
            )
            fatal_b_hash = normalize_log_entry(late_fatal).evidence_sha256
            second, _, _ = make_enricher(
                [late_fatal],
                ledger=reopened,
                limits=QueryLimits(maximum_window_seconds=3_600, overlap_seconds=120),
            )
            self.assertEqual(
                second.run_once(end_time_utc="2026-10-13T12:00:40Z").prepared_count, 0,
            )

            alert = reopened.list_outbox()[0]
            fields = alert["payload"]["event_fields"]
            self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
            self.assertIs(fields["exit_status_confirmed"], False)
            self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
            self.assertEqual(fields["exit_candidate_fatal_sha256"], sorted([fatal_a_hash, fatal_b_hash]))
            self.assertIn("Miner exit: UNKNOWN", alert["message_text"])
            reopened.close()

    def test_conflicting_confirmed_exits_after_restart_downgrade_and_commit_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-conflicting-confirmed-exits.sqlite3"
            fatal = cuda_fatal_entry(
                event_time="2026-10-13T12:00:00Z", log_id="same-fatal",
            )
            exit_first = cuda_exit_entry(
                event_time="2026-10-13T12:00:20Z", log_id="exit-first",
            )
            exit_second = cuda_exit_entry(
                event_time="2026-10-13T12:00:25Z", log_id="exit-second",
            )
            fatal_hash = normalize_log_entry(fatal).evidence_sha256
            exit_hashes = sorted({
                normalize_log_entry(exit_first).evidence_sha256,
                normalize_log_entry(exit_second).evidence_sha256,
            })

            first_store = SQLiteAlertLedger(db_path)
            first, _, _ = make_enricher(
                [fatal, exit_first], ledger=first_store,
            )
            self.assertEqual(
                first.run_once(end_time_utc="2026-10-13T12:00:30Z").prepared_count, 1,
            )
            initial_fields = first_store.list_outbox()[0]["payload"]["event_fields"]
            self.assertIs(initial_fields["exit_status_confirmed"], True)
            first_store.close()

            reopened = SQLiteAlertLedger(db_path)
            try:
                second, _, _ = make_enricher(
                    [fatal, exit_second],
                    ledger=reopened,
                    limits=QueryLimits(maximum_window_seconds=3_600, overlap_seconds=120),
                )
                result = second.run_once(end_time_utc="2026-10-13T12:00:40Z")

                self.assertEqual(result.prepared_count, 0)
                self.assertEqual(reopened.get_cursor(), "2026-10-13T12:00:40.000000Z")
                self.assertEqual(reopened.alert_count(), 1)
                outbox = reopened.list_outbox()
                self.assertEqual(len(outbox), 1)
                fields = outbox[0]["payload"]["event_fields"]
                self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
                self.assertIs(fields["exit_status_confirmed"], False)
                self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
                self.assertEqual(fields["exit_evidence_audit_sha256"], exit_hashes)
                self.assertEqual(fields["exit_candidate_fatal_sha256"], [fatal_hash])
                self.assertIn("Miner exit: UNKNOWN", outbox[0]["message_text"])
            finally:
                reopened.close()

    def test_ambiguous_exit_binding_is_never_promoted_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-ambiguous-never-promoted.sqlite3"
            first_store = SQLiteAlertLedger(db_path)
            first, _, _ = make_enricher(
                [
                    cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal"),
                    cuda_exit_entry(event_time="2026-10-13T12:00:20Z", log_id="exit-a"),
                    cuda_exit_entry(event_time="2026-10-13T12:00:30Z", log_id="exit-b"),
                ],
                ledger=first_store,
            )
            self.assertEqual(
                first.run_once(end_time_utc="2026-10-13T12:00:35Z").prepared_count, 1,
            )
            first_fields = first_store.list_outbox()[0]["payload"]["event_fields"]
            self.assertEqual(first_fields["exit_correlation_status"], "AMBIGUOUS")
            first_store.close()

            reopened = SQLiteAlertLedger(db_path)
            late_exit = cuda_exit_entry(
                event_time="2026-10-13T12:00:40Z", log_id="exit-later",
            )
            second, _, _ = make_enricher(
                [late_exit],
                ledger=reopened,
                limits=QueryLimits(maximum_window_seconds=3_600, overlap_seconds=120),
            )
            self.assertEqual(
                second.run_once(end_time_utc="2026-10-13T12:00:45Z").prepared_count, 0,
            )

            fields = reopened.list_outbox()[0]["payload"]["event_fields"]
            self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
            self.assertIs(fields["exit_status_confirmed"], False)
            self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
            self.assertIn("Miner exit: UNKNOWN", reopened.list_outbox()[0]["message_text"])
            reopened.close()

    def test_ambiguous_evidence_merge_downgrades_a_prior_confirmation(self):
        from log_alerts.ledger import _merge_cuda_exit_evidence

        common = {
            "reason": "CUDA_DRIVER_VERSION_INSUFFICIENT",
            "gpu_initialized": False,
            "actions_performed": False,
            "recommendation": "REALLOCATE",
        }
        confirmed = {
            "event_type": "CUDA_DRIVER_INCOMPATIBLE",
            "event_fields": {
                **common,
                "miner_exit_status": 1,
                "exit_status_confirmed": True,
                "exit_status_event_time_utc": "2026-10-13T12:00:20.000000Z",
                "exit_evidence_sha256": "a" * 64,
                "exit_correlation_status": "CONFIRMED",
            },
        }
        ambiguous = {
            "event_type": "CUDA_DRIVER_INCOMPATIBLE",
            "event_fields": {
                **common,
                "miner_exit_status": "UNKNOWN",
                "exit_status_confirmed": False,
                "exit_status_event_time_utc": None,
                "exit_evidence_sha256": None,
                "exit_correlation_status": "AMBIGUOUS",
                "exit_evidence_audit_sha256": ["a" * 64, "b" * 64],
                "exit_candidate_fatal_sha256": ["c" * 64],
            },
        }

        merged = _merge_cuda_exit_evidence(confirmed, ambiguous)
        fields = merged["event_fields"]
        self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
        self.assertIs(fields["exit_status_confirmed"], False)
        self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
        self.assertIsNone(fields["exit_status_event_time_utc"])
        self.assertIsNone(fields["exit_evidence_sha256"])

    def test_cuda_exit_audit_hashes_are_bounded_across_sqlite_restarts(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-bounded-exit-audit.sqlite3"
            base = datetime.fromisoformat("2026-10-13T12:00:00+00:00")

            def stamp(offset: timedelta) -> str:
                return (base + offset).isoformat(timespec="microseconds").replace("+00:00", "Z")

            fatals = [
                cuda_fatal_entry(
                    event_time=stamp(timedelta(milliseconds=200 * index)),
                    log_id=f"fatal-{index}",
                )
                for index in range(101)
            ]
            exits = [
                cuda_exit_entry(
                    event_time=stamp(timedelta(seconds=21, milliseconds=300 * index)),
                    log_id=f"exit-{index}",
                )
                for index in range(101)
            ]
            first_store = SQLiteAlertLedger(db_path)
            pages = [
                LogQueryPage(tuple(fatals[:100]), next_page_token="audit-page-2"),
                LogQueryPage(tuple([*fatals[100:], *exits[:99]]), next_page_token="audit-page-3"),
                LogQueryPage(tuple(exits[99:])),
            ]
            first, _, _ = make_enricher([], pages=pages, ledger=first_store)
            self.assertEqual(
                first.run_once(end_time_utc="2026-10-13T12:00:52Z").prepared_count, 1,
            )

            first_fields = first_store.list_outbox()[0]["payload"]["event_fields"]
            self.assertEqual(len(first_fields["exit_evidence_audit_sha256"]), 100)
            self.assertEqual(len(first_fields["exit_candidate_fatal_sha256"]), 100)
            self.assertIs(first_fields["exit_correlation_audit_truncated"], True)
            self.assertEqual(first_fields["miner_exit_status"], "UNKNOWN")
            first_store.close()

            reopened = SQLiteAlertLedger(db_path)
            later_exit = cuda_exit_entry(
                event_time=stamp(timedelta(milliseconds=51_500)), log_id="exit-after-restart",
            )
            second, _, _ = make_enricher(
                [later_exit],
                ledger=reopened,
                limits=QueryLimits(maximum_window_seconds=3_600, overlap_seconds=120),
            )
            self.assertEqual(
                second.run_once(end_time_utc="2026-10-13T12:00:53Z").prepared_count, 0,
            )

            fields = reopened.list_outbox()[0]["payload"]["event_fields"]
            self.assertLessEqual(len(fields["exit_evidence_audit_sha256"]), 100)
            self.assertLessEqual(len(fields["exit_candidate_fatal_sha256"]), 100)
            self.assertIs(fields["exit_correlation_audit_truncated"], True)
            self.assertEqual(fields["exit_status_confirmed"], False)
            self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
            self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
            reopened.close()

    def test_cuda_fatal_without_exit_still_alerts_with_unknown_exit(self):
        enricher, _, ledger = make_enricher([cuda_fatal_entry()])
        result = enricher.run_once(end_time_utc=END_TIME)
        alert = ledger.list_outbox()[0]
        self.assertEqual(result.prepared_count, 1)
        self.assertEqual(alert["payload"]["event_fields"]["miner_exit_status"], "UNKNOWN")
        self.assertIs(alert["payload"]["event_fields"]["exit_status_confirmed"], False)
        self.assertIn("Miner exit: UNKNOWN", alert["message_text"])
        self.assertNotIn(CUDA_FATAL_LINE, repr(alert))
        ledger.close()

    def test_cuda_exit_from_other_machine_or_instance_is_never_claimed(self):
        scenarios = (
            provider_labels("machine-other", "instance-other"),
            provider_labels("machine-1", "instance-replaced"),
        )
        for index, exit_labels in enumerate(scenarios):
            with self.subTest(exit_labels=exit_labels):
                enricher, _, ledger = make_enricher([
                    cuda_fatal_entry(labels=provider_labels("machine-1", "instance-1"), log_id=f"fatal-{index}"),
                    cuda_exit_entry(labels=exit_labels, log_id=f"exit-{index}"),
                ])
                enricher.run_once(end_time_utc=END_TIME)
                alert = ledger.list_outbox()[0]
                self.assertEqual(alert["payload"]["event_fields"]["miner_exit_status"], "UNKNOWN")
                self.assertIs(alert["payload"]["event_fields"]["exit_status_confirmed"], False)
                ledger.close()

    def test_nvidia_smi_success_does_not_suppress_exact_cuda_fatal(self):
        enricher, _, ledger = make_enricher([
            log_entry(text_log="nvidia-smi diagnostic succeeded", log_id="diagnostic"),
            cuda_fatal_entry(log_id="fatal"),
        ])
        result = enricher.run_once(end_time_utc=END_TIME)
        self.assertEqual(result.prepared_count, 1)
        self.assertEqual(ledger.list_outbox()[0]["payload"]["event_type"], "CUDA_DRIVER_INCOMPATIBLE")
        ledger.close()

    def test_machine_group_cooldown_is_durable_across_instances_and_expires(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-cooldown.sqlite3"
            first_store = SQLiteAlertLedger(db_path)
            first, _, _ = make_enricher(
                [cuda_fatal_entry(
                    labels=provider_labels("machine-1", "instance-a"),
                    log_id="fatal-a", event_time="2026-10-13T12:00:00Z",
                )],
                ledger=first_store,
            )
            self.assertEqual(first.run_once(end_time_utc="2026-10-13T12:00:30Z").prepared_count, 1)
            first_store.close()

            reopened = SQLiteAlertLedger(db_path)
            second, _, _ = make_enricher(
                [cuda_fatal_entry(
                    labels=provider_labels("machine-1", "instance-b"),
                    log_id="fatal-b", event_time="2026-10-13T12:05:00Z",
                )],
                ledger=reopened,
            )
            self.assertEqual(second.run_once(end_time_utc="2026-10-13T12:05:00Z").prepared_count, 0)
            self.assertEqual(reopened.alert_count(), 1)
            observations = reopened.list_cuda_suppressed_observations()
            self.assertEqual(len(observations), 1)
            self.assertEqual(observations[0]["instance_id"], "instance-b")

            third, _, _ = make_enricher(
                [
                    # Replaying the exact original evidence after expiry stays
                    # deduplicated; a new fatal record may alert again.
                    cuda_fatal_entry(
                        labels=provider_labels("machine-1", "instance-a"),
                        log_id="fatal-a", event_time="2026-10-13T12:00:00Z",
                    ),
                    cuda_fatal_entry(
                        labels=provider_labels("machine-1", "instance-c"),
                        log_id="fatal-c", event_time="2026-10-13T12:10:01Z",
                    ),
                ],
                ledger=reopened,
                limits=QueryLimits(maximum_window_seconds=10_000, overlap_seconds=1_000),
            )
            self.assertEqual(third.run_once(end_time_utc="2026-10-13T12:10:10Z").prepared_count, 1)
            self.assertEqual(reopened.alert_count(), 2)
            self.assertEqual(len(reopened.list_outbox()), 2)
            reopened.close()

    def test_cuda_cooldown_is_independent_by_machine_and_container_group(self):
        entries = [
            cuda_fatal_entry(labels=provider_labels("machine-1", "instance-a", "fl4shminer"), log_id="a"),
            cuda_fatal_entry(labels=provider_labels("machine-1", "instance-b", "fl4shminer-2"), log_id="b"),
            cuda_fatal_entry(labels=provider_labels("machine-2", "instance-c", "fl4shminer"), log_id="c"),
        ]
        enricher, _, ledger = make_enricher(entries)
        self.assertEqual(enricher.run_once(end_time_utc=END_TIME).prepared_count, 3)
        self.assertEqual(
            {(item["payload"]["identity"]["machine_id"], item["payload"]["identity"]["container_group_name"])
             for item in ledger.list_outbox()},
            {("machine-1", "fl4shminer"), ("machine-1", "fl4shminer-2"), ("machine-2", "fl4shminer")},
        )
        ledger.close()

    def test_missing_or_conflicting_cuda_identity_is_not_guessed_or_machine_deduplicated(self):
        missing = provider_labels("machine-hidden", "instance-missing")
        missing.pop("machine_id")
        conflicting = provider_labels("machine-claimed", "instance-conflict")
        conflicting["machine id"] = "machine-other"
        enricher, _, ledger = make_enricher([
            cuda_fatal_entry(labels=missing, log_id="unknown"),
            cuda_fatal_entry(labels=conflicting, log_id="conflicting"),
        ])
        self.assertEqual(enricher.run_once(end_time_utc=END_TIME).prepared_count, 2)
        outbox = ledger.list_outbox()
        by_status = {item["payload"]["identity"]["identity_status"]: item for item in outbox}
        self.assertEqual(set(by_status), {"UNKNOWN", "CONFLICTING"})
        for status, item in by_status.items():
            self.assertIsNone(item["payload"]["identity"]["machine_id"])
            self.assertIn("Machine ID: UNKNOWN", item["message_text"])
            self.assertIn(f"Identity status: {status}", item["message_text"])
        self.assertEqual(ledger.list_cuda_suppressed_observations(), [])
        ledger.close()

    def test_late_exit_after_restart_enriches_existing_cuda_outbox_without_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-late-exit.sqlite3"
            first_store = SQLiteAlertLedger(db_path)
            first, _, _ = make_enricher(
                [cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal")],
                ledger=first_store,
            )
            self.assertEqual(first.run_once(end_time_utc="2026-10-13T12:00:30Z").prepared_count, 1)
            first_store.close()

            reopened = SQLiteAlertLedger(db_path)
            second, _, _ = make_enricher(
                [cuda_exit_entry(event_time="2026-10-13T12:00:40Z", log_id="late-exit")],
                ledger=reopened,
            )
            result = second.run_once(end_time_utc="2026-10-13T12:01:00Z")
            self.assertEqual(result.prepared_count, 0)
            self.assertEqual(reopened.alert_count(), 1)
            outbox = reopened.list_outbox()
            self.assertEqual(len(outbox), 1)
            self.assertIs(outbox[0]["payload"]["event_fields"]["exit_status_confirmed"], True)
            self.assertEqual(outbox[0]["payload"]["event_fields"]["miner_exit_status"], 1)
            self.assertIn("Miner exit: 1", outbox[0]["message_text"])
            reopened.close()

    def test_ambiguous_late_exit_after_sqlite_reopen_stays_unknown_and_audited(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-ambiguous-late-exit.sqlite3"
            fatal_hashes = {
                normalize_log_entry(cuda_fatal_entry(
                    event_time="2026-10-13T12:00:00Z", log_id="fatal-a",
                )).evidence_sha256,
                normalize_log_entry(cuda_fatal_entry(
                    event_time="2026-10-13T12:00:20Z", log_id="fatal-b",
                )).evidence_sha256,
            }
            first_store = SQLiteAlertLedger(db_path)
            first, _, _ = make_enricher(
                [cuda_fatal_entry(event_time="2026-10-13T12:00:00Z", log_id="fatal-a")],
                ledger=first_store,
            )
            self.assertEqual(first.run_once(end_time_utc="2026-10-13T12:00:10Z").prepared_count, 1)
            first_store.close()

            second_store = SQLiteAlertLedger(db_path)
            second, _, _ = make_enricher(
                [cuda_fatal_entry(event_time="2026-10-13T12:00:20Z", log_id="fatal-b")],
                ledger=second_store,
            )
            self.assertEqual(second.run_once(end_time_utc="2026-10-13T12:00:30Z").prepared_count, 0)
            self.assertEqual(len(second_store.list_cuda_suppressed_observations()), 1)
            second_store.close()

            exit_entry = cuda_exit_entry(event_time="2026-10-13T12:00:40Z", log_id="stopped")
            exit_hash = normalize_log_entry(exit_entry).evidence_sha256
            reopened = SQLiteAlertLedger(db_path)
            third, _, _ = make_enricher([exit_entry], ledger=reopened)
            self.assertEqual(third.run_once(end_time_utc="2026-10-13T12:00:50Z").prepared_count, 0)

            outbox = reopened.list_outbox()
            self.assertEqual(len(outbox), 1)
            fields = outbox[0]["payload"]["event_fields"]
            self.assertEqual(fields["miner_exit_status"], "UNKNOWN")
            self.assertIs(fields["exit_status_confirmed"], False)
            self.assertEqual(fields["exit_correlation_status"], "AMBIGUOUS")
            self.assertEqual(fields["exit_evidence_audit_sha256"], [exit_hash])
            self.assertEqual(fields["exit_candidate_fatal_sha256"], sorted(fatal_hashes))
            self.assertIn("Miner exit: UNKNOWN", outbox[0]["message_text"])
            reopened.close()

    def test_cuda_terminal_failure_suppresses_same_generation_startup_timeout_and_recovery(self):
        event_time = "2026-10-13T12:00:00Z"
        entries = [
            lifecycle_entry("running", event_time=event_time, log_id="running"),
            lifecycle_entry("ready", event_time=event_time, log_id="ready"),
            cuda_fatal_entry(event_time="2026-10-13T12:00:20Z", log_id="fatal"),
        ]
        enricher, _, ledger = make_enricher(entries)
        result = enricher.run_once(end_time_utc="2026-10-13T12:01:31Z")
        outbox = ledger.list_outbox()
        self.assertEqual(result.prepared_count, 1)
        self.assertEqual([item["payload"]["event_type"] for item in outbox], ["CUDA_DRIVER_INCOMPATIBLE"])
        state = next(iter(ledger.get_startup_states().values()))
        self.assertEqual(state["status"], "CUDA_DRIVER_INCOMPATIBLE")
        self.assertEqual(state["terminal_failure_reason"], "CUDA_DRIVER_VERSION_INSUFFICIENT")
        self.assertFalse(any(item["payload"]["event_type"] == "MINER_STARTUP_RECOVERED" for item in outbox))
        ledger.close()

    def test_cuda_fatal_suppresses_previously_prepared_startup_alert_transactionally(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "cuda-startup-suppression.sqlite3"
            store = SQLiteAlertLedger(db_path)
            lifecycle = [
                lifecycle_entry("running", event_time=EVENT_TIME, log_id="running"),
                lifecycle_entry("ready", event_time=EVENT_TIME, log_id="ready"),
            ]
            first, _, _ = make_enricher(lifecycle, ledger=store)
            self.assertEqual(first.run_once(end_time_utc="2026-10-13T12:01:31Z").prepared_count, 1)
            store.close()

            reopened = SQLiteAlertLedger(db_path)
            second, _, _ = make_enricher(
                [*lifecycle, cuda_fatal_entry(event_time="2026-10-13T12:01:32Z", log_id="fatal")],
                ledger=reopened,
            )
            self.assertEqual(second.run_once(end_time_utc="2026-10-13T12:02:00Z").prepared_count, 1)
            outbox = reopened.list_outbox()
            self.assertEqual(len(outbox), 2)
            startup = next(item for item in outbox if item["payload"]["event_type"] == "RUNNING_READY_BUT_MINER_NOT_STARTED")
            self.assertEqual(startup["state"], "SUPPRESSED_BY_CUDA_FATAL")
            self.assertTrue(startup["suppressed_by"])
            self.assertEqual(
                {item["payload"]["event_type"] for item in outbox},
                {"RUNNING_READY_BUT_MINER_NOT_STARTED", "CUDA_DRIVER_INCOMPATIBLE"},
            )
            self.assertFalse(any(item["payload"]["event_type"] == "MINER_STARTUP_RECOVERED" for item in outbox))
            reopened.close()


if __name__ == "__main__":
    unittest.main()
