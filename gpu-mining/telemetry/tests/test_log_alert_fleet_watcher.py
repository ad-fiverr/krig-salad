"""Offline integration tests for scoped multi-organization log monitoring."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid


TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from log_alerts.central_telegram import (  # noqa: E402
    CentralTelegramSender,
    SyntheticTelegramSecretProvider,
)
from log_alerts.contract import LiveLogQueryPolicy  # noqa: E402
from log_alerts.fleet_targets import (  # noqa: E402
    FleetTarget,
    load_targets_file,
    parse_target,
    validate_targets,
)
from log_alerts.fleet_watcher import CentralFleetWatcher  # noqa: E402
from log_alerts.live_capability import authorize_live_invocation  # noqa: E402
from log_alerts.live_adapter import LiveAdapterError  # noqa: E402
from log_alerts import live_cli as live_cli_module  # noqa: E402
from log_alerts.live_cli import (  # noqa: E402
    WatcherAlreadyRunning,
    main as live_cli_main,
)
from log_alerts.live_transport import (  # noqa: E402
    LiveSaladReadTransport,
    LiveTransportBlocked,
    OfflineSaladExchange,
    SaladTransportResponse,
    secret_boundary_types,
)


_SMOKE_PATH = TELEMETRY_ROOT.parent / "runtime" / "fl4shminer" / "ci-fleet-image-smoke.py"
_SMOKE_SPEC = importlib.util.spec_from_file_location("fl4sh_fleet_image_smoke_test", _SMOKE_PATH)
if _SMOKE_SPEC is None or _SMOKE_SPEC.loader is None:
    raise RuntimeError("Fl4sh fleet image smoke module is unavailable")
_SMOKE_MODULE = importlib.util.module_from_spec(_SMOKE_SPEC)
sys.modules[_SMOKE_SPEC.name] = _SMOKE_MODULE
_SMOKE_SPEC.loader.exec_module(_SMOKE_MODULE)


ORGANIZATIONS = ("fleet-alpha", "fleet-bravo")
PROJECT = "miners"
GROUPS = ("fl4shminer", "fl4shminer-2", "fl4shminer-3", "fl4shminer-4")
COMMON_INSTANCE = "00000000-0000-4000-8000-000000000001"
POOL_SESSION = "11111111-1111-4111-8111-111111111111"
POOL_EPISODE = "22222222-2222-4222-8222-222222222222"
SOLUTION_LINE = "Solutions accepted: 5-NVIDIA GeForce RTX 5080 Laptop GPU, 0 stale"
SOLUTION_HASH = hashlib.sha256(SOLUTION_LINE.encode("utf-8")).hexdigest()
InteractiveSecretProvider, SyntheticSecretProvider, _ = secret_boundary_types()


def _machine_id(org_index: int, group_index: int, local_index: int) -> str:
    return str(uuid.UUID(int=10_000 + org_index * 10_000 + group_index * 100 + local_index + 1))


def _instance_id(group_index: int, local_index: int) -> str:
    # Intentionally reused across organizations and groups: scope must be part
    # of the List Instances lookup key.
    if local_index == 0:
        return COMMON_INSTANCE
    return str(uuid.UUID(int=20_000 + group_index * 100 + local_index + 1))


def _reallocation_line(index: int, timestamp: str) -> str:
    episode_id = str(uuid.UUID(int=30_000 + index + 1, version=4))
    return " ".join((
        "FL4SH_MONITOR state=REALLOCATE_RECOMMENDED",
        "profile=RTX_5080_LAPTOP",
        "device=fl4shminer_device:1",
        "gpu_key=RTX_5080_LAPTOP",
        "gpu_candidates=RTX_5080_LAPTOP",
        'gpu_raw="NVIDIA GeForce RTX 5080 Laptop GPU"',
        "floor=105 floor_ths=105 floor_source=ENV_REGISTRY",
        "observed=98.94 bad_windows=2/2 coverage=0.91 window_samples=12",
        "stale=7/591 stale_pct=1.2% provider_binding=UNKNOWN",
        "gpu_identity_verified=false billing=UNKNOWN actions_performed=false",
        f"policy_hash={'a' * 64}", f"timestamp={timestamp}",
        "tolerance_ths=2 decision_threshold_ths=103",
        f"episode_id={episode_id} alert_sequence=1",
        "notification_reason=INITIAL_THRESHOLD_CROSSING",
    ))


def _pool_line(
    state: str, *, timestamp: str, sequence: int = 1,
    first_failure: str = "2026-10-13T12:00:00Z",
    latest_failure: str = "2026-10-13T12:00:00Z",
) -> str:
    common = [
        f"FL4SH_MONITOR state={state}",
        f"monitor_session_id={POOL_SESSION}", f"pool_episode_id={POOL_EPISODE}",
        f"pool_alert_sequence={sequence}", "reason=MINING_AUTHORIZE_RESPONSE_TIMEOUT",
        "retry_seconds=10", f"first_failure_utc={first_failure}",
        f"latest_failure_utc={latest_failure}", "gpu_key=RTX_5080_LAPTOP",
        "device=fl4shminer_device:1", "actions_performed=false",
    ]
    if state == "POOL_CONNECTION_FAILED":
        common.append("failure_count=1")
    elif state == "POOL_CONNECTION_UNSTABLE":
        common.extend((
            "failure_count=3 recent_failure_count=3",
            "notification_reason=BURST_FAILURES unstable_duration_seconds=10",
            f"recent_failure_window_start_utc={first_failure}",
        ))
    elif state == "POOL_CONNECTION_RECOVERED":
        common.extend((
            "failure_count=3 prior_failure_count=3 recovery_signal=SOLUTIONS_ACCEPTED",
            f"timestamp_utc={timestamp} recovered_at_utc={timestamp}",
            f"solutions_evidence_sha256={SOLUTION_HASH}",
        ))
    return " ".join(common)


def _pool_recovery_evidence(event_time: str, recovered_at: str) -> str:
    return " ".join((
        "FL4SH_MONITOR state=POOL_RECOVERY_EVIDENCE",
        f"monitor_session_id={POOL_SESSION}", f"pool_episode_id={POOL_EPISODE}",
        "pool_alert_sequence=2 recovery_signal=SOLUTIONS_ACCEPTED",
        f"timestamp_utc={recovered_at}", f"solutions_evidence_sha256={SOLUTION_HASH}",
        "actions_performed=false",
    ))


def _no_floor_line(timestamp: str) -> str:
    return " ".join((
        "FL4SH_MONITOR state=NO_FLOOR_CONFIGURED",
        "gpu_key=RTX_9999 device=fl4shminer_device:1 observed=20",
        "floor_ths=unknown",
        f"policy_hash={'b' * 64}", f"timestamp={timestamp}",
        "actions_performed=false",
    ))


def _log_item(org: str, group: str, instance: str, timestamp: str, text: str) -> dict[str, object]:
    return {
        "time": timestamp,
        "receive_time": timestamp,
        "resource": {
            "type": "salad.container_group_instance",
            "labels": {
                # Machine ID deliberately omitted: only exact, route-scoped
                # provider List Instances evidence can fill it.
                "organization_name": org,
                "project_name": PROJECT,
                "container_group_name": group,
                "instance_id": instance,
            },
        },
        "severity": "ERROR",
        "json_log": None,
        "text_log": text,
    }


def _json_response(value: object, status: int = 200) -> SaladTransportResponse:
    return SaladTransportResponse(status, json.dumps(value, separators=(",", ":")).encode("utf-8"))


def _page(items: list[dict[str, object]]) -> dict[str, object]:
    times = [str(item["time"]) for item in items]
    return {
        "items": items,
        "page_min_time": min(times) if times else None,
        "page_max_time": max(times) if times else None,
    }


class CentralFleetWatcherTests(unittest.TestCase):
    def test_synthetic_image_layout_resolves_monitor_and_healthcheck_at_install_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            image_root = Path(temporary) / "fl4shminer"
            image_root.mkdir()
            for relative in _SMOKE_MODULE.WATCHER_INPUTS:
                target = image_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# synthetic packaged fixture\n", encoding="utf-8")
            for relative in _SMOKE_MODULE.RUNTIME_INPUTS:
                (image_root / Path(relative).name).write_text(
                    "# synthetic packaged fixture\n", encoding="utf-8",
                )
            (image_root / "fl4shminer").write_text("synthetic binary fixture\n", encoding="utf-8")

            _SMOKE_MODULE.check_image_tree(image_root)
            monitor_path, healthcheck_path = _SMOKE_MODULE.runtime_script_paths(
                image_root, image=True,
            )
            self.assertEqual(monitor_path, image_root / "fl4sh-runtime-monitor.py")
            self.assertEqual(healthcheck_path, image_root / "fl4sh-healthcheck.sh")
            self.assertTrue(monitor_path.is_file())
            self.assertTrue(healthcheck_path.is_file())

    def test_healthcheck_has_a_distinct_central_watcher_readiness_contract(self):
        healthcheck = (
            TELEMETRY_ROOT.parent / "runtime" / "fl4shminer" / "fl4sh-healthcheck.sh"
        ).read_text(encoding="utf-8")
        for required in (
            'container_role="${FL4SH_ROLE:-miner}"',
            'if [[ "$container_role" == central ]]; then',
            '[[ "$process_name" == python3 && -r /proc/1/cmdline ]]',
            '[[ "$command_line" == *"-m log_alerts.live_cli"* ]]',
            '[[ "$command_line" == *"--watch-live-alerts"* ]]',
            '[[ "${FL4SH_MONITOR_ENABLED:-0}" == 0 ]]',
            '[[ "${FL4SH_TELEGRAM_ENABLED:-0}" == 0 ]]',
            '[[ "$container_role" == miner ]] || exit 1',
            '--check-readiness --miner-pid "$child"',
        ):
            self.assertIn(required, healthcheck)

    def make_watcher(self, directory, items_by_org, instance_rows_by_scope, *, failing=None,
                     lookup_failing=None, query_responder=None, poll_seconds=30,
                     clock=None, monotonic=None):
        secret_provider = SyntheticSecretProvider()
        telegram = SyntheticTelegramSecretProvider().acquire()
        telegram_calls = []
        sender = CentralTelegramSender.for_offline_test(
            credentials=telegram,
            responder=lambda host, path, body: (telegram_calls.append((host, path, body)) or (200, b'{"ok":true}')),
        )
        capability = authorize_live_invocation(
            mode="watch", enable_live_read=True, enable_central_telegram=True,
            confirmation="CENTRAL_FLEET_MONITOR",
        )
        exchanges = {}

        def transport_factory(organization, _provider, _capability):
            def responder(host, path, headers, body):
                if path.endswith("/log-entries"):
                    if failing and organization in failing:
                        failure = failing[organization]
                        if failure == "TIMEOUT":
                            raise LiveTransportBlocked("Salad HTTPS query timeout; details redacted")
                        return _json_response({"error": "synthetic unavailable"}, int(failure))
                    if query_responder is not None:
                        return query_responder(organization, body, items_by_org.get(organization, []))
                    return _json_response(_page(items_by_org.get(organization, [])))
                match = re.fullmatch(
                    rf"/api/public/organizations/{re.escape(organization)}/projects/{PROJECT}/containers/([^/]+)/instances",
                    path,
                )
                if match:
                    if lookup_failing and organization in lookup_failing:
                        failure = lookup_failing[organization]
                        return _json_response({"error": "synthetic provider body must stay hidden"}, int(failure))
                    group = match.group(1)
                    return _json_response({"instances": instance_rows_by_scope.get((organization, group), [])})
                return _json_response({"denied": True}, 404)

            exchange = OfflineSaladExchange(responder)
            exchanges[organization] = exchange
            return LiveSaladReadTransport.for_offline_test(
                policy=LiveLogQueryPolicy(organization), exchange=exchange,
            )

        watcher = CentralFleetWatcher(
            targets=[FleetTarget(org, PROJECT) for org in ORGANIZATIONS],
            query='severity="ERROR"',
            state_dir=directory,
            secret_provider=secret_provider,
            sender=sender,
            capability=capability,
            poll_seconds=poll_seconds,
            transport_factory=transport_factory,
            clock_utc=clock,
            monotonic=monotonic or (lambda: 0.0),
        )
        return watcher, exchanges, telegram_calls, secret_provider

    def test_100_synthetic_machines_are_scoped_by_org_project_and_group_and_replay_dedupes(self):
        items_by_org = {org: [] for org in ORGANIZATIONS}
        rows_by_scope = {}
        expected = {}
        base = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
        global_index = 0
        for org_index, org in enumerate(ORGANIZATIONS):
            group_counts = {group: 0 for group in GROUPS}
            for index in range(50):
                group_index = index % len(GROUPS)
                group = GROUPS[group_index]
                local_index = group_counts[group]
                group_counts[group] += 1
                instance = _instance_id(group_index, local_index)
                machine = _machine_id(org_index, group_index, local_index)
                expected[(org, group, instance)] = machine
                timestamp = (base + timedelta(seconds=index)).strftime("%Y-%m-%dT%H:%M:%SZ")
                items_by_org[org].append(_log_item(
                    org, group, instance, timestamp, _reallocation_line(global_index, timestamp),
                ))
                global_index += 1
            # Add a mixed set of records to the same 100-machine synthetic
            # fleet: a complete pool episode, CUDA failure, healthy sample,
            # and an alert whose provider identity is deliberately incomplete.
            pool_times = {
                "failed": "2026-10-13T12:00:05Z",
                "unstable": "2026-10-13T12:00:15Z",
                "marker": "2026-10-13T12:00:25Z",
                "recovered": "2026-10-13T12:00:26Z",
                "solutions": "2026-10-13T12:00:27Z",
            }
            pool_instance = _instance_id(0, 0)
            items_by_org[org].extend((
                _log_item(org, GROUPS[0], pool_instance, pool_times["failed"], _pool_line(
                    "POOL_CONNECTION_FAILED", timestamp=pool_times["failed"],
                    first_failure=pool_times["failed"], latest_failure=pool_times["failed"],
                )),
                _log_item(org, GROUPS[0], pool_instance, pool_times["unstable"], _pool_line(
                    "POOL_CONNECTION_UNSTABLE", timestamp=pool_times["unstable"], sequence=2,
                    first_failure=pool_times["failed"], latest_failure=pool_times["unstable"],
                )),
                _log_item(org, GROUPS[0], pool_instance, pool_times["marker"], _pool_recovery_evidence(
                    pool_times["marker"], pool_times["recovered"],
                )),
                _log_item(org, GROUPS[0], pool_instance, pool_times["recovered"], _pool_line(
                    "POOL_CONNECTION_RECOVERED", timestamp=pool_times["recovered"], sequence=2,
                    first_failure=pool_times["failed"], latest_failure=pool_times["unstable"],
                )),
                _log_item(org, GROUPS[0], pool_instance, pool_times["solutions"], SOLUTION_LINE),
                _log_item(
                    org, GROUPS[1], _instance_id(1, 0), "2026-10-13T12:00:52Z",
                    "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is insufficient for CUDA runtime version, OpenCL: <nil>).",
                ),
                _log_item(
                    org, GROUPS[2], _instance_id(2, 0), "2026-10-13T12:00:53Z",
                    "Device [1] hashRate: 217.81 TH/s, stale: 0/0 (0.0%), warm: 0",
                ),
                _log_item(
                    org, GROUPS[3], "", "2026-10-13T12:00:54Z", _no_floor_line("2026-10-13T12:00:54Z"),
                ),
            ))
            for group_index, group in enumerate(GROUPS):
                rows_by_scope[(org, group)] = [
                    {"id": instance, "instance_id": instance, "machine_id": machine}
                    for (row_org, row_group, instance), machine in expected.items()
                    if row_org == org and row_group == group
                ]

        with tempfile.TemporaryDirectory() as temp:
            watcher, exchanges, telegram_calls, secret_provider = self.make_watcher(
                temp, items_by_org, rows_by_scope,
            )
            try:
                first = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                self.assertEqual([item.status for item in first], ["SYNTHETIC_ONLY"] * 2)
                self.assertEqual([item.records_seen for item in first], [58, 58])
                self.assertEqual([item.alerts_prepared for item in first], [55, 55])
                self.assertEqual([item.group_lookups for item in first], [4, 4])
                self.assertEqual(sum(len(exchange.calls) for exchange in exchanges.values()), 10)
                self.assertEqual(telegram_calls, [])
                self.assertEqual(secret_provider.read_count, 10)

                observed = set()
                for organization, ledger in watcher._ledgers.items():
                    rows = ledger.list_outbox()
                    self.assertEqual(len(rows), 55)
                    event_types = {row["payload"]["event_type"] for row in rows}
                    self.assertTrue({
                        "REALLOCATE_RECOMMENDED", "POOL_CONNECTION_FAILED",
                        "POOL_CONNECTION_UNSTABLE", "POOL_CONNECTION_RECOVERED",
                        "CUDA_DRIVER_INCOMPATIBLE", "NO_FLOOR_CONFIGURED",
                    }.issubset(event_types))
                    for row in rows:
                        payload = row["payload"]
                        identity = payload["identity"]
                        if row["payload"]["event_type"] == "NO_FLOOR_CONFIGURED":
                            self.assertEqual(identity["identity_status"], "UNKNOWN")
                            self.assertIsNone(identity["machine_id"])
                            self.assertIsNone(identity["instance_id"])
                            key = None
                        else:
                            key = (organization, identity["container_group_name"], identity["instance_id"])
                            self.assertEqual(identity["machine_id"], expected[key])
                            self.assertEqual(identity["identity_source"], "list_container_group_instances")
                            self.assertEqual(identity["identity_status"], "SYNTHETIC/UNVERIFIED")
                        self.assertEqual(payload["query_organization"], organization)
                        self.assertEqual(payload["data_classification"], "SYNTHETIC/UNVERIFIED")
                        self.assertFalse(payload["actions_performed"])
                        message = row["message_text"]
                        expected_instance = identity.get("instance_id") or "UNKNOWN"
                        expected_machine = identity.get("machine_id") or "UNKNOWN"
                        self.assertEqual(message.splitlines()[:6], [
                            f"Organization: {organization}",
                            f"Project: {PROJECT}",
                            f"Container Group: {identity.get('container_group_name') or 'UNKNOWN'}",
                            f"Machine ID: {expected_machine}",
                            f"Instance ID: {expected_instance}",
                            f"Identity source: {identity.get('identity_source') or 'UNKNOWN'}",
                        ])
                        self.assertTrue(message.splitlines()[6].endswith(row["payload"]["event_type"]))
                        self.assertIn(f"Organization: {organization}", message)
                        self.assertIn(f"Project: {PROJECT}", message)
                        if key is not None:
                            self.assertIn(f"Container Group: {key[1]}", message)
                            self.assertIn(f"Machine ID: {expected[key]}", message)
                            if row["payload"]["event_type"] == "REALLOCATE_RECOMMENDED":
                                self.assertIn("Recommendation: REALLOCATE", message)
                            observed.add(key)
                self.assertEqual(len(observed), 100)

                second = watcher.run_cycle(end_time_utc="2026-10-13T12:01:30Z")
                self.assertEqual([item.alerts_prepared for item in second], [0, 0])
                self.assertEqual([item.duplicates for item in second], [55, 55])
                self.assertEqual([item.group_lookups for item in second], [0, 0])
                # Each identity-bearing log entry consumes the one cached snapshot
                # for its group; provider requests remain zero this cycle.
                self.assertEqual([item.lookup_cache_hits for item in second], [57, 57])
                self.assertEqual(sum(len(exchange.calls) for exchange in exchanges.values()), 12)
                self.assertTrue(all(ledger.get_cursor() == "2026-10-13T12:01:30.000000Z" for ledger in watcher._ledgers.values()))

                expected_files = {
                    hashlib.sha256(org.encode("ascii")).hexdigest() + ".sqlite3"
                    for org in ORGANIZATIONS
                }
                self.assertEqual({path.name for path in Path(temp).glob("*.sqlite3")}, expected_files)
                for path in Path(temp).glob("*.sqlite3"):
                    self.assertNotIn(b"SYNTHETIC_ONLY_NOT_A_CREDENTIAL", path.read_bytes())
            finally:
                watcher.close()

    def test_one_organization_failure_does_not_retry_or_block_the_other(self):
        items = {org: [] for org in ORGANIZATIONS}
        rows = {}
        clock = iter(("2026-10-13T12:01:00.123456Z", "2026-10-13T12:01:30.123456Z"))
        queries = []

        def responder(organization, body, _items):
            queries.append((organization, json.loads(body)))
            return _json_response(_page([]))

        with tempfile.TemporaryDirectory() as temp:
            watcher, exchanges, telegram_calls, _provider = self.make_watcher(
                temp, items, rows, failing={"fleet-alpha": 403},
                clock=clock.__next__, query_responder=responder,
            )
            waits = []
            try:
                results = watcher.watch(
                    maximum_cycles=2,
                    wait=lambda seconds: waits.append(seconds),
                )
                self.assertEqual([(row.organization_name, row.status) for row in results], [
                    ("fleet-alpha", "ACCESS_DENIED"),
                    ("fleet-bravo", "SYNTHETIC_ONLY"),
                ])
                self.assertEqual(waits, [30])
                self.assertEqual(len(exchanges["fleet-alpha"].calls), 2)
                self.assertEqual(len(exchanges["fleet-bravo"].calls), 3)
                # Two adjacent capped slices cover the first fractional-hour
                # window; the third query is the next cycle, never a retry.
                self.assertEqual([organization for organization, _ in queries], ["fleet-bravo"] * 3)
                self.assertEqual([(query["start_time"], query["end_time"]) for _, query in queries], [
                    ("2026-10-13T11:01:00.123Z", "2026-10-13T12:01:00.123Z"),
                    ("2026-10-13T12:01:00.123Z", "2026-10-13T12:01:00.124Z"),
                    ("2026-10-13T11:59:00.123Z", "2026-10-13T12:01:30.124Z"),
                ])
                self.assertTrue(all(call["method"] == "POST" for group in exchanges.values() for call in group.calls))
                self.assertEqual(telegram_calls, [])
            finally:
                watcher.close()

    def test_nonempty_failure_has_fixed_code_without_disclosing_provider_data(self):
        private_markers = ("synthetic-private-body", "synthetic-private-label", "synthetic-private-machine", "synthetic-private-instance")
        timestamp = "2026-10-13T12:00:30Z"
        bad = _log_item(ORGANIZATIONS[0], GROUPS[0], COMMON_INSTANCE, timestamp, private_markers[0] + "\nsecond line")
        bad["resource"]["labels"].update({"machine_id": private_markers[2], "instance_id": private_markers[3], "opaque": private_markers[1]})
        good = _log_item(ORGANIZATIONS[1], GROUPS[0], COMMON_INSTANCE, timestamp, "Device [1] hashRate: 150.0 TH/s")
        items = {ORGANIZATIONS[0]: [bad], ORGANIZATIONS[1]: [good]}
        with tempfile.TemporaryDirectory() as temp:
            watcher, exchanges, telegram_calls, _ = self.make_watcher(temp, items, {})
            try:
                with patch("log_alerts.live_transport.http.client.HTTPSConnection", side_effect=AssertionError("network forbidden")):
                    results = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                self.assertEqual(results[0].status, "QUERY_FAILED")
                self.assertEqual(results[0].query_failure_code, "ENTRY_NORMALIZATION_REJECTED")
                self.assertEqual(results[0].records_seen, 0)
                self.assertIsNone(watcher._ledgers[ORGANIZATIONS[0]].get_cursor())
                self.assertEqual(results[1].status, "SYNTHETIC_ONLY")
                self.assertIsNone(results[1].query_failure_code)
                self.assertEqual(results[1].records_seen, 1)
                self.assertEqual(watcher._ledgers[ORGANIZATIONS[1]].get_cursor(), "2026-10-13T12:01:00.000000Z")
                self.assertEqual([len(exchanges[org].calls) for org in ORGANIZATIONS], [1, 2])
                # The healthy progress record keeps the existing identity GET;
                # neither organization's log POST is retried.
                self.assertEqual([call["method"] for call in exchanges[ORGANIZATIONS[1]].calls], ["POST", "GET"])
                rendered = json.dumps([asdict(result) for result in results])
                for value in private_markers:
                    self.assertNotIn(value, rendered)
                self.assertEqual(telegram_calls, [])
            finally:
                watcher.close()

    def test_empty_and_unrecognized_nonempty_responses_have_no_failure_code(self):
        for nonempty in (False, True):
            with self.subTest(nonempty=nonempty), tempfile.TemporaryDirectory() as temp:
                items = {
                    org: [_log_item(org, GROUPS[0], COMMON_INSTANCE, "2026-10-13T12:00:30Z", "unrecognized ordinary output")] if nonempty else []
                    for org in ORGANIZATIONS
                }
                watcher, _, telegram_calls, _ = self.make_watcher(temp, items, {})
                try:
                    results = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                    self.assertTrue(all(result.status == "SYNTHETIC_ONLY" for result in results))
                    self.assertTrue(all(result.query_failure_code is None for result in results))
                    self.assertEqual([result.records_seen for result in results], [int(nonempty)] * 2)
                    self.assertEqual(telegram_calls, [])
                finally:
                    watcher.close()

    def test_unknown_exceptions_and_forged_codes_do_not_escape_through_diagnostics(self):
        marker = "synthetic-private-exception-must-not-be-emitted"
        forged = LiveAdapterError(marker, code=marker)
        tampered = LiveAdapterError(marker, code="PAGE_BOUNDS_INVALID")
        tampered.failure_code = [marker]
        for exception in (RuntimeError(marker), forged, tampered):
            with self.subTest(kind=type(exception).__name__), tempfile.TemporaryDirectory() as temp:
                watcher, _, telegram_calls, _ = self.make_watcher(temp, {}, {})
                try:
                    with patch.object(watcher, "_ledger_for", side_effect=exception):
                        results = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                    self.assertTrue(all(result.status == "QUERY_FAILED" and result.query_failure_code == "UNKNOWN" for result in results))
                    self.assertNotIn(marker, json.dumps([asdict(result) for result in results]))
                    self.assertEqual(telegram_calls, [])
                finally:
                    watcher.close()

    def test_saturated_minimum_slice_is_incomplete_with_a_precise_diagnostic(self):
        items = {
            org: [_log_item(org, GROUPS[0], COMMON_INSTANCE, "2026-10-13T12:00:30Z", "ordinary output") for _ in range(100)]
            for org in ORGANIZATIONS
        }

        def responder(_organization, body, rows):
            query = json.loads(body)
            def moment(value):
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            selected = [row for row in rows if moment(query["start_time"]) <= moment(row["time"]) <= moment(query["end_time"])]
            return _json_response(_page(selected[:query["page_size"]]))

        with tempfile.TemporaryDirectory() as temp:
            watcher, exchanges, telegram_calls, _ = self.make_watcher(temp, items, {}, query_responder=responder)
            try:
                results = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                self.assertTrue(all(result.status == "INCOMPLETE_RESPONSE" and result.query_failure_code == "TIME_SLICE_LIMIT" for result in results))
                self.assertTrue(all(ledger.get_cursor() is None for ledger in watcher._ledgers.values()))
                self.assertTrue(all(len(exchange.calls) <= 64 for exchange in exchanges.values()))
                self.assertEqual(telegram_calls, [])
            finally:
                watcher.close()

    def test_one_organization_timeout_waits_for_next_cycle_and_other_org_continues(self):
        items = {org: [] for org in ORGANIZATIONS}
        clock = iter(("2026-10-13T12:01:00.123456Z", "2026-10-13T12:01:30.123456Z"))
        queries = []

        def responder(organization, body, _items):
            queries.append((organization, json.loads(body)))
            return _json_response(_page([]))

        with tempfile.TemporaryDirectory() as temp:
            watcher, exchanges, telegram_calls, _provider = self.make_watcher(
                temp, items, {}, failing={"fleet-alpha": "TIMEOUT"},
                clock=clock.__next__, query_responder=responder,
            )
            waits = []
            try:
                last = watcher.watch(maximum_cycles=2, wait=lambda seconds: waits.append(seconds))
                self.assertEqual([(row.organization_name, row.status) for row in last], [
                    ("fleet-alpha", "TIMEOUT"),
                    ("fleet-bravo", "SYNTHETIC_ONLY"),
                ])
                self.assertEqual(len(exchanges["fleet-alpha"].calls), 2)
                self.assertEqual(len(exchanges["fleet-bravo"].calls), 3)
                self.assertEqual([organization for organization, _ in queries], ["fleet-bravo"] * 3)
                self.assertEqual([(query["start_time"], query["end_time"]) for _, query in queries], [
                    ("2026-10-13T11:01:00.123Z", "2026-10-13T12:01:00.123Z"),
                    ("2026-10-13T12:01:00.123Z", "2026-10-13T12:01:00.124Z"),
                    ("2026-10-13T11:59:00.123Z", "2026-10-13T12:01:30.124Z"),
                ])
                self.assertEqual(waits, [30])
                self.assertTrue(all(call["method"] == "POST" for group in exchanges.values() for call in group.calls))
                self.assertEqual(telegram_calls, [])
            finally:
                watcher.close()

    def test_list_instances_401_and_403_are_sanitized_partial_org_failures(self):
        timestamp = "2026-10-13T12:00:30Z"
        items = {org: [] for org in ORGANIZATIONS}
        for org in ORGANIZATIONS:
            items[org].append(_log_item(
                org, GROUPS[0], COMMON_INSTANCE, timestamp,
                _reallocation_line(1 if org == ORGANIZATIONS[0] else 2, timestamp),
            ))
        rows = {
            (ORGANIZATIONS[1], GROUPS[0]): [
                {"instance_id": COMMON_INSTANCE, "machine_id": _machine_id(1, 0, 0)},
            ],
        }
        for denied_status in (401, 403):
            with self.subTest(status=denied_status), tempfile.TemporaryDirectory() as temp:
                watcher, exchanges, telegram_calls, _provider = self.make_watcher(
                    temp, items, rows, lookup_failing={ORGANIZATIONS[0]: denied_status},
                )
                try:
                    results = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                    self.assertEqual([(row.organization_name, row.status) for row in results], [
                        (ORGANIZATIONS[0], "ACCESS_DENIED"),
                        (ORGANIZATIONS[1], "SYNTHETIC_ONLY"),
                    ])
                    self.assertEqual(results[0].identity_lookup_status, "ACCESS_DENIED")
                    self.assertEqual(results[0].identity_lookup_http_status, denied_status)
                    self.assertEqual(results[0].lookup_failures, 1)
                    self.assertEqual(results[1].identity_lookup_status, "OK")
                    self.assertIsNone(results[1].identity_lookup_http_status)
                    first_alert = watcher._ledgers[ORGANIZATIONS[0]].list_outbox()[0]
                    self.assertEqual(first_alert["payload"]["identity"]["identity_status"], "UNKNOWN")
                    self.assertIsNone(first_alert["payload"]["identity"]["machine_id"])
                    self.assertIn("Machine ID: UNKNOWN", first_alert["message_text"])
                    self.assertNotIn("synthetic provider body", repr(results))
                    self.assertNotIn("/instances", repr(results))
                    self.assertEqual(telegram_calls, [])
                    get_statuses = []
                    for exchange in exchanges.values():
                        get_statuses.extend(
                            call["method"] for call in exchange.calls if call["method"] == "GET"
                        )
                    self.assertEqual(len(get_statuses), 2)
                finally:
                    watcher.close()

    def test_saturated_log_page_is_time_sliced_without_loss_or_duplicate_outbox(self):
        org = ORGANIZATIONS[0]
        items = {name: [] for name in ORGANIZATIONS}
        base = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
        for index in range(120):
            timestamp = (base + timedelta(seconds=index * 30)).strftime("%Y-%m-%dT%H:%M:%SZ")
            item = _log_item(
                org, GROUPS[0], _instance_id(0, index), timestamp,
                _reallocation_line(index, timestamp),
            )
            item["resource"]["labels"]["machine_id"] = _machine_id(0, 0, index)
            items[org].append(item)

        def sliced_responder(_organization, body, source_items):
            request = json.loads(body.decode("utf-8"))
            start = datetime.fromisoformat(request["start_time"].replace("Z", "+00:00"))
            end = datetime.fromisoformat(request["end_time"].replace("Z", "+00:00"))
            matching = [
                item for item in source_items
                if start <= datetime.fromisoformat(str(item["time"]).replace("Z", "+00:00")) <= end
            ]
            return _json_response(_page(matching[:100]))

        with tempfile.TemporaryDirectory() as temp:
            watcher, exchanges, telegram_calls, _provider = self.make_watcher(
                temp, items, {}, query_responder=sliced_responder,
            )
            try:
                result = watcher.run_cycle(end_time_utc="2026-10-13T13:00:00Z")
                org_result = result[0]
                ledger = watcher._ledgers[org]
                log_calls = [
                    call for call in exchanges[org].calls if call["method"] == "POST"
                ]
                self.assertEqual(org_result.status, "SYNTHETIC_ONLY")
                self.assertEqual(org_result.records_seen, 120)
                self.assertEqual(org_result.alerts_prepared, 120)
                self.assertEqual(ledger.alert_count(), 120)
                self.assertEqual(len(ledger.list_outbox()), 120)
                self.assertEqual(len(log_calls), 3)
                self.assertEqual(telegram_calls, [])
                self.assertEqual(ledger.get_cursor(), "2026-10-13T13:00:00.000000Z")
            finally:
                watcher.close()

    def test_fallback_identity_enriches_without_changing_dedupe_or_downgrading(self):
        org = ORGANIZATIONS[0]
        timestamp = "2026-10-13T12:00:30Z"
        items = {name: [] for name in ORGANIZATIONS}
        items[org] = [_log_item(
            org, GROUPS[0], COMMON_INSTANCE, timestamp,
            _reallocation_line(9, timestamp),
        )]
        rows = {}
        now = [0.0]
        machine = _machine_id(0, 0, 0)
        with tempfile.TemporaryDirectory() as temp:
            watcher, _exchanges, telegram_calls, _provider = self.make_watcher(
                temp, items, rows, monotonic=lambda: now[0],
            )
            try:
                first = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")[0]
                ledger = watcher._ledgers[org]
                original = ledger.list_outbox()[0]
                key = original["dedupe_key"]
                self.assertEqual(first.alerts_prepared, 1)
                self.assertEqual(original["payload"]["identity"]["identity_status"], "UNKNOWN")
                rows[(org, GROUPS[0])] = [{
                    "instance_id": COMMON_INSTANCE, "machine_id": machine,
                }]
                now[0] = 46.0
                second = watcher.run_cycle(end_time_utc="2026-10-13T12:01:30Z")[0]
                enriched = ledger.list_outbox()[0]
                self.assertEqual(second.alerts_prepared, 0)
                self.assertEqual(second.duplicates, 1)
                self.assertEqual(enriched["dedupe_key"], key)
                self.assertEqual(enriched["payload"]["identity"]["machine_id"], machine)
                self.assertEqual(enriched["payload"]["identity"]["identity_source"], "list_container_group_instances")
                self.assertEqual(len(ledger.list_outbox()), 1)
                rows[(org, GROUPS[0])] = []
                now[0] = 92.0
                third = watcher.run_cycle(end_time_utc="2026-10-13T12:02:00Z")[0]
                retained = ledger.list_outbox()[0]
                self.assertEqual(third.alerts_prepared, 0)
                self.assertEqual(third.duplicates, 1)
                self.assertEqual(retained["payload"]["identity"]["machine_id"], machine)
                self.assertEqual(len(ledger.list_outbox()), 1)
                db_path = Path(temp) / (hashlib.sha256(org.encode("ascii")).hexdigest() + ".sqlite3")
            finally:
                watcher.close()

            from log_alerts.ledger import SQLiteAlertLedger
            reopened = SQLiteAlertLedger(db_path)
            try:
                saved = reopened.list_outbox()[0]
                self.assertEqual(saved["dedupe_key"], key)
                self.assertEqual(saved["payload"]["identity"]["machine_id"], machine)
                self.assertEqual(len(reopened.list_outbox()), 1)
            finally:
                reopened.close()
        self.assertEqual(telegram_calls, [])

    def test_cuda_cooldown_accepts_exact_list_instances_identity_fallback(self):
        org = ORGANIZATIONS[0]
        instance_a = _instance_id(0, 40)
        instance_b = _instance_id(0, 41)
        machine = _machine_id(0, 0, 40)
        items = {name: [] for name in ORGANIZATIONS}
        for instance, timestamp, log_id in (
            (instance_a, "2026-10-13T12:00:00Z", "cuda-a"),
            (instance_b, "2026-10-13T12:05:00Z", "cuda-b"),
        ):
            items[org].append(_log_item(
                org, GROUPS[0], instance, timestamp,
                "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is insufficient for CUDA runtime version, OpenCL: <nil>).",
            ))
            items[org][-1]["log_id"] = log_id
        rows = {(org, GROUPS[0]): [
            {"instance_id": instance_a, "machine_id": machine},
            {"instance_id": instance_b, "machine_id": machine},
        ]}
        with tempfile.TemporaryDirectory() as temp:
            watcher, _exchanges, telegram_calls, _provider = self.make_watcher(temp, items, rows)
            try:
                result = watcher.run_cycle(end_time_utc="2026-10-13T12:10:00Z")[0]
                ledger = watcher._ledgers[org]
                outbox = ledger.list_outbox()
                suppressed = ledger.list_cuda_suppressed_observations()
                self.assertEqual(result.status, "SYNTHETIC_ONLY")
                self.assertEqual(len(outbox), 1)
                self.assertEqual(outbox[0]["payload"]["identity"]["machine_id"], machine)
                self.assertEqual(outbox[0]["payload"]["identity"]["identity_source"], "list_container_group_instances")
                self.assertEqual(len(suppressed), 1)
                self.assertEqual(suppressed[0]["instance_id"], instance_b)
                self.assertEqual(telegram_calls, [])
            finally:
                watcher.close()

    def test_pool_episode_cuda_and_healthy_records_share_identity_pipeline(self):
        items = {org: [] for org in ORGANIZATIONS}
        rows = {}
        pool_instance = _instance_id(0, 0)
        pool_machine = _machine_id(0, 0, 0)
        cuda_instance = _instance_id(1, 0)
        cuda_machine = _machine_id(0, 1, 0)
        healthy_instance = _instance_id(2, 0)
        healthy_machine = _machine_id(0, 2, 0)
        pool_times = {
            "failed": "2026-10-13T12:00:00Z",
            "unstable": "2026-10-13T12:00:10Z",
            "recovery_marker": "2026-10-13T12:00:21Z",
            "recovered": "2026-10-13T12:00:22Z",
            "solutions": "2026-10-13T12:00:23Z",
        }
        items[ORGANIZATIONS[0]].extend((
            _log_item(
                ORGANIZATIONS[0], GROUPS[0], pool_instance, pool_times["failed"],
                _pool_line("POOL_CONNECTION_FAILED", timestamp=pool_times["failed"]),
            ),
            _log_item(
                ORGANIZATIONS[0], GROUPS[0], pool_instance, pool_times["unstable"],
                _pool_line(
                    "POOL_CONNECTION_UNSTABLE", timestamp=pool_times["unstable"], sequence=2,
                    first_failure=pool_times["failed"], latest_failure=pool_times["unstable"],
                ),
            ),
            _log_item(
                ORGANIZATIONS[0], GROUPS[0], pool_instance, pool_times["recovery_marker"],
                _pool_recovery_evidence(pool_times["recovery_marker"], pool_times["recovered"]),
            ),
            _log_item(
                ORGANIZATIONS[0], GROUPS[0], pool_instance, pool_times["solutions"], SOLUTION_LINE,
            ),
            _log_item(
                ORGANIZATIONS[0], GROUPS[0], pool_instance, pool_times["recovered"],
                _pool_line(
                    "POOL_CONNECTION_RECOVERED", timestamp=pool_times["recovered"], sequence=2,
                    first_failure=pool_times["failed"], latest_failure=pool_times["unstable"],
                ),
            ),
            _log_item(
                ORGANIZATIONS[0], GROUPS[1], cuda_instance, "2026-10-13T12:00:30Z",
                "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is insufficient for CUDA runtime version, OpenCL: <nil>).",
            ),
            _log_item(
                ORGANIZATIONS[0], GROUPS[2], healthy_instance, "2026-10-13T12:00:40Z",
                "Device [1] hashRate: 217.81 TH/s, stale: 0/0 (0.0%), warm: 0",
            ),
        ))
        rows[(ORGANIZATIONS[0], GROUPS[0])] = [
            {"instance_id": pool_instance, "machine_id": pool_machine},
        ]
        rows[(ORGANIZATIONS[0], GROUPS[1])] = [
            {"instance_id": cuda_instance, "machine_id": cuda_machine},
        ]
        rows[(ORGANIZATIONS[0], GROUPS[2])] = [
            {"instance_id": healthy_instance, "machine_id": healthy_machine},
        ]
        with tempfile.TemporaryDirectory() as temp:
            watcher, _exchanges, telegram_calls, _provider = self.make_watcher(temp, items, rows)
            try:
                result = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                self.assertEqual(result[0].status, "SYNTHETIC_ONLY")
                self.assertEqual(result[1].status, "SYNTHETIC_ONLY")
                outbox = watcher._ledgers[ORGANIZATIONS[0]].list_outbox()
                types = {row["payload"]["event_type"] for row in outbox}
                self.assertIn("POOL_CONNECTION_FAILED", types)
                self.assertIn("POOL_CONNECTION_UNSTABLE", types)
                self.assertIn("POOL_CONNECTION_RECOVERED", types)
                self.assertIn("CUDA_DRIVER_INCOMPATIBLE", types)
                self.assertNotIn("Device [1] hashRate", " ".join(row["message_text"] for row in outbox))
                for row in outbox:
                    payload = row["payload"]
                    identity = payload["identity"]
                    self.assertEqual(payload["data_classification"], "SYNTHETIC/UNVERIFIED")
                    self.assertFalse(payload["actions_performed"])
                    if identity["container_group_name"] == GROUPS[0]:
                        self.assertEqual(identity["instance_id"], pool_instance)
                        self.assertEqual(identity["machine_id"], pool_machine)
                    elif identity["container_group_name"] == GROUPS[1]:
                        self.assertEqual(identity["instance_id"], cuda_instance)
                        self.assertEqual(identity["machine_id"], cuda_machine)
                self.assertEqual(telegram_calls, [])
            finally:
                watcher.close()

    def test_missing_project_label_is_excluded_from_target_project_alerts(self):
        timestamp = "2026-10-13T12:00:00Z"
        item = _log_item(
            ORGANIZATIONS[0], GROUPS[0], _instance_id(0, 0), timestamp,
            _reallocation_line(77, timestamp),
        )
        item["resource"]["labels"].pop("project_name")
        with tempfile.TemporaryDirectory() as temp:
            watcher, exchanges, telegram_calls, _ = self.make_watcher(
                temp, {ORGANIZATIONS[0]: [item]}, {},
            )
            try:
                results = watcher.run_cycle(end_time_utc="2026-10-13T12:00:30Z")
                first_org = next(result for result in results if result.organization_name == ORGANIZATIONS[0])
                self.assertEqual(first_org.records_seen, 0)
                self.assertEqual(first_org.alerts_prepared, 0)
                self.assertEqual(first_org.group_lookups, 0)
                self.assertEqual(telegram_calls, [])
                self.assertEqual(len(exchanges[ORGANIZATIONS[0]].calls), 1)
            finally:
                watcher.close()

    def test_startup_fast_path_summary_is_separate_from_alerts_and_provider_identity(self):
        item = _log_item(
            ORGANIZATIONS[0], GROUPS[0], _instance_id(0, 0), "2026-10-13T12:00:05Z",
            "GPU=NVIDIA GeForce RTX 4070 Ti Laptop GPU Pearl autotune hashrate = 143.41 TH/s",
        )
        with tempfile.TemporaryDirectory() as temp:
            watcher, _exchanges, telegram_calls, _provider = self.make_watcher(
                temp, {ORGANIZATIONS[0]: [item]}, {},
            )
            try:
                results = watcher.run_cycle(end_time_utc="2026-10-13T12:01:00Z")
                result = next(row for row in results if row.organization_name == ORGANIZATIONS[0])
                self.assertEqual(result.early_signal_count, 1)
                self.assertEqual(result.early_unknown_count, 1)
                self.assertEqual(result.early_under_floor_count, 0)
                self.assertEqual(result.alerts_prepared, 0)
                # The existing provider-identity resolver still performs its
                # normal single scoped lookup for this instance. The startup
                # projection adds no lookup or alert of its own.
                self.assertEqual(result.group_lookups, 1)
                self.assertEqual(telegram_calls, [])
            finally:
                watcher.close()

    def test_one_watcher_accepts_100_organization_targets_without_spawning_or_connecting(self):
        targets = [FleetTarget(f"fleet-{index:03d}", PROJECT) for index in range(100)]
        secret_provider = SyntheticSecretProvider()
        sender = CentralTelegramSender.for_offline_test(
            credentials=SyntheticTelegramSecretProvider().acquire(),
            responder=lambda *_args: self.fail("watcher construction must not send Telegram"),
        )
        capability = authorize_live_invocation(
            mode="watch", enable_live_read=True, enable_central_telegram=True,
            confirmation="CENTRAL_FLEET_MONITOR",
        )
        with tempfile.TemporaryDirectory() as temp:
            watcher = CentralFleetWatcher(
                targets=targets,
                query='severity="ERROR"',
                state_dir=temp,
                secret_provider=secret_provider,
                sender=sender,
                capability=capability,
            )
            try:
                self.assertEqual(len(watcher.by_organization), 100)
                self.assertEqual(watcher._ledgers, {})
                self.assertEqual(watcher._transports, {})
                self.assertEqual(secret_provider.read_count, 0)
            finally:
                watcher.close()

    def test_targets_file_supports_many_scopes_and_rejects_credentials_or_unknown_fields(self):
        targets = [{"organization_name": f"org-{index:03d}", "project_name": PROJECT} for index in range(100)]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "targets.json"
            path.write_text(json.dumps(targets), encoding="utf-8")
            parsed = load_targets_file(path)
            self.assertEqual(len(parsed), 100)
            self.assertEqual(parsed[0], FleetTarget("org-000", PROJECT))

            for bad in (
                [{"organization_name": "org-secret", "project_name": PROJECT, "api_key": "do-not-store"}],
                [{"organization_name": "org-token", "project_name": PROJECT}],
                [{"organization_name": "a" + "b" * 40, "project_name": PROJECT}],
                [{"organization_name": "org-one", "project_name": PROJECT}, {"organization_name": "org-one", "project_name": PROJECT}],
                [{"organization_name": "org-one", "project_name": PROJECT}, {"organization_name": "org-one", "project_name": PROJECT.upper()}],
            ):
                path.write_text(json.dumps(bad), encoding="utf-8")
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    load_targets_file(path)
        with self.assertRaises(ValueError):
            parse_target("org-one:miners:extra")
        with self.assertRaises(ValueError):
            validate_targets([FleetTarget("org-one", PROJECT)] * 101)

    def test_live_invocation_requires_exact_read_and_delivery_gates(self):
        for kwargs in (
            {"mode": "watch", "enable_live_read": False, "enable_central_telegram": True,
             "confirmation": "CENTRAL_FLEET_MONITOR"},
            {"mode": "watch", "enable_live_read": True, "enable_central_telegram": False,
             "confirmation": "CENTRAL_FLEET_MONITOR"},
            {"mode": "watch", "enable_live_read": True, "enable_central_telegram": True,
             "confirmation": "wrong"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(Exception):
                authorize_live_invocation(**kwargs)

    def test_cli_blocks_before_secret_prompt_on_bad_confirmation_or_query(self):
        base = [
            "--watch-live-alerts", "--enable-live-read", "--enable-central-telegram",
            "--target", "fleet-alpha:miners", "--query", 'severity="ERROR"',
        ]
        output = io.StringIO()
        with (
            patch("sys.stdout", output),
            patch("sys.stdin.isatty", return_value=True),
            patch("log_alerts.live_cli._load_interactive_salad_provider", side_effect=AssertionError("secret prompt reached")),
        ):
            code = live_cli_main(base + ["--confirm-live", "incorrect"])
        self.assertEqual(code, 3)
        self.assertIn("EXPLICIT_LIVE_CONFIRMATION_REQUIRED", output.getvalue())

        output = io.StringIO()
        with (
            patch("sys.stdout", output),
            patch("sys.stdin.isatty", return_value=True),
            patch("log_alerts.live_cli._load_interactive_salad_provider", side_effect=AssertionError("secret prompt reached")),
        ):
            code = live_cli_main([
                "--watch-live-alerts", "--enable-live-read", "--enable-central-telegram",
                "--confirm-live", "CENTRAL_FLEET_MONITOR", "--target", "fleet-alpha:miners",
                "--query", "salad_api_key=synthetic-looking-but-forbidden",
            ])
        self.assertEqual(code, 2)
        self.assertIn("CONFIGURATION_INVALID", output.getvalue())
        self.assertNotIn("synthetic-looking-but-forbidden", output.getvalue())

    def test_default_cli_invocation_stays_offline_and_does_not_prompt(self):
        with (
            patch("log_alerts.live_cli._load_interactive_salad_provider", side_effect=AssertionError("secret prompt reached")),
            patch("log_alerts.live_transport.http.client.HTTPSConnection", side_effect=AssertionError("network opened")),
        ):
            code = live_cli_main([
                "--watch-live-alerts", "--target", "fleet-alpha:miners",
                "--query", 'severity="ERROR"',
            ])
        self.assertEqual(code, 2)

    def test_watcher_lock_allows_only_one_process_per_local_state_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            first = live_cli_module._acquire_watcher_lock(directory)
            try:
                with self.assertRaises(WatcherAlreadyRunning):
                    live_cli_module._acquire_watcher_lock(directory)
            finally:
                live_cli_module._release_watcher_lock(first)
            second = live_cli_module._acquire_watcher_lock(directory)
            live_cli_module._release_watcher_lock(second)


if __name__ == "__main__":
    unittest.main()
