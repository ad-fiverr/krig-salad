from __future__ import annotations

import csv
import hashlib
import ast
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

TELEMETRY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TELEMETRY_ROOT))

from collector.fl4shminer import (  # noqa: E402
    _classify,
    _stable_id,
    build_fl4shminer_snapshot,
    import_fl4shminer_csv,
)
from collector.fl4sh_early_autotune import (  # noqa: E402
    AssociationEvidenceRecord,
    BindingAttestation,
    EarlyCalibration,
    EarlyEvaluationContext,
    EarlyPolicy,
    MonitorPolicyEvidence,
    ObservationReference,
    ProviderBinding,
    association_evidence_sha256,
    monitor_policy_evidence_sha256,
)


def _synthetic_binding(reference, *, assignment_id, generation, valid_from, revalidated_at, policy_hash):
    record = AssociationEvidenceRecord(
        1, f"association-{generation}", "SYNTHETIC_TEST_ONLY", "VERIFIED", reference,
        assignment_id, generation, valid_from, revalidated_at + timedelta(seconds=30),
        revalidated_at, policy_hash,
        "synthetic-verifier", "test-v1", "",
    )
    record = AssociationEvidenceRecord(
        **{**record.__dict__, "evidence_sha256": association_evidence_sha256(record)}
    )
    binding = ProviderBinding(
        reference.device_index, reference.gpu_key, reference.organization, reference.project,
        reference.container_group, reference.machine_id, reference.instance_id,
        assignment_id, generation, valid_from, revalidated_at, policy_hash,
        source="SYNTHETIC_TEST_ONLY", observation_reference=reference,
        attestation=BindingAttestation(1, record.evidence_id, record.evidence_sha256),
        valid_until_utc=revalidated_at + timedelta(seconds=30),
    )
    return binding, record


class Fl4shMinerTests(unittest.TestCase):
    columns = [
        "Json Log message", "Text Log", "Resource labels instance id", "Time",
        "Resource labels machine id", "Json Log gpu class name",
        "Resource labels container group version", "Resource labels container group name",
        "Resource labels organization name", "Resource labels project name",
    ]

    def test_early_estimates_keep_signal_kind_and_do_not_become_real_hashrate(self):
        cuda = "2026/10/10 18:30:35 Device [1] CUDA autotune: 130.20 TH/s (measured pool-equivalent)"
        pearl = "2026/10/10 18:30:36 GPU=NVIDIA GeForce RTX 5090 Laptop GPU Pearl autotune hashrate = 148.5 TH/s"
        first_kind, first = _classify(cuda)
        second_kind, second = _classify(pearl)
        self.assertEqual((first_kind, second_kind), ("hashrate_estimate", "hashrate_estimate"))
        self.assertEqual((first["early_signal_type"], second["early_signal_type"]),
                         ("CUDA_POOL_EQUIVALENT", "PEARL_AUTOTUNE"))
        self.assertEqual((first["estimate_stage"], second["estimate_stage"]),
                         ("EARLY_STARTUP", "EARLY_STARTUP"))
        self.assertEqual(first["device_namespace"], "fl4shminer_device")
        self.assertEqual(second["device_namespace"], "unknown")
        self.assertFalse(first["worker_hashrate"] or second["worker_hashrate"])
        for invalid in ("arbitrary " + cuda, cuda + " suffix", cuda.replace("130.20", "nan"),
                        pearl.replace("148.5", "0")):
            self.assertIsNone(_classify(invalid))

    def test_exact_cuda_fatal_becomes_startup_unqualified_and_near_miss_does_not(self):
        fatal = (
            "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is "
            "insufficient for CUDA runtime version, OpenCL: <nil>)."
        )
        classified = _classify(fatal)
        self.assertEqual(classified[0], "startup_failure")
        self.assertEqual(classified[1]["startup_failure_reason"], "CUDA_DRIVER_VERSION_INSUFFICIENT")
        self.assertIsNone(_classify(fatal.replace("insufficient", "unknown")))

    def test_normal_collector_flow_emits_early_decision_before_full_hash_window(self):
        identity = {
            "Resource labels instance id": "instance-a",
            "Resource labels machine id": "machine-a",
            "Resource labels container group version": "version-a",
            "Resource labels container group name": "fl4shminer",
            "Resource labels organization name": "org-a",
            "Resource labels project name": "miners",
        }
        rows = [
            {
                **identity,
                "Time": "2026-10-18T11:59:50Z",
                "Text Log": "2026/10/18 11:59:50 starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://pool.example:7048 device=0",
            },
            {
                **identity,
                "Time": "2026-10-18T11:59:52Z",
                "Text Log": "FL4SH_MONITOR state=CONFIG enabled=true floor=120 floor_source=DEFAULT policy_hash=" + "a" * 64 + " actions_performed=false",
            },
            {
                **identity,
                "Time": "2026-10-18T11:59:55Z",
                "Text Log": "2026/10/18 11:59:55 Device [1] NVIDIA GeForce RTX 5090 Laptop GPU: Initialized",
            },
            {
                **identity,
                "Time": "2026-10-18T11:59:58Z",
                "Text Log": "2026/10/18 11:59:58 Device [1] CUDA autotune: 80.0 TH/s (measured pool-equivalent)",
            },
            {
                **identity,
                "Time": "2026-10-18T12:00:05Z",
                "Text Log": "2026/10/18 12:00:05 Device [1] hashRate: 150.0 TH/s, stale: 0/10 (0.0%), warm: 0",
            },
        ]
        now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write_csv(Path(temporary) / "early.csv", rows)
            source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            policy_evidence = MonitorPolicyEvidence(
                _stable_id("fl4sh-source-event", [source_hash, 3, "monitor_config"]),
                source_hash, 3, "org-a", "miners", "fl4shminer", "version-a", "machine-a", "instance-a",
                _stable_id("fl4sh-source-event", [source_hash, 2, "worker_start"]),
                "2026-10-18T11:59:50Z", "2026-10-18T11:59:52Z", "a" * 64,
            )
            reference = ObservationReference(
                _stable_id("fl4sh-source-event", [source_hash, 5, "hashrate_estimate"]),
                source_hash,
                5,
                "org-a",
                "miners",
                "fl4shminer",
                "version-a",
                "machine-a",
                "instance-a",
                "fl4shminer_device",
                1,
                "RTX_5090_LAPTOP",
                _stable_id("fl4sh-source-event", [source_hash, 4, "gpu_initialized"]),
                _stable_id("fl4sh-source-event", [source_hash, 2, "worker_start"]),
                "2026-10-18T11:59:50Z",
                monitor_policy_evidence_sha256(policy_evidence),
            )
            binding, association_record = _synthetic_binding(
                reference, assignment_id="assignment-a", generation="generation-a",
                valid_from=datetime(2026, 10, 18, 11, 59, tzinfo=timezone.utc),
                revalidated_at=now, policy_hash="a" * 64,
            )
            calibration = EarlyCalibration(
                "CUDA_POOL_EQUIVALENT", "RTX_5090_LAPTOP", 0.9, 1.1, 40,
                now.replace(hour=0), now.replace(day=19), "a" * 64, "b" * 64,
                "SYNTHETIC_TEST_ONLY",
            )
            context = EarlyEvaluationContext(
                policy=EarlyPolicy("a" * 64, {"RTX_5090_LAPTOP": 120.0}, 2.0),
                bindings=(binding,),
                association_records=(association_record,),
                calibrations=(calibration,),
                now_utc=now,
                allow_synthetic_calibration_for_test=True,
                allow_synthetic_binding_evidence_for_test=True,
            )
            parsed = import_fl4shminer_csv(path, recorded_at_utc=now.isoformat(), early_context=context)

        early_event = next(event for event in parsed.events if event["event_type"] == "hashrate_estimate")
        actual_event = next(event for event in parsed.events if event["event_type"] == "gpu_sample")
        self.assertEqual(early_event["early_decision"]["state"], "EARLY_UNDER_FLOOR")
        self.assertEqual(early_event["early_decision"]["signal_type"], "CUDA_POOL_EQUIVALENT")
        self.assertFalse(early_event["early_decision"]["actions_performed"])
        self.assertFalse(early_event["early_decision"]["action_eligible"])
        self.assertEqual(actual_event["payload"]["hashrate_ths"], 150.0)
        self.assertEqual(actual_event["payload"]["hashrate_semantics"], "fl4shminer_device_reported")
        self.assertNotIn("early_decision", actual_event)

    def test_two_machines_with_same_device_gpu_time_and_policy_do_not_cross_bind(self):
        def rows_for(machine: str, instance: str) -> list[dict[str, str]]:
            identity = {
                "Resource labels instance id": instance,
                "Resource labels machine id": machine,
                "Resource labels container group version": "version-a",
                "Resource labels container group name": "fl4shminer",
                "Resource labels organization name": "org-a",
                "Resource labels project name": "miners",
            }
            return [
                {**identity, "Time": "2026-10-18T11:59:50Z",
                 "Text Log": "2026/10/18 11:59:50 starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://pool.example:7048 device=0"},
                {**identity, "Time": "2026-10-18T11:59:52Z",
                 "Text Log": "FL4SH_MONITOR state=CONFIG enabled=true floor=120 floor_source=DEFAULT policy_hash=" + "a" * 64 + " actions_performed=false"},
                {**identity, "Time": "2026-10-18T11:59:55Z",
                 "Text Log": "2026/10/18 11:59:55 Device [1] NVIDIA GeForce RTX 5090 Laptop GPU: Initialized"},
                {**identity, "Time": "2026-10-18T11:59:58Z",
                 "Text Log": "2026/10/18 11:59:58 Device [1] CUDA autotune: 80.0 TH/s (measured pool-equivalent)"},
            ]

        now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write_csv(Path(temporary) / "two-machines.csv",
                                   rows_for("machine-a", "instance-a") + rows_for("machine-b", "instance-b"))
            source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            policy_evidence = MonitorPolicyEvidence(
                _stable_id("fl4sh-source-event", [source_hash, 7, "monitor_config"]),
                source_hash, 7, "org-a", "miners", "fl4shminer", "version-a", "machine-b", "instance-b",
                _stable_id("fl4sh-source-event", [source_hash, 6, "worker_start"]),
                "2026-10-18T11:59:50Z", "2026-10-18T11:59:52Z", "a" * 64,
            )
            binding_reference = ObservationReference(
                _stable_id("fl4sh-source-event", [source_hash, 9, "hashrate_estimate"]),
                source_hash, 9, "org-a", "miners", "fl4shminer", "version-a", "machine-b", "instance-b",
                "fl4shminer_device", 1, "RTX_5090_LAPTOP",
                _stable_id("fl4sh-source-event", [source_hash, 8, "gpu_initialized"]),
                _stable_id("fl4sh-source-event", [source_hash, 6, "worker_start"]),
                "2026-10-18T11:59:50Z",
                monitor_policy_evidence_sha256(policy_evidence),
            )
            binding, association_record = _synthetic_binding(
                binding_reference, assignment_id="assignment-b", generation="generation-b",
                valid_from=datetime(2026, 10, 18, 11, 59, tzinfo=timezone.utc),
                revalidated_at=now, policy_hash="a" * 64,
            )
            calibration = EarlyCalibration(
                "CUDA_POOL_EQUIVALENT", "RTX_5090_LAPTOP", 0.9, 1.1, 40,
                now.replace(hour=0), now.replace(day=19), "a" * 64, "b" * 64, "SYNTHETIC_TEST_ONLY",
            )
            context = EarlyEvaluationContext(
                policy=EarlyPolicy("a" * 64, {"RTX_5090_LAPTOP": 120.0}, 2.0),
                bindings=(binding,), association_records=(association_record,),
                calibrations=(calibration,), now_utc=now,
                allow_synthetic_calibration_for_test=True,
                allow_synthetic_binding_evidence_for_test=True,
            )
            parsed = import_fl4shminer_csv(path, recorded_at_utc=now.isoformat(), early_context=context)

        decisions_by_machine = {
            event["machine_id"]: event["early_decision"]
            for event in parsed.events if event["event_type"] == "hashrate_estimate"
        }
        self.assertEqual(decisions_by_machine["machine-a"]["reason"], "BINDING_SOURCE_CONFLICT")
        self.assertEqual(decisions_by_machine["machine-a"]["state"], "EARLY_UNKNOWN")
        self.assertEqual(decisions_by_machine["machine-b"]["state"], "EARLY_UNDER_FLOOR")
        self.assertFalse(any(item["action_eligible"] or item["actions_performed"]
                             for item in decisions_by_machine.values()))

    def test_unindexed_pearl_and_missing_context_emit_unknown_not_binding_claim(self):
        identity = {
            "Resource labels instance id": "instance-a",
            "Resource labels machine id": "machine-a",
            "Resource labels container group version": "version-a",
            "Resource labels container group name": "fl4shminer",
            "Resource labels organization name": "org-a",
            "Resource labels project name": "miners",
        }
        rows = [
            {**identity, "Time": "2026-10-18T11:59:50Z",
             "Text Log": "2026/10/18 11:59:50 starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://pool.example:7048 device=0"},
            {**identity, "Time": "2026-10-18T11:59:55Z",
             "Text Log": "2026/10/18 11:59:55 GPU=NVIDIA GeForce RTX 5090 Laptop GPU Pearl autotune hashrate = 80.0 TH/s"},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(
                self._write_csv(Path(temporary) / "pearl.csv", rows),
                recorded_at_utc="2026-10-18T12:00:00Z",
            )
        estimate = next(event for event in parsed.events if event["event_type"] == "hashrate_estimate")
        self.assertEqual(estimate["early_decision"]["state"], "EARLY_UNKNOWN")
        self.assertEqual(estimate["early_decision"]["reason"], "POLICY_UNAVAILABLE")
        self.assertIsNone(estimate["early_decision"]["device_index"])
        self.assertFalse(estimate["early_decision"]["action_eligible"])

    def test_monitor_policy_declaration_must_be_unique_well_formed_and_same_startup_episode(self):
        identity = {
            "Resource labels instance id": "instance-a",
            "Resource labels machine id": "machine-a",
            "Resource labels container group version": "version-a",
            "Resource labels container group name": "fl4shminer",
            "Resource labels organization name": "org-a",
            "Resource labels project name": "miners",
        }
        now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
        context = EarlyEvaluationContext(
            policy=EarlyPolicy("a" * 64, {"RTX_5090_LAPTOP": 120.0}, 2.0),
            now_utc=now,
        )
        start = {**identity, "Time": "2026-10-18T11:59:50Z",
                 "Text Log": "2026/10/18 11:59:50 starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://pool.example:7048 device=0"}
        config = {**identity, "Time": "2026-10-18T11:59:52Z",
                  "Text Log": "FL4SH_MONITOR state=CONFIG enabled=true floor=120 floor_source=DEFAULT policy_hash=" + "a" * 64 + " actions_performed=false"}
        initialized = {**identity, "Time": "2026-10-18T11:59:55Z",
                       "Text Log": "2026/10/18 11:59:55 Device [1] NVIDIA GeForce RTX 5090 Laptop GPU: Initialized"}
        estimate = {**identity, "Time": "2026-10-18T11:59:58Z",
                    "Text Log": "2026/10/18 11:59:58 Device [1] CUDA autotune: 80.0 TH/s (measured pool-equivalent)"}

        cases = (
            ("missing", [start, initialized, estimate], "POLICY_EVIDENCE_UNVERIFIED"),
            ("malformed", [start, {**config, "Text Log": config["Text Log"].replace("a" * 64, "not-a-hash")}, initialized, estimate],
             "POLICY_EVIDENCE_UNVERIFIED"),
            ("ambiguous", [start, config, {**config, "Time": "2026-10-18T11:59:53Z"}, initialized, estimate],
             "POLICY_EVIDENCE_AMBIGUOUS"),
            ("wrong-machine", [start, {**config, "Resource labels machine id": "machine-b"}, initialized, estimate],
             "POLICY_EVIDENCE_UNVERIFIED"),
            ("wrong-policy", [start, {**config, "Text Log": config["Text Log"].replace("a" * 64, "c" * 64)}, initialized, estimate],
             "POLICY_MISMATCH"),
        )
        for name, rows, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                parsed = import_fl4shminer_csv(
                    self._write_csv(Path(temporary) / f"{name}.csv", rows),
                    recorded_at_utc=now.isoformat(), early_context=context,
                )
                decision = next(event for event in parsed.events if event["event_type"] == "hashrate_estimate")["early_decision"]
                self.assertEqual(decision["reason"], expected)
                self.assertFalse(decision["action_eligible"] or decision["actions_performed"])
                self.assertNotIn("FL4SH_MONITOR state=CONFIG", repr(decision))

        later_start = {**start, "Time": "2026-10-18T11:59:55Z",
                       "Text Log": "2026/10/18 11:59:55 starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://pool.example:7048 device=0"}
        later_initialized = {**initialized, "Time": "2026-10-18T11:59:56Z",
                             "Text Log": "2026/10/18 11:59:56 Device [1] NVIDIA GeForce RTX 5090 Laptop GPU: Initialized"}
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(
                self._write_csv(Path(temporary) / "previous-episode-config.csv",
                                [start, config, later_start, later_initialized, estimate]),
                recorded_at_utc=now.isoformat(), early_context=context,
            )
        decision = next(event for event in parsed.events if event["event_type"] == "hashrate_estimate")["early_decision"]
        self.assertEqual(decision["reason"], "POLICY_EVIDENCE_UNVERIFIED")

    def test_normal_collector_flow_maps_only_exact_cuda_fatal_to_startup_unqualified(self):
        identity = {
            "Resource labels instance id": "instance-a",
            "Resource labels machine id": "machine-a",
            "Resource labels container group version": "version-a",
            "Resource labels container group name": "fl4shminer",
            "Resource labels organization name": "org-a",
            "Resource labels project name": "miners",
        }
        fatal = (
            "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is "
            "insufficient for CUDA runtime version, OpenCL: <nil>)."
        )
        rows = [
            {**identity, "Time": "2026-10-18T11:59:50Z",
             "Text Log": "2026/10/18 11:59:50 starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://pool.example:7048 device=0"},
            {**identity, "Time": "2026-10-18T11:59:55Z", "Text Log": fatal},
            {**identity, "Time": "2026-10-18T11:59:56Z", "Text Log": fatal.replace("insufficient", "unknown")},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(
                self._write_csv(Path(temporary) / "cuda-fatal.csv", rows),
                recorded_at_utc="2026-10-18T12:00:00Z",
            )
        startup = next(event for event in parsed.events if event["event_type"] == "startup_failure")
        self.assertEqual(startup["early_decision"]["state"], "STARTUP_UNQUALIFIED")
        self.assertEqual(startup["early_decision"]["reason"], "CUDA_DRIVER_VERSION_INSUFFICIENT")
        self.assertFalse(startup["early_decision"]["actions_performed"])
        self.assertEqual(parsed.unrecognized_nonempty_rows, 1)

    def test_early_pass_is_not_overwritten_by_later_low_device_hashrate(self):
        identity = {
            "Resource labels instance id": "instance-a",
            "Resource labels machine id": "machine-a",
            "Resource labels container group version": "version-a",
            "Resource labels container group name": "fl4shminer",
            "Resource labels organization name": "org-a",
            "Resource labels project name": "miners",
        }
        rows = [
            {**identity, "Time": "2026-10-18T11:59:50Z",
             "Text Log": "2026/10/18 11:59:50 starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://pool.example:7048 device=0"},
            {**identity, "Time": "2026-10-18T11:59:52Z",
             "Text Log": "FL4SH_MONITOR state=CONFIG enabled=true floor=120 floor_source=DEFAULT policy_hash=" + "a" * 64 + " actions_performed=false"},
            {**identity, "Time": "2026-10-18T11:59:55Z",
             "Text Log": "2026/10/18 11:59:55 Device [1] NVIDIA GeForce RTX 5090 Laptop GPU: Initialized"},
            {**identity, "Time": "2026-10-18T11:59:58Z",
             "Text Log": "2026/10/18 11:59:58 Device [1] CUDA autotune: 150.0 TH/s (measured pool-equivalent)"},
            {**identity, "Time": "2026-10-18T11:59:59Z",
             "Text Log": "2026/10/18 11:59:59 Device [1] hashRate: 80.0 TH/s, stale: 0/10 (0.0%), warm: 0"},
        ]
        now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary:
            path = self._write_csv(Path(temporary) / "early-pass-low-observed.csv", rows)
            source_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            policy_evidence = MonitorPolicyEvidence(
                _stable_id("fl4sh-source-event", [source_hash, 3, "monitor_config"]),
                source_hash, 3, "org-a", "miners", "fl4shminer", "version-a", "machine-a", "instance-a",
                _stable_id("fl4sh-source-event", [source_hash, 2, "worker_start"]),
                "2026-10-18T11:59:50Z", "2026-10-18T11:59:52Z", "a" * 64,
            )
            reference = ObservationReference(
                _stable_id("fl4sh-source-event", [source_hash, 5, "hashrate_estimate"]),
                source_hash, 5, "org-a", "miners", "fl4shminer", "version-a", "machine-a", "instance-a",
                "fl4shminer_device", 1, "RTX_5090_LAPTOP",
                _stable_id("fl4sh-source-event", [source_hash, 4, "gpu_initialized"]),
                _stable_id("fl4sh-source-event", [source_hash, 2, "worker_start"]),
                "2026-10-18T11:59:50Z",
                monitor_policy_evidence_sha256(policy_evidence),
            )
            binding, association_record = _synthetic_binding(
                reference, assignment_id="assignment-a", generation="generation-a",
                valid_from=datetime(2026, 10, 18, 11, 59, tzinfo=timezone.utc),
                revalidated_at=now, policy_hash="a" * 64,
            )
            calibration = EarlyCalibration(
                "CUDA_POOL_EQUIVALENT", "RTX_5090_LAPTOP", 0.9, 1.1, 40,
                now.replace(hour=0), now.replace(day=19), "a" * 64, "b" * 64, "SYNTHETIC_TEST_ONLY",
            )
            context = EarlyEvaluationContext(
                policy=EarlyPolicy("a" * 64, {"RTX_5090_LAPTOP": 120.0}, 2.0),
                bindings=(binding,), association_records=(association_record,),
                calibrations=(calibration,), now_utc=now,
                allow_synthetic_calibration_for_test=True,
                allow_synthetic_binding_evidence_for_test=True,
            )
            parsed = import_fl4shminer_csv(path, recorded_at_utc=now.isoformat(), early_context=context)

        estimate = next(event for event in parsed.events if event["event_type"] == "hashrate_estimate")
        observed = next(event for event in parsed.events if event["event_type"] == "gpu_sample")
        self.assertEqual(estimate["early_decision"]["state"], "EARLY_PASS")
        self.assertEqual(estimate["early_decision"]["estimate_ths"], 150.0)
        self.assertEqual(observed["payload"]["hashrate_ths"], 80.0)
        self.assertEqual(observed["payload"]["hashrate_semantics"], "fl4shminer_device_reported")
        self.assertNotIn("early_decision", observed)
        self.assertFalse(estimate["early_decision"]["action_eligible"])

    def test_early_classifier_has_no_network_or_mutation_dependencies(self):
        forbidden_roots = {"firebase", "firebase_admin", "requests", "httpx", "telegram", "salad"}
        paths = (
            TELEMETRY_ROOT / "collector" / "fl4shminer.py",
            TELEMETRY_ROOT / "collector" / "fl4sh_early_autotune.py",
        )
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".", 1)[0] for alias in node.names}
                    self.assertFalse(roots & forbidden_roots, path.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".", 1)[0]
                    self.assertNotIn(root, forbidden_roots, path.name)

    def _write_csv(self, path: Path, rows: list[dict[str, str]]) -> Path:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.columns)
            writer.writeheader()
            writer.writerows(rows)
        return path

    def _rows(self) -> list[dict[str, str]]:
        identity = {
            "Resource labels instance id": "instance-a",
            "Resource labels machine id": "machine-a",
            "Resource labels container group version": "13",
            "Resource labels container group name": "fl4shminer",
        }
        return [
            {
                **identity,
                "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
                "Time": "10/10/2026, 6:30:00 PM",
                "Text Log": "2026/10/10 18:30:00 Starting Fl4shMiner v1.5.2: coin=PRL pool=stratum+tcp://prl-us.kryptex.network:7048 device=0",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:30:30 PM",
                "Text Log": "2026/10/10 18:30:30 Device [1] hashRate: 150.00 TH/s, stale: 3/100 (3.0%), warm: 0",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:30:35 PM",
                "Text Log": "2026/10/10 18:30:35 Device [1] CUDA autotune: 130.20 TH/s (measured pool-equivalent)",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:30:36 PM",
                "Text Log": "2026/10/10 18:30:36 GPU=NVIDIA GeForce RTX 5090 Laptop Pearl autotune hashrate = 148.5 TH/s",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:31:00 PM",
                "Text Log": "2026/10/10 18:31:00 Solutions accepted: 1-NVIDIA GeForce RTX 5090 Laptop GPU, 0xabc, pool=stratum+tcp://prl-us.kryptex.network:7048, proof=bbb902fd",
            },
            {
                **identity,
                "Time": "10/10/2026, 6:31:10 PM",
                "Text Log": "2026/10/10 18:31:10 Solutions rejected: 1-NVIDIA GeForce RTX 5090 Laptop GPU, 0xdef, pool=stratum+tcp://prl-us.kryptex.network:7048, status=stale, reason=Stale",
            },
            {
                **identity,
                "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
                "Time": "10/10/2026, 6:31:30 PM",
                "Text Log": "2026/10/10 18:31:30 Device [1] hashRate: 151.00 TH/s, stale: 4/120 (3.3%), warm: 0",
            },
            {
                **identity,
                "Json Log gpu class name": "NVIDIA GeForce RTX 5090 Laptop (24 GB)",
                "Time": "10/10/2026, 6:32:00 PM",
                "Text Log": "",
            },
        ]

    def test_wrapper_and_miner_device_ids_keep_namespaces_without_splitting_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "run.csv", self._rows()))
        snapshot = build_fl4shminer_snapshot([parsed])
        self.assertEqual(len(snapshot["segments"]), 1)
        segment = snapshot["segments"][0]
        self.assertEqual(segment["gpu_identity"]["form_factor"], "laptop")
        self.assertTrue(segment["gpu_identity"]["identity_verified"])
        self.assertEqual(segment["gpu_sample_count"], 2)
        observations = {(item["namespace"], item["id"]) for item in segment["device_id_observations"]}
        self.assertIn(("salad_wrapper_device", "0"), observations)
        self.assertIn(("fl4shminer_device", "1"), observations)
        self.assertEqual({event["segment_id"] for event in snapshot["events"]}, {segment["segment_id"]})
        self.assertIn("wall_clock_anchor_timezone_unverified", segment["run_identity_status"])

    def test_hashrate_estimates_solutions_and_stale_counters_remain_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "run.csv", self._rows()))
        snapshot = build_fl4shminer_snapshot([parsed])
        events = snapshot["events"]
        device = next(event for event in events if event["event_type"] == "gpu_sample")
        estimates = [event for event in events if event["event_type"] == "hashrate_estimate"]
        accepted = next(event for event in events if event["event_type"] == "solution_accepted")
        rejected = next(event for event in events if event["event_type"] == "solution_rejected")
        segment = snapshot["segments"][0]
        self.assertEqual(device["payload"]["hashrate_ths"], 150.0)
        self.assertEqual(device["payload"]["hashrate_semantics"], "fl4shminer_device_reported")
        self.assertEqual({item["payload"]["hashrate_semantics"] for item in estimates}, {
            "fl4shminer_cuda_autotune_pool_equivalent_estimate", "pearl_autotune_estimate",
        })
        self.assertTrue(all(item["payload"]["worker_hashrate"] is False for item in estimates))
        self.assertEqual(accepted["payload"]["share_difficulty_value"], None)
        self.assertEqual(accepted["payload"]["solution_hex_interpretation"], "unverified_solution_field_not_difficulty")
        self.assertEqual(rejected["payload"]["reported_rejection_status"], "stale")
        self.assertEqual(segment["explicit_accepted_solution_count"], 1)
        self.assertEqual(segment["explicit_rejected_solution_count"], 1)
        work_segment = snapshot["work"]["segments"][0]
        self.assertEqual(work_segment["accepted_share_count"], 0)
        self.assertEqual(work_segment["explicit_share_accepted_count"], 0)
        self.assertEqual(work_segment["explicit_solution_accepted_count"], 1)
        self.assertEqual(work_segment["explicit_solution_rejected_count"], 1)
        self.assertEqual(len(segment["cumulative_stale_counter_observations"]), 2)
        self.assertTrue(all(not item["is_paid_share_count"] for item in segment["cumulative_stale_counter_observations"] if "is_paid_share_count" in item))
        self.assertEqual(segment["actual_kryptex_worker_hashrate_ths"], None)
        self.assertEqual(segment["actual_kryptex_worker_hashrate_status"], "not_observed_in_supported_records")
        self.assertEqual(segment["billing_status"], "UNKNOWN")

    def test_timezone_unverified_exports_do_not_cross_deduplicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows = self._rows()
            first = import_fl4shminer_csv(self._write_csv(root / "first.csv", rows))
            second_rows = self._rows()
            second_rows[-1]["Json Log message"] = "provider observation not consumed by the miner parser"
            second = import_fl4shminer_csv(self._write_csv(root / "second.csv", second_rows))
        snapshot = build_fl4shminer_snapshot([first, second])
        self.assertEqual(snapshot["report"]["segment_count"], 2)
        self.assertEqual(snapshot["report"]["deduplicated_event_count"], 0)
        self.assertEqual(snapshot["report"]["worker_hashrate_status"], "UNKNOWN_NOT_REPORTED_IN_SUPPORTED_RECORDS")

    def test_gpu_identity_is_scoped_to_each_complete_provider_assignment(self):
        desktop_rows = self._rows()[:2]
        desktop_rows[0]["Json Log gpu class name"] = "NVIDIA GeForce RTX 5090 Desktop (24 GB)"
        laptop_rows = self._rows()[:2]
        for row_item in laptop_rows:
            row_item["Resource labels instance id"] = "instance-b"
            row_item["Resource labels machine id"] = "machine-b"
            row_item["Time"] = row_item["Time"].replace("6:30", "6:31")
        all_rows = desktop_rows + laptop_rows
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "two-machines.csv", all_rows))
        snapshot = build_fl4shminer_snapshot([parsed])
        identities = {segment["machine_id"]: segment["gpu_identity"] for segment in snapshot["segments"]}
        self.assertEqual(len(identities), 2)
        self.assertEqual(identities["machine-a"]["form_factor"], "desktop")
        self.assertEqual(identities["machine-b"]["form_factor"], "laptop")
        self.assertTrue(all(identity["identity_verified"] for identity in identities.values()))

    def test_incomplete_provider_assignment_isolated_per_event_and_gpu_identity_unknown(self):
        rows = self._rows()[:2]
        for row_item in rows:
            row_item["Resource labels machine id"] = ""
        with tempfile.TemporaryDirectory() as temporary:
            parsed = import_fl4shminer_csv(self._write_csv(Path(temporary) / "incomplete.csv", rows))
        snapshot = build_fl4shminer_snapshot([parsed])
        self.assertEqual(len(snapshot["segments"]), 2)
        self.assertEqual(len({event["segment_id"] for event in snapshot["events"]}), 2)
        self.assertTrue(all(not segment["gpu_identity"]["identity_verified"] for segment in snapshot["segments"]))
        self.assertTrue(all(segment["run_identity_status"] == "incomplete_provider_assignment_event_isolated" for segment in snapshot["segments"]))


if __name__ == "__main__":
    unittest.main()
