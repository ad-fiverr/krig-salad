"""Backend service composing existing guard/economics code with G5 gates."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from collector.action_ledger import ActionLedger
from collector.auto_reallocation_gate import AutoReallocationGate, AutoReallocationLimits
from collector.continuous import ContinuousMonitor, fleet_monitor_event_feed
from collector.dashboard_projection import project_device, project_fleet
from collector.device_guard import inspect_monitor_source, load_monitor_events
from collector.fl4sh_early_autotune import (
    EarlyEvaluationContext,
    EarlyObservation,
    EarlyPolicy,
)
from collector.guard_store import GuardStore
from collector.guards import HashGuardPolicy
from collector.reallocation_controller import ReallocationController, ReallocationPolicy
from collector.salad_action_policy import SaladAction, SaladActionPolicy
from collector.startup_admission import StartupAdmissionEngine
from collector.startup_recovery_policy import StartupCause, StartupRecoveryPolicy
from collector.startup_latency import polling_comparison, reaction_exposure_comparison
from collector.v2_adapters import normalize_v2_evaluation

from .config import G5Config, GROUPS
from .store import ControlPlaneStore


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


_LIVE_GET_ERROR_MESSAGES = {
    "AUTHORIZATION_BLOCKED": "No valid signed GET authorization was available.",
    "BUDGET_EXHAUSTED": "The durable four-request ledger has no available slot.",
    "DEADLINE_BLOCKED": "The GET request deadline expired before completion.",
    "KILL_SWITCH_BLOCKED": "The read session was stopped by its kill switch.",
    "LEDGER_BLOCKED": "The durable GET ledger blocked the request.",
    "LIVE_GET_DISABLED": "The live read session is disabled.",
    "NOT_QUERIED": "This fixed group was not queried in this session.",
    "OUTCOME_UNCERTAIN": "The request outcome is uncertain; no retry was made.",
    "REQUEST_OUTCOME_UNCERTAIN": "The request outcome is uncertain; no retry was made.",
    "RESPONSE_REJECTED": "The response failed safe schema validation.",
    "SECRET_ACCESS_BLOCKED": "The hidden terminal secret provider blocked this request.",
}


def _fixed_group_instances_path(organization: str, project: str, group: str) -> str:
    """Return the existing fixed GET path for one of the four approved groups."""
    parts = tuple(quote(part, safe="-_.~") for part in (organization, project, group))
    return f"/api/public/organizations/{parts[0]}/projects/{parts[1]}/containers/{parts[2]}/instances"


def _early_gpu_floor_registry(floors: Mapping[str, Any]) -> dict[str, float]:
    """Map the existing exact G5 model/form-factor floors to EarlyDecision keys."""
    result: dict[str, float] = {}
    for source_key, raw_floor in floors.items():
        parts = source_key.split("|") if isinstance(source_key, str) else []
        if len(parts) != 3 or parts[1] not in {"laptop", "desktop"}:
            continue
        tokens = re.findall(r"[A-Za-z0-9]+", parts[0])
        if not tokens:
            continue
        key = "_".join(tokens).upper() + "_" + parts[1].upper()
        value = float(raw_floor)
        if key in result and result[key] != value:
            raise ValueError("G5 floor registry has a canonical EarlyDecision key collision")
        result[key] = value
    return result


class G5ControlPlaneService:
    """Local control API state; live Salad/Firebase capabilities stay unconfigured."""

    def __init__(
        self,
        config: G5Config,
        *,
        control_store: ControlPlaneStore | None = None,
        guard_store: GuardStore | None = None,
        action_ledger: ActionLedger | None = None,
        read_session: Any = None,
        offline_read_broker: Any = None,
        action_executor: Any = None,
        clock: Any = time.time,
    ):
        if type(config) is not G5Config:
            raise TypeError("G5 service requires validated local-only configuration")
        self.config = config
        self.store = control_store or ControlPlaneStore(":memory:")
        self.guard_store = guard_store or GuardStore(":memory:")
        self.guard_policy = HashGuardPolicy(
            gpu_floors_ths=dict(config.gpu_floors_ths),
            warmup_seconds=config.warmup_seconds,
            hash_window_seconds=config.hash_window_seconds,
            reevaluation_interval_seconds=config.reevaluation_interval_seconds,
            minimum_samples_per_window=config.minimum_samples_per_window,
            expected_sample_interval_seconds=config.expected_sample_interval_seconds,
            maximum_sample_gap_seconds=config.maximum_sample_gap_seconds,
            minimum_window_coverage_ratio=config.minimum_window_coverage_ratio,
            consecutive_bad_windows=config.consecutive_bad_windows,
            reallocation_cooldown_seconds=None,
            max_reallocations_per_run=None,
        )
        self.monitor = ContinuousMonitor(self.guard_store, self.guard_policy)
        self.action_ledger = action_ledger or ActionLedger(":memory:")
        self._auto_gate_reviews: dict[str, dict[str, Any]] = {}
        self.action_policy = SaladActionPolicy(hard_budget_usd=config.hard_budget_usd)
        self.read_session = read_session
        self.offline_read_broker = offline_read_broker
        self.action_executor = action_executor
        self._clock = clock
        self._lock = threading.RLock()
        self._kill_switch_engaged = bool(config.kill_switch_engaged)
        self._auto_armed = False
        self._simulation_armed = False
        self._simulation_limits: AutoReallocationLimits | None = None
        self.auto_reallocation_gate = self._build_auto_reallocation_gate()
        self._bindings: dict[str, dict[str, Any]] = {}
        self._fleet_records: list[dict[str, Any]] = []
        self._controller_decisions: dict[str, dict[str, Any]] = {}
        self.startup_admission_engine = StartupAdmissionEngine(
            StartupRecoveryPolicy.from_env()
        )
        self._last_startup_preview: dict[str, Any] | None = None
        self.reallocation_controller = ReallocationController(
            ReallocationPolicy(
                allowed_targets=(),
                gpu_floors_ths=dict(config.gpu_floors_ths),
                maximum_telemetry_age_seconds=config.maximum_sample_gap_seconds,
                minimum_window_coverage_ratio=config.minimum_window_coverage_ratio,
                maximum_sample_gap_seconds=config.maximum_sample_gap_seconds,
                evaluation_max_age_seconds=(
                    config.maximum_sample_gap_seconds
                    + config.reevaluation_interval_seconds * config.consecutive_bad_windows
                ),
                cooldown_seconds=None,
                maximum_per_assignment=None,
                maximum_per_fleet=None,
                budget_limit_usd=min(float(config.hard_budget_usd), 30.0),
                action_enabled=False,
                g5_authorized=False,
            ),
            self.action_ledger,
            guard_policy_hash=self.monitor.policy_hash,
        )
        self._closed = False
        self.action_ledger.update_auto_reallocation_simulation_control(
            armed=False,
            event_type="SERVICE_START_CLOSED",
            kill_switch_engaged=self._kill_switch_engaged,
            live_actions_enabled=config.live_actions_enabled,
            g5_authorized=False,
            at_utc=_now_utc(),
        )
        self.store.append_audit(
            "CONTROL_PLANE_STARTED",
            {"mode": config.mode, "host": config.host, "port": config.port, "live_get_enabled": False, "live_actions_enabled": False},
            _now_utc(),
        )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._simulation_armed:
                self.disarm_auto_reallocation_simulation()
            self._closed = True
            self.action_ledger.close()
            self.guard_store.close()
            self.store.close()

    def _build_auto_reallocation_gate(self) -> AutoReallocationGate:
        return AutoReallocationGate(
            self.action_ledger,
            policy_hash=self.monitor.policy_hash,
            gpu_floors_ths=_early_gpu_floor_registry(self.config.gpu_floors_ths),
            limits=self._simulation_limits or AutoReallocationLimits(),
            hard_budget_cap_usd=min(float(self.config.hard_budget_usd), 30.0),
            maximum_evidence_age_seconds=(
                self.config.maximum_sample_gap_seconds
                + self.config.reevaluation_interval_seconds * self.config.consecutive_bad_windows
            ),
            simulation_enabled=self._simulation_armed,
        )

    def arm_auto_reallocation_simulation(self, limits: AutoReallocationLimits) -> dict[str, Any]:
        """Enable only the internal synthetic admission path; no HTTP surface calls this."""
        with self._lock:
            permitted = (
                type(limits) is AutoReallocationLimits
                and limits.complete()
                and not self._kill_switch_engaged
                and self.config.live_actions_enabled is False
                and self._auto_armed is False
            )
            if not permitted:
                self._simulation_armed = False
                self._simulation_limits = None
                self.auto_reallocation_gate = self._build_auto_reallocation_gate()
                self.action_ledger.update_auto_reallocation_simulation_control(
                    armed=False, event_type="SIMULATION_ARM_BLOCKED",
                    kill_switch_engaged=self._kill_switch_engaged,
                    live_actions_enabled=self.config.live_actions_enabled,
                    g5_authorized=False, at_utc=_now_utc(),
                )
                return {"status": "BLOCKED", "simulation_armed": False, "actions_performed": False}
            # Build the gate before committing the armed bit so malformed settings
            # cannot leave a durable control record open.
            previous_limits = self._simulation_limits
            self._simulation_limits = limits
            try:
                gate = self._build_auto_reallocation_gate_for(True, limits)
            except Exception:
                self._simulation_limits = previous_limits
                self.action_ledger.update_auto_reallocation_simulation_control(
                    armed=False, event_type="SIMULATION_ARM_BLOCKED",
                    kill_switch_engaged=self._kill_switch_engaged,
                    live_actions_enabled=self.config.live_actions_enabled,
                    g5_authorized=False, at_utc=_now_utc(),
                )
                return {"status": "BLOCKED", "simulation_armed": False, "actions_performed": False}
            try:
                self.action_ledger.update_auto_reallocation_simulation_control(
                    armed=True, event_type="SIMULATION_ARMED",
                    kill_switch_engaged=False, live_actions_enabled=False,
                    g5_authorized=False, at_utc=_now_utc(), limits=limits.as_ledger_limits(),
                )
            except Exception:
                self._simulation_limits = previous_limits
                self._simulation_armed = False
                self.auto_reallocation_gate = self._build_auto_reallocation_gate()
                return {"status": "BLOCKED", "simulation_armed": False, "actions_performed": False}
            self._simulation_limits = limits
            self._simulation_armed = True
            self.auto_reallocation_gate = gate
            self.store.append_audit("AUTO_REALLOCATION_SIMULATION_ARMED", {
                "status": "SIMULATION_ARMED", "simulation_only": True,
                "actions_performed": False, "request_submitted": False,
            }, _now_utc())
            return {"status": "SIMULATION_ARMED", "simulation_armed": True, "actions_performed": False}

    def _build_auto_reallocation_gate_for(
        self, armed: bool, limits: AutoReallocationLimits,
    ) -> AutoReallocationGate:
        return AutoReallocationGate(
            self.action_ledger,
            policy_hash=self.monitor.policy_hash,
            gpu_floors_ths=_early_gpu_floor_registry(self.config.gpu_floors_ths),
            limits=limits,
            hard_budget_cap_usd=min(float(self.config.hard_budget_usd), 30.0),
            maximum_evidence_age_seconds=(
                self.config.maximum_sample_gap_seconds
                + self.config.reevaluation_interval_seconds * self.config.consecutive_bad_windows
            ),
            simulation_enabled=armed,
        )

    def disarm_auto_reallocation_simulation(self) -> dict[str, Any]:
        with self._lock:
            self._simulation_armed = False
            self._simulation_limits = None
            self.auto_reallocation_gate = self._build_auto_reallocation_gate()
            self.action_ledger.update_auto_reallocation_simulation_control(
                armed=False, event_type="SIMULATION_DISARMED",
                kill_switch_engaged=self._kill_switch_engaged,
                live_actions_enabled=self.config.live_actions_enabled,
                g5_authorized=False, at_utc=_now_utc(),
            )
            self.store.append_audit("AUTO_REALLOCATION_SIMULATION_DISARMED", {
                "status": "SIMULATION_DISARMED", "simulation_only": True,
                "actions_performed": False, "request_submitted": False,
            }, _now_utc())
            return {"status": "SIMULATION_DISARMED", "simulation_armed": False, "actions_performed": False}

    def simulate_auto_reallocation_transport(
        self, simulation_key: str, *, outcome: str, at_utc: str,
    ) -> dict[str, Any]:
        """Drive a bounded fake outcome; this method never calls the action executor."""
        with self._lock:
            if (
                not self._simulation_armed or self._kill_switch_engaged
                or self.config.live_actions_enabled is not False or self._auto_armed
            ):
                return {"status": "BLOCKED", "reason": "SIMULATION_GATE_CLOSED", "actions_performed": False}
            return self.action_ledger.record_auto_reallocation_simulation_transport(
                simulation_key, outcome=outcome, at_utc=at_utc,
            )

    def ingest_miner_events(self, events: list[Mapping[str, Any]]) -> dict[str, Any]:
        """Feed verified local workload events into the existing ContinuousMonitor."""
        with self._lock:
            result = self.monitor.ingest(events)
            control_cycle = self.evaluate_control_cycle()
            self.store.append_audit(
                "MINER_EVENTS_INGESTED",
                {
                    "inserted_sample_count": result["inserted_sample_count"],
                    "duplicate_sample_count": result["duplicate_sample_count"],
                    "controller_decision_count": control_cycle["decision_count"],
                    "actions_performed": False,
                },
                _now_utc(),
            )
            return result

    def ingest_configured_local_events(self) -> dict[str, Any]:
        """Incrementally ingest only source paths explicitly configured by the operator."""
        paths = tuple(Path(item).expanduser().resolve(strict=True) for item in self.config.local_telemetry_sources)
        if not paths:
            return {"status": "NO_CONFIGURED_SOURCES", "source_count": 0, "inserted_sample_count": 0, "actions_performed": False}
        normalized_paths = [os.path.normcase(str(path)).replace("\\", "/") for path in paths]
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError("configured local telemetry sources resolve to duplicate files")

        snapshots: list[tuple[dict[str, Any], dict[str, Any]]] = []
        contexts: dict[str, Mapping[str, Any]] = {}
        for path in paths:
            snapshot = inspect_monitor_source(path)
            cursor = self.guard_store.begin_source_cursor(snapshot)
            snapshots.append((snapshot, cursor))
            contexts[snapshot["source_path_key"]] = cursor
        events = load_monitor_events(paths, source_contexts=contexts)
        result = self.ingest_miner_events(events) if events else {
            "inserted_sample_count": 0,
            "duplicate_sample_count": 0,
            "lifecycle_event_count": 0,
            "identity_invalidated_track_count": 0,
            "terminated_track_ids": [],
            "evaluations": [],
            "actions_performed": False,
        }
        # Commit cursors only after monitor ingestion. A crash before this point
        # replays deterministic event IDs and is harmlessly idempotent.
        cursor_updates = []
        for snapshot, cursor in snapshots:
            self.guard_store.commit_source_cursor(snapshot, cursor)
            cursor_updates.append({
                "source_id": cursor["source_id"],
                "source_format": cursor["source_format"],
                "generation": cursor["generation"],
                "previous_row_count": cursor["start_row_count"],
                "current_row_count": cursor["current_row_count"],
                "reset_detected": cursor["reset_detected"],
            })
        self.store.append_audit(
            "LOCAL_TELEMETRY_SOURCE_INGESTED",
            {
                "source_count": len(paths),
                "event_count": len(events),
                "cursor_updates": cursor_updates,
                "inserted_sample_count": result["inserted_sample_count"],
                "actions_performed": False,
            },
            _now_utc(),
        )
        return {"status": "INGESTED", "source_count": len(paths), "event_count": len(events), **result}

    def _budget_for_controller(self) -> dict[str, Any]:
        summary = self.store.budget_summary()
        return {
            "status": summary.get("status"),
            "currency": summary.get("currency"),
            "verified_spend_usd": summary.get("verified_spend_usd"),
            "verified_next_action_cost_usd": summary.get("verified_next_action_cost_usd"),
            "pending_exposure_usd": summary.get("pending_exposure_usd"),
            "pending_exposure_status": summary.get("pending_exposure_status"),
            "pending_exposure_evidence_id": summary.get("pending_exposure_evidence_id"),
            "maximum_exposure_usd": summary.get("maximum_exposure_usd"),
            "maximum_exposure_status": summary.get("maximum_exposure_status"),
            "maximum_exposure_evidence_id": summary.get("maximum_exposure_evidence_id"),
            "spend_evidence_id": summary.get("spend_evidence_id"),
            "spend_source_reference": summary.get("spend_source_reference"),
            "spend_observed_at_utc": summary.get("spend_observed_at_utc"),
            "next_action_cost_evidence_id": summary.get("action_cost_evidence_id"),
            "next_action_cost_source_reference": summary.get("action_cost_source_reference"),
            "next_action_cost_observed_at_utc": summary.get("action_cost_observed_at_utc"),
            "valid_until_utc": summary.get("action_cost_valid_until_utc"),
        }

    def evaluate_control_cycle(self, at_utc: str | None = None) -> dict[str, Any]:
        """Refresh the existing continuous monitor and preview reallocation eligibility only."""
        with self._lock:
            timestamp = at_utc or _now_utc()
            evaluations_added = self.monitor.evaluate_all(timestamp)
            tracks = self.guard_store.track_rows(active_only=True)
            decisions: dict[str, dict[str, Any]] = {}
            budget = self._budget_for_controller()
            for track in tracks:
                try:
                    identity = json.loads(track.get("gpu_identity_json") or "{}")
                except (TypeError, ValueError):
                    identity = {}
                eval_rows = self.guard_store.evaluations_for_track(track["track_id"])
                # Historical evaluations remain stored across a restart, but a
                # changed policy hash requires fresh evaluations before the
                # controller can consider the track again.
                evaluations = [
                    normalized
                    for item in eval_rows
                    if (normalized := normalize_v2_evaluation(item)).get("policy_hash") == self.monitor.policy_hash
                ]
                last = evaluations[-1] if evaluations else {}
                candidate = {
                    "track_id": track["track_id"],
                    "allocation_id": track.get("allocation_id"),
                    "assignment_id": track.get("assignment_id"),
                    "device_namespace": track.get("device_namespace"),
                    "device_id": track.get("device_id"),
                    "track_active": track.get("closed_at_utc") is None,
                    "gpu_identity": identity if isinstance(identity, Mapping) else {},
                    "gpu_floor_ths": last.get("gpu_floor_ths"),
                    "guard_policy_hash": self.monitor.policy_hash,
                    "deterioration_start_utc": last.get("deterioration_start_utc"),
                    # Provider identifiers must come from a separately
                    # attested provider binding; local miner IDs are not copied.
                    "organization_id": None,
                    "project_id": None,
                    "container_group_id": None,
                    "instance_id": None,
                    "machine_id": None,
                }
                samples = self.guard_store.samples_for_track(track["track_id"])
                sample = samples[-1] if samples else {}
                revalidated_sample = {
                    **sample,
                    "track_id": track["track_id"],
                    "allocation_id": track.get("allocation_id"),
                    "assignment_id": track.get("assignment_id"),
                    "machine_id": track.get("machine_id"),
                    "instance_id": track.get("instance_id"),
                    "device_namespace": track.get("device_namespace"),
                    "device_id": track.get("device_id"),
                    "gpu_identity": identity if isinstance(identity, Mapping) else {},
                    "monitor_policy_hash": self.monitor.policy_hash,
                }
                history_known = track.get("reallocation_history_known") == 1
                allocation_history = {
                    "history_known": history_known,
                    "allocation_reallocation_count": track.get("reallocation_count") if history_known else None,
                    "fleet_reallocation_count": None,
                    "last_reallocation_at_utc": track.get("last_reallocation_utc"),
                }
                assessment = self.reallocation_controller.assess(
                    candidate=candidate,
                    evaluations=evaluations,
                    provider_revalidation={},
                    revalidated_sample=revalidated_sample,
                    allocation_history=allocation_history,
                    budget=budget,
                    now_utc=timestamp,
                    reserve_action=False,
                )
                decisions[track["track_id"]] = assessment
                self.store.append_audit(
                    "REALLOCATION_ELIGIBILITY_REVIEWED",
                    {
                        "track_id": track["track_id"],
                        "eligibility": assessment.get("eligibility"),
                        "blockers": assessment.get("blockers", []),
                        "policy_hash": self.monitor.policy_hash,
                        "actions_performed": False,
                    },
                    timestamp,
                )
            self._controller_decisions = decisions
            return {
                "status": "EVALUATED",
                "evaluations_added": len(evaluations_added),
                "decision_count": len(decisions),
                "eligible_count": sum(item.get("eligibility") == "CANDIDATE" for item in decisions.values()),
                "actions_performed": False,
            }

    def preview_auto_reallocation(
        self,
        trigger_kind: str,
        *,
        trigger_evidence: Mapping[str, Any],
        source_evidence: Mapping[str, Any],
        policy_evidence: Mapping[str, Any],
        generation_evidence: Mapping[str, Any],
        provider_binding: Mapping[str, Any],
        provider_revalidation: Mapping[str, Any],
        budget_evidence: Mapping[str, Any],
        allocation_history: Mapping[str, Any],
        fleet_id: str,
        now_utc: str,
    ) -> dict[str, Any]:
        """Run a non-executable gate preview; no web route calls this method."""
        with self._lock:
            controls = {
                "kill_switch_engaged": self._kill_switch_engaged,
                # This input controls only the synthetic admission gate. The
                # production auto-arm remains permanently false in this build.
                "auto_armed": self._simulation_armed,
                "live_actions_enabled": self.config.live_actions_enabled,
                "g5_authorized": False,
            }
            common = {
                "source_evidence": source_evidence,
                "policy_evidence": policy_evidence,
                "generation_evidence": generation_evidence,
                "provider_binding": provider_binding,
                "provider_revalidation": provider_revalidation,
                "budget_evidence": budget_evidence,
                "allocation_history": allocation_history,
                "fleet_id": fleet_id,
                "now_utc": now_utc,
                **controls,
            }
            if trigger_kind == "EARLY":
                result = self.auto_reallocation_gate.assess_early(trigger_evidence, **common)
            elif trigger_kind == "STEADY_STATE":
                result = self.auto_reallocation_gate.assess_steady_state(trigger_evidence, **common)
            else:
                return {"status": "BLOCKED", "blockers": ["TRIGGER_KIND_UNSUPPORTED"],
                        "actions_performed": False, "request_submitted": False,
                        "dossier_created": False, "live_action_eligible": False,
                        "simulation_only": True}
            self._auto_gate_reviews[trigger_kind] = result
            self.store.append_audit(
                "AUTO_REALLOCATION_GATE_REVIEWED",
                {
                    "trigger_kind": trigger_kind,
                    "status": result.get("status"),
                    "blockers": result.get("blockers", []),
                    "policy_hash": self.monitor.policy_hash,
                    "simulation_only": True,
                    "actions_performed": False,
                    "request_submitted": False,
                    "dossier_created": False,
                },
                _now_utc(),
            )
            return dict(result)

    def preview_startup_admission(
        self,
        observation: EarlyObservation,
        context: EarlyEvaluationContext | None = None,
        *,
        source_evidence: Mapping[str, Any] | None = None,
        policy_evidence: Mapping[str, Any] | None = None,
        generation_evidence: Mapping[str, Any] | None = None,
        provider_binding: Mapping[str, Any] | None = None,
        provider_revalidation: Mapping[str, Any] | None = None,
        budget_evidence: Mapping[str, Any] | None = None,
        allocation_history: Mapping[str, Any] | None = None,
        fleet_id: str = "unknown",
        now_utc: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate the separate startup fast path and preview the closed G5 gate.

        This method is in-memory only: it does not write audit/ledger/cursor
        state, submit an action, or enable the existing simulation control.
        """
        if type(observation) is not EarlyObservation:
            raise TypeError("startup observation must use the approved exact evidence type")
        if context is not None and type(context) is not EarlyEvaluationContext:
            raise TypeError("startup context must use the approved exact evidence type")
        timestamp = now_utc or _now_utc()
        parsed_now = datetime.fromisoformat(timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp)
        if parsed_now.tzinfo is None or parsed_now.utcoffset() is None:
            raise ValueError("startup preview time must include a timezone")
        floors = _early_gpu_floor_registry(self.config.gpu_floors_ths)
        policy = EarlyPolicy(
            self.monitor.policy_hash,
            floors,
            margin_ths=0.0,
        )
        active = context or EarlyEvaluationContext()
        policy_conflict = active.policy is not None and (
            type(active.policy) is not EarlyPolicy
            or active.policy.policy_hash != policy.policy_hash
            or dict(active.policy.floors_ths) != dict(policy.floors_ths)
        )
        active = EarlyEvaluationContext(
            policy=policy,
            bindings=active.bindings,
            association_records=active.association_records,
            calibrations=active.calibrations,
            now_utc=parsed_now,
            allow_synthetic_calibration_for_test=active.allow_synthetic_calibration_for_test,
            allow_synthetic_binding_evidence_for_test=active.allow_synthetic_binding_evidence_for_test,
        )
        decision = self.startup_admission_engine.evaluate(
            observation,
            active,
            contradictory_evidence=policy_conflict,
        )
        recovery_cause = (
            StartupCause.LOW_AUTOTUNE
            if decision.state == "EARLY_UNDER_FLOOR"
            else StartupCause.UNKNOWN
        )
        recovery = self.startup_admission_engine.classify_recovery(
            recovery_cause,
            admission_decision=decision if recovery_cause is StartupCause.LOW_AUTOTUNE else None,
        )
        gate_review: dict[str, Any] | None = None
        if decision.state == "EARLY_UNDER_FLOOR":
            # The existing gate is deliberately instantiated closed for this
            # preview. Its disabled simulation switch guarantees a blocker
            # before reservation; it cannot write the durable action ledger.
            gate = AutoReallocationGate(
                self.action_ledger,
                policy_hash=self.monitor.policy_hash,
                gpu_floors_ths=floors,
                limits=AutoReallocationLimits(),
                hard_budget_cap_usd=min(float(self.config.hard_budget_usd), 30.0),
                maximum_evidence_age_seconds=(
                    self.config.maximum_sample_gap_seconds
                    + self.config.reevaluation_interval_seconds * self.config.consecutive_bad_windows
                ),
                simulation_enabled=False,
            )
            gate_review = gate.assess_early(
                decision.to_dict(),
                source_evidence=source_evidence or {},
                policy_evidence=policy_evidence or {},
                generation_evidence=generation_evidence or {},
                provider_binding=provider_binding or {},
                provider_revalidation=provider_revalidation or {},
                budget_evidence=budget_evidence or {},
                allocation_history=allocation_history or {},
                fleet_id=fleet_id,
                now_utc=timestamp,
                kill_switch_engaged=self._kill_switch_engaged,
                auto_armed=False,
                live_actions_enabled=False,
                g5_authorized=False,
            )
        safe_gate = self._safe_startup_gate_summary(gate_review)
        summary = {
            "mode": "STARTUP_FAST_PATH",
            "state": decision.state,
            "reason": decision.reason if re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", decision.reason) else "UNKNOWN",
            "cause": "LOW_AUTOTUNE" if decision.state == "EARLY_UNDER_FLOOR" else "UNKNOWN",
            "signal_type": decision.signal_type,
            "device_index": decision.device_index,
            "gpu_key": decision.gpu_key,
            "estimate_ths": decision.estimate_ths,
            "predicted_lower_ths": decision.predicted_lower_ths,
            "predicted_upper_ths": decision.predicted_upper_ths,
            "floor_ths": decision.floor_ths,
            "policy_hash": self.monitor.policy_hash,
            "action_gate": safe_gate,
            "recovery_policy": recovery.to_dict(),
            "actions_performed": False,
            "request_submitted": False,
            "live_action_eligible": False,
        }
        with self._lock:
            self._last_startup_preview = dict(summary)
        return summary

    @staticmethod
    def _safe_startup_gate_summary(result: Mapping[str, Any] | None) -> dict[str, Any]:
        if result is None:
            return {"status": "NOT_EVALUATED", "blockers": [], "actions_performed": False}
        status = result.get("status")
        status = status if status in {"BLOCKED", "CANDIDATE"} else "UNKNOWN"
        blockers = result.get("blockers", [])
        safe_blockers = sorted({item for item in blockers if isinstance(item, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,79}", item)}) if isinstance(blockers, list) else []
        return {"status": status, "blockers": safe_blockers, "actions_performed": False}

    def register_binding_evidence(self, track_id: str, result: Mapping[str, Any]) -> None:
        if not isinstance(track_id, str) or not track_id or not isinstance(result, Mapping):
            raise ValueError("binding evidence key and result are required")
        status = result.get("binding_status")
        if status not in {"VERIFIED", "CONFLICTING", "UNKNOWN"}:
            raise ValueError("binding status is invalid")
        safe = {key: result.get(key) for key in ("binding_status", "reason", "provider", "assignment", "miner", "mismatches", "data_classification", "attestation_evidence_id", "actions_authorized_by_binding")}
        with self._lock:
            self._bindings[track_id] = safe
            self.store.append_audit("BINDING_EVIDENCE_UPDATED", {"track_id": track_id, "binding_status": status}, _now_utc())

    def register_fleet_record(self, record: Mapping[str, Any]) -> None:
        if not isinstance(record, Mapping):
            raise ValueError("fleet accounting record must be an object")
        with self._lock:
            self._fleet_records = [dict(item) for item in self._fleet_records if item.get("fleet_id") != record.get("fleet_id")]
            self._fleet_records.append(dict(record))

    def persist_live_read_result(self, raw: Mapping[str, Any], *, local_tls_test: bool) -> dict[str, Any]:
        """Persist sanitized LiveSaladReadSession observations for the localhost dashboard.

        This is deliberately separate from ``refresh()``: a browser request can
        never start a live read. The terminal-only app bridge calls this after
        the session has completed. Loopback TLS results are downgraded to
        SYNTHETIC/UNVERIFIED before storage, even though they use the fixed
        Salad Host header and SNI for transport testing.
        """
        if not isinstance(raw, Mapping) or type(local_tls_test) is not bool:
            return {"status": "LIVE_RESULT_REJECTED", "groups": [], "groups_queried": 0, "observations_saved": 0, "live_calls_performed": False, "actions_performed": False}
        execution_mode = raw.get("execution_mode")
        disabled_mode = execution_mode == "LIVE_SALAD_GET_DISABLED"
        if (
            execution_mode not in {"LIVE_SALAD_GET", "LIVE_SALAD_GET_DISABLED"}
            or raw.get("actions_performed") is not False
            or raw.get("reallocation_enabled", False) is not False
            or (disabled_mode and raw.get("live_calls_performed") is not False)
        ):
            return {"status": "LIVE_RESULT_REJECTED", "groups": [], "groups_queried": 0, "observations_saved": 0, "live_calls_performed": False, "actions_performed": False}
        rows = raw.get("groups")
        if not isinstance(rows, list) or len(rows) > len(GROUPS):
            return {"status": "LIVE_RESULT_REJECTED", "groups": [], "groups_queried": 0, "observations_saved": 0, "live_calls_performed": False, "actions_performed": False}

        group_indexes: list[int] = []
        summarized: list[dict[str, Any]] = []
        observations_saved = 0
        requests_attempted = 0
        live_calls_performed = False
        rejected = False
        for row in rows:
            if not isinstance(row, Mapping):
                rejected = True
                continue
            group = row.get("container_group")
            if group not in GROUPS:
                rejected = True
                continue
            group_indexes.append(GROUPS.index(group))
            if row.get("actions_performed") is not False or row.get("reallocation_enabled") is not False:
                rejected = True
                summarized.append({"container_group": group, "state": "RESPONSE_REJECTED", "error": "The read result carried an invalid action state."})
                continue
            expected_path = _fixed_group_instances_path(self.config.organization, self.config.project, group)
            if row.get("method") != "GET" or row.get("request_path") != expected_path:
                rejected = True
                summarized.append({"container_group": group, "state": "RESPONSE_REJECTED", "error": "The request did not match the fixed GET route."})
                continue

            attempted = row.get("live_call_attempted") is True
            response_received = row.get("live_calls_performed") is True
            requests_attempted += int(attempted)
            live_calls_performed = live_calls_performed or (response_received and not local_tls_test)
            state = row.get("state") if isinstance(row.get("state"), str) else "UNKNOWN"
            status_code = row.get("http_status_code")
            if isinstance(status_code, bool) or not isinstance(status_code, int) or not 100 <= status_code <= 599:
                status_code = None
            saved = False
            if state == "OBSERVED" and disabled_mode:
                rejected = True
                state = "RESPONSE_REJECTED"
            if state == "OBSERVED":
                evidence = row.get("evidence")
                if not isinstance(evidence, Mapping):
                    rejected = True
                    state = "RESPONSE_REJECTED"
                else:
                    provenance = evidence.get("source_provenance")
                    payload = evidence.get("payload")
                    observed_at = provenance.get("observed_at_utc") if isinstance(provenance, Mapping) else None
                    expected_source = (
                        evidence.get("schema_version") == "1.0"
                        and evidence.get("operation") == "list_container_group_instances"
                        and evidence.get("http_method") == "GET"
                        and evidence.get("organization") == self.config.organization
                        and evidence.get("project") == self.config.project
                        and evidence.get("container_group") == group
                        and evidence.get("request_path") == expected_path
                        and evidence.get("live_calls_performed") is True
                        and evidence.get("actions_performed") is False
                        and evidence.get("reallocation_enabled") is False
                        and evidence.get("binding_status") == "UNKNOWN"
                        and evidence.get("billing_status") == "UNKNOWN"
                        and isinstance(payload, Mapping)
                        and isinstance(payload.get("instances"), list)
                    )
                    expected_live_provenance = (
                        isinstance(provenance, Mapping)
                        and provenance.get("system") == "salad_api"
                        and provenance.get("host") == "api.salad.com"
                        and provenance.get("capture_mode") == "fixed_authenticated_https_get"
                        and provenance.get("provider_response_observed") is True
                        and provenance.get("transport_tls_hostname_verified") is True
                    )
                    if not expected_source or not expected_live_provenance or not isinstance(observed_at, str):
                        rejected = True
                        state = "RESPONSE_REJECTED"
                    else:
                        stored_evidence = dict(evidence)
                        if local_tls_test:
                            stored_evidence.update({
                                "data_classification": "SYNTHETIC/UNVERIFIED",
                                "evidence_status": "UNVERIFIED",
                                "source_provenance": {
                                    "system": "local_fixture",
                                    "capture_mode": "loopback_tls_simulation",
                                    "fixture_id": "G5-LIVE-READ-TLS-LOOPBACK",
                                    "provider_observation_verified": False,
                                    "observed_at_utc": observed_at,
                                },
                                "synthetic_fixture": True,
                                "live_calls_performed": False,
                                "actions_performed": False,
                                "reallocation_enabled": False,
                            })
                            stored_evidence.pop("sanitized_observation_sha256", None)
                            canonical_fixture = json.dumps(
                                stored_evidence,
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=False,
                                allow_nan=False,
                            ).encode("utf-8")
                            stored_evidence["sanitized_fixture_sha256"] = hashlib.sha256(canonical_fixture).hexdigest()
                        elif evidence.get("data_classification") != "PROVIDER_OBSERVED" or evidence.get("evidence_status") != "OBSERVED_UNVERIFIED_BINDING":
                            rejected = True
                            state = "RESPONSE_REJECTED"
                            stored_evidence = {}
                        if stored_evidence:
                            try:
                                self.store.save_provider_observation(stored_evidence, observed_at)
                                saved = True
                                observations_saved += 1
                            except Exception:
                                rejected = True
                                state = "RESPONSE_REJECTED"
            safe_group = {"container_group": group, "state": state, "observation_saved": saved}
            if status_code is not None:
                safe_group["http_status_code"] = status_code
            if row.get("error") is not None or state not in {"OBSERVED", "NOT_QUERIED"}:
                safe_group["error"] = _LIVE_GET_ERROR_MESSAGES.get(state, "The GET request did not complete safely.")
            summarized.append(safe_group)

        if len(group_indexes) != len(set(group_indexes)) or group_indexes != sorted(group_indexes):
            rejected = True
        if len(summarized) != len(rows):
            rejected = True
        if disabled_mode and not rejected and observations_saved == 0 and requests_attempted == 0:
            status = "LIVE_GET_DISABLED"
        elif rejected and observations_saved == 0:
            status = "LIVE_RESULT_REJECTED"
        elif observations_saved == len(GROUPS):
            status = "ALL_GROUPS_OBSERVED"
        elif observations_saved:
            status = "PARTIAL_OBSERVATIONS"
        else:
            status = "NO_OBSERVATIONS"

        result = {
            "status": status,
            "groups": summarized,
            "groups_queried": requests_attempted,
            "observations_saved": observations_saved,
            "data_classification": "SYNTHETIC/UNVERIFIED" if local_tls_test else ("PROVIDER_OBSERVED" if observations_saved else "UNKNOWN"),
            "live_calls_performed": live_calls_performed,
            "local_tls_test_requests_performed": bool(local_tls_test and requests_attempted),
            "actions_performed": False,
            "reallocation_enabled": False,
        }
        self.store.append_audit(
            "MANUAL_SALAD_GET_RESULT_STORED",
            {
                "status": status,
                "container_groups": [item.get("container_group") for item in summarized],
                "groups_queried": requests_attempted,
                "observations_saved": observations_saved,
                "data_classification": result["data_classification"],
                "live_calls_performed": live_calls_performed,
                "local_tls_test_requests_performed": result["local_tls_test_requests_performed"],
                "actions_performed": False,
            },
            _now_utc(),
        )
        return result

    def refresh(self) -> dict[str, Any]:
        """Manual UI refresh is blocked until a separately reviewed live gate."""
        with self._lock:
            local_ingest = self.ingest_configured_local_events() if self.config.local_telemetry_sources else None
            if self.offline_read_broker is not None:
                raw = self.offline_read_broker.run_all_offline()
                if (
                    not isinstance(raw, Mapping)
                    or raw.get("execution_mode") != "OFFLINE_LOCAL_TLS_TEST"
                    or raw.get("data_classification") != "SYNTHETIC/UNVERIFIED"
                    or raw.get("live_calls_performed") is not False
                    or raw.get("actions_performed") is not False
                ):
                    result = {"status": "OFFLINE_FIXTURE_RESULT_REJECTED", "groups_queried": 0, "live_calls_performed": False}
                else:
                    safe_groups = raw.get("groups") if isinstance(raw.get("groups"), list) else []
                    stored = 0
                    for row in safe_groups:
                        evidence = row.get("evidence") if isinstance(row, Mapping) else None
                        if not isinstance(evidence, Mapping):
                            continue
                        provenance = evidence.get("source_provenance") if isinstance(evidence.get("source_provenance"), Mapping) else {}
                        if (
                            evidence.get("data_classification") != "SYNTHETIC/UNVERIFIED"
                            or provenance.get("system") != "local_fixture"
                            or provenance.get("provider_observation_verified") is not False
                            or evidence.get("live_calls_performed") is not False
                        ):
                            continue
                        self.store.save_provider_observation(evidence, _now_utc())
                        stored += 1
                    result = {
                        "status": raw.get("state", "UNKNOWN"),
                        "groups_queried": min(len(safe_groups), 4),
                        "synthetic_observations_stored": stored,
                        "data_classification": "SYNTHETIC/UNVERIFIED",
                        "live_calls_performed": False,
                        "actions_performed": False,
                    }
            else:
                # Web refresh never starts LiveSaladReadSession, even if a
                # session was injected by a local test or future composition.
                result = {"status": "LIVE_GET_DISABLED", "groups_queried": 0, "observations_saved": 0, "live_calls_performed": False, "actions_performed": False}
            self.store.append_audit("DISCOVERY_REFRESH_REQUESTED", result, _now_utc())
            self.evaluate_control_cycle()
            if local_ingest is not None:
                result["local_telemetry_ingest"] = {
                    "status": local_ingest.get("status"),
                    "source_count": local_ingest.get("source_count"),
                    "event_count": local_ingest.get("event_count"),
                    "inserted_sample_count": local_ingest.get("inserted_sample_count"),
                }
            return result

    def _current_group_evidence(self) -> dict[str, list[dict[str, Any]]]:
        selected = {group: [] for group in GROUPS}
        for row in self.store.observations():
            payload = row["payload"]
            selected[payload["container_group"]].append(payload)
        return selected

    def state(self) -> dict[str, Any]:
        with self._lock:
            by_group = self._current_group_evidence()
            tracks = self.guard_store.track_rows()
            devices: list[dict[str, Any]] = []
            budget_summary = self.store.budget_summary()
            for track in tracks:
                evaluation_row = self.guard_store.last_evaluation(track["track_id"])
                evaluation = evaluation_row.get("result") if isinstance(evaluation_row, Mapping) else None
                if (
                    not isinstance(evaluation_row, Mapping)
                    or evaluation_row.get("policy_hash") != self.monitor.policy_hash
                    or not isinstance(evaluation, Mapping)
                    or evaluation.get("policy_hash") != self.monitor.policy_hash
                ):
                    evaluation = None
                binding = self._bindings.get(track["track_id"], {"binding_status": "UNKNOWN", "reason": "no independent binding proof registered"})
                projection = project_device(
                    track,
                    evaluation if isinstance(evaluation, Mapping) else None,
                    binding=binding,
                    economic_summary={
                        "budget_status": budget_summary.get("status", "UNKNOWN"),
                        "hard_budget_cap_usd": min(float(self.config.hard_budget_usd), 30.0),
                        "verified_spend_usd": budget_summary.get("verified_spend_usd"),
                    },
                    action_context={"status": "DISABLED", "blockers": ["G5_REVIEW_REQUIRED", "LIVE_ACTIONS_DISABLED"]},
                )
                if projection["binding"].get("binding_status") != "VERIFIED":
                    projection["provider_instance_attribution"] = "UNKNOWN"
                devices.append(projection)
            groups = []
            for group in GROUPS:
                latest = by_group[group][-1] if by_group[group] else None
                rows = latest.get("payload", {}).get("instances", []) if latest else []
                groups.append({
                    "container_group": group,
                    "provider_observation_status": latest.get("evidence_status", "UNKNOWN") if latest else "UNKNOWN",
                    "data_classification": latest.get("data_classification", "UNKNOWN") if latest else "UNKNOWN",
                    "observed_at_utc": latest.get("source_provenance", {}).get("observed_at_utc") if latest else None,
                    "instances": rows,
                    "instance_count_observed": len(rows),
                    "gpu_binding_status": "UNKNOWN",
                    "billing_status": "UNKNOWN",
                    "actions_performed": False,
                })
            fleets = []
            for record in self._fleet_records:
                device_rows = [row for row in devices if row.get("fleet_id") == record.get("fleet_id")]
                fleets.append(project_fleet(record, device_projections=device_rows))
            return {
                "schema_version": "1.0",
                "mode": "offline_local",
                "server": {"host": "127.0.0.1", "port": self.config.port},
                "salad": {"organization": self.config.organization, "project": self.config.project, "groups": groups, "live_get_enabled": False},
                "monitor": {
                    "implementation": "ContinuousMonitor",
                    "policy_hash": self.monitor.policy_hash,
                    "event_feed": fleet_monitor_event_feed(
                        self.guard_store,
                        limit=100,
                        binding_by_track=self._bindings,
                    ),
                    "configuration": {
                        "gpu_floors_ths": [
                            {
                                "identity_key": key,
                                "threshold_ths": value,
                                "source": self.config.source_for(f"gpu_floors_ths.{key}"),
                            }
                            for key, value in sorted(self.config.gpu_floors_ths.items())
                        ],
                        "settings": {
                            name: {"value": getattr(self.config, name), "source": self.config.source_for(name)}
                            for name in (
                                "warmup_seconds",
                                "expected_sample_interval_seconds",
                                "hash_window_seconds",
                                "reevaluation_interval_seconds",
                                "minimum_samples_per_window",
                                "maximum_sample_gap_seconds",
                                "minimum_window_coverage_ratio",
                                "consecutive_bad_windows",
                            )
                        },
                    },
                    "devices": devices,
                },
                "startup_admission": {
                    "mode": "STARTUP_FAST_PATH_SEPARATE_FROM_ROLLING_DEGRADATION",
                    "status": self._last_startup_preview.get("state", "NO_OBSERVATION")
                    if self._last_startup_preview else "NO_OBSERVATION",
                    "production_calibration_count": 0,
                    "unmapped_or_uncalibrated_gpu_state": "EARLY_UNKNOWN",
                    "rolling_guard_unchanged": True,
                    "last_preview": dict(self._last_startup_preview) if self._last_startup_preview else None,
                    "actions_performed": False,
                    "request_submitted": False,
                    "live_action_eligible": False,
                },
                "startup_recovery_policy": self.startup_admission_engine.recovery_policy.to_dict(),
                "latency_model": {
                    "polling_scenarios": polling_comparison((30, 15), organization_count=3),
                    "reaction_exposure_scenarios": reaction_exposure_comparison(),
                    "current_default_poll_seconds": 30,
                    "polling_default_changed": False,
                    "request_amplification_source": "watcher subqueries per organization cycle",
                    "actual_request_rate_status": "UNKNOWN_UNTIL_WATCHER_MEASUREMENT",
                    "cost_classification": "ESTIMATED_OPERATOR_RATE_NOT_VERIFIED_BILLING",
                },
                "reallocation_reviews": {
                    "mode": "DRY_RUN",
                    "items": [
                        {"track_id": key, "eligibility": value.get("eligibility"), "blockers": value.get("blockers", []), "actions_performed": False}
                        for key, value in sorted(self._controller_decisions.items())
                    ],
                },
                "economics": {
                    "profit_status": "UNKNOWN",
                    "billing_status": "UNKNOWN",
                    "budget": budget_summary,
                    "hard_budget_cap_usd": min(float(self.config.hard_budget_usd), 30.0),
                    "revenue_attribution": "fleet_worker_only",
                    "hourly_price_estimate": {
                        "usd_per_hour": self.config.salad_hourly_price_usd_estimate,
                        "source": self.config.source_for("salad_hourly_price_usd_estimate"),
                        "classification": "OPERATOR_ESTIMATE_NOT_VERIFIED_BILLING",
                        "billing_verified": False,
                        "spend_authorized": False,
                    },
                },
                "fleets": fleets,
                "actions": {"live_actions_enabled": False, "auto_reallocate": False, "auto_armed": self._auto_armed, "simulation_armed": self._simulation_armed, "kill_switch_engaged": self._kill_switch_engaged, "reallocation_enabled": False, "actions_performed": False},
                "auto_reallocation_gate": {
                    "mode": "OFFLINE_SIMULATION_ONLY",
                    "status": "SIMULATION_ARMED" if self._simulation_armed else "DISABLED",
                    "simulation_enabled": self.auto_reallocation_gate.simulation_enabled,
                    "policy_hash": self.monitor.policy_hash,
                    "hard_budget_cap_usd": min(float(self.config.hard_budget_usd), 30.0),
                    "reviews": {
                        kind: {
                            "status": result.get("status"),
                            "blockers": result.get("blockers", []),
                            "evidence_classification": result.get("evidence_classification", "UNKNOWN"),
                            "actions_performed": False,
                            "request_submitted": False,
                            "dossier_created": False,
                            "live_action_eligible": False,
                        }
                        for kind, result in sorted(self._auto_gate_reviews.items())
                    },
                    "reservations": self.action_ledger.auto_reallocation_simulation_snapshot(),
                    "simulation_control": self.action_ledger.auto_reallocation_simulation_control_snapshot(),
                    "actions_performed": False,
                    "request_submitted": False,
                    "dossier_created": False,
                    "live_action_eligible": False,
                },
            }

    def audit(self) -> dict[str, Any]:
        return {
            "events": self.store.audit(),
            "actions": self.action_ledger.snapshot(),
            "auto_reallocation_simulations": self.action_ledger.auto_reallocation_simulation_snapshot(),
            "auto_reallocation_simulation_control": self.action_ledger.auto_reallocation_simulation_control_snapshot(),
            "actions_performed": False,
        }

    def request_action(self, action_name: str, body: Mapping[str, Any]) -> dict[str, Any]:
        try:
            action = SaladAction(action_name)
        except (ValueError, TypeError):
            return self._audit_action("ACTION_BLOCKED", {"action": "UNKNOWN", "reason": "unsupported action"})
        group = body.get("container_group")
        target = {"organization": self.config.organization, "project": self.config.project, "container_group": group}
        if action is SaladAction.REALLOCATE_INSTANCE:
            target["instance_id"] = body.get("instance_id")
            target["assignment_id"] = body.get("assignment_id")
            target["deterioration_id"] = body.get("deterioration_id")
        with self._lock:
            if group not in GROUPS:
                return self._audit_action("ACTION_BLOCKED", {"action": action.value, "container_group": group, "reason": "target group outside allowlist"})
            if self._kill_switch_engaged or not self.config.live_actions_enabled or self.action_executor is None:
                return self._audit_action("ACTION_BLOCKED", {"action": action.value, "container_group": group, "reason": "kill switch or live action gate is closed"})
            # The browser can request an operation but cannot supply the
            # backend-only signed evidence dossier required by the sender.
            receipt = self.action_executor.execute(
                action, target, decision_dossier=None, auto_armed=self._auto_armed,
            )
            return self._audit_action("ACTION_DECISION", {"action": action.value, "container_group": group, "status": receipt.status, "reason": receipt.reason, "action_key": receipt.action_key, "actions_performed": False})

    def set_auto_reallocate(self, armed: bool) -> dict[str, Any]:
        if not isinstance(armed, bool):
            raise ValueError("auto arm command must be boolean")
        with self._lock:
            if armed:
                result = {"status": "BLOCKED", "armed": False, "reason": "AUTO_REALLOCATE is disabled in the offline G5 build"}
                self._auto_armed = False
            else:
                self._auto_armed = False
                result = {"status": "DISARMED", "armed": False}
            self.store.append_audit("AUTO_REALLOCATE_ARM_REQUESTED", result, _now_utc())
            return result

    def set_kill_switch(self, engaged: bool) -> dict[str, Any]:
        if not isinstance(engaged, bool):
            raise ValueError("kill switch command must be boolean")
        with self._lock:
            self._kill_switch_engaged = engaged
            # Any change to this safety control closes the synthetic path. A
            # caller must explicitly re-arm after reviewing the new state.
            self._simulation_armed = False
            self._simulation_limits = None
            self.auto_reallocation_gate = self._build_auto_reallocation_gate()
            self.action_ledger.update_auto_reallocation_simulation_control(
                armed=False,
                event_type="KILL_SWITCH_ENGAGED" if engaged else "KILL_SWITCH_DISENGAGED",
                kill_switch_engaged=engaged,
                live_actions_enabled=self.config.live_actions_enabled,
                g5_authorized=False,
                at_utc=_now_utc(),
            )
            result = {"status": "KILL_SWITCH_ENGAGED" if engaged else "KILL_SWITCH_DISENGAGED_LOCAL_ONLY", "engaged": engaged, "actions_performed": False}
            self.store.append_audit("KILL_SWITCH_CHANGED", result, _now_utc())
            return result

    def _audit_action(self, event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self.store.append_audit(event_type, payload, _now_utc())
        return {"status": payload.get("status", "BLOCKED"), "actions_performed": False, **dict(payload)}
