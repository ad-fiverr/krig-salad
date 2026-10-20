"""Read-only bridge from bounded normalized logs to startup-admission summaries.

Provider labels alone never create a workload binding. Salad log text can
identify an early signal, but without CSV source references, policy evidence,
generation binding and empirical calibration the decision remains UNKNOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import math
import re
import time
from typing import Any, Mapping

from collector.fl4sh_early_autotune import (
    EarlyEvaluationContext,
    EarlyObservation,
    LocalStartupPolicyEvidence,
    ProviderLogObservationReference,
    StartupPolicySnapshot,
)
from collector.fl4shminer import _classify
from collector.startup_admission import StartupAdmissionEngine
from collector.startup_recovery_policy import (
    StartupCause,
    StartupRecoveryDecision,
)

from .contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED, canonical_utc
from .normalize import MAX_TEXT_LOG_CHARS, NormalizedLogEntry
from .provider_binding_revalidation import ProviderBindingPreDispatchResult
from .startup_v2_attestation import (
    StartupV2AttestationResolver,
    StartupV2ProofHandle,
    StartupV2Resolution,
    _startup_v2_proof_handle,
)


_GPU_NAME_RE = re.compile(
    r"NVIDIA +(?P<geforce>GeForce +)?(?P<name>[A-Za-z0-9]+(?:[ _-]+[A-Za-z0-9]+)*)",
    re.IGNORECASE,
)
_GPU_KEY_RE = re.compile(r"[A-Z0-9]+(?:_[A-Z0-9]+)*\Z")
_MODEL_ONLY_TOKENS = frozenset({"NVIDIA", "GEFORCE", "GPU", "UNKNOWN", "SERIES", "FAMILY"})
_FORM_FACTOR_TOKENS = frozenset({"LAPTOP", "NOTEBOOK", "MOBILE", "DESKTOP"})
_SAFE_REASON_RE = re.compile(r"[A-Z][A-Z0-9_]{0,79}\Z")
_GPU_INIT_RE = re.compile(
    r"^(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?"
    r"Device\s*\[(?P<device>[0-9]{1,3})\]\s+"
    r"(?P<model>[^:\r\n=]{1,256}?)\s*:\s*Initialized\s*$",
    re.IGNORECASE,
)
MAX_GPU_DETECTIONS = 512
GPU_DETECTION_TTL_SECONDS = 600
MAX_EMITTED_STARTUP_EVENTS = 4_096
STARTUP_EVENT_DEDUPE_TTL_SECONDS = 600

CAUSE_CODES = frozenset({
    "LOW_AUTOTUNE", "POOL_AUTH_TIMEOUT", "NETWORK_FAILURE", "CUDA_INCOMPATIBLE",
    "NO_GPU", "NO_POSITIVE_HASHRATE", "PROCESS_EXIT", "PROVIDER_PREEMPTION", "UNKNOWN",
})


def normalize_observed_gpu_key(raw_name: Any) -> str | None:
    """Canonicalize an explicit NVIDIA model without inventing form factor."""
    if (
        not isinstance(raw_name, str) or not 1 <= len(raw_name) <= 256
        or any(ord(char) < 32 or ord(char) > 126 for char in raw_name)
    ):
        return None
    match = _GPU_NAME_RE.fullmatch(raw_name.strip())
    if match is None:
        return None
    name = match.group("name").upper()
    tokens = re.split(r"[ _-]+", name)
    if tokens and tokens[-1] == "GPU":
        tokens.pop()
    if not tokens or any(token in _MODEL_ONLY_TOKENS for token in tokens):
        return None
    if sum(bool(re.search(r"[0-9]", word)) for word in name.split()) != 1 or tokens.count("RTX") > 1:
        return None
    forms = [token for token in tokens if token in _FORM_FACTOR_TOKENS]
    if len(forms) > 1:
        return None
    suffix: list[str] = []
    if forms:
        suffix.append("LAPTOP" if forms[0] in {"LAPTOP", "NOTEBOOK", "MOBILE"} else "DESKTOP")
        tokens = [token for token in tokens if token not in _FORM_FACTOR_TOKENS]
    key = "_".join(tokens + suffix)
    return key if len(key) <= 128 and _GPU_KEY_RE.fullmatch(key) else None


@dataclass(frozen=True, slots=True)
class StartupEarlyEvent:
    state: str
    reason: str
    cause: str
    signal_type: str | None
    device_index: int | None
    gpu_key: str | None
    estimate_ths: float | None
    floor_ths: float | None
    event_time_utc: str
    data_classification: str
    recovery: StartupRecoveryDecision
    floor_source: str | None = None
    floor_catalog_hash: str | None = None
    policy_hash: str | None = None
    pool_equivalent_ths: float | None = None
    provenance_status: str = "UNKNOWN"
    mode: str = "STARTUP_FAST_PATH"
    polling_latency_seconds: None = None
    polling_latency_status: str = "UNKNOWN_PROVIDER_AVAILABILITY_TIME"
    event_age_at_ingestion_seconds: float | None = None
    provider_response_received_at_utc: str | None = None
    watcher_ingested_at_utc: str | None = None
    response_to_decision_ms: float | None = None
    classification_ms: float | None = None
    decision: str | None = None
    actions_performed: bool = False
    request_submitted: bool = False
    provider_binding_revalidation: ProviderBindingPreDispatchResult | None = field(
        default=None, repr=False, compare=False,
    )
    _provider_binding_proof_handle: StartupV2ProofHandle | None = field(
        default=None, repr=False, compare=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "reason": self.reason,
            "cause": self.cause,
            "signal_type": self.signal_type,
            "device_index": self.device_index,
            "gpu_key": self.gpu_key,
            "estimate_ths": self.estimate_ths,
            "floor_ths": self.floor_ths,
            "floor_source": self.floor_source,
            "floor_catalog_hash": self.floor_catalog_hash,
            "policy_hash": self.policy_hash,
            "mode": self.mode,
            "decision_signal": "PEARL_AUTOTUNE" if self.signal_type == "PEARL_AUTOTUNE" else self.signal_type,
            "gpu_autotune_ths": self.estimate_ths if self.signal_type == "PEARL_AUTOTUNE" else None,
            "pool_equivalent_ths": self.pool_equivalent_ths,
            "decision": self.decision or self.state,
            "provenance_status": self.provenance_status,
            "polling_latency_seconds": self.polling_latency_seconds,
            "polling_latency_status": self.polling_latency_status,
            "event_age_at_ingestion_seconds": self.event_age_at_ingestion_seconds,
            "provider_response_received_at_utc": self.provider_response_received_at_utc,
            "watcher_ingested_at_utc": self.watcher_ingested_at_utc,
            "response_to_decision_ms": self.response_to_decision_ms,
            "classification_ms": self.classification_ms,
            "event_time_utc": self.event_time_utc,
            "data_classification": self.data_classification,
            "recovery_policy": self.recovery.to_dict(),
            "provider_binding_revalidation": (
                self.provider_binding_revalidation.to_dict()
                if type(self.provider_binding_revalidation) is ProviderBindingPreDispatchResult
                else {
                    "binding_status": "UNKNOWN",
                    "revalidation_status": "REVALIDATION_BLOCKED",
                    "reason": "SOURCE_UNAVAILABLE",
                    "evidence_classification": "UNKNOWN",
                    "event_evidence_ref_sha256": None,
                    "assignment_evidence_ref_sha256": None,
                    "device_evidence_ref_sha256": None,
                    "policy_hash": None,
                    "observed_at_utc": None,
                    "revalidated_at_utc": None,
                    "action_eligible": False,
                    "actions_performed": False,
                    "request_submitted": False,
                }
            ),
            "actions_performed": False,
            "request_submitted": False,
        }


@dataclass(frozen=True, slots=True)
class _GpuDetection:
    gpu_key: str | None
    event_time_utc: str
    evidence_sha256: str
    inserted_monotonic: float
    data_classification: str
    provider_response_evidence: Any = None
    conflict: bool = False


class StartupEarlyBridge:
    """Read-only GPU/Pearl bridge; incomplete trust remains EARLY_UNKNOWN."""

    def __init__(
        self,
        engine: StartupAdmissionEngine | None = None,
        *,
        policy_snapshot: StartupPolicySnapshot | None = None,
        startup_v2_attestation_resolver: StartupV2AttestationResolver | None = None,
        monotonic=time.monotonic,
    ) -> None:
        self.engine = engine or StartupAdmissionEngine()
        if type(self.engine) is not StartupAdmissionEngine:
            raise TypeError("startup bridge requires the existing admission engine")
        if policy_snapshot is not None and type(policy_snapshot) is not StartupPolicySnapshot:
            raise TypeError("startup bridge requires the exact read-only G5 policy snapshot")
        if (
            startup_v2_attestation_resolver is not None
            and type(startup_v2_attestation_resolver) is not StartupV2AttestationResolver
        ):
            raise TypeError("startup bridge requires the exact V2 attestation resolver")
        if not callable(monotonic):
            raise TypeError("startup bridge clock is invalid")
        self.policy_snapshot = policy_snapshot
        self.startup_v2_attestation_resolver = startup_v2_attestation_resolver
        self.monotonic = monotonic
        self._gpu_detections: dict[tuple[str, int], _GpuDetection] = {}
        self._pool_equivalent: dict[tuple[str, int], float] = {}
        # Overlapping provider query windows can return the same log record in
        # multiple cycles. Keep only bounded, one-way event fingerprints so the
        # read-only projection does not repeat indefinitely.
        self._emitted_events: dict[str, float] = {}

    def inspect(
        self,
        entry: NormalizedLogEntry,
        context: EarlyEvaluationContext | None = None,
    ) -> StartupEarlyEvent | None:
        return next(iter(self.process_entries((entry,), context=context)), None)

    def process_entries(
        self,
        entries: tuple[NormalizedLogEntry, ...] | list[NormalizedLogEntry],
        *,
        context: EarlyEvaluationContext | None = None,
        response_received_monotonic: float | None = None,
        response_received_at_utc: str | None = None,
        watcher_ingested_at_utc: str | None = None,
    ) -> tuple[StartupEarlyEvent, ...]:
        if context is not None and type(context) is not EarlyEvaluationContext:
            raise TypeError("startup bridge context must use the approved exact evidence type")
        if self.startup_v2_attestation_resolver is not None and context is not None:
            raise TypeError("V2 attestation resolver owns the startup evaluation context")
        received = self.monotonic() if response_received_monotonic is None else response_received_monotonic
        ingest_monotonic = self.monotonic()
        ingested_at = canonical_utc(watcher_ingested_at_utc or datetime.now(timezone.utc))
        response_at = canonical_utc(response_received_at_utc or ingested_at)
        self._prune_detections(ingest_monotonic)
        ordered = sorted(entries, key=self._startup_order_key)
        events: list[StartupEarlyEvent] = []
        for entry in ordered:
            if type(entry) is not NormalizedLogEntry:
                raise TypeError("startup bridge accepts only normalized log evidence")
            if entry.data_classification not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}:
                continue
            message = self._message(entry)
            init_match = _GPU_INIT_RE.fullmatch(message) if message is not None else None
            if init_match is not None:
                event = self._record_gpu_detection(entry, init_match, ingested_at)
                if event is not None and self._mark_event_emitted(entry, event):
                    events.append(event)
                continue
            parsed = _classify(message) if message is not None else None
            if isinstance(parsed, tuple) and len(parsed) == 2 and parsed[0] == "hashrate_estimate":
                payload = parsed[1]
                if isinstance(payload, Mapping):
                    signal_type = payload.get("early_signal_type")
                    if signal_type in {"CUDA_POOL_EQUIVALENT", "PEARL_AUTOTUNE"}:
                        if signal_type == "CUDA_POOL_EQUIVALENT":
                            device_text = payload.get("device_id")
                            resource_key = self._resource_key(entry)
                            estimate = payload.get("hashrate_ths")
                            if (
                                resource_key is not None
                                and isinstance(device_text, str)
                                and device_text.isdigit()
                                and type(estimate) in {int, float}
                                and math.isfinite(float(estimate))
                                and 0 < estimate <= 10_000
                            ):
                                self._pool_equivalent[(resource_key, int(device_text))] = float(estimate)
                        event = self._evaluate_signal(
                            entry, payload, signal_type, context=context,
                            response_received_monotonic=received,
                            response_received_at_utc=response_at,
                            watcher_ingested_at_utc=ingested_at,
                        )
                        if event is not None and self._mark_event_emitted(entry, event):
                            events.append(event)
                        continue
            event = self._non_gpu_event(entry, message)
            if event is not None and self._mark_event_emitted(entry, event):
                events.append(event)
        return tuple(events)

    def _mark_event_emitted(self, entry: NormalizedLogEntry, event: StartupEarlyEvent) -> bool:
        """Deduplicate an overlapping provider record without retaining raw IDs or text."""
        now = self.monotonic()
        expired = [
            digest for digest, emitted_at in self._emitted_events.items()
            if now - emitted_at > STARTUP_EVENT_DEDUPE_TTL_SECONDS
        ]
        for digest in expired:
            self._emitted_events.pop(digest, None)
        material = "\0".join((
            entry.evidence_sha256,
            event.state,
            event.reason,
            event.policy_hash or "",
            event.floor_catalog_hash or "",
            event.floor_source or "",
            "" if event.floor_ths is None else format(event.floor_ths, ".17g"),
            "" if event.estimate_ths is None else format(event.estimate_ths, ".17g"),
            event.gpu_key or "",
            event.decision or "",
        ))
        digest = hashlib.sha256(material.encode("ascii")).hexdigest()
        if digest in self._emitted_events:
            return False
        self._emitted_events[digest] = now
        if len(self._emitted_events) > MAX_EMITTED_STARTUP_EVENTS:
            oldest = sorted(self._emitted_events.items(), key=lambda item: item[1])
            for stale_digest, _timestamp in oldest[:len(oldest) - MAX_EMITTED_STARTUP_EVENTS]:
                self._emitted_events.pop(stale_digest, None)
        return True

    def _startup_order_key(self, entry: NormalizedLogEntry) -> tuple[str, int, str]:
        message = self._message(entry)
        if message is not None and _GPU_INIT_RE.fullmatch(message):
            priority = 0
        else:
            parsed = _classify(message) if message is not None else None
            payload = parsed[1] if isinstance(parsed, tuple) and len(parsed) == 2 else None
            signal = payload.get("early_signal_type") if isinstance(payload, Mapping) else None
            priority = {"CUDA_POOL_EQUIVALENT": 1, "PEARL_AUTOTUNE": 2}.get(signal, 3)
        return (entry.event_time_utc, priority, entry.evidence_sha256)

    def _resource_key(self, entry: NormalizedLogEntry) -> str | None:
        identity = entry.identity
        if identity.source != "resource.labels" or identity.status != entry.data_classification or not all((
            identity.organization_name, identity.project_name, identity.container_group_name,
            identity.machine_id, identity.instance_id,
        )):
            return None
        material = "\0".join((
            identity.organization_name or "", identity.project_name or "",
            identity.container_group_name or "", identity.machine_id or "", identity.instance_id or "",
        ))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _group_version(self, entry: NormalizedLogEntry) -> str | None:
        found: set[str] = set()
        for key, value in entry.resource_labels.items():
            if not isinstance(key, str):
                continue
            normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
            if normalized in {"containergroupversion", "containergroupversionid"} and isinstance(value, str):
                found.add(value)
        return next(iter(found)) if len(found) == 1 else None

    def _policy_scope_matches(self, entry: NormalizedLogEntry) -> bool:
        snapshot = self.policy_snapshot
        identity = entry.identity
        return bool(
            snapshot is not None
            and identity.organization_name == snapshot.organization
            and identity.project_name == snapshot.project
            and identity.container_group_name in snapshot.container_groups
        )

    def _floor(self, gpu_key: str | None, entry: NormalizedLogEntry) -> tuple[float | None, str | None]:
        snapshot = self.policy_snapshot
        if snapshot is None or not self._policy_scope_matches(entry) or gpu_key is None:
            return None, None
        floor = snapshot.policy.floors_ths.get(gpu_key)
        source = snapshot.floor_sources.get(gpu_key) if floor is not None else None
        return (float(floor), source) if floor is not None else (None, None)

    def _record_gpu_detection(self, entry: NormalizedLogEntry, match: re.Match[str], ingested_at: str) -> StartupEarlyEvent | None:
        device = int(match.group("device"))
        raw_model = match.group("model").strip()
        gpu_key = normalize_observed_gpu_key(raw_model)
        resource_key = self._resource_key(entry)
        state = "GPU_DETECTED" if gpu_key is not None and resource_key is not None else "GPU_IDENTITY_UNKNOWN"
        reason = "GPU_MODEL_NORMALIZED" if state == "GPU_DETECTED" else "GPU_IDENTITY_UNVERIFIED"
        detection_key = (resource_key, device) if resource_key is not None else None
        if detection_key is not None and gpu_key is not None:
            prior = self._gpu_detections.get(detection_key)
            conflict = prior is not None and (
                prior.conflict or (prior.gpu_key is not None and prior.gpu_key != gpu_key)
            )
            if conflict:
                state, reason, gpu_key = "GPU_IDENTITY_CONFLICT", "GPU_MODEL_CONFLICT", None
                self._gpu_detections[detection_key] = _GpuDetection(
                    None, entry.event_time_utc, entry.evidence_sha256, self.monotonic(),
                    entry.data_classification, entry.provider_response_evidence, True,
                )
            elif not (prior and prior.conflict):
                self._gpu_detections[detection_key] = _GpuDetection(
                    gpu_key, entry.event_time_utc, entry.evidence_sha256, self.monotonic(),
                    entry.data_classification, entry.provider_response_evidence, False,
                )
        floor, floor_source = self._floor(gpu_key, entry)
        return self._simple_event(
            state=state, reason=reason, event=entry, signal=None, device=device,
            gpu_key=gpu_key, estimate=None, floor=floor, floor_source=floor_source,
            decision="NOT_EVALUATED", ingested_at=ingested_at,
            provenance="PROVIDER_OBSERVED" if self._resource_key(entry) else "IDENTITY_UNVERIFIED",
        )

    def _evaluate_signal(
        self,
        entry: NormalizedLogEntry,
        payload: Mapping[str, Any],
        signal_type: str,
        *,
        context: EarlyEvaluationContext | None,
        response_received_monotonic: float,
        response_received_at_utc: str,
        watcher_ingested_at_utc: str,
    ) -> StartupEarlyEvent | None:
        decision_started_monotonic = self.monotonic()
        device_value = payload.get("device_id")
        device = int(device_value) if isinstance(device_value, str) and device_value.isdigit() else None
        if device is not None and not 0 <= device <= 999:
            device = None
        estimate = payload.get("hashrate_ths")
        if type(estimate) not in {int, float} or not math.isfinite(float(estimate)) or not 0 < estimate <= 10_000:
            estimate = None
        resource_key = self._resource_key(entry)
        reported_key = normalize_observed_gpu_key(payload.get("reported_gpu_model_label"))
        correlation_reason = None
        if device is None and signal_type == "PEARL_AUTOTUNE":
            device, correlation_reason = self._correlate_implicit_pearl_device(
                resource_key, reported_key,
            )
        detection = self._gpu_detections.get((resource_key, device)) if resource_key and device is not None else None
        conflict = bool(
            correlation_reason == "GPU_IDENTITY_CONFLICT"
            or detection is not None and (
                detection.conflict or (reported_key is not None and detection.gpu_key != reported_key)
            )
        )
        detected_gpu_key = detection.gpu_key if detection is not None and not conflict else None
        # Preserve the miner-reported model as explicitly uncorroborated
        # display evidence. It cannot select a floor or form a provider binding.
        gpu_key = detected_gpu_key or (reported_key if not conflict else None)
        event_time = canonical_utc(entry.event_time_utc)
        timestamp = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        snapshot = self.policy_snapshot if self._policy_scope_matches(entry) else None
        policy = snapshot.policy if snapshot is not None else None
        floor, floor_source = self._floor(detected_gpu_key, entry)
        ref = None
        policy_evidence = None
        policy_status = "MISSING"
        if resource_key is not None and device is not None and detection is not None and detected_gpu_key is not None and not conflict:
            ref = ProviderLogObservationReference(
                evidence_sha256=entry.evidence_sha256,
                event_time_utc=event_time,
                data_classification=entry.data_classification,
                organization=entry.identity.organization_name or "",
                project=entry.identity.project_name or "",
                container_group=entry.identity.container_group_name or "",
                machine_id=entry.identity.machine_id or "",
                instance_id=entry.identity.instance_id or "",
                device_namespace="fl4shminer_device",
                device_index=device,
                gpu_key=detected_gpu_key,
                gpu_identity_source_sha256=detection.evidence_sha256,
                container_group_version=self._group_version(entry),
            )
            if snapshot is not None:
                policy_evidence = LocalStartupPolicyEvidence(
                    policy_hash=snapshot.policy.policy_hash,
                    config_sha256=snapshot.config_sha256,
                    floor_catalog_hash=snapshot.floor_catalog_hash,
                    organization=snapshot.organization,
                    project=snapshot.project,
                    container_groups=snapshot.container_groups,
                    loaded_at_utc=snapshot.loaded_at_utc,
                )
                policy_status = "PARSED"
        observation = EarlyObservation(
            signal_type=signal_type,
            device_index=device,
            gpu_key=gpu_key,
            estimate_ths=float(estimate) if estimate is not None else None,
            event_time_utc=timestamp,
            policy_hash=policy.policy_hash if policy is not None else None,
            source="SALAD_PROVIDER_LOG_AUTOTUNE",
            source_reference=ref,
            policy_evidence=policy_evidence,
            policy_evidence_status=policy_status,
        )
        resolution: StartupV2Resolution | None = None
        if self.startup_v2_attestation_resolver is not None:
            if policy is None or ref is None or detection is None:
                resolution = StartupV2Resolution(None, "ATTESTATION_INPUT_INCOMPLETE")
            else:
                try:
                    gpu_identity_time = datetime.fromisoformat(
                        detection.event_time_utc.replace("Z", "+00:00"),
                    )
                    now_time = datetime.fromisoformat(
                        watcher_ingested_at_utc.replace("Z", "+00:00"),
                    )
                except (AttributeError, TypeError, ValueError):
                    resolution = StartupV2Resolution(None, "ATTESTATION_TIME_INVALID")
                else:
                    resolution = self.startup_v2_attestation_resolver.resolve(
                        reference=ref,
                        response_evidence=entry.provider_response_evidence,
                        gpu_identity_response_evidence=detection.provider_response_evidence,
                        gpu_identity_data_classification=detection.data_classification,
                        policy=policy,
                        event_time_utc=timestamp,
                        gpu_identity_event_time_utc=gpu_identity_time,
                        now_utc=now_time,
                    )
        active_context = (
            resolution.context or EarlyEvaluationContext(policy=policy)
            if resolution is not None
            else context or EarlyEvaluationContext()
        )
        policy_conflict = bool(
            policy is not None
            and active_context.policy is not None
            and (
                active_context.policy.policy_hash != policy.policy_hash
                or dict(active_context.policy.floors_ths) != dict(policy.floors_ths)
            )
        )
        eval_context = EarlyEvaluationContext(
            policy=(
                policy
                if self.policy_snapshot is not None
                else active_context.policy
            ),
            bindings=active_context.bindings,
            association_records=active_context.association_records,
            calibrations=active_context.calibrations,
            now_utc=active_context.now_utc or datetime.now(timezone.utc),
            allow_synthetic_calibration_for_test=active_context.allow_synthetic_calibration_for_test,
            allow_synthetic_binding_evidence_for_test=active_context.allow_synthetic_binding_evidence_for_test,
            allow_synthetic_provider_log_evidence_for_test=active_context.allow_synthetic_provider_log_evidence_for_test,
        )
        decision = self.engine.evaluate(
            observation,
            eval_context,
            contradictory_evidence=conflict or policy_conflict,
        )
        state = decision.state
        reason = decision.reason
        if conflict:
            reason = "GPU_IDENTITY_CONFLICT"
        elif correlation_reason is not None:
            reason = correlation_reason
        elif device is None or detection is None:
            reason = "GPU_IDENTITY_UNVERIFIED"
        elif self.policy_snapshot is not None and not self._policy_scope_matches(entry):
            reason = "POLICY_SCOPE_UNVERIFIED"
        elif detected_gpu_key is not None and floor is None:
            reason = "FLOOR_UNCONFIGURED"
        if resolution is not None and resolution.context is None:
            state = "EARLY_UNKNOWN"
            reason = resolution.reason
        if not _SAFE_REASON_RE.fullmatch(reason):
            reason = "UNSAFE_DECISION_REASON"
        cause = StartupCause.LOW_AUTOTUNE if state == "EARLY_UNDER_FLOOR" else StartupCause.UNKNOWN
        recovery = self.engine.classify_recovery(
            cause,
            admission_decision=decision if cause is StartupCause.LOW_AUTOTUNE else None,
        )
        pool_value = self._pool_equivalent.get((resource_key, device)) if resource_key and device is not None else None
        ingestion_dt = datetime.fromisoformat(watcher_ingested_at_utc.replace("Z", "+00:00"))
        raw_event_age = (ingestion_dt - timestamp).total_seconds()
        if raw_event_age < 0:
            state = "EARLY_UNKNOWN"
            reason = "CLOCK_INCONSISTENT"
            cause = StartupCause.UNKNOWN
            recovery = self.engine.classify_recovery(StartupCause.UNKNOWN)
            event_age = None
        else:
            event_age = raw_event_age
        local_elapsed = max(0.0, (self.monotonic() - decision_started_monotonic) * 1000.0)
        response_elapsed = max(0.0, (self.monotonic() - response_received_monotonic) * 1000.0)
        provenance = (
            "SYNTHETIC_TEST_ONLY" if entry.data_classification == DATA_CLASSIFICATION
            else "PROVIDER_OBSERVED_LABELS_AND_GPU_INIT"
        ) if ref is not None else (
            "GPU_IDENTITY_CONFLICT" if conflict else
            "MINER_REPORTED_UNCORROBORATED" if reported_key is not None else
            "IDENTITY_OR_GPU_EVIDENCE_UNVERIFIED"
        )
        return StartupEarlyEvent(
            state=state,
            reason=reason,
            cause=cause.value,
            signal_type=signal_type,
            device_index=device,
            gpu_key=gpu_key,
            estimate_ths=float(estimate) if estimate is not None else None,
            floor_ths=floor,
            floor_source=floor_source,
            floor_catalog_hash=snapshot.floor_catalog_hash if snapshot is not None else None,
            policy_hash=policy.policy_hash if policy is not None else None,
            pool_equivalent_ths=pool_value,
            event_time_utc=event_time,
            data_classification=entry.data_classification,
            recovery=recovery,
            provenance_status=provenance,
            polling_latency_seconds=None,
            polling_latency_status="UNKNOWN_PROVIDER_AVAILABILITY_TIME",
            event_age_at_ingestion_seconds=round(event_age, 3) if event_age is not None else None,
            provider_response_received_at_utc=response_received_at_utc,
            watcher_ingested_at_utc=watcher_ingested_at_utc,
            response_to_decision_ms=round(response_elapsed, 3),
            classification_ms=round(local_elapsed, 3),
            decision=state,
            _provider_binding_proof_handle=(
                _startup_v2_proof_handle(resolution) if resolution is not None else None
            ),
        )

    def _correlate_implicit_pearl_device(
        self,
        resource_key: str | None,
        reported_gpu_key: str | None,
    ) -> tuple[int | None, str | None]:
        """Match a model-only Pearl record only when one initialized device is unambiguous."""
        if resource_key is None or reported_gpu_key is None:
            return None, "GPU_IDENTITY_UNVERIFIED"
        resource_detections = [
            (device, detection)
            for (key, device), detection in self._gpu_detections.items()
            if key == resource_key
        ]
        matching = [
            (device, detection)
            for device, detection in resource_detections
            if not detection.conflict and detection.gpu_key == reported_gpu_key
        ]
        if len(matching) == 1:
            return matching[0][0], None
        if len(matching) > 1:
            return None, "GPU_IDENTITY_AMBIGUOUS"
        # A single initialized device with a different explicit model is a
        # contradiction. With multiple devices, a missing match is ambiguous
        # rather than evidence that the provider log identities conflict.
        if len(resource_detections) == 1 and not resource_detections[0][1].conflict:
            return None, "GPU_IDENTITY_CONFLICT"
        if any(detection.conflict for _device, detection in resource_detections):
            return None, "GPU_IDENTITY_CONFLICT"
        return None, "GPU_IDENTITY_UNVERIFIED"

    def _non_gpu_event(self, entry: NormalizedLogEntry, message: str | None) -> StartupEarlyEvent | None:
        event_time = canonical_utc(entry.event_time_utc)
        if entry.cuda_signal == "CUDA_DRIVER_INCOMPATIBLE":
            return self._event(state="STARTUP_UNQUALIFIED", reason="CUDA_DRIVER_VERSION_INSUFFICIENT", cause=StartupCause.CUDA_INCOMPATIBLE, event_time=event_time, classification=entry.data_classification)
        if entry.alert is not None and entry.alert.event_type in {"POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE"} and entry.alert.fields.get("reason") == "MINING_AUTHORIZE_RESPONSE_TIMEOUT":
            return self._event(state="STARTUP_NON_GPU_CAUSE", reason="POOL_AUTH_TIMEOUT", cause=StartupCause.POOL_AUTH_TIMEOUT, event_time=event_time, classification=entry.data_classification)
        if entry.alert is not None and entry.alert.event_type == "MINER_STARTUP_HASHRATE_TIMEOUT":
            reason = entry.alert.fields.get("reason")
            cause = {"NO_POSITIVE_DEVICE_HASHRATE": StartupCause.NO_POSITIVE_HASHRATE, "MINER_EXITED_BEFORE_HASHRATE": StartupCause.PROCESS_EXIT}.get(reason, StartupCause.UNKNOWN)
            elapsed = entry.alert.fields.get("startup_timeout_seconds", 0)
            return self._event(state="STARTUP_NON_GPU_CAUSE", reason=cause.value, cause=cause, event_time=event_time, classification=entry.data_classification, elapsed_seconds=elapsed if type(elapsed) is int else 0)
        if entry.cuda_signal == "MINER_EXIT_STATUS_1":
            return self._event(state="STARTUP_NON_GPU_CAUSE", reason="PROCESS_EXIT", cause=StartupCause.PROCESS_EXIT, event_time=event_time, classification=entry.data_classification)
        return None

    @staticmethod
    def _message(entry: NormalizedLogEntry) -> str | None:
        candidates: list[str] = []
        if isinstance(entry.text_log, str):
            candidates.append(entry.text_log)
        structured = entry.structured_message
        if isinstance(structured, str):
            candidates.append(structured)
        elif isinstance(structured, Mapping):
            for key in ("message", "text"):
                value = structured.get(key)
                if isinstance(value, str):
                    candidates.append(value)
        if not candidates or any(len(item) > MAX_TEXT_LOG_CHARS for item in candidates):
            return None
        distinct = set(candidates)
        return candidates[0] if len(distinct) == 1 else None

    def _simple_event(
        self, *, state: str, reason: str, event: NormalizedLogEntry, signal: str | None,
        device: int | None, gpu_key: str | None, estimate: float | None, floor: float | None,
        floor_source: str | None, decision: str, ingested_at: str, provenance: str,
    ) -> StartupEarlyEvent:
        recovery = self.engine.classify_recovery(StartupCause.UNKNOWN)
        return StartupEarlyEvent(
            state=state,
            reason=reason if _SAFE_REASON_RE.fullmatch(reason) else "UNKNOWN",
            cause="UNKNOWN",
            signal_type=signal,
            device_index=device,
            gpu_key=gpu_key,
            estimate_ths=estimate,
            floor_ths=floor,
            floor_source=floor_source,
            floor_catalog_hash=(
                self.policy_snapshot.floor_catalog_hash
                if self.policy_snapshot is not None and self._policy_scope_matches(event)
                else None
            ),
            policy_hash=self.policy_snapshot.policy.policy_hash if self.policy_snapshot and self._policy_scope_matches(event) else None,
            event_time_utc=canonical_utc(event.event_time_utc),
            data_classification=event.data_classification,
            recovery=recovery,
            provenance_status=provenance,
            watcher_ingested_at_utc=ingested_at,
            decision=decision,
        )

    def _event(
        self,
        *,
        state: str,
        reason: str,
        cause: StartupCause,
        event_time: str,
        classification: str,
        elapsed_seconds: int | float = 0,
    ) -> StartupEarlyEvent:
        if cause.value not in CAUSE_CODES:
            cause = StartupCause.UNKNOWN
        recovery = self.engine.classify_recovery(cause, elapsed_seconds=elapsed_seconds)
        return StartupEarlyEvent(
            state=state,
            reason=reason if _SAFE_REASON_RE.fullmatch(reason) else "UNKNOWN",
            cause=cause.value,
            signal_type=None,
            device_index=None,
            gpu_key=None,
            estimate_ths=None,
            floor_ths=None,
            event_time_utc=event_time,
            data_classification=classification,
            recovery=recovery,
        )

    def _prune_detections(self, now: float) -> None:
        expired = [
            key for key, value in self._gpu_detections.items()
            if now - value.inserted_monotonic > GPU_DETECTION_TTL_SECONDS
        ]
        for key in expired:
            self._gpu_detections.pop(key, None)
            self._pool_equivalent.pop(key, None)
        if len(self._gpu_detections) > MAX_GPU_DETECTIONS:
            oldest = sorted(self._gpu_detections.items(), key=lambda item: item[1].inserted_monotonic)
            for key, _value in oldest[:len(oldest) - MAX_GPU_DETECTIONS]:
                self._gpu_detections.pop(key, None)
                self._pool_equivalent.pop(key, None)
