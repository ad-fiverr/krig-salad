"""Bounded normalization for synthetic and transport-proven Salad log records.

Offline fixtures use a local envelope, not a verified wire schema. Provider
classification is accepted only with response evidence from the exact
transport. Resource identity is sourced only from ``resource.labels``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
import hashlib
import json
import math
import re
import shlex

from .contract import DATA_CLASSIFICATION, PROVIDER_OBSERVED, canonical_utc


MAX_ENTRY_BYTES = 64_000
MAX_TEXT_LOG_CHARS = 8_192
MAX_STRUCTURED_BYTES = 32_000
MAX_RESOURCE_LABELS = 128
MAX_LABEL_VALUE_CHARS = 1_024
MAX_POOL_RETRY_SECONDS = 86_400
CUDA_DRIVER_FAILURE_REASON = "CUDA_DRIVER_VERSION_INSUFFICIENT"
CUDA_FATAL_LINE = (
    "No supported GPUs found (CUDA: cudaGetDeviceCount: CUDA driver version is "
    "insufficient for CUDA runtime version, OpenCL: <nil>)."
)
CUDA_EXIT_STATUS_LINE = "Fl4shMiner stopped: exit status 1"
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GPU_KEY_RE = re.compile(r"^RTX_[A-Z0-9]+(?:_[A-Z0-9]+)*$")
_DEVICE_RE = re.compile(r"^fl4shminer_device:[0-9]{1,4}$")
_POLICY_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_POOL_LINE_RE = re.compile(
    r"(?:(?P<timestamp>[0-9]{4}/[0-9]{2}/[0-9]{2} "
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}) )?"
    r"Pool connection failed: mining\.authorize response timeout"
    r"; reconnecting; retrying in (?P<retry_seconds>[0-9]{1,5})s"
)
_POOL_RECOVERY_EVIDENCE_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_SOLUTIONS_ACCEPTED_RE = re.compile(
    r"^Solutions accepted:\s+[0-9]{1,10}-NVIDIA GeForce RTX "
    r"[A-Za-z0-9 .+()/_-]{1,192}"
    r"(?:,\s*(?:[0-9]{1,10} stale|stale=[0-9]{1,10}|[0-9]{1,10} accepted))?$",
    re.IGNORECASE,
)
_CONFIG_INVALID_RE = re.compile(
    r"^FL4SH_MONITOR configuration invalid: "
    r"(?P<reason>INVALID_GPU_FLOORS_JSON|MISSING_TELEGRAM_TOKEN|"
    r"MISSING_TELEGRAM_CHAT_ID|INVALID_MONITOR_SETTING|"
    r"INVALID_ENTRYPOINT_CONFIGURATION)$"
)
_STARTUP_TIMESTAMP = r"(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?"
_CUDA_FATAL_RE = re.compile(r"^" + _STARTUP_TIMESTAMP + re.escape(CUDA_FATAL_LINE) + r"$")
_CUDA_EXIT_STATUS_RE = re.compile(r"^" + _STARTUP_TIMESTAMP + re.escape(CUDA_EXIT_STATUS_LINE) + r"$")
FIXTURE_LIFECYCLE_SOURCE = "SYNTHETIC_PROVIDER_LIFECYCLE_FIXTURE"
_INITIALIZED_RE = re.compile(
    r"^" + _STARTUP_TIMESTAMP + r"Device\s*\[(?P<device>[0-9]{1,3})\]\s+"
    r"(?P<gpu>[^\r\n:]{1,256})\s*:\s*Initialized$",
    re.IGNORECASE,
)
_HASHRATE_PROGRESS_RE = re.compile(
    r"^" + _STARTUP_TIMESTAMP + r"Device\s*\[(?P<device>[0-9]{1,3})\]\s+"
    r"hashRate:\s*(?P<rate>[0-9]+(?:\.[0-9]+)?)\s+TH/s(?:,.*)?$",
    re.IGNORECASE,
)
_MONITOR_PROGRESS_RE = re.compile(r"^FL4SH_MONITOR\s+state=(?P<state>CONFIG|GPU_DETECTED)(?:\s|$)")
_SAFE_REASON_CODES = frozenset({
    "INVALID_GPU_FLOORS_JSON", "MISSING_TELEGRAM_TOKEN", "MISSING_TELEGRAM_CHAT_ID",
    "INVALID_MONITOR_SETTING", "INVALID_ENTRYPOINT_CONFIGURATION",
})
_EVENT_FIELDS = frozenset({
    "FL4SH_MONITOR", "state", "profile", "device", "gpu_key", "gpu_candidates",
    "gpu_raw", "floor", "floor_ths", "floor_source", "observed", "bad_windows",
    "coverage", "window_samples", "stale", "stale_pct", "provider_binding",
    "gpu_identity_verified", "billing", "actions_performed", "policy_hash", "timestamp",
    "alert_id", "tolerance_ths", "decision_threshold_ths", "episode_id", "alert_sequence",
    "notification_reason", "previous_alert_mean_ths",
    "deterioration_since_previous_alert_ths", "reason",
    "failure_count", "window_seconds", "first_failure_utc", "latest_failure_utc",
    "monitor_session_id", "pool_episode_id", "pool_alert_sequence",
    "recent_failure_count", "unstable_duration_seconds", "prior_failure_count",
    "recent_failure_window_start_utc", "recovery_signal", "recovered_at_utc",
    "retry_seconds", "timestamp_utc", "solutions_evidence_sha256",
})
_MARKER_FIELDS = frozenset({
    "FL4SH_MONITOR", "state", "alert_id", "event", "actions_performed", "episode_id",
    "alert_sequence", "monitor_session_id", "pool_episode_id", "pool_alert_sequence",
})
_IDENTITY_LABELS = {
    "machineid": "machine_id",
    "instanceid": "instance_id",
    "containergroupname": "container_group_name",
    "organizationname": "organization_name",
    "projectname": "project_name",
}
_SECRET_KEY_RE = re.compile(
    r"(?i)(?:secret|token|password|credential|api.?key|authorization|private.?key)"
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:\b(?:bearer|basic)\s+\S{8,}|salad[ _-]*api[ _-]*key\s*[:=]|"
    r"(?:^|[\s&])(?:api[_-]?key|authorization|token)\s*[:=]\s*[^\s&,;]+)"
)


class LogRecordError(ValueError):
    """The synthetic log envelope is malformed or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class ProviderIdentity:
    status: str
    machine_id: str | None
    instance_id: str | None
    container_group_name: str | None
    organization_name: str | None
    project_name: str | None
    source: str
    labels_fingerprint: str

    def resource_key(self) -> str:
        if self.machine_id and self.instance_id:
            values = [self.organization_name, self.project_name, self.container_group_name,
                      self.machine_id, self.instance_id]
            return hashlib.sha256(_canonical_json(values).encode("utf-8")).hexdigest()
        return self.labels_fingerprint

    def public_fields(self) -> dict[str, Any]:
        identity_known = self.status in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}
        identity_conflict = self.status == "CONFLICTING"
        return {
            "identity_status": self.status,
            "machine_id": self.machine_id if identity_known else None,
            "instance_id": self.instance_id if identity_known else None,
            "container_group_name": None if identity_conflict else self.container_group_name,
            "organization_name": None if identity_conflict else self.organization_name,
            "project_name": None if identity_conflict else self.project_name,
            "identity_source": self.source,
        }


@dataclass(frozen=True, slots=True)
class MonitorAlert:
    event_type: str
    fields: Mapping[str, Any]
    alert_id: str | None = None

    def identity_tuple(self) -> tuple[Any, ...]:
        return (self.event_type, tuple(sorted(self.fields.items())))


@dataclass(frozen=True, slots=True)
class AlertMarker:
    alert_id: str
    event_type: str
    episode_id: str | None = None
    alert_sequence: int | None = None
    monitor_session_id: str | None = None
    pool_episode_id: str | None = None
    pool_alert_sequence: int | None = None


@dataclass(frozen=True, slots=True)
class NormalizedLogEntry:
    log_id: str | None
    event_time_utc: str
    resource_type: str
    resource_labels: Mapping[str, Any]
    text_log: str | None
    structured_message: Any
    data_classification: str
    identity: ProviderIdentity
    alert: MonitorAlert | None
    marker: AlertMarker | None
    alert_source: str | None
    evidence_sha256: str
    startup_signal: str | None
    startup_signal_source: str | None
    cuda_signal: str | None
    cuda_signal_source: str | None
    pool_recovery_signal: bool = False
    pool_recovery_signal_sha256: str | None = None
    pool_recovery_marker: "PoolRecoveryMarker | None" = None


@dataclass(frozen=True, slots=True)
class PoolRecoveryMarker:
    monitor_session_id: str
    pool_episode_id: str
    pool_alert_sequence: int
    recovery_signal: str
    timestamp_utc: str
    solutions_evidence_sha256: str


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _plain_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        raise LogRecordError("structured log message exceeds the local depth limit")
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            raise LogRecordError("structured log message contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        if len(value) > 256 or any(not isinstance(key, str) or len(key) > 128 for key in value):
            raise LogRecordError("structured log message exceeds local object bounds")
        return {key: _plain_json_value(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        if len(value) > 512:
            raise LogRecordError("structured log message exceeds local array bounds")
        return [_plain_json_value(item, depth=depth + 1) for item in value]
    raise LogRecordError("structured log message is not JSON-compatible")


def _reject_secret_like_content(value: Any, *, depth: int = 0) -> None:
    """Fail closed on credential-shaped fields without echoing their values."""
    if depth > 8:
        raise LogRecordError("log envelope exceeds local inspection depth")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and _SECRET_KEY_RE.search(key):
                raise LogRecordError("credential-like log content is forbidden")
            _reject_secret_like_content(item, depth=depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_secret_like_content(item, depth=depth + 1)
    elif isinstance(value, str) and _SECRET_VALUE_RE.search(value):
        raise LogRecordError("credential-like log content is forbidden")


def _clean_label_scalar(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        return None
    text = str(value)
    if len(text) > MAX_LABEL_VALUE_CHARS or any(ord(char) < 32 for char in text):
        return None
    return text


def _label_canonical_name(name: str) -> str | None:
    folded = re.sub(r"[^a-z0-9]", "", name.casefold())
    return _IDENTITY_LABELS.get(folded)


def provider_organization_label_values(labels: Mapping[str, Any]) -> tuple[str, ...]:
    """Return explicit organization-label values for scope validation only."""
    if not isinstance(labels, Mapping):
        return ()
    values: set[str] = set()
    for key, raw_value in labels.items():
        if isinstance(key, str) and _label_canonical_name(key) == "organization_name":
            value = _clean_label_scalar(raw_value)
            if value is not None:
                values.add(value)
    return tuple(sorted(values))


def resolve_provider_identity(
    labels: Mapping[str, Any], *, complete_identity_status: str = DATA_CLASSIFICATION,
) -> ProviderIdentity:
    if not isinstance(labels, Mapping) or len(labels) > MAX_RESOURCE_LABELS:
        raise LogRecordError("resource labels are malformed or exceed local bounds")
    safe_labels: dict[str, Any] = {}
    grouped_values: dict[str, set[str]] = {}
    for key, raw_value in labels.items():
        if not isinstance(key, str) or not key or len(key) > 128 or any(ord(c) < 32 for c in key):
            raise LogRecordError("resource label key is invalid")
        if raw_value is not None and (
            not isinstance(raw_value, str)
            or len(raw_value) > MAX_LABEL_VALUE_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in raw_value)
        ):
            raise LogRecordError("resource label value is invalid or exceeds local bounds")
        safe_value = _plain_json_value(raw_value)
        safe_labels[key] = safe_value
        canonical = _label_canonical_name(key)
        if canonical is not None:
            candidates = {_clean_label_scalar(raw_value)}
            candidates.discard(None)
            if candidates:
                grouped_values.setdefault(canonical, set()).update(candidates)
    canonical_values: dict[str, str | None] = {}
    conflicting = False
    for key, values in grouped_values.items():
        if len(values) > 1:
            conflicting = True
        else:
            canonical_values[key] = next(iter(values))
    machine_id = canonical_values.get("machine_id")
    instance_id = canonical_values.get("instance_id")
    group_name = canonical_values.get("container_group_name")
    organization = canonical_values.get("organization_name")
    project = canonical_values.get("project_name")
    if any(value is not None and not _SAFE_ID_RE.fullmatch(value) for value in (
        machine_id, instance_id, group_name, organization, project
    )):
        machine_id = instance_id = None
        conflicting = True
    label_digest = hashlib.sha256(_canonical_json(safe_labels).encode("utf-8")).hexdigest()
    if conflicting:
        status = "CONFLICTING"
        machine_id = instance_id = None
    elif machine_id is None or instance_id is None:
        status = "UNKNOWN"
    else:
        # Even syntactically consistent fixture labels are never provider-verified.
        if complete_identity_status not in {DATA_CLASSIFICATION, PROVIDER_OBSERVED}:
            raise LogRecordError("identity provenance is invalid")
        status = complete_identity_status
    return ProviderIdentity(
        status=status,
        machine_id=machine_id,
        instance_id=instance_id,
        container_group_name=group_name,
        organization_name=organization,
        project_name=project,
        source="resource.labels",
        labels_fingerprint=label_digest,
    )


def _finite_number(value: Any, *, positive: bool = False) -> float:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise LogRecordError("monitor event has an invalid numeric field")
    try:
        number = float(value)
    except (ValueError, OverflowError) as exc:
        raise LogRecordError("monitor event has an invalid numeric field") from exc
    if not math.isfinite(number) or (positive and number <= 0) or (not positive and number < 0):
        raise LogRecordError("monitor event numeric field is outside bounds")
    return number


def _safe_token(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise LogRecordError("monitor event has an invalid bounded field")
    return value


def _parse_bad_windows(value: Any) -> tuple[int, int]:
    if not isinstance(value, str):
        raise LogRecordError("monitor event has invalid bad-window data")
    match = re.fullmatch(r"([0-9]{1,4})/([0-9]{1,4})", value)
    if not match:
        raise LogRecordError("monitor event has invalid bad-window data")
    bad, required = (int(part) for part in match.groups())
    if not 1 <= bad <= required <= 1_000:
        raise LogRecordError("monitor event bad-window count is outside bounds")
    return bad, required


def _parse_stale(value: Any, percent_value: Any) -> dict[str, Any] | None:
    if value is None:
        if percent_value is not None:
            raise LogRecordError("stale percentage has no counter")
        return None
    if not isinstance(value, str):
        raise LogRecordError("monitor event has invalid stale counter")
    match = re.fullmatch(r"([0-9]{1,9})/([0-9]{1,9})", value)
    if not match:
        raise LogRecordError("monitor event has invalid stale counter")
    numerator, denominator = (int(part) for part in match.groups())
    if denominator <= 0 or numerator > denominator:
        raise LogRecordError("monitor event stale counter is outside bounds")
    percent = None
    if percent_value is not None:
        text = str(percent_value).removesuffix("%")
        percent = _finite_number(text)
        if percent > 100:
            raise LogRecordError("monitor event stale percentage is outside bounds")
    return {"numerator": numerator, "denominator": denominator, "reported_percent": percent}


def _normalize_reallocation(fields: Mapping[str, Any]) -> MonitorAlert:
    if fields.get("actions_performed") != "false" and fields.get("actions_performed") is not False:
        raise LogRecordError("monitor action state is not dry-run")
    device = _safe_token(fields.get("device"), _DEVICE_RE)
    gpu_key = _safe_token(fields.get("gpu_key"), _GPU_KEY_RE)
    floor = _finite_number(fields.get("floor_ths"), positive=True)
    if fields.get("floor") is not None:
        floor_alias = _finite_number(fields.get("floor"), positive=True)
        if not math.isclose(floor, floor_alias, rel_tol=0.0, abs_tol=1e-9):
            raise LogRecordError("monitor floor fields conflict")
    observed = _finite_number(fields.get("observed"))
    bad, required = _parse_bad_windows(fields.get("bad_windows"))
    policy_hash = _safe_token(fields.get("policy_hash"), _POLICY_HASH_RE)
    monitor_time = fields.get("timestamp")
    monitor_time_utc = canonical_utc(monitor_time) if monitor_time is not None else None
    stale = _parse_stale(fields.get("stale"), fields.get("stale_pct"))
    tolerance = None
    threshold = None
    if fields.get("tolerance_ths") is not None or fields.get("decision_threshold_ths") not in (None, "unknown"):
        tolerance = _finite_number(fields.get("tolerance_ths"), positive=True)
        if not 1.0 <= tolerance <= 3.0:
            raise LogRecordError("monitor floor tolerance is outside bounds")
        expected_threshold = floor - tolerance
        if expected_threshold <= 0:
            raise LogRecordError("monitor decision threshold is not actionable")
        threshold = _finite_number(fields.get("decision_threshold_ths"), positive=True)
        if not math.isclose(threshold, expected_threshold, rel_tol=0.0, abs_tol=1e-6):
            raise LogRecordError("monitor decision threshold conflicts with floor policy")
    episode_id = fields.get("episode_id")
    sequence = fields.get("alert_sequence")
    reason = fields.get("notification_reason")
    previous_mean = fields.get("previous_alert_mean_ths")
    deterioration = fields.get("deterioration_since_previous_alert_ths")
    if episode_id is not None or sequence is not None or reason is not None:
        if not isinstance(episode_id, str) or not _UUID_RE.fullmatch(episode_id):
            raise LogRecordError("monitor degradation episode ID is invalid")
        if not isinstance(sequence, str) or not re.fullmatch(r"[1-9][0-9]{0,5}", sequence):
            raise LogRecordError("monitor alert sequence is invalid")
        sequence_number = int(sequence)
        if reason not in {"INITIAL_THRESHOLD_CROSSING", "WORSENED"}:
            raise LogRecordError("monitor alert reason is invalid")
        if (sequence_number == 1) != (reason == "INITIAL_THRESHOLD_CROSSING"):
            raise LogRecordError("monitor alert reason conflicts with sequence")
        if sequence_number > 1:
            previous_mean = _finite_number(previous_mean, positive=True)
            deterioration = _finite_number(deterioration, positive=True)
        else:
            previous_mean = None
            deterioration = None
    else:
        sequence_number = None
    alert_id = fields.get("alert_id")
    if alert_id is not None and (not isinstance(alert_id, str) or not _UUID_RE.fullmatch(alert_id)):
        raise LogRecordError("monitor alert ID is invalid")
    result = {
        "gpu_key": gpu_key,
        "device": device,
        "floor_ths": floor,
        "observed_window_mean_ths": observed,
        "bad_windows": bad,
        "bad_windows_required": required,
        "stale": stale,
        "policy_hash": policy_hash,
        "monitor_timestamp_utc": monitor_time_utc,
        "floor_tolerance_ths": tolerance,
        "decision_threshold_ths": threshold,
        "degradation_episode_id": episode_id,
        "alert_sequence": sequence_number,
        "notification_reason": reason,
        "previous_alert_mean_ths": previous_mean,
        "deterioration_since_previous_alert_ths": deterioration,
        "actions_performed": False,
    }
    return MonitorAlert("REALLOCATE_RECOMMENDED", result, alert_id)


def _normalize_pool(fields: Mapping[str, Any]) -> MonitorAlert:
    action_value = fields.get("actions_performed", False)
    if action_value is not False and action_value != "false":
        raise LogRecordError("monitor action state is not dry-run")
    if fields.get("reason") != "MINING_AUTHORIZE_RESPONSE_TIMEOUT":
        raise LogRecordError("pool event reason is not the exact normalized cause")
    retry = fields.get("retry_seconds")
    if type(retry) is not int or not 1 <= retry <= MAX_POOL_RETRY_SECONDS:
        raise LogRecordError("pool retry interval is outside bounds")
    alert_id = fields.get("alert_id")
    if alert_id is not None and (not isinstance(alert_id, str) or not _UUID_RE.fullmatch(alert_id)):
        raise LogRecordError("monitor alert ID is invalid")
    return MonitorAlert(
        "POOL_CONNECTION_FAILED",
        {"reason": "MINING_AUTHORIZE_RESPONSE_TIMEOUT", "retry_seconds": retry,
         "actions_performed": False},
        alert_id,
    )


def _normalize_pool_episode_failed(fields: Mapping[str, Any]) -> MonitorAlert:
    if fields.get("actions_performed") not in (False, "false"):
        raise LogRecordError("monitor action state is not dry-run")
    if fields.get("reason") != "MINING_AUTHORIZE_RESPONSE_TIMEOUT":
        raise LogRecordError("pool event reason is not the exact normalized cause")
    episode_id = _safe_token(fields.get("pool_episode_id"), _UUID_RE)
    session_id = _safe_token(fields.get("monitor_session_id"), _UUID_RE)
    sequence = _bounded_integer(fields.get("pool_alert_sequence"), minimum=1, maximum=1_000_000)
    failure_count = _bounded_integer(fields.get("failure_count"), minimum=1, maximum=POOL_MAX_FAILURE_COUNT)
    retry = _bounded_integer(fields.get("retry_seconds"), minimum=1, maximum=MAX_POOL_RETRY_SECONDS)
    first = canonical_utc(fields.get("first_failure_utc"))
    latest = canonical_utc(fields.get("latest_failure_utc"))
    if sequence != 1 or failure_count != 1 or first != latest:
        raise LogRecordError("initial pool alert does not describe the first episode failure")
    alert_id = fields.get("alert_id")
    if alert_id is not None and (not isinstance(alert_id, str) or not _UUID_RE.fullmatch(alert_id)):
        raise LogRecordError("monitor alert ID is invalid")
    return MonitorAlert("POOL_CONNECTION_FAILED", {
        "reason": "MINING_AUTHORIZE_RESPONSE_TIMEOUT",
        "retry_seconds": retry,
        "pool_episode_id": episode_id,
        "pool_alert_sequence": sequence,
        "monitor_session_id": session_id,
        "failure_count": failure_count,
        "first_failure_utc": first,
        "latest_failure_utc": latest,
        "gpu_key": _pool_gpu(fields.get("gpu_key", "unknown")),
        "device": _pool_device(fields.get("device", "unknown")),
        "actions_performed": False,
    }, alert_id)


POOL_MAX_FAILURE_COUNT = 1_000_000


def _pool_gpu(value: Any) -> str:
    return "unknown" if value in (None, "unknown") else _safe_token(value, _GPU_KEY_RE)


def _pool_device(value: Any) -> str:
    return "unknown" if value in (None, "unknown") else _safe_token(value, _DEVICE_RE)


def _normalize_pool_recovered(fields: Mapping[str, Any]) -> MonitorAlert:
    if fields.get("actions_performed") not in (False, "false"):
        raise LogRecordError("monitor action state is not dry-run")
    episode_id = _safe_token(fields.get("pool_episode_id"), _UUID_RE)
    session_id = _safe_token(fields.get("monitor_session_id"), _UUID_RE)
    sequence = _bounded_integer(fields.get("pool_alert_sequence"), minimum=2, maximum=1_000_000)
    prior_count = _bounded_integer(fields.get("prior_failure_count"), minimum=1, maximum=POOL_MAX_FAILURE_COUNT)
    failure_count = _bounded_integer(fields.get("failure_count"), minimum=1, maximum=POOL_MAX_FAILURE_COUNT)
    retry = _bounded_integer(fields.get("retry_seconds"), minimum=1, maximum=MAX_POOL_RETRY_SECONDS)
    if fields.get("recovery_signal") != "SOLUTIONS_ACCEPTED":
        raise LogRecordError("pool recovery signal is not allowlisted")
    first = canonical_utc(fields.get("first_failure_utc"))
    latest = canonical_utc(fields.get("latest_failure_utc"))
    recovered = canonical_utc(fields.get("recovered_at_utc"))
    timestamp = canonical_utc(fields.get("timestamp_utc"))
    evidence_hash = fields.get("solutions_evidence_sha256")
    if not isinstance(evidence_hash, str) or not _POOL_RECOVERY_EVIDENCE_HASH_RE.fullmatch(evidence_hash):
        raise LogRecordError("pool recovery evidence reference is invalid")
    if (
        failure_count != prior_count
        or timestamp != recovered
        or _utc_delta(first, latest) < 0
        or _utc_delta(latest, recovered) < 0
    ):
        raise LogRecordError("pool recovery episode fields are inconsistent")
    alert_id = fields.get("alert_id")
    if alert_id is not None and (not isinstance(alert_id, str) or not _UUID_RE.fullmatch(alert_id)):
        raise LogRecordError("monitor alert ID is invalid")
    return MonitorAlert("POOL_CONNECTION_RECOVERED", {
        "pool_episode_id": episode_id,
        "pool_alert_sequence": sequence,
        "monitor_session_id": session_id,
        "prior_failure_count": prior_count,
        "failure_count": failure_count,
        "retry_seconds": retry,
        "first_failure_utc": first,
        "latest_failure_utc": latest,
        "recovery_signal": "SOLUTIONS_ACCEPTED",
        "recovered_at_utc": recovered,
        "timestamp_utc": timestamp,
        "solutions_evidence_sha256": evidence_hash,
        "gpu_key": _pool_gpu(fields.get("gpu_key", "unknown")),
        "device": _pool_device(fields.get("device", "unknown")),
        "actions_performed": False,
    }, alert_id)


def _normalize_pool_episode_unstable(fields: Mapping[str, Any]) -> MonitorAlert:
    if fields.get("actions_performed") not in (False, "false"):
        raise LogRecordError("monitor action state is not dry-run")
    if fields.get("reason") != "MINING_AUTHORIZE_RESPONSE_TIMEOUT":
        raise LogRecordError("pool event reason is not the exact normalized cause")
    episode_id = _safe_token(fields.get("pool_episode_id"), _UUID_RE)
    session_id = _safe_token(fields.get("monitor_session_id"), _UUID_RE)
    sequence = _bounded_integer(fields.get("pool_alert_sequence"), minimum=2, maximum=1_000_000)
    count = _bounded_integer(fields.get("failure_count"), minimum=2, maximum=POOL_MAX_FAILURE_COUNT)
    recent = _bounded_integer(fields.get("recent_failure_count"), minimum=1, maximum=min(count, 64))
    retry = _bounded_integer(fields.get("retry_seconds"), minimum=1, maximum=MAX_POOL_RETRY_SECONDS)
    duration = _bounded_integer(fields.get("unstable_duration_seconds"), minimum=0, maximum=2_592_000)
    first = canonical_utc(fields.get("first_failure_utc"))
    latest = canonical_utc(fields.get("latest_failure_utc"))
    recent_start = canonical_utc(fields.get("recent_failure_window_start_utc"))
    delta = _utc_delta(first, latest)
    recent_delta = _utc_delta(recent_start, latest)
    if delta < 0 or recent_delta < 0 or _utc_delta(first, recent_start) < 0:
        raise LogRecordError("pool failure timestamps are out of order")
    notification_reason = fields.get("notification_reason")
    if notification_reason == "BURST_FAILURES":
        if recent < 3 or recent_delta > 90:
            raise LogRecordError("pool burst evidence does not meet its bounded threshold")
    elif notification_reason == "PERSISTENT_FAILURES":
        if count < 2 or delta < 300:
            raise LogRecordError("persistent pool evidence does not meet its bounded threshold")
    elif notification_reason == "STILL_UNSTABLE":
        if sequence < 3 or duration < 900:
            raise LogRecordError("pool reminder is earlier than its bounded cooldown")
    else:
        raise LogRecordError("pool notification reason is not allowlisted")
    alert_id = fields.get("alert_id")
    if alert_id is not None and (not isinstance(alert_id, str) or not _UUID_RE.fullmatch(alert_id)):
        raise LogRecordError("monitor alert ID is invalid")
    return MonitorAlert("POOL_CONNECTION_UNSTABLE", {
        "reason": "MINING_AUTHORIZE_RESPONSE_TIMEOUT",
        "pool_episode_id": episode_id,
        "pool_alert_sequence": sequence,
        "monitor_session_id": session_id,
        "notification_reason": notification_reason,
        "failure_count": count,
        "recent_failure_count": recent,
        "recent_failure_window_start_utc": recent_start,
        "retry_seconds": retry,
        "unstable_duration_seconds": duration,
        "first_failure_utc": first,
        "latest_failure_utc": latest,
        "gpu_key": _pool_gpu(fields.get("gpu_key", "unknown")),
        "device": _pool_device(fields.get("device", "unknown")),
        "actions_performed": False,
    }, alert_id)


def _normalize_pool_unstable(fields: Mapping[str, Any]) -> MonitorAlert:
    if fields.get("actions_performed") not in (False, "false"):
        raise LogRecordError("monitor action state is not dry-run")
    if fields.get("reason") != "MINING_AUTHORIZE_RESPONSE_TIMEOUT":
        raise LogRecordError("pool event reason is not the exact normalized cause")
    count = _bounded_integer(fields.get("failure_count"), minimum=3, maximum=10_000)
    window = _bounded_integer(fields.get("window_seconds"), minimum=1, maximum=90)
    first = canonical_utc(fields.get("first_failure_utc"))
    latest = canonical_utc(fields.get("latest_failure_utc"))
    if _utc_delta(first, latest) < 0 or _utc_delta(first, latest) > window:
        raise LogRecordError("pool failure timestamps are outside the reported window")
    gpu = fields.get("gpu_key", "unknown")
    if gpu != "unknown":
        gpu = _safe_token(gpu, _GPU_KEY_RE)
    device = fields.get("device", "unknown")
    if device != "unknown":
        device = _safe_token(device, _DEVICE_RE)
    return MonitorAlert("POOL_CONNECTION_UNSTABLE", {
        "reason": "MINING_AUTHORIZE_RESPONSE_TIMEOUT",
        "failure_count": count,
        "window_seconds": window,
        "first_failure_utc": first,
        "latest_failure_utc": latest,
        "gpu_key": gpu,
        "device": device,
        "actions_performed": False,
    })


def _normalize_no_floor(fields: Mapping[str, Any]) -> MonitorAlert:
    if fields.get("actions_performed") != "false" and fields.get("actions_performed") is not False:
        raise LogRecordError("monitor action state is not dry-run")
    gpu = fields.get("gpu_key", "unknown")
    if gpu != "unknown":
        gpu = _safe_token(gpu, _GPU_KEY_RE)
    device = fields.get("device", "unknown")
    if device != "unknown":
        device = _safe_token(device, _DEVICE_RE)
    observed_value = fields.get("observed")
    observed = None if observed_value in (None, "unknown") else _finite_number(observed_value)
    floor = fields.get("floor_ths", fields.get("floor"))
    if floor not in (None, "unknown"):
        raise LogRecordError("no-floor event unexpectedly includes a floor")
    policy_hash = fields.get("policy_hash")
    if policy_hash is not None:
        policy_hash = _safe_token(policy_hash, _POLICY_HASH_RE)
    return MonitorAlert("NO_FLOOR_CONFIGURED", {
        "gpu_key": gpu,
        "device": device,
        "observed_window_mean_ths": observed,
        "policy_hash": policy_hash,
        "suggestion": "CHECK_GPU_FLOOR_CONFIG",
        "actions_performed": False,
    })


def _normalize_cuda_driver_incompatible() -> MonitorAlert:
    return MonitorAlert("CUDA_DRIVER_INCOMPATIBLE", {
        "reason": CUDA_DRIVER_FAILURE_REASON,
        "gpu_initialized": False,
        "miner_exit_status": "UNKNOWN",
        "exit_status_confirmed": False,
        "recommendation": "REALLOCATE",
        "actions_performed": False,
    })


def _cuda_signal_from_text(text: Any) -> str | None:
    if not isinstance(text, str) or len(text) > MAX_TEXT_LOG_CHARS:
        return None
    fatal = _CUDA_FATAL_RE.fullmatch(text)
    if fatal is not None:
        timestamp = text[:19] if len(text) > len(CUDA_FATAL_LINE) else None
        if timestamp is not None:
            try:
                datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                return None
        return "CUDA_DRIVER_INCOMPATIBLE"
    stopped = _CUDA_EXIT_STATUS_RE.fullmatch(text)
    if stopped is not None:
        timestamp = text[:19] if len(text) > len(CUDA_EXIT_STATUS_LINE) else None
        if timestamp is not None:
            try:
                datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                return None
        return "MINER_EXIT_STATUS_1"
    return None


def _cuda_signal_from_structured(value: Any) -> str | None:
    if isinstance(value, str):
        return _cuda_signal_from_text(value)
    if not isinstance(value, Mapping):
        return None
    signals = {
        signal
        for key in ("message", "text")
        if (signal := _cuda_signal_from_text(value.get(key))) is not None
    }
    if len(signals) > 1:
        raise LogRecordError("structured CUDA evidence conflicts")
    return next(iter(signals), None)


def _bounded_integer(value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise LogRecordError("monitor count is invalid")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        raise LogRecordError("monitor count is invalid") from None
    if str(value) != str(parsed) or not minimum <= parsed <= maximum:
        raise LogRecordError("monitor count is outside bounds")
    return parsed


def _utc_delta(start: str, end: str) -> float:
    return (datetime.fromisoformat(end.replace("Z", "+00:00")) -
            datetime.fromisoformat(start.replace("Z", "+00:00"))).total_seconds()


def _parse_text_message(text: str) -> tuple[MonitorAlert | None, AlertMarker | None]:
    if len(text) > MAX_TEXT_LOG_CHARS:
        raise LogRecordError("text log exceeds the local size limit")
    if _cuda_signal_from_text(text) == "CUDA_DRIVER_INCOMPATIBLE":
        return _normalize_cuda_driver_incompatible(), None
    config_match = _CONFIG_INVALID_RE.fullmatch(text)
    if config_match is not None:
        reason = config_match.group("reason")
        if reason not in _SAFE_REASON_CODES:
            return None, None
        return MonitorAlert("MONITOR_CONFIGURATION_INVALID", {
            "reason": reason,
            "suggestion": "CHECK_CONFIGURATION",
            "actions_performed": False,
        }), None
    pool_match = _POOL_LINE_RE.fullmatch(text)
    if pool_match is not None:
        timestamp = pool_match.group("timestamp")
        if timestamp is not None:
            try:
                datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                return None, None
        retry = int(pool_match.group("retry_seconds"))
        if not 1 <= retry <= MAX_POOL_RETRY_SECONDS:
            return None, None
        return _normalize_pool({
            "reason": "MINING_AUTHORIZE_RESPONSE_TIMEOUT",
            "retry_seconds": retry,
            "actions_performed": False,
        }), None
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return None, None
    if not tokens or tokens[0] != "FL4SH_MONITOR":
        return None, None
    fields: dict[str, str] = {"FL4SH_MONITOR": "true"}
    allowed = _EVENT_FIELDS | _MARKER_FIELDS
    for token in tokens[1:]:
        if "=" not in token:
            return None, None
        key, value = token.split("=", 1)
        if key not in allowed or key in fields:
            return None, None
        fields[key] = value
    if fields.get("actions_performed") != "false":
        return None, None
    if fields.get("state") == "TELEGRAM_ALERT":
        event_type = fields.get("event")
        alert_id = fields.get("alert_id")
        if event_type not in {
            "REALLOCATE_RECOMMENDED", "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
            "POOL_CONNECTION_RECOVERED",
        }:
            return None, None
        if not isinstance(alert_id, str) or not _UUID_RE.fullmatch(alert_id):
            return None, None
        episode_id = fields.get("episode_id")
        if episode_id is not None and not _UUID_RE.fullmatch(episode_id):
            return None, None
        sequence = fields.get("alert_sequence")
        if sequence is not None and not re.fullmatch(r"[1-9][0-9]{0,5}", sequence):
            return None, None
        pool_episode_id = fields.get("pool_episode_id")
        monitor_session_id = fields.get("monitor_session_id")
        pool_sequence_text = fields.get("pool_alert_sequence")
        is_pool_event = event_type.startswith("POOL_CONNECTION_")
        if is_pool_event:
            if (
                not isinstance(pool_episode_id, str) or not _UUID_RE.fullmatch(pool_episode_id)
                or not isinstance(monitor_session_id, str) or not _UUID_RE.fullmatch(monitor_session_id)
                or not isinstance(pool_sequence_text, str)
                or not re.fullmatch(r"[1-9][0-9]{0,5}", pool_sequence_text)
            ):
                return None, None
        return None, AlertMarker(
            alert_id,
            event_type,
            episode_id,
            int(sequence) if sequence else None,
            monitor_session_id,
            pool_episode_id,
            int(pool_sequence_text) if pool_sequence_text else None,
        )
    if fields.get("state") == "REALLOCATE_RECOMMENDED":
        if not _EVENT_FIELDS.issuperset(fields):
            return None, None
        return _normalize_reallocation(fields), None
    if fields.get("state") == "POOL_CONNECTION_FAILED":
        if not _EVENT_FIELDS.issuperset(fields):
            return None, None
        return _normalize_pool_episode_failed(fields), None
    if fields.get("state") == "POOL_CONNECTION_UNSTABLE":
        if "pool_episode_id" in fields:
            if not _EVENT_FIELDS.issuperset(fields):
                return None, None
            return _normalize_pool_episode_unstable(fields), None
        return _normalize_pool_unstable(fields), None
    if fields.get("state") == "POOL_CONNECTION_RECOVERED":
        if not _EVENT_FIELDS.issuperset(fields):
            return None, None
        return _normalize_pool_recovered(fields), None
    if fields.get("state") == "NO_FLOOR_CONFIGURED":
        return _normalize_no_floor(fields), None
    return None, None


def _parse_structured_message(value: Any) -> tuple[MonitorAlert | None, AlertMarker | None]:
    if isinstance(value, str):
        return _parse_text_message(value)
    if not isinstance(value, Mapping):
        return None, None
    state = value.get("state")
    if value.get("type") not in {"FL4SH_MONITOR", None}:
        return None, None
    if state == "TELEGRAM_ALERT":
        alert_id = value.get("alert_id")
        event_type = value.get("event")
        if (
            value.get("actions_performed") is not False
            or not isinstance(alert_id, str)
            or not _UUID_RE.fullmatch(alert_id)
            or event_type not in {
                "REALLOCATE_RECOMMENDED", "POOL_CONNECTION_FAILED", "POOL_CONNECTION_UNSTABLE",
                "POOL_CONNECTION_RECOVERED",
            }
        ):
            return None, None
        episode_id = value.get("episode_id")
        sequence = value.get("alert_sequence")
        if episode_id is not None and (not isinstance(episode_id, str) or not _UUID_RE.fullmatch(episode_id)):
            return None, None
        if sequence is not None and (type(sequence) is not int or not 1 <= sequence <= 1_000_000):
            return None, None
        pool_episode_id = value.get("pool_episode_id")
        monitor_session_id = value.get("monitor_session_id")
        pool_sequence = value.get("pool_alert_sequence")
        if event_type.startswith("POOL_CONNECTION_") and (
            not isinstance(pool_episode_id, str) or not _UUID_RE.fullmatch(pool_episode_id)
            or not isinstance(monitor_session_id, str) or not _UUID_RE.fullmatch(monitor_session_id)
            or type(pool_sequence) is not int or not 1 <= pool_sequence <= 1_000_000
        ):
            return None, None
        return None, AlertMarker(
            alert_id, event_type, episode_id, sequence,
            monitor_session_id, pool_episode_id, pool_sequence,
        )
    if state == "REALLOCATE_RECOMMENDED":
        fields = value.get("fields", value)
        if not isinstance(fields, Mapping):
            raise LogRecordError("structured monitor fields are malformed")
        return _normalize_reallocation(fields), None
    if state == "POOL_CONNECTION_FAILED":
        fields = value.get("fields", value)
        if not isinstance(fields, Mapping):
            raise LogRecordError("structured monitor fields are malformed")
        if "pool_episode_id" in fields:
            return _normalize_pool_episode_failed(fields), None
        return _normalize_pool(fields), None
    if state in {"POOL_CONNECTION_UNSTABLE", "POOL_CONNECTION_RECOVERED", "NO_FLOOR_CONFIGURED"}:
        fields = value.get("fields", value)
        if not isinstance(fields, Mapping):
            raise LogRecordError("structured monitor fields are malformed")
        if state == "POOL_CONNECTION_UNSTABLE":
            if "pool_episode_id" in fields:
                return _normalize_pool_episode_unstable(fields), None
            return _normalize_pool_unstable(fields), None
        if state == "POOL_CONNECTION_RECOVERED":
            return _normalize_pool_recovered(fields), None
        return _normalize_no_floor(fields), None
    message = value.get("message")
    if isinstance(message, str):
        return _parse_text_message(message)
    return None, None


def _startup_signal(text: str | None) -> str | None:
    """Recognize bounded Fl4sh progress records from log text only.

    Running/Ready are deliberately excluded: text_log may contain miner-owned
    output and cannot prove a provider lifecycle transition.
    """
    if not isinstance(text, str) or len(text) > MAX_TEXT_LOG_CHARS:
        return None
    monitor_match = _MONITOR_PROGRESS_RE.match(text)
    if monitor_match is not None:
        return "MONITOR_CONFIG" if monitor_match.group("state") == "CONFIG" else "GPU_DETECTED"
    initialized = _INITIALIZED_RE.fullmatch(text)
    if initialized is not None and initialized.group("gpu").strip():
        return "DEVICE_INITIALIZED"
    hashrate = _HASHRATE_PROGRESS_RE.fullmatch(text)
    if hashrate is not None:
        try:
            rate = float(hashrate.group("rate"))
        except (ValueError, OverflowError):
            return None
        if math.isfinite(rate) and 0 <= rate <= 100_000:
            return "DEVICE_HASHRATE"
    return None


def _fixture_lifecycle_signal(entry: Mapping[str, Any]) -> str | None:
    """Read only the explicit synthetic fixture envelope, never Salad fields.

    ``fixture_lifecycle_observation`` is a local test-harness field, not an
    asserted Salad API schema. Every accepted record remains
    SYNTHETIC/UNVERIFIED.
    """
    observation = entry.get("fixture_lifecycle_observation")
    if not isinstance(observation, Mapping) or set(observation) != {"source", "event"}:
        return None
    if observation.get("source") != FIXTURE_LIFECYCLE_SOURCE:
        return None
    event = observation.get("event")
    if isinstance(event, str) and event in {"INSTANCE_RUNNING", "INSTANCE_READY"}:
        return event
    return None


def _startup_signal_from_structured(value: Any) -> str | None:
    if isinstance(value, str):
        return _startup_signal(value)
    if not isinstance(value, Mapping):
        return None
    if value.get("type") == "FL4SH_MONITOR" and value.get("state") in {"CONFIG", "GPU_DETECTED"}:
        return "MONITOR_CONFIG" if value.get("state") == "CONFIG" else "GPU_DETECTED"
    for key in ("message", "text"):
        message = value.get(key)
        if isinstance(message, str):
            signal = _startup_signal(message)
            if signal is not None:
                return signal
    return None


def _pool_recovery_signal_from_structured(value: Any) -> bool:
    if isinstance(value, str):
        return _SOLUTIONS_ACCEPTED_RE.fullmatch(value) is not None
    if not isinstance(value, Mapping):
        return False
    for key in ("message", "text"):
        message = value.get(key)
        if isinstance(message, str) and _SOLUTIONS_ACCEPTED_RE.fullmatch(message):
            return True
    return False


def _recovery_signal_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value if _SOLUTIONS_ACCEPTED_RE.fullmatch(value) else None
    if not isinstance(value, Mapping):
        return None
    candidates = [
        message for key in ("message", "text")
        if isinstance((message := value.get(key)), str)
        and _SOLUTIONS_ACCEPTED_RE.fullmatch(message)
    ]
    if len(set(candidates)) > 1:
        raise LogRecordError("structured pool recovery evidence conflicts")
    return candidates[0] if candidates else None


def _parse_pool_recovery_marker_text(text: str) -> PoolRecoveryMarker | None:
    if not isinstance(text, str) or len(text) > 1024:
        return None
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return None
    if len(tokens) < 2 or tokens[0] != "FL4SH_MONITOR" or tokens[1] != "state=POOL_RECOVERY_EVIDENCE":
        return None
    expected = {
        "monitor_session_id", "pool_episode_id", "pool_alert_sequence",
        "recovery_signal", "timestamp_utc", "solutions_evidence_sha256",
        "actions_performed",
    }
    fields: dict[str, str] = {}
    for token in tokens[2:]:
        if "=" not in token:
            return None
        key, value = token.split("=", 1)
        if key not in expected or key in fields:
            return None
        fields[key] = value
    if set(fields) != expected or fields["actions_performed"] != "false":
        return None
    if fields["recovery_signal"] != "SOLUTIONS_ACCEPTED":
        return None
    if not _UUID_RE.fullmatch(fields["monitor_session_id"]):
        return None
    if not _UUID_RE.fullmatch(fields["pool_episode_id"]):
        return None
    try:
        sequence = _bounded_integer(fields["pool_alert_sequence"], minimum=2, maximum=1_000_000)
        timestamp = canonical_utc(fields["timestamp_utc"])
    except (LogRecordError, TypeError, ValueError):
        return None
    evidence_hash = fields["solutions_evidence_sha256"]
    if not _POOL_RECOVERY_EVIDENCE_HASH_RE.fullmatch(evidence_hash):
        return None
    return PoolRecoveryMarker(
        monitor_session_id=fields["monitor_session_id"],
        pool_episode_id=fields["pool_episode_id"],
        pool_alert_sequence=sequence,
        recovery_signal="SOLUTIONS_ACCEPTED",
        timestamp_utc=timestamp,
        solutions_evidence_sha256=evidence_hash,
    )


def _pool_recovery_marker_from_structured(value: Any) -> PoolRecoveryMarker | None:
    if isinstance(value, str):
        return _parse_pool_recovery_marker_text(value)
    if not isinstance(value, Mapping):
        return None
    for key in ("message", "text"):
        message = value.get(key)
        if isinstance(message, str):
            parsed = _parse_pool_recovery_marker_text(message)
            if parsed is not None:
                return parsed
    if value.get("type") not in {None, "FL4SH_MONITOR"} or value.get("state") != "POOL_RECOVERY_EVIDENCE":
        return None
    fields = value.get("fields", value)
    if not isinstance(fields, Mapping):
        return None
    normalized = {key: str(raw) if key not in {"actions_performed"} else "false" if raw is False else str(raw)
                  for key, raw in fields.items() if key != "type"}
    if normalized.get("state") == "POOL_RECOVERY_EVIDENCE":
        normalized.pop("state")
    text = "FL4SH_MONITOR state=POOL_RECOVERY_EVIDENCE " + " ".join(
        f"{key}={value}" for key, value in normalized.items()
    )
    return _parse_pool_recovery_marker_text(text)


def _same_parsed(
    left: tuple[MonitorAlert | None, AlertMarker | None],
    right: tuple[MonitorAlert | None, AlertMarker | None],
) -> bool:
    if left[0] is not None or right[0] is not None:
        return left[0] is not None and right[0] is not None and left[0] == right[0]
    if left[1] is not None or right[1] is not None:
        return left[1] is not None and right[1] is not None and left[1] == right[1]
    return True


def normalize_log_entry(entry: Mapping[str, Any]) -> NormalizedLogEntry:
    """Normalize only an explicitly SYNTHETIC/UNVERIFIED fixture envelope."""
    return _normalize_log_entry(entry, expected_classification=DATA_CLASSIFICATION)


def normalize_provider_log_entry(entry: Mapping[str, Any], response_evidence: Any) -> NormalizedLogEntry:
    """Normalize an allowlisted response item with transport-derived provenance.

    The caller cannot promote a fixture by setting a classification field: the
    exact evidence type and its source/classification pair must come from the
    Salad transport module. Offline exchange evidence remains synthetic.
    """
    from .live_transport import ProviderResponseEvidence

    if type(response_evidence) is not ProviderResponseEvidence:
        raise LogRecordError("provider response provenance is missing")
    if response_evidence.source == "salad_https_fixed_route" and response_evidence.classification == PROVIDER_OBSERVED:
        classification = PROVIDER_OBSERVED
    elif response_evidence.source == "offline_test_transport" and response_evidence.classification == DATA_CLASSIFICATION:
        classification = DATA_CLASSIFICATION
    else:
        raise LogRecordError("provider response provenance is invalid")
    envelope = dict(entry)
    envelope["data_classification"] = classification
    return _normalize_log_entry(
        envelope,
        expected_classification=classification,
        identity_classification=classification,
    )


def _normalize_log_entry(
    entry: Mapping[str, Any], *, expected_classification: str,
    identity_classification: str | None = None,
) -> NormalizedLogEntry:
    """Shared alert parser; evidence classification is fixed by its caller."""
    if not isinstance(entry, Mapping):
        raise LogRecordError("log entry is malformed or exceeds local bounds")
    plain_entry = _plain_json_value(entry)
    try:
        encoded_entry = _canonical_json(plain_entry).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise LogRecordError("log entry is malformed or exceeds local bounds") from exc
    if len(encoded_entry) > MAX_ENTRY_BYTES:
        raise LogRecordError("log entry is malformed or exceeds local bounds")
    _reject_secret_like_content(plain_entry)
    if entry.get("data_classification") != expected_classification:
        raise LogRecordError("log entry provenance does not match the trusted input path")
    event_time = canonical_utc(entry.get("event_time_utc"))
    resource = entry.get("resource")
    if not isinstance(resource, Mapping):
        raise LogRecordError("log resource is missing")
    resource_type = resource.get("type")
    if (
        not isinstance(resource_type, str)
        or not resource_type
        or len(resource_type) > 128
        or any(ord(char) < 32 or ord(char) == 127 for char in resource_type)
    ):
        raise LogRecordError("resource type is invalid")
    labels = resource.get("labels")
    if not isinstance(labels, Mapping):
        raise LogRecordError("resource labels are missing")
    identity = resolve_provider_identity(
        labels,
        complete_identity_status=identity_classification or expected_classification,
    )
    text_log = entry.get("text_log")
    if text_log is not None and (
        not isinstance(text_log, str)
        or len(text_log) > MAX_TEXT_LOG_CHARS
        or any((ord(char) < 32 and char not in "\t") or ord(char) == 127 for char in text_log)
    ):
        raise LogRecordError("text log exceeds the local size limit")
    structured = entry.get("structured_message")
    structured_copy = _plain_json_value(structured) if structured is not None else None
    if structured_copy is not None and len(_canonical_json(structured_copy).encode("utf-8")) > MAX_STRUCTURED_BYTES:
        raise LogRecordError("structured log message exceeds the local size limit")
    if text_log is not None:
        text_result = _parse_text_message(text_log)
    else:
        text_result = (None, None)
    structured_result = _parse_structured_message(structured_copy)
    if text_log is not None and structured_copy is not None and not _same_parsed(text_result, structured_result):
        if text_result != (None, None) or structured_result != (None, None):
            raise LogRecordError("text and structured alert evidence conflict")
    text_signal = _startup_signal(text_log)
    structured_signal = _startup_signal_from_structured(structured_copy)
    if text_signal is not None and structured_signal is not None and text_signal != structured_signal:
        raise LogRecordError("text and structured startup evidence conflict")
    fixture_lifecycle_signal = _fixture_lifecycle_signal(entry)
    if fixture_lifecycle_signal is not None and (text_signal is not None or structured_signal is not None):
        raise LogRecordError("fixture lifecycle and miner progress evidence conflict")
    text_cuda_signal = _cuda_signal_from_text(text_log)
    structured_cuda_signal = _cuda_signal_from_structured(structured_copy)
    if (
        text_cuda_signal is not None
        and structured_cuda_signal is not None
        and text_cuda_signal != structured_cuda_signal
    ):
        raise LogRecordError("text and structured CUDA evidence conflict")
    if text_result != (None, None) and structured_result != (None, None):
        alert, marker = text_result
        alert_source = "text_log+structured_message"
    elif text_result != (None, None):
        alert, marker = text_result
        alert_source = "text_log"
    elif structured_result != (None, None):
        alert, marker = structured_result
        alert_source = "structured_message"
    else:
        alert, marker = None, None
        alert_source = None
    text_recovery = (
        text_log if isinstance(text_log, str) and _SOLUTIONS_ACCEPTED_RE.fullmatch(text_log) else None
    )
    structured_recovery = _recovery_signal_text(structured_copy)
    if text_recovery is not None and structured_recovery is not None and text_recovery != structured_recovery:
        raise LogRecordError("text and structured pool recovery evidence conflict")
    recovery_text = text_recovery or structured_recovery
    pool_recovery_signal = recovery_text is not None
    pool_recovery_signal_sha256 = (
        hashlib.sha256(recovery_text.encode("utf-8")).hexdigest() if recovery_text is not None else None
    )
    text_recovery_marker = _parse_pool_recovery_marker_text(text_log) if isinstance(text_log, str) else None
    structured_recovery_marker = _pool_recovery_marker_from_structured(structured_copy)
    if (
        text_recovery_marker is not None
        and structured_recovery_marker is not None
        and text_recovery_marker != structured_recovery_marker
    ):
        raise LogRecordError("text and structured pool recovery markers conflict")
    pool_recovery_marker = text_recovery_marker or structured_recovery_marker
    cuda_signal = text_cuda_signal or structured_cuda_signal
    if text_cuda_signal is not None and structured_cuda_signal is not None:
        cuda_source = "text_log+structured_message"
    elif text_cuda_signal is not None:
        cuda_source = "text_log"
    elif structured_cuda_signal is not None:
        cuda_source = "structured_message"
    else:
        cuda_source = None
    if alert is None and cuda_signal == "CUDA_DRIVER_INCOMPATIBLE":
        alert = _normalize_cuda_driver_incompatible()
        alert_source = cuda_source or "unknown"
    if alert is None:
        alert_source = None
    if alert is not None and marker is not None:
        raise LogRecordError("one log record contains conflicting alert forms")
    log_id = entry.get("log_id")
    if log_id is not None and (
        not isinstance(log_id, str) or not _SAFE_ID_RE.fullmatch(log_id)
    ):
        raise LogRecordError("provider log reference is invalid")
    safe_labels = _plain_json_value(labels)
    identity_bytes = _canonical_json(safe_labels).encode("utf-8")
    evidence_material = {
        "log_id": log_id,
        "event_time_utc": event_time,
        "resource_type": resource_type,
        "resource_labels": safe_labels,
        "text_log": text_log,
        "structured_message": structured_copy,
        "fixture_lifecycle_observation": _plain_json_value(
            entry.get("fixture_lifecycle_observation")
        ) if entry.get("fixture_lifecycle_observation") is not None else None,
    }
    evidence_sha = hashlib.sha256(_canonical_json(evidence_material).encode("utf-8")).hexdigest()
    if fixture_lifecycle_signal is not None:
        startup_source = FIXTURE_LIFECYCLE_SOURCE
    elif text_signal is not None and structured_signal is not None:
        startup_source = "text_log+structured_message"
    elif text_signal is not None:
        startup_source = "text_log"
    elif structured_signal is not None:
        startup_source = "structured_message"
    else:
        startup_source = None
    # The label fingerprint is intentionally derived from provider labels only.
    if hashlib.sha256(identity_bytes).hexdigest() != identity.labels_fingerprint:
        raise LogRecordError("resource label fingerprint is inconsistent")
    return NormalizedLogEntry(
        log_id=log_id,
        event_time_utc=event_time,
        resource_type=resource_type,
        resource_labels=safe_labels,
        text_log=text_log,
        structured_message=structured_copy,
        data_classification=expected_classification,
        identity=identity,
        alert=alert,
        marker=marker,
        alert_source=alert_source,
        evidence_sha256=evidence_sha,
        startup_signal=fixture_lifecycle_signal or text_signal or structured_signal,
        startup_signal_source=startup_source,
        cuda_signal=cuda_signal,
        cuda_signal_source=cuda_source,
        pool_recovery_signal=pool_recovery_signal,
        pool_recovery_signal_sha256=pool_recovery_signal_sha256,
        pool_recovery_marker=pool_recovery_marker,
    )
