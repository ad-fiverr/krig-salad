# Offline Salad log alert enricher

**Status:** offline implementation with a prepared, hard-disabled live
boundary. Fixtures and local fake exchanges remain `SYNTHETIC/UNVERIFIED`.
`PROVIDER_OBSERVED` is reserved for a successful response obtained through the
exact Salad HTTPS transport; it does not verify GPU binding, billing, or profit.
The production Salad and Telegram network gates are both hard-coded OFF, so
this task's code and tests make no external requests.

## Contract evidence checked 2026-10-13

The current official [SaladCloud Query Log Entries reference](https://docs.salad.com/reference/saladcloud-api/logs/query-log-entries)
documents `POST https://api.salad.com/api/public/organizations/{organization_name}/log-entries`.
This is an organization-wide log query operation. Its documented request body
has required `start_time`, `end_time`, and `query`; optional `page_size` is
limited to 1–100 and `sort_order` accepts `asc`/`desc`. The reference lists
responses 200, 400, 401, 403, 404, 429, and a default response. A successful
response contains `items` and `page_min_time` / `page_max_time`; each documented
item can include `time`, `receive_time`, `resource.type`, `resource.labels`,
`severity`, `json_log`, and `text_log`.

The [Salad Go SDK `logs` package](https://pkg.go.dev/github.com/saladtechnologies/salad-cloud-sdk-go@v0.9.0-alpha.17/pkg/logs)
also exposes `LogEntry` fields for `json_log`, `receive_time`, `resource`,
`severity`, `text_log`, and `time`; `LogEntryResource.Labels` is a
`map[string]*string`. The SDK exposes organization-scoped `QueryLogEntries`.

| Contract item | Status | Evidence / limit |
| --- | --- | --- |
| Exact operation and HTTP method | `VERIFIED` | Official API reference documents the organization log query as POST. This task classifies only this exact operation as `READ_LOG_QUERY`. |
| Host and API base path | `VERIFIED` | The reference example uses `api.salad.com` and `/api/public`; no live request is made here. |
| Request fields and maximum page size | `VERIFIED` | `start_time`, `end_time`, and `query` are required; page size is 1–100. |
| Response log fields and resource labels map | `VERIFIED` | Official reference and SDK expose these fields. |
| Real label keys for machine, instance, group, project, organization | `UNKNOWN` | The labels map is documented; presence and exact names for this workload are not verified. The parser accepts only aliases explicitly listed in its code and never infers missing values. |
| Query language and filters for the four groups | `UNKNOWN` | The schema requires a query string but this implementation does not construct or send one. |
| Full pagination / tie behavior | `UNKNOWN` | The response documents page time boundaries, but this implementation does not claim that a local fixture page token is a provider token or establish a complete live traversal algorithm. |
| Rate limits, `Retry-After`, or retry safety | `UNKNOWN` | The reference lists 429 but does not establish a retry policy here. This implementation has no retry loop. |
| Provider idempotency guarantee | `UNKNOWN` | Not required for the offline fixture; local dedup is not a provider guarantee. |
| Provider labels prove this Fl4shMiner event belongs to a GPU | `UNKNOWN` | Salad labels identify the log resource only. Binding to a mining device needs separate evidence. |

The official request URL includes `/api/public` as its base path. The local
route classifier represents the operation-relative path
`/organizations/{approved_org}/log-entries`; it is not a URL builder or an
HTTP allowlist implementation. A future live adapter must hardcode the full
documented URL and be separately reviewed and authorized.

## Processing and identity rules

- Only the provider envelope's `resource.labels` is considered for provider
  identity. Labels appearing in miner text or structured messages are ignored.
- The offline fixture envelope uses `text_log`, `structured_message`,
  `event_time_utc`, `resource.type`, and `resource.labels`. It preserves both
  message forms and records which source produced a recognized alert.
- Missing Machine ID or Instance ID yields `UNKNOWN`; conflicting label
  aliases yield `CONFLICTING`. Both cases suppress Machine/Instance IDs in the
  prepared message. No IDs are synthesized from GPU device numbers, monitor
  text, timestamps, or other machines.
- Even when synthetic labels are internally consistent, the identity status is
  `SYNTHETIC/UNVERIFIED`; it is not a verified Salad observation.
- Recognized events include the bounded monitor records
  `REALLOCATE_RECOMMENDED`, `NO_FLOOR_CONFIGURED`,
  `POOL_CONNECTION_FAILED`, `POOL_CONNECTION_UNSTABLE`, and
  `POOL_CONNECTION_RECOVERED`; the exact
  `mining.authorize response timeout; reconnecting; retrying in Ns` pool
  condition; and allowlisted configuration-invalid reason codes. Reallocation
  fields retain threshold tolerance, local degradation episode and alert
  sequence when present. Pool episode events retain the local monitor session,
  pool episode UUID, `pool_alert_sequence`, bounded failure counts/reason,
  retry interval and UTC receipts. The initial warning appears once per
  unresolved episode; unstable events identify burst, persistent failure or a
  cooldown reminder. Burst validation uses the reported rolling-window start,
  not the age of the full episode. Recovery requires a matching provider
  resource, an open durable episode and a bounded `Solutions accepted:` record
  strictly after the episode's latest failure, plus the supervisor's internal
  `POOL_RECOVERY_EVIDENCE` marker bound to the same provider resource, monitor
  session, episode, recovery sequence and SHA-256 of that exact accepted line.
  Correlation follows the actual stdout order (marker, recovery audit, original
  accepted-solutions line), with bounded provider timestamps and ties allowed
  for coarse timestamp precision. If polling splits the records, a later
  overlapping cycle can complete correlation while SQLite retains the open
  episode; all three evidence records must be present together in that cycle.
  The marker is internal evidence and never creates a fourth public event.
  Recovered messages retain failure count, retry seconds and timestamp. Raw
  pool and accepted-solution text is never copied into a prepared message or
  ledger payload. Historical raw retry lines
  remain parseable for offline analysis; live provider delivery requires a
  canonical monitor episode event to avoid turning each retry into a new
  notification. Unknown floor remains `UNKNOWN`.
- `TELEGRAM_ALERT` markers are associated only when event type, provider
  resource-label fingerprint, degradation episode/sequence or exact pool
  monitor-session/episode/sequence when present, and the bounded local time
  window identify one unique marker. Ambiguous or absent markers do not invent
  an alert ID. Machine ID, Instance ID and Container Group remain visible near
  the top of every provider-enriched message and come only from
  `resource.labels`; a known alert ID is not required for identity display.
- The exact bounded Fl4shMiner CUDA fatal line (including its final period) maps to
  `CUDA_DRIVER_INCOMPATIBLE` / `CUDA_DRIVER_VERSION_INSUFFICIENT`. Generic CUDA,
  OpenCL, OOM, initialization, and `nvidia-smi` diagnostic lines do not match.
  An exact `Fl4shMiner stopped: exit status 1` record enriches the alert only
  when it is strictly later, within 60 seconds, and has the same complete
  provider resource labels including Machine ID, Instance ID, and Container
  Group. Multiple fatal candidates for one exit, or multiple exits for one
  fatal, remain `UNKNOWN`; their bounded evidence hashes are retained for
  audit. The fatal line is sufficient by itself; missing exit evidence stays
  `UNKNOWN`. A delayed, uniquely correlated exit found by a later overlapping
  poll updates the same durable outbox item rather than creating another
  notification.
- CUDA alerts contain only normalized bounded fields. Their message says
  `Instance ID (at detection)` and does not include the raw fatal line or infer
  a GPU model. A successful optional `nvidia-smi` diagnostic does not suppress
  the CUDA runtime incompatibility alert.
- A durable 10-minute CUDA cooldown is keyed by organization, project,
  Container Group, Machine ID, and normalized reason, so replacement Instance
  IDs on the same host do not cause restart-loop spam. Different Machines or
  Container Groups remain independent. Cooldown-suppressed observations retain
  only a bounded audit row with the Instance ID and evidence hash. Missing or
  conflicting identity never receives a guessed machine-level cooldown.
- Startup monitoring requires complete organization, project, container-group,
  Machine ID and Instance ID labels plus an explicit local
  `fixture_lifecycle_observation` with source
  `SYNTHETIC_PROVIDER_LIFECYCLE_FIXTURE` for Running/Ready. That wrapper field
  is test-harness metadata, not an asserted Salad API field; raw
  `Instance Running` / `Instance Ready (Readiness Probe Passed)` text is never
  accepted as provider lifecycle evidence because miner output can spoof it.
  After both synthetic observations for the same complete resource, the
  90-second grace is measured before preparing
  `RUNNING_READY_BUT_MINER_NOT_STARTED`. Only exact `FL4SH_MONITOR` CONFIG or
  GPU_DETECTED states and bounded `Device [N] ... Initialized` / `hashRate`
  lines count as miner progress. The guard never joins partial, conflicting or
  different provider resource identities. Late progress records a `MINER_STARTUP_RECOVERED`
  transition, including a provider event ingested after an alert whose event
  timestamp falls inside the grace period. The recovery event records the
  observation time and preserves the progress event time separately. Its
  generation fingerprint is local evidence derived from the
  provider Running record; it is not claimed as a Salad allocation ID.
  Startup-timeout notifications report Running/Ready, `miner_started=false`,
  `gpu_detected=false`, zero hashrate samples at the deadline, elapsed time
  since Ready, and a REALLOCATE recommendation with actions disabled.
- An exact CUDA fatal after Running is terminal startup-failure evidence for
  that local generation, not successful GPU progress. It suppresses the
  redundant startup-timeout notification; if a timeout was already prepared,
  its outbox row is retained and marked `SUPPRESSED_BY_CUDA_FATAL`. The fatal
  itself never emits `MINER_STARTUP_RECOVERED`; only separately observed miner
  progress can do that. A newer provider Running generation clears the prior
  terminal marker.
- Startup guard state is persisted in the local SQLite ledger in the same
  transaction as outbox notifications and cursor advancement. Persisted data
  contains only hashes, normalized identity fields, bounded state and times;
  raw resource labels and opaque label values are not stored.
- `NO_FLOOR_CONFIGURED` deduplicates per provider resource, GPU key and device
  namespace and effective policy hash, so a policy change can re-arm the
  warning. `MONITOR_CONFIGURATION_INVALID` deduplicates identical log records
  and applies a durable five-minute cooldown per provider resource and
  normalized reason. Missing or conflicting provider identity
  remains `UNKNOWN` or `CONFLICTING` in both alert families.
- Credential-shaped fields or values are rejected before evidence can be
  returned or persisted. Raw log text is kept only in the in-memory normalized
  result; SQLite stores hashes and bounded extracted notification evidence,
  not the raw log line.

## Cursor, dedup, and limits

`SQLiteAlertLedger` uses one local SQLite transaction for prepared outbox rows
startup guard state and the durable time cursor. The cursor advances only after every fixture page
has been fetched and validated. Repeated pages and overlapping local polling
windows are deduplicated using provider resource identity plus stable log
evidence and `alert_id` when present. Different provider Machine IDs remain
separate. This is single-host local state, not distributed production
coordination and not exactly-once Telegram delivery.

The current defaults are local safety bounds: 100 items/page, at most 20 pages,
2,000 entries, 2 MB total fixture data, a one-hour query window, 120 seconds of
overlap, and a 60-second marker correlation window. The fixture transport uses
synthetic page tokens solely to test bounded pagination. Provider continuation
semantics remain `UNKNOWN`.

## Offline test

From the repository root, run:

```powershell
python -m unittest discover -s gpu-mining/telemetry/tests -p "test_log_alert_enricher.py" -v
```

The tests do not require external packages, credentials, emulators, network
access, Salad resources, or Telegram. They cover identity provenance, exact
route classification, floor tolerance and degradation re-alerts, exact pool
failure and unstable-pool normalization, startup grace/progress/recovery,
unknown/conflicting identity, duplicate/overlap/restart behavior, incomplete
pagination, credential rejection, and 100 synthetic machines served by one
organization query.

Reallocation re-alerts use the canonical `notification_reason` values
`INITIAL_THRESHOLD_CROSSING` (sequence 1) and `WORSENED` (later sequences).
Sequences after 1 include `previous_alert_mean_ths` and
`deterioration_since_previous_alert_ths`; these names are shared by the
monitor record, normalizer, and enriched message.

## Prepared live boundary (still disabled)

The following components are implemented for later review, but cannot make a
production request in this release:

| Capability | Current state | Boundary |
| --- | --- | --- |
| Organization log query | Implemented, hard-disabled | Only `POST https://api.salad.com:443/api/public/organizations/{approved_org}/log-entries`, classified `READ_LOG_QUERY`; all other methods, hosts, ports and paths are denied. |
| Query | Explicit operator input required | Required start/end/query; query is bounded and rejects control/credential-like content; page size is at most 100 and sort order is `asc`. No query is inferred. |
| HTTPS | Implemented, hard-disabled | Fixed `api.salad.com:443`, certificate and hostname verification, TLS 1.2 minimum, finite timeouts/bytes, no proxy discovery, redirects or retries. |
| Completeness | Implemented with local bounds | Alert cycles split saturated responses by time recursively and deduplicate boundary evidence. They fail without cursor advance on excess items over `page_size`, more than 64 subqueries, 5,000 response items, 5 MB cumulative response, unsupported pagination, invalid page bounds, or a saturated minimum slice. The contract probe makes exactly one physical request, never splits, and marks a full page `UNKNOWN_SATURATED`; its completeness is unknown. Provider inclusion/boundary semantics still need a live contract probe. |
| Salad credential | Reuses exact `InteractiveSecretProvider` / `SecretMaterial` classes from the repository-owned boundary | Future prompt is hidden TTY input, acquired once and kept in memory. The production transport and adapter reject arbitrary provider/material types. Environment, command-line, config, file, browser, Firebase and SQLite sources are not accepted. This task never prompts for a key. |
| Contract probe | Implemented, not executed | One physical request with a window no longer than the configured maximum; it never splits a saturated page. Output includes completeness status, response counts, resource types, identity status counts and label-key names. It never prints label values, IDs, raw logs or credentials. |
| Central Telegram | Implemented, hard-disabled | Fixed `api.telegram.org:443` HTTPS `sendMessage`, TLS verification, finite bounds, no redirects/retries. Token/chat ID use hidden TTY input only and remain in memory. |
| Delivery | One attempt maximum | Separate durable states: `PENDING`, `DISPATCHING`, `SENT`, `DELIVERY_UNKNOWN`, `FAILED`. A restart in `DISPATCHING` becomes `DELIVERY_UNKNOWN`; no retry occurs. Only newly inserted, unsuppressed `PROVIDER_OBSERVED` alerts can enter delivery. Synthetic alerts are never sent. |
| Live lifecycle | Disabled | Salad `Running`/`Ready` lifecycle semantics remain unverified; `StartupGuard` runs only on explicitly synthetic lifecycle fixtures. |
| Reallocation / start / stop | Not implemented | No import, route, client, or action path is present. `actions_performed` remains false. |
| Firebase / scheduling | Not implemented | This package has no Firebase sink or polling daemon. |

`PROVIDER_OBSERVED` is created only by the fixed Salad HTTPS transport after an
HTTP 200 response and is backed by sealed response evidence before SQLite can
bind a live scope. Offline fake exchanges always remain
`SYNTHETIC/UNVERIFIED`. A live scope stores only organization, operation and a
SHA-256 of the operator query; changing organization/query or mixing a live
ledger with unbound fixture history fails closed. Raw log lines and opaque
resource-label values are not persisted. Identity is parsed only from
`resource.labels`; missing/conflicting labels remain `UNKNOWN`/`CONFLICTING`.

The local command entrypoints are prepared but must not be run as a live
operation during this task. Both immutable network gates are closed, so even
the explicit flags cannot open them. The probe form is:

```powershell
$env:PYTHONPATH = "gpu-mining/telemetry"
python -m log_alerts.live_cli --probe-live-contract-once --enable-live-read `
  --organization <approved-org> --query <operator-query> `
  --start-time <RFC3339-start> --end-time <RFC3339-end>
```

The one-shot alert form additionally requires
`--live-alert-once --enable-central-telegram`; neither command is authorized or
executable against production by this release. A real Salad probe requires a
separate task and operator authorization, with Telegram disabled. Central
Telegram delivery requires its own later review/authorization. Reallocation,
Firebase production, deployment, billing claims and profitability decisions
remain outside this package.
