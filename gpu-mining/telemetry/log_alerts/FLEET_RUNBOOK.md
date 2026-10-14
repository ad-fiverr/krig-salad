# Central Salad fleet watcher

This foreground process reuses the existing log alert normalizer, enricher,
delivery ledger, and centralized Telegram sender. It can monitor up to 100
`organization:project` targets from one process. It does not run in the
Fl4shMiner container and does not infer Machine ID from miner output.

## Current gate

The implementation and tests are offline. No Salad or Telegram credentials
were requested, and no live request was made. The provider's query-language
grammar and the exact filter for the Fl4shMiner records remain `UNKNOWN`; the
official endpoint requires a `query` string but does not define its syntax in
the checked reference. Do not replace the placeholder below with guessed
syntax. A contract probe and separate operator authorization are required
before starting a real watcher.

The image also supports a `FL4SH_ROLE=central` entrypoint role. It does not
launch Fl4shMiner. The role requires non-secret target, query and state-path
settings, then enters the existing live CLI gates; Salad and Telegram
credentials are still acquired only through hidden interactive TTY prompts.
The miner role rejects local Telegram so an alert with `LOCAL_MONITOR_ONLY`
can never be presented as the fleet's provider-identified alert. Central
delivery remains blocked until all five provider identity fields are verified
and the message includes their source.

## Non-secret target file

Create `fleet-targets.json` with only the approved target pairs:

```json
[
  {"organization_name": "org-a", "project_name": "miners"},
  {"organization_name": "org-b", "project_name": "miners"}
]
```

The file accepts 1–100 unique organization/project pairs. Credentials, unknown
fields, duplicate members, duplicate targets, and invalid names are rejected.
Add another organization by adding a target row; no code change and no
per-machine process or browser is needed.

## Single-command whole-fleet launcher

Run only after the query is verified and the real-read gate is separately
authorized. From the repository root, substitute the local target/state paths
and the verified query. Never put credentials in this command or the target
file.

```powershell
$env:PYTHONPATH = "gpu-mining/telemetry"
python -m log_alerts.live_cli --watch-live-alerts --enable-live-read --enable-central-telegram --confirm-live CENTRAL_FLEET_MONITOR --targets-file .\fleet-targets.json --poll-seconds 30 --state-dir .\salad-alert-state --query '<VERIFIED SALAD QUERY>'
```

After all flags, targets, query text, and the interactive TTY are validated,
the process prompts with hidden input for the Salad API key, Telegram bot token,
and Telegram chat ID. The three values stay in memory for that process. The
Salad credential is reused across organizations; the central Telegram sender
is shared by all targets. Ctrl+C ends the foreground watcher gracefully.

The accepted poll interval is 15–300 seconds; default is 30 seconds. Each
cycle queries organizations sequentially. A saturated log page is subdivided
by the existing bounded time-slice adapter, with a hard cap of 64 subqueries
per organization cycle. Failed requests are not retried inline; the next
scheduled cycle is the next opportunity. A page still incomplete at the bound
leaves that organization's cursor unchanged for safe retry on the next
scheduled poll. One organization's 401/403 or timeout does not stop other
targets.

The central process holds `.watcher.lock` under its configured state directory
for its lifetime. This prevents a duplicate only on hosts that share the same
lock file and filesystem locking semantics; it is not a cross-host or
distributed lease. Keep the process single-replica until a separately reviewed
distributed coordinator exists.

## Identity and state

Each alert begins with `Organization`, `Project`, `Container Group`, `Machine
ID`, `Instance ID`, and `Identity source`, followed by its event title and
details. Identity status appears after the title. Organization is the exact
endpoint scope. Provider `resource.labels` is the primary Machine ID
source. When a log record lacks Machine ID but has a canonical Instance ID and
provider Project/Container Group labels, one exact List Container Group
Instances GET may be made for that complete route scope. The fallback requires
exactly one canonical Instance ID match with one canonical Machine ID. Missing
or ambiguous evidence remains `Machine ID: UNKNOWN`; known project, group, and
instance values are retained. This enrichment changes presentation only; the
stable source-label identity controls deduplication, so a later failed lookup
cannot create a duplicate or erase a previously resolved Machine ID.

List Instances data is cached in memory for 45 seconds by organization,
project, and Container Group. The cache stores normalized identifiers only.
SQLite state uses one file per organization, named with a SHA-256 organization
hash under `--state-dir`. Each database has its own cursor, deduplication,
alert cooldowns, pool episodes, and delivery attempts. Back up this directory
as protected operational state; it contains alert identities and evidence
hashes but never API credentials, Telegram credentials, raw log lines, or raw
resource-label maps. This is single-host state, not distributed coordination.

## Action and delivery boundary

The watcher has no Salad action transport. It never starts, stops, restarts,
creates, deletes, updates, or reallocates Salad resources. Every prepared
message reports `Actions performed: false`. Synthetic/offline observations
cannot be sent to Telegram. An unsuppressed provider-observed alert stays
`PENDING` until the complete five-field provider identity is verified and
included in its message. Exact late identity enrichment can unlock that same
pending dedupe key; it does not reopen a terminal delivery state. Ambiguous
delivery remains `DELIVERY_UNKNOWN` and is not automatically retried.

This task did not run the launcher, probe Salad, send Telegram, write Firebase,
deploy, or spend cloud credits. A real contract probe remains a distinct,
one-request, Telegram-disabled operation and requires separate operator
authorization.

## Miner productive-health boundary

With `FL4SH_MONITOR_ENABLED=1`, the image healthcheck requires PID 1's
supervisor, its live Fl4shMiner child, and a fresh, positive device-hashrate
sample tied to the current child PID, monitor session and policy hash. Pearl
autotune estimates, CUDA pool-equivalent estimates, GPU initialization and
configuration logs do not satisfy this check. If no positive device sample
arrives before `FL4SH_STARTUP_HASHRATE_TIMEOUT_SECONDS` (default 180 seconds),
the supervisor emits a sanitized startup-failure record, terminates the child
after a bounded grace period and exits unsuccessfully. The central watcher can
attach provider Machine ID and Instance ID only from Salad's exact resource
labels or an exact same-scope List Instances response; otherwise the alert
remains held. Salad may establish `Instance Running` independently of this
healthcheck, so the container cannot prevent a transient provider-side state,
but it will not report productive health without observed TH/s.
