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
cannot be sent to Telegram. Live Telegram delivery is limited to newly inserted,
unsuppressed provider-observed alerts. Ambiguous delivery remains
`DELIVERY_UNKNOWN` and is not automatically retried.

This task did not run the launcher, probe Salad, send Telegram, write Firebase,
deploy, or spend cloud credits. A real contract probe remains a distinct,
one-request, Telegram-disabled operation and requires separate operator
authorization.
