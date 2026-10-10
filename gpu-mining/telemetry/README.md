# Offline GPU telemetry ledger and dry-run guards

This package is an offline, read-only toolkit for Salad-exported KRig and Fl4shMiner CSV logs plus Salad lifecycle observations. It converts recognized rows into a normalized event ledger, run/segment aggregates, and minute-level statistics. Guard evaluation is pure and dry-run only: it returns recommendations and never calls a provider, stops a worker, or reallocates a machine.

## Boundaries

- The input CSV is opened read-only. Raw log text is not copied into the ledger; recognized fields are extracted, and mining identifiers/wallet strings are not retained.
- Provider billing is not inferred from KRig telemetry. Billed runtime, productive runtime, and productive ratio remain unknown until a billing source can establish them.
- Estimated pool income, pool-observed balance, paid BTC, converted proceeds, and realized proceeds are separate evidence stages. The V2 offline ledger never adds them together or promotes one stage to another.
- Segments include container group, version, instance, and machine identity. Rows with incomplete identity are isolated by source row rather than merged with another machine.
- Naive source timestamps stay source-local and do not receive a fabricated UTC offset. Supply an IANA timezone only when it is known; an explicit offset in the CSV takes precedence over the option. When a log line has only a clock time, the parser chooses the nearest calendar date among the export timestamp's previous, same, or next day.
- Historical CSV regression is a separate, operator-invoked check. The ordinary unit suite uses synthetic fixtures and does not require historical files.

## Run, segment, and event model

A run groups the mining attempt represented by one imported source and container group. A segment is one concrete container allocation, identified by container group name/version plus instance and machine IDs. A changed instance or machine ID starts a distinct segment because reallocation can change the GPU and billed allocation; telemetry from different machine IDs is never merged. Rows missing provider identity are isolated by source row.

Each event carries schema version, deterministic event/run/segment IDs, event type, source classification and row provenance, source-clock and optional UTC timestamps, import time, source-file SHA-256, provider identity, and a typed payload. Recognized KRig patterns include miner startup, GPU and total hashrate/share counters, accepted/rejected/stale shares, new Stratum jobs, and miner/runtime errors. The known preflight error `NVIDIA runtime is not exposed: /dev/nvidiactl is missing` is classified separately from a running miner's errors.

Minute statistics group samples and explicit share events into source-clock minutes. They are telemetry aggregates, not evidence of billed time or realized pool payouts.

## GPU identity, Fl4shMiner, and Salad lifecycle evidence

Physical hashrate floors use exact `MODEL|form_factor|identity_source` keys. The identity source must be verified; model substring matches and missing variant labels do not qualify. The editable example config sets RTX 5090 Desktop to 350 TH/s, RTX 5080 Desktop to 209 TH/s, and both RTX 5090 Laptop and RTX 5080 Laptop to 120 TH/s. A Laptop never inherits a Desktop floor. Scenario E (125 TH/s below 130) uses a test-only synthetic override; it does not change the production Laptop floors. Only local device-reported hashrate is comparable to these floors. CUDA autotune pool-equivalent estimates and Kryptex worker hashrate are excluded.

Hash evaluation uses duration-weighted windows with bounded hold-forward coverage, expected cadence, maximum gap, minimum sample count, coverage ratio, and consecutive-window count. The lab defaults are 90 seconds warm-up, 10-second expected cadence, 120-second window, 30-second reevaluation, 80% coverage, 30-second maximum gap, and two consecutive low evaluations. They are editable starting values, not calibrated production limits. Health is reported separately from dry-run action eligibility. Missing coverage or stale telemetry never becomes zero hashrate. Cooldown and maximum reallocation count are unset in the example config, so the physical guard can classify low performance while a reallocation recommendation remains unavailable until an operator configures those safeguards.

`import-salad-lifecycle` reads `Text Log` and `Json Log message` by their CSV column names and recognizes provider lifecycle states plus startup/readiness probe outcomes independently. Each event retains its source column and row. Allocated, running, or ready observations describe provider logs only; they never establish Salad billing or billed runtime.

`import-fl4shminer` reads `Text Log` and the Salad GPU class column by name. It keeps the Salad wrapper device ID and Fl4shMiner device ID in separate namespaces, and groups source-local rows by provider assignment and an available worker-start wall-clock anchor. The Salad GPU class label is preserved at provider-assignment scope; it is not copied to each Fl4shMiner device. If multiple miner devices appear without an explicit per-device GPU mapping, per-device physical floors remain `INSUFFICIENT_DATA` while their observed hashrates stay separate. Naive source clocks remain local and cannot deduplicate different exports. Cross-export event deduplication requires a verified provider assignment, trusted UTC time, and a unique matching worker-start anchor.

Fl4shMiner device `hashRate`, CUDA autotune's measured pool-equivalent estimate, Pearl autotune, and actual Kryptex worker hashrate are separate fields. The actual worker rate remains `UNKNOWN` unless the logs report it. Explicit `Solutions accepted/rejected` are not counted as generic accepted/rejected pool shares; stale `x/y` values are retained as cumulative counter observations and are never treated as paid shares. Solution hex/proof fields are unverified log observations, not share difficulty.

`evaluate-fleet` reports observed device work separately from economic-profit rankings. Profit ranking requires attribution-matched, verified, timestamped and sourced Salad billing, rental price, productive ratio, and pool-revenue evidence with reconciled values and explicit fee status. Missing or inconsistent evidence produces `UNKNOWN` and excludes the machine from profit ranking; it is never converted to zero or a verified loss. Unknown economic results appear in a separate list. All output is dry-run only.

The four inspected Fl4shMiner exports contain 897 rows and report Laptop device hashrates in approximately the 123–155 TH/s range. They do not prove the separately user-observed 20 TH/s scenario or a late-session 170-to-90 TH/s drop. Both remain labeled synthetic regression fixtures: `fixtures/guards/rtx5090_laptop_20_ths_synthetic.json` and `fixtures/guards/rtx5090_laptop_late_drop_synthetic.json`.

## Versioned batch and accounting path

`import-krig` remains the V1 single-source workflow and keeps its original source-file-based identifiers and append rules. Do not combine V1 outputs from different CSV exports: the original files are required to reconstruct a coherent multi-export snapshot.

`import-krig-batch` starts a separate V2 snapshot from all original CSVs at once. It requires a new output directory and writes `events.jsonl`, `segments.json`, `minute_stats.jsonl`, `work.json`, and `report.json`; it will not merge with an existing V1 or V2 directory. V2 derives `source_event_id` from file provenance and uses a distinct `logical_event_id` only when complete provider identity, trusted UTC time, event content, and one verified worker-start interval prove equivalence. It preserves every source reference. Incomplete identity/time or repeated identical fingerprints within one export remain unresolved and retain multiplicity. V2 preserves legacy IDs as provenance; it does not rewrite V1 artifacts.

Work accounting counts explicit accepted/stale/rejected share events and their observed timestamps. Accepted work remains null unless every accepted share has verified work with explicit provenance and compatible unit/context; the parser never derives difficulty from a Stratum job identifier. GPU hashrate work is a Decimal trapezoid estimate over each pair of timestamped samples for that GPU. Every interval and worker-start timestamp is reported, no endpoint extrapolation or default gap cutoff is applied, and GPU samples are not added to `Total` counters. Cumulative counter decreases are compared only within one CSV, complete provider assignment, run, segment, device, and counter. Samples missing that identity remain explicit unresolved comparisons instead of being joined across machines. Billed seconds and productive seconds remain null without provider lifecycle/billing evidence.

The frozen PRL and QTC observations in `fixtures/revenue/` are historical evidence, not current quotes. QTC preserves the documented 1 MH/s unit, daily response amounts, minute-level capture uncertainty, QPoW reference, and unknown fee state. `validate-revenue-fixture` checks the exact ten-field RevenueObservation payload. `estimate-revenue` requires an explicit pool-effective hashrate, matching coin/algorithm and provenance, productive seconds, bounded timestamps, and unique attribution; it never substitutes local GPU hashrate or share counts. A frozen snapshot is accepted only with `--historical-analysis` and the resulting record is tagged `estimated`, not payout evidence. Fresh estimates require `fresh` envelope state, an observation timestamp, an explicit `--as-of`, and an explicit maximum age.

`reconcile-money` accepts a local JSON evidence file with `schema_version: "2.0"`, `money_evidence`, `billing_evidence`, and `balance_snapshots` arrays; `money-input.example.json` shows the empty template. Evidence amounts should be decimal strings and every record needs a source reference and verifiable time: non-estimated records require a timezone-aware `observed_at` with second/millisecond precision, while estimates require a positive bounded window. Salad billing is a separate cost-evidence record with USD amount, attribution, source reference, and timestamp; CLI cost/evidence-ID arguments alone never establish a billed cost. Converted records require source amount/currency, target currency, positive exchange rate, rate timestamp, and rate source. The reported amount must match the rate at the amount's stated precision or a separately timestamped documented adjustment; otherwise the record stays visible as `UNRECONCILED` and is excluded from reconciled converted totals. Snapshot deltas are attributed only when the before/after records share run and segment identity and bounded worker scope (or an explicit one-worker account interval). Account-only balance deltas with multiple or unknown workers remain unattributed. Duplicate IDs are idempotent; conflicting records with the same ID are rejected. Fee deductions are never guessed. Actual P&L remains unknown without matching realized USD evidence and an explicit Salad billing record for the same attribution.

An explicit billing record has this shape; pass its `evidence_id` and matching attribution to `reconcile-money` when requesting an actual P&L calculation:

```json
{
  "evidence_id": "salad-invoice-row-1",
  "attribution_id": "run-id/segment-id",
  "amount": "0.50",
  "currency": "USD",
  "observed_at": "2026-10-08T19:30:00Z",
  "observed_at_precision": "second",
  "source_reference": "redacted Salad billing record"
}
```

The CLI cost argument is only a candidate consistency check: if supplied, it must equal the linked record's USD amount. Missing IDs, mismatched attribution, or mismatched amounts keep actual P&L unknown.

## Artifacts

`import-krig` writes these files into the operator-selected output directory:

- `events.jsonl`: normalized events, appended idempotently by `event_id`.
- `report.json`: source summary, run/segment aggregates, billing status, and provenance.
- `segments.json`: run and segment aggregates.
- `minute_stats.jsonl`: per-minute sample and share-event statistics.

Hashrate summary statistics distinguish arithmetic sample mean from trapezoidal sample interpolation. Interpolation is an estimate over observed sample intervals; it is not a billing or productivity measurement. Share interarrival values use explicit accepted-share event timestamps, not cumulative share counters.

## Dry-run guard configuration

`guard-config.example.json` contains the four exact physical floors and initial continuous-monitor timing policy. Cooldown, maximum reallocations, provider-state inputs, and economics inputs remain `null` until configured. In particular, absent Salad billing or pool-revenue evidence remains `UNKNOWN`; the physical guard does not declare an economic loss.

There is not yet a configured floor for RTX 3090 or RTX 4090. A physical hash health floor answers whether a GPU is performing below its hardware-class baseline; it is separate from an economic threshold, which needs rental cost, revenue rate, and productive ratio. Guard configuration schema `2.0` names `target_profit_over_rental_cost_fraction` explicitly. Required revenue is `rental * (1 + target_profit_over_rental_cost_fraction)`. Legacy schema `1.0` configs using `target_profit_margin_fraction` are rejected until explicitly migrated; values are never silently reinterpreted.

The one-shot `evaluate-guards` command remains a snapshot evaluator. The incremental monitor below reuses the same floor policy while retaining assignment state. The KRig historical importer does not supply verified lifetime reallocation history, so it never substitutes an assumed zero. Economics and hardware-health checks remain independent.

## Continuous monitor, replay, and fleet accounting

`monitor-replay` replays local CSV or normalized JSONL chronologically into a new SQLite state file. `monitor-ingest` incrementally adds later observations; `monitor-evaluate`, `monitor-status`, and `monitor-audit` inspect the persisted state. Repeated event IDs are idempotent. Every sample updates its assignment track and can trigger a reevaluation after the configured interval, including after a previous `PASS`. A new Machine or Instance ID closes the previous assignment track while retaining its history. Preempted, stopped, lost, terminated, and reallocated lifecycle observations close the active track.

The SQLite ledger persists each local source's format, logical record cursor, generation, and consumed-prefix SHA-256. An append keeps prior row/event/track identities and sends only newly appended events to the ledger; a changed or shortened prefix starts an isolated source generation so old observations remain auditable. Prefix verification scans the local source before accepting an append. This is offline file replay/ingestion, not a provider transport.

A terminal provider event closes tracks only when the supplied identity resolves to one allocation/assignment/machine/instance key; a partial match spanning several assignments is retained and audited without closing any. If a later Fl4shMiner append reveals multiple miner device IDs under one provider GPU assignment, the ledger invalidates previously persisted per-device floor identities for that assignment while preserving each observed rate.

The continuous engine requires trusted UTC observations and a verified worker-start or allocation-time anchor before evaluating lifetime windows. It records the minimum configured floor, duration-weighted observed rate, deterioration start/duration, sample coverage, assignment identity, provenance, and known reallocation history with each decision. Duplicate recommendations are suppressed for the same deterioration and assignment generation; recovery and confirmed replacement are auditable. If prior allocation history is unknown or safeguards are unset, it does not fabricate history or authorize action. `DisabledReallocationActionAdapter` is the only adapter in this iteration: it is disabled, reports no action, and has no Salad credentials or network path.

`monitor-watch-local` is a foreground poller for operator-selected local files only. It is not a Salad live monitor and does not receive provider events unless an operator supplies local files. Live deployment still needs a separately reviewed Salad transport/identity adapter, durable service lifecycle, authenticated secret handling, and operational authorization. No real reallocation is available here. A future real-action proposal should first add provider-side idempotency, explicit opt-in, policy-version allowlisting, per-fleet action budgets, cooldown enforcement, audit receipts, rollback/recovery behavior, and a kill switch; it must receive a separate safety review and explicit authorization before any authenticated call is implemented.

Fleet accounting records `fleet_id`, shared `worker_id`, Machine/Instance assignment history and replacements, and failed-assignment costs with source attribution. It can combine observed hashrate only when coin, algorithm, semantics, and time window match. Worker-level BTC is reported at the worker/fleet evidence stage and is never split into per-machine confirmed revenue. `fleet-summary` reports observed work and economic reconciliation separately; net profit is calculated only when realized USD revenue and Salad billing are attributable to the same compatible window. Missing inputs remain `UNKNOWN`, not zero profit.

## CLI

From the repository root:

```powershell
python gpu-mining/telemetry/collector/cli.py import-krig `
  --input "path\to\salad-krig-export.csv" `
  --output "path\to\telemetry-output" `
  --source-timezone UTC

python gpu-mining/telemetry/collector/cli.py evaluate-guards `
  --report "path\to\telemetry-output\report.json" `
  --config "gpu-mining/telemetry/guard-config.example.json"

python gpu-mining/telemetry/collector/cli.py import-krig-batch `
  --input "path\to\export-a.csv" --input "path\to\export-b.csv" `
  --output "path\to\new-v2-snapshot" --source-timezone UTC

python gpu-mining/telemetry/collector/cli.py validate-revenue-fixture `
  --input gpu-mining/telemetry/fixtures/revenue/prl_2026-10-07.json

python gpu-mining/telemetry/collector/cli.py import-salad-lifecycle `
  --input "path\to\salad-export.csv" --output "path\to\new-lifecycle-output"

python gpu-mining/telemetry/collector/cli.py import-fl4shminer `
  --input "path\to\fl4shminer-export.csv" --output "path\to\new-fl4shminer-output"

python gpu-mining/telemetry/collector/cli.py evaluate-fleet `
  --input "path\to\fleet-evidence.json"

python gpu-mining/telemetry/collector/cli.py monitor-replay `
  --state "path\to\new-monitor-state.sqlite" `
  --config "gpu-mining/telemetry/guard-config.example.json" `
  --input "path\to\fl4shminer-export.csv"

python gpu-mining/telemetry/collector/cli.py monitor-ingest `
  --state "path\to\monitor-state.sqlite" `
  --config "gpu-mining/telemetry/guard-config.example.json" `
  --input "path\to\next-export.csv"

python gpu-mining/telemetry/collector/cli.py monitor-audit `
  --state "path\to\monitor-state.sqlite"

python gpu-mining/telemetry/collector/cli.py fleet-summary `
  --input "path\to\fleet-worker-evidence.json"
```

Omit `--source-timezone` when the CSV timezone is unknown. The V1 output directory remains a single-source, single-timezone ledger: reimporting the exact same CSV with the same timezone option is idempotent, while a different source CSV or timezone option is rejected before artifacts are modified. A nonempty event ledger without its report provenance is also rejected. For overlapping exports, import all originals together with `import-krig-batch` into a new V2 directory; do not rebuild V2 from V1 reports or mix schema versions.

## Future transport boundary

A future `POST /v1/telemetry/batch` endpoint may receive normalized batches, but no API server, Firebase adapter, provider integration, or upload code is included here. The offline V2 schema is only a preparation boundary; it does not connect to Firebase. The proposed Firestore mapping is `sessions`, `sessions/{run_id}/events`, `sessions/{run_id}/minute_stats`, `machines`, and `financial_ledger`. These are future design targets, not resources created by this package.

## Validation

From the repository root:

```powershell
python -m unittest discover -s gpu-mining/telemetry/tests -v
python -m py_compile gpu-mining/telemetry/collector/*.py gpu-mining/telemetry/tests/*.py
python gpu-mining/telemetry/tests/local_historical_regression.py
```

The last command is optional and requires the existing KRig historical CSV at its documented workspace path.
