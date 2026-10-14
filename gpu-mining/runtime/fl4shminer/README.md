# Fl4shMiner PRL runtime for Salad

This directory builds an isolated Linux/amd64 image for Fl4shMiner v1.5.2 and PearlHash (PRL). It does not change or wrap the KRig runtime. The image is intended for a separately authorized Salad lab; a successful build and container smoke test do not establish Salad GPU compatibility, accepted pool shares, pool credit, or profitability.

## Pinned artifact and trust notes

- Release: Fl4shMiner v1.5.2, Linux x86-64.
- Upstream asset: https://github.com/Fl4sh9174/Fl4shMiner/releases/download/v1.5.2/fl4shminer-v1.5.2.tar.gz
- Archive size: 53,173,385 bytes.
- Archive SHA-256: 105bf6e799adcc6a2a814b8a3ce1549696fe20a931cb9676bc363367280c4052 (UPSTREAM_PUBLISHED).
- Extracted executable SHA-256: 18eb1c096770c9f7614be2690172ff6418fdf1755b6c5b07e481ac15f3d85f58 (LOCALLY_FROZEN_AUDIT).
- Both build stages use nvidia/cuda:12.8.2-runtime-ubuntu22.04 for linux/amd64, pinned by digest.

The builder verifies the exact archive byte count and digest before inspecting its tar members. Extraction accepts only regular files and directories under the expected fl4shminer root, rejects links and traversal paths, extracts only the locked executable, then checks its digest and ELF64 x86-64 identity. The final image does not contain the download/build toolchain.

The opt-in supervisor requires the Python standard library. The final stage installs Ubuntu's `python3` package with `--no-install-recommends`; `python3-minimal` alone is insufficient because modules such as `dataclasses` are supplied by the full standard-library package. The image smoke checks the imports used by the monitor before validating its offline configuration. CI diagnostics for these checks are bounded and redacted.

The upstream publisher describes a 1.5% developer fee. That is a publisher claim, not a separately measured fee for this runtime or a Salad session.

## Runtime contract

The container accepts only these required environment variables:

- FL4SH_POOL_URL: an explicit stratum+tcp://host:port URL. There is no default endpoint.
- FL4SH_MINING_ID: the complete pool login/identifier, optionally followed by a worker suffix. The wrapper does not print its value.

The password is fixed to x by the launch contract. Arbitrary command overrides, shell evaluation, extra devices, and pool fallback are disabled. With the monitor disabled (the default), the miner keeps its existing direct-exec PID 1 behavior. Optional nvidia-smi diagnostics do not decide CUDA compatibility.

### Optional runtime hashrate monitor

Set `FL4SH_MONITOR_ENABLED=1` to opt in. The Python supervisor becomes PID 1, starts Fl4shMiner as its child, forwards termination signals, and relays stdout/stderr in byte chunks so progress output without a newline remains visible. Hashrate parsing uses a separate bounded line buffer; oversized records cannot grow parser memory. A child ended by a signal maps to the conventional `128 + signal` exit status. With `FL4SH_MONITOR_ENABLED=0` or unset, the original direct-exec process behavior remains. The liveness healthcheck supports both process layouts and does not use hashrate as a health signal.

The monitor parses only explicit Fl4shMiner lines of the form `Device [N] hashRate: ... TH/s`. It ignores Pearl autotune and CUDA pool-equivalent estimates. Its rolling average is time-weighted; each reading is held for at most the expected sample interval, never across a larger configured sample gap. Larger gaps reduce coverage, and a gap beyond the maximum invalidates the window. The first performance decision waits for the complete hash window after warm-up; subsequent decisions use the configured reevaluation cadence. Incomplete windows result in `INSUFFICIENT_DATA` or `TELEMETRY_STALE`, never an invented zero rate. Device numbers are reported in the `fl4shminer_device:N` namespace and are not a verified Salad GPU or allocation identity. Stale counters remain miner-reported counters, not proof of paid shares. Provider binding, billing, and GPU identity remain `UNKNOWN`; every advisory includes `actions_performed=false`.

The monitor now detects each Fl4shMiner device from its streaming `Device [N] <GPU name>: Initialized` line. It preserves an explicitly reported form factor in the normalized key. When a recognized RTX name omits the form factor, it uses a neutral key and does not infer Laptop or Desktop. For backward compatibility, the exact bare names `NVIDIA GeForce RTX 5080` and `NVIDIA GeForce RTX 5090` continue to map to their existing Desktop keys. Unparseable names or names containing conflicting form-factor markers remain `UNKNOWN` and receive no floor. Device indices remain in the `fl4shminer_device:N` namespace and never imply a Salad Machine ID or Instance ID.

Configure model floors with `FL4SH_MONITOR_GPU_FLOORS_JSON`, for example:

    FL4SH_MONITOR_ENABLED=1
    FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110,"RTX_5090_LAPTOP":115,"RTX_5080_DESKTOP":209,"RTX_5090_DESKTOP":350,"RTX_5070_TI_LAPTOP":100,"RTX_3090_TI":110}'

The JSON object accepts both neutral keys such as `RTX_3090_TI` and `RTX_5070_TI`, and explicit form-factor keys such as `RTX_3090_TI_LAPTOP` and `RTX_3090_TI_DESKTOP`. Values must be finite numeric floors greater than zero and at most 10,000 TH/s. The registry is size- and entry-bounded, rejects duplicate/case-alias keys and never echoes the supplied JSON in validation errors. A neutral key only matches the same neutral detected key: it cannot inherit a Laptop or Desktop floor, and form-factor keys do not match a neutral identity. For example, `FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_3090_TI":110}'` configures 110 TH/s only for an observed `RTX_3090_TI`. The built-in defaults remain 120 TH/s for RTX 5080 Laptop, 120 for RTX 5090 Laptop, 209 for RTX 5080 Desktop, and 350 for RTX 5090 Desktop. A JSON value overrides the corresponding default; additional canonical GPU keys can be added without rebuilding the image. `policy_hash` includes the complete effective floor registry.

`FL4SH_MONITOR_PROFILE` remains a temporary explicit compatibility override. If a detected device disagrees with that profile, the monitor emits `GPU_PROFILE_MISMATCH` and does not evaluate that device against a floor. Without a profile, the detected GPU key selects its JSON floor or known default. If identity is ambiguous, corroborating sources conflict, or no matching floor exists, the monitor emits `GPU_IDENTITY_UNKNOWN`, `GPU_IDENTITY_CONFLICT`, or `NO_FLOOR_CONFIGURED` and does not recommend reallocation. `GPU=<name> Pearl autotune hashrate` and `Solutions accepted: ...-<name>` can corroborate a device model only; they never supply hashrate samples. Identity events include `gpu_key`, quoted `gpu_raw`, `floor_ths`, `floor_source`, source, and `actions_performed=false`. A local miner name is observed telemetry, not proof of provider assignment.

For compatibility, the legacy per-model `SALAD_G5_GPU_FLOOR_RTX_..._THS` variables still override the built-in defaults when no JSON value replaces that key. Profile selection is only an operator configuration and is not evidence that the provider assigned that GPU.

Initial monitoring values can be set independently using `SALAD_G5_WARMUP_SECONDS` (90), `SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS` (10), `SALAD_G5_HASH_WINDOW_SECONDS` (120), `SALAD_G5_REEVALUATION_INTERVAL_SECONDS` (30), `SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW` (10), `SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS` (30), `SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO` (0.8), and `SALAD_G5_CONSECUTIVE_BAD_WINDOWS` (2). Invalid or incoherent values fail closed before the monitor can start Fl4shMiner. On startup, the monitor logs its effective settings and `policy_hash` for traceability.

`FL4SH_MONITOR_FLOOR_TOLERANCE_THS` defaults to 2 TH/s and accepts finite values from 1 through 3. The decision threshold is `configured floor - tolerance`; a valid mean exactly at that threshold is not a breach. Means from the threshold up to (but not including) the nominal floor emit `WITHIN_FLOOR_TOLERANCE`, and a floor no greater than the tolerance is explicitly non-actionable. `FL4SH_MONITOR_REALLOCATE_RENOTIFY_DROP_THS` defaults to 3 TH/s and accepts positive finite drops through 1,000 TH/s. Both settings are part of `policy_hash`.

The monitor emits `WARMUP`, `INSUFFICIENT_DATA`, `TELEMETRY_STALE`, `NO_FLOOR_CONFIGURED`, `HEALTHY`, `BELOW_FLOOR`, `WITHIN_FLOOR_TOLERANCE`, `REALLOCATE_RECOMMENDED`, and `RECOVERED` transitions when applicable. A recommendation starts a local UUID degradation episode at sequence 1 after the configured bad-window confirmation. In the same episode, another advisory is emitted only after the configured number of new valid low windows and an additional mean drop at least `FL4SH_MONITOR_REALLOCATE_RENOTIFY_DROP_THS` below the previous alert mean. Each advisory includes the episode ID and sequence. Its canonical `notification_reason` is `INITIAL_THRESHOLD_CROSSING` at sequence 1 and `WORSENED` for later advisories; sequence 2 and later also include `previous_alert_mean_ths` and `deterioration_since_previous_alert_ths`. Reaching the decision threshold closes the episode; an ensuing breach receives a new ID. `REALLOCATE_RECOMMENDED` is an advisory only: this image does not stop, move, or reallocate a Salad instance, and the monitor does not verify profitability or Salad billing.

### Optional Telegram audit notifications

Telegram notifications are disabled unless `FL4SH_TELEGRAM_ENABLED=1` is explicitly set. Enabling them requires `FL4SH_MONITOR_ENABLED=1`, `FL4SH_TELEGRAM_BOT_TOKEN`, and `FL4SH_TELEGRAM_CHAT_ID`; the entrypoint rejects a Telegram-enabled/monitor-disabled combination, and monitor configuration is validated before Fl4shMiner is started. `FL4SH_TELEGRAM_POOL_ERROR_COOLDOWN_SECONDS` is retained and validated for backward compatibility, but it no longer controls pool retry episode alerts. `FL4SH_MONITOR_LABEL` is an optional printable label of at most 64 characters.

The supervisor parses only the exact bounded authorize-timeout/reconnect line. One unresolved monitor-session episode emits one `POOL_CONNECTION_FAILED`; a later timeout does not repeat that warning. The episode escalates to `POOL_CONNECTION_UNSTABLE` after either three failures inside the rolling 90-second window or two failures spanning at least 300 seconds. Burst evidence includes `recent_failure_window_start_utc`, so the central validator measures the rolling burst window rather than the whole episode age. A reminder is allowed only after 900 seconds since the prior unstable alert and a new exact timeout. An exact bounded `Solutions accepted: <device>-NVIDIA GeForce RTX ...` line after the latest failure emits one `POOL_CONNECTION_RECOVERED`; hashrate, silence and GPU initialization do not recover pool health. Every public episode event increments `pool_alert_sequence`; recovery includes failure count, retry seconds and `timestamp_utc` as well as the prior failure count. Pool status remains independent from hashrate status and never fabricates zero TH/s or recommends automatic reallocation. Other pool errors do not notify.

The supervisor writes sanitized `FL4SH_MONITOR state=POOL_CONNECTION_FAILED|POOL_CONNECTION_UNSTABLE|POOL_CONNECTION_RECOVERED` records to stdout even when direct Telegram is disabled, so the central enricher can attach exact Machine ID, Instance ID and Container Group exclusively from Salad `resource.labels`. When a bounded accepted-solutions line follows an open pool episode, it also writes an internal `POOL_RECOVERY_EVIDENCE` audit marker containing the monitor session, episode, recovery sequence, UTC time and SHA-256 of that exact miner line. This marker is not a public alert. The central enricher requires the raw accepted-solutions record and marker to match the same provider resource, session, episode, sequence and hash before preparing recovery. A missing or ambiguous match suppresses recovery. The supervisor's actual stdout order is the internal marker, the recovery audit record, then the original accepted-solutions line; the central enricher validates this bounded provider-record order while allowing timestamp ties at provider precision. When polling splits these records, a later overlapping cycle can complete correlation while the durable SQLite episode remains open. The local container does not know provider identity and never emits a Machine ID claim. Its optional direct Telegram message is a fallback/debug path and explicitly says `Provider Machine ID: unavailable in local container` and `Identity source: LOCAL_MONITOR_ONLY`. Do not enable direct and central Telegram delivery for the same deployment; disable this fallback when the central notifier is active. The central alert is the operator-facing identity-enriched message.

Configuration failures emit only one allowlisted code (`INVALID_GPU_FLOORS_JSON`, `MISSING_TELEGRAM_TOKEN`, `MISSING_TELEGRAM_CHAT_ID`, or `INVALID_MONITOR_SETTING`), never the raw environment value or parser text. Alerts retain the existing hash-guard fields, UTC time, and `actions_performed=false`. No Salad API, Firebase write, or action request is sent from the miner.

The notifier uses one bounded daemon queue and makes at most one best-effort attempt per queued alert while the supervisor remains alive. Queue saturation and transport errors produce generic sanitized `TELEGRAM_NOTIFY_FAILED` audit lines; errors do not stop the monitor or miner. HTTPS is sent directly to `api.telegram.org:443` with certificate verification, a five-second timeout, a bounded response read, no redirects, and no retries. The Bot API requires the bot token in its HTTPS request path; the path is held only in memory for the request and is never logged, returned in an exception, persisted, included in the monitor policy hash, or passed to the Fl4shMiner child process. The token and chat ID are omitted from config output and redacted from relayed streams. Do not enable this option until the operator has provisioned the bot token and chat destination securely.

The offline regression suite uses synthetic credentials and a fake HTTPS connection only. It does not contact Telegram. Telegram delivery, bot permissions, and operator-side secret provisioning remain unverified until a separately authorized live test.

Kryptex documents regional PRL endpoints as candidates; prl-us.kryptex.network:7048 is a candidate endpoint for an explicitly configured lab, not a hidden image default. The third-party command form and device flag have not been validated by running this pinned binary against Salad. KRig's port 8048 must not be substituted based on its separate runtime.

Automatic tuning behavior on Salad is unvalidated. Configure conservative settings through the pool/miner behavior available in the pinned release, and record actual accepted/rejected/stale shares and GPU telemetry in a later lab. Do not interpret startup, image health, or a successful config check as mining productivity.

## Build, smoke test, and publish

Run source checks from the repository root:

    bash gpu-mining/runtime/fl4shminer/ci-smoke-test.sh --source

The CI source checks validate Bash syntax, the release lock, workflow YAML, the monitor's offline regression tests, configuration rejection and redaction, and the exact launch arguments in monitor-off and monitor-on modes using a temporary stub executable. They never execute the Fl4shMiner binary.

The image smoke test runs with Docker networking disabled and no GPU:

    docker run --rm --network none --entrypoint /opt/fl4shminer/ci-smoke-test.sh fl4shminer-salad:ci --image

It verifies the required Python standard-library imports, installed binary hash and ELF header, runtime package boundary, config handling, and healthcheck behavior outside a mining container. It does not connect to a pool or invoke the real miner. A passing image smoke is required before the workflow publishes the version, commit, and latest tags.

The independent GitHub Actions workflow builds and smoke-tests a local linux/amd64 image before Docker Hub login. On main only, it publishes the same image as 1.5.2, sha-<12-character-commit>, and latest, then checks that all tags resolve to the published digest. Required repository secrets are DOCKERHUB_USERNAME and DOCKERHUB_TOKEN. The destination is fixed to docker.io/myblockchaincompany/fl4shminer-salad.

### Unified miner and central watcher image

The image packages the miner runtime with the current `log_alerts` central fleet watcher and only its two required repository dependencies: `collector/g4a_salad_get.py` and `g4c-live/live_secret_boundary.py`. The Dockerfile-specific ignore file starts from a deny-all repository-root context and allows exact required files. It does not copy the rest of the repository, all of `collector/`, tests, credentials, SQLite state, logs, CSV evidence, or unrelated telemetry. The offline fleet image smoke verifies the exact source allowlist and, inside CI, the installed image inventory and imports.

The default entrypoint continues to start Fl4shMiner, including its existing optional local monitor behavior. The central watcher is a separate CLI capability and never starts automatically in miner replicas. A dedicated, separately authorized watcher process can invoke `python3 -m log_alerts.live_cli`; the image sets `PYTHONPATH=/opt/fl4shminer/gpu-mining/telemetry`. The watcher smoke blocks network, DNS, credential prompts, and delivery, and verifies that live reads remain disabled by default. Packaging the watcher does not enable live operations.

The workflow rebuilds for changes under `gpu-mining/runtime/fl4shminer/**`, any source under `gpu-mining/telemetry/log_alerts/**`, the exact `gpu-mining/telemetry/collector/g4a_salad_get.py` resolver, the exact `gpu-mining/g4c-live/live_secret_boundary.py` secret boundary, and the workflow itself. Both CI and publication builds use the repository root as context and the explicit Fl4sh Dockerfile. OCI `source` identifies this repository, `revision` is the full integration commit SHA, and `version` remains Fl4shMiner `1.5.2`; the immutable digest identifies a concrete image build.

Use the immutable docker.io/myblockchaincompany/fl4shminer-salad@sha256:<digest> reference reported by the successful workflow for a later Salad test. The digest is created by the publish run and must be copied from that run; a mutable tag is not deployment evidence.

## Salad test boundary

The image contains no automatic Salad deployment, allocator, billing API, wallet secret, or pool connection at build time. A later manual lab must choose the GPU class and hourly price, explicitly set the pool URL and mining identifier, and observe the actual Salad lifecycle and billing record separately from miner uptime and pool balance. Preserve estimated income, pool-observed balance, paid amount, conversion, and realized income as distinct evidence states.

The accompanying research uses 94.75 TH/s as a theoretical screening threshold under stated assumptions. It is not a measured Fl4shMiner result, a Salad benchmark, a compatibility finding, or a profitability promise.
