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

The upstream publisher describes a 1.5% developer fee. That is a publisher claim, not a separately measured fee for this runtime or a Salad session.

## Runtime contract

The container accepts only these required environment variables:

- FL4SH_POOL_URL: an explicit stratum+tcp://host:port URL. There is no default endpoint.
- FL4SH_MINING_ID: the complete pool login/identifier, optionally followed by a worker suffix. The wrapper does not print its value.

The password is fixed to x by the launch contract. Arbitrary command overrides, shell evaluation, extra devices, and pool fallback are disabled. With the monitor disabled (the default), the miner keeps its existing direct-exec PID 1 behavior. Optional nvidia-smi diagnostics do not decide CUDA compatibility.

### Optional runtime hashrate monitor

Set `FL4SH_MONITOR_ENABLED=1` to opt in. The Python supervisor becomes PID 1, starts Fl4shMiner as its child, forwards termination signals, and relays stdout/stderr in byte chunks so progress output without a newline remains visible. Hashrate parsing uses a separate bounded line buffer; oversized records cannot grow parser memory. A child ended by a signal maps to the conventional `128 + signal` exit status. With `FL4SH_MONITOR_ENABLED=0` or unset, the original direct-exec process behavior remains. The liveness healthcheck supports both process layouts and does not use hashrate as a health signal.

The monitor parses only explicit Fl4shMiner lines of the form `Device [N] hashRate: ... TH/s`. It ignores Pearl autotune and CUDA pool-equivalent estimates. Its rolling average is time-weighted; each reading is held for at most the expected sample interval, never across a larger configured sample gap. Larger gaps reduce coverage, and a gap beyond the maximum invalidates the window. The first performance decision waits for the complete hash window after warm-up; subsequent decisions use the configured reevaluation cadence. Incomplete windows result in `INSUFFICIENT_DATA` or `TELEMETRY_STALE`, never an invented zero rate. Device numbers are reported in the `fl4shminer_device:N` namespace and are not a verified Salad GPU or allocation identity. Stale counters remain miner-reported counters, not proof of paid shares. Provider binding, billing, and GPU identity remain `UNKNOWN`; every advisory includes `actions_performed=false`.

Select an exact operator alert profile with `FL4SH_MONITOR_PROFILE`: `RTX_5080_LAPTOP`, `RTX_5090_LAPTOP`, `RTX_5080_DESKTOP`, or `RTX_5090_DESKTOP`. Default floors are 120, 120, 209, and 350 TH/s respectively. The matching floor can be overridden independently with `SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS`, `SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS`, `SALAD_G5_GPU_FLOOR_RTX_5080_DESKTOP_THS`, or `SALAD_G5_GPU_FLOOR_RTX_5090_DESKTOP_THS`. Profile selection is an operator configuration, not evidence that the provider assigned that GPU.

Initial monitoring values can be set independently using `SALAD_G5_WARMUP_SECONDS` (90), `SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS` (10), `SALAD_G5_HASH_WINDOW_SECONDS` (120), `SALAD_G5_REEVALUATION_INTERVAL_SECONDS` (30), `SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW` (10), `SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS` (30), `SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO` (0.8), and `SALAD_G5_CONSECUTIVE_BAD_WINDOWS` (2). Invalid or incoherent values fail closed before the monitor can start Fl4shMiner. On startup, the monitor logs its effective settings and `policy_hash` for traceability.

The monitor emits `WARMUP`, `INSUFFICIENT_DATA`, `TELEMETRY_STALE`, `NO_FLOOR_CONFIGURED`, `HEALTHY`, `BELOW_FLOOR`, `REALLOCATE_RECOMMENDED`, and `RECOVERED` transitions when applicable. `REALLOCATE_RECOMMENDED` is an advisory only: this image does not stop, move, or reallocate a Salad instance, and the monitor does not verify profitability or Salad billing.

Kryptex documents regional PRL endpoints as candidates; prl-us.kryptex.network:7048 is a candidate endpoint for an explicitly configured lab, not a hidden image default. The third-party command form and device flag have not been validated by running this pinned binary against Salad. KRig's port 8048 must not be substituted based on its separate runtime.

Automatic tuning behavior on Salad is unvalidated. Configure conservative settings through the pool/miner behavior available in the pinned release, and record actual accepted/rejected/stale shares and GPU telemetry in a later lab. Do not interpret startup, image health, or a successful config check as mining productivity.

## Build, smoke test, and publish

Run source checks from the repository root:

    bash gpu-mining/runtime/fl4shminer/ci-smoke-test.sh --source

The CI source checks validate Bash syntax, the release lock, workflow YAML, the monitor's offline regression tests, configuration rejection and redaction, and the exact launch arguments in monitor-off and monitor-on modes using a temporary stub executable. They never execute the Fl4shMiner binary.

The image smoke test runs with Docker networking disabled and no GPU:

    docker run --rm --network none --entrypoint /opt/fl4shminer/ci-smoke-test.sh fl4shminer-salad:ci --image

It verifies the installed binary hash and ELF header, runtime package boundary, config handling, and healthcheck behavior outside a mining container. It does not connect to a pool or invoke the real miner.

The independent GitHub Actions workflow builds and smoke-tests a local linux/amd64 image before Docker Hub login. On main only, it publishes the same image as 1.5.2, sha-<12-character-commit>, and latest, then checks that all tags resolve to the published digest. Required repository secrets are DOCKERHUB_USERNAME and DOCKERHUB_TOKEN. The destination is fixed to docker.io/myblockchaincompany/fl4shminer-salad.

Use the immutable docker.io/myblockchaincompany/fl4shminer-salad@sha256:<digest> reference reported by the successful workflow for a later Salad test. The digest is created by the publish run and must be copied from that run; a mutable tag is not deployment evidence.

## Salad test boundary

The image contains no automatic Salad deployment, allocator, billing API, wallet secret, or pool connection at build time. A later manual lab must choose the GPU class and hourly price, explicitly set the pool URL and mining identifier, and observe the actual Salad lifecycle and billing record separately from miner uptime and pool balance. Preserve estimated income, pool-observed balance, paid amount, conversion, and realized income as distinct evidence states.

The accompanying research uses 94.75 TH/s as a theoretical screening threshold under stated assumptions. It is not a measured Fl4shMiner result, a Salad benchmark, a compatibility finding, or a profitability promise.
