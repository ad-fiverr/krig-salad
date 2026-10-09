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

The password is fixed to x by the launch contract. Arbitrary command overrides, shell evaluation, extra devices, and pool fallback are disabled. The normal process uses PearlHash, requests device 0, and runs as PID 1 through direct exec. Optional nvidia-smi diagnostics do not decide CUDA compatibility.

Kryptex documents regional PRL endpoints as candidates; prl-us.kryptex.network:7048 is a candidate endpoint for an explicitly configured lab, not a hidden image default. The third-party command form and device flag have not been validated by running this pinned binary against Salad. KRig's port 8048 must not be substituted based on its separate runtime.

Automatic tuning behavior on Salad is unvalidated. Configure conservative settings through the pool/miner behavior available in the pinned release, and record actual accepted/rejected/stale shares and GPU telemetry in a later lab. Do not interpret startup, image health, or a successful config check as mining productivity.

## Build, smoke test, and publish

Run source checks from the repository root:

    bash gpu-mining/runtime/fl4shminer/ci-smoke-test.sh --source

The CI source checks validate Bash syntax, the release lock, workflow YAML, configuration rejection and redaction, and the exact launch arguments using a temporary stub executable. They never execute the Fl4shMiner binary.

The image smoke test runs with Docker networking disabled and no GPU:

    docker run --rm --network none --entrypoint /opt/fl4shminer/ci-smoke-test.sh fl4shminer-salad:ci --image

It verifies the installed binary hash and ELF header, runtime package boundary, config handling, and healthcheck behavior outside a mining container. It does not connect to a pool or invoke the real miner.

The independent GitHub Actions workflow builds and smoke-tests a local linux/amd64 image before Docker Hub login. On main only, it publishes the same image as 1.5.2, sha-<12-character-commit>, and latest, then checks that all tags resolve to the published digest. Required repository secrets are DOCKERHUB_USERNAME and DOCKERHUB_TOKEN. The destination is fixed to docker.io/myblockchaincompany/fl4shminer-salad.

Use the immutable docker.io/myblockchaincompany/fl4shminer-salad@sha256:<digest> reference reported by the successful workflow for a later Salad test. The digest is created by the publish run and must be copied from that run; a mutable tag is not deployment evidence.

## Salad test boundary

The image contains no automatic Salad deployment, allocator, billing API, wallet secret, or pool connection at build time. A later manual lab must choose the GPU class and hourly price, explicitly set the pool URL and mining identifier, and observe the actual Salad lifecycle and billing record separately from miner uptime and pool balance. Preserve estimated income, pool-observed balance, paid amount, conversion, and realized income as distinct evidence states.

The accompanying research uses 94.75 TH/s as a theoretical screening threshold under stated assumptions. It is not a measured Fl4shMiner result, a Salad benchmark, a compatibility finding, or a profitability promise.
