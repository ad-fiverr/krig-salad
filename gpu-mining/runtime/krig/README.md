# KRig Salad container (v1.5.6)

This directory builds a Linux/amd64 image containing the pinned KRig v1.5.6 executable. At runtime, one process mines one selected coin: Pearl (PRL) or Quantus (QTC). CI validates configuration and image construction; it does not start KRig, connect to a pool, or claim a Salad benchmark.

## Pinned inputs

- KRig release: [v1.5.6](https://github.com/kryptex/krig-miner/releases/tag/v1.5.6), release revision `259a2a064b28dcf7d0f1921dcdb2c3f608242567`.
- Executable options: [v1.5.6 README](https://github.com/kryptex/krig-miner/blob/v1.5.6/README.md)
- Upstream license: [v1.5.6 LICENSE](https://github.com/kryptex/krig-miner/blob/v1.5.6/LICENSE). The upstream notice allows the release binaries to be downloaded, redistributed, and run by mining software and supplies them as-is without warranty. Consult the linked full text.
- NVIDIA runtime base: `nvidia/cuda:12.8.2-runtime-ubuntu22.04`, pinned by digest in `Dockerfile`.
- `krig-release.lock` records the release tag/revision, archive type, asset URL/name/size, both SHA-256 values, and explicit provenance for each digest. The archive SHA-256 is `UPSTREAM_PUBLISHED` from GitHub Release metadata; the executable SHA-256 is `LOCALLY_FROZEN_AUDIT`, calculated from the extracted binary in that verified archive. The build checks both values and their provenance labels.

Static ELF inspection of the pinned executable reports `DT_NEEDED` entries `libm.so.6`, `libc.so.6`, and `ld-linux-x86-64.so.2`, a maximum observed GLIBC symbol version of `2.35`, and the interpreter `/lib64/ld-linux-x86-64.so.2`. The binary also contains the `libcuda.so.1` runtime-library name; that NVIDIA driver interface must be supplied by the host runtime and is not included as a direct `DT_NEEDED` dependency. The digest-pinned `nvidia/cuda:12.8.2-runtime-ubuntu22.04` base supplies the Ubuntu 22.04/glibc 2.35 user-space and CUDA runtime layer; its direct ELF dependencies are checked statically against the same pinned base during build. No miner command is run for that audit. This justifies the selected candidate base, but does not prove Salad driver injection or GPU runtime compatibility.

KRig v1.5.6 is one executable that supports PRL or QTC, selected at process start. This image starts exactly one coin process. It uses the host-provided NVIDIA driver interface; it does not bundle a host driver or install kernel modules. The CUDA runtime base is pinned for a reproducible user-space image and is not evidence that Salad has run this image.

## Runtime configuration

Set these three environment variables in the Salad container group:

| Variable | Required | Meaning |
|---|---:|---|
| `KRIG_COIN` | Yes | Exactly `PRL` or `QTC`, one coin per process. |
| `KRIG_POOL_URL` | Yes | Explicit TLS Stratum endpoint, `stratum+ssl://host:port`. There is no default host or port. |
| `KRIG_USER` | Yes | Complete pool identifier, such as `wallet/worker` or `username/worker` when a worker suffix is needed; a separate worker variable is not used. |

The pool endpoint is deliberately configurable. KRig v1.5.6 documents `stratum+ssl://` for both Pearl and Quantus in its `--url` help, so this wrapper accepts that published scheme only; the pool's generic TCP/SSL listing is not miner-specific evidence for KRig. See the [KRig v1.5.6 CLI documentation](https://github.com/kryptex/krig-miner/blob/v1.5.6/README.md#usage). The available PRL material conflicts between ports `7048` and `8048`; choose the endpoint shown by the intended pool/account and enter it explicitly. `7049` is a documented QTC example, not an enforced default. The entrypoint rejects other schemes, user-info, query strings, malformed hosts/ports, unsupported coins, unsafe identifiers, and arbitrary container command overrides.

Before normal startup, the entrypoint strictly validates the configuration and then starts KRig directly as PID 1. It does not inspect `/dev/nvidiactl` or `/dev/nvidiaN` or use their presence as a CUDA availability contract. If `nvidia-smi` exists, `nvidia-smi -L` is an optional diagnostic: a missing command or failed query is logged but never prevents the KRig `exec`. KRig itself attempts CUDA initialization and reports the actual driver, device, or compatibility error. This change does not prove that Salad exposes a usable GPU. KRig remains configured for visible CUDA device index `0` with the ROCm backend disabled; configure one GPU per Salad instance.

`--check-runtime` validates the required configuration, may run the same optional `nvidia-smi` diagnostic, and exits without starting KRig. It does not inspect NVIDIA device paths, and a missing or failed diagnostic still returns success. Its completion message explicitly says that the miner was not started and CUDA compatibility was not tested. `--validate-config` remains configuration-only. Salad driver injection, GPU assignment, preemption, billing, and runtime health still require a separately authorized lab run. The Docker healthcheck only verifies that KRig is alive as PID 1; it does not establish pool connectivity, accepted shares, payout, or profitability.

### Identifier and log handling

Use only the pool's mining identifier in `KRIG_USER`; never put an account password, seed phrase, private key, or exchange credential in this container. The identifier is passed in KRig's process arguments and KRig's own output is not filtered, so it may appear in process inspection or container logs. The entrypoint's validation/startup summaries redact it.

## Build and publish

The root workflow `.github/workflows/build-krig.yml` builds and tests `linux/amd64` for pushes to `main` that match its path filters, plus manual `workflow_dispatch`. It does not run on pull requests. On the repository default branch, it publishes to Docker Hub after tests pass. Configure GitHub Actions secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, and create the Docker Hub repository `<username>/krig-salad` with the desired visibility before the first publish. The token needs permission to push that repository.

Tags produced by a successful default-branch publish:

- `<username>/krig-salad:1.5.6` — pinned miner release convenience tag.
- `<username>/krig-salad:sha-<12-character-commit>` — commit-specific tag.
- `<username>/krig-salad:latest` — moving default-branch convenience tag.

The workflow confirms that all published tags point to the same manifest digest and writes the digest to the Actions summary. For a deployment, prefer the recorded immutable reference `docker.io/<username>/krig-salad@sha256:<digest>`; tags can move. No workflow is dispatched by this repository change.

## Manual Salad deployment

After the user has confirmed a published image and digest:

1. In Salad Portal, create a container group manually with the image pinned to that digest.
2. Select one GPU instance and one replica. Choose the GPU class and priority explicitly; this image does not select or reallocate Salad capacity.
3. Set `KRIG_COIN`, `KRIG_POOL_URL`, and the complete `KRIG_USER` value in the group configuration. Include `/worker` in that value only when the pool identifier requires it.
4. Do not set a web gateway, inbound port, or command override. The workload is an outbound Stratum client, not a web service. Allow the runtime's required outbound DNS/TLS pool traffic under the applicable Salad configuration.
5. Inspect the container state and logs manually. A running/healthy process is only a liveness signal; it does not prove accepted shares, rewards, payout, account autoconversion, or net proceeds.

This repository change does not create a Salad group or start mining. There is no Salad API automation, scheduler, real pool connection, GPU validation, or revenue claim in this v1 image build.

## Checks

`ci-smoke-test.sh --source` runs syntax, lock, workflow, Dockerfile, and static no-device-gate checks before the image build. After building, the workflow inspects the local image's `linux/amd64` platform, entrypoint, healthcheck, and OCI release labels. It then runs `ci-smoke-test.sh --image` inside that image with Docker networking disabled and without GPU access. The image smoke verifies the installed executable's SHA-256 and ELF x86-64 header, checks installed packages for host-driver components, and exercises placeholder configuration validation and optional diagnostics. It also confirms `/dev/nvidiactl` and `/dev/nvidia0` are absent, then runs a temporary copy of the entrypoint whose KRig target is replaced by a stub; the stub records and verifies the exact arguments from normal startup. The smoke never executes the actual KRig binary, connects to a pool, or starts mining. A passing build and smoke test do not prove GPU compatibility in Salad; Salad deployment is outside this task's scope.
