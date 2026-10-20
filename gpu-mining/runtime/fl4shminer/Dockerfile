# Fl4shMiner v1.5.2 PRL runtime plus the separately invoked central watcher.
# Both build stages use the repository root as their context.
FROM --platform=linux/amd64 nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91 AS artifact

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl file binutils coreutils tar python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/fl4shminer
COPY gpu-mining/runtime/fl4shminer/fl4sh-release.lock gpu-mining/runtime/fl4shminer/verify-artifact.sh ./
RUN chmod 0555 verify-artifact.sh \
    && ./verify-artifact.sh --download-and-verify /opt/fl4shminer

FROM --platform=linux/amd64 nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91

# The opt-in miner supervisor and central CLI need Python's standard library.
# Keep the final stage free of pip, compilers, downloaders, and build tooling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-cryptography=3.4.8-1ubuntu2.4 \
    && rm -rf /var/lib/apt/lists/*

ARG IMAGE_REVISION=unknown
LABEL org.opencontainers.image.title="Fl4shMiner Salad runtime and central watcher" \
      org.opencontainers.image.description="Fl4shMiner v1.5.2 PRL runtime with a separately invoked, disabled-by-default central Salad log watcher" \
      org.opencontainers.image.version="1.5.2" \
      org.opencontainers.image.source="https://github.com/ad-fiverr/krig-salad" \
      org.opencontainers.image.revision="${IMAGE_REVISION}"

WORKDIR /opt/fl4shminer
ENV PYTHONPATH=/opt/fl4shminer/gpu-mining/telemetry
COPY --from=artifact --chmod=0555 /opt/fl4shminer/fl4shminer /opt/fl4shminer/fl4shminer
COPY --chmod=0555 gpu-mining/runtime/fl4shminer/fl4sh-entrypoint.sh gpu-mining/runtime/fl4shminer/fl4sh-healthcheck.sh gpu-mining/runtime/fl4shminer/verify-artifact.sh gpu-mining/runtime/fl4shminer/ci-smoke-test.sh /opt/fl4shminer/
COPY --chmod=0555 gpu-mining/runtime/fl4shminer/fl4sh-runtime-monitor.py /opt/fl4shminer/fl4sh-runtime-monitor.py
COPY --chmod=0555 gpu-mining/runtime/fl4shminer/ci-fleet-image-smoke.py /opt/fl4shminer/ci-fleet-image-smoke.py
COPY gpu-mining/runtime/fl4shminer/fl4sh-release.lock gpu-mining/runtime/fl4shminer/README.md /opt/fl4shminer/

# Explicit Python-module allowlist. collector is intentionally a namespace
# package here: do not copy collector/__init__.py or unrelated telemetry.
COPY gpu-mining/telemetry/log_alerts/__init__.py gpu-mining/telemetry/log_alerts/central_telegram.py gpu-mining/telemetry/log_alerts/contract.py gpu-mining/telemetry/log_alerts/cuda_guard.py gpu-mining/telemetry/log_alerts/delivery.py gpu-mining/telemetry/log_alerts/engine.py gpu-mining/telemetry/log_alerts/fleet_targets.py gpu-mining/telemetry/log_alerts/fleet_watcher.py gpu-mining/telemetry/log_alerts/ledger.py gpu-mining/telemetry/log_alerts/list_instances_lookup.py gpu-mining/telemetry/log_alerts/live_adapter.py gpu-mining/telemetry/log_alerts/live_capability.py gpu-mining/telemetry/log_alerts/live_cli.py gpu-mining/telemetry/log_alerts/live_controller.py gpu-mining/telemetry/log_alerts/live_transport.py gpu-mining/telemetry/log_alerts/normalize.py gpu-mining/telemetry/log_alerts/provider_binding_revalidation.py gpu-mining/telemetry/log_alerts/startup_early_bridge.py gpu-mining/telemetry/log_alerts/startup_guard.py gpu-mining/telemetry/log_alerts/startup_v2_attestation.py /opt/fl4shminer/gpu-mining/telemetry/log_alerts/
COPY gpu-mining/telemetry/collector/fl4sh_early_autotune.py gpu-mining/telemetry/collector/fl4shminer.py gpu-mining/telemetry/collector/g4a_salad_get.py gpu-mining/telemetry/collector/gpu_identity.py gpu-mining/telemetry/collector/models.py gpu-mining/telemetry/collector/startup_admission.py gpu-mining/telemetry/collector/startup_recovery_policy.py gpu-mining/telemetry/collector/work.py /opt/fl4shminer/gpu-mining/telemetry/collector/
COPY gpu-mining/telemetry/collector/guards.py /opt/fl4shminer/gpu-mining/telemetry/collector/guards.py
COPY gpu-mining/telemetry/collector/action_ledger.py gpu-mining/telemetry/collector/auto_reallocation_gate.py gpu-mining/telemetry/collector/continuous.py gpu-mining/telemetry/collector/dashboard_projection.py gpu-mining/telemetry/collector/device_guard.py gpu-mining/telemetry/collector/early_reallocation_dispatch.py gpu-mining/telemetry/collector/fleet.py gpu-mining/telemetry/collector/fleet_hashrate_rollups.py gpu-mining/telemetry/collector/guard_store.py gpu-mining/telemetry/collector/live_contracts.py gpu-mining/telemetry/collector/reallocation_controller.py gpu-mining/telemetry/collector/salad_action_policy.py gpu-mining/telemetry/collector/salad_action_transport.py gpu-mining/telemetry/collector/salad_billing_cost.py gpu-mining/telemetry/collector/salad_lifecycle.py gpu-mining/telemetry/collector/startup_latency.py gpu-mining/telemetry/collector/v2_adapters.py /opt/fl4shminer/gpu-mining/telemetry/collector/
COPY gpu-mining/telemetry/g5_control_plane/__init__.py gpu-mining/telemetry/g5_control_plane/app.py gpu-mining/telemetry/g5_control_plane/config.py gpu-mining/telemetry/g5_control_plane/server.py gpu-mining/telemetry/g5_control_plane/service.py gpu-mining/telemetry/g5_control_plane/startup_policy.py gpu-mining/telemetry/g5_control_plane/store.py /opt/fl4shminer/gpu-mining/telemetry/g5_control_plane/
COPY gpu-mining/telemetry/g5_control_plane/static/index.html /opt/fl4shminer/gpu-mining/telemetry/g5_control_plane/static/index.html
COPY gpu-mining/telemetry/g5_control_plane/static/app.js /opt/fl4shminer/gpu-mining/telemetry/g5_control_plane/static/app.js
COPY gpu-mining/telemetry/g5_control_plane/static/styles.css /opt/fl4shminer/gpu-mining/telemetry/g5_control_plane/static/styles.css
COPY gpu-mining/g4c-live/live_secret_boundary.py /opt/fl4shminer/gpu-mining/g4c-live/live_secret_boundary.py

HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 CMD ["/opt/fl4shminer/fl4sh-healthcheck.sh"]
ENTRYPOINT ["/opt/fl4shminer/fl4sh-entrypoint.sh"]
