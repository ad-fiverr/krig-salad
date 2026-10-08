# KRig v1.5.6 runtime for Salad's manually configured GPU container.
# Both stages use the same immutable NVIDIA CUDA runtime base.
FROM nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91 AS artifact

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl file binutils libc-bin tar coreutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/krig
COPY krig-release.lock verify-artifact.sh ./
RUN chmod 0555 verify-artifact.sh \
    && ./verify-artifact.sh --download-and-verify /opt/krig

FROM nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91

LABEL org.opencontainers.image.title="KRig Salad GPU miner runtime" \
      org.opencontainers.image.description="Pinned KRig v1.5.6 runtime for manually configured PRL or QTC Salad workloads" \
      org.opencontainers.image.version="1.5.6" \
      org.opencontainers.image.source="https://github.com/kryptex/krig-miner" \
      org.opencontainers.image.revision="259a2a064b28dcf7d0f1921dcdb2c3f608242567"

WORKDIR /opt/krig
COPY --from=artifact --chmod=0555 /opt/krig/krig-miner /opt/krig/krig-miner
COPY --chmod=0555 krig-entrypoint.sh krig-healthcheck.sh ci-smoke-test.sh verify-artifact.sh /opt/krig/
COPY krig-release.lock README.md /opt/krig/

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD ["/opt/krig/krig-healthcheck.sh"]
ENTRYPOINT ["/opt/krig/krig-entrypoint.sh"]
