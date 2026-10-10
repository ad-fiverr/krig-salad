# Fl4shMiner v1.5.2 PRL runtime. Keep this image isolated from KRig.
FROM --platform=linux/amd64 nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91 AS artifact

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl file binutils coreutils tar python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/fl4shminer
COPY fl4sh-release.lock verify-artifact.sh ./
RUN chmod 0555 verify-artifact.sh \
    && ./verify-artifact.sh --download-and-verify /opt/fl4shminer

FROM --platform=linux/amd64 nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91

LABEL org.opencontainers.image.title="Fl4shMiner Salad runtime" \
      org.opencontainers.image.description="Isolated Fl4shMiner v1.5.2 PRL/PearlHash runtime; Salad GPU and pool behavior require a later lab" \
      org.opencontainers.image.version="1.5.2" \
      org.opencontainers.image.source="https://github.com/Fl4sh9174/Fl4shMiner"

WORKDIR /opt/fl4shminer
COPY --from=artifact --chmod=0555 /opt/fl4shminer/fl4shminer /opt/fl4shminer/fl4shminer
COPY --chmod=0555 fl4sh-entrypoint.sh fl4sh-healthcheck.sh verify-artifact.sh ci-smoke-test.sh /opt/fl4shminer/
COPY fl4sh-release.lock README.md /opt/fl4shminer/

HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 CMD ["/opt/fl4shminer/fl4sh-healthcheck.sh"]
ENTRYPOINT ["/opt/fl4shminer/fl4sh-entrypoint.sh"]
