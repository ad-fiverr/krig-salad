#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ulimit -c 0 2>/dev/null || true

fail() {
  printf 'krig-entrypoint: %s\n' "$*" >&2
  exit 64
}

if [[ "$#" -gt 0 && ( "$#" -ne 1 || ( "$1" != --validate-config && "$1" != --check-runtime ) ) ]]; then
  fail "container command overrides are disabled; only --validate-config and --check-runtime are supported for smoke checks"
fi

[[ -n "${KRIG_COIN:-}" ]] || fail "KRIG_COIN is required (PRL or QTC)"
[[ -n "${KRIG_POOL_URL:-}" ]] || fail "KRIG_POOL_URL is required; select an explicit pool host and port"
[[ -n "${KRIG_USER:-}" ]] || fail "KRIG_USER is required"

case "${KRIG_COIN^^}" in
  PRL) coin_arg=pearl; coin_label=PRL ;;
  QTC) coin_arg=quantus; coin_label=QTC ;;
  *) fail "KRIG_COIN must be PRL or QTC" ;;
esac

[[ "$KRIG_USER" =~ ^[A-Za-z0-9._:@+-]{1,128}(/[A-Za-z0-9._-]{1,32})?$ ]] ||
  fail "KRIG_USER must be a safe wallet or username, optionally followed by /worker"

if [[ ! "$KRIG_POOL_URL" =~ ^stratum\+ssl://([A-Za-z0-9][A-Za-z0-9.-]*):([0-9]{1,5})$ ]]; then
  fail "KRIG_POOL_URL must be an explicit stratum+ssl://fully-qualified-host:port URL"
fi
pool_host="${BASH_REMATCH[1]}"
pool_port_text="${BASH_REMATCH[2]}"
[[ "$pool_host" == *.* && "$pool_host" != *..* && "$pool_host" != *. ]] || fail "KRIG_POOL_URL host must be a fully-qualified DNS name or IPv4 address"
IFS='.' read -r -a host_labels <<< "$pool_host"
for host_label in "${host_labels[@]}"; do
  [[ "$host_label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || fail "KRIG_POOL_URL contains an invalid host label"
done
pool_port=$((10#$pool_port_text))
(( pool_port >= 1 && pool_port <= 65535 )) || fail "KRIG_POOL_URL port must be between 1 and 65535"

if [[ "${1:-}" == --validate-config ]]; then
  printf 'configuration valid: coin=%s pool=%s:%s mining-identifier=redacted\n' "$coin_label" "$pool_host" "$pool_port"
  exit 0
fi

detect_nvidia_runtime() {
  [[ -e /dev/nvidiactl ]] || fail "NVIDIA runtime is not exposed: /dev/nvidiactl is missing"
  local device gpu_count=0
  for device in /dev/nvidia[0-9]*; do
    if [[ -c "$device" ]]; then
      gpu_count=$((gpu_count + 1))
    fi
  done
  (( gpu_count > 0 )) || fail "NVIDIA runtime is not exposed: no /dev/nvidiaN GPU device nodes found"
  if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia-smi -L >/dev/null 2>&1 || fail "nvidia-smi could not query the exposed GPU runtime"
  fi
  printf 'NVIDIA runtime detected: gpu_device_nodes=%s; KRig will use visible device 0\n' "$gpu_count"
}

if [[ "${1:-}" == --check-runtime ]]; then
  detect_nvidia_runtime
  printf 'runtime check complete; miner was not started\n'
  exit 0
fi

detect_nvidia_runtime
printf 'starting KRig v1.5.6: coin=%s pool=%s:%s device=0 mining-identifier=redacted\n' "$coin_label" "$pool_host" "$pool_port"
exec /opt/krig/krig-miner \
  --coin "$coin_arg" \
  --url "$KRIG_POOL_URL" \
  --user "$KRIG_USER" \
  --no-rocm \
  --devices 0 \
  --no-tui
