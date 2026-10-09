#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ulimit -c 0 2>/dev/null || true

fail() {
  printf 'fl4sh-entrypoint: %s\n' "$*" >&2
  exit 64
}

if [[ "$#" -gt 0 && ( "$#" -ne 1 || ( "$1" != --validate-config && "$1" != --check-runtime ) ) ]]; then
  fail "container command overrides are disabled; only --validate-config and --check-runtime are supported for smoke checks"
fi

[[ -n "${FL4SH_POOL_URL:-}" ]] || fail "FL4SH_POOL_URL is required; select an explicit stratum+tcp host and port"
[[ -n "${FL4SH_MINING_ID:-}" ]] || fail "FL4SH_MINING_ID is required"

if [[ ! "$FL4SH_POOL_URL" =~ ^stratum\+tcp://([A-Za-z0-9][A-Za-z0-9.-]*):([0-9]{1,5})$ ]]; then
  fail "FL4SH_POOL_URL must be an explicit stratum+tcp://host:port URL without user-info or query"
fi
pool_host="${BASH_REMATCH[1]}"
pool_port_text="${BASH_REMATCH[2]}"
[[ "$pool_host" == *.* && "$pool_host" != *..* && "$pool_host" != *. && "$pool_host" != .* ]] ||
  fail "FL4SH_POOL_URL host must be a fully qualified DNS name"
IFS='.' read -r -a host_labels <<< "$pool_host"
for host_label in "${host_labels[@]}"; do
  [[ "$host_label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] ||
    fail "FL4SH_POOL_URL contains an invalid DNS label"
done
pool_port=$((10#$pool_port_text))
(( pool_port >= 1 && pool_port <= 65535 )) || fail "FL4SH_POOL_URL port must be between 1 and 65535"

[[ "$FL4SH_MINING_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}(/[A-Za-z0-9._-]{1,32})?$ ]] ||
  fail "FL4SH_MINING_ID contains unsupported characters or an invalid worker suffix"

if [[ "${1:-}" == --validate-config ]]; then
  printf 'configuration valid: coin=PRL pool=%s:%s mining-identifier=redacted\n' "$pool_host" "$pool_port"
  exit 0
fi

diagnose_nvidia_smi() {
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    printf 'fl4sh-entrypoint: optional nvidia-smi diagnostic unavailable; continuing to Fl4shMiner for CUDA initialization\n' >&2
    return 0
  fi

  if nvidia-smi -L >/dev/null 2>&1; then
    printf 'fl4sh-entrypoint: optional nvidia-smi diagnostic succeeded; Fl4shMiner will initialize CUDA\n'
  else
    printf 'fl4sh-entrypoint: WARNING: optional nvidia-smi diagnostic failed; continuing to Fl4shMiner for CUDA initialization\n' >&2
  fi
}

if [[ "${1:-}" == --check-runtime ]]; then
  diagnose_nvidia_smi
  printf 'runtime diagnostics complete; miner was not started; CUDA compatibility was not tested\n'
  exit 0
fi

diagnose_nvidia_smi
printf 'starting Fl4shMiner v1.5.2: coin=PRL pool=%s:%s device=0 mining-identifier=redacted\n' "$pool_host" "$pool_port"
exec /opt/fl4shminer/fl4shminer \
  -a pearlhash \
  -pool "$FL4SH_POOL_URL" \
  -w "$FL4SH_MINING_ID" \
  -pass x \
  -d 0
