#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
mode="${1:-}"
fail() {
  printf 'ci-smoke-test: %s\n' "$*" >&2
  exit 1
}
[[ "$#" -eq 1 ]] || fail "usage: $0 --source | --image"
[[ "$mode" == --source || "$mode" == --image ]] || fail "usage: $0 --source | --image"
unset KRIG_COIN KRIG_POOL_URL KRIG_USER

entrypoint="${SCRIPT_DIR}/krig-entrypoint.sh"
if [[ "$mode" == --source ]]; then
  dockerfile="${SCRIPT_DIR}/Dockerfile"
  workflow="${SCRIPT_DIR}/../../../.github/workflows/build-krig.yml"
  for script in "$entrypoint" "${SCRIPT_DIR}/krig-healthcheck.sh" "${SCRIPT_DIR}/verify-artifact.sh" "$0"; do
    bash -n "$script"
  done
  "${SCRIPT_DIR}/verify-artifact.sh" --lock-only

  if grep -Eq '^[[:space:]]*EXPOSE([[:space:]]|$)' "$dockerfile"; then
    fail "Dockerfile must not expose inbound ports"
  fi
  if grep -Eiq 'nvidia-driver|cuda-drivers|nvidia-container-toolkit|nvidia[-_]kernel[-_]modules' "$dockerfile"; then
    fail "Dockerfile must not install host NVIDIA driver components"
  fi
  grep -Fq 'COPY --from=artifact --chmod=0555 /opt/krig/krig-miner /opt/krig/krig-miner' "$dockerfile" ||
    fail "Dockerfile must preserve executable mode for the installed KRig binary"
  if grep -Eiq '(^|[^[:alnum:]_-])(tini|supervisor|supervisord|dumb-init)([^[:alnum:]_-]|$)' "$dockerfile" "$entrypoint"; then
    fail "KRig must remain the direct PID 1 process without an init or supervisor"
  fi
  grep -Eq '^exec[[:space:]]+/opt/krig/krig-miner([[:space:]]|$)' "$entrypoint" ||
    fail "entrypoint must exec KRig directly as PID 1"
  if grep -Eq '/dev/nvidiactl|/dev/nvidia[0-9]' "$entrypoint"; then
    fail "entrypoint must not gate Salad startup on guessed NVIDIA device-node paths"
  fi
  for fixed_flag in '--no-rocm' '--devices 0' '--no-tui'; do
    grep -Fq -- "$fixed_flag" "$entrypoint" || fail "entrypoint is missing fixed KRig flag ${fixed_flag}"
  done
  if grep -Eq 'KRIG_EXTRA_ARGS|(^|[[:space:]])eval([[:space:]]|$)|sh[[:space:]]+-c' "$entrypoint"; then
    fail "entrypoint must not accept arbitrary CLI or shell passthrough"
  fi
  mapfile -t from_lines < <(grep -E '^[[:space:]]*FROM[[:space:]]+' "$dockerfile")
  [[ "${#from_lines[@]}" -eq 2 ]] || fail "Dockerfile must keep its two pinned CUDA runtime stages"
  for from_line in "${from_lines[@]}"; do
    [[ "$from_line" == *nvidia/cuda:* && "$from_line" =~ @sha256:[0-9a-f]{64}([[:space:]]|$) ]] ||
      fail "every Docker base image must be an immutable NVIDIA CUDA digest"
  done

  grep -Fq '  push:' "$workflow" || fail "workflow push trigger is missing"
  grep -Fq '    branches: [main]' "$workflow" || fail "workflow must trigger pushes only on main"
  grep -Fq '  workflow_dispatch:' "$workflow" || fail "manual workflow trigger is missing"
  grep -Fq '      - "gpu-mining/runtime/krig/**"' "$workflow" || fail "runtime path filter is missing"
  grep -Fq '      - ".github/workflows/build-krig.yml"' "$workflow" || fail "workflow path filter is missing"
  if grep -Eq '^  pull_request:' "$workflow"; then
    fail "pull_request trigger is outside the approved workflow scope"
  fi
else
  for required_file in krig-miner krig-entrypoint.sh krig-healthcheck.sh verify-artifact.sh krig-release.lock; do
    [[ -f "${SCRIPT_DIR}/${required_file}" ]] || fail "runtime image is missing ${required_file}"
  done
  [[ -x "${SCRIPT_DIR}/krig-miner" ]] || fail "installed KRig executable is not executable"
  for script in "$entrypoint" "${SCRIPT_DIR}/krig-healthcheck.sh" "${SCRIPT_DIR}/verify-artifact.sh" "$0"; do
    bash -n "$script"
  done
  "${SCRIPT_DIR}/verify-artifact.sh" --lock-only
  "${SCRIPT_DIR}/verify-artifact.sh" --installed
  command -v dpkg-query >/dev/null 2>&1 || fail "dpkg-query is required to inspect installed image packages"
  package_status="$(dpkg-query -W -f='${Package}\t${db:Status-Status}\n' 2>/dev/null)" ||
    fail "could not inspect installed image packages"
  if grep -Eiq '^(nvidia-driver-[^[:space:]]*|cuda-drivers(-[^[:space:]]*)?|nvidia-container-toolkit(-base)?|nvidia-dkms-[^[:space:]]*|nvidia-kernel-(common|source)-[^[:space:]]*|nvidia-modprobe)[[:space:]]+installed$' <<< "$package_status"; then
    fail "runtime image contains an NVIDIA host-driver package"
  fi
fi

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT

no_nvidia_smi_path="${tmp}/no-nvidia-smi"
fake_nvidia_smi_ok="${tmp}/fake-nvidia-smi-ok"
fake_nvidia_smi_fail="${tmp}/fake-nvidia-smi-fail"
mkdir -p "$no_nvidia_smi_path" "$fake_nvidia_smi_ok" "$fake_nvidia_smi_fail"
cat >"${fake_nvidia_smi_ok}/nvidia-smi" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"${fake_nvidia_smi_fail}/nvidia-smi" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 0555 "${fake_nvidia_smi_ok}/nvidia-smi" "${fake_nvidia_smi_fail}/nvidia-smi"

check_runtime_diagnostic() {
  local label="$1" path="$2" expected="$3"
  local output="${tmp}/runtime-${label}.txt"
  if ! KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 \
    KRIG_USER=wallet-placeholder/ci-worker PATH="$path" "$BASH" "$entrypoint" --check-runtime >"$output" 2>&1; then
    fail "--check-runtime rejected valid configuration for ${label}"
  fi
  grep -Fq "$expected" "$output" || fail "--check-runtime diagnostic mismatch for ${label}"
  grep -Fq 'runtime diagnostics complete; miner was not started; CUDA compatibility was not tested' "$output" ||
    fail "--check-runtime must state that it did not start the miner or validate CUDA"
  ! grep -Fq 'starting KRig' "$output" || fail "--check-runtime must not enter normal mining startup"
  ! grep -Fq 'wallet-placeholder' "$output" || fail "--check-runtime output leaked the mining identifier"
}

check_runtime_diagnostic missing-nvidia-smi "$no_nvidia_smi_path" \
  'optional nvidia-smi diagnostic unavailable'
check_runtime_diagnostic nvidia-smi-success "$fake_nvidia_smi_ok" \
  'optional nvidia-smi diagnostic succeeded'
check_runtime_diagnostic nvidia-smi-failure "$fake_nvidia_smi_fail" \
  'WARNING: optional nvidia-smi diagnostic failed'

env KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 \
  KRIG_USER=wallet-placeholder/ci-worker \
  "$entrypoint" --validate-config >"${tmp}/valid-prl.txt" 2>&1
grep -Fq 'coin=PRL pool=pool.example.net:7048 mining-identifier=redacted' "${tmp}/valid-prl.txt" || fail "PRL validation summary mismatch"
! grep -Fq 'wallet-placeholder' "${tmp}/valid-prl.txt" || fail "validation output leaked the mining identifier"
! grep -Fq 'ci-worker' "${tmp}/valid-prl.txt" || fail "validation output leaked the mining identifier suffix"

env KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 \
  KRIG_USER=wallet-placeholder \
  "$entrypoint" --validate-config >"${tmp}/valid-prl-wallet-only.txt" 2>&1
grep -Fq 'coin=PRL pool=pool.example.net:7048 mining-identifier=redacted' "${tmp}/valid-prl-wallet-only.txt" || fail "wallet-only PRL identifier was rejected"

env KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:8048 \
  KRIG_USER=wallet-placeholder/ci-worker \
  "$entrypoint" --validate-config >"${tmp}/valid-prl-alt-port.txt" 2>&1
grep -Fq 'coin=PRL pool=pool.example.net:8048' "${tmp}/valid-prl-alt-port.txt" || fail "alternate PRL port validation mismatch"

env KRIG_COIN=QTC KRIG_POOL_URL=stratum+ssl://pool.example.net:7049 \
  KRIG_USER=wallet-placeholder/ci-worker \
  "$entrypoint" --validate-config >"${tmp}/valid-qtc.txt" 2>&1
grep -Fq 'coin=QTC pool=pool.example.net:7049' "${tmp}/valid-qtc.txt" || fail "QTC validation summary mismatch"

expect_invalid() {
  local label="$1"
  shift
  if env "$@" "$entrypoint" --validate-config >"${tmp}/invalid.txt" 2>&1; then
    fail "invalid configuration was accepted: ${label}"
  fi
}

expect_invalid missing-coin KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 KRIG_USER=wallet/ci-worker
expect_invalid missing-prl-pool KRIG_COIN=PRL KRIG_USER=wallet/ci-worker
expect_invalid missing-qtc-pool KRIG_COIN=QTC KRIG_USER=wallet/ci-worker
expect_invalid missing-user KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048
expect_invalid unsupported-alias KRIG_COIN=PEARL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 KRIG_USER=wallet
expect_invalid unknown-coin KRIG_COIN=BTC KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 KRIG_USER=wallet
expect_invalid plaintext-pool KRIG_COIN=PRL KRIG_POOL_URL=stratum://pool.example.net:7048 KRIG_USER=wallet
expect_invalid undocumented-tcp-scheme KRIG_COIN=PRL KRIG_POOL_URL=stratum+tcp://pool.example.net:7048 KRIG_USER=wallet
expect_invalid embedded-userinfo KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://user@pool.example.net:7048 KRIG_USER=wallet
expect_invalid query-string KRIG_COIN=PRL KRIG_POOL_URL='stratum+ssl://pool.example.net:7048?x=1' KRIG_USER=wallet
expect_invalid invalid-port KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:65536 KRIG_USER=wallet
expect_invalid extra-worker-separator KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 KRIG_USER=wallet/worker/extra
expect_invalid unsafe-user KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 KRIG_USER='wallet;touch /tmp/nope'
if env KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 \
  KRIG_USER=wallet-placeholder/ci-worker \
  "$entrypoint" --help >"${tmp}/unsupported-command.txt" 2>&1; then
  fail "arbitrary command override was accepted"
fi

if [[ "$mode" == --image ]]; then
  [[ ! -e /dev/nvidiactl ]] || fail "normal-start regression requires /dev/nvidiactl to be absent; do not create fake device nodes"
  [[ ! -e /dev/nvidia0 ]] || fail "normal-start regression requires /dev/nvidia0 to be absent; do not create fake device nodes"

  stub="${tmp}/krig-miner-stub"
  stub_argv="${tmp}/krig-stub-argv.bin"
  expected_argv="${tmp}/krig-stub-expected-argv.bin"
  test_entrypoint="${tmp}/krig-entrypoint-launch-test.sh"
  normal_start_output="${tmp}/normal-start.txt"
  cat >"$stub" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
: "${KRIG_TEST_ARGV_FILE:?}"
printf '%s\0' "$@" >"$KRIG_TEST_ARGV_FILE"
EOF
  chmod 0555 "$stub"
  sed "s#/opt/krig/krig-miner#${stub}#g" "$entrypoint" >"$test_entrypoint" ||
    fail "could not prepare temporary entrypoint copy for the no-GPU regression"
  chmod 0555 "$test_entrypoint"
  grep -Fq "$stub" "$test_entrypoint" || fail "temporary entrypoint does not target the KRig stub"
  if grep -Fq '/opt/krig/krig-miner' "$test_entrypoint"; then
    fail "temporary entrypoint still references the real KRig binary"
  fi

  if ! KRIG_COIN=PRL KRIG_POOL_URL=stratum+ssl://pool.example.net:7048 \
    KRIG_USER=wallet-placeholder/ci-worker KRIG_TEST_ARGV_FILE="$stub_argv" \
    PATH="${fake_nvidia_smi_fail}:${PATH}" "$BASH" "$test_entrypoint" >"$normal_start_output" 2>&1; then
    fail "valid normal-start configuration did not reach the temporary KRig stub without NVIDIA device nodes"
  fi
  grep -Fq 'starting KRig v1.5.6: coin=PRL pool=pool.example.net:7048 device=0 mining-identifier=redacted' "$normal_start_output" ||
    fail "normal-start summary did not report the redacted PRL configuration"
  grep -Fq 'WARNING: optional nvidia-smi diagnostic failed; continuing to KRig for CUDA initialization' "$normal_start_output" ||
    fail "normal startup did not continue after nvidia-smi failure"
  ! grep -Fq 'wallet-placeholder' "$normal_start_output" || fail "normal-start output leaked the mining identifier"

  printf '%s\0' \
    '--coin' 'pearl' \
    '--url' 'stratum+ssl://pool.example.net:7048' \
    '--user' 'wallet-placeholder/ci-worker' \
    '--no-rocm' \
    '--devices' '0' \
    '--no-tui' >"$expected_argv"
  cmp -s "$expected_argv" "$stub_argv" || fail "temporary KRig stub did not receive the exact coin, URL, user, and fixed flags"
fi

sample_digest="sha256:$(printf 'a%.0s' {1..64})"
parsed_digest="$(printf '1.5.6: digest: %s size: 2048\n' "$sample_digest" | sed -nE 's/.*digest: (sha256:[0-9a-f]{64}).*/\1/p')"
[[ "$parsed_digest" == "$sample_digest" ]] || fail "Docker push digest parser did not extract the manifest digest"

if [[ "$mode" == --image ]]; then
  printf 'non-GPU image smoke tests passed: PRL/QTC config mapping, optional diagnostics, no-device normal-start stub argv, fail-closed validation, and artifact/digest checks\n'
else
  printf 'non-GPU source smoke tests passed: PRL/QTC config mapping, optional runtime diagnostics, fail-closed validation, and registry digest parsing\n'
fi
