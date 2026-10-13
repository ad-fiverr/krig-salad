#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT="$SCRIPT_DIR/fl4sh-entrypoint.sh"
HEALTHCHECK="$SCRIPT_DIR/fl4sh-healthcheck.sh"
VERIFIER="$SCRIPT_DIR/verify-artifact.sh"
LOCK="$SCRIPT_DIR/fl4sh-release.lock"
MONITOR="$SCRIPT_DIR/fl4sh-runtime-monitor.py"
MONITOR_TESTS="$SCRIPT_DIR/test-runtime-monitor.py"

fail() {
  printf 'ci-smoke-test: %s\n' "$*" >&2
  exit 1
}

mode="${1:-}"
[[ "$#" -eq 1 && ( "$mode" == --source || "$mode" == --image ) ]] ||
  fail "usage: $0 --source | --image"

# Keep developer or CI notifier credentials out of this isolated smoke process.
unset FL4SH_TELEGRAM_ENABLED FL4SH_TELEGRAM_BOT_TOKEN FL4SH_TELEGRAM_CHAT_ID \
  FL4SH_TELEGRAM_POOL_ERROR_COOLDOWN_SECONDS FL4SH_MONITOR_LABEL || true

if [[ "$mode" == --source ]]; then
  for script in "$ENTRYPOINT" "$HEALTHCHECK" "$VERIFIER" "$SCRIPT_DIR/ci-smoke-test.sh"; do
    bash -n "$script" || fail "Bash syntax check failed: $(basename "$script")"
  done
  bash "$VERIFIER" --lock-only

  cuda_base='nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91'
  [[ "$(grep -Fc "$cuda_base" "$SCRIPT_DIR/Dockerfile")" -eq 2 ]] ||
    fail "both Docker stages must use the pinned CUDA base"
  ! grep -Eq '^[[:space:]]*EXPOSE[[:space:]]' "$SCRIPT_DIR/Dockerfile" ||
    fail "Dockerfile must not expose a port"
  grep -Fq 'apt-get install -y --no-install-recommends python3' "$SCRIPT_DIR/Dockerfile" ||
    fail "final image must install the Python standard library needed by the opt-in monitor"
  ! grep -Fq 'python3-minimal' "$SCRIPT_DIR/Dockerfile" ||
    fail "final image must not substitute the incomplete minimal Python runtime"
  grep -Fq 'COPY --chmod=0555 fl4sh-runtime-monitor.py /opt/fl4shminer/fl4sh-runtime-monitor.py' "$SCRIPT_DIR/Dockerfile" ||
    fail "final image does not contain the runtime monitor"
  grep -Fxq '!fl4sh-runtime-monitor.py' "$SCRIPT_DIR/.dockerignore" ||
    fail "Docker context does not allow the runtime monitor source"
  if grep -Eq 'FL4SH_MINING_ID=.*(PASSWORD|TOKEN|SECRET)|FL4SH_POOL_URL=.*(@|password=)' "$ENTRYPOINT"; then
    fail "entrypoint contains an unsafe credential pattern"
  fi
  python_bin=python3
  if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == mingw* ]]; then
    python_bin=python
  fi
  command -v "$python_bin" >/dev/null 2>&1 || fail "Python is required for isolated smoke checks"
  temporary="$(mktemp -d)"
  trap 'rm -rf -- "$temporary"' EXIT
  [[ -f "$MONITOR" && -f "$MONITOR_TESTS" ]] || fail "runtime monitor source and tests are required"
  monitor_env_keys=(
    FL4SH_MONITOR_ENABLED FL4SH_MONITOR_PROFILE FL4SH_MONITOR_GPU_FLOORS_JSON
    SALAD_G5_GPU_FLOOR_RTX_5080_LAPTOP_THS SALAD_G5_GPU_FLOOR_RTX_5090_LAPTOP_THS
    SALAD_G5_GPU_FLOOR_RTX_5080_DESKTOP_THS SALAD_G5_GPU_FLOOR_RTX_5090_DESKTOP_THS
    SALAD_G5_WARMUP_SECONDS SALAD_G5_EXPECTED_SAMPLE_INTERVAL_SECONDS
    SALAD_G5_HASH_WINDOW_SECONDS SALAD_G5_REEVALUATION_INTERVAL_SECONDS
    SALAD_G5_MINIMUM_SAMPLES_PER_WINDOW SALAD_G5_MAXIMUM_SAMPLE_GAP_SECONDS
    SALAD_G5_MINIMUM_WINDOW_COVERAGE_RATIO SALAD_G5_CONSECUTIVE_BAD_WINDOWS
    FL4SH_MONITOR_FLOOR_TOLERANCE_THS FL4SH_MONITOR_REALLOCATE_RENOTIFY_DROP_THS
    FL4SH_TELEGRAM_ENABLED FL4SH_TELEGRAM_BOT_TOKEN FL4SH_TELEGRAM_CHAT_ID
    FL4SH_TELEGRAM_POOL_ERROR_COOLDOWN_SECONDS FL4SH_MONITOR_LABEL
  )
  monitor_env_unset=()
  for env_name in "${monitor_env_keys[@]}"; do monitor_env_unset+=(-u "$env_name"); done
  env "${monitor_env_unset[@]}" "$python_bin" -B "$MONITOR" --check-config >/dev/null 2>&1 &&
    fail "monitor unexpectedly accepted a disabled configuration"
  env "${monitor_env_unset[@]}" FL4SH_MONITOR_ENABLED=1 \
    FL4SH_MONITOR_PROFILE=RTX_5090_LAPTOP "$python_bin" -B "$MONITOR" --check-config >/dev/null ||
    fail "valid opt-in monitor configuration was rejected"
  env "${monitor_env_unset[@]}" FL4SH_MONITOR_ENABLED=1 \
    FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110,"RTX_5090_LAPTOP":115,"RTX_5070_TI_LAPTOP":100}' \
    "$python_bin" -B "$MONITOR" --check-config >/dev/null 2>&1 ||
    fail "valid autodetected GPU floor registry was rejected"
  env "${monitor_env_unset[@]}" FL4SH_MONITOR_ENABLED=1 \
    FL4SH_MONITOR_PROFILE=RTX_5090_LAPTOP FL4SH_MONITOR_FLOOR_TOLERANCE_THS=2.5 \
    FL4SH_MONITOR_REALLOCATE_RENOTIFY_DROP_THS=4.25 \
    "$python_bin" -B "$MONITOR" --check-config > "$temporary.monitor-policy.out" 2>&1 ||
    fail "valid floor tolerance or re-alert policy was rejected"
  grep -Fq 'floor_tolerance_ths=2.5' "$temporary.monitor-policy.out" ||
    fail "monitor output omitted the effective floor tolerance"
  grep -Fq 'reallocate_renotify_drop_ths=4.25' "$temporary.monitor-policy.out" ||
    fail "monitor output omitted the effective re-alert drop threshold"
  if env "${monitor_env_unset[@]}" FL4SH_MONITOR_ENABLED=1 \
    FL4SH_MONITOR_PROFILE=RTX_5090_LAPTOP FL4SH_MONITOR_FLOOR_TOLERANCE_THS=3.1 \
    "$python_bin" -B "$MONITOR" --check-config > "$temporary.invalid-policy.out" 2>&1; then
    fail "out-of-range floor tolerance was accepted"
  fi
  grep -Fq 'configuration invalid: INVALID_MONITOR_SETTING' "$temporary.invalid-policy.out" ||
    fail "invalid monitor policy did not use its sanitized error code"
  if env "${monitor_env_unset[@]}" FL4SH_MONITOR_ENABLED=1 FL4SH_TELEGRAM_ENABLED=1 \
    "$python_bin" -B "$MONITOR" --check-config > /dev/null 2>&1; then
    fail "Telegram enabled without credentials was accepted"
  fi
  telegram_token='123456:synthetic_token_for_source_smoke'
  telegram_chat='-1001234567890'
  env "${monitor_env_unset[@]}" FL4SH_MONITOR_ENABLED=1 \
    FL4SH_TELEGRAM_ENABLED=1 FL4SH_TELEGRAM_BOT_TOKEN="$telegram_token" \
    FL4SH_TELEGRAM_CHAT_ID="$telegram_chat" \
    "$python_bin" -B "$MONITOR" --check-config > "$temporary.telegram-config.out" 2>&1 ||
    fail "valid synthetic Telegram config was rejected"
  grep -Fq 'telegram_enabled=true' "$temporary.telegram-config.out" ||
    fail "monitor config did not expose the Telegram enabled state"
  if grep -Fq "$telegram_token" "$temporary.telegram-config.out" ||
    grep -Fq "$telegram_chat" "$temporary.telegram-config.out"; then
    fail "Telegram configuration leaked to monitor output"
  fi
  "$python_bin" -B "$MONITOR_TESTS" || fail "runtime monitor unit tests failed"
  if command -v ruby >/dev/null 2>&1; then
    ruby -e 'require "yaml"; doc = YAML.load_file(ARGV.fetch(0)); abort "workflow jobs missing" unless doc.is_a?(Hash) && doc["jobs"].is_a?(Hash)' \
      "$SCRIPT_DIR/../../../.github/workflows/build-fl4shminer.yml"
  else
    "$python_bin" -c 'import sys, yaml; doc = yaml.safe_load(open(sys.argv[1], encoding="utf-8")); assert isinstance(doc, dict) and isinstance(doc.get("jobs"), dict)' \
      "$SCRIPT_DIR/../../../.github/workflows/build-fl4shminer.yml" ||
      fail "workflow YAML could not be parsed (Ruby or Python PyYAML is required)"
  fi

  mkdir -p "$temporary/bin"
  cat > "$temporary/bin/nvidia-smi" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  cat > "$temporary/bin/python3" <<'STUB'
#!/usr/bin/env bash
if [[ "${1:-}" == /opt/fl4shminer/fl4sh-runtime-monitor.py && "${2:-}" == --check-config ]]; then
  printf 'FL4SH_MONITOR configuration valid provider_binding=UNKNOWN actions_performed=false\n'
  exit 0
fi
exit 91
STUB
  cat > "$temporary/miner-stub" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$FL4SH_TEST_ARGV_FILE"
STUB
  chmod 0555 "$temporary/bin/nvidia-smi" "$temporary/bin/python3" "$temporary/miner-stub"

  "$python_bin" - "$ENTRYPOINT" "$temporary/entrypoint-test.sh" "$temporary/monitor-entrypoint-test.sh" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
needle = "exec /opt/fl4shminer/fl4shminer \\\n"
replacement = 'exec "$FL4SH_TEST_EXECUTABLE" \\\n'
if source.count(needle) != 1:
    raise SystemExit("could not isolate the normal-start command for argument capture")
pathlib.Path(sys.argv[2]).write_text(source.replace(needle, replacement), newline="\n")
monitor_needle = "exec python3 /opt/fl4shminer/fl4sh-runtime-monitor.py -- \\\n"
monitor_replacement = 'exec "$FL4SH_TEST_EXECUTABLE" \\\n'
if source.count(monitor_needle) != 1:
    raise SystemExit("could not isolate the opt-in monitor command for argument capture")
pathlib.Path(sys.argv[3]).write_text(source.replace(monitor_needle, monitor_replacement), newline="\n")
PY
  chmod 0555 "$temporary/entrypoint-test.sh" "$temporary/monitor-entrypoint-test.sh"

  pool='stratum+tcp://pool.example:7048'
  mining_id='PRL_WALLET_FOR_SMOKE.worker-1'
  FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
    bash "$ENTRYPOINT" --validate-config > "$temporary/config.out" 2>&1 ||
    fail "valid configuration was rejected"
  grep -Fq 'configuration valid: coin=PRL pool=pool.example:7048 mining-identifier=redacted' \
    "$temporary/config.out" || fail "configuration success message was unexpected"
  if grep -Fq "$mining_id" "$temporary/config.out"; then
    fail "mining identifier leaked into validation output"
  fi

  expect_rejected() {
    local label="$1"
    shift
    if "$@" > "$temporary/reject.out" 2>&1; then
      fail "invalid configuration was accepted: $label"
    fi
  }
  expect_rejected "missing pool" env -u FL4SH_POOL_URL FL4SH_MINING_ID="$mining_id" \
    bash "$ENTRYPOINT" --validate-config
  if env -u FL4SH_POOL_URL FL4SH_MINING_ID="$mining_id" FL4SH_MONITOR_ENABLED=1 \
    bash "$ENTRYPOINT" --validate-config > "$temporary.monitor-preflight.out" 2>&1; then
    fail "monitor-enabled preflight accepted a missing pool"
  else
    preflight_status=$?
  fi
  [[ "$preflight_status" -eq 64 ]] || fail "monitor preflight did not preserve exit code 64"
  grep -Fxq 'FL4SH_MONITOR configuration invalid: INVALID_ENTRYPOINT_CONFIGURATION' \
    "$temporary.monitor-preflight.out" ||
    fail "monitor preflight did not emit its normalized configuration event"
  if grep -Fq "$mining_id" "$temporary.monitor-preflight.out"; then
    fail "monitor preflight leaked the mining identifier"
  fi
  if env -u FL4SH_POOL_URL FL4SH_MINING_ID="$mining_id" FL4SH_MONITOR_ENABLED=0 \
    bash "$ENTRYPOINT" --validate-config > "$temporary.monitor-off-preflight.out" 2>&1; then
    fail "monitor-off preflight accepted a missing pool"
  else
    monitor_off_status=$?
  fi
  [[ "$monitor_off_status" -eq 64 ]] || fail "monitor-off preflight changed exit code 64"
  grep -Fxq 'fl4sh-entrypoint: FL4SH_POOL_URL is required; select an explicit stratum+tcp host and port' \
    "$temporary.monitor-off-preflight.out" ||
    fail "monitor-off preflight did not preserve its legacy diagnostic"
  if grep -Fq 'FL4SH_MONITOR configuration invalid:' "$temporary.monitor-off-preflight.out"; then
    fail "monitor-off preflight unexpectedly emitted a monitor alert"
  fi
  if env FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" FL4SH_MONITOR_ENABLED=1 \
    bash "$ENTRYPOINT" --help > "$temporary.monitor-flags.out" 2>&1; then
    fail "monitor-enabled entrypoint accepted an unsupported command"
  else
    invalid_flags_status=$?
  fi
  [[ "$invalid_flags_status" -eq 64 ]] || fail "unsupported monitor command changed exit code 64"
  grep -Fxq 'FL4SH_MONITOR configuration invalid: INVALID_ENTRYPOINT_CONFIGURATION' \
    "$temporary.monitor-flags.out" ||
    fail "unsupported monitor command did not emit a normalized configuration event"
  expect_rejected "invalid scheme" env FL4SH_POOL_URL='http://pool.example:7048' \
    FL4SH_MINING_ID="$mining_id" bash "$ENTRYPOINT" --validate-config
  expect_rejected "invalid port" env FL4SH_POOL_URL='stratum+tcp://pool.example:65536' \
    FL4SH_MINING_ID="$mining_id" bash "$ENTRYPOINT" --validate-config
  expect_rejected "unsafe mining identifier" env FL4SH_POOL_URL="$pool" \
    FL4SH_MINING_ID='wallet with spaces' bash "$ENTRYPOINT" --validate-config
  expect_rejected "arbitrary command override" env FL4SH_POOL_URL="$pool" \
    FL4SH_MINING_ID="$mining_id" bash "$ENTRYPOINT" --help

  FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
    PATH="$temporary/bin:$PATH" bash "$ENTRYPOINT" --check-runtime \
    > "$temporary/runtime.out" 2>&1 || fail "non-mining runtime diagnostic failed"
  grep -Fq 'miner was not started; CUDA compatibility was not tested' "$temporary/runtime.out" ||
    fail "runtime diagnostic did not state its test boundary"

  FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
    FL4SH_TEST_EXECUTABLE="$temporary/miner-stub" \
    FL4SH_TEST_ARGV_FILE="$temporary/argv.txt" \
    PATH="$temporary/bin:$PATH" \
    bash "$temporary/entrypoint-test.sh" > "$temporary/start.out" 2>&1 ||
    fail "isolated normal-start argument capture failed"
  if grep -Fq "$mining_id" "$temporary/start.out"; then
    fail "mining identifier leaked into wrapper output"
  fi
  mapfile -t actual_args < "$temporary/argv.txt"
  expected_args=(-a pearlhash -pool "$pool" -w "$mining_id" -pass x -d 0)
  [[ "${#actual_args[@]}" -eq "${#expected_args[@]}" ]] ||
    fail "miner argument count differs from the locked launch contract"
  for index in "${!expected_args[@]}"; do
    [[ "${actual_args[$index]}" == "${expected_args[$index]}" ]] ||
      fail "miner argument mismatch at index $index"
  done

  FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
    FL4SH_MONITOR_ENABLED=1 FL4SH_MONITOR_PROFILE=RTX_5090_LAPTOP \
    PATH="$temporary/bin:$PATH" bash "$ENTRYPOINT" --validate-config \
    > "$temporary/monitor-config.out" 2>&1 ||
    fail "valid monitor-enabled configuration was rejected"
  if grep -Fq "$mining_id" "$temporary/monitor-config.out"; then
    fail "mining identifier leaked from monitor-enabled config validation"
  fi
  expect_rejected "invalid monitor switch" env FL4SH_POOL_URL="$pool" \
    FL4SH_MINING_ID="$mining_id" FL4SH_MONITOR_ENABLED=true \
    bash "$ENTRYPOINT" --validate-config
  if env FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
    FL4SH_TELEGRAM_ENABLED=1 FL4SH_MONITOR_ENABLED=0 \
    bash "$ENTRYPOINT" --validate-config > "$temporary.telegram-guard.out" 2>&1; then
    fail "Telegram enabled while monitor disabled was accepted"
  fi
  grep -Fq 'requires FL4SH_MONITOR_ENABLED=1' "$temporary.telegram-guard.out" ||
    fail "Telegram/monitor dependency guard returned an unexpected message"

  FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
    FL4SH_MONITOR_ENABLED=1 FL4SH_MONITOR_PROFILE=RTX_5090_LAPTOP \
    FL4SH_TEST_EXECUTABLE="$temporary/miner-stub" \
    FL4SH_TEST_ARGV_FILE="$temporary/monitor-argv.txt" \
    PATH="$temporary/bin:$PATH" \
    bash "$temporary/monitor-entrypoint-test.sh" > "$temporary/monitor-start.out" 2>&1 ||
    fail "isolated opt-in monitor command capture failed"
  if grep -Fq "$mining_id" "$temporary/monitor-start.out"; then
    fail "mining identifier leaked into opt-in monitor wrapper output"
  fi
  mapfile -t monitor_args < "$temporary/monitor-argv.txt"
  expected_monitor_args=(/opt/fl4shminer/fl4shminer -a pearlhash -pool "$pool" -w "$mining_id" -pass x -d 0)
  [[ "${#monitor_args[@]}" -eq "${#expected_monitor_args[@]}" ]] ||
    fail "opt-in monitor miner argument count differs from the locked launch contract"
  for index in "${!expected_monitor_args[@]}"; do
    [[ "${monitor_args[$index]}" == "${expected_monitor_args[$index]}" ]] ||
      fail "opt-in monitor miner argument mismatch at index $index"
  done
  printf 'source smoke passed: lock, scripts, workflow YAML, monitor tests, config redaction, and opt-in/off argv capture\n'
  exit 0
fi

bash "$VERIFIER" --lock-only
binary="$SCRIPT_DIR/fl4shminer"
[[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] || fail "installed miner is missing or not executable"
expected_sha="$(awk -F= '$1 == "executable_sha256" {print $2}' "$LOCK")"
actual_sha="$(sha256sum "$binary" | awk '{print $1}')"
[[ "$actual_sha" == "$expected_sha" ]] || fail "installed binary SHA-256 mismatch"

magic="$(od -An -tx1 -N4 "$binary" | tr -d '[:space:]')"
elf_class_data="$(od -An -tx1 -j4 -N2 "$binary" | tr -d '[:space:]')"
elf_machine="$(od -An -tx1 -j18 -N2 "$binary" | tr -d '[:space:]')"
[[ "$magic" == 7f454c46 && "$elf_class_data" == 0201 && "$elf_machine" == 3e00 ]] ||
  fail "installed binary is not an ELF64 little-endian x86-64 executable"

if command -v dpkg-query >/dev/null 2>&1; then
  for package in curl wget gcc g++ build-essential python3-pip python3-venv python3-dev nvidia-smi; do
    status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)"
    [[ "$status" != 'install ok installed' ]] || fail "runtime image unexpectedly contains $package"
  done
  driver_packages="$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null |
    awk '$2 == "install" && $3 == "ok" && $4 == "installed" && $1 ~ /^nvidia-(driver|utils|kernel|dkms)/ {print $1}')"
  [[ -z "$driver_packages" ]] || fail "runtime image contains host driver packages: $driver_packages"
fi
command -v python3 >/dev/null 2>&1 || fail "runtime image is missing the opt-in monitor Python interpreter"
if ! python3 -c 'import collections, dataclasses, datetime, hashlib, http.client, json, math, os, queue, re, signal, ssl, subprocess, sys, threading, time, typing, uuid' >/tmp/fl4sh-python-stdlib.out 2>&1; then
  printf 'Python standard-library import diagnostic (first 12 lines):\n' >&2
  head -n 12 /tmp/fl4sh-python-stdlib.out | sed -E 's/(api[_-]?key|token|secret|password)([=: ]+)[^[:space:]]+/\1\2[REDACTED]/Ig' >&2
  fail "runtime image is missing required Python standard-library modules"
fi

pool='stratum+tcp://pool.example:7048'
mining_id='PRL_WALLET_FOR_IMAGE_SMOKE.worker-1'
FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
  "$ENTRYPOINT" --validate-config > /tmp/fl4sh-config.out 2>&1 ||
  fail "installed entrypoint rejected a valid configuration"
if grep -Fq "$mining_id" /tmp/fl4sh-config.out; then
  fail "installed entrypoint leaked the mining identifier"
fi
if env -u FL4SH_POOL_URL FL4SH_MINING_ID="$mining_id" \
  "$ENTRYPOINT" --validate-config >/tmp/fl4sh-invalid.out 2>&1; then
  fail "installed entrypoint accepted a missing pool URL"
fi
FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
  "$ENTRYPOINT" --check-runtime >/tmp/fl4sh-runtime.out 2>&1 ||
  fail "installed non-mining runtime check failed"
grep -Fq 'miner was not started; CUDA compatibility was not tested' /tmp/fl4sh-runtime.out ||
  fail "installed runtime check exceeded or misreported its scope"
if ! FL4SH_MONITOR_ENABLED=1 \
  FL4SH_MONITOR_GPU_FLOORS_JSON='{"RTX_5080_LAPTOP":110,"RTX_5090_LAPTOP":115,"RTX_5070_TI_LAPTOP":100,"RTX_3090_TI":110}' \
  python3 -B "$MONITOR" --check-config >/tmp/fl4sh-monitor-config.out 2>&1; then
  printf 'Monitor config diagnostic (first 12 lines):\n' >&2
  head -n 12 /tmp/fl4sh-monitor-config.out | sed -E 's/(api[_-]?key|token|secret|password)([=: ]+)[^[:space:]]+/\1\2[REDACTED]/Ig' >&2
  fail "installed monitor rejected its valid offline configuration"
fi
grep -Fq 'floor_registry_entries=6' /tmp/fl4sh-monitor-config.out ||
  fail "installed monitor did not load the autodetected GPU floor registry"
FL4SH_POOL_URL="$pool" FL4SH_MINING_ID="$mining_id" \
  FL4SH_MONITOR_ENABLED=1 FL4SH_MONITOR_PROFILE=RTX_5090_LAPTOP \
  "$ENTRYPOINT" --check-runtime >/tmp/fl4sh-monitor-runtime.out 2>&1 ||
  fail "installed monitor runtime check failed"
grep -Fq 'miner was not started; CUDA compatibility was not tested' /tmp/fl4sh-monitor-runtime.out ||
  fail "opt-in monitor runtime check exceeded or misreported its scope"
if "$HEALTHCHECK" >/dev/null 2>&1; then
  fail "liveness healthcheck unexpectedly passed outside a running miner container"
fi
printf 'image smoke passed: installed hash/ELF/config/monitor/liveness checks; miner and network were not used\n'
