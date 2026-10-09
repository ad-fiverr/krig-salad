#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT="$SCRIPT_DIR/fl4sh-entrypoint.sh"
HEALTHCHECK="$SCRIPT_DIR/fl4sh-healthcheck.sh"
VERIFIER="$SCRIPT_DIR/verify-artifact.sh"
LOCK="$SCRIPT_DIR/fl4sh-release.lock"

fail() {
  printf 'ci-smoke-test: %s\n' "$*" >&2
  exit 1
}

mode="${1:-}"
[[ "$#" -eq 1 && ( "$mode" == --source || "$mode" == --image ) ]] ||
  fail "usage: $0 --source | --image"

if [[ "$mode" == --source ]]; then
  for script in "$ENTRYPOINT" "$HEALTHCHECK" "$VERIFIER" "$SCRIPT_DIR/ci-smoke-test.sh"; do
    bash -n "$script" || fail "Bash syntax check failed: $(basename "$script")"
  done
  "$VERIFIER" --lock-only

  cuda_base='nvidia/cuda:12.8.2-runtime-ubuntu22.04@sha256:f442e45b864e8e3fcb53764f69a011d494d402812ef4abec104621b508264a91'
  [[ "$(grep -Fc "$cuda_base" "$SCRIPT_DIR/Dockerfile")" -eq 2 ]] ||
    fail "both Docker stages must use the pinned CUDA base"
  ! grep -Eq '^[[:space:]]*EXPOSE[[:space:]]' "$SCRIPT_DIR/Dockerfile" ||
    fail "Dockerfile must not expose a port"
  if grep -Eq 'FL4SH_MINING_ID=.*(PASSWORD|TOKEN|SECRET)|FL4SH_POOL_URL=.*(@|password=)' "$ENTRYPOINT"; then
    fail "entrypoint contains an unsafe credential pattern"
  fi
  python_bin=python3
  if [[ "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == mingw* ]]; then
    python_bin=python
  fi
  command -v "$python_bin" >/dev/null 2>&1 || fail "Python is required for isolated smoke checks"
  if command -v ruby >/dev/null 2>&1; then
    ruby -e 'require "yaml"; doc = YAML.load_file(ARGV.fetch(0)); abort "workflow jobs missing" unless doc.is_a?(Hash) && doc["jobs"].is_a?(Hash)' \
      "$SCRIPT_DIR/../../../.github/workflows/build-fl4shminer.yml"
  else
    "$python_bin" -c 'import sys, yaml; doc = yaml.safe_load(open(sys.argv[1], encoding="utf-8")); assert isinstance(doc, dict) and isinstance(doc.get("jobs"), dict)' \
      "$SCRIPT_DIR/../../../.github/workflows/build-fl4shminer.yml" ||
      fail "workflow YAML could not be parsed (Ruby or Python PyYAML is required)"
  fi

  temporary="$(mktemp -d)"
  trap 'rm -rf -- "$temporary"' EXIT
  mkdir -p "$temporary/bin"
  cat > "$temporary/bin/nvidia-smi" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
  cat > "$temporary/miner-stub" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$FL4SH_TEST_ARGV_FILE"
STUB
  chmod 0555 "$temporary/bin/nvidia-smi" "$temporary/miner-stub"

  "$python_bin" - "$ENTRYPOINT" "$temporary/entrypoint-test.sh" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
needle = "exec /opt/fl4shminer/fl4shminer \\\n"
replacement = 'exec "$FL4SH_TEST_EXECUTABLE" \\\n'
if source.count(needle) != 1:
    raise SystemExit("could not isolate the normal-start command for argument capture")
pathlib.Path(sys.argv[2]).write_text(source.replace(needle, replacement), newline="\n")
PY
  chmod 0555 "$temporary/entrypoint-test.sh"

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
  printf 'source smoke passed: lock, scripts, workflow YAML, config rejection/redaction, and captured argv\n'
  exit 0
fi

"$VERIFIER" --lock-only
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
  for package in curl wget gcc g++ build-essential python3 nvidia-smi; do
    status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)"
    [[ "$status" != 'install ok installed' ]] || fail "runtime image unexpectedly contains $package"
  done
  driver_packages="$(dpkg-query -W -f='${Package} ${Status}\n' 2>/dev/null |
    awk '$2 == "install" && $3 == "ok" && $4 == "installed" && $1 ~ /^nvidia-(driver|utils|kernel|dkms)/ {print $1}')"
  [[ -z "$driver_packages" ]] || fail "runtime image contains host driver packages: $driver_packages"
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
if "$HEALTHCHECK" >/dev/null 2>&1; then
  fail "liveness healthcheck unexpectedly passed outside a running miner container"
fi
printf 'image smoke passed: installed hash/ELF/config/liveness checks; miner and network were not used\n'
