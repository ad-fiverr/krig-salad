#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LOCK_FILE="${SCRIPT_DIR}/krig-release.lock"

fail() {
  printf 'verify-artifact: %s\n' "$*" >&2
  exit 1
}

[[ -f "$LOCK_FILE" ]] || fail "missing lock file: ${LOCK_FILE}"

declare -A lock=()
while IFS='=' read -r key value || [[ -n "${key:-}${value:-}" ]]; do
  [[ -z "${key:-}" || "$key" == \#* ]] && continue
  [[ "$key" =~ ^[A-Z0-9_]+$ ]] || fail "invalid lock key"
  [[ -n "${value:-}" && "$value" != *[$'\t\r\n ']* ]] || fail "invalid value for ${key}"
  [[ -z "${lock[$key]+present}" ]] || fail "duplicate key: ${key}"
  lock["$key"]="$value"
done < "$LOCK_FILE"

required_keys=(
  FORMAT_VERSION KRIG_VERSION KRIG_RELEASE_TAG KRIG_RELEASE_REVISION
  KRIG_ASSET_NAME KRIG_ASSET_URL KRIG_ARCHIVE_TYPE KRIG_ASSET_SIZE_BYTES
  KRIG_ASSET_SHA256 KRIG_ASSET_SHA256_PROVENANCE
  KRIG_BINARY_SHA256 KRIG_BINARY_SHA256_PROVENANCE
)
[[ "${#lock[@]}" -eq "${#required_keys[@]}" ]] || fail "unexpected lock schema"
for key in "${required_keys[@]}"; do
  [[ -n "${lock[$key]:-}" ]] || fail "missing lock key: ${key}"
done

[[ "${lock[FORMAT_VERSION]}" == 1 ]] || fail "unsupported lock format"
[[ "${lock[KRIG_VERSION]}" == 1.5.6 ]] || fail "this image is pinned to KRig v1.5.6"
[[ "${lock[KRIG_RELEASE_TAG]}" == "v${lock[KRIG_VERSION]}" ]] || fail "release tag does not match version"
[[ "${lock[KRIG_RELEASE_REVISION]}" == 259a2a064b28dcf7d0f1921dcdb2c3f608242567 ]] || fail "unexpected release revision"
[[ "${lock[KRIG_ARCHIVE_TYPE]}" == tar.gz ]] || fail "unsupported archive type"
expected_asset="krig-miner-${lock[KRIG_VERSION]}-linux-x64.tar.gz"
expected_url="https://github.com/kryptex/krig-miner/releases/download/${lock[KRIG_RELEASE_TAG]}/${expected_asset}"
[[ "${lock[KRIG_ASSET_NAME]}" == "$expected_asset" ]] || fail "asset name does not match version"
[[ "${lock[KRIG_ASSET_URL]}" == "$expected_url" ]] || fail "asset URL is not the official pinned release URL"
[[ "${lock[KRIG_ASSET_SIZE_BYTES]}" =~ ^[1-9][0-9]*$ ]] || fail "invalid asset size"
[[ "${lock[KRIG_ASSET_SHA256]}" =~ ^[0-9a-f]{64}$ ]] || fail "invalid archive SHA-256"
[[ "${lock[KRIG_ASSET_SHA256_PROVENANCE]}" == UPSTREAM_PUBLISHED ]] || fail "archive SHA-256 provenance must be UPSTREAM_PUBLISHED"
[[ "${lock[KRIG_BINARY_SHA256]}" =~ ^[0-9a-f]{64}$ ]] || fail "invalid executable SHA-256"
[[ "${lock[KRIG_BINARY_SHA256_PROVENANCE]}" == LOCALLY_FROZEN_AUDIT ]] || fail "binary SHA-256 provenance must be LOCALLY_FROZEN_AUDIT"

verify_and_extract() {
  local archive="$1"
  local output_dir="$2"
  local actual_size actual_hash listing entry saw_binary=0 saw_wrapper=0 tmp binary file_description
  local dynamic_output needed_libraries interpreter_output interpreter ldconfig_output library resolved_path

  [[ -f "$archive" ]] || fail "archive does not exist"
  actual_size="$(wc -c < "$archive" | tr -d '[:space:]')"
  [[ "$actual_size" == "${lock[KRIG_ASSET_SIZE_BYTES]}" ]] || fail "archive size mismatch"
  actual_hash="$(sha256sum "$archive" | awk '{print $1}')"
  [[ "$actual_hash" == "${lock[KRIG_ASSET_SHA256]}" ]] || fail "archive SHA-256 mismatch"

  listing="$(tar -tzf "$archive")" || fail "archive is not a readable gzip tar file"
  while IFS= read -r entry; do
    case "$entry" in
      krig-miner) (( saw_binary == 0 )) || fail "duplicate executable in archive"; saw_binary=1 ;;
      mine-pearl.sh) (( saw_wrapper == 0 )) || fail "duplicate wrapper in archive"; saw_wrapper=1 ;;
      *) fail "unexpected archive path: ${entry}" ;;
    esac
  done <<< "$listing"
  (( saw_binary == 1 && saw_wrapper == 1 )) || fail "archive contents do not match the pinned release"

  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' RETURN
  tar -xzf "$archive" -C "$tmp" -- krig-miner || fail "could not extract the miner executable"
  binary="${tmp}/krig-miner"
  [[ -f "$binary" && ! -L "$binary" ]] || fail "extracted executable is not a regular file"
  actual_hash="$(sha256sum "$binary" | awk '{print $1}')"
  [[ "$actual_hash" == "${lock[KRIG_BINARY_SHA256]}" ]] || fail "executable SHA-256 mismatch"

  file_description="$(file -b "$binary")"
  [[ "$file_description" == *"ELF 64-bit"* && "$file_description" == *"x86-64"* ]] || fail "executable is not Linux x86-64 ELF"
  readelf -h "$binary" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' || fail "unexpected ELF machine"
  dynamic_output="$(readelf -d "$binary" 2>&1)" || fail "static ELF dynamic-section inspection failed"
  needed_libraries="$(printf '%s\n' "$dynamic_output" | sed -nE 's/.*\(NEEDED\).*Shared library: \[([^]]+)\].*/\1/p')"
  [[ -n "$needed_libraries" ]] || fail "readelf did not report any DT_NEEDED libraries"
  interpreter_output="$(readelf -l "$binary" 2>&1)" || fail "static ELF program-header inspection failed"
  interpreter="$(printf '%s\n' "$interpreter_output" | sed -nE 's/.*Requesting program interpreter: ([^]]+)\].*/\1/p' | head -n 1)"
  [[ -n "$interpreter" && -x "$interpreter" ]] || fail "ELF program interpreter is missing from the pinned runtime base"
  ldconfig_output="$(ldconfig -p 2>&1)" || fail "runtime library cache inspection failed"
  while IFS= read -r library; do
    [[ -n "$library" ]] || continue
    [[ "$library" =~ ^[A-Za-z0-9._+-]+$ ]] || fail "unexpected DT_NEEDED soname"
    resolved_path="$(printf '%s\n' "$ldconfig_output" | awk -v soname="$library" '$1 == soname && /x86-64/ { print $NF; exit }')"
    [[ -n "$resolved_path" && -e "$resolved_path" ]] || fail "DT_NEEDED library is missing from the pinned runtime base: ${library}"
  done <<< "$needed_libraries"
  printf 'static ELF dependencies resolved in pinned runtime base: %s\n' "$(tr '\n' ' ' <<< "$needed_libraries")"

  install -d -m 0755 "$output_dir"
  install -m 0555 "$binary" "${output_dir}/krig-miner"
  printf 'verified KRig v%s: linux/amd64 asset and executable hashes match\n' "${lock[KRIG_VERSION]}"
}

verify_installed() {
  local binary="${SCRIPT_DIR}/krig-miner" actual_hash elf_magic elf_data elf_machine
  [[ -f "$binary" && -x "$binary" && ! -L "$binary" ]] || fail "installed KRig executable is missing or not executable"
  actual_hash="$(sha256sum "$binary" | awk '{print $1}')"
  [[ "$actual_hash" == "${lock[KRIG_BINARY_SHA256]}" ]] || fail "installed executable SHA-256 does not match the lock"
  elf_magic="$(od -An -N4 -tx1 "$binary" | tr -d '[:space:]')"
  elf_data="$(od -An -j5 -N1 -tx1 "$binary" | tr -d '[:space:]')"
  elf_machine="$(od -An -j18 -N2 -tx1 "$binary" | tr -d '[:space:]')"
  [[ "$elf_magic" == 7f454c46 && "$elf_data" == 01 && "$elf_machine" == 3e00 ]] ||
    fail "installed executable is not a little-endian ELF64 x86-64 binary"
  printf 'installed KRig matches locked SHA-256 and ELF x86-64 metadata\n'
}

case "${1:-}" in
  --lock-only)
    [[ "$#" -eq 1 ]] || fail "usage: $0 --lock-only"
    printf 'lock valid: KRig %s at %s, linux/amd64 %s; archive SHA=%s; binary SHA=%s\n' \
      "${lock[KRIG_RELEASE_TAG]}" "${lock[KRIG_RELEASE_REVISION]}" "${lock[KRIG_ARCHIVE_TYPE]}" \
      "${lock[KRIG_ASSET_SHA256_PROVENANCE]}" "${lock[KRIG_BINARY_SHA256_PROVENANCE]}"
    ;;
  --installed)
    [[ "$#" -eq 1 ]] || fail "usage: $0 --installed"
    verify_installed
    ;;
  --artifact)
    [[ "$#" -eq 3 ]] || fail "usage: $0 --artifact ARCHIVE OUTPUT_DIR"
    verify_and_extract "$2" "$3"
    ;;
  --download-and-verify)
    [[ "$#" -eq 2 ]] || fail "usage: $0 --download-and-verify OUTPUT_DIR"
    command -v curl >/dev/null 2>&1 || fail "curl is required"
    download_dir="$(mktemp -d)"
    trap 'rm -rf -- "$download_dir"' EXIT
    archive="${download_dir}/${lock[KRIG_ASSET_NAME]}"
    curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
      --retry 3 --connect-timeout 20 --max-time 300 \
      "${lock[KRIG_ASSET_URL]}" --output "$archive" || fail "official release download failed"
    verify_and_extract "$archive" "$2"
    ;;
  *)
    fail "usage: $0 --lock-only | --installed | --artifact ARCHIVE OUTPUT_DIR | --download-and-verify OUTPUT_DIR"
    ;;
esac
