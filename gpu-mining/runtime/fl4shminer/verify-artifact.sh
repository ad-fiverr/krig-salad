#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOCK_FILE="${FL4SH_LOCK_FILE:-$SCRIPT_DIR/fl4sh-release.lock}"

fail() {
  printf 'verify-artifact: %s\n' "$*" >&2
  exit 1
}

declare -A LOCK=()
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || fail "invalid lock line"
  key="${line%%=*}"
  value="${line#*=}"
  [[ "$key" =~ ^[a-z][a-z0-9_]*$ && -n "$value" && "$value" != *=* ]] ||
    fail "invalid lock key/value"
  [[ -z "${LOCK[$key]+present}" ]] || fail "duplicate lock key: $key"
  LOCK["$key"]="$value"
done < "$LOCK_FILE"

required_keys=(
  schema_version release_version target_platform asset_url asset_bytes
  asset_sha256 asset_sha256_provenance executable_path executable_sha256
  executable_sha256_provenance
)
[[ "${#LOCK[@]}" -eq "${#required_keys[@]}" ]] || fail "lock schema has missing or unknown fields"
for key in "${required_keys[@]}"; do
  [[ -n "${LOCK[$key]+present}" ]] || fail "lock schema is missing $key"
done

[[ "${LOCK[schema_version]}" == 1 ]] || fail "unsupported lock schema"
[[ "${LOCK[release_version]}" == 1.5.2 ]] || fail "unexpected Fl4shMiner version"
[[ "${LOCK[target_platform]}" == linux/amd64 ]] || fail "unexpected target platform"
[[ "${LOCK[asset_url]}" == https://github.com/Fl4sh9174/Fl4shMiner/releases/download/v1.5.2/fl4shminer-v1.5.2.tar.gz ]] ||
  fail "asset URL does not match the pinned release"
[[ "${LOCK[asset_bytes]}" =~ ^[0-9]+$ && "${LOCK[asset_bytes]}" == 53173385 ]] ||
  fail "asset size does not match the pinned release"
[[ "${LOCK[asset_sha256]}" =~ ^[0-9a-f]{64}$ &&
   "${LOCK[asset_sha256]}" == 105bf6e799adcc6a2a814b8a3ce1549696fe20a931cb9676bc363367280c4052 ]] ||
  fail "asset digest does not match the pinned release"
[[ "${LOCK[asset_sha256_provenance]}" == UPSTREAM_PUBLISHED ]] ||
  fail "unexpected archive digest provenance"
[[ "${LOCK[executable_path]}" == fl4shminer/fl4shminer ]] ||
  fail "unexpected executable path"
[[ "${LOCK[executable_sha256]}" =~ ^[0-9a-f]{64}$ &&
   "${LOCK[executable_sha256]}" == 18eb1c096770c9f7614be2690172ff6418fdf1755b6c5b07e481ac15f3d85f58 ]] ||
  fail "executable digest does not match the locally frozen audit"
[[ "${LOCK[executable_sha256_provenance]}" == LOCALLY_FROZEN_AUDIT ]] ||
  fail "unexpected executable digest provenance"

if [[ "$#" -eq 1 && "$1" == --lock-only ]]; then
  printf 'release lock valid: Fl4shMiner %s (%s)\n' \
    "${LOCK[release_version]}" "${LOCK[target_platform]}"
  exit 0
fi

if [[ "$#" -eq 2 && "$1" == --download-and-verify ]]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required for download verification"
  work_dir="$(mktemp -d)"
  trap 'rm -rf -- "$work_dir"' EXIT
  archive="$work_dir/fl4shminer.tar.gz"
  curl --fail --location --retry 3 --retry-delay 2 \
    --output "$archive" "${LOCK[asset_url]}"
  set -- --verify-archive "$archive" "$2"
fi

if [[ "$#" -ne 3 || "$1" != --verify-archive ]]; then
  fail "usage: $0 --lock-only | --verify-archive ARCHIVE DESTINATION | --download-and-verify DESTINATION"
fi

archive="$2"
destination="$3"
[[ -f "$archive" && ! -L "$archive" ]] || fail "archive must be a regular file"
actual_bytes="$(wc -c < "$archive" | tr -d '[:space:]')"
[[ "$actual_bytes" == "${LOCK[asset_bytes]}" ]] || fail "archive byte count mismatch"
actual_sha="$(sha256sum "$archive" | awk '{print $1}')"
[[ "$actual_sha" == "${LOCK[asset_sha256]}" ]] || fail "archive SHA-256 mismatch"

command -v python3 >/dev/null 2>&1 || fail "python3 is required for safe archive extraction"
python3 - "$archive" "$destination" "${LOCK[executable_path]}" <<'PY'
import pathlib
import shutil
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected_path = sys.argv[3]
expected_parts = pathlib.PurePosixPath(expected_path).parts
if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
    raise SystemExit("destination must be a real directory")
destination.mkdir(parents=True, exist_ok=True)
output = destination / expected_parts[-1]
if output.exists() or output.is_symlink():
    raise SystemExit("refusing to overwrite an existing executable")

try:
    with tarfile.open(archive_path, mode="r:gz") as bundle:
        normalized_members = {}
        target = None
        for member in bundle.getmembers():
            name = member.name
            while name.startswith("./"):
                name = name[2:]
            if not name or name.startswith("/") or "\\" in name or "\x00" in name:
                raise SystemExit("archive contains an unsafe member path")
            parts = pathlib.PurePosixPath(name).parts
            if any(part in ("", ".", "..") for part in parts):
                raise SystemExit("archive member escapes its extraction root")
            normalized = "/".join(parts)
            if normalized in normalized_members:
                if member.isdir() and normalized_members[normalized].isdir():
                    continue
                raise SystemExit(f"archive contains a duplicate member path: {name!r}")
            if not (member.isdir() or member.isfile()):
                raise SystemExit("archive contains a link or special file")
            normalized_members[normalized] = member
            if normalized == expected_path:
                if not member.isfile():
                    raise SystemExit("locked executable is not a regular file")
                target = member
        if target is None:
            raise SystemExit("locked executable is missing from archive")
        source = bundle.extractfile(target)
        if source is None:
            raise SystemExit("unable to read locked executable")
        with source, output.open("xb") as sink:
            shutil.copyfileobj(source, sink)
except (tarfile.TarError, OSError, ValueError) as exc:
    raise SystemExit(f"archive validation or extraction failed: {exc}")
output.chmod(0o555)
PY

executable="$destination/${LOCK[executable_path]##*/}"
[[ -f "$executable" && ! -L "$executable" && -x "$executable" ]] ||
  fail "extracted executable is missing or not executable"
actual_executable_sha="$(sha256sum "$executable" | awk '{print $1}')"
[[ "$actual_executable_sha" == "${LOCK[executable_sha256]}" ]] ||
  fail "executable SHA-256 mismatch"

command -v file >/dev/null 2>&1 || fail "file is required for ELF validation"
command -v readelf >/dev/null 2>&1 || fail "readelf is required for ELF validation"
file_description="$(file -b "$executable")"
[[ "$file_description" =~ ^ELF[[:space:]]64-bit[[:space:]]LSB.*x86-64 ]] ||
  fail "artifact is not a Linux ELF64 x86-64 executable"
elf_header="$(readelf -hW "$executable")"
grep -Eq 'Class:[[:space:]]+ELF64' <<< "$elf_header" || fail "ELF class is not 64-bit"
grep -Eq 'Data:.*little endian' <<< "$elf_header" || fail "ELF byte order is not little endian"
grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' <<< "$elf_header" ||
  fail "ELF machine is not x86-64"
printf 'artifact verified: %s (%s)\n' "${LOCK[release_version]}" "$actual_executable_sha"
