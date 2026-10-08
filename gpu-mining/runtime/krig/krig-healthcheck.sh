#!/usr/bin/env bash
set -Eeuo pipefail

expected=/opt/krig/krig-miner
[[ -x "$expected" ]] || exit 1
[[ -e /proc/1/exe ]] || exit 1
actual="$(readlink -f /proc/1/exe 2>/dev/null || true)"
[[ "$actual" == "$expected" ]] || exit 1
kill -0 1 2>/dev/null
