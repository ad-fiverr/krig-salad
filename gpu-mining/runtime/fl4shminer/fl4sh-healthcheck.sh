#!/usr/bin/env bash
set -Eeuo pipefail

[[ -r /proc/1/comm ]] || exit 1
IFS= read -r process_name < /proc/1/comm || exit 1
[[ "$process_name" == fl4shminer ]] || exit 1
kill -0 1
