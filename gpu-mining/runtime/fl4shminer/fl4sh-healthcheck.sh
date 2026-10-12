#!/usr/bin/env bash
set -Eeuo pipefail

[[ -r /proc/1/comm ]] || exit 1
kill -0 1 || exit 1
IFS= read -r process_name < /proc/1/comm || exit 1

if [[ "${FL4SH_MONITOR_ENABLED:-0}" == 1 ]]; then
  [[ "$process_name" == python3 && -r /proc/1/cmdline ]] || exit 1
  tr '\0' ' ' < /proc/1/cmdline | grep -Fq '/opt/fl4shminer/fl4sh-runtime-monitor.py' || exit 1
  [[ -r /proc/1/task/1/children ]] || exit 1
  child_pids="$(cat /proc/1/task/1/children 2>/dev/null)" || exit 1
  for child in $child_pids; do
    kill -0 "$child" 2>/dev/null || continue
    [[ -r "/proc/$child/comm" ]] || continue
    IFS= read -r child_name < "/proc/$child/comm" || continue
    [[ "$child_name" == fl4shminer ]] || continue
    [[ -r "/proc/$child/stat" ]] || continue
    IFS=' ' read -r _ _ child_state _ < "/proc/$child/stat" || continue
    [[ "$child_state" != Z ]] && exit 0
  done
  exit 1
fi

[[ "$process_name" == fl4shminer ]]
