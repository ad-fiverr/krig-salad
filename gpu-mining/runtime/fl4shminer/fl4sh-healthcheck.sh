#!/usr/bin/env bash
set -Eeuo pipefail

[[ -r /proc/1/comm ]] || exit 1
kill -0 1 || exit 1
IFS= read -r process_name < /proc/1/comm || exit 1
container_role="${FL4SH_ROLE:-miner}"

if [[ "$container_role" == central ]]; then
  [[ "${FL4SH_MONITOR_ENABLED:-0}" == 0 ]] || exit 1
  [[ "${FL4SH_TELEGRAM_ENABLED:-0}" == 0 ]] || exit 1
  [[ "$process_name" == python3 && -r /proc/1/cmdline ]] || exit 1
  command_line="$(tr '\0' ' ' < /proc/1/cmdline)" || exit 1
  [[ "$command_line" == *"-m log_alerts.live_cli"* ]] || exit 1
  [[ "$command_line" == *"--watch-live-alerts"* ]] || exit 1
  exit 0
fi

[[ "$container_role" == miner ]] || exit 1

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
    [[ "$child_state" != Z ]] || continue
    command -v python3 >/dev/null 2>&1 || exit 1
    python3 /opt/fl4shminer/fl4sh-runtime-monitor.py \
      --check-readiness --miner-pid "$child" >/dev/null 2>&1 || exit 1
    exit 0
  done
  exit 1
fi

[[ "$process_name" == fl4shminer ]]
