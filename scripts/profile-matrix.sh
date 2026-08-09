#!/usr/bin/env bash
set -euo pipefail

api_base="${1:-http://127.0.0.1:18082}"
core_pid="${2:-}"
clock_ticks="$(getconf CLK_TCK)"

profiles=(
  'process|process|process'
  'connections|connections|process,connections'
  'network|network|process,connections,traffic,dns'
  'web|web|process,connections,traffic,dns,tls,http'
  'security|security|process,connections,traffic,dns,files,tls'
  'custom-files|custom|files'
)

cpu_ticks() {
  if [[ -n "$core_pid" && -r "/proc/$core_pid/stat" ]]; then
    awk '{print $14 + $15}' "/proc/$core_pid/stat"
  else
    echo 0
  fi
}

echo 'profile,attach_ms,kernel_links,kernel_objects,userspace_providers,userspace_readers,userspace_links,core_cpu_percent'
for row in "${profiles[@]}"; do
  IFS='|' read -r label profile modules <<<"$row"
  curl -fsS -X POST "$api_base/api/capture/stop" >/dev/null
  started_ns="$(date +%s%N)"
  curl -fsS -X POST "$api_base/api/capture/start" \
    -H 'Content-Type: application/json' \
    --data "{\"target\":\"global\",\"profile\":\"$profile\",\"modules\":[$(printf '"%s"' "${modules//,/\",\"}")]}" >/dev/null
  attached_ns="$(date +%s%N)"
  ticks_before="$(cpu_ticks)"
  sample_before="$(date +%s%N)"
  for _ in $(seq 1 50); do
    curl -fsS "$api_base/api/health" >/dev/null
  done
  if [[ "$label" == web ]]; then
    curl -fsS --http1.1 --max-time 8 https://example.com/ >/dev/null || true
  fi
  sleep 1
  ticks_after="$(cpu_ticks)"
  sample_after="$(date +%s%N)"
  health="$(curl -fsS "$api_base/api/health")"
  node -e '
    const health = JSON.parse(process.argv[1]);
    const attachMs = (Number(process.argv[4]) - Number(process.argv[3])) / 1e6;
    const ticks = Number(process.argv[6]) - Number(process.argv[5]);
    const seconds = (Number(process.argv[8]) - Number(process.argv[7])) / 1e9;
    const cpu = seconds > 0 ? ticks / Number(process.argv[9]) / seconds * 100 : 0;
    console.log([
      process.argv[2], attachMs.toFixed(2), health.kernel_link_count,
      health.kernel_objects.length, health.userspace_provider_instances,
      health.userspace_reader_count, health.userspace_link_count, cpu.toFixed(2),
    ].join(","));
  ' "$health" "$label" "$started_ns" "$attached_ns" "$ticks_before" "$ticks_after" "$sample_before" "$sample_after" "$clock_ticks"
done
curl -fsS -X POST "$api_base/api/capture/stop" >/dev/null
