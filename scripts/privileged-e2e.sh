#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
listen="${TRACELENS_E2E_LISTEN:-127.0.0.1:18082}"
api_base="http://$listen"
core="$repo_root/target/debug/tracelens-core"
object_dir="$repo_root/build/bpf/objects"
log_file="$(mktemp)"
launcher_pid=''

cleanup() {
  if [[ -n "$launcher_pid" ]]; then
    sudo -n kill "$launcher_pid" 2>/dev/null || kill "$launcher_pid" 2>/dev/null || true
    wait "$launcher_pid" 2>/dev/null || true
  fi
  rm -f "$log_file"
}
trap cleanup EXIT

sudo -n "$core" --observe --api-listen "$listen" --bpf-object-dir "$object_dir" >"$log_file" 2>&1 &
launcher_pid=$!
for _ in $(seq 1 50); do
  if curl -fsS "$api_base/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -fsS "$api_base/api/health" >/dev/null || {
  cat "$log_file" >&2
  exit 1
}

health="$(curl -fsS "$api_base/api/health")"
node -e '
  const h = JSON.parse(process.argv[1]);
  if (h.kernel_link_count !== 0 || h.userspace_link_count !== 0) process.exit(1);
' "$health"

curl -fsS -X POST "$api_base/api/capture/start" \
  -H 'Content-Type: application/json' \
  --data '{"target":"process-name:curl","profile":"web","modules":["process","connections","traffic","dns","tls","http"]}' >/dev/null
curl -fsS --http1.1 --max-time 8 https://example.com/ >/dev/null

for _ in $(seq 1 30); do
  timeline="$(curl -fsS "$api_base/api/timeline?limit=200")"
  if node -e '
    const page = JSON.parse(process.argv[1]);
    process.exit(page.entries.some(event => event.kind === "http") ? 0 : 1);
  ' "$timeline"; then
    break
  fi
  sleep 0.1
done

health="$(curl -fsS "$api_base/api/health")"
timeline="$(curl -fsS "$api_base/api/timeline?limit=200")"
node -e '
  const health = JSON.parse(process.argv[1]);
  const page = JSON.parse(process.argv[2]);
  if (health.kernel_link_count !== 18) throw new Error("Web profile must use 18 kernel links");
  if (health.userspace_provider_instances < 1) throw new Error("expected at least one userspace provider");
  if (health.userspace_reader_count !== health.userspace_provider_instances) throw new Error("each userspace provider needs one reader");
  if (health.userspace_link_count < 12) throw new Error("expected modern OpenSSL hooks");
  if (!page.entries.some(event => event.kind === "http")) throw new Error("HTTP event missing");
  const names = [...new Set(page.entries.map(event => event.process_name).filter(Boolean))];
  if (names.some(name => name !== "curl")) throw new Error(`scope leak: ${names.join(",")}`);
' "$health" "$timeline"

core_pid="$(pgrep -n -f "$core --observe --api-listen $listen" || true)"
"$repo_root/scripts/profile-matrix.sh" "$api_base" "$core_pid"

curl -fsS -X POST "$api_base/api/capture/stop" >/dev/null
health="$(curl -fsS "$api_base/api/health")"
node -e '
  const h = JSON.parse(process.argv[1]);
  if (h.kernel_link_count !== 0 || h.kernel_objects.length !== 0) throw new Error("kernel detach failed");
  if (h.userspace_provider_instances !== 0 || h.userspace_reader_count !== 0 || h.userspace_link_count !== 0) throw new Error("userspace detach failed");
  console.log("privileged E2E passed: payload, scope, profile matrix, and detach verified");
' "$health"
