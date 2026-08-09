#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
listen="${TRACELENS_TLS_E2E_LISTEN:-127.0.0.1:18085}"
api_base="http://$listen"
tls_port="${TRACELENS_TLS_E2E_PORT:-18444}"
fixture_dir="$(mktemp -d /tmp/tracelens-tls-e2e.XXXXXX)"
core_pid=''
server_pid=''

cleanup() {
  [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true
  [[ -z "$core_pid" ]] || sudo -n kill "$core_pid" 2>/dev/null || kill "$core_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  wait "$core_pid" 2>/dev/null || true
  rm -rf -- "$fixture_dir"
}
trap cleanup EXIT

pkg-config --exists nss || {
  echo 'NSS development files are required (Debian: libnss3-dev libnspr4-dev)' >&2
  exit 1
}
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
  -keyout "$fixture_dir/key.pem" -out "$fixture_dir/cert.pem" -days 1 >/dev/null 2>&1
cc -O2 -Wall -Wextra "$repo_root/tests/fixtures/nss_http_client.c" \
  -o "$fixture_dir/nssclient" $(pkg-config --cflags --libs nss)

python3 -c 'import socket,ssl,sys
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[1],sys.argv[2])
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",int(sys.argv[3])));s.listen()
while True:
 c,_=s.accept()
 try:
  t=ctx.wrap_socket(c,server_side=True);t.recv(65536);t.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}");t.close()
 except Exception:c.close()' "$fixture_dir/cert.pem" "$fixture_dir/key.pem" "$tls_port" &
server_pid=$!

sudo -n "$repo_root/target/debug/tracelens-core" --observe --api-listen "$listen" \
  --bpf-object-dir "$repo_root/build/bpf/objects" >"$fixture_dir/core.log" 2>&1 &
core_pid=$!
for _ in $(seq 1 50); do
  curl -fsS "$api_base/api/health" >/dev/null 2>&1 && break
  sleep .1
done
curl -fsS "$api_base/api/health" >/dev/null

capture_provider() {
  local process_name="$1"
  local provider="$2"
  shift 2
  curl -fsS -X POST "$api_base/api/capture/stop" >/dev/null
  curl -fsS -X POST "$api_base/api/capture/start" -H 'content-type: application/json' \
    --data "{\"target\":\"process-name:$process_name\",\"profile\":\"web\",\"modules\":[\"process\",\"connections\",\"traffic\",\"dns\",\"tls\",\"http\"]}" >/dev/null
  curl -fsS -X POST "$api_base/api/capture/reset" >/dev/null
  "$@" >/dev/null
  local timeline=''
  for _ in $(seq 1 50); do
    timeline="$(curl -fsS "$api_base/api/timeline?limit=200")"
    if printf '%s' "$timeline" | node -e '
      let input="";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", chunk => input += chunk);
      process.stdin.on("end", () => {
      const page=JSON.parse(input), provider=process.argv[1];
      const http=page.entries.filter(event=>event.kind==="http" && event.tls_provider===provider);
      process.exit(http.some(event=>event.http_direction==="request") && http.some(event=>event.http_direction==="response") ? 0 : 1);
      });
    ' "$provider"; then
      echo "$process_name,$provider,request+response"
      return
    fi
    sleep .2
  done
  echo "$provider HTTP request/response events missing" >&2
  printf '%s' "$timeline" | node -e '
    let input="";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => input += chunk);
    process.stdin.on("end", () => {
      const page=JSON.parse(input);
      console.error(page.entries.filter(event => event.kind === "tls" || event.kind === "http").map(event=>({kind:event.kind,summary:event.summary,provider:event.tls_provider,api:event.tls_api_function})));
    });
  '
  return 1
}

echo 'process,provider,result'
capture_provider curl OpenSSL curl -ksS --http1.1 "https://127.0.0.1:$tls_port/"
capture_provider wget GnuTLS wget -q --no-check-certificate -O /dev/null "https://127.0.0.1:$tls_port/"
capture_provider nssclient NSS "$fixture_dir/nssclient" "$tls_port"
curl -fsS -X POST "$api_base/api/capture/stop" >/dev/null
node -e '
  const h=JSON.parse(process.argv[1]);
  if(h.userspace_provider_instances || h.userspace_reader_count || h.userspace_link_count) throw new Error("userspace detach failed");
' "$(curl -fsS "$api_base/api/health")"
echo 'TLS Provider E2E passed'
