# TraceLens

TraceLens is a process-aware network security observability tool built around
eBPF and bpftime. It starts with low-overhead metadata collection and can
escalate selected processes or connections into deeper userspace inspection.

## Repository status

The repository now contains the Phase 1 application skeleton plus the real
Phase 2-12 process, connection, DNS, inspection, detection, and behavior graph
paths:

```text
core/           Rust composition root and runtime boundaries
crates/events/  shared serialized event model
bpf/            CMake/eBPF probe boundary (kernel/userspace)
ui/             Vite/React + Tauri desktop shell
config/         example configuration
docs/           product and engineering documentation
```

The process, TCP state/byte, and DNS probes emit metadata through BPF ring
buffers; the Core loader decodes them into process, connection, DNS, and
timeline read models and serves a local API. Recent events stay in a bounded
in-memory store by default; SQLite history is opt-in. Connection activity is
grouped into session cards, and Observation Manager controls L1-L5 Probe
dependencies. The Phase 7 runtime adapter now includes a real `bpftime trace`
loader path (`tracelens-bpftime-loader`) and a libbpf-backed kernel-uProbe
path. It resolves the target process ELF and loaded libssl mapping, keeps real
link/process handles for detach, and reports attach failures through
`/api/health`. Phase 8 adds OpenSSL TLS metadata events through the userspace
ring buffer: SNI, negotiated version, SSL object/fd, and connection correlation
are visible in Timeline and connection sessions. Phase 9 adds on-demand L5
`SSL_read`/`SSL_write` capture: each plaintext event is capped at 512 bytes,
keeps its original byte count/truncation flag, and is correlated through the
SSL object into the connection Timeline. L1-L3 never collect payload bytes.
Phase 10 adds a bounded L4 HTTP capture path for OpenSSL traffic: Core
reassembles HTTP/1.1 requests and responses, exposes method/host/path/status/
headers as metadata, and drops the raw L4 capture after parsing. L5 continues
to expose the separate bounded plaintext stream. Phase 11 adds an in-memory
rule engine for beacon, scan, lateral movement, suspicious upload, first-seen
domain, and sensitive-file correlation alerts. Phase 12 adds a derived
`/api/graph` behavior graph for processes, connections, domains, and retained
sensitive-file events. Alert and graph state are runtime-only by default.

## Prerequisites

- Linux x86_64 for the first runtime milestone
- Rust stable and Cargo
- Clang, CMake, libbpf headers, and Linux kernel headers for eBPF builds
- Node.js/npm for the UI
- Tauri 2 system dependencies for the desktop shell

## Quick start

Run the core skeleton:

```bash
cargo run -p tracelens-core -- --print-example-event
```

Check the Rust workspace:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
```

Configure and compile the probe layer:

```bash
cmake -S . -B build -DTRACELENS_BUILD_BPF=ON
cmake --build build
```

Run the real Phase 2/3/4 observer (root or equivalent BPF capabilities are
required):

```bash
cargo build -p tracelens-core
sudo ./target/debug/tracelens-core --observe --api-listen 127.0.0.1:8080
```

The API exposes /api/health, /api/summary, /api/processes, /api/connections,
`/api/timeline`, `/api/connection-timeline`, `/api/alerts`, and `/api/graph`.
The UI loads connection
session summaries first and fetches up to 200 child events only when a session
is expanded; it hides closed connections by default and falls back to clearly
labelled demo data when Core is offline.

Run the frontend:

```bash
cd ui
npm install
npm run dev
```

## Current implementation slice

The observer now correlates process snapshots, TCP byte counters, richer TCP
states, DNS query/response answers, and resolver-backed domain mappings. The
current slice includes connection-oriented Timeline UX, optional durable
history, TLS metadata inspection, bounded L4 HTTP metadata inspection, bounded
L5 plaintext inspection, and the real userspace runtime loading boundary.
