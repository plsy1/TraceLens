# TraceLens

TraceLens is a process-aware network security observability tool built around
eBPF and bpftime. It starts with low-overhead metadata collection and can
escalate selected processes or connections into deeper userspace inspection.

## Repository status

The repository now contains the Phase 1 application skeleton and the first
Phase 2/3 process/connection event path:

```text
core/           Rust composition root and runtime boundaries
crates/events/  shared serialized event model
bpf/            CMake/eBPF probe boundary (kernel/userspace)
ui/             Vite/React + Tauri desktop shell
config/         example configuration
docs/           product and engineering documentation
```

The process and connect/close probes now emit metadata through BPF ring buffers;
the Core loader decodes them into process and connection read models and serves
a small read-only local API. DNS, byte counters, userspace TLS probes, and
detection rules are still placeholders.

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
cargo test --workspace
```

Configure and compile the probe layer:

```bash
cmake -S . -B build -DTRACELENS_BUILD_BPF=ON
cmake --build build
```

Run the real Phase 2/3 observer (root or equivalent BPF capabilities are
required):

```bash
cargo build -p tracelens-core
sudo ./target/debug/tracelens-core --observe --api-listen 127.0.0.1:8080
```

The API exposes /api/health, /api/summary, /api/processes, and
/api/connections. Start the UI separately with npm run dev; it polls the Core
API and falls back to clearly labelled demo data when Core is offline.

Run the frontend:

```bash
cd ui
npm install
npm run dev
```

## Next implementation slice

The next vertical slice is DNS correlation: connect the observed process and
connection to DNS query/response events so the dashboard can show a domain
instead of only an IP. Byte counters and richer connection state tracking will
follow that metadata path.
