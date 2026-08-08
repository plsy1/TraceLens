# TraceLens

TraceLens is a Linux process-aware network observation tool built on eBPF.
It is designed as a capture utility: the observer starts idle, you select a
process or scope, choose an observation level, start a capture, inspect the
traffic, and stop or reset the session when finished.

## What it does

- Collects process lifecycle, socket/TCP, byte-counter, and DNS metadata from
  kernel probes.
- Correlates processes, connections, DNS names, TLS sessions, and HTTP
  messages into one local event model.
- Uses optional userspace OpenSSL probes for TLS metadata, bounded HTTP/1.1
  inspection, and bounded plaintext inspection.
- Provides a local HTTP API and a Web UI with process, connection, session,
  and event views.
- Keeps capture data in memory by default. SQLite history is opt-in.

Payload capture is intentionally bounded. Small textual HTTP bodies such as
HTML, JSON, XML, JavaScript, and CSS can be previewed; large, binary, media,
archive, or compressed content is represented by metadata and byte counts.

## Observation levels

| Level | Collected data |
| --- | --- |
| L1 | Process, network, TCP, and DNS metadata; no payload bytes |
| L2 | Reserved for additional probe capabilities |
| L3 | L1 data plus TLS metadata such as SNI, version, SSL object, and fd correlation |
| L4 | L3 data plus parsed HTTP/1.1 metadata and bounded small-text previews |
| L5 | L4 data plus bounded raw plaintext previews from selected userspace targets |

The global level is the baseline for all processes. A PID or process-name
capture can apply a target-specific level. L4 uses bounded plaintext capture
internally to reconstruct HTTP, but raw plaintext fragments are only exposed
at L5.

## Architecture

```text
core/           Rust service, observation manager, correlation, API, and runtime
crates/events/  Shared serialized event model
bpf/            C/eBPF kernel and userspace probes
ui/             Vite/React Web UI and Tauri shell
tests/          Integration tests and API contract coverage
docs/           Architecture, deployment, and development notes
scripts/        Build and development helpers
```

The kernel runtime emits events through BPF ring buffers. The Rust `core`
process decodes and correlates them, maintains bounded in-memory read models,
and serves the local API. Userspace probes are loaded through bpftime when
available, with a kernel-uProbe fallback on Linux.

## Prerequisites

- Linux x86_64
- Rust stable and Cargo
- Clang, CMake, libbpf headers, and Linux kernel headers
- Node.js and npm for the Web UI
- Tauri 2 system dependencies when building the desktop shell

## Run the observer

Build the probe layer:

```bash
cmake -S . -B build -DTRACELENS_BUILD_BPF=ON
cmake --build build
```

Build and start `core`:

```bash
cargo build -p tracelens-core
sudo ./target/debug/tracelens-core --observe --api-listen 0.0.0.0:8080
```

Root or equivalent BPF capabilities are required for live observation. The
observer starts idle and does not collect events until a capture is started.

## Use the Web UI

Start the development server in another terminal:

```bash
cd ui
npm install
npm run dev -- --host 0.0.0.0
```

Open the URL printed by Vite from another machine. In the capture console:

1. Select `Selected PID`, `Process name`, or `Global`.
2. Enter a PID or process name when needed.
3. Select L1-L5.
4. Press `Start capture`.
5. Generate traffic, inspect the active workspace, then press `Stop`.
6. Press `Reset` to discard the in-memory session and start a fresh capture.

The capture workspace shows one view at a time: Connections, Processes,
Sessions, or Raw events. Tables support sorting, pagination, and draggable
column widths. Payload details open in a bounded modal instead of loading
large files into the browser.

## Local API

The default API address is `127.0.0.1:8080`. Useful endpoints include:

```text
GET  /api/health
GET  /api/summary
GET  /api/process-candidates
GET  /api/processes
GET  /api/connections
GET  /api/timeline
GET  /api/connection-timeline
GET  /api/alerts
GET  /api/observations
GET  /api/observations/default
POST /api/capture/start
POST /api/capture/stop
POST /api/capture/reset
POST /api/observations
POST /api/observations/default
```

Capture commands accept a target of `global`, `process:<pid>`, or
`process-name:<name>`. The API is intended for local tooling and does not
provide authentication or remote multi-user access.

## Storage

Memory storage is the default and is appropriate for short-lived captures.
Use SQLite only when durable history is needed:

```bash
sudo ./target/debug/tracelens-core \
  --observe \
  --storage sqlite \
  --database ./tracelens.db \
  --api-listen 0.0.0.0:8080
```

`Reset` clears the current capture state. In memory mode, stopping the
capture keeps its data available for inspection until it is reset or the
process exits.

## Development

Run the core smoke command:

```bash
cargo run -p tracelens-core -- --print-example-event
```

The Rust workspace is organized around `core/src/` and the shared event model
in `crates/events/`. Probe sources live under `bpf/`; the Web UI is under
`ui/src/`; integration coverage is under `tests/integration/`.

## Validation

Run the repository checks before submitting changes:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cd ui && npm run build
```

More detailed engineering notes are available in
[`docs/architecture.md`](docs/architecture.md),
[`docs/deployment.md`](docs/deployment.md), and
[`docs/development_workflow.md`](docs/development_workflow.md).
