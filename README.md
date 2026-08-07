# TraceLens

TraceLens is a process-aware network security observability tool built around
eBPF and bpftime. It starts with low-overhead metadata collection and can
escalate selected processes or connections into deeper userspace inspection.

## Repository status

The repository now contains the Phase 1 application skeleton:

```text
core/           Rust composition root and runtime boundaries
crates/events/  shared serialized event model
bpf/            CMake/eBPF probe boundary (kernel/userspace)
ui/             Vite/React + Tauri desktop shell
config/         example configuration
docs/           product and engineering documentation
```

The probes and local API are intentionally placeholders. The current core
can initialize its runtime model and print a sample shared event, but it does
not attach to the kernel yet.

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

Run the frontend:

```bash
cd ui
npm install
npm run dev
```

## Next implementation slice

The next vertical slice should connect `bpf/kernel/process.bpf.c` and
`bpf/kernel/network.bpf.c` to a ring buffer, decode them into
`tracelens-events`, and
feed the process/connection read models. The first end-to-end acceptance case
is `curl https://example.com` appearing as a process, connection, and domain
in the dashboard.
