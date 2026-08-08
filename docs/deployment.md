# Development setup

The initial target is Linux x86_64. The repository separates the three tool
chains so the core model and UI can be developed before kernel probe support
is available.

## Rust core

```bash
cargo test --workspace
cargo run -p tracelens-core -- --print-example-event
```

## eBPF probes

The default CMake configuration only registers the source target. Enable
object compilation after installing Clang, libbpf headers, and kernel headers:

```bash
cmake -S . -B build -DTRACELENS_BUILD_BPF=ON
cmake --build build
```

The Phase 2/3/4 observer requires root or equivalent Linux BPF capabilities:

~~~bash
cargo build -p tracelens-core
sudo ./target/debug/tracelens-core --observe --api-listen 127.0.0.1:8080
~~~

This loads build/bpf/objects/process.o, network.o, and dns.o, attaches process,
TCP state/byte, and DNS tracepoints, and serves the read-only API.

## Desktop UI

```bash
cd ui
npm install
npm run dev
```

Use `npm run tauri dev` once Tauri's platform dependencies are installed.
