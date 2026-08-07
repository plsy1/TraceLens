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

The core will eventually require the appropriate Linux capabilities to load
eBPF programs. Capability checks belong in the runtime adapter, not in the
event model.

## Desktop UI

```bash
cd ui
npm install
npm run dev
```

Use `npm run tauri dev` once Tauri's platform dependencies are installed.
