# TraceLens architecture

## Runtime boundaries

```text
kernel eBPF probes ─┐
                    ├─> shared event ABI ─> Rust core ─> local API ─> Tauri UI
bpftime probes ─────┘                         │
                                             ├─> correlation
                                             ├─> observation manager
                                             ├─> detection
                                             └─> memory (default) / SQLite (optional)
```

The shared event model lives in `crates/events`. It is the contract between
probe output, core read models, and the UI/API layer. Runtime integrations
are kept behind `core/src/runtime` so kernel eBPF and bpftime can be selected
independently.

## Current boundaries

- `process`: process identity and lifecycle read model.
- `network`: socket/connection identity and traffic counters.
- `dns`: query/response cache and correlation boundary.
- `http`: bounded directional stream reassembly and HTTP/1.1 metadata parser.
- `observation`: L1–L5 target-level escalation state.
- `events`: event bus and correlation entry point.
- `detection`: rule engine boundary.
- `storage`: bounded in-memory timeline store by default, with optional SQLite history mode.
- `runtime`: bpftime CLI/loader integration, target ELF/libssl resolution,
  real userspace probe lifecycle, and libbpf kernel uProbe fallback.
- `api`: read API plus connection-session and observation-level command endpoints for the UI.

The kernel event path and Phase 8 OpenSSL metadata path are real: the latter
consumes a per-object userspace ring buffer and correlates SNI/version/fd data
back to the process connection. Phase 7 also provides the bpftime loader
boundary; when that runtime is selected, the loader forwards the same shared
TLS event schema to Core.

HTTP capture is a separate L4 userspace path. It reuses the SSL object/fd
correlation established by TLS, keeps request and response buffers separate,
and writes only parsed `Http` events to storage. The bounded raw capture event
is consumed transiently by Core and is never exposed as a Timeline row.
