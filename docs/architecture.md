# TraceLens architecture

## Runtime boundaries

```text
kernel eBPF probes ─┐
                    ├─> shared event ABI ─> Rust core ─> local API ─> Tauri UI
bpftime probes ─────┘                         │
                                             ├─> correlation
                                             ├─> observation manager
                                             ├─> detection
                                             └─> SQLite
```

The shared event model lives in `crates/events`. It is the contract between
probe output, core read models, and the UI/API layer. Runtime integrations
are kept behind `core/src/runtime` so kernel eBPF and bpftime can be selected
independently.

## Current boundaries

- `process`: process identity and lifecycle read model.
- `network`: socket/connection identity and traffic counters.
- `dns`: query/response cache and correlation boundary.
- `observation`: L1–L5 target-level escalation state.
- `events`: event bus and correlation entry point.
- `detection`: rule engine boundary.
- `storage`: temporary in-memory store with a SQLite-compatible seam.
- `api`: read and command API seams for the UI.

The first implementation should make the kernel event path real before adding
TLS plaintext capture. That keeps the process-to-connection identity stable
while deeper probes are added later.
