# TraceLens architecture

## Runtime boundaries

```text
kernel eBPF probes ─┐
                    ├─> shared event ABI ─> Rust core ─> local API ─> Tauri UI
bpftime probes ─────┘                         │
                                             ├─> correlation
                                             ├─> capture planner
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
- `capture`: CaptureFeatures, Profile presets, dependency closure, and ProbePlan.
- `observation`: legacy L1–L5 compatibility state during API migration.
- `events`: event bus and correlation entry point.
- `detection`: rule engine boundary.
- `storage`: bounded in-memory timeline store by default, with optional SQLite history mode.
- `runtime`: bounded event ingress, bpftime CLI/loader integration, ELF
  build-id Provider identity, same-runtime NSS/NSPR pairing, shared-object
  userspace probe lifecycle, and libbpf kernel uProbe fallback.
- `api`: capture plan/lifecycle, capabilities, process-candidate, read, and connection-session endpoints for the UI.

The provider detector inspects mapped libraries, dynamic symbols, and ELF
build-id. OpenSSL-family libraries load `openssl.o`, GnuTLS loads `gnutls.o`,
NSS/NSPR loads one cross-library `nss.o`, and rustls-ffi loads `rustls.o`.
Each `(provider, build-id, target scope)` owns one object, the links
for symbols that actually exist, and one ring-buffer reader. Modern OpenSSL
payload capture covers `SSL_read/write` and `SSL_read_ex/write_ex`; GnuTLS uses
`gnutls_record_recv/send`. Kernel uProbe and bpftime consume the same Provider
plan and forward the same normalized event schema to Core. The event source
records the Provider, actual hooked library, and API function. Active captures
re-scan providers every two seconds to cover delayed `dlopen`.

NSS only records `PR_Read`/`PR_Write` when the `PRFileDesc` was returned by
`SSL_ImportFD`; `PR_Close` removes it from the BPF map. This prevents ordinary
NSPR file and socket I/O from entering the TLS stream. Native/static rustls,
Go crypto/tls, and Java JSSE do not expose one stable dynamic ABI. TraceLens
reports their build/runtime capability and leaves deep capture disabled unless
a verified adapter exists; dynamic rustls-ffi uses its stable C API.

HTTP capture is enabled by the HTTP module. It reuses the SSL object/fd
correlation established by TLS, keeps request and response buffers separate,
and writes only parsed `Http` events to storage. The bounded raw capture event
is consumed transiently by Core and is never exposed as a Timeline row.
