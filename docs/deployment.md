# Development setup

The initial target is Linux x86_64. The repository separates the three tool
chains so the core model and UI can be developed before kernel probe support
is available.

## Rust core

```bash
cargo test --workspace --all-targets
cargo run -p tracelens-core -- --print-example-event
```

## eBPF probes

The default CMake configuration only registers the source target. Enable
object compilation after installing Clang, libbpf headers, and kernel headers:

```bash
cmake -S . -B build -DTRACELENS_BUILD_BPF=ON
cmake --build build
```

The observer requires root or equivalent Linux BPF capabilities:

~~~bash
cargo build -p tracelens-core
sudo ./target/debug/tracelens-core --observe --api-listen 127.0.0.1:8080
~~~

Start dynamically loads the required `process.o`, `network.o`, and optional
`file.o`. Connections uses 6 links in total, Network uses 18, and Security
uses 19; Stop releases every Kernel link and object. The API includes
`/api/timeline?limit=50&offset=0&pid=&kind=&connection_id=`.
The observer starts in `stopped` capture state. The Web UI or API must start a
capture explicitly; events received while stopped are discarded. A capture
can be scoped to `global`, `process:<pid>`, or `process-name:<name>` and can be
stopped or reset without retaining the previous in-memory session.

Capture profiles expand into independent Process, Connections, Traffic, DNS,
Files, TLS, HTTP, and Plaintext modules. TLS automatically detects supported
OpenSSL-family, GnuTLS, NSS/NSPR, and rustls-ffi libraries. HTTP adds bounded Provider-specific record
capture for HTTP/1.1 reconstruction;
Core drops raw fragments after parsing. Plaintext uses the same bounded payload
transport but additionally exposes raw fragments, with a 16 KiB per-event
limit and explicit confirmation.

Timeline events stay in memory by default and are lost on restart. To enable
optional SQLite history, start the observer with
`--storage sqlite --database tracelens.db`. Query available profiles and
modules with `GET /api/capabilities`, and start a capture with:

```json
{"target":"process:4242","profile":"web","modules":["process","connections","traffic","dns","tls","http"]}
```

Plaintext additionally requires `"confirm_plaintext":true`. Profiles are
presets; `modules` is authoritative. Legacy `level` requests are temporarily
translated to modules and return a deprecation warning.

Connection-oriented history is available from
`/api/connection-timeline?limit=50&offset=0&include_closed=true&include_events=false`.
Use `connection_id=...&include_events=true&event_limit=200` to load the child
events for one session. The health response and `/api/tls-capabilities` report
the selected userspace runtime, Provider/library/build-id, supported hooks,
object count, reader count, link count, and probe errors. Build both Core binaries:

```bash
cargo build -p tracelens-core --bins
```

Set `TRACELENS_BPFTIME` to an explicit bpftime executable when it is not on
`PATH`. Set `TRACELENS_BPFTIME_LOADER` if `tracelens-bpftime-loader` is
installed outside the Core binary directory; `TRACELENS_BPFTIME_INSTALL` can
point at the bpftime install directory when the executable is not installed
under the default `~/.bpftime` location. When bpftime or the loader is
unavailable, Linux uses the real libbpf kernel uProbe fallback. Missing
objects, target processes, symbols, or permissions are reported in
`/api/health.probe_errors` and do not create fake attachment records.

The current adapter requires a bpftime distribution that exposes the legacy
`trace` command. Newer upstream builds use a different `load/start/attach`
lifecycle; capability detection rejects those builds instead of reporting a
false attachment, then uses kernel uProbe. Migrating to the newer lifecycle is
tracked as a separate runtime-compatibility item.

Run the isolated privileged runtime test and profile matrix with:

```bash
./scripts/privileged-e2e.sh
```

The test binds to `127.0.0.1:18082` by default and does not touch a normal UI
instance. See `docs/performance.md` for the latest baseline and caveats.

## Desktop UI

```bash
cd ui
npm ci
npm run desktop:dev
```

`desktop:dev` compiles the current Core and BPF objects before opening the
Tauri window. If no Core is already listening on `127.0.0.1:8080`, the desktop
backend uses `/usr/bin/pkexec` to request administrator authorization and
starts its bundled Core. The elevated child has a Linux parent-death signal;
normal exit and GUI crashes both release its probes. An externally started
Core is never terminated by the desktop application.

Build installable Linux packages with:

```bash
cd ui
npm ci
npm run desktop:build
```

The preparation hook builds Release Core and all BPF objects, copies them into
Tauri resources, bundles `libelf`, `zlib`, and `zstd` for the resource-sidecar,
and sets an origin-relative runtime path. Outputs:

```text
ui/src-tauri/target/release/bundle/deb/TraceLens_<version>_amd64.deb
ui/src-tauri/target/release/bundle/appimage/TraceLens_<version>_amd64.AppImage
```

The Debian package declares `pkexec` and WebKitGTK runtime dependencies. The
AppImage includes the UI runtime but expects the host to provide `pkexec` and
a desktop Polkit agent. Both formats bind the API only to localhost. Logs from
a desktop-managed Core are written to the platform application log directory
under `io.tracelens.desktop/core.log`.
