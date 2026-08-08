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

This loads build/bpf/objects/process.o, network.o, and dns.o, attaches process,
TCP state/byte, and DNS tracepoints, and serves the API including
`/api/timeline?limit=50&offset=0&pid=&kind=&connection_id=`.
When a process is upgraded to L3, Core additionally attaches the OpenSSL
userspace objects and consumes TLS metadata ring-buffer events. The Timeline
and connection APIs expose SNI, TLS version, SSL object/fd, and correlated
session data. L4 attaches a separate bounded `SSL_read`/`SSL_write` capture
object and emits only parsed HTTP/1.1 request/response metadata (method, host,
path, status, and headers); Core drops the raw capture after parsing. L5
additionally attaches the plaintext object for on-demand payload inspection;
each event is bounded to 512 captured bytes and includes its original byte
count/truncation flag. L1-L3 do not attach either payload path.

Timeline events stay in memory by default and are lost on restart. To enable
optional SQLite history, start the observer with
`--storage sqlite --database tracelens.db`. Observation levels can be queried
with `GET /api/observations` and changed with a JSON `POST /api/observations`
body such as:

```json
{"target":"process:4242","level":3,"duration_secs":300}
```

Connection-oriented history is available from
`/api/connection-timeline?limit=50&offset=0&include_closed=true&include_events=false`.
Use `connection_id=...&include_events=true&event_limit=200` to load the child
events for one session. The health response reports the selected userspace
runtime, attached hook entries, and probe errors. Build both Core binaries:

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

## Desktop UI

```bash
cd ui
npm install
npm run dev
```

Use `npm run tauri dev` once Tauri's platform dependencies are installed.
