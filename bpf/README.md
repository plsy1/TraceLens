# TraceLens eBPF layer

This directory contains the probe-side boundary. The process, network, TCP
state/byte, and DNS probes emit the current Phase 2/3/4 metadata events;
userspace probe objects are loaded and attached on demand by the Phase 7
runtime. OpenSSL/TLS objects emit Phase 8 metadata records through their own
ring buffers. The Phase 10 HTTP object is attached at L4 and uses a separate
bounded `SSL_read`/`SSL_write` capture ABI; Core parses the bytes and drops the
raw capture. The Phase 9 plaintext object is only attached at L5: it pairs the
same entry/return probes and caps each persisted plaintext record at 512 bytes.

```text
kernel/       always-on process, network, DNS, TCP, and file probes
userspace/    on-demand OpenSSL, TLS, HTTP, and plaintext probes
include/      shared C event ABI and probe helpers
```

The intended flow is:

```text
kernel tracepoint / kprobe
        ↓
     ring buffer
        ↓
   Rust core ABI
```

Configure the source-only target with:

```bash
cmake -S . -B build
```

After installing Clang, libbpf headers, and Linux kernel headers, compile the
objects with:

```bash
cmake -S . -B build -DTRACELENS_BUILD_BPF=ON
cmake --build build
```

process.bpf.c emits exec/exit records, network.bpf.c emits connect/close/state/
byte records, and dns.bpf.c emits bounded UDP/TCP DNS query/response payloads
through ring buffers. DNS socket tracking covers sendto/recvfrom,
sendmsg/recvmsg, connected read/write, and close cleanup. The Rust loader reads
the resulting process.o, network.o, and dns.o objects from build/bpf/objects.

Phase 7 builds `target/debug/tracelens-bpftime-loader` alongside the Core
binary. When `bpftime` is available, Core starts `bpftime trace` with that
loader and passes the target PID, resolved ELF/libssl path, object path, and
symbol. Without bpftime, Core uses the same object and symbol metadata through
libbpf's real kernel uProbe attach API. The TLS objects emit metadata through a
ring buffer consumed by Core. The HTTP and plaintext objects use bounded
directional records; Core correlates them through the SSL object and current
TLS session. HTTP capture records are an internal derivation input and are not
written to the event store.
