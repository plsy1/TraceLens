# TraceLens eBPF layer

This directory contains the probe-side boundary. The process, network, TCP
state/byte, and DNS probes emit the current Phase 2/3/4 metadata events;
userspace probes remain compile targets for later phases.

```text
kernel/       always-on process, network, DNS, TCP, and file probes
userspace/    on-demand OpenSSL, TLS, and plaintext probes
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
byte records, and dns.bpf.c emits bounded DNS query/response payloads through
ring buffers. The Rust loader reads the resulting process.o, network.o, and
dns.o objects from build/bpf/objects.
