# TraceLens eBPF layer

This directory contains the probe-side boundary. The process and network
probes now emit Phase 2/3 metadata events; DNS, TCP byte counters, and
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

process.bpf.c emits exec/exit records and network.bpf.c emits connect/close
records through ring buffers. The Rust loader reads the resulting process.o
and network.o objects from build/bpf/objects.
