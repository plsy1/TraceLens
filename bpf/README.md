# TraceLens eBPF layer

This directory contains the probe-side boundary. The current programs are
minimal compile targets and do not emit events yet.

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

`vmlinux.h` generation and ring-buffer emission will be added alongside the
first real process and TCP probes.
