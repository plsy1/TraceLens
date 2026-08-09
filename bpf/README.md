# TraceLens eBPF layer

This directory contains the probe-side boundary. Kernel objects are attached
only while a capture is active and only for its selected modules. Userspace
objects provide OpenSSL-family, GnuTLS, NSS/NSPR, and rustls-ffi metadata,
bounded HTTP reconstruction input, and explicit bounded Plaintext capture.

```text
kernel/       on-demand process, network/socket-I/O/DNS, and file probes
userspace/    on-demand OpenSSL, GnuTLS, NSS/NSPR, and rustls-ffi objects
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

`process.bpf.c` emits exec/exit records. `network.bpf.c` owns connection state
and one shared set of send/recv/read/write hooks; `dns_helpers.h` adds bounded
UDP/TCP DNS query/response handling to those same hooks. A feature map disables
Traffic or DNS work when its module is off. `file.bpf.c` is completely optional.
The Rust controller loads `process.o`, `network.o`, and `file.o` according to
the immutable CapturePlan and drops them on Stop.

`openssl.o` contains TLS metadata plus bounded `SSL_read/write` and
`SSL_read_ex/write_ex` programs. `gnutls.o` covers `gnutls_handshake`, transport
fd, and bounded `gnutls_record_recv/send`. `nss.o` shares one TLS-object
allowlist across `libssl3` and `libnspr4`, while `rustls.o` targets the stable
dynamic rustls-ffi connection API. A Provider instance is keyed by TLS
implementation, ELF build-id, and target scope; it owns one loaded object, all
available selected-symbol links, and one ring-buffer reader. When `bpftime` is
available, Core passes the complete hook set to one loader process. Otherwise
the same plan uses libbpf kernel uProbe attachment. Core derives HTTP from the
bounded payload stream and only retains raw fragments when Plaintext was
explicitly selected.
