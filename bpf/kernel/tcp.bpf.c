#include "common.h"

// The Phase 3 TCP state and byte-counter hooks live in network.bpf.c so they
// can share the PID/FD connection maps. This source remains the future
// boundary for socket-level probes that do not need syscall context.
SEC("tracepoint/sock/inet_sock_set_state")
int tracelens_tcp_state(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
