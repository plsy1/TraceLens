#include "common.h"

// Placeholder for TCP state and byte-counter collection.
SEC("tracepoint/sock/inet_sock_set_state")
int tracelens_tcp_state(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
