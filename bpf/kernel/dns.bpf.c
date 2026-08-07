#include "common.h"

// Placeholder for DNS query/response correlation.
SEC("tracepoint/syscalls/sys_enter_sendto")
int tracelens_dns_send(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
