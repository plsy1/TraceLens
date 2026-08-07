#include "common.h"

// Placeholder probe for the first network milestone.
SEC("tracepoint/syscalls/sys_enter_connect")
int tracelens_connect(void *ctx)
{
    (void)ctx;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
