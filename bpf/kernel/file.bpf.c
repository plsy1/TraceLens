#include "common.h"

// Placeholder for security-relevant file access events.
SEC("tracepoint/syscalls/sys_enter_openat")
int tracelens_file_open(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
