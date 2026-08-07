#include "common.h"

// Placeholder probe. The event ABI is defined before attaching to real
// tracepoints so the core and UI can evolve independently.
SEC("tracepoint/sched/sched_process_exec")
int tracelens_process_exec(void *ctx)
{
    (void)ctx;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
