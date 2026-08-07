#include "common.h"

// Placeholder for on-demand SSL_read/SSL_write capture.
SEC("uprobe/SSL_read")
int tracelens_plaintext_read(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
