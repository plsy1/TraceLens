#include "common.h"

// Placeholder for TLS metadata collection.
SEC("uprobe/SSL_get_servername")
int tracelens_tls_metadata(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
