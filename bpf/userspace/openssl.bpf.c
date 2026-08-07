#include "common.h"

// Placeholder for OpenSSL library detection and SSL object discovery.
SEC("uprobe/SSL_connect")
int tracelens_openssl_connect(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
