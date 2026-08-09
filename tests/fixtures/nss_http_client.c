#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nss.h>
#include <prerror.h>
#include <prio.h>
#include <prinit.h>
#include <prnetdb.h>
#include <ssl.h>

static SECStatus accept_certificate(void *arg, PRFileDesc *fd, PRBool checksig, PRBool is_server)
{
    (void)arg;
    (void)fd;
    (void)checksig;
    (void)is_server;
    return SECSuccess;
}

static void fail(const char *operation)
{
    fprintf(stderr, "%s failed: NSPR error %d\n", operation, PR_GetError());
    exit(1);
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 18443;
    PRNetAddr address;
    PRFileDesc *socket;
    PRFileDesc *tls;
    char response[4096];
    const char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    PRInt32 received;
    SSLChannelInfo channel_info;

    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
    if (NSS_NoDB_Init(NULL) != SECSuccess) fail("NSS_NoDB_Init");
    socket = PR_OpenTCPSocket(PR_AF_INET);
    if (!socket) fail("PR_OpenTCPSocket");
    if (PR_InitializeNetAddr(PR_IpAddrLoopback, (PRUint16)port, &address) != PR_SUCCESS)
        fail("PR_InitializeNetAddr");
    if (PR_Connect(socket, &address, PR_SecondsToInterval(5)) != PR_SUCCESS)
        fail("PR_Connect");

    tls = SSL_ImportFD(NULL, socket);
    if (!tls) fail("SSL_ImportFD");
    if (SSL_OptionSet(tls, SSL_SECURITY, PR_TRUE) != SECSuccess ||
        SSL_OptionSet(tls, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE) != SECSuccess ||
        SSL_SetURL(tls, "localhost") != SECSuccess ||
        SSL_AuthCertificateHook(tls, accept_certificate, NULL) != SECSuccess ||
        SSL_ResetHandshake(tls, PR_FALSE) != SECSuccess ||
        SSL_ForceHandshake(tls) != SECSuccess)
        fail("NSS TLS setup");
    memset(&channel_info, 0, sizeof(channel_info));
    if (SSL_GetChannelInfo(tls, &channel_info, sizeof(channel_info)) != SECSuccess)
        fail("SSL_GetChannelInfo");

    if (PR_Write(tls, request, (PRInt32)strlen(request)) <= 0) fail("PR_Write");
    received = PR_Read(tls, response, sizeof(response) - 1);
    if (received <= 0) fail("PR_Read");
    response[received] = '\0';
    if (strstr(response, "HTTP/") == NULL) fail("HTTP response");
    fwrite(response, 1, (size_t)received, stdout);
    while ((received = PR_Read(tls, response, sizeof(response))) > 0)
        fwrite(response, 1, (size_t)received, stdout);

    PR_Close(tls);
    NSS_Shutdown();
    PR_Cleanup();
    return 0;
}
