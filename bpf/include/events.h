#ifndef TRACELENS_EVENTS_H
#define TRACELENS_EVENTS_H

#include <linux/types.h>

#define TRACELENS_EVENT_PROCESS_EXEC 1
#define TRACELENS_EVENT_PROCESS_EXIT 2
#define TRACELENS_EVENT_TCP_CONNECT 3
#define TRACELENS_EVENT_TCP_CLOSE 4
#define TRACELENS_EVENT_DNS_QUERY 5
#define TRACELENS_EVENT_DNS_RESPONSE 6
#define TRACELENS_EVENT_TLS_METADATA 7
#define TRACELENS_EVENT_PLAINTEXT 8

struct tracelens_process_event {
    __u32 pid;
    __u32 ppid;
    __u64 timestamp_ns;
    char comm[16];
};

struct tracelens_network_event {
    __u32 pid;
    __u32 protocol;
    __u64 socket_cookie;
    __u64 timestamp_ns;
    __u32 remote_ipv4;
    __u16 remote_port;
    __u16 event_type;
};

struct tracelens_tls_event {
    __u32 pid;
    __u64 timestamp_ns;
    __u64 ssl_object;
    __u16 event_type;
    __u16 payload_size;
};

#endif
