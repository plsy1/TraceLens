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
#define TRACELENS_EVENT_TCP_STATE 9
#define TRACELENS_EVENT_TCP_BYTES 10

#define TRACELENS_AF_INET 2
#define TRACELENS_AF_INET6 10
#define TRACELENS_IPPROTO_TCP 6
#define TRACELENS_IPPROTO_UDP 17
#define TRACELENS_COMM_LEN 16
#define TRACELENS_ADDR_LEN 16
#define TRACELENS_DNS_PAYLOAD_LEN 512

struct tracelens_process_event {
    __u16 event_type;
    __u16 reserved;
    __u32 pid;
    char comm[TRACELENS_COMM_LEN];
    __u64 timestamp_ns;
};

struct tracelens_network_event {
    __u16 event_type;
    __u16 family;
    __u32 pid;
    __u64 socket_id;
    __u64 timestamp_ns;
    __u16 protocol;
    __u16 local_port;
    __u16 remote_port;
    __u16 reserved;
    __u32 old_state;
    __u32 new_state;
    __u8 local_addr[TRACELENS_ADDR_LEN];
    __u8 remote_addr[TRACELENS_ADDR_LEN];
    __u64 sent_bytes;
    __u64 received_bytes;
};

struct tracelens_dns_event {
    __u16 event_type;
    __u16 protocol;
    __u32 pid;
    __u64 socket_id;
    __u64 timestamp_ns;
    __u32 payload_size;
    __u8 payload[TRACELENS_DNS_PAYLOAD_LEN];
};

struct tracelens_tls_event {
    __u32 pid;
    __u64 timestamp_ns;
    __u64 ssl_object;
    __u16 event_type;
    __u16 payload_size;
};

#endif
