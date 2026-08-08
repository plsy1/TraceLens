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
#define TRACELENS_EVENT_HTTP_CAPTURE 11
#define TRACELENS_EVENT_FILE_OPEN 12
#define TRACELENS_EVENT_FILE_READ 13

#define TRACELENS_TLS_METADATA_HANDSHAKE 1
#define TRACELENS_TLS_METADATA_SNI 2
#define TRACELENS_TLS_METADATA_VERSION 3
#define TRACELENS_TLS_METADATA_FD 4

#define TRACELENS_AF_INET 2
#define TRACELENS_AF_INET6 10
#define TRACELENS_IPPROTO_TCP 6
#define TRACELENS_IPPROTO_UDP 17
#define TRACELENS_COMM_LEN 16
#define TRACELENS_ADDR_LEN 16
#define TRACELENS_DNS_PAYLOAD_LEN 512
#define TRACELENS_TLS_NAME_LEN 128
#define TRACELENS_TLS_VERSION_LEN 32
#define TRACELENS_PLAINTEXT_READ 1
#define TRACELENS_PLAINTEXT_WRITE 2
/* Keep ordinary HTML/JSON responses in one bounded SSL capture event. */
#define TRACELENS_PLAINTEXT_MAX_LEN (16 * 1024)
#define TRACELENS_FILE_PATH_LEN 256

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
    __u16 event_type;
    __u16 metadata_kind;
    __u32 pid;
    __u64 timestamp_ns;
    __u64 ssl_object;
    __s32 fd;
    __u32 reserved;
    char sni[TRACELENS_TLS_NAME_LEN];
    char version[TRACELENS_TLS_VERSION_LEN];
};

struct tracelens_plaintext_event {
    __u16 event_type;
    __u16 direction;
    __u32 pid;
    __u64 timestamp_ns;
    __u64 ssl_object;
    __s32 fd;
    __u32 payload_size;
    __u32 truncated;
    __u8 payload[TRACELENS_PLAINTEXT_MAX_LEN];
};

struct tracelens_http_capture_event {
    __u16 event_type;
    __u16 direction;
    __u32 pid;
    __u64 timestamp_ns;
    __u64 ssl_object;
    __s32 fd;
    __u32 payload_size;
    __u32 truncated;
    __u8 payload[TRACELENS_PLAINTEXT_MAX_LEN];
};

struct tracelens_file_event {
    __u16 event_type;
    __u16 reserved;
    __u32 pid;
    __u64 timestamp_ns;
    __u64 bytes;
    char path[TRACELENS_FILE_PATH_LEN];
};

#endif
