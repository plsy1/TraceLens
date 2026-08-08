#include "common.h"
#include <bpf/bpf_endian.h>

struct trace_event_raw_sys_enter {
    __u64 unused;
    long syscall_nr;
    unsigned long args[6];
};

struct trace_event_raw_sys_close {
    __u64 unused;
    long syscall_nr;
    long fd;
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long syscall_nr;
    long ret;
};

struct tracelens_sockaddr_in {
    __u16 family;
    __u16 port;
    __u32 address;
};

struct tracelens_sockaddr_in6 {
    __u16 family;
    __u16 port;
    __u32 flowinfo;
    __u8 address[16];
    __u32 scope_id;
};

struct tracelens_socket_key {
    __u32 pid;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct tracelens_socket_key);
    __type(value, struct tracelens_network_event);
} active_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct tracelens_network_event);
} pending_connections SEC(".maps");

static __always_inline int emit_network_event(struct tracelens_network_event *source)
{
    struct tracelens_network_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    *event = *source;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int read_connect_address(
    const void *user_address,
    __u32 address_length,
    struct tracelens_network_event *event)
{
    __u16 family = 0;

    if (!user_address || address_length < sizeof(family)) {
        return -1;
    }

    if (bpf_probe_read_user(&family, sizeof(family), user_address) < 0) {
        return -1;
    }

    event->family = family;
    if (family == TRACELENS_AF_INET) {
        struct tracelens_sockaddr_in address = {};

        if (address_length < sizeof(address) ||
            bpf_probe_read_user(&address, sizeof(address), user_address) < 0) {
            return -1;
        }
        event->remote_port = bpf_ntohs(address.port);
        __builtin_memcpy(event->remote_addr, &address.address, sizeof(address.address));
        return 0;
    }

    if (family == TRACELENS_AF_INET6) {
        struct tracelens_sockaddr_in6 address = {};

        if (address_length < sizeof(address) ||
            bpf_probe_read_user(&address, sizeof(address), user_address) < 0) {
            return -1;
        }
        event->remote_port = bpf_ntohs(address.port);
        __builtin_memcpy(event->remote_addr, address.address, sizeof(address.address));
        return 0;
    }

    return -1;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracelens_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_network_event event = {};
    struct tracelens_socket_key key = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    event.event_type = TRACELENS_EVENT_TCP_CONNECT;
    event.pid = pid;
    event.socket_id = ((__u64)pid << 32) | fd;
    event.protocol = TRACELENS_IPPROTO_TCP;
    if (read_connect_address(
            (const void *)(unsigned long)ctx->args[1],
            (__u32)ctx->args[2],
            &event) < 0) {
        return 0;
    }

    bpf_map_update_elem(&pending_connections, &pid_tgid, &event, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracelens_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_network_event *pending;
    struct tracelens_socket_key key = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    pending = bpf_map_lookup_elem(&pending_connections, &pid_tgid);
    if (!pending) {
        return 0;
    }

    if (ctx->ret == 0) {
        key.pid = pending->pid;
        key.fd = (__u32)pending->socket_id;
        bpf_map_update_elem(&active_connections, &key, pending, BPF_ANY);
        emit_network_event(pending);
    }

    bpf_map_delete_elem(&pending_connections, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracelens_close(struct trace_event_raw_sys_close *ctx)
{
    struct tracelens_socket_key key = {};
    struct tracelens_network_event *active;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    key.pid = pid_tgid >> 32;
    key.fd = (__u32)ctx->fd;
    active = bpf_map_lookup_elem(&active_connections, &key);
    if (!active) {
        return 0;
    }

    struct tracelens_network_event event = *active;
    event.event_type = TRACELENS_EVENT_TCP_CLOSE;
    emit_network_event(&event);
    bpf_map_delete_elem(&active_connections, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
