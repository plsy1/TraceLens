#include "common.h"
#include <bpf/bpf_endian.h>

struct trace_event_raw_sys_enter {
    __u64 unused;
    long syscall_nr;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    __u64 unused;
    long syscall_nr;
    long ret;
};

struct tracelens_user_iovec {
    void *base;
    __u64 length;
};

struct tracelens_user_msghdr {
    void *name;
    __u32 name_length;
    __u32 name_padding;
    struct tracelens_user_iovec *iov;
    __u64 iov_length;
    void *control;
    __u64 control_length;
    __u32 flags;
    __u32 flags_padding;
};

struct tracelens_socket_key {
    __u32 pid;
    __u32 fd;
};

struct tracelens_dns_socket {
    __u16 protocol;
};

struct tracelens_dns_recv_request {
    __u32 pid;
    __u32 fd;
    __u16 protocol;
    __u16 reserved;
    void *buffer;
};

struct tracelens_dns_connect_request {
    __u32 pid;
    __u32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct tracelens_socket_key);
    __type(value, struct tracelens_dns_socket);
} dns_sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct tracelens_dns_recv_request);
} pending_receives SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct tracelens_dns_connect_request);
} pending_connects SEC(".maps");

static __always_inline int is_dns_destination(const void *address, __u32 address_length)
{
    __u16 family = 0;
    __u16 port = 0;

    if (!address || address_length < 4 ||
        bpf_probe_read_user(&family, sizeof(family), address) < 0 ||
        bpf_probe_read_user(&port, sizeof(port), (const char *)address + 2) < 0) {
        return 0;
    }

    return (family == TRACELENS_AF_INET || family == TRACELENS_AF_INET6) &&
        bpf_ntohs(port) == 53;
}

static __always_inline int socket_dns_protocol(__u32 pid, __u32 fd, __u16 *protocol)
{
    struct tracelens_socket_key key = {};
    struct tracelens_dns_socket *socket;

    key.pid = pid;
    key.fd = fd;
    socket = bpf_map_lookup_elem(&dns_sockets, &key);
    if (!socket) {
        return 0;
    }
    *protocol = socket->protocol;
    return 1;
}

static __always_inline void mark_dns_socket(__u32 pid, __u32 fd, __u16 protocol)
{
    struct tracelens_socket_key key = {};
    struct tracelens_dns_socket value = {};

    key.pid = pid;
    key.fd = fd;
    value.protocol = protocol;
    bpf_map_update_elem(&dns_sockets, &key, &value, BPF_ANY);
}

static __always_inline int read_message_buffer(
    const void *user_message,
    void **buffer,
    __u32 *buffer_length,
    void **name,
    __u32 *name_length)
{
    struct tracelens_user_msghdr message = {};
    struct tracelens_user_iovec iovec = {};

    if (!user_message ||
        bpf_probe_read_user(&message, sizeof(message), user_message) < 0 ||
        message.iov_length < 1 ||
        bpf_probe_read_user(&iovec, sizeof(iovec), message.iov) < 0) {
        return -1;
    }
    *buffer = iovec.base;
    *buffer_length = iovec.length > TRACELENS_DNS_PAYLOAD_LEN
        ? TRACELENS_DNS_PAYLOAD_LEN
        : (__u32)iovec.length;
    *name = message.name;
    *name_length = message.name_length;
    return 0;
}

static __always_inline int emit_dns_event(
    __u16 event_type,
    __u32 pid,
    __u32 fd,
    __u16 protocol,
    const void *buffer,
    __u32 buffer_length)
{
    struct tracelens_dns_event *event;
    __u32 payload_size = buffer_length;

    if (!buffer || payload_size < 12) {
        return 0;
    }
    if (payload_size > TRACELENS_DNS_PAYLOAD_LEN) {
        payload_size = TRACELENS_DNS_PAYLOAD_LEN;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    if (bpf_probe_read_user(event->payload, payload_size, buffer) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    if (event_type == TRACELENS_EVENT_DNS_QUERY && (event->payload[2] & 0x80)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    if (event_type == TRACELENS_EVENT_DNS_RESPONSE && !(event->payload[2] & 0x80)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    event->event_type = event_type;
    event->protocol = protocol;
    event->pid = pid;
    event->socket_id = ((__u64)pid << 32) | fd;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->payload_size = payload_size;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracelens_dns_send(struct trace_event_raw_sys_enter *ctx)
{
    __u16 protocol = TRACELENS_IPPROTO_UDP;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!is_dns_destination(
            (const void *)(unsigned long)ctx->args[4],
            (__u32)ctx->args[5]) &&
        !socket_dns_protocol(pid, fd, &protocol)) {
        return 0;
    }

    if (is_dns_destination(
            (const void *)(unsigned long)ctx->args[4],
            (__u32)ctx->args[5])) {
        protocol = TRACELENS_IPPROTO_UDP;
        mark_dns_socket(pid, fd, protocol);
    }
    return emit_dns_event(
        TRACELENS_EVENT_DNS_QUERY,
        pid,
        fd,
        protocol,
        (const void *)(unsigned long)ctx->args[1],
        (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracelens_dns_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_dns_connect_request request = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!is_dns_destination(
            (const void *)(unsigned long)ctx->args[1],
            (__u32)ctx->args[2])) {
        return 0;
    }
    request.pid = pid;
    request.fd = fd;
    bpf_map_update_elem(&pending_connects, &pid_tgid, &request, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracelens_dns_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_dns_connect_request *request;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    request = bpf_map_lookup_elem(&pending_connects, &pid_tgid);
    if (request && ctx->ret == 0) {
        mark_dns_socket(request->pid, request->fd, TRACELENS_IPPROTO_TCP);
    }
    bpf_map_delete_elem(&pending_connects, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracelens_dns_recv_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_socket_key socket_key = {};
    struct tracelens_dns_recv_request request = {};
    __u16 protocol = 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    socket_key.pid = pid_tgid >> 32;
    socket_key.fd = (__u32)ctx->args[0];
    if (!socket_dns_protocol(socket_key.pid, socket_key.fd, &protocol)) {
        return 0;
    }

    request.pid = socket_key.pid;
    request.fd = socket_key.fd;
    request.protocol = protocol;
    request.buffer = (void *)(unsigned long)ctx->args[1];
    bpf_map_update_elem(&pending_receives, &pid_tgid, &request, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracelens_dns_recv_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_dns_recv_request *request;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    request = bpf_map_lookup_elem(&pending_receives, &pid_tgid);
    if (request && ctx->ret > 0) {
        emit_dns_event(
            TRACELENS_EVENT_DNS_RESPONSE,
            request->pid,
            request->fd,
            request->protocol,
            request->buffer,
            (__u32)ctx->ret);
    }
    bpf_map_delete_elem(&pending_receives, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracelens_dns_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_user_msghdr message = {};
    void *buffer = 0;
    void *name = 0;
    __u32 buffer_length = 0;
    __u32 name_length = 0;
    __u16 protocol = TRACELENS_IPPROTO_UDP;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (read_message_buffer(
            (const void *)(unsigned long)ctx->args[1],
            &buffer,
            &buffer_length,
            &name,
            &name_length) < 0 ||
        (!is_dns_destination(name, name_length) &&
            !socket_dns_protocol(pid, fd, &protocol))) {
        return 0;
    }
    if (is_dns_destination(name, name_length)) {
        protocol = TRACELENS_IPPROTO_UDP;
        mark_dns_socket(pid, fd, protocol);
    }
    return emit_dns_event(
        TRACELENS_EVENT_DNS_QUERY,
        pid,
        fd,
        protocol,
        buffer,
        buffer_length);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracelens_dns_recvmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_user_msghdr message = {};
    struct tracelens_dns_recv_request request = {};
    void *buffer = 0;
    void *name = 0;
    __u32 buffer_length = 0;
    __u32 name_length = 0;
    __u16 protocol = 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!socket_dns_protocol(pid, fd, &protocol) ||
        read_message_buffer(
            (const void *)(unsigned long)ctx->args[1],
            &buffer,
            &buffer_length,
            &name,
            &name_length) < 0) {
        return 0;
    }
    request.pid = pid;
    request.fd = fd;
    request.protocol = protocol;
    request.buffer = buffer;
    bpf_map_update_elem(&pending_receives, &pid_tgid, &request, BPF_ANY);
    return 0;
}

static __always_inline int finish_dns_receive(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_dns_recv_request *request;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    request = bpf_map_lookup_elem(&pending_receives, &pid_tgid);
    if (request && ctx->ret > 0) {
        emit_dns_event(
            TRACELENS_EVENT_DNS_RESPONSE,
            request->pid,
            request->fd,
            request->protocol,
            request->buffer,
            (__u32)ctx->ret);
    }
    bpf_map_delete_elem(&pending_receives, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tracelens_dns_recvmsg_exit(struct trace_event_raw_sys_exit *ctx)
{
    return finish_dns_receive(ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracelens_dns_write(struct trace_event_raw_sys_enter *ctx)
{
    __u16 protocol = 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!socket_dns_protocol(pid, fd, &protocol)) {
        return 0;
    }
    return emit_dns_event(
        TRACELENS_EVENT_DNS_QUERY,
        pid,
        fd,
        protocol,
        (const void *)(unsigned long)ctx->args[1],
        (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracelens_dns_read(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_dns_recv_request request = {};
    __u16 protocol = 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!socket_dns_protocol(pid, fd, &protocol)) {
        return 0;
    }
    request.pid = pid;
    request.fd = fd;
    request.protocol = protocol;
    request.buffer = (void *)(unsigned long)ctx->args[1];
    bpf_map_update_elem(&pending_receives, &pid_tgid, &request, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracelens_dns_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    return finish_dns_receive(ctx);
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracelens_dns_close(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_socket_key key = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    key.pid = pid_tgid >> 32;
    key.fd = (__u32)ctx->args[0];
    bpf_map_delete_elem(&dns_sockets, &key);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
