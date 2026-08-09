#ifndef TRACELENS_DNS_HELPERS_H
#define TRACELENS_DNS_HELPERS_H

/*
 * DNS support shared by network.bpf.c's socket I/O tracepoints. Keeping the
 * parsing helpers here lets Traffic and DNS use one syscall attachment set.
 */

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
} pending_dns_receives SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct tracelens_dns_connect_request);
} pending_dns_connects SEC(".maps");

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

static __always_inline void dns_connect_enter_shared(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_dns_connect_request request = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) ||
        !capture_dns_matches_current() ||
        !is_dns_destination(
            (const void *)(unsigned long)ctx->args[1],
            (__u32)ctx->args[2])) {
        return;
    }
    request.pid = pid_tgid >> 32;
    request.fd = (__u32)ctx->args[0];
    bpf_map_update_elem(&pending_dns_connects, &pid_tgid, &request, BPF_ANY);
}

static __always_inline void dns_connect_exit_shared(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_dns_connect_request *request;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }

    request = bpf_map_lookup_elem(&pending_dns_connects, &pid_tgid);
    if (request && ctx->ret == 0) {
        mark_dns_socket(request->pid, request->fd, TRACELENS_IPPROTO_TCP);
    }
    bpf_map_delete_elem(&pending_dns_connects, &pid_tgid);
}

static __always_inline void dns_sendto_shared(struct trace_event_raw_sys_enter *ctx)
{
    __u16 protocol = TRACELENS_IPPROTO_UDP;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];
    int destination_is_dns;

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }
    destination_is_dns = is_dns_destination(
        (const void *)(unsigned long)ctx->args[4], (__u32)ctx->args[5]);

    if (!destination_is_dns && !socket_dns_protocol(pid, fd, &protocol)) {
        return;
    }
    if (destination_is_dns) {
        mark_dns_socket(pid, fd, TRACELENS_IPPROTO_UDP);
    }
    emit_dns_event(
        TRACELENS_EVENT_DNS_QUERY,
        pid,
        fd,
        protocol,
        (const void *)(unsigned long)ctx->args[1],
        (__u32)ctx->args[2]);
}

static __always_inline void remember_dns_receive(
    __u32 pid,
    __u32 fd,
    __u16 protocol,
    void *buffer)
{
    struct tracelens_dns_recv_request request = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    request.pid = pid;
    request.fd = fd;
    request.protocol = protocol;
    request.buffer = buffer;
    bpf_map_update_elem(&pending_dns_receives, &pid_tgid, &request, BPF_ANY);
}

static __always_inline void dns_recvfrom_shared(struct trace_event_raw_sys_enter *ctx)
{
    __u16 protocol = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }

    if (socket_dns_protocol(pid, fd, &protocol)) {
        remember_dns_receive(pid, fd, protocol, (void *)(unsigned long)ctx->args[1]);
    }
}

static __always_inline void dns_sendmsg_shared(struct trace_event_raw_sys_enter *ctx)
{
    void *buffer = 0;
    void *name = 0;
    __u32 buffer_length = 0;
    __u32 name_length = 0;
    __u16 protocol = TRACELENS_IPPROTO_UDP;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }

    if (read_message_buffer(
            (const void *)(unsigned long)ctx->args[1],
            &buffer,
            &buffer_length,
            &name,
            &name_length) < 0) {
        return;
    }
    if (is_dns_destination(name, name_length)) {
        mark_dns_socket(pid, fd, TRACELENS_IPPROTO_UDP);
    } else if (!socket_dns_protocol(pid, fd, &protocol)) {
        return;
    }
    emit_dns_event(TRACELENS_EVENT_DNS_QUERY, pid, fd, protocol, buffer, buffer_length);
}

static __always_inline void dns_recvmsg_shared(struct trace_event_raw_sys_enter *ctx)
{
    void *buffer = 0;
    void *name = 0;
    __u32 buffer_length = 0;
    __u32 name_length = 0;
    __u16 protocol = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }

    if (socket_dns_protocol(pid, fd, &protocol) &&
        read_message_buffer(
            (const void *)(unsigned long)ctx->args[1],
            &buffer,
            &buffer_length,
            &name,
            &name_length) == 0) {
        remember_dns_receive(pid, fd, protocol, buffer);
    }
}

static __always_inline void dns_write_shared(struct trace_event_raw_sys_enter *ctx)
{
    __u16 protocol = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }

    if (socket_dns_protocol(pid, fd, &protocol)) {
        emit_dns_event(
            TRACELENS_EVENT_DNS_QUERY,
            pid,
            fd,
            protocol,
            (const void *)(unsigned long)ctx->args[1],
            (__u32)ctx->args[2]);
    }
}

static __always_inline void dns_read_shared(struct trace_event_raw_sys_enter *ctx)
{
    __u16 protocol = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = (__u32)ctx->args[0];

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }

    if (socket_dns_protocol(pid, fd, &protocol)) {
        remember_dns_receive(pid, fd, protocol, (void *)(unsigned long)ctx->args[1]);
    }
}

static __always_inline void dns_receive_exit_shared(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_dns_recv_request *request;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }

    request = bpf_map_lookup_elem(&pending_dns_receives, &pid_tgid);
    if (request && ctx->ret > 0) {
        emit_dns_event(
            TRACELENS_EVENT_DNS_RESPONSE,
            request->pid,
            request->fd,
            request->protocol,
            request->buffer,
            (__u32)ctx->ret);
    }
    bpf_map_delete_elem(&pending_dns_receives, &pid_tgid);
}

static __always_inline void dns_close_shared(__u32 pid, __u32 fd)
{
    struct tracelens_socket_key key = {};
    if (!feature_is_enabled(TRACELENS_FEATURE_DNS) || !capture_dns_matches_current()) {
        return;
    }
    key.pid = pid;
    key.fd = fd;
    bpf_map_delete_elem(&dns_sockets, &key);
}

#endif
