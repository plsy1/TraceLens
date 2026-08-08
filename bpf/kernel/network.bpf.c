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

struct trace_event_raw_sock_state {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    const void *skaddr;
    __s32 oldstate;
    __s32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
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

struct tracelens_tuple_key {
    __u32 pid;
    __u16 family;
    __u16 remote_port;
    __u8 remote_addr[TRACELENS_ADDR_LEN];
};

struct tracelens_io_request {
    __u32 pid;
    __u32 fd;
    __u8 direction;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct tracelens_tuple_key);
    __type(value, struct tracelens_socket_key);
} connections_by_remote SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct tracelens_socket_key);
} sockets_by_kernel_address SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct tracelens_io_request);
} pending_io SEC(".maps");

#define TRACELENS_EINPROGRESS 115
#define TRACELENS_EALREADY 114

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

static __always_inline void make_remote_key(
    struct tracelens_tuple_key *key,
    __u32 pid,
    struct tracelens_network_event *event)
{
    key->pid = pid;
    key->family = event->family;
    key->remote_port = event->remote_port;
    __builtin_memcpy(key->remote_addr, event->remote_addr, sizeof(key->remote_addr));
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracelens_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_network_event event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 fd = (__u32)ctx->args[0];

    event.event_type = TRACELENS_EVENT_TCP_CONNECT;
    event.pid = pid;
    event.socket_id = ((__u64)pid << 32) | fd;
    event.protocol = TRACELENS_IPPROTO_TCP;
    event.old_state = 7;
    event.new_state = 2;
    if (read_connect_address(
            (const void *)(unsigned long)ctx->args[1],
            (__u32)ctx->args[2],
            &event) < 0) {
        return 0;
    }

    {
        struct tracelens_socket_key key = {};
        struct tracelens_tuple_key tuple = {};

        key.pid = pid;
        key.fd = fd;
        bpf_map_update_elem(&active_connections, &key, &event, BPF_ANY);
        make_remote_key(&tuple, pid, &event);
        bpf_map_update_elem(&connections_by_remote, &tuple, &key, BPF_ANY);
    }
    bpf_map_update_elem(&pending_connections, &pid_tgid, &event, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracelens_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_network_event *pending;
    struct tracelens_socket_key key = {};
    struct tracelens_tuple_key tuple = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    pending = bpf_map_lookup_elem(&pending_connections, &pid_tgid);
    if (!pending) {
        return 0;
    }

    if (ctx->ret == 0 || ctx->ret == -TRACELENS_EINPROGRESS || ctx->ret == -TRACELENS_EALREADY) {
        key.pid = pending->pid;
        key.fd = (__u32)pending->socket_id;
        bpf_map_update_elem(&active_connections, &key, pending, BPF_ANY);
        make_remote_key(&tuple, pending->pid, pending);
        bpf_map_update_elem(&connections_by_remote, &tuple, &key, BPF_ANY);
        if (ctx->ret == 0) {
            emit_network_event(pending);
        }
    } else {
        key.pid = pending->pid;
        key.fd = (__u32)pending->socket_id;
        bpf_map_delete_elem(&active_connections, &key);
        {
            struct tracelens_tuple_key tuple = {};
            make_remote_key(&tuple, pending->pid, pending);
            bpf_map_delete_elem(&connections_by_remote, &tuple);
        }
    }

    bpf_map_delete_elem(&pending_connections, &pid_tgid);
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int tracelens_tcp_state(struct trace_event_raw_sock_state *ctx)
{
    struct tracelens_socket_key *key_by_socket;
    struct tracelens_socket_key *key_by_remote;
    struct tracelens_network_event *active;
    struct tracelens_network_event state = {};
    struct tracelens_tuple_key tuple = {};
    __u64 socket_address = (__u64)ctx->skaddr;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (ctx->protocol != TRACELENS_IPPROTO_TCP ||
        (ctx->family != TRACELENS_AF_INET && ctx->family != TRACELENS_AF_INET6)) {
        return 0;
    }

    if (ctx->dport == 0 || ctx->newstate == 10) {
        return 0;
    }

    state.event_type = TRACELENS_EVENT_TCP_STATE;
    state.pid = pid;
    state.socket_id = socket_address;
    state.family = ctx->family;
    state.protocol = ctx->protocol;
    state.local_port = ctx->sport;
    state.remote_port = ctx->dport;
    state.old_state = ctx->oldstate;
    state.new_state = ctx->newstate;
    if (ctx->family == TRACELENS_AF_INET) {
        __builtin_memcpy(state.local_addr, ctx->saddr, 4);
        __builtin_memcpy(state.remote_addr, ctx->daddr, 4);
    } else {
        __builtin_memcpy(state.local_addr, ctx->saddr_v6, sizeof(state.local_addr));
        __builtin_memcpy(state.remote_addr, ctx->daddr_v6, sizeof(state.remote_addr));
    }

    key_by_socket = bpf_map_lookup_elem(&sockets_by_kernel_address, &socket_address);
    if (!key_by_socket) {
        tuple.pid = pid;
        tuple.family = ctx->family;
        tuple.remote_port = ctx->dport;
        if (ctx->family == TRACELENS_AF_INET) {
            __builtin_memcpy(tuple.remote_addr, ctx->daddr, 4);
        } else {
            __builtin_memcpy(tuple.remote_addr, ctx->daddr_v6, sizeof(tuple.remote_addr));
        }
        key_by_remote = bpf_map_lookup_elem(&connections_by_remote, &tuple);
        if (!key_by_remote) {
            if (pid == 0) {
                return 0;
            }
            emit_network_event(&state);
            return 0;
        }
        bpf_map_update_elem(&sockets_by_kernel_address, &socket_address, key_by_remote, BPF_ANY);
        key_by_socket = key_by_remote;
    }

    active = bpf_map_lookup_elem(&active_connections, key_by_socket);
    if (!active) {
        if (pid == 0) {
            return 0;
        }
        emit_network_event(&state);
        return 0;
    }

    active->event_type = state.event_type;
    active->family = state.family;
    active->protocol = state.protocol;
    active->local_port = state.local_port;
    active->remote_port = state.remote_port;
    active->old_state = state.old_state;
    active->new_state = state.new_state;
    __builtin_memcpy(active->local_addr, state.local_addr, sizeof(active->local_addr));
    __builtin_memcpy(active->remote_addr, state.remote_addr, sizeof(active->remote_addr));
    emit_network_event(active);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracelens_close(struct trace_event_raw_sys_close *ctx)
{
    struct tracelens_socket_key key = {};
    struct tracelens_network_event *active;
    struct tracelens_tuple_key tuple = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    key.pid = pid_tgid >> 32;
    key.fd = (__u32)ctx->fd;
    active = bpf_map_lookup_elem(&active_connections, &key);
    if (!active) {
        return 0;
    }

    {
        struct tracelens_network_event event = *active;
        event.event_type = TRACELENS_EVENT_TCP_CLOSE;
        event.old_state = active->new_state;
        event.new_state = 7;
        emit_network_event(&event);
    }
    make_remote_key(&tuple, key.pid, active);
    bpf_map_delete_elem(&connections_by_remote, &tuple);
    bpf_map_delete_elem(&active_connections, &key);
    return 0;
}

static __always_inline int remember_io(struct trace_event_raw_sys_enter *ctx, __u8 direction)
{
    struct tracelens_io_request request = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    request.pid = pid_tgid >> 32;
    request.fd = (__u32)ctx->args[0];
    request.direction = direction;
    bpf_map_update_elem(&pending_io, &pid_tgid, &request, BPF_ANY);
    return 0;
}

static __always_inline int account_io(struct trace_event_raw_sys_exit *ctx)
{
    struct tracelens_io_request *request;
    struct tracelens_socket_key key = {};
    struct tracelens_network_event *active;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    request = bpf_map_lookup_elem(&pending_io, &pid_tgid);
    if (!request) {
        return 0;
    }

    if (ctx->ret > 0) {
        key.pid = request->pid;
        key.fd = request->fd;
        active = bpf_map_lookup_elem(&active_connections, &key);
        if (active) {
            if (request->direction == 0) {
                active->sent_bytes += (__u64)ctx->ret;
            } else {
                active->received_bytes += (__u64)ctx->ret;
            }
            active->event_type = TRACELENS_EVENT_TCP_BYTES;
            emit_network_event(active);
        }
    }

    bpf_map_delete_elem(&pending_io, &pid_tgid);
    return 0;
}

#define TRACELENS_IO_HOOKS(prefix, direction) \
SEC("tracepoint/syscalls/sys_enter_" #prefix) \
int tracelens_##prefix##_enter(struct trace_event_raw_sys_enter *ctx) \
{ \
    return remember_io(ctx, direction); \
} \
SEC("tracepoint/syscalls/sys_exit_" #prefix) \
int tracelens_##prefix##_exit(struct trace_event_raw_sys_exit *ctx) \
{ \
    return account_io(ctx); \
}

TRACELENS_IO_HOOKS(sendto, 0)
TRACELENS_IO_HOOKS(recvfrom, 1)
TRACELENS_IO_HOOKS(sendmsg, 0)
TRACELENS_IO_HOOKS(recvmsg, 1)
TRACELENS_IO_HOOKS(write, 0)
TRACELENS_IO_HOOKS(read, 1)

char LICENSE[] SEC("license") = "GPL";
