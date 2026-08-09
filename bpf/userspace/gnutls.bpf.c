#include "common.h"
#include <linux/ptrace.h>
#include <bpf/bpf_tracing.h>

struct gnutls_record_call {
    __u64 session;
    const void *buffer;
    __u16 direction;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct gnutls_record_call);
} record_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} protocol_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_metadata(__u16 kind, __u16 api_id, __u64 session, __s32 fd)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = kind;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = session;
    event->fd = fd;
    event->reserved = api_id;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_plaintext(struct gnutls_record_call *call, __s64 result)
{
    struct tracelens_plaintext_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 payload_size;

    if (!call || !call->buffer || result <= 0) {
        return 0;
    }
    payload_size = result > 0xffffffffLL ? 0xffffffffU : (__u32)result;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    event->event_type = TRACELENS_EVENT_PLAINTEXT;
    event->direction = call->direction |
        ((call->direction == TRACELENS_PLAINTEXT_READ
              ? TRACELENS_TLS_API_GNUTLS_RECV
              : TRACELENS_TLS_API_GNUTLS_SEND)
         << 8);
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = call->session;
    event->fd = -1;
    event->payload_size = payload_size;
    event->truncated = payload_size > TRACELENS_PLAINTEXT_MAX_LEN;
    if (payload_size > TRACELENS_PLAINTEXT_MAX_LEN) {
        payload_size = TRACELENS_PLAINTEXT_MAX_LEN;
    }
    if (bpf_probe_read_user(event->payload, payload_size, call->buffer) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_sni(__u64 session, const void *data, __u64 size)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 copy_size = size >= TRACELENS_TLS_NAME_LEN
        ? TRACELENS_TLS_NAME_LEN - 1
        : (__u32)size;

    if (!data || copy_size == 0) {
        return 0;
    }
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = TRACELENS_TLS_METADATA_SNI;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = session;
    event->fd = -1;
    event->reserved = TRACELENS_TLS_API_GNUTLS_SERVER_NAME;
    if (bpf_probe_read_user(event->sni, copy_size, data) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_protocol(__u64 session, __s64 protocol)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = TRACELENS_TLS_METADATA_VERSION;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = session;
    event->fd = -1;
    event->reserved = TRACELENS_TLS_API_GNUTLS_PROTOCOL;
    if (protocol == 1) {
        __builtin_memcpy(event->version, "SSL 3.0", 8);
    } else if (protocol == 2) {
        __builtin_memcpy(event->version, "TLS 1.0", 8);
    } else if (protocol == 3) {
        __builtin_memcpy(event->version, "TLS 1.1", 8);
    } else if (protocol == 4) {
        __builtin_memcpy(event->version, "TLS 1.2", 8);
    } else if (protocol == 5) {
        __builtin_memcpy(event->version, "TLS 1.3", 8);
    } else if (protocol == 200) {
        __builtin_memcpy(event->version, "DTLS 0.9", 9);
    } else if (protocol == 201) {
        __builtin_memcpy(event->version, "DTLS 1.0", 9);
    } else if (protocol == 202) {
        __builtin_memcpy(event->version, "DTLS 1.2", 9);
    } else {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int remember_record(struct pt_regs *ctx, __u16 direction)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct gnutls_record_call call = {
        .session = (__u64)PT_REGS_PARM1(ctx),
        .buffer = (const void *)PT_REGS_PARM2(ctx),
        .direction = direction,
    };
    bpf_map_update_elem(&record_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

static __always_inline int finish_record(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct gnutls_record_call *call = bpf_map_lookup_elem(&record_calls, &pid_tgid);
    emit_plaintext(call, (__s64)PT_REGS_RC(ctx));
    bpf_map_delete_elem(&record_calls, &pid_tgid);
    return 0;
}

SEC("uprobe/gnutls_record_recv")
int tracelens_gnutls_recv_enter(struct pt_regs *ctx)
{
    return remember_record(ctx, TRACELENS_PLAINTEXT_READ);
}

SEC("uretprobe/gnutls_record_recv")
int tracelens_gnutls_recv_exit(struct pt_regs *ctx)
{
    return finish_record(ctx);
}

SEC("uprobe/gnutls_record_send")
int tracelens_gnutls_send_enter(struct pt_regs *ctx)
{
    return remember_record(ctx, TRACELENS_PLAINTEXT_WRITE);
}

SEC("uretprobe/gnutls_record_send")
int tracelens_gnutls_send_exit(struct pt_regs *ctx)
{
    return finish_record(ctx);
}

SEC("uprobe/gnutls_handshake")
int tracelens_gnutls_handshake(struct pt_regs *ctx)
{
    return emit_metadata(
        TRACELENS_TLS_METADATA_HANDSHAKE,
        TRACELENS_TLS_API_GNUTLS_HANDSHAKE,
        (__u64)PT_REGS_PARM1(ctx),
        -1);
}

SEC("uprobe/gnutls_transport_set_int2")
int tracelens_gnutls_set_fd(struct pt_regs *ctx)
{
    return emit_metadata(
        TRACELENS_TLS_METADATA_FD,
        TRACELENS_TLS_API_GNUTLS_SET_FD,
        (__u64)PT_REGS_PARM1(ctx),
        (__s32)PT_REGS_PARM2(ctx));
}

SEC("uprobe/gnutls_server_name_set")
int tracelens_gnutls_server_name_set(struct pt_regs *ctx)
{
    return emit_sni(
        (__u64)PT_REGS_PARM1(ctx),
        (const void *)PT_REGS_PARM3(ctx),
        (__u64)PT_REGS_PARM4(ctx));
}

SEC("uprobe/gnutls_protocol_get_version")
int tracelens_gnutls_protocol_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 session = (__u64)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&protocol_calls, &pid_tgid, &session, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_protocol_get_version")
int tracelens_gnutls_protocol_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *session = bpf_map_lookup_elem(&protocol_calls, &pid_tgid);
    if (session) {
        emit_protocol(*session, (__s64)PT_REGS_RC(ctx));
    }
    bpf_map_delete_elem(&protocol_calls, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
