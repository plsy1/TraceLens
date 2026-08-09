#include "common.h"
#include <linux/ptrace.h>
#include <bpf/bpf_tracing.h>

struct plaintext_call {
    __u64 ssl_object;
    const void *buffer;
    const __u64 *result_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct plaintext_call);
} read_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct plaintext_call);
} ex_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_metadata(
    __u16 metadata_kind,
    __u16 api_id,
    const char *text,
    __s32 fd,
    __u64 ssl_object)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = metadata_kind;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = ssl_object;
    event->fd = fd;
    event->reserved = api_id;
    if (text) {
        if (metadata_kind == TRACELENS_TLS_METADATA_SNI) {
            bpf_probe_read_user_str(event->sni, sizeof(event->sni), text);
        } else if (metadata_kind == TRACELENS_TLS_METADATA_VERSION) {
            bpf_probe_read_user_str(event->version, sizeof(event->version), text);
        }
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_plaintext(
    __u16 direction,
    __u16 api_id,
    __u64 ssl_object,
    const void *buffer,
    __s32 length)
{
    struct tracelens_plaintext_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 payload_size;

    if (!buffer || length <= 0) {
        return 0;
    }
    payload_size = (__u32)length;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    event->event_type = TRACELENS_EVENT_PLAINTEXT;
    event->direction = direction | (api_id << 8);
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = ssl_object;
    event->fd = -1;
    event->payload_size = payload_size;
    event->truncated = payload_size > TRACELENS_PLAINTEXT_MAX_LEN;
    if (payload_size > TRACELENS_PLAINTEXT_MAX_LEN) {
        payload_size = TRACELENS_PLAINTEXT_MAX_LEN;
    }
    if (bpf_probe_read_user(event->payload, payload_size, buffer) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe/SSL_connect")
int tracelens_openssl_connect(struct pt_regs *ctx)
{
    return emit_metadata(
        TRACELENS_TLS_METADATA_HANDSHAKE,
        TRACELENS_TLS_API_OPENSSL_CONNECT,
        0,
        -1,
        (__u64)PT_REGS_PARM1(ctx));
}

SEC("uretprobe/SSL_get_servername")
int tracelens_tls_servername(struct pt_regs *ctx)
{
    return emit_metadata(
        TRACELENS_TLS_METADATA_SNI,
        TRACELENS_TLS_API_OPENSSL_GET_SERVERNAME,
        (const char *)PT_REGS_RC(ctx),
        -1,
        0);
}

SEC("uretprobe/SSL_get_version")
int tracelens_tls_version(struct pt_regs *ctx)
{
    return emit_metadata(
        TRACELENS_TLS_METADATA_VERSION,
        TRACELENS_TLS_API_OPENSSL_GET_VERSION,
        (const char *)PT_REGS_RC(ctx),
        -1,
        0);
}

SEC("uretprobe/SSL_get_fd")
int tracelens_tls_fd(struct pt_regs *ctx)
{
    return emit_metadata(
        TRACELENS_TLS_METADATA_FD,
        TRACELENS_TLS_API_OPENSSL_GET_FD,
        0,
        (__s32)PT_REGS_RC(ctx),
        0);
}

SEC("uprobe/SSL_set_fd")
int tracelens_tls_set_fd(struct pt_regs *ctx)
{
    return emit_metadata(
        TRACELENS_TLS_METADATA_FD,
        TRACELENS_TLS_API_OPENSSL_SET_FD,
        0,
        (__s32)PT_REGS_PARM2(ctx),
        (__u64)PT_REGS_PARM1(ctx));
}

SEC("uprobe/SSL_read")
int tracelens_plaintext_read_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct plaintext_call call = {
        .ssl_object = (__u64)PT_REGS_PARM1(ctx),
        .buffer = (const void *)PT_REGS_PARM2(ctx),
        .result_size = 0,
    };

    bpf_map_update_elem(&read_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

SEC("uprobe/SSL_read_ex")
int tracelens_plaintext_read_ex_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct plaintext_call call = {
        .ssl_object = (__u64)PT_REGS_PARM1(ctx),
        .buffer = (const void *)PT_REGS_PARM2(ctx),
        .result_size = (const __u64 *)PT_REGS_PARM4(ctx),
    };

    bpf_map_update_elem(&ex_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int tracelens_plaintext_read_ex_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct plaintext_call *call = bpf_map_lookup_elem(&ex_calls, &pid_tgid);
    __u64 result_size = 0;

    if (call && PT_REGS_RC(ctx) == 1 && call->result_size &&
        bpf_probe_read_user(&result_size, sizeof(result_size), call->result_size) == 0) {
        emit_plaintext(
            TRACELENS_PLAINTEXT_READ,
            TRACELENS_TLS_API_OPENSSL_READ_EX,
            call->ssl_object,
            call->buffer,
            result_size > 0x7fffffffULL ? 0x7fffffff : (__s32)result_size);
    }
    bpf_map_delete_elem(&ex_calls, &pid_tgid);
    return 0;
}

SEC("uretprobe/SSL_read")
int tracelens_plaintext_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct plaintext_call *call = bpf_map_lookup_elem(&read_calls, &pid_tgid);
    __s32 result = (__s32)PT_REGS_RC(ctx);

    if (call && result > 0) {
        emit_plaintext(
            TRACELENS_PLAINTEXT_READ,
            TRACELENS_TLS_API_OPENSSL_READ,
            call->ssl_object,
            call->buffer,
            result);
    }
    bpf_map_delete_elem(&read_calls, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_write")
int tracelens_plaintext_write(struct pt_regs *ctx)
{
    return emit_plaintext(
        TRACELENS_PLAINTEXT_WRITE,
        TRACELENS_TLS_API_OPENSSL_WRITE,
        (__u64)PT_REGS_PARM1(ctx),
        (const void *)PT_REGS_PARM2(ctx),
        (__s32)PT_REGS_PARM3(ctx));
}

SEC("uprobe/SSL_write_ex")
int tracelens_plaintext_write_ex_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct plaintext_call call = {
        .ssl_object = (__u64)PT_REGS_PARM1(ctx),
        .buffer = (const void *)PT_REGS_PARM2(ctx),
        .result_size = (const __u64 *)PT_REGS_PARM4(ctx),
    };

    bpf_map_update_elem(&ex_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int tracelens_plaintext_write_ex_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct plaintext_call *call = bpf_map_lookup_elem(&ex_calls, &pid_tgid);
    __u64 result_size = 0;

    if (call && PT_REGS_RC(ctx) == 1 && call->result_size &&
        bpf_probe_read_user(&result_size, sizeof(result_size), call->result_size) == 0) {
        emit_plaintext(
            TRACELENS_PLAINTEXT_WRITE,
            TRACELENS_TLS_API_OPENSSL_WRITE_EX,
            call->ssl_object,
            call->buffer,
            result_size > 0x7fffffffULL ? 0x7fffffff : (__s32)result_size);
    }
    bpf_map_delete_elem(&ex_calls, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
