#include "common.h"
#include <linux/ptrace.h>
#include <bpf/bpf_tracing.h>

struct rustls_call {
    __u64 connection;
    const void *buffer;
    const __u64 *result_size;
    __u16 direction;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct rustls_call);
} calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("uprobe/rustls_connection_process_new_packets")
int tracelens_rustls_process_packets(struct pt_regs *ctx)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = TRACELENS_TLS_METADATA_HANDSHAKE;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = (__u64)PT_REGS_PARM1(ctx);
    event->fd = -1;
    event->reserved = TRACELENS_TLS_API_RUSTLS_PROCESS_PACKETS;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int remember_call(struct pt_regs *ctx, __u16 direction)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rustls_call call = {
        .connection = (__u64)PT_REGS_PARM1(ctx),
        .buffer = (const void *)PT_REGS_PARM2(ctx),
        .result_size = (const __u64 *)PT_REGS_PARM4(ctx),
        .direction = direction,
    };
    bpf_map_update_elem(&calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

static __always_inline int finish_call(struct pt_regs *ctx)
{
    struct tracelens_plaintext_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rustls_call *call = bpf_map_lookup_elem(&calls, &pid_tgid);
    __u64 result_size = 0;
    __u32 payload_size;
    __u16 api_id;

    /* rustls_result == 0 is success. */
    if (!call || PT_REGS_RC(ctx) != 0 || !call->result_size ||
        bpf_probe_read_user(&result_size, sizeof(result_size), call->result_size) < 0 ||
        result_size == 0) {
        bpf_map_delete_elem(&calls, &pid_tgid);
        return 0;
    }
    payload_size = result_size > 0xffffffffULL ? 0xffffffffU : (__u32)result_size;
    api_id = call->direction == TRACELENS_PLAINTEXT_READ
        ? TRACELENS_TLS_API_RUSTLS_READ
        : TRACELENS_TLS_API_RUSTLS_WRITE;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&calls, &pid_tgid);
        return 0;
    }
    event->event_type = TRACELENS_EVENT_PLAINTEXT;
    event->direction = call->direction | (api_id << 8);
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = call->connection;
    event->fd = -1;
    event->payload_size = payload_size;
    event->truncated = payload_size > TRACELENS_PLAINTEXT_MAX_LEN;
    if (payload_size > TRACELENS_PLAINTEXT_MAX_LEN)
        payload_size = TRACELENS_PLAINTEXT_MAX_LEN;
    if (bpf_probe_read_user(event->payload, payload_size, call->buffer) < 0)
        bpf_ringbuf_discard(event, 0);
    else
        bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&calls, &pid_tgid);
    return 0;
}

SEC("uprobe/rustls_connection_read")
int tracelens_rustls_read_enter(struct pt_regs *ctx)
{
    return remember_call(ctx, TRACELENS_PLAINTEXT_READ);
}

SEC("uretprobe/rustls_connection_read")
int tracelens_rustls_read_exit(struct pt_regs *ctx)
{
    return finish_call(ctx);
}

SEC("uprobe/rustls_connection_write")
int tracelens_rustls_write_enter(struct pt_regs *ctx)
{
    return remember_call(ctx, TRACELENS_PLAINTEXT_WRITE);
}

SEC("uretprobe/rustls_connection_write")
int tracelens_rustls_write_exit(struct pt_regs *ctx)
{
    return finish_call(ctx);
}

char LICENSE[] SEC("license") = "GPL";
