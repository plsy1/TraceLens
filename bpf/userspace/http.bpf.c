#include "common.h"
#include <linux/ptrace.h>
#include <bpf/bpf_tracing.h>

struct http_call {
    __u64 ssl_object;
    const void *buffer;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct http_call);
} read_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_http_capture(
    __u16 direction,
    __u64 ssl_object,
    const void *buffer,
    __s32 length)
{
    struct tracelens_http_capture_event *event;
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
    event->event_type = TRACELENS_EVENT_HTTP_CAPTURE;
    event->direction = direction;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = ssl_object;
    event->fd = -1;
    event->payload_size = payload_size;
    event->truncated = payload_size > TRACELENS_PLAINTEXT_MAX_LEN;
    if (payload_size > TRACELENS_PLAINTEXT_MAX_LEN) {
        payload_size = TRACELENS_PLAINTEXT_MAX_LEN;
    }
    bpf_probe_read_user(event->payload, payload_size, buffer);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe/SSL_read")
int tracelens_http_read_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct http_call call = {
        .ssl_object = (__u64)PT_REGS_PARM1(ctx),
        .buffer = (const void *)PT_REGS_PARM2(ctx),
    };

    bpf_map_update_elem(&read_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int tracelens_http_read_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct http_call *call = bpf_map_lookup_elem(&read_calls, &pid_tgid);
    __s32 result = (__s32)PT_REGS_RC(ctx);

    if (call && result > 0) {
        emit_http_capture(
            TRACELENS_PLAINTEXT_READ,
            call->ssl_object,
            call->buffer,
            result);
    }
    bpf_map_delete_elem(&read_calls, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_write")
int tracelens_http_write(struct pt_regs *ctx)
{
    return emit_http_capture(
        TRACELENS_PLAINTEXT_WRITE,
        (__u64)PT_REGS_PARM1(ctx),
        (const void *)PT_REGS_PARM2(ctx),
        (__s32)PT_REGS_PARM3(ctx));
}

char LICENSE[] SEC("license") = "GPL";
