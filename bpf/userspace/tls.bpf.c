#include "common.h"
#include <linux/ptrace.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_metadata(
    struct pt_regs *ctx,
    __u16 metadata_kind,
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

SEC("uretprobe/SSL_get_servername")
int tracelens_tls_servername(struct pt_regs *ctx)
{
    return emit_metadata(
        ctx,
        TRACELENS_TLS_METADATA_SNI,
        (const char *)PT_REGS_RC(ctx),
        -1,
        0);
}

SEC("uretprobe/SSL_get_version")
int tracelens_tls_version(struct pt_regs *ctx)
{
    return emit_metadata(
        ctx,
        TRACELENS_TLS_METADATA_VERSION,
        (const char *)PT_REGS_RC(ctx),
        -1,
        0);
}

SEC("uretprobe/SSL_get_fd")
int tracelens_tls_fd(struct pt_regs *ctx)
{
    return emit_metadata(
        ctx,
        TRACELENS_TLS_METADATA_FD,
        0,
        (__s32)PT_REGS_RC(ctx),
        0);
}

SEC("uprobe/SSL_set_fd")
int tracelens_tls_set_fd(struct pt_regs *ctx)
{
    return emit_metadata(
        ctx,
        TRACELENS_TLS_METADATA_FD,
        0,
        (__s32)PT_REGS_PARM2(ctx),
        (__u64)PT_REGS_PARM1(ctx));
}

char LICENSE[] SEC("license") = "GPL";
