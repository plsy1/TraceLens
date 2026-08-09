#include "common.h"
#include <linux/ptrace.h>
#include <bpf/bpf_tracing.h>

struct nspr_call {
    __u64 ssl_object;
    const void *buffer;
    __u16 direction;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} tls_file_descriptors SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct nspr_call);
} nspr_calls SEC(".maps");

struct nss_channel_call {
    __u64 ssl_object;
    const void *info;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct nss_channel_call);
} channel_calls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_import(__u64 ssl_object)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!ssl_object) return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = TRACELENS_TLS_METADATA_HANDSHAKE;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = ssl_object;
    event->fd = -1;
    event->reserved = TRACELENS_TLS_API_NSS_IMPORT_FD;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_sni(__u64 ssl_object, const char *url)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!ssl_object || !url) return 0;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = TRACELENS_TLS_METADATA_SNI;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = ssl_object;
    event->fd = -1;
    event->reserved = TRACELENS_TLS_API_NSS_SET_URL;
    bpf_probe_read_user_str(event->sni, sizeof(event->sni), url);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int emit_version(__u64 ssl_object, __u16 version)
{
    struct tracelens_tls_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->event_type = TRACELENS_EVENT_TLS_METADATA;
    event->metadata_kind = TRACELENS_TLS_METADATA_VERSION;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = ssl_object;
    event->fd = -1;
    event->reserved = TRACELENS_TLS_API_NSS_CHANNEL_INFO;
    if (version == 0x0301)
        __builtin_memcpy(event->version, "TLS 1.0", 8);
    else if (version == 0x0302)
        __builtin_memcpy(event->version, "TLS 1.1", 8);
    else if (version == 0x0303)
        __builtin_memcpy(event->version, "TLS 1.2", 8);
    else if (version == 0x0304)
        __builtin_memcpy(event->version, "TLS 1.3", 8);
    else {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int remember_nspr_call(struct pt_regs *ctx, __u16 direction)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 descriptor = (__u64)PT_REGS_PARM1(ctx);
    struct nspr_call call = {
        .ssl_object = descriptor,
        .buffer = (const void *)PT_REGS_PARM2(ctx),
        .direction = direction,
    };

    if (!bpf_map_lookup_elem(&tls_file_descriptors, &descriptor)) return 0;
    bpf_map_update_elem(&nspr_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

static __always_inline int finish_nspr_call(struct pt_regs *ctx)
{
    struct tracelens_plaintext_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct nspr_call *call = bpf_map_lookup_elem(&nspr_calls, &pid_tgid);
    __s64 result = (__s64)PT_REGS_RC(ctx);
    __u32 payload_size;
    __u16 api_id;

    if (!call || result <= 0) {
        bpf_map_delete_elem(&nspr_calls, &pid_tgid);
        return 0;
    }
    payload_size = result > 0xffffffffLL ? 0xffffffffU : (__u32)result;
    api_id = call->direction == TRACELENS_PLAINTEXT_READ
        ? TRACELENS_TLS_API_NSPR_READ
        : TRACELENS_TLS_API_NSPR_WRITE;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&nspr_calls, &pid_tgid);
        return 0;
    }
    event->event_type = TRACELENS_EVENT_PLAINTEXT;
    event->direction = call->direction | (api_id << 8);
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->ssl_object = call->ssl_object;
    event->fd = -1;
    event->payload_size = payload_size;
    event->truncated = payload_size > TRACELENS_PLAINTEXT_MAX_LEN;
    if (payload_size > TRACELENS_PLAINTEXT_MAX_LEN)
        payload_size = TRACELENS_PLAINTEXT_MAX_LEN;
    if (bpf_probe_read_user(event->payload, payload_size, call->buffer) < 0)
        bpf_ringbuf_discard(event, 0);
    else
        bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&nspr_calls, &pid_tgid);
    return 0;
}

SEC("uretprobe/SSL_ImportFD")
int tracelens_nss_import_fd(struct pt_regs *ctx)
{
    __u64 descriptor = (__u64)PT_REGS_RC(ctx);
    __u8 tracked = 1;
    if (descriptor) {
        bpf_map_update_elem(&tls_file_descriptors, &descriptor, &tracked, BPF_ANY);
        emit_import(descriptor);
    }
    return 0;
}

SEC("uprobe/SSL_SetURL")
int tracelens_nss_set_url(struct pt_regs *ctx)
{
    return emit_sni((__u64)PT_REGS_PARM1(ctx), (const char *)PT_REGS_PARM2(ctx));
}

SEC("uprobe/SSL_GetChannelInfo")
int tracelens_nss_channel_info_enter(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct nss_channel_call call = {
        .ssl_object = (__u64)PT_REGS_PARM1(ctx),
        .info = (const void *)PT_REGS_PARM2(ctx),
    };
    bpf_map_update_elem(&channel_calls, &pid_tgid, &call, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_GetChannelInfo")
int tracelens_nss_channel_info_exit(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct nss_channel_call *call = bpf_map_lookup_elem(&channel_calls, &pid_tgid);
    __u16 version = 0;
    if (call && PT_REGS_RC(ctx) == 0 && call->info &&
        bpf_probe_read_user(&version, sizeof(version), (const char *)call->info + 4) == 0)
        emit_version(call->ssl_object, version);
    bpf_map_delete_elem(&channel_calls, &pid_tgid);
    return 0;
}

SEC("uprobe/PR_Read")
int tracelens_nspr_read_enter(struct pt_regs *ctx)
{
    return remember_nspr_call(ctx, TRACELENS_PLAINTEXT_READ);
}

SEC("uretprobe/PR_Read")
int tracelens_nspr_read_exit(struct pt_regs *ctx)
{
    return finish_nspr_call(ctx);
}

SEC("uprobe/PR_Write")
int tracelens_nspr_write_enter(struct pt_regs *ctx)
{
    return remember_nspr_call(ctx, TRACELENS_PLAINTEXT_WRITE);
}

SEC("uretprobe/PR_Write")
int tracelens_nspr_write_exit(struct pt_regs *ctx)
{
    return finish_nspr_call(ctx);
}

SEC("uprobe/PR_Close")
int tracelens_nspr_close(struct pt_regs *ctx)
{
    __u64 descriptor = (__u64)PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&tls_file_descriptors, &descriptor);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
