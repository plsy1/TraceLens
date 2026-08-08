#include "common.h"

struct trace_event_raw_sys_enter {
    __u64 _unused;
    __u64 syscall_nr;
    __s64 dfd;
    const char *filename;
    __u64 flags;
    __u64 mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracelens_file_open(struct trace_event_raw_sys_enter *ctx)
{
    struct tracelens_file_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->event_type = TRACELENS_EVENT_FILE_OPEN;
    event->reserved = 0;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->bytes = 0;
    if (bpf_probe_read_user_str(event->path, sizeof(event->path), ctx->filename) < 0) {
        event->path[0] = '\0';
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
