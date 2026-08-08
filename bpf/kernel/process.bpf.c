#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int emit_process_event(__u16 event_type)
{
    struct tracelens_process_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->event_type = event_type;
    event->reserved = 0;
    event->pid = pid_tgid >> 32;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tracelens_process_exec(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return emit_process_event(TRACELENS_EVENT_PROCESS_EXEC);
}

SEC("tracepoint/sched/sched_process_exit")
int tracelens_process_exit(void *ctx)
{
    TRACELENS_UNUSED(ctx);
    return emit_process_event(TRACELENS_EVENT_PROCESS_EXIT);
}

char LICENSE[] SEC("license") = "GPL";
