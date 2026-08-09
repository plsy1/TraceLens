#ifndef TRACELENS_CAPTURE_FILTER_H
#define TRACELENS_CAPTURE_FILTER_H

#define TRACELENS_SCOPE_GLOBAL 0
#define TRACELENS_SCOPE_PID 1
#define TRACELENS_SCOPE_COMM 2

struct tracelens_capture_config {
    __u32 active;
    __u32 scope_mode;
    __u32 target_pid;
    char target_comm[TRACELENS_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tracelens_capture_config);
} capture_config SEC(".maps");

static __always_inline int capture_comm_matches(
    const char current[TRACELENS_COMM_LEN],
    const char expected[TRACELENS_COMM_LEN])
{
#pragma unroll
    for (int index = 0; index < TRACELENS_COMM_LEN; index++) {
        if (current[index] != expected[index]) {
            return 0;
        }
        if (expected[index] == '\0') {
            return 1;
        }
    }
    return 1;
}

static __always_inline int capture_matches_current(void)
{
    struct tracelens_capture_config *config;
    __u32 key = 0;
    __u32 pid;

    config = bpf_map_lookup_elem(&capture_config, &key);
    if (!config || !config->active) {
        return 0;
    }
    if (config->scope_mode == TRACELENS_SCOPE_GLOBAL) {
        return 1;
    }

    pid = bpf_get_current_pid_tgid() >> 32;
    if (config->scope_mode == TRACELENS_SCOPE_PID) {
        return pid == config->target_pid;
    }
    if (config->scope_mode == TRACELENS_SCOPE_COMM) {
        char comm[TRACELENS_COMM_LEN] = {};
        if (bpf_get_current_comm(comm, sizeof(comm)) < 0) {
            return 0;
        }
        return capture_comm_matches(comm, config->target_comm);
    }
    return 0;
}

#ifdef TRACELENS_CAPTURE_DEPENDENCIES
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u8);
} dependency_pids SEC(".maps");

static __always_inline int capture_dns_matches_current(void)
{
    struct tracelens_capture_config *config;
    __u32 config_key = 0;
    __u32 pid;

    config = bpf_map_lookup_elem(&capture_config, &config_key);
    if (!config || !config->active) {
        return 0;
    }
    if (capture_matches_current()) {
        return 1;
    }
    pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&dependency_pids, &pid) != 0;
}
#endif

#endif
