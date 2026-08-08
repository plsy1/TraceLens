use std::collections::HashMap;

use tracelens_events::ProcessRef;

use super::ProcessRecord;

#[derive(Debug, Default)]
pub struct ProcessTracker {
    processes: HashMap<u32, ProcessRecord>,
}

impl ProcessTracker {
    pub fn observe(&mut self, process: ProcessRef, timestamp_ns: u64) {
        self.processes
            .entry(process.pid)
            .and_modify(|record| {
                record.identity = process.clone();
                record.last_seen_ns = timestamp_ns;
            })
            .or_insert(ProcessRecord {
                identity: process,
                first_seen_ns: timestamp_ns,
                last_seen_ns: timestamp_ns,
            });
    }

    pub fn remove(&mut self, pid: u32) -> Option<ProcessRecord> {
        self.processes.remove(&pid)
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessRecord> {
        self.processes.get(&pid)
    }

    pub fn all(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.processes.values()
    }

    pub fn len(&self) -> usize {
        self.processes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}

/// Recover a process identity for processes that were already running before
/// the observer attached its exec tracepoint.
pub fn read_process_ref(pid: u32, timestamp_ns: u64) -> Option<ProcessRef> {
    #[cfg(target_os = "linux")]
    {
        let executable = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let command_line = std::fs::read(format!("/proc/{pid}/cmdline"))
            .ok()
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .filter(|value| !value.is_empty());
        let ppid = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|status| {
                status.lines().find_map(|line| {
                    line.strip_prefix("PPid:")
                        .and_then(|value| value.trim().parse().ok())
                })
            });
        if executable.is_none() && command_line.is_none() {
            return None;
        }
        Some(ProcessRef {
            pid,
            ppid,
            executable,
            command_line,
            start_time_ns: Some(timestamp_ns),
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, timestamp_ns);
        None
    }
}
