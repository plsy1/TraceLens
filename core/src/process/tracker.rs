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
            .and_modify(|record| record.last_seen_ns = timestamp_ns)
            .or_insert(ProcessRecord {
                identity: process,
                first_seen_ns: timestamp_ns,
                last_seen_ns: timestamp_ns,
            });
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessRecord> {
        self.processes.get(&pid)
    }

    pub fn all(&self) -> impl Iterator<Item = &ProcessRecord> {
        self.processes.values()
    }
}
