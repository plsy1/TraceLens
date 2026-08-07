use tracelens_events::ProcessRef;

#[derive(Debug, Clone)]
pub struct ProcessRecord {
    pub identity: ProcessRef,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}
