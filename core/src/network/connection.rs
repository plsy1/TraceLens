use tracelens_events::{ConnectionRef, ProcessRef};

#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub pid: Option<u32>,
    pub process: Option<ProcessRef>,
    pub connection: ConnectionRef,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}
