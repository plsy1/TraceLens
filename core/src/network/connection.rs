use tracelens_events::ConnectionRef;

#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub connection: ConnectionRef,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}
