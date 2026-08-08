use std::collections::HashMap;

use tracelens_events::ConnectionRef;

use super::ConnectionRecord;

#[derive(Debug, Default)]
pub struct ConnectionTracker {
    connections: HashMap<String, ConnectionRecord>,
}

impl ConnectionTracker {
    pub fn observe(&mut self, pid: Option<u32>, connection: ConnectionRef, timestamp_ns: u64) {
        self.connections
            .entry(connection.id.clone())
            .and_modify(|record| {
                record.pid = pid.or(record.pid);
                record.connection = connection.clone();
                record.last_seen_ns = timestamp_ns;
            })
            .or_insert(ConnectionRecord {
                pid,
                connection,
                first_seen_ns: timestamp_ns,
                last_seen_ns: timestamp_ns,
            });
    }

    pub fn get(&self, id: &str) -> Option<&ConnectionRecord> {
        self.connections.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &ConnectionRecord> {
        self.connections.values()
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}
