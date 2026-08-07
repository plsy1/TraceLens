use std::collections::HashMap;

use tracelens_events::ConnectionRef;

use super::ConnectionRecord;

#[derive(Debug, Default)]
pub struct ConnectionTracker {
    connections: HashMap<String, ConnectionRecord>,
}

impl ConnectionTracker {
    pub fn observe(&mut self, connection: ConnectionRef, timestamp_ns: u64) {
        self.connections
            .entry(connection.id.clone())
            .and_modify(|record| {
                record.connection = connection.clone();
                record.last_seen_ns = timestamp_ns;
            })
            .or_insert(ConnectionRecord {
                connection,
                first_seen_ns: timestamp_ns,
                last_seen_ns: timestamp_ns,
            });
    }

    pub fn get(&self, id: &str) -> Option<&ConnectionRecord> {
        self.connections.get(id)
    }
}
