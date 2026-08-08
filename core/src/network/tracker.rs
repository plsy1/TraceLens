use std::collections::HashMap;

use tracelens_events::{ConnectionRef, ProcessRef, TcpState};

use super::ConnectionRecord;

#[derive(Debug, Default)]
pub struct ConnectionTracker {
    connections: HashMap<String, ConnectionRecord>,
}

impl ConnectionTracker {
    pub fn observe(
        &mut self,
        pid: Option<u32>,
        process: Option<ProcessRef>,
        mut connection: ConnectionRef,
        timestamp_ns: u64,
    ) {
        let existing_id = if self.connections.contains_key(&connection.id) {
            None
        } else {
            self.connections
                .iter()
                .find(|(_, record)| {
                    record.pid == pid
                        && record.connection.remote == connection.remote
                        && (connection.local.is_none()
                            || record.connection.local.is_none()
                            || record.connection.local == connection.local)
                })
                .map(|(id, _)| id.clone())
        };
        if let Some(existing_id) = existing_id {
            connection.id = existing_id;
        }
        self.connections
            .entry(connection.id.clone())
            .and_modify(|record| {
                record.pid = pid.or(record.pid);
                record.process = process.clone().or_else(|| record.process.clone());
                if connection.domain.is_none() {
                    connection.domain.clone_from(&record.connection.domain);
                }
                if connection.local.is_none() {
                    connection.local.clone_from(&record.connection.local);
                }
                if connection.tcp_state.is_none() {
                    connection
                        .tcp_state
                        .clone_from(&record.connection.tcp_state);
                }
                if matches!(
                    connection.tcp_state,
                    Some(TcpState::SynSent | TcpState::SynRecv)
                ) && record.connection.tcp_state == Some(TcpState::Established)
                {
                    connection.tcp_state = Some(TcpState::Established);
                    connection.state = record.connection.state;
                }
                if connection.state == tracelens_events::ConnectionState::Connecting
                    && record.connection.state == tracelens_events::ConnectionState::Established
                {
                    connection.state = record.connection.state;
                }
                connection.sent_bytes = connection.sent_bytes.max(record.connection.sent_bytes);
                connection.received_bytes = connection
                    .received_bytes
                    .max(record.connection.received_bytes);
                record.connection = connection.clone();
                record.last_seen_ns = timestamp_ns;
            })
            .or_insert(ConnectionRecord {
                pid,
                process,
                connection,
                first_seen_ns: timestamp_ns,
                last_seen_ns: timestamp_ns,
            });
    }

    pub fn set_domain(&mut self, pid: u32, addresses: &[String], domain: &str) {
        for record in self.connections.values_mut() {
            if record.pid == Some(pid)
                && addresses
                    .iter()
                    .any(|address| address == &record.connection.remote.address)
            {
                record.connection.domain = Some(domain.to_owned());
            }
        }
    }

    pub fn set_domain_for_addresses(&mut self, addresses: &[String], domain: &str) {
        for record in self.connections.values_mut() {
            if record.connection.domain.is_none()
                && addresses
                    .iter()
                    .any(|address| address == &record.connection.remote.address)
            {
                record.connection.domain = Some(domain.to_owned());
            }
        }
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

#[cfg(test)]
mod tests {
    use tracelens_events::{
        ConnectionRef, ConnectionState, Endpoint, ProcessRef, TcpState, TransportProtocol,
    };

    use super::ConnectionTracker;

    fn connection(id: &str, local: Option<Endpoint>, state: ConnectionState) -> ConnectionRef {
        ConnectionRef {
            id: id.to_owned(),
            protocol: TransportProtocol::Tcp,
            local,
            remote: Endpoint {
                address: "198.51.100.10".to_owned(),
                port: 443,
            },
            state,
            tcp_state: Some(TcpState::Established),
            sent_bytes: 0,
            received_bytes: 0,
            domain: None,
        }
    }

    #[test]
    fn process_snapshot_survives_close_event() {
        let process = ProcessRef {
            pid: 42,
            ppid: Some(1),
            executable: Some("curl".to_owned()),
            command_line: Some("curl https://example.com".to_owned()),
            start_time_ns: Some(1),
        };
        let mut tracker = ConnectionTracker::default();
        tracker.observe(
            Some(42),
            Some(process.clone()),
            connection("socket-1", None, ConnectionState::Established),
            1,
        );
        tracker.observe(
            Some(42),
            None,
            connection("socket-1", None, ConnectionState::Closed),
            2,
        );

        let record = tracker.get("socket-1").expect("connection record");
        assert_eq!(record.process.as_ref(), Some(&process));
        assert_eq!(record.connection.state, ConnectionState::Closed);
    }

    #[test]
    fn state_event_reuses_connection_by_pid_and_remote_endpoint() {
        let mut tracker = ConnectionTracker::default();
        tracker.observe(
            Some(42),
            None,
            connection("socket-42-7", None, ConnectionState::Connecting),
            1,
        );
        tracker.observe(
            Some(42),
            None,
            connection(
                "socket-kernel-address",
                Some(Endpoint {
                    address: "127.0.0.1".to_owned(),
                    port: 51515,
                }),
                ConnectionState::Established,
            ),
            2,
        );

        assert_eq!(tracker.len(), 1);
        let record = tracker.get("socket-42-7").expect("merged connection");
        assert_eq!(
            record
                .connection
                .local
                .as_ref()
                .map(|endpoint| endpoint.port),
            Some(51515)
        );
        assert_eq!(record.connection.state, ConnectionState::Established);
    }
}
