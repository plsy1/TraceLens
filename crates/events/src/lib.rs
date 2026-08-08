//! Shared event ABI between probes, the core service, and the UI/API layer.

use serde::{Deserialize, Serialize};

pub type EventId = String;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Kernel,
    Bpftime,
    Core,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessExec,
    ProcessExit,
    TcpConnect,
    TcpClose,
    DnsQuery,
    DnsResponse,
    ObservationChanged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Connecting,
    Established,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessRef {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub executable: Option<String>,
    pub command_line: Option<String>,
    pub start_time_ns: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionRef {
    pub id: String,
    pub protocol: TransportProtocol,
    pub local: Option<Endpoint>,
    pub remote: Endpoint,
    pub state: ConnectionState,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum EventPayload {
    Empty,
    Process {
        executable: String,
        command_line: String,
    },
    Connection {
        connection: ConnectionRef,
    },
    Dns {
        domain: String,
        addresses: Vec<String>,
    },
    Observation {
        target: String,
        level: u8,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    pub id: EventId,
    pub timestamp_ns: u64,
    pub source: EventSource,
    pub kind: EventKind,
    pub pid: Option<u32>,
    pub process: Option<ProcessRef>,
    pub connection: Option<ConnectionRef>,
    pub payload: EventPayload,
}

impl TraceEvent {
    pub fn process_exec(pid: u32, executable: &str, command_line: &str, timestamp_ns: u64) -> Self {
        Self::process_event(
            EventSource::Core,
            EventKind::ProcessExec,
            pid,
            None,
            executable,
            command_line,
            timestamp_ns,
        )
    }

    pub fn process_event(
        source: EventSource,
        kind: EventKind,
        pid: u32,
        ppid: Option<u32>,
        executable: &str,
        command_line: &str,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!("process-{kind:?}-{pid}-{timestamp_ns}"),
            timestamp_ns,
            source,
            kind,
            pid: Some(pid),
            process: Some(ProcessRef {
                pid,
                ppid,
                executable: Some(executable.to_owned()),
                command_line: Some(command_line.to_owned()),
                start_time_ns: Some(timestamp_ns),
            }),
            connection: None,
            payload: EventPayload::Process {
                executable: executable.to_owned(),
                command_line: command_line.to_owned(),
            },
        }
    }

    pub fn connection_event(
        source: EventSource,
        kind: EventKind,
        pid: u32,
        connection: ConnectionRef,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!("connection-{kind:?}-{}-{timestamp_ns}", connection.id),
            timestamp_ns,
            source,
            kind,
            pid: Some(pid),
            process: None,
            connection: Some(connection.clone()),
            payload: EventPayload::Connection { connection },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventKind, EventSource, TraceEvent};

    #[test]
    fn process_exec_uses_the_shared_core_schema() {
        let event = TraceEvent::process_exec(7, "curl", "curl https://example.com", 42);

        assert_eq!(event.source, EventSource::Core);
        assert_eq!(event.kind, EventKind::ProcessExec);
        assert_eq!(event.pid, Some(7));
    }
}
