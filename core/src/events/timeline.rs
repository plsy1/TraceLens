use serde::Serialize;
use tracelens_events::{
    ConnectionState, Endpoint, EventKind, EventPayload, EventSource, TcpState, TraceEvent,
    TransportProtocol,
};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TimelineEntry {
    pub id: String,
    pub timestamp_ns: u64,
    pub source: EventSource,
    pub kind: EventKind,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub process_command_line: Option<String>,
    pub summary: String,
    pub domain: Option<String>,
    pub addresses: Vec<String>,
    pub protocol: Option<TransportProtocol>,
    pub connection_id: Option<String>,
    pub remote: Option<Endpoint>,
    pub state: Option<ConnectionState>,
    pub tcp_state: Option<TcpState>,
    pub sent_bytes: Option<u64>,
    pub received_bytes: Option<u64>,
}

impl TimelineEntry {
    pub fn from_event(event: TraceEvent) -> Self {
        let process_name = event
            .process
            .as_ref()
            .and_then(|process| process.executable.clone());
        let process_command_line = event
            .process
            .as_ref()
            .and_then(|process| process.command_line.clone());
        let mut entry = Self {
            id: event.id,
            timestamp_ns: event.timestamp_ns,
            source: event.source,
            kind: event.kind,
            pid: event.pid,
            process_name: process_name.clone(),
            process_command_line,
            summary: String::new(),
            domain: None,
            addresses: Vec::new(),
            protocol: None,
            connection_id: None,
            remote: None,
            state: None,
            tcp_state: None,
            sent_bytes: None,
            received_bytes: None,
        };

        match event.payload {
            EventPayload::Process {
                executable,
                command_line: _,
            } => {
                let action = match event.kind {
                    EventKind::ProcessExit => "exited",
                    _ => "started",
                };
                entry.summary = format!("{executable} {action}");
            }
            EventPayload::Connection { connection } => {
                entry.connection_id = Some(connection.id.clone());
                entry.remote = Some(connection.remote.clone());
                entry.state = Some(connection.state);
                entry.tcp_state = connection.tcp_state;
                entry.sent_bytes = Some(connection.sent_bytes);
                entry.received_bytes = Some(connection.received_bytes);
                entry.domain = connection.domain.clone();
                entry.protocol = Some(connection.protocol);
                let target = connection
                    .domain
                    .as_deref()
                    .unwrap_or(&connection.remote.address);
                entry.summary = match event.kind {
                    EventKind::TcpConnect => {
                        format!("Connected to {target}:{}", connection.remote.port)
                    }
                    EventKind::TcpClose => {
                        format!("Closed connection to {target}:{}", connection.remote.port)
                    }
                    EventKind::TcpStateChanged => format!(
                        "TCP state changed to {}",
                        connection
                            .tcp_state
                            .map(|state| format!("{state:?}").to_lowercase())
                            .unwrap_or_else(|| "unknown".to_owned())
                    ),
                    EventKind::TcpBytes => format!(
                        "Transferred {} up / {} down",
                        connection.sent_bytes, connection.received_bytes
                    ),
                    _ => "Network event".to_owned(),
                };
            }
            EventPayload::Dns {
                protocol,
                domain,
                addresses,
                ttl_secs: _,
            } => {
                entry.domain = Some(domain.clone());
                entry.addresses = addresses.clone();
                entry.protocol = Some(protocol);
                let action = match event.kind {
                    EventKind::DnsQuery => "query",
                    _ => "response",
                };
                entry.summary = format!("DNS {action} for {domain}");
            }
            EventPayload::Observation { target, level } => {
                entry.summary = format!("Observation {target} → L{level}");
            }
            EventPayload::Empty => {
                entry.summary = format!("{} event", event.kind.kind_label());
            }
        }

        if entry.summary.is_empty() {
            entry.summary = format!("{} event", event.kind.kind_label());
        }
        entry
    }
}

trait EventKindLabel {
    fn kind_label(&self) -> &'static str;
}

impl EventKindLabel for EventKind {
    fn kind_label(&self) -> &'static str {
        match self {
            EventKind::ProcessExec => "Process start",
            EventKind::ProcessExit => "Process exit",
            EventKind::TcpConnect => "TCP connect",
            EventKind::TcpClose => "TCP close",
            EventKind::TcpStateChanged => "TCP state",
            EventKind::TcpBytes => "TCP bytes",
            EventKind::DnsQuery => "DNS query",
            EventKind::DnsResponse => "DNS response",
            EventKind::ObservationChanged => "Observation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TimelineEntry;
    use tracelens_events::{DnsEventData, EventKind, EventSource, TraceEvent, TransportProtocol};

    #[test]
    fn projects_dns_event_into_a_timeline_entry() {
        let entry = TimelineEntry::from_event(TraceEvent::dns_event_with_data(
            EventSource::Kernel,
            EventKind::DnsResponse,
            7,
            DnsEventData {
                protocol: TransportProtocol::Tcp,
                domain: "example.com".to_owned(),
                addresses: vec!["203.0.113.7".to_owned()],
                ttl_secs: 60,
            },
            42,
        ));

        assert_eq!(entry.kind, EventKind::DnsResponse);
        assert_eq!(entry.pid, Some(7));
        assert_eq!(entry.protocol, Some(TransportProtocol::Tcp));
        assert_eq!(entry.domain.as_deref(), Some("example.com"));
        assert_eq!(entry.addresses, vec!["203.0.113.7"]);
        assert_eq!(entry.summary, "DNS response for example.com");
    }
}
