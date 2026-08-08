use serde::Serialize;
use tracelens_events::{
    ConnectionState, Endpoint, EventKind, EventPayload, EventSource, HttpHeader,
    HttpMessageDirection, PlaintextDirection, TcpState, TraceEvent, TransportProtocol,
};

#[derive(Debug, Clone)]
pub struct TimelineFilter {
    pub pid: Option<u32>,
    pub kind: Option<EventKind>,
    pub connection_id: Option<String>,
    /// Include individual SSL plaintext fragments in addition to aggregated
    /// HTTP events. The API/UI can turn this off for the calm default view.
    pub include_plaintext: bool,
    /// Number of newest matching events to skip. This makes the next page
    /// point toward older history rather than newer events.
    pub offset: usize,
    pub limit: usize,
}

impl Default for TimelineFilter {
    fn default() -> Self {
        Self {
            pid: None,
            kind: None,
            connection_id: None,
            include_plaintext: true,
            offset: 0,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TimelinePage {
    pub entries: Vec<TimelineEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone)]
pub struct ConnectionTimelineFilter {
    pub pid: Option<u32>,
    pub connection_id: Option<String>,
    pub include_plaintext: bool,
    pub include_closed: bool,
    pub include_events: bool,
    pub event_limit: usize,
    pub offset: usize,
    pub limit: usize,
}

impl Default for ConnectionTimelineFilter {
    fn default() -> Self {
        Self {
            pid: None,
            connection_id: None,
            include_plaintext: true,
            include_closed: true,
            include_events: true,
            event_limit: 200,
            offset: 0,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConnectionTimelinePage {
    pub sessions: Vec<ConnectionTimeline>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConnectionTimeline {
    pub id: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub process_command_line: Option<String>,
    pub protocol: TransportProtocol,
    pub local: Option<Endpoint>,
    pub remote: Endpoint,
    pub domain: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_version: Option<String>,
    pub state: ConnectionState,
    pub tcp_state: Option<TcpState>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub duration_ns: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub event_count: usize,
    pub events: Vec<TimelineEntry>,
}

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
    pub tls_sni: Option<String>,
    pub tls_version: Option<String>,
    pub ssl_object: Option<u64>,
    pub fd: Option<i32>,
    pub plaintext_direction: Option<PlaintextDirection>,
    pub plaintext: Option<String>,
    pub plaintext_bytes: Option<usize>,
    pub plaintext_truncated: bool,
    pub plaintext_skipped: bool,
    pub plaintext_skip_reason: Option<String>,
    pub http_direction: Option<HttpMessageDirection>,
    pub http_version: Option<String>,
    pub http_method: Option<String>,
    pub http_target: Option<String>,
    pub http_host: Option<String>,
    pub http_status: Option<u16>,
    pub http_reason: Option<String>,
    pub http_headers: Vec<HttpHeader>,
    pub http_content_length: Option<usize>,
    pub http_body_preview: Option<String>,
    pub http_body_bytes: usize,
    pub http_body_truncated: bool,
    pub http_payload_skipped: bool,
    pub http_payload_skip_reason: Option<String>,
    pub file_path: Option<String>,
    pub file_bytes: Option<u64>,
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
            tls_sni: None,
            tls_version: None,
            ssl_object: None,
            fd: None,
            plaintext_direction: None,
            plaintext: None,
            plaintext_bytes: None,
            plaintext_truncated: false,
            plaintext_skipped: false,
            plaintext_skip_reason: None,
            http_direction: None,
            http_version: None,
            http_method: None,
            http_target: None,
            http_host: None,
            http_status: None,
            http_reason: None,
            http_headers: Vec::new(),
            http_content_length: None,
            http_body_preview: None,
            http_body_bytes: 0,
            http_body_truncated: false,
            http_payload_skipped: false,
            http_payload_skip_reason: None,
            file_path: None,
            file_bytes: None,
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
            EventPayload::Tls {
                ssl_object,
                fd,
                sni,
                version,
            } => {
                if let Some(connection) = event.connection.as_ref() {
                    entry.connection_id = Some(connection.id.clone());
                    entry.remote = Some(connection.remote.clone());
                    entry.state = Some(connection.state);
                    entry.tcp_state = connection.tcp_state;
                    entry.sent_bytes = Some(connection.sent_bytes);
                    entry.received_bytes = Some(connection.received_bytes);
                    entry.domain = connection.domain.clone();
                    entry.protocol = Some(connection.protocol);
                }
                entry.ssl_object = Some(ssl_object);
                entry.fd = fd;
                entry.tls_sni = sni.clone();
                entry.tls_version = version.clone();
                entry.summary = match (sni.as_deref(), version.as_deref(), fd) {
                    (Some(sni), Some(version), _) => {
                        format!("TLS metadata: {sni} · {version}")
                    }
                    (Some(sni), _, _) => format!("TLS SNI {sni}"),
                    (_, Some(version), _) => format!("TLS version {version}"),
                    (_, _, Some(fd)) if fd >= 0 => format!("TLS socket fd {fd}"),
                    _ => "TLS handshake observed".to_owned(),
                };
            }
            EventPayload::Plaintext {
                ssl_object,
                fd,
                direction,
                data,
                bytes,
                truncated,
                payload_skipped,
                payload_skip_reason,
            } => {
                if let Some(connection) = event.connection.as_ref() {
                    entry.connection_id = Some(connection.id.clone());
                    entry.remote = Some(connection.remote.clone());
                    entry.state = Some(connection.state);
                    entry.tcp_state = connection.tcp_state;
                    entry.sent_bytes = Some(connection.sent_bytes);
                    entry.received_bytes = Some(connection.received_bytes);
                    entry.domain = connection.domain.clone();
                    entry.protocol = Some(connection.protocol);
                }
                entry.ssl_object = Some(ssl_object);
                entry.fd = fd;
                entry.plaintext_direction = Some(direction);
                entry.plaintext = Some(data);
                entry.plaintext_bytes = Some(bytes);
                entry.plaintext_truncated = truncated;
                entry.plaintext_skipped = payload_skipped;
                entry.plaintext_skip_reason = payload_skip_reason;
                let direction_label = match direction {
                    PlaintextDirection::Read => "read",
                    PlaintextDirection::Write => "write",
                };
                entry.summary = format!(
                    "Plaintext {direction_label} · {bytes} B{}",
                    if truncated { " · truncated" } else { "" }
                );
            }
            EventPayload::HttpCapture {
                ssl_object,
                fd,
                direction,
                data,
                bytes,
                truncated,
                payload_skipped,
                payload_skip_reason,
            } => {
                entry.ssl_object = Some(ssl_object);
                entry.fd = fd;
                entry.plaintext_direction = Some(direction);
                entry.plaintext = Some(data);
                entry.plaintext_bytes = Some(bytes);
                entry.plaintext_truncated = truncated;
                entry.plaintext_skipped = payload_skipped;
                entry.plaintext_skip_reason = payload_skip_reason;
                entry.summary = format!(
                    "HTTP capture {} · {} B{}",
                    match direction {
                        PlaintextDirection::Read => "read",
                        PlaintextDirection::Write => "write",
                    },
                    bytes,
                    if truncated { " · truncated" } else { "" }
                );
            }
            EventPayload::Http {
                direction,
                version,
                method,
                target,
                host,
                status,
                reason,
                headers,
                content_length,
                body_preview,
                body_bytes,
                body_truncated,
                payload_skipped,
                payload_skip_reason,
            } => {
                if let Some(connection) = event.connection.as_ref() {
                    entry.connection_id = Some(connection.id.clone());
                    entry.remote = Some(connection.remote.clone());
                    entry.state = Some(connection.state);
                    entry.tcp_state = connection.tcp_state;
                    entry.sent_bytes = Some(connection.sent_bytes);
                    entry.received_bytes = Some(connection.received_bytes);
                    entry.domain = connection.domain.clone();
                    entry.protocol = Some(connection.protocol);
                }
                entry.http_direction = Some(direction);
                entry.http_version = Some(version);
                entry.http_method = method;
                entry.http_target = target;
                entry.http_host = host;
                entry.http_status = status;
                entry.http_reason = reason;
                entry.http_headers = headers;
                entry.http_content_length = content_length;
                entry.http_body_preview = body_preview;
                entry.http_body_bytes = body_bytes;
                entry.http_body_truncated = body_truncated;
                entry.http_payload_skipped = payload_skipped;
                entry.http_payload_skip_reason = payload_skip_reason;
                entry.summary = match direction {
                    HttpMessageDirection::Request => format!(
                        "HTTP request {} {}",
                        entry.http_method.as_deref().unwrap_or("?"),
                        entry.http_target.as_deref().unwrap_or("?")
                    ),
                    HttpMessageDirection::Response => format!(
                        "HTTP response {}{}",
                        entry
                            .http_status
                            .map(|status| status.to_string())
                            .unwrap_or_else(|| "?".to_owned()),
                        entry
                            .http_reason
                            .as_deref()
                            .filter(|reason| !reason.is_empty())
                            .map(|reason| format!(" {reason}"))
                            .unwrap_or_default()
                    ),
                };
            }
            EventPayload::File { path, bytes } => {
                entry.file_path = Some(path.clone());
                entry.file_bytes = Some(bytes);
                let operation = match event.kind {
                    EventKind::FileRead => "read",
                    _ => "opened",
                };
                entry.summary = format!("File {operation} · {path}");
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
            EventKind::TlsMetadata => "TLS metadata",
            EventKind::Plaintext => "Plaintext",
            EventKind::HttpCapture => "HTTP capture",
            EventKind::Http => "HTTP",
            EventKind::FileOpen => "File open",
            EventKind::FileRead => "File read",
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
