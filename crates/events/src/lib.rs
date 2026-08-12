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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstrumentationSource {
    pub provider: String,
    pub library: String,
    pub api_function: String,
}

pub const TLS_API_OPENSSL_CONNECT: u16 = 1;
pub const TLS_API_OPENSSL_GET_SERVERNAME: u16 = 2;
pub const TLS_API_OPENSSL_GET_VERSION: u16 = 3;
pub const TLS_API_OPENSSL_GET_FD: u16 = 4;
pub const TLS_API_OPENSSL_SET_FD: u16 = 5;
pub const TLS_API_OPENSSL_READ: u16 = 6;
pub const TLS_API_OPENSSL_WRITE: u16 = 7;
pub const TLS_API_OPENSSL_READ_EX: u16 = 8;
pub const TLS_API_OPENSSL_WRITE_EX: u16 = 9;
pub const TLS_API_GNUTLS_HANDSHAKE: u16 = 20;
pub const TLS_API_GNUTLS_SET_FD: u16 = 21;
pub const TLS_API_GNUTLS_RECV: u16 = 22;
pub const TLS_API_GNUTLS_SEND: u16 = 23;
pub const TLS_API_GNUTLS_SERVER_NAME: u16 = 24;
pub const TLS_API_GNUTLS_PROTOCOL: u16 = 25;
pub const TLS_API_NSS_IMPORT_FD: u16 = 40;
pub const TLS_API_NSPR_READ: u16 = 41;
pub const TLS_API_NSPR_WRITE: u16 = 42;
pub const TLS_API_NSS_SET_URL: u16 = 43;
pub const TLS_API_NSS_CHANNEL_INFO: u16 = 44;
pub const TLS_API_RUSTLS_READ: u16 = 60;
pub const TLS_API_RUSTLS_WRITE: u16 = 61;
pub const TLS_API_RUSTLS_PROCESS_PACKETS: u16 = 62;

pub fn tls_api_function(api_id: u16) -> Option<&'static str> {
    match api_id {
        TLS_API_OPENSSL_CONNECT => Some("SSL_connect"),
        TLS_API_OPENSSL_GET_SERVERNAME => Some("SSL_get_servername"),
        TLS_API_OPENSSL_GET_VERSION => Some("SSL_get_version"),
        TLS_API_OPENSSL_GET_FD => Some("SSL_get_fd"),
        TLS_API_OPENSSL_SET_FD => Some("SSL_set_fd"),
        TLS_API_OPENSSL_READ => Some("SSL_read"),
        TLS_API_OPENSSL_WRITE => Some("SSL_write"),
        TLS_API_OPENSSL_READ_EX => Some("SSL_read_ex"),
        TLS_API_OPENSSL_WRITE_EX => Some("SSL_write_ex"),
        TLS_API_GNUTLS_HANDSHAKE => Some("gnutls_handshake"),
        TLS_API_GNUTLS_SET_FD => Some("gnutls_transport_set_int2"),
        TLS_API_GNUTLS_RECV => Some("gnutls_record_recv"),
        TLS_API_GNUTLS_SEND => Some("gnutls_record_send"),
        TLS_API_GNUTLS_SERVER_NAME => Some("gnutls_server_name_set"),
        TLS_API_GNUTLS_PROTOCOL => Some("gnutls_protocol_get_version"),
        TLS_API_NSS_IMPORT_FD => Some("SSL_ImportFD"),
        TLS_API_NSPR_READ => Some("PR_Read"),
        TLS_API_NSPR_WRITE => Some("PR_Write"),
        TLS_API_NSS_SET_URL => Some("SSL_SetURL"),
        TLS_API_NSS_CHANNEL_INFO => Some("SSL_GetChannelInfo"),
        TLS_API_RUSTLS_READ => Some("rustls_connection_read"),
        TLS_API_RUSTLS_WRITE => Some("rustls_connection_write"),
        TLS_API_RUSTLS_PROCESS_PACKETS => Some("rustls_connection_process_new_packets"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessExec,
    ProcessExit,
    TcpConnect,
    TcpClose,
    TcpStateChanged,
    TcpBytes,
    DnsQuery,
    DnsResponse,
    TlsMetadata,
    Plaintext,
    HttpCapture,
    Http,
    FileOpen,
    FileRead,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TcpState {
    Established,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    TimeWait,
    Close,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    NewSynRecv,
    Unknown,
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
    pub tcp_state: Option<TcpState>,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsEventData {
    pub protocol: TransportProtocol,
    pub domain: String,
    pub addresses: Vec<String>,
    pub ttl_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsEventData {
    pub ssl_object: u64,
    pub fd: Option<i32>,
    pub sni: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextDirection {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlaintextEventData {
    pub ssl_object: u64,
    pub fd: Option<i32>,
    pub direction: PlaintextDirection,
    pub data: String,
    pub bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpCaptureEventData {
    pub ssl_object: u64,
    pub fd: Option<i32>,
    pub direction: PlaintextDirection,
    pub data: Vec<u8>,
    pub bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpMessageDirection {
    Request,
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpEventData {
    #[serde(default)]
    pub stream_id: Option<String>,
    pub direction: HttpMessageDirection,
    pub version: String,
    pub method: Option<String>,
    pub target: Option<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub content_length: Option<usize>,
    pub body_preview: Option<String>,
    pub body_bytes: usize,
    pub body_truncated: bool,
    pub payload_skipped: bool,
    pub payload_skip_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEventData {
    pub path: String,
    pub bytes: u64,
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
        protocol: TransportProtocol,
        domain: String,
        addresses: Vec<String>,
        ttl_secs: u32,
    },
    Tls {
        ssl_object: u64,
        fd: Option<i32>,
        sni: Option<String>,
        version: Option<String>,
    },
    Plaintext {
        ssl_object: u64,
        fd: Option<i32>,
        direction: PlaintextDirection,
        data: String,
        #[serde(skip)]
        raw_data: Option<Vec<u8>>,
        bytes: usize,
        truncated: bool,
        #[serde(default)]
        payload_skipped: bool,
        #[serde(default)]
        payload_skip_reason: Option<String>,
    },
    /// Bounded application bytes used internally to derive HTTP metadata.
    /// Core drops this raw event after parsing; it is not a persisted timeline row.
    HttpCapture {
        ssl_object: u64,
        fd: Option<i32>,
        direction: PlaintextDirection,
        data: Vec<u8>,
        bytes: usize,
        truncated: bool,
        #[serde(default)]
        payload_skipped: bool,
        #[serde(default)]
        payload_skip_reason: Option<String>,
    },
    Http {
        #[serde(default)]
        stream_id: Option<String>,
        direction: HttpMessageDirection,
        version: String,
        method: Option<String>,
        target: Option<String>,
        host: Option<String>,
        status: Option<u16>,
        reason: Option<String>,
        headers: Vec<HttpHeader>,
        content_length: Option<usize>,
        #[serde(default)]
        body_preview: Option<String>,
        #[serde(default)]
        body_bytes: usize,
        #[serde(default)]
        body_truncated: bool,
        #[serde(default)]
        payload_skipped: bool,
        #[serde(default)]
        payload_skip_reason: Option<String>,
    },
    File {
        path: String,
        bytes: u64,
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
    #[serde(default)]
    pub instrumentation: Option<InstrumentationSource>,
    pub payload: EventPayload,
}

impl TraceEvent {
    pub fn with_instrumentation(
        mut self,
        provider: impl Into<String>,
        library: impl Into<String>,
        api_id: u16,
    ) -> Self {
        if let Some(api_function) = tls_api_function(api_id) {
            self.instrumentation = Some(InstrumentationSource {
                provider: provider.into(),
                library: library.into(),
                api_function: api_function.to_owned(),
            });
        }
        self
    }
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
            instrumentation: None,
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
        Self::connection_event_with_process(source, kind, pid, None, connection, timestamp_ns)
    }

    pub fn connection_event_with_process(
        source: EventSource,
        kind: EventKind,
        pid: u32,
        process: Option<ProcessRef>,
        connection: ConnectionRef,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!("connection-{kind:?}-{}-{timestamp_ns}", connection.id),
            timestamp_ns,
            source,
            kind,
            pid: Some(pid),
            process,
            connection: Some(connection.clone()),
            instrumentation: None,
            payload: EventPayload::Connection { connection },
        }
    }

    pub fn dns_event(
        source: EventSource,
        kind: EventKind,
        pid: u32,
        domain: &str,
        addresses: Vec<String>,
        ttl_secs: u32,
        timestamp_ns: u64,
    ) -> Self {
        Self::dns_event_with_data(
            source,
            kind,
            pid,
            DnsEventData {
                protocol: TransportProtocol::Udp,
                domain: domain.to_owned(),
                addresses,
                ttl_secs,
            },
            timestamp_ns,
        )
    }

    pub fn dns_event_with_data(
        source: EventSource,
        kind: EventKind,
        pid: u32,
        data: DnsEventData,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!("dns-{kind:?}-{pid}-{}-{timestamp_ns}", data.domain),
            timestamp_ns,
            source,
            kind,
            pid: Some(pid),
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::Dns {
                protocol: data.protocol,
                domain: data.domain,
                addresses: data.addresses,
                ttl_secs: data.ttl_secs,
            },
        }
    }

    pub fn observation_event(target: String, level: u8, timestamp_ns: u64) -> Self {
        Self {
            id: format!("observation-{target}-{timestamp_ns}"),
            timestamp_ns,
            source: EventSource::Core,
            kind: EventKind::ObservationChanged,
            pid: None,
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::Observation { target, level },
        }
    }

    pub fn tls_metadata(
        source: EventSource,
        pid: u32,
        data: TlsEventData,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!("tls-{pid}-{}-{}", data.ssl_object, timestamp_ns),
            timestamp_ns,
            source,
            kind: EventKind::TlsMetadata,
            pid: Some(pid),
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::Tls {
                ssl_object: data.ssl_object,
                fd: data.fd,
                sni: data.sni,
                version: data.version,
            },
        }
    }

    pub fn plaintext(
        source: EventSource,
        pid: u32,
        data: PlaintextEventData,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!(
                "plaintext-{pid}-{}-{direction:?}-{timestamp_ns}",
                data.ssl_object,
                direction = data.direction
            ),
            timestamp_ns,
            source,
            kind: EventKind::Plaintext,
            pid: Some(pid),
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::Plaintext {
                ssl_object: data.ssl_object,
                fd: data.fd,
                direction: data.direction,
                data: data.data,
                raw_data: None,
                bytes: data.bytes,
                truncated: data.truncated,
                payload_skipped: false,
                payload_skip_reason: None,
            },
        }
    }

    pub fn plaintext_bytes(
        source: EventSource,
        pid: u32,
        data: HttpCaptureEventData,
        timestamp_ns: u64,
    ) -> Self {
        let text = String::from_utf8_lossy(&data.data).into_owned();
        Self {
            id: format!(
                "plaintext-{pid}-{}-{direction:?}-{timestamp_ns}",
                data.ssl_object,
                direction = data.direction
            ),
            timestamp_ns,
            source,
            kind: EventKind::Plaintext,
            pid: Some(pid),
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::Plaintext {
                ssl_object: data.ssl_object,
                fd: data.fd,
                direction: data.direction,
                data: text,
                raw_data: Some(data.data),
                bytes: data.bytes,
                truncated: data.truncated,
                payload_skipped: false,
                payload_skip_reason: None,
            },
        }
    }

    pub fn http(source: EventSource, pid: u32, data: HttpEventData, timestamp_ns: u64) -> Self {
        Self::http_with_sequence(source, pid, data, timestamp_ns, 0)
    }

    pub fn http_with_sequence(
        source: EventSource,
        pid: u32,
        data: HttpEventData,
        timestamp_ns: u64,
        sequence: usize,
    ) -> Self {
        Self {
            id: format!(
                "http-{pid}-{}-{timestamp_ns}-{sequence}",
                match data.direction {
                    HttpMessageDirection::Request => "request",
                    HttpMessageDirection::Response => "response",
                }
            ),
            timestamp_ns,
            source,
            kind: EventKind::Http,
            pid: Some(pid),
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::Http {
                stream_id: data.stream_id,
                direction: data.direction,
                version: data.version,
                method: data.method,
                target: data.target,
                host: data.host,
                status: data.status,
                reason: data.reason,
                headers: data.headers,
                content_length: data.content_length,
                body_preview: data.body_preview,
                body_bytes: data.body_bytes,
                body_truncated: data.body_truncated,
                payload_skipped: data.payload_skipped,
                payload_skip_reason: data.payload_skip_reason,
            },
        }
    }

    pub fn http_capture(
        source: EventSource,
        pid: u32,
        data: HttpCaptureEventData,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!(
                "http-capture-{pid}-{}-{direction:?}-{timestamp_ns}",
                data.ssl_object,
                direction = data.direction
            ),
            timestamp_ns,
            source,
            kind: EventKind::HttpCapture,
            pid: Some(pid),
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::HttpCapture {
                ssl_object: data.ssl_object,
                fd: data.fd,
                direction: data.direction,
                data: data.data,
                bytes: data.bytes,
                truncated: data.truncated,
                payload_skipped: false,
                payload_skip_reason: None,
            },
        }
    }

    pub fn file_event(
        source: EventSource,
        kind: EventKind,
        pid: u32,
        data: FileEventData,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            id: format!("file-{kind:?}-{pid}-{}-{timestamp_ns}", data.path),
            timestamp_ns,
            source,
            kind,
            pid: Some(pid),
            process: None,
            connection: None,
            instrumentation: None,
            payload: EventPayload::File {
                path: data.path,
                bytes: data.bytes,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EventKind, EventSource, PlaintextDirection, PlaintextEventData, TlsEventData, TraceEvent,
    };

    #[test]
    fn process_exec_uses_the_shared_core_schema() {
        let event = TraceEvent::process_exec(7, "curl", "curl https://example.com", 42);

        assert_eq!(event.source, EventSource::Core);
        assert_eq!(event.kind, EventKind::ProcessExec);
        assert_eq!(event.pid, Some(7));
    }

    #[test]
    fn tls_metadata_uses_the_shared_event_schema() {
        let event = TraceEvent::tls_metadata(
            EventSource::Kernel,
            7,
            TlsEventData {
                ssl_object: 0x1234,
                fd: Some(9),
                sni: Some("example.com".to_owned()),
                version: Some("TLSv1.3".to_owned()),
            },
            42,
        );

        assert_eq!(event.kind, EventKind::TlsMetadata);
        assert_eq!(event.pid, Some(7));
        assert!(matches!(event.payload, super::EventPayload::Tls { .. }));
    }

    #[test]
    fn plaintext_uses_a_bounded_directional_event_schema() {
        let event = TraceEvent::plaintext(
            EventSource::Kernel,
            7,
            PlaintextEventData {
                ssl_object: 0x1234,
                fd: Some(9),
                direction: PlaintextDirection::Write,
                data: "hello".to_owned(),
                bytes: 5,
                truncated: false,
            },
            42,
        );

        assert_eq!(event.kind, EventKind::Plaintext);
        assert_eq!(event.pid, Some(7));
        assert!(matches!(
            event.payload,
            super::EventPayload::Plaintext { .. }
        ));
    }
}
