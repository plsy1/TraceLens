use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use tracelens_core::{api::server, config::CoreConfig, Core};
use tracelens_events::{
    ConnectionRef, ConnectionState, Endpoint, EventKind, EventSource, TcpState, TraceEvent,
    TransportProtocol,
};

const PID: u32 = 4242;
const FAKE_IP: &str = "198.19.0.116";
const BASE_TIME_NS: u64 = 1_000_000_000;

fn connection(
    id: &str,
    local: Option<Endpoint>,
    state: ConnectionState,
    tcp_state: TcpState,
    sent_bytes: u64,
    received_bytes: u64,
) -> ConnectionRef {
    ConnectionRef {
        id: id.to_owned(),
        protocol: TransportProtocol::Tcp,
        local,
        remote: Endpoint {
            address: FAKE_IP.to_owned(),
            port: 443,
        },
        state,
        tcp_state: Some(tcp_state),
        sent_bytes,
        received_bytes,
        domain: None,
    }
}

fn process_event(kind: EventKind, timestamp_ns: u64) -> TraceEvent {
    TraceEvent::process_event(
        EventSource::Kernel,
        kind,
        PID,
        Some(1),
        "curl",
        "curl https://example.net",
        timestamp_ns,
    )
}

fn ingest_connection(
    core: &mut Core,
    kind: EventKind,
    connection: ConnectionRef,
    timestamp_ns: u64,
) {
    core.ingest_event(TraceEvent::connection_event(
        EventSource::Kernel,
        kind,
        PID,
        connection,
        timestamp_ns,
    ));
}

#[test]
fn correlates_process_dns_and_connection_telemetry() {
    let mut core = Core::new(CoreConfig::default());

    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    core.ingest_event(TraceEvent::dns_event(
        EventSource::Kernel,
        EventKind::DnsResponse,
        PID,
        "example.net",
        vec![FAKE_IP.to_owned()],
        60,
        BASE_TIME_NS + 1,
    ));
    ingest_connection(
        &mut core,
        EventKind::TcpConnect,
        connection(
            "socket-enter",
            None,
            ConnectionState::Connecting,
            TcpState::SynSent,
            0,
            0,
        ),
        BASE_TIME_NS + 2,
    );
    ingest_connection(
        &mut core,
        EventKind::TcpStateChanged,
        connection(
            "socket-state",
            Some(Endpoint {
                address: "192.0.2.10".to_owned(),
                port: 51515,
            }),
            ConnectionState::Established,
            TcpState::Established,
            0,
            0,
        ),
        BASE_TIME_NS + 3,
    );
    ingest_connection(
        &mut core,
        EventKind::TcpBytes,
        connection(
            "socket-state",
            Some(Endpoint {
                address: "192.0.2.10".to_owned(),
                port: 51515,
            }),
            ConnectionState::Established,
            TcpState::Established,
            1_877,
            6_425,
        ),
        BASE_TIME_NS + 4,
    );

    assert_eq!(core.processes().len(), 1);
    assert_eq!(core.connections().len(), 1);
    assert_eq!(core.store().len(), 5);

    let record = core
        .connections()
        .all()
        .next()
        .expect("the connection should be tracked");
    assert_eq!(record.pid, Some(PID));
    assert_eq!(
        record
            .process
            .as_ref()
            .and_then(|process| process.executable.as_deref()),
        Some("curl")
    );
    assert_eq!(
        record
            .process
            .as_ref()
            .and_then(|process| process.command_line.as_deref()),
        Some("curl https://example.net")
    );
    assert_eq!(record.connection.domain.as_deref(), Some("example.net"));
    assert_eq!(record.connection.state, ConnectionState::Established);
    assert_eq!(record.connection.tcp_state, Some(TcpState::Established));
    assert_eq!(record.connection.sent_bytes, 1_877);
    assert_eq!(record.connection.received_bytes, 6_425);
    assert_eq!(
        record.connection.local,
        Some(Endpoint {
            address: "192.0.2.10".to_owned(),
            port: 51515,
        })
    );

    let timeline = core.timeline(20);
    assert_eq!(timeline.len(), 5);
    assert_eq!(timeline[0].kind, EventKind::ProcessExec);
    assert_eq!(timeline[1].kind, EventKind::DnsResponse);
    assert_eq!(timeline[1].process_name.as_deref(), Some("curl"));
    assert_eq!(timeline[1].domain.as_deref(), Some("example.net"));
    assert_eq!(timeline[2].kind, EventKind::TcpConnect);
    assert_eq!(timeline[4].kind, EventKind::TcpBytes);
}

#[test]
fn preserves_closed_connection_snapshot_after_process_exit() {
    let mut core = Core::new(CoreConfig::default());

    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    core.ingest_event(TraceEvent::dns_event(
        EventSource::Kernel,
        EventKind::DnsResponse,
        PID,
        "example.net",
        vec![FAKE_IP.to_owned()],
        60,
        BASE_TIME_NS + 1,
    ));
    ingest_connection(
        &mut core,
        EventKind::TcpConnect,
        connection(
            "socket-1",
            None,
            ConnectionState::Established,
            TcpState::Established,
            100,
            200,
        ),
        BASE_TIME_NS + 2,
    );
    ingest_connection(
        &mut core,
        EventKind::TcpClose,
        connection(
            "socket-1",
            None,
            ConnectionState::Closed,
            TcpState::Close,
            100,
            200,
        ),
        BASE_TIME_NS + 3,
    );
    core.ingest_event(process_event(EventKind::ProcessExit, BASE_TIME_NS + 4));

    assert!(core.processes().is_empty());
    let record = core
        .connections()
        .all()
        .next()
        .expect("closed connections remain in history");
    assert_eq!(record.connection.state, ConnectionState::Closed);
    assert_eq!(record.connection.domain.as_deref(), Some("example.net"));
    assert_eq!(
        record
            .process
            .as_ref()
            .and_then(|process| process.executable.as_deref()),
        Some("curl")
    );
    assert_eq!(record.connection.sent_bytes, 100);
    assert_eq!(record.connection.received_bytes, 200);
}

#[test]
fn does_not_correlate_connection_after_dns_ttl_expires() {
    let mut core = Core::new(CoreConfig::default());

    core.ingest_event(TraceEvent::dns_event(
        EventSource::Kernel,
        EventKind::DnsResponse,
        PID,
        "short-lived.example",
        vec![FAKE_IP.to_owned()],
        1,
        BASE_TIME_NS,
    ));
    ingest_connection(
        &mut core,
        EventKind::TcpConnect,
        connection(
            "socket-expired",
            None,
            ConnectionState::Established,
            TcpState::Established,
            0,
            0,
        ),
        BASE_TIME_NS + 1_000_000_001,
    );

    let record = core
        .connections()
        .all()
        .next()
        .expect("the connection should still be tracked");
    assert_eq!(record.connection.domain, None);
}

#[test]
fn serves_timeline_through_the_read_only_api() {
    let mut core = Core::new(CoreConfig::default());
    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    let core = Arc::new(Mutex::new(core));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test API listener");
    let address = listener.local_addr().expect("read test API address");
    let server_core = Arc::clone(&core);
    let server = std::thread::spawn(move || server::serve_once(listener, server_core));

    let mut client = TcpStream::connect(address).expect("connect test API listener");
    client
        .write_all(
            b"GET /api/timeline?limit=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .expect("write API request");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("read API response");
    server
        .join()
        .expect("API server thread should finish")
        .expect("API request should succeed");

    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("HTTP response body");
    let entries: Vec<serde_json::Value> = serde_json::from_str(body).expect("timeline JSON");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["kind"], "process_exec");
    assert_eq!(entries[0]["process_name"], "curl");
}

#[test]
fn correlates_domains_from_a_separate_system_resolver_process() {
    let mut core = Core::new(CoreConfig::default());
    let resolver_pid = 53;
    let connection_pid = 9001;

    let mut connection = connection(
        "resolver-backed-socket",
        None,
        ConnectionState::Established,
        TcpState::Established,
        0,
        0,
    );
    connection.remote.port = 443;
    core.ingest_event(TraceEvent::connection_event(
        EventSource::Kernel,
        EventKind::TcpConnect,
        connection_pid,
        connection,
        BASE_TIME_NS + 1,
    ));
    core.ingest_event(TraceEvent::dns_event(
        EventSource::Kernel,
        EventKind::DnsResponse,
        resolver_pid,
        "resolver.example",
        vec![FAKE_IP.to_owned()],
        60,
        BASE_TIME_NS + 2,
    ));

    let record = core
        .connections()
        .all()
        .next()
        .expect("resolver-backed connection");
    assert_eq!(
        record.connection.domain.as_deref(),
        Some("resolver.example")
    );
}
