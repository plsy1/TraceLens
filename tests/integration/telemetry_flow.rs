use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use tracelens_core::{
    api::server,
    config::{CoreConfig, StorageMode},
    events::{ConnectionTimelineFilter, TimelineFilter},
    observation::{ObservationLevel, ObservationTarget},
    Core,
};
use tracelens_events::{
    ConnectionRef, ConnectionState, Endpoint, EventKind, EventSource, FileEventData,
    PlaintextDirection, PlaintextEventData, TcpState, TlsEventData, TraceEvent, TransportProtocol,
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

    let connection_page = core.timeline_page(TimelineFilter {
        connection_id: Some("socket-enter".to_owned()),
        ..TimelineFilter::default()
    });
    assert_eq!(connection_page.total, 3);
    assert!(connection_page
        .entries
        .iter()
        .all(|entry| entry.connection_id.as_deref() == Some("socket-enter")));

    let connection_sessions = core.connection_timeline_page(ConnectionTimelineFilter::default());
    assert_eq!(connection_sessions.total, 1);
    assert_eq!(connection_sessions.sessions[0].id, "socket-enter");
    assert_eq!(connection_sessions.sessions[0].event_count, 4);
    assert_eq!(
        connection_sessions.sessions[0].events[0].kind,
        EventKind::DnsResponse
    );

    let dns_page = core.timeline_page(TimelineFilter {
        kind: Some(EventKind::DnsResponse),
        limit: 1,
        ..TimelineFilter::default()
    });
    assert_eq!(dns_page.total, 1);
    assert_eq!(dns_page.entries[0].kind, EventKind::DnsResponse);

    let latest_page = core.timeline_page(TimelineFilter {
        limit: 2,
        ..TimelineFilter::default()
    });
    assert_eq!(latest_page.entries.len(), 2);
    assert!(latest_page.has_more);
    assert_eq!(latest_page.entries[1].kind, EventKind::TcpBytes);

    let older_page = core.timeline_page(TimelineFilter {
        limit: 2,
        offset: 2,
        ..TimelineFilter::default()
    });
    assert_eq!(older_page.entries[0].kind, EventKind::DnsResponse);
    assert_eq!(older_page.entries[1].kind, EventKind::TcpConnect);
    assert!(older_page.has_more);

    let oldest_page = core.timeline_page(TimelineFilter {
        limit: 2,
        offset: 4,
        ..TimelineFilter::default()
    });
    assert_eq!(oldest_page.entries[0].kind, EventKind::ProcessExec);
    assert!(!oldest_page.has_more);
}

#[test]
fn correlates_tls_metadata_to_the_process_connection() {
    let mut core = Core::new(CoreConfig::default());
    let fd = 7_u32;
    let socket_id = format!("socket-{}", (u64::from(PID) << 32) | u64::from(fd));

    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    ingest_connection(
        &mut core,
        EventKind::TcpConnect,
        connection(
            &socket_id,
            None,
            ConnectionState::Established,
            TcpState::Established,
            0,
            0,
        ),
        BASE_TIME_NS + 1,
    );
    core.ingest_event(TraceEvent::tls_metadata(
        EventSource::Kernel,
        PID,
        TlsEventData {
            ssl_object: 0x1234,
            fd: Some(fd as i32),
            sni: Some("example.net".to_owned()),
            version: Some("TLSv1.3".to_owned()),
        },
        BASE_TIME_NS + 2,
    ));
    core.ingest_event(TraceEvent::plaintext(
        EventSource::Kernel,
        PID,
        PlaintextEventData {
            ssl_object: 0x1234,
            fd: None,
            direction: PlaintextDirection::Write,
            data: "GET / HTTP/1.1".to_owned(),
            bytes: 14,
            truncated: false,
        },
        BASE_TIME_NS + 3,
    ));

    let timeline = core.timeline_page(TimelineFilter {
        kind: Some(EventKind::TlsMetadata),
        ..TimelineFilter::default()
    });
    assert_eq!(timeline.total, 1);
    assert_eq!(
        timeline.entries[0].connection_id.as_deref(),
        Some(socket_id.as_str())
    );
    assert_eq!(timeline.entries[0].tls_sni.as_deref(), Some("example.net"));
    assert_eq!(timeline.entries[0].tls_version.as_deref(), Some("TLSv1.3"));

    let plaintext_timeline = core.timeline_page(TimelineFilter {
        kind: Some(EventKind::Plaintext),
        ..TimelineFilter::default()
    });
    assert_eq!(plaintext_timeline.total, 1);
    assert_eq!(
        plaintext_timeline.entries[0].connection_id.as_deref(),
        Some(socket_id.as_str())
    );
    assert_eq!(
        plaintext_timeline.entries[0].plaintext.as_deref(),
        Some("GET / HTTP/1.1")
    );
    assert_eq!(plaintext_timeline.entries[0].plaintext_bytes, Some(14));
    assert!(!plaintext_timeline.entries[0].plaintext_truncated);

    let sessions = core.connection_timeline_page(ConnectionTimelineFilter::default());
    assert_eq!(sessions.sessions[0].tls_sni.as_deref(), Some("example.net"));
    assert_eq!(sessions.sessions[0].tls_version.as_deref(), Some("TLSv1.3"));
    assert_eq!(sessions.sessions[0].event_count, 3);
}

#[test]
fn parses_http_messages_from_reassembled_plaintext() {
    let mut core = Core::new(CoreConfig::default());
    let fd = 8_u32;
    let socket_id = format!("socket-{}", (u64::from(PID) << 32) | u64::from(fd));

    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    ingest_connection(
        &mut core,
        EventKind::TcpConnect,
        connection(
            &socket_id,
            None,
            ConnectionState::Established,
            TcpState::Established,
            0,
            0,
        ),
        BASE_TIME_NS + 1,
    );
    core.ingest_event(TraceEvent::http_capture(
        EventSource::Kernel,
        PID,
        PlaintextEventData {
            ssl_object: 0x5678,
            fd: Some(fd as i32),
            direction: PlaintextDirection::Write,
            data: "GET /health HTTP/1.1\r\nHost: example.net\r\n".to_owned(),
            bytes: 43,
            truncated: false,
        },
        BASE_TIME_NS + 2,
    ));
    core.ingest_event(TraceEvent::http_capture(
        EventSource::Kernel,
        PID,
        PlaintextEventData {
            ssl_object: 0x5678,
            fd: Some(fd as i32),
            direction: PlaintextDirection::Write,
            data: "User-Agent: tracelens\r\n\r\n".to_owned(),
            bytes: 26,
            truncated: false,
        },
        BASE_TIME_NS + 3,
    ));
    core.ingest_event(TraceEvent::http_capture(
        EventSource::Kernel,
        PID,
        PlaintextEventData {
            ssl_object: 0x5678,
            fd: Some(fd as i32),
            direction: PlaintextDirection::Read,
            data: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_owned(),
            bytes: 47,
            truncated: false,
        },
        BASE_TIME_NS + 4,
    ));

    let page = core.timeline_page(TimelineFilter {
        kind: Some(EventKind::Http),
        ..TimelineFilter::default()
    });
    assert_eq!(page.total, 2);
    assert_eq!(page.entries[0].summary, "HTTP request GET /health");
    assert_eq!(page.entries[0].http_host.as_deref(), Some("example.net"));
    assert_eq!(page.entries[0].http_headers.len(), 2);
    assert_eq!(page.entries[1].summary, "HTTP response 200 OK");
    assert_eq!(page.entries[1].http_status, Some(200));
    assert_eq!(page.entries[1].http_content_length, Some(2));
    assert!(page
        .entries
        .iter()
        .all(|entry| entry.connection_id.as_deref() == Some(socket_id.as_str())));
    assert_eq!(core.http_stream_count(), 1);
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
            b"GET /api/timeline?limit=1&pid=4242&kind=process_exec HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
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
    let page: serde_json::Value = serde_json::from_str(body).expect("timeline JSON");
    let entries = page["entries"].as_array().expect("timeline entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(page["total"], 1);
    assert_eq!(page["has_more"], false);
    assert_eq!(entries[0]["kind"], "process_exec");
    assert_eq!(entries[0]["process_name"], "curl");
}

#[test]
fn serves_grouped_connection_timeline_through_the_api() {
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
            "grouped-connect",
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
            "grouped-connect",
            None,
            ConnectionState::Closed,
            TcpState::Close,
            100,
            200,
        ),
        BASE_TIME_NS + 3,
    );

    let summary_page = core.connection_timeline_page(ConnectionTimelineFilter {
        include_events: false,
        ..ConnectionTimelineFilter::default()
    });
    assert_eq!(summary_page.sessions[0].event_count, 2);
    assert!(summary_page.sessions[0].events.is_empty());

    let truncated_page = core.connection_timeline_page(ConnectionTimelineFilter {
        event_limit: 1,
        ..ConnectionTimelineFilter::default()
    });
    assert_eq!(truncated_page.sessions[0].event_count, 3);
    assert_eq!(truncated_page.sessions[0].events.len(), 1);

    let core = Arc::new(Mutex::new(core));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind grouped API listener");
    let address = listener.local_addr().expect("read grouped API address");
    let server_core = Arc::clone(&core);
    let server = std::thread::spawn(move || server::serve_once(listener, server_core));
    let mut client = TcpStream::connect(address).expect("connect grouped API listener");
    client
        .write_all(
            b"GET /api/connection-timeline?limit=1&include_closed=true HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .expect("write grouped API request");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("read grouped API response");
    server
        .join()
        .expect("grouped API server thread should finish")
        .expect("grouped API request should succeed");

    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("grouped API response body");
    let page: serde_json::Value = serde_json::from_str(body).expect("grouped timeline JSON");
    let sessions = page["sessions"].as_array().expect("connection sessions");
    assert_eq!(page["total"], 1);
    assert_eq!(sessions[0]["id"], "grouped-connect");
    assert_eq!(sessions[0]["event_count"], 3);
    assert_eq!(sessions[0]["events"][0]["kind"], "dns_response");
}

#[test]
fn serves_observation_upgrade_through_the_command_api() {
    let core = Arc::new(Mutex::new(Core::new(CoreConfig::default())));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind observation API listener");
    let address = listener.local_addr().expect("read observation API address");
    let server_core = Arc::clone(&core);
    let server = std::thread::spawn(move || server::serve_once(listener, server_core));

    let body = r#"{"target":"process:4242","level":3,"duration_secs":300}"#;
    let request = format!(
        "POST /api/observations HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let mut client = TcpStream::connect(address).expect("connect observation API listener");
    client
        .write_all(request.as_bytes())
        .expect("write observation command");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("read observation response");
    server
        .join()
        .expect("observation API server thread should finish")
        .expect("observation API request should succeed");

    let response_body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("observation response body");
    let value: serde_json::Value = serde_json::from_str(response_body).expect("observation JSON");
    assert_eq!(value["target"], "process:4242");
    assert_eq!(value["level"], "L3");
    assert_eq!(
        core.lock()
            .expect("core lock")
            .observations()
            .current_level(&ObservationTarget::Process(4242)),
        ObservationLevel::L3
    );
    let core = core.lock().expect("core lock");
    assert!(core.probe_attachments().is_empty());
    assert!(!core.probe_errors().is_empty());
}

#[test]
fn exact_observation_level_can_be_lowered_again() {
    let mut core = Core::new(CoreConfig::default());
    let target = ObservationTarget::Process(PID);

    assert_eq!(
        core.upgrade_observation(target.clone(), ObservationLevel::L5, Some(300)),
        ObservationLevel::L5
    );
    assert_eq!(
        core.observations().current_level(&target),
        ObservationLevel::L5
    );

    assert_eq!(
        core.set_observation(target.clone(), ObservationLevel::L3, Some(300)),
        ObservationLevel::L3
    );
    assert_eq!(
        core.observations().current_level(&target),
        ObservationLevel::L3
    );

    assert_eq!(
        core.set_observation(target.clone(), ObservationLevel::L1, Some(300)),
        ObservationLevel::L1
    );
    assert_eq!(
        core.observations().current_level(&target),
        ObservationLevel::L1
    );
}

#[test]
#[cfg(target_os = "linux")]
fn backfills_process_inventory_for_processes_seen_before_observer_start() {
    let pid = std::process::id();
    let mut core = Core::new(CoreConfig::default());
    core.ingest_event(TraceEvent::connection_event(
        EventSource::Kernel,
        EventKind::TcpConnect,
        pid,
        connection(
            "preexisting-process",
            None,
            ConnectionState::Established,
            TcpState::Established,
            0,
            0,
        ),
        BASE_TIME_NS,
    ));

    let process = core.processes().get(pid).expect("backfilled process");
    assert!(process.identity.executable.is_some());
}

#[test]
fn default_core_uses_memory_storage_without_creating_a_database_file() {
    let path = std::env::temp_dir().join(format!(
        "tracelens-memory-default-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    let config = CoreConfig {
        database: path.clone(),
        ..CoreConfig::default()
    };
    let mut core = Core::open(config).expect("open memory core");
    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));

    assert_eq!(core.store().len(), 1);
    assert!(!path.exists());
}

#[test]
fn durable_core_rebuilds_timeline_and_process_state_after_restart() {
    let path = std::env::temp_dir().join(format!(
        "tracelens-core-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    let config = CoreConfig {
        storage: StorageMode::Sqlite,
        database: path.clone(),
        ..CoreConfig::default()
    };
    {
        let mut core = Core::open(config.clone()).expect("open durable core");
        core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    }
    {
        let core = Core::open(config).expect("reopen durable core");
        assert_eq!(core.processes().len(), 1);
        let page = core.timeline_page(TimelineFilter::default());
        assert_eq!(page.total, 1);
        assert_eq!(page.entries[0].kind, EventKind::ProcessExec);
    }
    std::fs::remove_file(&path).expect("remove test database");
    let _ = std::fs::remove_file(format!("{}.wal", path.display()));
    let _ = std::fs::remove_file(format!("{}.shm", path.display()));
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

#[test]
fn detection_and_behavior_graph_use_the_live_event_models() {
    let mut core = Core::new(CoreConfig::default());
    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    core.ingest_event(TraceEvent::file_event(
        EventSource::Kernel,
        EventKind::FileOpen,
        PID,
        FileEventData {
            path: "/home/user/.ssh/id_rsa".to_owned(),
            bytes: 0,
        },
        BASE_TIME_NS + 1,
    ));
    core.ingest_event(TraceEvent::dns_event(
        EventSource::Kernel,
        EventKind::DnsResponse,
        PID,
        "new.example",
        vec![FAKE_IP.to_owned()],
        60,
        BASE_TIME_NS + 2,
    ));
    ingest_connection(
        &mut core,
        EventKind::TcpConnect,
        connection(
            "detection-socket",
            None,
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
            "detection-socket",
            None,
            ConnectionState::Established,
            TcpState::Established,
            512 * 1024,
            0,
        ),
        BASE_TIME_NS + 4,
    );

    assert!(core.alerts().iter().any(|alert| alert.rule == "new_domain"));
    assert!(core
        .alerts()
        .iter()
        .any(|alert| alert.rule == "sensitive_file_upload"));
    let graph = core.behavior_graph();
    assert!(graph
        .nodes
        .iter()
        .any(|node| node.kind == tracelens_core::graph::GraphNodeKind::Process));
    assert!(graph
        .nodes
        .iter()
        .any(|node| node.kind == tracelens_core::graph::GraphNodeKind::Domain));
    assert!(graph.edges.iter().any(|edge| edge.relation == "opened"));
}

#[test]
fn serves_detection_and_behavior_graph_through_the_api() {
    let mut core = Core::new(CoreConfig::default());
    core.ingest_event(process_event(EventKind::ProcessExec, BASE_TIME_NS));
    core.ingest_event(TraceEvent::dns_event(
        EventSource::Kernel,
        EventKind::DnsResponse,
        PID,
        "api.example",
        vec![FAKE_IP.to_owned()],
        60,
        BASE_TIME_NS + 1,
    ));
    ingest_connection(
        &mut core,
        EventKind::TcpConnect,
        connection(
            "api-detection-socket",
            None,
            ConnectionState::Established,
            TcpState::Established,
            0,
            0,
        ),
        BASE_TIME_NS + 2,
    );
    let core = Arc::new(Mutex::new(core));

    let get_json = |path: &str| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind API listener");
        let address = listener.local_addr().expect("read API address");
        let server_core = Arc::clone(&core);
        let server = std::thread::spawn(move || server::serve_once(listener, server_core));
        let mut client = TcpStream::connect(address).expect("connect API listener");
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        client
            .write_all(request.as_bytes())
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
            .expect("API response body");
        serde_json::from_str::<serde_json::Value>(body).expect("API JSON")
    };

    let alerts = get_json("/api/alerts?limit=5");
    assert!(alerts
        .as_array()
        .expect("alert array")
        .iter()
        .any(|alert| { alert["rule"] == "new_domain" }));
    let graph = get_json("/api/graph?pid=4242");
    assert!(graph["nodes"]
        .as_array()
        .expect("graph nodes")
        .iter()
        .any(|node| { node["kind"] == "process" && node["pid"] == 4242 }));
}
