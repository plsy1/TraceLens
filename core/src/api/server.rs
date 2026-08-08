//! Small read-only HTTP API for the local dashboard.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};
use tracelens_events::{ConnectionState, EventKind, TcpState, TransportProtocol};

use crate::detection::{Alert, AlertSeverity};
use crate::events::{ConnectionTimelineFilter, TimelineFilter};
use crate::graph::BehaviorGraph;
use crate::observation::{ObservationLevel, ObservationTarget};
use crate::Core;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    kernel_observation: bool,
    userspace_runtime: String,
    detail: String,
    attached_probes: Vec<String>,
    probe_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SummaryResponse {
    processes: usize,
    connections: usize,
    domains: usize,
    alerts: usize,
    observation_level: String,
}

#[derive(Debug, Serialize)]
struct ProcessResponse {
    pid: u32,
    ppid: Option<u32>,
    name: String,
    command_line: Option<String>,
    first_seen_ns: u64,
    last_seen_ns: u64,
    connections: usize,
    sent_bytes: u64,
    received_bytes: u64,
    level: String,
    risk_score: f32,
}

#[derive(Debug, Serialize)]
struct ConnectionResponse {
    id: String,
    pid: Option<u32>,
    process_name: Option<String>,
    process_command_line: Option<String>,
    protocol: TransportProtocol,
    local: Option<tracelens_events::Endpoint>,
    remote: tracelens_events::Endpoint,
    state: ConnectionState,
    tcp_state: Option<TcpState>,
    sent_bytes: u64,
    received_bytes: u64,
    domain: Option<String>,
    tls_sni: Option<String>,
    tls_version: Option<String>,
    first_seen_ns: u64,
    last_seen_ns: u64,
    risk_score: f32,
}

#[derive(Debug, Serialize)]
struct ObservationResponse {
    target: String,
    level: String,
    expires_in_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ObservationCommand {
    target: String,
    level: u8,
    duration_secs: Option<u64>,
    #[serde(default)]
    exact: bool,
}

pub fn serve(core: Arc<Mutex<Core>>, listen: SocketAddr) -> std::io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    eprintln!("TraceLens API listening on http://{listen}");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let core = Arc::clone(&core);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, &core) {
                        eprintln!("API request failed: {error}");
                    }
                });
            }
            Err(error) => eprintln!("API accept failed: {error}"),
        }
    }

    Ok(())
}

/// Serve one request on a pre-bound listener. This keeps API contract tests
/// deterministic without starting an unbounded server thread.
pub fn serve_once(listener: TcpListener, core: Arc<Mutex<Core>>) -> std::io::Result<()> {
    let (stream, _) = listener.accept()?;
    handle_connection(stream, &core)
}

fn handle_connection(mut stream: TcpStream, core: &Arc<Mutex<Core>>) -> std::io::Result<()> {
    let request = read_http_request(&mut stream)?;
    let (headers, body) = request
        .split_once("\r\n\r\n")
        .unwrap_or((request.as_str(), ""));
    let mut request_line = headers
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or_default();
    let raw_path = request_line.next().unwrap_or_default();
    let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));

    if method == "OPTIONS" {
        return write_response(&mut stream, 204, "", "text/plain");
    }
    if method == "POST" && path == "/api/observations" {
        return handle_observation_command(&mut stream, core, body);
    }
    if method == "DELETE" && path == "/api/observations" {
        return handle_observation_delete(&mut stream, core, query);
    }
    if method != "GET" {
        return write_response(
            &mut stream,
            405,
            "{\"error\":\"method not allowed\"}",
            "application/json",
        );
    }

    let body = match path {
        "/api/health" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            Ok(HealthResponse {
                status: "ok",
                kernel_observation: core.runtime_status().kernel_observation,
                userspace_runtime: core.runtime_status().userspace_runtime.to_string(),
                detail: core.runtime_status().detail.clone(),
                attached_probes: core
                    .probe_attachments()
                    .into_iter()
                    .map(|attachment| {
                        format!(
                            "{}:{}:{} pid={} ({})",
                            attachment.target,
                            attachment.probe,
                            attachment.hook,
                            attachment.pid,
                            attachment.runtime
                        )
                    })
                    .collect(),
                probe_errors: core.probe_errors().to_vec(),
            })
        }),
        "/api/summary" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            let active_connections = core
                .connections()
                .all()
                .filter(|record| record.connection.state != ConnectionState::Closed)
                .count();
            let domains = core
                .connections()
                .all()
                .filter_map(|record| record.connection.domain.as_ref())
                .collect::<std::collections::HashSet<_>>()
                .len();
            Ok(SummaryResponse {
                processes: core.processes().len(),
                connections: active_connections,
                domains,
                alerts: core.alerts().len(),
                observation_level: core.config().default_observation_level.to_string(),
            })
        }),
        "/api/processes" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            let processes = core
                .processes()
                .all()
                .map(|record| {
                    let pid = record.identity.pid;
                    let (connections, sent_bytes, received_bytes) = core
                        .connections()
                        .all()
                        .filter(|connection| connection.pid == Some(pid))
                        .fold((0, 0, 0), |(count, sent, received), connection| {
                            (
                                count
                                    + usize::from(
                                        connection.connection.state != ConnectionState::Closed,
                                    ),
                                sent + connection.connection.sent_bytes,
                                received + connection.connection.received_bytes,
                            )
                        });
                    ProcessResponse {
                        pid,
                        ppid: record.identity.ppid,
                        name: record
                            .identity
                            .executable
                            .clone()
                            .unwrap_or_else(|| "unknown".to_owned()),
                        command_line: record.identity.command_line.clone(),
                        first_seen_ns: record.first_seen_ns,
                        last_seen_ns: record.last_seen_ns,
                        connections,
                        sent_bytes,
                        received_bytes,
                        level: core
                            .observations()
                            .current_level(&ObservationTarget::Process(pid))
                            .to_string(),
                        risk_score: core.risk_score_for_process(pid).0,
                    }
                })
                .collect::<Vec<_>>();
            Ok(processes)
        }),
        "/api/connections" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            let connections = core
                .connections()
                .all()
                .map(|record| ConnectionResponse {
                    id: record.connection.id.clone(),
                    pid: record.pid,
                    process_name: record
                        .process
                        .as_ref()
                        .and_then(|process| process.executable.clone())
                        .or_else(|| record.pid.and_then(read_process_name)),
                    process_command_line: record
                        .process
                        .as_ref()
                        .and_then(|process| process.command_line.clone()),
                    protocol: record.connection.protocol,
                    local: record.connection.local.clone(),
                    remote: record.connection.remote.clone(),
                    state: record.connection.state,
                    tcp_state: record.connection.tcp_state,
                    sent_bytes: record.connection.sent_bytes,
                    received_bytes: record.connection.received_bytes,
                    domain: record.connection.domain.clone(),
                    tls_sni: core
                        .tls_metadata_for_connection(&record.connection.id)
                        .and_then(|(sni, _)| sni),
                    tls_version: core
                        .tls_metadata_for_connection(&record.connection.id)
                        .and_then(|(_, version)| version),
                    first_seen_ns: record.first_seen_ns,
                    last_seen_ns: record.last_seen_ns,
                    risk_score: core.risk_score_for_connection(&record.connection.id).0,
                })
                .collect::<Vec<_>>();
            Ok(connections)
        }),
        "/api/timeline" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            Ok(core.timeline_page(timeline_filter(query)))
        }),
        "/api/connection-timeline" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            Ok(core.connection_timeline_page(connection_timeline_filter(query)))
        }),
        "/api/alerts" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            Ok(alerts_for_query(core.alerts(), query))
        }),
        "/api/graph" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            Ok(graph_for_query(core.behavior_graph(), query))
        }),
        "/api/observations" => response_json(|| {
            let core = core.lock().map_err(|_| "core lock poisoned")?;
            Ok(core
                .observation_statuses()
                .into_iter()
                .map(|status| ObservationResponse {
                    target: status.target.to_string(),
                    level: status.level.to_string(),
                    expires_in_secs: status.expires_in_secs,
                })
                .collect::<Vec<_>>())
        }),
        _ => {
            return write_response(
                &mut stream,
                404,
                "{\"error\":\"not found\"}",
                "application/json",
            )
        }
    };

    match body {
        Ok(body) => write_response(&mut stream, 200, &body, "application/json"),
        Err(error) => write_response(
            &mut stream,
            500,
            &format!("{{\"error\":\"{error}\"}}"),
            "application/json",
        ),
    }
}

fn timeline_filter(query: &str) -> TimelineFilter {
    TimelineFilter {
        pid: query_parameter(query, "pid").and_then(|value| value.parse().ok()),
        kind: query_parameter(query, "kind").and_then(|value| parse_event_kind(&value)),
        connection_id: query_parameter(query, "connection_id"),
        offset: query_parameter(query, "offset")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        limit: query_parameter(query, "limit")
            .and_then(|value| value.parse().ok())
            .unwrap_or(50)
            .clamp(1, 200),
    }
}

fn connection_timeline_filter(query: &str) -> ConnectionTimelineFilter {
    ConnectionTimelineFilter {
        pid: query_parameter(query, "pid").and_then(|value| value.parse().ok()),
        connection_id: query_parameter(query, "connection_id"),
        include_closed: query_parameter(query, "include_closed")
            .and_then(|value| value.parse().ok())
            .unwrap_or(true),
        include_events: query_parameter(query, "include_events")
            .and_then(|value| value.parse().ok())
            .unwrap_or(true),
        event_limit: query_parameter(query, "event_limit")
            .and_then(|value| value.parse().ok())
            .unwrap_or(200)
            .clamp(1, 200),
        offset: query_parameter(query, "offset")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        limit: query_parameter(query, "limit")
            .and_then(|value| value.parse().ok())
            .unwrap_or(50)
            .clamp(1, 200),
    }
}

fn handle_observation_command(
    stream: &mut TcpStream,
    core: &Arc<Mutex<Core>>,
    body: &str,
) -> std::io::Result<()> {
    let command: ObservationCommand = match serde_json::from_str(body) {
        Ok(command) => command,
        Err(error) => {
            return write_json_error(
                stream,
                400,
                &format!("invalid observation command: {error}"),
            )
        }
    };
    let target = match command.target.parse::<ObservationTarget>() {
        Ok(target) => target,
        Err(error) => return write_json_error(stream, 400, &error),
    };
    let level = match ObservationLevel::from_number(command.level) {
        Some(level) => level,
        None => return write_json_error(stream, 400, "observation level must be between 1 and 5"),
    };
    let response = {
        let mut core = match core.lock() {
            Ok(core) => core,
            Err(_) => return write_json_error(stream, 500, "core lock poisoned"),
        };
        let target_name = target.to_string();
        let applied_level = if command.exact {
            core.set_observation(target.clone(), level, command.duration_secs)
        } else {
            core.upgrade_observation(target.clone(), level, command.duration_secs)
        };
        let expires_in_secs = core
            .observation_statuses()
            .into_iter()
            .find(|status| status.target == target)
            .and_then(|status| status.expires_in_secs);
        ObservationResponse {
            target: target_name,
            level: applied_level.to_string(),
            expires_in_secs,
        }
    };
    let body = serde_json::to_string(&response)
        .map_err(|error| io::Error::other(format!("encode observation response: {error}")))?;
    write_response(stream, 200, &body, "application/json")
}

fn handle_observation_delete(
    stream: &mut TcpStream,
    core: &Arc<Mutex<Core>>,
    query: &str,
) -> std::io::Result<()> {
    let Some(raw_target) = query_parameter(query, "target") else {
        return write_json_error(stream, 400, "target query parameter is required");
    };
    let target = match raw_target.parse::<ObservationTarget>() {
        Ok(target) => target,
        Err(error) => return write_json_error(stream, 400, &error),
    };
    let level = match core.lock() {
        Ok(mut core) => core.downgrade_observation(&target),
        Err(_) => return write_json_error(stream, 500, "core lock poisoned"),
    };
    let body = serde_json::to_string(&ObservationResponse {
        target: target.to_string(),
        level: level.to_string(),
        expires_in_secs: None,
    })
    .map_err(|error| io::Error::other(format!("encode observation response: {error}")))?;
    write_response(stream, 200, &body, "application/json")
}

fn query_parameter(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|parameter| {
        let (parameter_name, value) = parameter.split_once('=')?;
        let parameter_name = decode_query_component(parameter_name)?;
        (parameter_name == name).then(|| decode_query_component(value))?
    })
}

fn decode_query_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn parse_event_kind(value: &str) -> Option<EventKind> {
    Some(match value {
        "process_exec" => EventKind::ProcessExec,
        "process_exit" => EventKind::ProcessExit,
        "tcp_connect" => EventKind::TcpConnect,
        "tcp_close" => EventKind::TcpClose,
        "tcp_state_changed" => EventKind::TcpStateChanged,
        "tcp_bytes" => EventKind::TcpBytes,
        "dns_query" => EventKind::DnsQuery,
        "dns_response" => EventKind::DnsResponse,
        "tls_metadata" => EventKind::TlsMetadata,
        "plaintext" => EventKind::Plaintext,
        "http" => EventKind::Http,
        "file_open" => EventKind::FileOpen,
        "file_read" => EventKind::FileRead,
        "observation_changed" => EventKind::ObservationChanged,
        _ => return None,
    })
}

fn read_process_name(pid: u32) -> Option<String> {
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

fn alerts_for_query(alerts: &[Alert], query: &str) -> Vec<Alert> {
    let pid = query_parameter(query, "pid").and_then(|value| value.parse::<u32>().ok());
    let rule = query_parameter(query, "rule");
    let severity = query_parameter(query, "severity").and_then(|value| {
        match value.to_ascii_lowercase().as_str() {
            "low" => Some(AlertSeverity::Low),
            "medium" => Some(AlertSeverity::Medium),
            "high" => Some(AlertSeverity::High),
            "critical" => Some(AlertSeverity::Critical),
            _ => None,
        }
    });
    let limit = query_parameter(query, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, 200);
    alerts
        .iter()
        .rev()
        .filter(|alert| pid.is_none_or(|pid| alert.process_id == Some(pid)))
        .filter(|alert| rule.as_deref().is_none_or(|rule| alert.rule == rule))
        .filter(|alert| severity.is_none_or(|severity| alert.severity == severity))
        .take(limit)
        .cloned()
        .collect()
}

fn graph_for_query(mut graph: BehaviorGraph, query: &str) -> BehaviorGraph {
    let Some(pid) = query_parameter(query, "pid").and_then(|value| value.parse::<u32>().ok())
    else {
        return graph;
    };
    let process_id = format!("process:{pid}");
    let mut related = std::collections::HashSet::from([process_id.clone()]);
    for edge in &graph.edges {
        if edge.source == process_id || edge.target == process_id {
            related.insert(edge.source.clone());
            related.insert(edge.target.clone());
        }
    }
    graph.nodes.retain(|node| related.contains(&node.id));
    graph
        .edges
        .retain(|edge| related.contains(&edge.source) && related.contains(&edge.target));
    graph
}

fn response_json<T, F>(build: F) -> Result<String, String>
where
    T: Serialize,
    F: FnOnce() -> Result<T, &'static str>,
{
    let value = build()?;
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

fn write_json_error(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let body = serde_json::json!({ "error": message }).to_string();
    write_response(stream, status, &body, "application/json")
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<String> {
    const MAX_REQUEST_BYTES: usize = 1 << 20;
    let mut request = Vec::with_capacity(8192);
    let mut chunk = [0_u8; 8192];
    let header_end = loop {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before sending HTTP headers",
            ));
        }
        request.extend_from_slice(&chunk[..bytes_read]);
        if request.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP request exceeds the 1 MiB limit",
            ));
        }
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };

    let content_length = String::from_utf8_lossy(&request[..header_end])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let required_length = header_end.saturating_add(content_length);
    if required_length > MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request exceeds the 1 MiB limit",
        ));
    }
    while request.len() < required_length {
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client closed before sending the complete HTTP body",
            ));
        }
        request.extend_from_slice(&chunk[..bytes_read]);
    }
    String::from_utf8(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
    content_type: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        204 => "No Content",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[allow(dead_code)]
fn _observation_level_is_serializable(level: ObservationLevel) -> String {
    level.to_string()
}

#[cfg(test)]
mod tests {
    use super::{query_parameter, timeline_filter};

    #[test]
    fn decodes_encoded_connection_targets() {
        assert_eq!(
            query_parameter("connection_id=socket-1%3A443+test", "connection_id"),
            Some("socket-1:443 test".to_owned())
        );
    }

    #[test]
    fn timeline_filter_accepts_encoded_event_kind() {
        assert_eq!(
            timeline_filter("kind=tls_metadata&connection_id=socket-1%3A2").connection_id,
            Some("socket-1:2".to_owned())
        );
    }
}
