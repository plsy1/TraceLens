//! Small read-only HTTP API for the local dashboard.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde::Serialize;
use tracelens_events::{ConnectionState, TcpState, TransportProtocol};

use crate::observation::{ObservationLevel, ObservationTarget};
use crate::Core;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    kernel_observation: bool,
    userspace_runtime: String,
    detail: String,
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
    first_seen_ns: u64,
    last_seen_ns: u64,
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

fn handle_connection(mut stream: TcpStream, core: &Arc<Mutex<Core>>) -> std::io::Result<()> {
    let mut buffer = [0_u8; 8192];
    let bytes_read = stream.read(&mut buffer)?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let mut request_line = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or_default();
    let path = request_line.next().unwrap_or_default();

    if method == "OPTIONS" {
        return write_response(&mut stream, 204, "", "text/plain");
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
                alerts: 0,
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
                    first_seen_ns: record.first_seen_ns,
                    last_seen_ns: record.last_seen_ns,
                })
                .collect::<Vec<_>>();
            Ok(connections)
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

fn read_process_name(pid: u32) -> Option<String> {
    let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

fn response_json<T, F>(build: F) -> Result<String, String>
where
    T: Serialize,
    F: FnOnce() -> Result<T, &'static str>,
{
    let value = build()?;
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
    content_type: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[allow(dead_code)]
fn _observation_level_is_serializable(level: ObservationLevel) -> String {
    level.to_string()
}
