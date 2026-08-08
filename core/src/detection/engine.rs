use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};

use tracelens_events::{ConnectionRef, EventKind, EventPayload, TraceEvent};

use super::{Alert, AlertSeverity};

const WINDOW_NS: u64 = 30_000_000_000;
const SENSITIVE_FILE_WINDOW_NS: u64 = 5 * 60 * 1_000_000_000;
const LARGE_UPLOAD_BYTES: u64 = 10 * 1024 * 1024;
const EXFIL_UPLOAD_BYTES: u64 = 256 * 1024;
const MAX_HISTORY: usize = 64;

#[derive(Debug, Clone)]
struct EndpointObservation {
    timestamp_ns: u64,
    endpoint: String,
}

#[derive(Debug, Clone)]
struct SensitiveFileObservation {
    timestamp_ns: u64,
    path: String,
}

#[derive(Debug, Default)]
pub struct DetectionEngine {
    seen_domains: HashSet<String>,
    recent_endpoints: HashMap<u32, Vec<EndpointObservation>>,
    beacon_history: HashMap<(u32, String), Vec<u64>>,
    sensitive_files: HashMap<u32, Vec<SensitiveFileObservation>>,
    emitted: HashSet<String>,
}

impl DetectionEngine {
    pub fn evaluate(&mut self, event: &TraceEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        match event.kind {
            EventKind::DnsResponse => self.evaluate_dns(event, &mut alerts),
            EventKind::TcpConnect => self.evaluate_connection(event, &mut alerts),
            EventKind::TcpBytes => self.evaluate_bytes(event, &mut alerts),
            EventKind::FileOpen | EventKind::FileRead => self.evaluate_file(event),
            _ => {}
        }
        alerts
    }

    fn evaluate_dns(&mut self, event: &TraceEvent, alerts: &mut Vec<Alert>) {
        let EventPayload::Dns {
            domain, addresses, ..
        } = &event.payload
        else {
            return;
        };
        let normalized_domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if !normalized_domain.is_empty() && self.seen_domains.insert(normalized_domain.clone()) {
            self.push_alert(
                alerts,
                event,
                AlertSeverity::Medium,
                "new_domain",
                format!("First-seen domain observed: {normalized_domain}"),
                None,
                Some(normalized_domain.clone()),
                vec![format!("domain={normalized_domain}")],
            );
        }
        let _ = addresses;
    }

    fn evaluate_connection(&mut self, event: &TraceEvent, alerts: &mut Vec<Alert>) {
        let Some(connection) = event.connection.as_ref() else {
            return;
        };
        let Some(pid) = event.pid else {
            return;
        };
        let endpoint = endpoint_key(connection);
        let domain = connection.domain.clone();
        let distinct_endpoints = {
            let history = self.recent_endpoints.entry(pid).or_default();
            history.retain(|observation| {
                event.timestamp_ns.saturating_sub(observation.timestamp_ns) <= WINDOW_NS
            });
            history.push(EndpointObservation {
                timestamp_ns: event.timestamp_ns,
                endpoint: endpoint.clone(),
            });
            if history.len() > MAX_HISTORY {
                let trim = history.len() - MAX_HISTORY;
                history.drain(..trim);
            }
            history
                .iter()
                .map(|observation| observation.endpoint.as_str())
                .collect::<HashSet<_>>()
                .len()
        };
        let is_scan = distinct_endpoints >= 10;
        if is_scan {
            self.push_alert(
                alerts,
                event,
                AlertSeverity::High,
                "scan",
                format!("Process touched {distinct_endpoints} endpoints in 30 seconds"),
                Some(connection),
                domain.clone(),
                vec![
                    format!("pid={pid}"),
                    format!("distinct_endpoints={distinct_endpoints}"),
                ],
            );
        }

        let is_lateral =
            is_lateral_movement_target(&connection.remote.address, connection.remote.port);
        if is_lateral {
            self.push_alert(
                alerts,
                event,
                AlertSeverity::High,
                "lateral_movement",
                format!(
                    "Process connected to an internal administration endpoint {}:{}",
                    connection.remote.address, connection.remote.port
                ),
                Some(connection),
                domain.clone(),
                vec![
                    format!(
                        "destination={}:{}",
                        connection.remote.address, connection.remote.port
                    ),
                    "private_network=true".to_owned(),
                ],
            );
        }

        let beacon_key = format!("{}:{}", connection.remote.address, connection.remote.port);
        let (regular_beacon, beacon_samples, beacon_period) = {
            let beacon_history = self
                .beacon_history
                .entry((pid, beacon_key.clone()))
                .or_default();
            beacon_history.push(event.timestamp_ns);
            if beacon_history.len() > 8 {
                beacon_history.remove(0);
            }
            let period = beacon_history
                .windows(2)
                .last()
                .map(|window| window[1].saturating_sub(window[0]) / 1_000_000_000)
                .unwrap_or_default();
            (
                is_regular_beacon(beacon_history),
                beacon_history.len(),
                period,
            )
        };
        if regular_beacon {
            self.push_alert(
                alerts,
                event,
                AlertSeverity::High,
                "beacon",
                format!("Regular connection pattern detected (period ~{beacon_period}s)"),
                Some(connection),
                domain.clone(),
                vec![
                    format!("endpoint={beacon_key}"),
                    format!("samples={beacon_samples}"),
                    format!("period_seconds={beacon_period}"),
                ],
            );
        }

        if let Some(previous_file) = self.recent_sensitive_file(pid, event.timestamp_ns) {
            if is_external_address(&connection.remote.address) {
                self.push_alert(
                    alerts,
                    event,
                    AlertSeverity::High,
                    "sensitive_file_network",
                    format!(
                        "Network access followed sensitive file activity: {}",
                        previous_file.path
                    ),
                    Some(connection),
                    domain,
                    vec![
                        format!("file={}", previous_file.path),
                        format!(
                            "destination={}:{}",
                            connection.remote.address, connection.remote.port
                        ),
                    ],
                );
            }
        }
    }

    fn evaluate_bytes(&mut self, event: &TraceEvent, alerts: &mut Vec<Alert>) {
        let Some(connection) = event.connection.as_ref() else {
            return;
        };
        if connection.sent_bytes >= LARGE_UPLOAD_BYTES
            && (connection.received_bytes == 0
                || connection.sent_bytes >= connection.received_bytes.saturating_mul(4))
        {
            self.push_alert(
                alerts,
                event,
                AlertSeverity::High,
                "suspicious_upload",
                format!(
                    "Large outbound transfer: {} bytes sent vs {} received",
                    connection.sent_bytes, connection.received_bytes
                ),
                Some(connection),
                connection.domain.clone(),
                vec![
                    format!("sent_bytes={}", connection.sent_bytes),
                    format!("received_bytes={}", connection.received_bytes),
                ],
            );
        }
        if let Some(pid) = event.pid {
            if let Some(previous_file) = self.recent_sensitive_file(pid, event.timestamp_ns) {
                if connection.sent_bytes >= EXFIL_UPLOAD_BYTES
                    && is_external_address(&connection.remote.address)
                {
                    self.push_alert(
                        alerts,
                        event,
                        AlertSeverity::Critical,
                        "sensitive_file_upload",
                        format!(
                            "Sensitive file activity followed by outbound upload: {}",
                            previous_file.path
                        ),
                        Some(connection),
                        connection.domain.clone(),
                        vec![
                            format!("file={}", previous_file.path),
                            format!("sent_bytes={}", connection.sent_bytes),
                        ],
                    );
                }
            }
        }
    }

    fn evaluate_file(&mut self, event: &TraceEvent) {
        let Some(pid) = event.pid else {
            return;
        };
        let EventPayload::File { path, .. } = &event.payload else {
            return;
        };
        if !is_sensitive_path(path) {
            return;
        }
        let history = self.sensitive_files.entry(pid).or_default();
        history.push(SensitiveFileObservation {
            timestamp_ns: event.timestamp_ns,
            path: path.clone(),
        });
        history.retain(|observation| {
            event.timestamp_ns.saturating_sub(observation.timestamp_ns) <= SENSITIVE_FILE_WINDOW_NS
        });
        if history.len() > MAX_HISTORY {
            let trim = history.len() - MAX_HISTORY;
            history.drain(..trim);
        }
    }

    fn recent_sensitive_file(
        &self,
        pid: u32,
        timestamp_ns: u64,
    ) -> Option<&SensitiveFileObservation> {
        self.sensitive_files
            .get(&pid)?
            .iter()
            .rev()
            .find(|file| timestamp_ns.saturating_sub(file.timestamp_ns) <= SENSITIVE_FILE_WINDOW_NS)
    }

    #[allow(clippy::too_many_arguments)]
    fn push_alert(
        &mut self,
        alerts: &mut Vec<Alert>,
        event: &TraceEvent,
        severity: AlertSeverity,
        rule: &str,
        summary: String,
        connection: Option<&ConnectionRef>,
        domain: Option<String>,
        evidence: Vec<String>,
    ) {
        let key = format!(
            "{rule}:{}:{}:{}",
            event.pid.unwrap_or_default(),
            match rule {
                "scan" => "".to_owned(),
                "beacon" | "lateral_movement" => connection.map(endpoint_key).unwrap_or_default(),
                _ => connection.map(|value| value.id.clone()).unwrap_or_default(),
            },
            domain.as_deref().unwrap_or_default()
        );
        if !self.emitted.insert(key) {
            return;
        }
        let process_name = event
            .process
            .as_ref()
            .and_then(|process| process.executable.clone());
        alerts.push(Alert::new(
            Some(event.id.clone()),
            event.timestamp_ns,
            severity,
            rule,
            summary,
            event.pid,
            process_name,
            connection.map(|value| value.id.clone()),
            domain,
            evidence,
        ));
    }
}

fn endpoint_key(connection: &ConnectionRef) -> String {
    format!("{}:{}", connection.remote.address, connection.remote.port)
}

fn is_regular_beacon(timestamps: &[u64]) -> bool {
    if timestamps.len() < 4 {
        return false;
    }
    let intervals = timestamps
        .windows(2)
        .map(|window| window[1].saturating_sub(window[0]))
        .collect::<Vec<_>>();
    let mean = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
    if !(1_000_000_000.0..=120_000_000_000.0).contains(&mean) {
        return false;
    }
    intervals
        .iter()
        .all(|interval| ((*interval as f64 - mean).abs() / mean) <= 0.2)
}

fn is_sensitive_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    if [
        "/proc/",
        "/sys/",
        "/dev/",
        "/usr/",
        "/lib/",
        "/run/",
        "/var/lib/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        return false;
    }
    [
        "/etc/shadow",
        "/etc/passwd",
        "/.ssh/",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "token",
        "secret",
        "/.aws/",
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

fn is_lateral_movement_target(address: &str, port: u16) -> bool {
    is_private_address(address) && matches!(port, 22 | 23 | 135 | 139 | 445 | 3389 | 5985 | 5986)
}

fn is_external_address(address: &str) -> bool {
    !is_private_address(address)
}

fn is_private_address(address: &str) -> bool {
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.octets()[0] == 100 && (address.octets()[1] & 0b1100_0000) == 64
                || address.octets()[0] == 198 && address.octets()[1] == 18
        }
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || is_unique_local(address)
                || is_link_local_v6(address)
        }
    }
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xfe00) == 0xfc00
}

fn is_link_local_v6(address: Ipv6Addr) -> bool {
    (address.segments()[0] & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use tracelens_events::{
        ConnectionRef, ConnectionState, Endpoint, EventKind, EventSource, FileEventData, TcpState,
        TraceEvent, TransportProtocol,
    };

    use super::DetectionEngine;

    fn connection(id: &str, address: &str, port: u16, sent: u64, received: u64) -> ConnectionRef {
        ConnectionRef {
            id: id.to_owned(),
            protocol: TransportProtocol::Tcp,
            local: None,
            remote: Endpoint {
                address: address.to_owned(),
                port,
            },
            state: ConnectionState::Established,
            tcp_state: Some(TcpState::Established),
            sent_bytes: sent,
            received_bytes: received,
            domain: None,
        }
    }

    #[test]
    fn detects_first_seen_domain_and_large_upload() {
        let mut engine = DetectionEngine::default();
        let domain = TraceEvent::dns_event(
            EventSource::Kernel,
            EventKind::DnsResponse,
            7,
            "new.example",
            vec!["203.0.113.7".to_owned()],
            60,
            1,
        );
        assert_eq!(engine.evaluate(&domain)[0].rule, "new_domain");

        let upload = TraceEvent::connection_event(
            EventSource::Kernel,
            EventKind::TcpBytes,
            7,
            connection("socket-7", "203.0.113.7", 443, 20 * 1024 * 1024, 0),
            2,
        );
        assert_eq!(engine.evaluate(&upload)[0].rule, "suspicious_upload");
    }

    #[test]
    fn correlates_sensitive_file_with_external_upload() {
        let mut engine = DetectionEngine::default();
        let file = TraceEvent::file_event(
            EventSource::Kernel,
            EventKind::FileOpen,
            7,
            FileEventData {
                path: "/home/user/.ssh/id_rsa".to_owned(),
                bytes: 0,
            },
            1,
        );
        assert!(engine.evaluate(&file).is_empty());
        let upload = TraceEvent::connection_event(
            EventSource::Kernel,
            EventKind::TcpBytes,
            7,
            connection("socket-7", "203.0.113.7", 443, 512 * 1024, 0),
            2,
        );
        let alerts = engine.evaluate(&upload);
        assert!(alerts
            .iter()
            .any(|alert| alert.rule == "sensitive_file_upload"));
    }

    #[test]
    fn detects_internal_admin_endpoint() {
        let mut engine = DetectionEngine::default();
        let event = TraceEvent::connection_event(
            EventSource::Kernel,
            EventKind::TcpConnect,
            7,
            connection("socket-7", "10.0.0.12", 22, 0, 0),
            1,
        );
        assert!(engine
            .evaluate(&event)
            .iter()
            .any(|alert| alert.rule == "lateral_movement"));
    }

    #[test]
    fn detects_scan_and_regular_beacon_patterns() {
        let mut scan_engine = DetectionEngine::default();
        let mut scan_alerts = Vec::new();
        for index in 0..10 {
            let event = TraceEvent::connection_event(
                EventSource::Kernel,
                EventKind::TcpConnect,
                7,
                connection(
                    &format!("scan-{index}"),
                    &format!("198.51.100.{}", index + 1),
                    8000,
                    0,
                    0,
                ),
                index,
            );
            scan_alerts.extend(scan_engine.evaluate(&event));
        }
        assert!(scan_alerts.iter().any(|alert| alert.rule == "scan"));

        let mut beacon_engine = DetectionEngine::default();
        let mut beacon_alerts = Vec::new();
        for index in 0..4 {
            let event = TraceEvent::connection_event(
                EventSource::Kernel,
                EventKind::TcpConnect,
                7,
                connection(&format!("beacon-{index}"), "203.0.113.9", 443, 0, 0),
                index * 60_000_000_000,
            );
            beacon_alerts.extend(beacon_engine.evaluate(&event));
        }
        assert!(beacon_alerts.iter().any(|alert| alert.rule == "beacon"));
    }
}
