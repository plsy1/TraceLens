//! TraceLens core service.
//!
//! Runtime integrations are intentionally kept behind small interfaces. The
//! event model and observation manager can therefore be tested before kernel
//! probes or bpftime are attached.

pub mod api;
pub mod config;
pub mod detection;
pub mod dns;
pub mod events;
pub mod graph;
pub mod http;
pub mod network;
pub mod observation;
pub mod process;
pub mod runtime;
pub mod storage;
pub mod tls;

use std::collections::{HashMap, HashSet};

use config::{CoreConfig, StorageMode};
use detection::{Alert, DetectionEngine, RiskScore};
use dns::DnsTracker;
use events::{
    ConnectionTimeline, ConnectionTimelineFilter, ConnectionTimelinePage, EventBus,
    EventCorrelator, TimelineEntry, TimelineFilter, TimelinePage,
};
use http::{HttpMessage, HttpTracker};
use network::ConnectionTracker;
use observation::ObservationManager;
use process::{read_process_ref, ProcessTracker};
use runtime::{ProbeAttachment, ProbeRuntime, RuntimeStatus};
use storage::{EventQuery, EventStore};
use tls::TlsTracker;
use tracelens_events::{
    EventKind, EventPayload, EventSource, HttpEventData, HttpHeader, HttpMessageDirection,
    TlsEventData, TraceEvent,
};

/// Top-level composition root for the core service.
pub struct Core {
    config: CoreConfig,
    runtime: RuntimeStatus,
    probe_runtime: ProbeRuntime,
    event_bus: EventBus,
    correlator: EventCorrelator,
    store: EventStore,
    processes: ProcessTracker,
    connections: ConnectionTracker,
    dns: DnsTracker,
    tls: TlsTracker,
    http: HttpTracker,
    observations: ObservationManager,
    detection: DetectionEngine,
    alerts: Vec<Alert>,
}

impl Core {
    /// Create a core backed by an isolated in-memory event store.
    ///
    /// This is useful for tests and short-lived library consumers. The CLI
    /// observer uses [`Self::open`] and follows the configured storage mode.
    pub fn new(config: CoreConfig) -> Self {
        let memory_event_limit = config.memory_event_limit;
        Self::with_store(config, EventStore::memory(memory_event_limit))
    }

    /// Open a core using the configured storage mode. Memory mode starts
    /// empty; SQLite mode rebuilds the live read models from persisted history.
    pub fn open(config: CoreConfig) -> Result<Self, String> {
        let storage = config.storage;
        let memory_event_limit = config.memory_event_limit;
        let store = match storage {
            StorageMode::Memory => EventStore::memory(memory_event_limit),
            StorageMode::Sqlite => EventStore::open(&config.database)?,
        };
        let mut core = Self::with_store(config, store);
        if storage == StorageMode::Sqlite {
            core.rebuild_read_models();
        }
        Ok(core)
    }

    fn with_store(config: CoreConfig, store: EventStore) -> Self {
        let default_observation_level = config.default_observation_level;
        let runtime = RuntimeStatus::detect_with_preference(&config.preferred_userspace_runtime);
        let probe_runtime = ProbeRuntime::new(&runtime, &config.bpf_object_dir);
        Self {
            config,
            runtime,
            probe_runtime,
            event_bus: EventBus::new(),
            correlator: EventCorrelator::new(),
            store,
            processes: ProcessTracker::default(),
            connections: ConnectionTracker::default(),
            dns: DnsTracker::default(),
            tls: TlsTracker::default(),
            http: HttpTracker::default(),
            observations: ObservationManager::new(default_observation_level),
            detection: DetectionEngine::default(),
            alerts: Vec::new(),
        }
    }

    pub fn config(&self) -> &CoreConfig {
        &self.config
    }

    pub fn runtime_status(&self) -> &RuntimeStatus {
        &self.runtime
    }

    pub fn probe_attachments(&self) -> Vec<ProbeAttachment> {
        self.probe_runtime.attachments()
    }

    pub fn probe_errors(&self) -> &[String] {
        self.probe_runtime.errors()
    }

    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    pub fn correlator(&self) -> &EventCorrelator {
        &self.correlator
    }

    pub fn store(&self) -> &EventStore {
        &self.store
    }

    pub fn processes(&self) -> &ProcessTracker {
        &self.processes
    }

    pub fn connections(&self) -> &ConnectionTracker {
        &self.connections
    }

    pub fn dns(&self) -> &DnsTracker {
        &self.dns
    }

    pub fn tls(&self) -> &TlsTracker {
        &self.tls
    }

    pub fn http_stream_count(&self) -> usize {
        self.http.stream_count()
    }

    pub fn set_probe_event_sender(&mut self, sender: std::sync::mpsc::Sender<TraceEvent>) {
        self.probe_runtime.set_event_sender(sender);
    }

    pub fn tls_metadata_for_connection(
        &self,
        connection_id: &str,
    ) -> Option<(Option<String>, Option<String>)> {
        self.tls
            .metadata_for_connection(connection_id)
            .map(|session| (session.server_name.clone(), session.version.clone()))
    }

    pub fn observations(&self) -> &ObservationManager {
        &self.observations
    }

    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    pub fn risk_score_for_process(&self, pid: u32) -> RiskScore {
        RiskScore(
            self.alerts
                .iter()
                .filter(|alert| alert.process_id == Some(pid))
                .map(|alert| alert.risk_score)
                .fold(0.0, |score, alert| score + alert.0),
        )
        .clamp()
    }

    pub fn risk_score_for_connection(&self, connection_id: &str) -> RiskScore {
        let canonical_id = self.connections.canonical_id(connection_id);
        RiskScore(
            self.alerts
                .iter()
                .filter(|alert| {
                    alert
                        .connection_id
                        .as_deref()
                        .map(|id| self.connections.canonical_id(id) == canonical_id)
                        .unwrap_or(false)
                })
                .map(|alert| alert.risk_score)
                .fold(0.0, |score, alert| score + alert.0),
        )
        .clamp()
    }

    pub fn behavior_graph(&self) -> graph::BehaviorGraph {
        graph::build(self)
    }

    pub fn timeline(&self, limit: usize) -> Vec<TimelineEntry> {
        self.timeline_page(TimelineFilter {
            limit,
            ..TimelineFilter::default()
        })
        .entries
    }

    pub fn timeline_page(&self, filter: TimelineFilter) -> TimelinePage {
        let page = self
            .store
            .query(EventQuery {
                pid: filter.pid,
                kind: filter.kind,
                connection_id: filter.connection_id,
                offset: filter.offset,
                limit: filter.limit,
            })
            .unwrap_or_default();
        TimelinePage {
            entries: page
                .events
                .into_iter()
                .map(|event| {
                    let mut entry = TimelineEntry::from_event(event);
                    if let Some(connection_id) = entry.connection_id.as_deref() {
                        entry.connection_id =
                            Some(self.connections.canonical_id(connection_id).to_owned());
                    }
                    entry
                })
                .collect(),
            total: page.total,
            offset: page.offset,
            limit: page.limit,
            has_more: page.has_more,
        }
    }

    pub fn connection_timeline_page(
        &self,
        filter: ConnectionTimelineFilter,
    ) -> ConnectionTimelinePage {
        let mut records = self
            .connections
            .all()
            .filter(|record| filter.pid.is_none_or(|pid| record.pid == Some(pid)))
            .filter(|record| {
                filter
                    .connection_id
                    .as_ref()
                    .is_none_or(|id| self.connections.canonical_id(id) == record.connection.id)
            })
            .filter(|record| {
                filter.include_closed
                    || record.connection.state != tracelens_events::ConnectionState::Closed
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .last_seen_ns
                .cmp(&left.last_seen_ns)
                .then_with(|| right.connection.id.cmp(&left.connection.id))
        });

        let total = records.len();
        let limit = filter.limit.clamp(1, 200);
        let offset = filter.offset.min(total);
        let records = records
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();

        let mut dns_events_by_pid: HashMap<u32, Vec<TraceEvent>> = HashMap::new();
        if filter.include_events {
            for pid in records.iter().filter_map(|record| record.pid) {
                if dns_events_by_pid.contains_key(&pid) {
                    continue;
                }
                let mut dns_events = Vec::new();
                for kind in [EventKind::DnsQuery, EventKind::DnsResponse] {
                    if let Ok(page) = self.store.query(EventQuery {
                        pid: Some(pid),
                        kind: Some(kind),
                        limit: 200,
                        ..EventQuery::default()
                    }) {
                        dns_events.extend(page.events);
                    }
                }
                dns_events.sort_by_key(|event| event.timestamp_ns);
                dns_events_by_pid.insert(pid, dns_events);
            }
        }

        let sessions = records
            .into_iter()
            .map(|record| {
                let connection_id = record.connection.id.clone();
                let mut event_ids = HashSet::new();
                let mut events = Vec::new();
                let mut event_count = 0usize;
                for event_id in self.connections.event_ids_for(&connection_id) {
                    let Ok(page) = self.store.query(EventQuery {
                        connection_id: Some(event_id),
                        limit: if filter.include_events {
                            filter.event_limit.clamp(1, 200)
                        } else {
                            1
                        },
                        ..EventQuery::default()
                    }) else {
                        continue;
                    };
                    event_count = event_count.saturating_add(page.total);
                    if !filter.include_events {
                        continue;
                    }
                    for event in page.events {
                        if !event_ids.insert(event.id.clone()) {
                            continue;
                        }
                        let mut entry = TimelineEntry::from_event(event);
                        entry.connection_id = Some(connection_id.clone());
                        events.push(entry);
                    }
                }

                if filter.include_events {
                    let events_before_dns = events.len();
                    self.append_dns_context(
                        record,
                        record.pid.and_then(|pid| dns_events_by_pid.get(&pid)),
                        &mut event_ids,
                        &mut events,
                    );
                    event_count = event_count.saturating_add(events.len() - events_before_dns);
                    events.sort_by_key(|event| event.timestamp_ns);
                    let event_limit = filter.event_limit.clamp(1, 200);
                    if events.len() > event_limit {
                        let trim_count = events.len() - event_limit;
                        events.drain(..trim_count);
                    }
                }

                let process_name = record
                    .process
                    .as_ref()
                    .and_then(|process| process.executable.clone());
                let process_command_line = record
                    .process
                    .as_ref()
                    .and_then(|process| process.command_line.clone());
                ConnectionTimeline {
                    id: connection_id.clone(),
                    pid: record.pid,
                    process_name,
                    process_command_line,
                    protocol: record.connection.protocol,
                    local: record.connection.local.clone(),
                    remote: record.connection.remote.clone(),
                    domain: record.connection.domain.clone(),
                    tls_sni: self
                        .tls
                        .metadata_for_connection(&connection_id)
                        .and_then(|session| session.server_name.clone()),
                    tls_version: self
                        .tls
                        .metadata_for_connection(&connection_id)
                        .and_then(|session| session.version.clone()),
                    state: record.connection.state,
                    tcp_state: record.connection.tcp_state,
                    first_seen_ns: record.first_seen_ns,
                    last_seen_ns: record.last_seen_ns,
                    duration_ns: record.last_seen_ns.saturating_sub(record.first_seen_ns),
                    sent_bytes: record.connection.sent_bytes,
                    received_bytes: record.connection.received_bytes,
                    event_count,
                    events,
                }
            })
            .collect::<Vec<_>>();

        ConnectionTimelinePage {
            has_more: offset + sessions.len() < total,
            sessions,
            total,
            offset,
            limit,
        }
    }

    pub fn ingest_event(&mut self, mut event: TraceEvent) {
        self.expire_observations();
        self.apply_event(&mut event);
        let derived_http_events = self.derive_http_events(&event);

        let persist_input = event.kind != EventKind::HttpCapture
            && (!matches!(event.kind, EventKind::FileOpen | EventKind::FileRead)
                || is_security_relevant_file_event(&event));
        let event = self.correlator.correlate(event);
        self.evaluate_event(&event);
        if persist_input {
            self.store.insert(event.clone());
            self.event_bus.publish(event);
        }
        for http_event in derived_http_events {
            let http_event = self.correlator.correlate(http_event);
            self.evaluate_event(&http_event);
            self.store.insert(http_event.clone());
            self.event_bus.publish(http_event);
        }
    }

    fn evaluate_event(&mut self, event: &TraceEvent) {
        const ALERT_LIMIT: usize = 1_000;
        for alert in self.detection.evaluate(event) {
            self.alerts.push(alert);
        }
        if self.alerts.len() > ALERT_LIMIT {
            let trim = self.alerts.len() - ALERT_LIMIT;
            self.alerts.drain(..trim);
        }
    }

    fn apply_event(&mut self, event: &mut TraceEvent) {
        if event.process.is_none() {
            event.process = event
                .pid
                .and_then(|pid| self.processes.get(pid))
                .map(|record| record.identity.clone())
                .or_else(|| {
                    event
                        .pid
                        .and_then(|pid| read_process_ref(pid, event.timestamp_ns))
                });
        }

        if event.kind != EventKind::ProcessExit {
            if let Some(process) = event.process.clone() {
                self.processes.observe(process, event.timestamp_ns);
            }
        }

        match event.kind {
            EventKind::ProcessExec => {}
            EventKind::ProcessExit => {
                if let Some(pid) = event.pid {
                    self.processes.remove(pid);
                    self.tls.remove_process(pid);
                    self.probe_runtime.detach_target(&format!("process:{pid}"));
                }
            }
            EventKind::TcpConnect | EventKind::TcpClose => {
                self.apply_connection_event(event);
            }
            EventKind::TcpStateChanged | EventKind::TcpBytes => {
                self.apply_connection_event(event);
            }
            EventKind::DnsResponse => {
                if let EventPayload::Dns {
                    protocol: _,
                    domain,
                    addresses,
                    ttl_secs,
                } = &event.payload
                {
                    if let Some(pid) = event.pid {
                        self.dns.observe_response_for_process(
                            pid,
                            domain.clone(),
                            addresses.clone(),
                            *ttl_secs,
                            event.timestamp_ns,
                        );
                    } else {
                        self.dns.observe_response(
                            domain.clone(),
                            addresses.clone(),
                            *ttl_secs,
                            event.timestamp_ns,
                        );
                    }
                    if !addresses.is_empty() {
                        if let Some(pid) = event.pid {
                            self.connections.set_domain(pid, addresses, domain);
                        }
                        self.connections.set_domain_for_addresses(addresses, domain);
                    }
                }
            }
            EventKind::TlsMetadata => self.apply_tls_event(event),
            EventKind::Plaintext | EventKind::HttpCapture => self.apply_plaintext_event(event),
            EventKind::FileOpen | EventKind::FileRead => {}
            _ => {}
        }
    }

    fn apply_tls_event(&mut self, event: &mut TraceEvent) {
        let Some(pid) = event.pid else {
            return;
        };
        let EventPayload::Tls {
            ssl_object,
            fd,
            sni,
            version,
        } = &mut event.payload
        else {
            return;
        };

        let fd_connection_id = fd.and_then(|fd| {
            if fd < 0 {
                return None;
            }
            let socket_id = format!("socket-{}", (u64::from(pid) << 32) | u64::from(fd as u32));
            self.connections
                .get(&socket_id)
                .map(|record| record.connection.id.clone())
        });
        let previous_connection_id = self
            .tls
            .latest_for_process(pid)
            .and_then(|session| session.connection_id.clone());
        let event_connection_id = event
            .connection
            .as_ref()
            .map(|connection| connection.id.clone());
        let connection_id = fd_connection_id
            .or(previous_connection_id)
            .or(event_connection_id);
        let session_ssl_object = self.tls.observe_event(
            pid,
            TlsEventData {
                ssl_object: *ssl_object,
                fd: *fd,
                sni: sni.clone(),
                version: version.clone(),
            },
            connection_id.clone(),
            event.timestamp_ns,
        );

        if *ssl_object == 0 {
            *ssl_object = session_ssl_object;
        }
        if let Some(session) = self.tls.get(pid, session_ssl_object) {
            if fd.is_none() {
                *fd = session.fd;
            }
            if sni.is_none() {
                *sni = session.server_name.clone();
            }
            if version.is_none() {
                *version = session.version.clone();
            }
        }

        let connection_id = connection_id.or_else(|| {
            self.tls
                .get(pid, session_ssl_object)
                .and_then(|session| session.connection_id.clone())
        });
        if let Some(connection_id) = connection_id {
            if let Some(record) = self.connections.get(&connection_id) {
                event.connection = Some(record.connection.clone());
            }
        }
    }

    fn apply_plaintext_event(&mut self, event: &mut TraceEvent) {
        let Some(pid) = event.pid else {
            return;
        };
        let (ssl_object, fd) = match &event.payload {
            EventPayload::Plaintext { ssl_object, fd, .. }
            | EventPayload::HttpCapture { ssl_object, fd, .. } => (ssl_object, fd),
            _ => return,
        };

        let session_ssl_object = if *ssl_object != 0 {
            *ssl_object
        } else {
            self.tls
                .latest_for_process(pid)
                .map(|session| session.ssl_object)
                .unwrap_or_default()
        };
        let session_fd = self
            .tls
            .get(pid, session_ssl_object)
            .and_then(|session| session.fd);
        let session_connection_id = self
            .tls
            .get(pid, session_ssl_object)
            .and_then(|session| session.connection_id.clone());
        let effective_fd = (*fd).or(session_fd);
        let fd_connection_id = effective_fd.and_then(|fd| {
            if fd < 0 {
                return None;
            }
            let socket_id = format!("socket-{}", (u64::from(pid) << 32) | u64::from(fd as u32));
            self.connections
                .get(&socket_id)
                .map(|record| record.connection.id.clone())
        });
        let event_connection_id = event
            .connection
            .as_ref()
            .map(|connection| connection.id.clone());
        let connection_id = fd_connection_id
            .or(session_connection_id)
            .or(event_connection_id);

        match &mut event.payload {
            EventPayload::Plaintext { ssl_object, fd, .. }
            | EventPayload::HttpCapture { ssl_object, fd, .. } => {
                if *ssl_object == 0 {
                    *ssl_object = session_ssl_object;
                }
                if fd.is_none() {
                    *fd = effective_fd;
                }
            }
            _ => {}
        }

        if let Some(connection_id) = connection_id {
            if let Some(record) = self.connections.get(&connection_id) {
                event.connection = Some(record.connection.clone());
            }
        }
    }

    fn derive_http_events(&mut self, event: &TraceEvent) -> Vec<TraceEvent> {
        let Some(pid) = event.pid else {
            return Vec::new();
        };
        let (ssl_object, fd, direction, data, truncated) = match &event.payload {
            EventPayload::Plaintext {
                ssl_object,
                fd,
                direction,
                data,
                truncated,
                ..
            }
            | EventPayload::HttpCapture {
                ssl_object,
                fd,
                direction,
                data,
                truncated,
                ..
            } => (ssl_object, fd, direction, data, truncated),
            _ => return Vec::new(),
        };
        let stream_key = event
            .connection
            .as_ref()
            .map(|connection| connection.id.clone())
            .or_else(|| (*ssl_object != 0).then(|| format!("process:{pid}:ssl:{ssl_object}")))
            .or_else(|| fd.map(|fd| format!("process:{pid}:fd:{fd}")));
        let Some(stream_key) = stream_key else {
            return Vec::new();
        };
        let messages = self
            .http
            .observe(&stream_key, *direction, data.as_bytes(), *truncated);
        messages
            .into_iter()
            .enumerate()
            .map(|(sequence, message)| {
                let data = match message {
                    HttpMessage::Request(request) => HttpEventData {
                        direction: HttpMessageDirection::Request,
                        version: request.version.as_str().to_owned(),
                        method: Some(request.method),
                        target: Some(request.path),
                        host: request.host,
                        status: None,
                        reason: None,
                        headers: request
                            .headers
                            .into_iter()
                            .map(|(name, value)| HttpHeader { name, value })
                            .collect(),
                        content_length: request.content_length,
                    },
                    HttpMessage::Response(response) => HttpEventData {
                        direction: HttpMessageDirection::Response,
                        version: response.version.as_str().to_owned(),
                        method: None,
                        target: None,
                        host: None,
                        status: Some(response.status),
                        reason: (!response.reason.is_empty()).then_some(response.reason),
                        headers: response
                            .headers
                            .into_iter()
                            .map(|(name, value)| HttpHeader { name, value })
                            .collect(),
                        content_length: response.content_length,
                    },
                };
                let mut http_event = TraceEvent::http_with_sequence(
                    EventSource::Core,
                    pid,
                    data,
                    event.timestamp_ns,
                    sequence,
                );
                http_event.id = format!("{}-http-{sequence}", event.id);
                http_event.process = event.process.clone();
                http_event.connection = event.connection.clone();
                http_event
            })
            .collect()
    }

    fn apply_connection_event(&mut self, event: &mut TraceEvent) {
        if let Some(mut connection) = event.connection.clone() {
            if connection.domain.is_none() {
                connection.domain =
                    self.resolve_domain(event.pid, &connection.remote.address, event.timestamp_ns);
            }
            let process = event.process.clone().or_else(|| {
                event
                    .pid
                    .and_then(|pid| self.processes.get(pid))
                    .map(|record| record.identity.clone())
            });
            let canonical_id = self.connections.observe(
                event.pid,
                process,
                connection.clone(),
                event.timestamp_ns,
            );
            if let Some(pid) = event.pid {
                if let Some(fd) = fd_from_socket_id(&canonical_id, pid) {
                    self.tls.link_connection_for_fd(pid, fd, &canonical_id);
                }
            }
            connection.id = canonical_id;
            event.connection = Some(connection.clone());
            event.payload = EventPayload::Connection { connection };
        }
    }

    fn append_dns_context(
        &self,
        record: &network::ConnectionRecord,
        persisted_events: Option<&Vec<TraceEvent>>,
        event_ids: &mut HashSet<String>,
        events: &mut Vec<TimelineEntry>,
    ) {
        let Some(persisted_events) = persisted_events else {
            return;
        };
        let Some(domain) = record.connection.domain.as_deref() else {
            return;
        };
        const DNS_CONTEXT_WINDOW_NS: u64 = 30_000_000_000;
        let start = record.first_seen_ns.saturating_sub(DNS_CONTEXT_WINDOW_NS);
        for event in persisted_events {
            if event_ids.contains(&event.id)
                || event.pid != record.pid
                || event.timestamp_ns < start
                || event.timestamp_ns > record.last_seen_ns
            {
                continue;
            }
            let matches_domain = match &event.payload {
                EventPayload::Dns {
                    domain: event_domain,
                    addresses,
                    ..
                } => {
                    event_domain == domain
                        && (event.kind == EventKind::DnsQuery
                            || addresses
                                .iter()
                                .any(|address| address == &record.connection.remote.address))
                }
                _ => false,
            };
            if !matches_domain {
                continue;
            }
            let mut entry = TimelineEntry::from_event(event.clone());
            entry.connection_id = Some(record.connection.id.clone());
            event_ids.insert(event.id.clone());
            events.push(entry);
        }
    }

    fn rebuild_read_models(&mut self) {
        for mut event in self.store.snapshot() {
            self.apply_event(&mut event);
            self.evaluate_event(&event);
            let _ = self.derive_http_events(&event);
        }
    }

    fn expire_observations(&mut self) {
        let expired = self.observations.sweep_expired();
        for (target, level) in expired {
            self.probe_runtime.detach_target(&target.to_string());
            self.record_observation_event(target, level);
        }
    }

    fn record_observation_event(
        &mut self,
        target: observation::ObservationTarget,
        level: observation::ObservationLevel,
    ) {
        let event =
            TraceEvent::observation_event(target.to_string(), level as u8, monotonic_now_ns());
        let event = self.correlator.correlate(event);
        self.store.insert(event.clone());
        self.event_bus.publish(event);
    }

    pub fn upgrade_observation(
        &mut self,
        target: observation::ObservationTarget,
        level: observation::ObservationLevel,
        duration_secs: Option<u64>,
    ) -> observation::ObservationLevel {
        let level = self.observations.upgrade(
            target.clone(),
            level,
            duration_secs.or(Some(self.config.deep_inspection_timeout_secs)),
        );
        self.sync_observation_target(target, level);
        level
    }

    pub fn set_observation(
        &mut self,
        target: observation::ObservationTarget,
        level: observation::ObservationLevel,
        duration_secs: Option<u64>,
    ) -> observation::ObservationLevel {
        self.observations.apply(observation::ObservationRequest {
            target: target.clone(),
            level,
            duration_secs: duration_secs.or(Some(self.config.deep_inspection_timeout_secs)),
        });
        self.sync_observation_target(target, level);
        level
    }

    fn sync_observation_target(
        &mut self,
        target: observation::ObservationTarget,
        level: observation::ObservationLevel,
    ) {
        let target_name = target.to_string();
        let process_pids = self.process_pids_for_target(&target);
        self.probe_runtime.detach_target(&target_name);
        if level > self.observations.default_level() {
            self.probe_runtime
                .set_level(&target_name, level, &process_pids);
        }
        self.record_observation_event(target, level);
    }

    pub fn downgrade_observation(
        &mut self,
        target: &observation::ObservationTarget,
    ) -> observation::ObservationLevel {
        let level = self.observations.downgrade_to_default(target);
        self.probe_runtime.detach_target(&target.to_string());
        self.record_observation_event(target.clone(), level);
        level
    }

    pub fn observation_statuses(&self) -> Vec<observation::ObservationStatus> {
        self.observations.statuses()
    }

    fn process_pids_for_target(&self, target: &observation::ObservationTarget) -> Vec<u32> {
        let mut pids = match target {
            observation::ObservationTarget::Process(pid) => vec![*pid],
            observation::ObservationTarget::Connection(id) => self
                .connections
                .get(id)
                .and_then(|record| record.pid)
                .into_iter()
                .collect(),
            observation::ObservationTarget::Domain(domain) => self
                .connections
                .all()
                .filter(|record| record.connection.domain.as_deref() == Some(domain.as_str()))
                .filter_map(|record| record.pid)
                .collect(),
        };
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    fn resolve_domain(&self, pid: Option<u32>, address: &str, timestamp_ns: u64) -> Option<String> {
        pid.and_then(|pid| {
            self.dns
                .domain_for_process_address(pid, address, timestamp_ns)
        })
        .or_else(|| self.dns.domain_for_unscoped_address(address, timestamp_ns))
        .or_else(|| self.dns.domain_for_address(address, timestamp_ns))
    }

    /// Stable smoke-test event for wiring the UI and local API.
    pub fn example_event() -> tracelens_events::TraceEvent {
        tracelens_events::TraceEvent::process_exec(
            12345,
            "curl",
            "curl https://example.com",
            1_723_000_000_000_000_000,
        )
    }
}

fn fd_from_socket_id(connection_id: &str, pid: u32) -> Option<i32> {
    let value = connection_id.strip_prefix("socket-")?.parse::<u64>().ok()?;
    (value >> 32 == u64::from(pid)).then_some((value as u32) as i32)
}

fn is_security_relevant_file_event(event: &TraceEvent) -> bool {
    let EventPayload::File { path, .. } = &event.payload else {
        return false;
    };
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

fn monotonic_now_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut timespec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // Kernel probe timestamps use CLOCK_MONOTONIC, so observation command
        // events must use the same clock to remain correctly ordered.
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timespec) } == 0 {
            let seconds = u64::try_from(timespec.tv_sec).unwrap_or_default();
            let nanos = u64::try_from(timespec.tv_nsec).unwrap_or_default();
            return seconds.saturating_mul(1_000_000_000).saturating_add(nanos);
        }
    }

    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}
