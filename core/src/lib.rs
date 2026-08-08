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
pub mod http;
pub mod network;
pub mod observation;
pub mod process;
pub mod runtime;
pub mod storage;
pub mod tls;

use config::CoreConfig;
use dns::DnsTracker;
use events::{EventBus, EventCorrelator};
use network::ConnectionTracker;
use observation::ObservationManager;
use process::ProcessTracker;
use runtime::RuntimeStatus;
use storage::EventStore;
use tracelens_events::{EventKind, EventPayload, TraceEvent};

/// Top-level composition root for the core service.
pub struct Core {
    config: CoreConfig,
    runtime: RuntimeStatus,
    event_bus: EventBus,
    correlator: EventCorrelator,
    store: EventStore,
    processes: ProcessTracker,
    connections: ConnectionTracker,
    dns: DnsTracker,
    observations: ObservationManager,
}

impl Core {
    pub fn new(config: CoreConfig) -> Self {
        Self {
            config,
            runtime: RuntimeStatus::detect(),
            event_bus: EventBus::new(),
            correlator: EventCorrelator::new(),
            store: EventStore::new(),
            processes: ProcessTracker::default(),
            connections: ConnectionTracker::default(),
            dns: DnsTracker::default(),
            observations: ObservationManager::default(),
        }
    }

    pub fn config(&self) -> &CoreConfig {
        &self.config
    }

    pub fn runtime_status(&self) -> &RuntimeStatus {
        &self.runtime
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

    pub fn observations(&self) -> &ObservationManager {
        &self.observations
    }

    pub fn ingest_event(&mut self, mut event: TraceEvent) {
        match event.kind {
            EventKind::ProcessExec => {
                if let Some(process) = event.process.clone() {
                    self.processes.observe(process, event.timestamp_ns);
                }
            }
            EventKind::ProcessExit => {
                if let Some(pid) = event.pid {
                    self.processes.remove(pid);
                }
            }
            EventKind::TcpConnect | EventKind::TcpClose => {
                if let Some(mut connection) = event.connection.clone() {
                    if connection.domain.is_none() {
                        connection.domain = self
                            .dns
                            .domain_for_address(&connection.remote.address, event.timestamp_ns);
                    }
                    let process = event.process.clone().or_else(|| {
                        event
                            .pid
                            .and_then(|pid| self.processes.get(pid))
                            .map(|record| record.identity.clone())
                    });
                    event.connection = Some(connection.clone());
                    event.payload = EventPayload::Connection {
                        connection: connection.clone(),
                    };
                    self.connections
                        .observe(event.pid, process, connection, event.timestamp_ns);
                }
            }
            EventKind::TcpStateChanged | EventKind::TcpBytes => {
                if let Some(mut connection) = event.connection.clone() {
                    if connection.domain.is_none() {
                        connection.domain = self
                            .dns
                            .domain_for_address(&connection.remote.address, event.timestamp_ns);
                    }
                    let process = event.process.clone().or_else(|| {
                        event
                            .pid
                            .and_then(|pid| self.processes.get(pid))
                            .map(|record| record.identity.clone())
                    });
                    event.connection = Some(connection.clone());
                    event.payload = EventPayload::Connection {
                        connection: connection.clone(),
                    };
                    self.connections
                        .observe(event.pid, process, connection, event.timestamp_ns);
                }
            }
            EventKind::DnsResponse => {
                if let EventPayload::Dns {
                    domain,
                    addresses,
                    ttl_secs,
                } = &event.payload
                {
                    if !addresses.is_empty() {
                        self.dns.observe_response(
                            domain.clone(),
                            addresses.clone(),
                            *ttl_secs,
                            event.timestamp_ns,
                        );
                        if let Some(pid) = event.pid {
                            self.connections.set_domain(pid, addresses, domain);
                        }
                    }
                }
            }
            _ => {}
        }

        let event = self.correlator.correlate(event);
        self.store.insert(event.clone());
        self.event_bus.publish(event);
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
