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
use events::{EventBus, EventCorrelator};
use network::ConnectionTracker;
use observation::ObservationManager;
use process::ProcessTracker;
use runtime::RuntimeStatus;
use storage::EventStore;
use tracelens_events::{EventKind, TraceEvent};

/// Top-level composition root for the core service.
pub struct Core {
    config: CoreConfig,
    runtime: RuntimeStatus,
    event_bus: EventBus,
    correlator: EventCorrelator,
    store: EventStore,
    processes: ProcessTracker,
    connections: ConnectionTracker,
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

    pub fn observations(&self) -> &ObservationManager {
        &self.observations
    }

    pub fn ingest_event(&mut self, event: TraceEvent) {
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
                if let Some(connection) = event.connection.clone() {
                    self.connections
                        .observe(event.pid, connection, event.timestamp_ns);
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
