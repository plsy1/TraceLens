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
use runtime::RuntimeStatus;
use storage::EventStore;

/// Top-level composition root for the core service.
pub struct Core {
    config: CoreConfig,
    runtime: RuntimeStatus,
    event_bus: EventBus,
    correlator: EventCorrelator,
    store: EventStore,
}

impl Core {
    pub fn new(config: CoreConfig) -> Self {
        Self {
            config,
            runtime: RuntimeStatus::detect(),
            event_bus: EventBus::new(),
            correlator: EventCorrelator::new(),
            store: EventStore::new(),
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
