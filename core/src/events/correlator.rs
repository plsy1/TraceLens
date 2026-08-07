use tracelens_events::TraceEvent;

#[derive(Debug, Default)]
pub struct EventCorrelator;

impl EventCorrelator {
    pub fn new() -> Self {
        Self
    }

    pub fn correlate(&self, event: TraceEvent) -> TraceEvent {
        // Process, DNS, socket, and connection state will be joined here.
        event
    }
}
