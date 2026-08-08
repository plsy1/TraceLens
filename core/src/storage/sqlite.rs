use std::sync::{Arc, Mutex};

use tracelens_events::TraceEvent;

#[derive(Debug, Clone, Default)]
pub struct EventStore {
    events: Arc<Mutex<Vec<TraceEvent>>>,
}

impl EventStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, event: TraceEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    pub fn len(&self) -> usize {
        self.events.lock().map(|events| events.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn snapshot(&self) -> Vec<TraceEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}
