use tracelens_events::TraceEvent;

use super::Alert;

#[derive(Debug, Default)]
pub struct DetectionEngine;

impl DetectionEngine {
    pub fn evaluate(&self, _event: &TraceEvent) -> Vec<Alert> {
        // Rule-based detection is introduced after the event loop is connected
        // to real kernel events.
        Vec::new()
    }
}
