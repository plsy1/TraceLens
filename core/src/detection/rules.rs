use tracelens_events::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub event_id: Option<EventId>,
    pub severity: AlertSeverity,
    pub rule: String,
    pub summary: String,
}
