#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObservationTarget {
    Process(u32),
    Connection(String),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRequest {
    pub target: ObservationTarget,
    pub level: super::ObservationLevel,
    pub duration_secs: Option<u64>,
}
