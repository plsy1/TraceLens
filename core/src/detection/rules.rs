use serde::{Deserialize, Serialize};
use tracelens_events::EventId;

use super::RiskScore;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub const fn risk_score(self) -> RiskScore {
        RiskScore(match self {
            Self::Low => 20.0,
            Self::Medium => 40.0,
            Self::High => 70.0,
            Self::Critical => 95.0,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub id: String,
    pub event_id: Option<EventId>,
    pub timestamp_ns: u64,
    pub severity: AlertSeverity,
    pub rule: String,
    pub summary: String,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub connection_id: Option<String>,
    pub domain: Option<String>,
    pub evidence: Vec<String>,
    pub risk_score: RiskScore,
}

impl Alert {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: Option<EventId>,
        timestamp_ns: u64,
        severity: AlertSeverity,
        rule: impl Into<String>,
        summary: impl Into<String>,
        process_id: Option<u32>,
        process_name: Option<String>,
        connection_id: Option<String>,
        domain: Option<String>,
        evidence: Vec<String>,
    ) -> Self {
        let rule = rule.into();
        Self {
            id: format!(
                "alert-{}-{}",
                rule.replace(' ', "_"),
                event_id.as_deref().unwrap_or("runtime")
            ),
            event_id,
            timestamp_ns,
            severity,
            rule,
            summary: summary.into(),
            process_id,
            process_name,
            connection_id,
            domain,
            evidence,
            risk_score: severity.risk_score(),
        }
    }
}
