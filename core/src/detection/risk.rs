use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, PartialOrd)]
#[serde(transparent)]
pub struct RiskScore(pub f32);

impl RiskScore {
    pub fn clamp(self) -> Self {
        Self(self.0.clamp(0.0, 100.0))
    }
}
