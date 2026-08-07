#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct RiskScore(pub f32);

impl RiskScore {
    pub fn clamp(self) -> Self {
        Self(self.0.clamp(0.0, 100.0))
    }
}
