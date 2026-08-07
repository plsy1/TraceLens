use std::collections::HashMap;

use super::{ObservationLevel, ObservationRequest, ObservationTarget};

#[derive(Debug, Default)]
pub struct ObservationManager {
    levels: HashMap<ObservationTarget, ObservationLevel>,
}

impl ObservationManager {
    pub fn current_level(&self, target: &ObservationTarget) -> ObservationLevel {
        self.levels.get(target).copied().unwrap_or_default()
    }

    pub fn apply(&mut self, request: ObservationRequest) {
        self.levels.insert(request.target, request.level);
    }

    pub fn downgrade(&mut self, target: &ObservationTarget) {
        self.levels.remove(target);
    }

    pub fn active_targets(&self) -> impl Iterator<Item = (&ObservationTarget, &ObservationLevel)> {
        self.levels.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_can_be_escalated_and_downgraded() {
        let target = ObservationTarget::Process(1234);
        let mut manager = ObservationManager::default();

        assert_eq!(manager.current_level(&target), ObservationLevel::L1);

        manager.apply(ObservationRequest {
            target: target.clone(),
            level: ObservationLevel::L5,
            duration_secs: Some(300),
        });
        assert_eq!(manager.current_level(&target), ObservationLevel::L5);

        manager.downgrade(&target);
        assert_eq!(manager.current_level(&target), ObservationLevel::L1);
    }
}
