use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::{ObservationLevel, ObservationRequest, ObservationTarget};

#[derive(Debug, Clone)]
struct ObservationSession {
    level: ObservationLevel,
    expires_at: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationStatus {
    pub target: ObservationTarget,
    pub level: ObservationLevel,
    pub expires_in_secs: Option<u64>,
}

#[derive(Debug)]
pub struct ObservationManager {
    default_level: ObservationLevel,
    sessions: HashMap<ObservationTarget, ObservationSession>,
}

impl Default for ObservationManager {
    fn default() -> Self {
        Self::new(ObservationLevel::L1)
    }
}

impl ObservationManager {
    pub fn new(default_level: ObservationLevel) -> Self {
        Self {
            default_level,
            sessions: HashMap::new(),
        }
    }

    pub fn default_level(&self) -> ObservationLevel {
        self.default_level
    }

    /// Change the baseline applied to every target without removing higher
    /// explicit overrides. Overrides that are now below the baseline no
    /// longer add anything and can be discarded.
    pub fn set_default_level(&mut self, level: ObservationLevel) {
        self.default_level = level;
        self.sessions.retain(|_, session| session.level > level);
    }

    pub fn current_level(&self, target: &ObservationTarget) -> ObservationLevel {
        self.current_level_at(target, Instant::now())
    }

    pub fn current_level_at(&self, target: &ObservationTarget, now: Instant) -> ObservationLevel {
        self.sessions
            .get(target)
            .filter(|session| !is_expired(session.expires_at, now))
            .map(|session| session.level.max(self.default_level))
            .unwrap_or(self.default_level)
    }

    /// Apply an explicit level. `upgrade` is usually preferable for callers
    /// that do not want a request to accidentally lower an active session.
    pub fn apply(&mut self, request: ObservationRequest) {
        self.apply_at(request, Instant::now());
    }

    fn apply_at(&mut self, request: ObservationRequest, now: Instant) {
        if request.level <= self.default_level {
            self.sessions.remove(&request.target);
            return;
        }
        self.sessions.insert(
            request.target,
            ObservationSession {
                level: request.level,
                expires_at: request
                    .duration_secs
                    .map(|seconds| now + Duration::from_secs(seconds)),
            },
        );
    }

    pub fn upgrade(
        &mut self,
        target: ObservationTarget,
        requested_level: ObservationLevel,
        duration_secs: Option<u64>,
    ) -> ObservationLevel {
        self.upgrade_at(target, requested_level, duration_secs, Instant::now())
    }

    fn upgrade_at(
        &mut self,
        target: ObservationTarget,
        requested_level: ObservationLevel,
        duration_secs: Option<u64>,
        now: Instant,
    ) -> ObservationLevel {
        let current = self.current_level_at(&target, now);
        let level = requested_level.max(current);
        self.apply_at(
            ObservationRequest {
                target,
                level,
                duration_secs,
            },
            now,
        );
        level
    }

    /// Preserve the original Phase 6 API: remove the target override and
    /// return to the configured baseline level.
    pub fn downgrade(&mut self, target: &ObservationTarget) {
        self.sessions.remove(target);
    }

    pub fn downgrade_to_default(&mut self, target: &ObservationTarget) -> ObservationLevel {
        self.downgrade(target);
        self.default_level
    }

    pub fn sweep_expired(&mut self) -> Vec<(ObservationTarget, ObservationLevel)> {
        self.sweep_expired_at(Instant::now())
    }

    fn sweep_expired_at(&mut self, now: Instant) -> Vec<(ObservationTarget, ObservationLevel)> {
        let expired = self
            .sessions
            .iter()
            .filter(|(_, session)| is_expired(session.expires_at, now))
            .map(|(target, _)| target.clone())
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|target| {
                self.sessions
                    .remove(&target)
                    .map(|_| (target, self.default_level))
            })
            .collect()
    }

    pub fn active_targets(&self) -> impl Iterator<Item = (&ObservationTarget, &ObservationLevel)> {
        // Kept as a compatibility read API. Callers that need timeout-safe
        // results should use `statuses`, which excludes expired sessions.
        self.sessions
            .iter()
            .map(|(target, session)| (target, &session.level))
    }

    pub fn statuses(&self) -> Vec<ObservationStatus> {
        let now = Instant::now();
        self.sessions
            .iter()
            .filter_map(|(target, session)| {
                let expires_in_secs = session
                    .expires_at
                    .and_then(|expires_at| expires_at.checked_duration_since(now))
                    .map(|duration| duration.as_secs());
                if session
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= now)
                {
                    None
                } else {
                    Some(ObservationStatus {
                        target: target.clone(),
                        level: session.level,
                        expires_in_secs,
                    })
                }
            })
            .collect()
    }
}

fn is_expired(expires_at: Option<Instant>, now: Instant) -> bool {
    expires_at.is_some_and(|expires_at| expires_at <= now)
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

    #[test]
    fn expired_session_returns_to_default_and_is_swept() {
        let target = ObservationTarget::Connection("socket-1".to_owned());
        let mut manager = ObservationManager::default();
        let start = Instant::now();
        manager.upgrade_at(target.clone(), ObservationLevel::L3, Some(5), start);

        assert_eq!(
            manager.current_level_at(&target, start + Duration::from_secs(4)),
            ObservationLevel::L3
        );
        assert_eq!(
            manager.current_level_at(&target, start + Duration::from_secs(5)),
            ObservationLevel::L1
        );
        assert_eq!(
            manager.sweep_expired_at(start + Duration::from_secs(5)),
            vec![(target, ObservationLevel::L1)]
        );
        assert!(manager.active_targets().next().is_none());
    }

    #[test]
    fn upgrades_do_not_lower_an_active_session() {
        let target = ObservationTarget::Process(42);
        let mut manager = ObservationManager::default();
        manager.upgrade(target.clone(), ObservationLevel::L5, Some(30));
        assert_eq!(
            manager.upgrade(target.clone(), ObservationLevel::L3, Some(30)),
            ObservationLevel::L5
        );
        assert_eq!(manager.current_level(&target), ObservationLevel::L5);
    }

    #[test]
    fn global_default_is_used_for_all_targets_and_keeps_higher_overrides() {
        let process = ObservationTarget::Process(42);
        let mut manager = ObservationManager::new(ObservationLevel::L1);
        manager.set_default_level(ObservationLevel::L4);
        assert_eq!(manager.current_level(&process), ObservationLevel::L4);

        manager.upgrade(process.clone(), ObservationLevel::L5, Some(30));
        manager.set_default_level(ObservationLevel::L3);
        assert_eq!(manager.current_level(&process), ObservationLevel::L5);

        manager.set_default_level(ObservationLevel::L5);
        assert_eq!(manager.current_level(&process), ObservationLevel::L5);
        assert!(manager.statuses().is_empty());
    }
}
