use super::{RuntimeStatus, UserspaceRuntime};

#[derive(Debug, Default)]
pub struct RuntimeSelector;

impl RuntimeSelector {
    pub fn select(status: &RuntimeStatus) -> UserspaceRuntime {
        status.userspace_runtime
    }
}
