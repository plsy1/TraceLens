//! bpftime runtime boundary.

#[derive(Debug, Default)]
pub struct BpftimeRuntime {
    attached_targets: Vec<String>,
}

impl BpftimeRuntime {
    pub fn attached_targets(&self) -> &[String] {
        &self.attached_targets
    }

    pub fn attach(&mut self, target: impl Into<String>) {
        self.attached_targets.push(target.into());
    }

    pub fn detach(&mut self, target: &str) {
        self.attached_targets.retain(|item| item != target);
    }
}
