pub mod bpftime;
pub mod kernel;
pub mod selector;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserspaceRuntime {
    Bpftime,
    KernelUprobe,
    Unavailable,
}

impl fmt::Display for UserspaceRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Bpftime => "bpftime",
            Self::KernelUprobe => "kernel uprobe",
            Self::Unavailable => "unavailable",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeStatus {
    pub kernel_observation: bool,
    pub userspace_runtime: UserspaceRuntime,
    pub detail: String,
}

impl RuntimeStatus {
    pub fn detect() -> Self {
        let kernel_observation = cfg!(target_os = "linux");

        Self {
            kernel_observation,
            userspace_runtime: UserspaceRuntime::Unavailable,
            detail: if kernel_observation {
                "runtime adapters are present; discovery is not connected".to_owned()
            } else {
                "the MVP currently targets Linux".to_owned()
            },
        }
    }
}
