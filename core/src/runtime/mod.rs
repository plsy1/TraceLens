pub mod bpftime;
pub mod kernel;
pub mod selector;
pub mod userspace;

use std::fmt;

use crate::observation::ObservationLevel;

pub use userspace::{ProbeAttachment, ProbeRuntime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserspaceRuntime {
    Bpftime,
    KernelUprobe,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum ProbeKind {
    Tls,
    Http,
    Plaintext,
}

impl fmt::Display for ProbeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Plaintext => "plaintext",
        };
        formatter.write_str(value)
    }
}

pub fn probes_for_level(level: ObservationLevel) -> Vec<ProbeKind> {
    let mut probes = Vec::new();
    if level >= ObservationLevel::L3 {
        probes.push(ProbeKind::Tls);
    }
    if level == ObservationLevel::L4 {
        probes.push(ProbeKind::Http);
    }
    if level >= ObservationLevel::L5 {
        probes.push(ProbeKind::Plaintext);
    }
    probes
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
        Self::detect_with_preference("bpftime")
    }

    pub fn detect_with_preference(preferred: &str) -> Self {
        let kernel_observation = cfg!(target_os = "linux");
        let bpftime = bpftime::BpftimeRuntime::detect();
        let (userspace_runtime, detail) = if preferred == "kernel_uprobe" {
            if kernel_observation {
                (
                    UserspaceRuntime::KernelUprobe,
                    "kernel uprobe selected by configuration".to_owned(),
                )
            } else {
                (
                    UserspaceRuntime::Unavailable,
                    "kernel uprobe is only available on Linux".to_owned(),
                )
            }
        } else if bpftime.is_available() {
            (
                UserspaceRuntime::Bpftime,
                format!(
                    "bpftime detected at {}; userspace probe control is available",
                    bpftime.executable().display()
                ),
            )
        } else if kernel_observation {
            (
                UserspaceRuntime::KernelUprobe,
                format!(
                    "bpftime unavailable; using kernel uprobe fallback ({})",
                    bpftime.detail()
                ),
            )
        } else {
            (
                UserspaceRuntime::Unavailable,
                "the MVP currently targets Linux".to_owned(),
            )
        };

        Self {
            kernel_observation,
            userspace_runtime,
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{probes_for_level, ProbeKind, UserspaceRuntime};
    use crate::observation::ObservationLevel;

    #[test]
    fn probe_dependencies_grow_with_observation_level() {
        assert!(probes_for_level(ObservationLevel::L1).is_empty());
        assert_eq!(probes_for_level(ObservationLevel::L3), vec![ProbeKind::Tls]);
        assert_eq!(
            probes_for_level(ObservationLevel::L5),
            vec![ProbeKind::Tls, ProbeKind::Plaintext]
        );
    }

    #[test]
    fn runtime_names_are_stable_for_health_api() {
        assert_eq!(UserspaceRuntime::KernelUprobe.to_string(), "kernel uprobe");
    }
}
