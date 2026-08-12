pub mod bpftime;
pub mod ingress;
pub mod kernel;
pub mod provider;
pub mod selector;
pub mod userspace;

use std::fmt;

use crate::capture::{CaptureFeatures, CaptureModule};
use crate::observation::ObservationLevel;

pub use ingress::{event_channel, EventQueueStats, EventSender};
pub use userspace::{ProbeAttachment, ProbeRuntime, UserspaceProbeDiagnostics};

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

pub fn probes_for_features(features: CaptureFeatures) -> Vec<ProbeKind> {
    let mut probes = Vec::new();
    if features.contains(CaptureModule::Tls) {
        probes.push(ProbeKind::Tls);
    }
    if features.contains(CaptureModule::Http) || features.contains(CaptureModule::Plaintext) {
        // HTTP reconstruction and the raw plaintext view share the bounded
        // SSL_read/SSL_write transport. Retention is decided independently
        // by CaptureFeatures in Core.
        probes.push(ProbeKind::Plaintext);
    }
    probes
}

#[deprecated(note = "translate legacy levels at the API boundary and use CaptureFeatures")]
pub fn probes_for_level(level: ObservationLevel) -> Vec<ProbeKind> {
    let features = CaptureFeatures::legacy_level(level as u8)
        .expect("ObservationLevel always maps to legacy CaptureFeatures");
    probes_for_features(features)
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
    use super::{probes_for_features, ProbeKind, UserspaceRuntime};
    use crate::capture::{CaptureFeatures, CaptureModule};

    #[test]
    fn probe_dependencies_follow_capture_features() {
        let network = CaptureFeatures::legacy_level(1).expect("network features");
        assert!(probes_for_features(network).is_empty());
        let tls = CaptureFeatures::from_modules([CaptureModule::Tls]);
        assert_eq!(probes_for_features(tls), vec![ProbeKind::Tls]);
        let plaintext =
            CaptureFeatures::from_modules([CaptureModule::Tls, CaptureModule::Plaintext]);
        assert_eq!(
            probes_for_features(plaintext),
            vec![ProbeKind::Tls, ProbeKind::Plaintext]
        );
    }

    #[test]
    fn runtime_names_are_stable_for_health_api() {
        assert_eq!(UserspaceRuntime::KernelUprobe.to_string(), "kernel uprobe");
    }
}
