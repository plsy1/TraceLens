use serde::{Deserialize, Serialize};

use crate::CaptureScope;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureModule {
    Process,
    Connections,
    Traffic,
    Dns,
    Files,
    #[serde(rename = "tls")]
    Tls,
    Http,
    Plaintext,
}

impl CaptureModule {
    pub const ALL: [Self; 8] = [
        Self::Process,
        Self::Connections,
        Self::Traffic,
        Self::Dns,
        Self::Files,
        Self::Tls,
        Self::Http,
        Self::Plaintext,
    ];

    const fn bit(self) -> u16 {
        1 << self as u16
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureFeatures(u16);

impl CaptureFeatures {
    pub const NONE: Self = Self(0);

    pub fn from_modules(modules: impl IntoIterator<Item = CaptureModule>) -> Self {
        let mut features = Self::NONE;
        for module in modules {
            features.insert(module);
        }
        features
    }

    pub fn contains(self, module: CaptureModule) -> bool {
        self.0 & module.bit() != 0
    }

    pub fn insert(&mut self, module: CaptureModule) {
        self.0 |= module.bit();
    }

    pub fn modules(self) -> Vec<CaptureModule> {
        CaptureModule::ALL
            .into_iter()
            .filter(|module| self.contains(*module))
            .collect()
    }

    pub fn dependency_closure(mut self) -> Self {
        if self.0 != 0 {
            self.insert(CaptureModule::Process);
        }
        if self.contains(CaptureModule::Traffic)
            || self.contains(CaptureModule::Dns)
            || self.contains(CaptureModule::Tls)
        {
            self.insert(CaptureModule::Connections);
        }
        if self.contains(CaptureModule::Http) || self.contains(CaptureModule::Plaintext) {
            self.insert(CaptureModule::Tls);
            self.insert(CaptureModule::Connections);
        }
        self
    }

    pub fn legacy_level(level: u8) -> Option<Self> {
        let profile = CaptureProfile::Network.features();
        match level {
            1 | 2 => Some(profile),
            3 => Some(profile.with(CaptureModule::Tls)),
            4 => Some(profile.with(CaptureModule::Tls).with(CaptureModule::Http)),
            5 => Some(
                profile
                    .with(CaptureModule::Tls)
                    .with(CaptureModule::Http)
                    .with(CaptureModule::Plaintext),
            ),
            _ => None,
        }
    }

    const fn with(mut self, module: CaptureModule) -> Self {
        self.0 |= module.bit();
        self
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProfile {
    Process,
    Connections,
    #[default]
    Network,
    Web,
    Security,
    Custom,
}

impl CaptureProfile {
    pub fn features(self) -> CaptureFeatures {
        let modules: &[CaptureModule] = match self {
            Self::Process => &[CaptureModule::Process],
            Self::Connections => &[CaptureModule::Process, CaptureModule::Connections],
            Self::Network => &[
                CaptureModule::Process,
                CaptureModule::Connections,
                CaptureModule::Traffic,
                CaptureModule::Dns,
            ],
            Self::Web => &[
                CaptureModule::Process,
                CaptureModule::Connections,
                CaptureModule::Traffic,
                CaptureModule::Dns,
                CaptureModule::Tls,
                CaptureModule::Http,
            ],
            Self::Security => &[
                CaptureModule::Process,
                CaptureModule::Connections,
                CaptureModule::Traffic,
                CaptureModule::Dns,
                CaptureModule::Files,
                CaptureModule::Tls,
            ],
            Self::Custom => &[],
        };
        CaptureFeatures::from_modules(modules.iter().copied())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbePlan {
    pub kernel_objects: Vec<String>,
    pub userspace_probes: Vec<String>,
    pub expected_kernel_links: usize,
}

impl ProbePlan {
    fn resolve(features: CaptureFeatures) -> Self {
        let mut kernel_objects = Vec::new();
        let mut expected_kernel_links = 0;
        if features.contains(CaptureModule::Process) {
            kernel_objects.push("process.o".to_owned());
            expected_kernel_links += 2;
        }
        if features.contains(CaptureModule::Connections) {
            kernel_objects.push("network.o".to_owned());
            expected_kernel_links += 4;
        }
        if features.contains(CaptureModule::Traffic) || features.contains(CaptureModule::Dns) {
            expected_kernel_links += 12;
        }
        if features.contains(CaptureModule::Files) {
            kernel_objects.push("file.o".to_owned());
            expected_kernel_links += 1;
        }

        let mut userspace_probes = Vec::new();
        if features.contains(CaptureModule::Tls) {
            userspace_probes.push("tls_metadata".to_owned());
        }
        if features.contains(CaptureModule::Http) || features.contains(CaptureModule::Plaintext) {
            userspace_probes.push("tls_payload".to_owned());
        }

        Self {
            kernel_objects,
            userspace_probes,
            expected_kernel_links,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlan {
    pub target: CaptureScope,
    pub profile: CaptureProfile,
    pub requested: CaptureFeatures,
    pub effective: CaptureFeatures,
    pub probes: ProbePlan,
    pub warnings: Vec<String>,
}

impl CapturePlan {
    pub fn resolve(
        target: CaptureScope,
        profile: CaptureProfile,
        requested: Option<CaptureFeatures>,
    ) -> Result<Self, String> {
        if profile == CaptureProfile::Custom && requested.is_none() {
            return Err("custom profile requires at least one module".to_owned());
        }
        let requested = requested.unwrap_or_else(|| profile.features());
        if requested == CaptureFeatures::NONE {
            return Err("capture requires at least one module".to_owned());
        }
        let profile = if profile != CaptureProfile::Custom && requested != profile.features() {
            CaptureProfile::Custom
        } else {
            profile
        };
        let effective = requested.dependency_closure();
        let mut warnings = Vec::new();
        if effective.contains(CaptureModule::Plaintext) {
            warnings.push(
                "plaintext capture is enabled; sensitive data stays memory-only by default"
                    .to_owned(),
            );
        }
        Ok(Self {
            target,
            profile,
            requested,
            effective,
            probes: ProbePlan::resolve(effective),
            warnings,
        })
    }

    pub fn network(target: CaptureScope) -> Self {
        Self::resolve(target, CaptureProfile::Network, None)
            .expect("the built-in network profile is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::{CaptureFeatures, CaptureModule, CapturePlan, CaptureProfile};
    use crate::CaptureScope;

    #[test]
    fn profiles_expand_to_stable_feature_sets() {
        let network = CapturePlan::resolve(CaptureScope::Global, CaptureProfile::Network, None)
            .expect("network profile");
        assert!(network.effective.contains(CaptureModule::Dns));
        assert!(!network.effective.contains(CaptureModule::Files));
        assert!(!network.effective.contains(CaptureModule::Tls));
        assert_eq!(network.probes.expected_kernel_links, 18);
        assert_eq!(network.probes.kernel_objects, ["process.o", "network.o"]);

        let security = CapturePlan::resolve(CaptureScope::Global, CaptureProfile::Security, None)
            .expect("security profile");
        assert!(security.effective.contains(CaptureModule::Files));
        assert!(!security.effective.contains(CaptureModule::Http));
        assert_eq!(security.probes.expected_kernel_links, 19);
    }

    #[test]
    fn dependencies_are_closed_without_enabling_files() {
        let requested = CaptureFeatures::from_modules([CaptureModule::Http]);
        let plan = CapturePlan::resolve(
            CaptureScope::Process(42),
            CaptureProfile::Custom,
            Some(requested),
        )
        .expect("custom HTTP plan");
        assert!(plan.effective.contains(CaptureModule::Process));
        assert!(plan.effective.contains(CaptureModule::Connections));
        assert!(plan.effective.contains(CaptureModule::Tls));
        assert!(plan.effective.contains(CaptureModule::Http));
        assert!(!plan.effective.contains(CaptureModule::Plaintext));
        assert!(!plan.effective.contains(CaptureModule::Files));
    }

    #[test]
    fn legacy_levels_translate_only_at_the_compatibility_boundary() {
        let l4 = CaptureFeatures::legacy_level(4).expect("legacy L4");
        assert!(l4.contains(CaptureModule::Http));
        assert!(!l4.contains(CaptureModule::Plaintext));
        let l5 = CaptureFeatures::legacy_level(5).expect("legacy L5");
        assert!(l5.contains(CaptureModule::Http));
        assert!(l5.contains(CaptureModule::Plaintext));
        assert!(CaptureFeatures::legacy_level(6).is_none());
    }
}
