use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use crate::capture::CaptureModule;

use super::bpftime::provider_build_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsProvider {
    OpenSsl,
    BoringSsl,
    LibreSsl,
    GnuTls,
    Nss,
    Rustls,
    GoTls,
    Java,
    Unknown,
}

impl std::fmt::Display for TlsProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OpenSsl => "OpenSSL",
            Self::BoringSsl => "BoringSSL",
            Self::LibreSsl => "LibreSSL",
            Self::GnuTls => "GnuTLS",
            Self::Nss => "NSS",
            Self::Rustls => "rustls",
            Self::GoTls => "Go crypto/tls",
            Self::Java => "Java JSSE",
            Self::Unknown => "Unknown",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsCapability {
    pub provider: TlsProvider,
    pub library: PathBuf,
    pub build_id: String,
    pub version_hint: Option<String>,
    pub auxiliary_libraries: Vec<PathBuf>,
    pub modules: Vec<CaptureModule>,
    pub symbols: Vec<String>,
    pub supported: bool,
    pub reason: Option<String>,
}

pub fn detect_process_tls(pid: u32) -> Vec<TlsCapability> {
    let libraries = mapped_libraries(pid);
    let mut capabilities = libraries
        .iter()
        .filter_map(|library| inspect_tls_library(library, &libraries))
        .collect::<Vec<_>>();
    if let Some(capability) = inspect_process_runtime(pid) {
        capabilities.push(capability);
    }
    capabilities
}

pub fn detect_global_tls() -> Vec<TlsCapability> {
    let mut libraries = BTreeSet::new();
    let mut runtime_capabilities = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for pid in entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        {
            libraries.extend(mapped_libraries(pid));
            if let Some(capability) = inspect_process_runtime(pid) {
                runtime_capabilities.push(capability);
            }
        }
    }
    for candidate in [
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/lib/x86_64-linux-gnu/libssl3.so",
        "/lib/x86_64-linux-gnu/libnspr4.so",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
        "/usr/lib/x86_64-linux-gnu/libssl3.so",
        "/usr/lib/x86_64-linux-gnu/libnspr4.so",
    ] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            libraries.insert(path);
        }
    }
    let mut capabilities = libraries
        .iter()
        .filter_map(|library| inspect_tls_library(library, &libraries))
        .collect::<Vec<_>>();
    capabilities.append(&mut runtime_capabilities);
    capabilities.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then_with(|| left.build_id.cmp(&right.build_id))
    });
    capabilities
        .dedup_by(|left, right| left.provider == right.provider && left.build_id == right.build_id);
    capabilities
}

fn mapped_libraries(pid: u32) -> BTreeSet<PathBuf> {
    fs::read_to_string(format!("/proc/{pid}/maps"))
        .ok()
        .into_iter()
        .flat_map(|maps| {
            maps.lines()
                .filter_map(|line| line.split_whitespace().nth(5))
                .filter(|path| path.starts_with('/'))
                .map(|path| path.strip_suffix(" (deleted)").unwrap_or(path))
                .map(PathBuf::from)
                .filter(|path| path.is_file())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn inspect_tls_library(
    path: &Path,
    available_libraries: &BTreeSet<PathBuf>,
) -> Option<TlsCapability> {
    if !looks_like_tls_library(path) {
        return None;
    }
    let symbols = dynamic_symbols(path);
    let provider = classify_provider(path, &symbols)?;
    let build_id = provider_build_id(path).ok()?;
    let nss_nspr = (provider == TlsProvider::Nss)
        .then(|| select_nss_nspr(path, available_libraries))
        .flatten();
    let (supported, reason) = match provider {
        TlsProvider::OpenSsl | TlsProvider::BoringSsl | TlsProvider::LibreSsl => {
            let required = ["SSL_read", "SSL_write"];
            let missing = required
                .into_iter()
                .filter(|symbol| !symbols.contains(*symbol))
                .collect::<Vec<_>>();
            (
                missing.is_empty(),
                (!missing.is_empty()).then(|| format!("missing symbols: {}", missing.join(", "))),
            )
        }
        TlsProvider::GnuTls => {
            let required = ["gnutls_record_recv", "gnutls_record_send"];
            let missing = required
                .into_iter()
                .filter(|symbol| !symbols.contains(*symbol))
                .collect::<Vec<_>>();
            (
                missing.is_empty(),
                (!missing.is_empty()).then(|| format!("missing symbols: {}", missing.join(", "))),
            )
        }
        TlsProvider::Nss => {
            let nspr_symbols = nss_nspr.as_deref().map(dynamic_symbols).unwrap_or_default();
            let supported = symbols.contains("SSL_ImportFD")
                && nspr_symbols.contains("PR_Read")
                && nspr_symbols.contains("PR_Write")
                && nss_nspr.is_some();
            (
                supported,
                (!supported).then(|| {
                    "NSS requires SSL_ImportFD plus PR_Read/PR_Write from libnspr4.so".to_owned()
                }),
            )
        }
        TlsProvider::Rustls => {
            let required = [
                "rustls_connection_process_new_packets",
                "rustls_connection_read",
                "rustls_connection_write",
            ];
            let missing = required
                .into_iter()
                .filter(|symbol| !symbols.contains(*symbol))
                .collect::<Vec<_>>();
            (
                missing.is_empty(),
                (!missing.is_empty()).then(|| {
                    format!(
                        "native/static rustls has no stable C ABI; rustls-ffi missing symbols: {}",
                        missing.join(", ")
                    )
                }),
            )
        }
        _ => (
            false,
            Some(format!("{provider} instrumentation is not implemented")),
        ),
    };
    let modules = if supported {
        vec![
            CaptureModule::Tls,
            CaptureModule::Http,
            CaptureModule::Plaintext,
        ]
    } else {
        Vec::new()
    };
    let mut exposed_symbols = provider_hooks(provider)
        .iter()
        .filter(|symbol| symbols.contains(**symbol))
        .map(|symbol| (*symbol).to_owned())
        .collect::<Vec<_>>();
    let auxiliary_libraries = nss_nspr.into_iter().collect::<Vec<_>>();
    if provider == TlsProvider::Nss {
        for library in &auxiliary_libraries {
            let auxiliary_symbols = dynamic_symbols(library);
            exposed_symbols.extend(
                provider_hooks(provider)
                    .iter()
                    .filter(|symbol| auxiliary_symbols.contains(**symbol))
                    .map(|symbol| (*symbol).to_owned()),
            );
        }
        exposed_symbols.sort();
        exposed_symbols.dedup();
    }
    Some(TlsCapability {
        provider,
        library: path.to_path_buf(),
        build_id,
        version_hint: path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned),
        auxiliary_libraries,
        modules,
        // This API is a capability report, not an ELF symbol dump. Returning
        // only hooks TraceLens understands keeps /api/health small and makes
        // the field useful to operators.
        symbols: exposed_symbols,
        supported,
        reason,
    })
}

fn select_nss_nspr(nss_library: &Path, available_libraries: &BTreeSet<PathBuf>) -> Option<PathBuf> {
    let sibling = nss_library.parent()?.join("libnspr4.so");
    if sibling.is_file() || available_libraries.contains(&sibling) {
        return Some(sibling);
    }
    available_libraries
        .iter()
        .find(|library| {
            library
                .file_name()
                .is_some_and(|name| name == "libnspr4.so")
        })
        .cloned()
}

fn provider_hooks(provider: TlsProvider) -> &'static [&'static str] {
    match provider {
        TlsProvider::OpenSsl | TlsProvider::BoringSsl | TlsProvider::LibreSsl => &[
            "SSL_connect",
            "SSL_get_servername",
            "SSL_get_version",
            "SSL_get_fd",
            "SSL_set_fd",
            "SSL_read",
            "SSL_write",
            "SSL_read_ex",
            "SSL_write_ex",
        ],
        TlsProvider::GnuTls => &[
            "gnutls_handshake",
            "gnutls_transport_set_int2",
            "gnutls_server_name_set",
            "gnutls_protocol_get_version",
            "gnutls_record_recv",
            "gnutls_record_send",
        ],
        TlsProvider::Nss => &[
            "SSL_ImportFD",
            "SSL_SetURL",
            "SSL_GetChannelInfo",
            "PR_Read",
            "PR_Write",
            "PR_Close",
        ],
        TlsProvider::Rustls => &[
            "rustls_connection_process_new_packets",
            "rustls_connection_read",
            "rustls_connection_write",
        ],
        _ => &[],
    }
}

fn classify_provider(path: &Path, symbols: &BTreeSet<String>) -> Option<TlsProvider> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if symbols.contains("gnutls_record_recv") || name.contains("gnutls") {
        return Some(TlsProvider::GnuTls);
    }
    if symbols.contains("SSL_ImportFD") || name == "libssl3.so" {
        return Some(TlsProvider::Nss);
    }
    if symbols.contains("rustls_connection_read") || name.contains("rustls") {
        return Some(TlsProvider::Rustls);
    }
    if name == "libjvm.so" {
        return Some(TlsProvider::Java);
    }
    if symbols.contains("SSL_read") || name.contains("libssl") {
        if symbols.iter().any(|symbol| symbol.contains("BORINGSSL")) {
            return Some(TlsProvider::BoringSsl);
        }
        if symbols.iter().any(|symbol| symbol.contains("LIBRESSL")) {
            return Some(TlsProvider::LibreSsl);
        }
        return Some(TlsProvider::OpenSsl);
    }
    None
}

fn inspect_process_runtime(pid: u32) -> Option<TlsCapability> {
    static CACHE: OnceLock<Mutex<BTreeMap<PathBuf, Option<TlsCapability>>>> = OnceLock::new();
    let executable = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(cache) = cache.lock() {
        if let Some(capability) = cache.get(&executable) {
            return capability.clone();
        }
    }
    let capability = inspect_runtime_executable(executable.clone());
    if let Ok(mut cache) = cache.lock() {
        cache.insert(executable, capability.clone());
    }
    capability
}

fn inspect_runtime_executable(executable: PathBuf) -> Option<TlsCapability> {
    let executable_name = executable
        .file_name()?
        .to_string_lossy()
        .to_ascii_lowercase();
    if executable_name == "java" || executable_name.starts_with("java-") {
        return runtime_capability(
            executable,
            TlsProvider::Java,
            None,
            "Java JSSE requires a version-matched JVMTI/JFR bridge; native uProbe ABI is unavailable",
        );
    }

    let is_go = Command::new("readelf")
        .args(["-S", "--wide"])
        .arg(&executable)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| String::from_utf8_lossy(&output.stdout).contains(".go.buildinfo"));
    if !is_go {
        return None;
    }

    let go_version = Command::new("go")
        .args(["version", "-m"])
        .arg(&executable)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .filter(|version| version.starts_with("go1."))
                .map(str::to_owned)
        })
        .or_else(|| {
            let output = Command::new("strings")
                .arg("-a")
                .arg(&executable)
                .output()
                .ok()?;
            let text = String::from_utf8_lossy(&output.stdout);
            if !text.contains("Go buildinf:") {
                return None;
            }
            text.lines().find_map(|line| {
                let start = line.find("go1.")?;
                Some(
                    line[start..]
                        .split_whitespace()
                        .next()
                        .unwrap_or("unknown")
                        .to_owned(),
                )
            })
        });
    if let Some(version) = go_version {
        return runtime_capability(
            executable,
            TlsProvider::GoTls,
            Some(version),
            "Go crypto/tls is statically linked and its register ABI is version-specific; no verified adapter matches this build",
        );
    }
    None
}

fn runtime_capability(
    executable: PathBuf,
    provider: TlsProvider,
    version_hint: Option<String>,
    reason: &str,
) -> Option<TlsCapability> {
    Some(TlsCapability {
        provider,
        build_id: provider_build_id(&executable).ok()?,
        library: executable,
        version_hint,
        auxiliary_libraries: Vec::new(),
        modules: Vec::new(),
        symbols: Vec::new(),
        supported: false,
        reason: Some(reason.to_owned()),
    })
}

fn looks_like_tls_library(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    name.contains("libssl")
        || name.contains("gnutls")
        || name.contains("nss")
        || name.contains("rustls")
        || name == "libjvm.so"
}

fn dynamic_symbols(path: &Path) -> BTreeSet<String> {
    let Ok(output) = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(path)
        .output()
    else {
        return BTreeSet::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().last())
        .map(|symbol| symbol.split('@').next().unwrap_or(symbol).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{classify_provider, select_nss_nspr, TlsProvider};
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    #[test]
    fn provider_classification_prefers_symbols_over_generic_names() {
        let gnutls = BTreeSet::from(["gnutls_record_recv".to_owned()]);
        assert_eq!(
            classify_provider(Path::new("libsomething.so"), &gnutls),
            Some(TlsProvider::GnuTls)
        );
        let openssl = BTreeSet::from(["SSL_read".to_owned()]);
        assert_eq!(
            classify_provider(Path::new("libssl.so"), &openssl),
            Some(TlsProvider::OpenSsl)
        );
        let nss = BTreeSet::from(["SSL_ImportFD".to_owned()]);
        assert_eq!(
            classify_provider(Path::new("libssl3.so"), &nss),
            Some(TlsProvider::Nss)
        );
        let rustls = BTreeSet::from(["rustls_connection_read".to_owned()]);
        assert_eq!(
            classify_provider(Path::new("librustls_ffi.so"), &rustls),
            Some(TlsProvider::Rustls)
        );
    }

    #[test]
    fn nss_uses_nspr_from_the_same_runtime_directory() {
        let libraries = BTreeSet::from([
            PathBuf::from("/lib/x86_64-linux-gnu/libnspr4.so"),
            PathBuf::from("/snap/firefox/current/usr/lib/firefox/libnspr4.so"),
        ]);
        assert_eq!(
            select_nss_nspr(
                Path::new("/snap/firefox/current/usr/lib/firefox/libssl3.so"),
                &libraries,
            ),
            Some(PathBuf::from(
                "/snap/firefox/current/usr/lib/firefox/libnspr4.so"
            ))
        );
    }
}
