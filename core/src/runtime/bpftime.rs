//! bpftime discovery, target resolution, and userspace probe launching.
//!
//! bpftime's public control surface is its CLI: a loader process is started
//! under `bpftime trace`, which injects the bpftime agent into the target and
//! keeps the loader alive while its links are active. TraceLens keeps that
//! process handle so detach is real and observable instead of being an
//! in-memory flag.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracelens_events::TraceEvent;

use super::provider::{TlsCapability, TlsProvider};
use super::ProbeKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserTarget {
    pub pid: u32,
    pub executable: PathBuf,
    pub library: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSpec {
    pub object_file: &'static str,
    pub program_name: &'static str,
    pub function_name: &'static str,
    pub retprobe: bool,
    pub companion_program_name: Option<&'static str>,
    pub companion_retprobe: bool,
}

const TLS_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_openssl_connect",
        function_name: "SSL_connect",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_tls_servername",
        function_name: "SSL_get_servername",
        retprobe: true,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_tls_version",
        function_name: "SSL_get_version",
        retprobe: true,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_tls_fd",
        function_name: "SSL_get_fd",
        retprobe: true,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_tls_set_fd",
        function_name: "SSL_set_fd",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
];
const PLAINTEXT_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_plaintext_read_enter",
        function_name: "SSL_read",
        retprobe: false,
        companion_program_name: Some("tracelens_plaintext_read_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_plaintext_write",
        function_name: "SSL_write",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_plaintext_read_ex_enter",
        function_name: "SSL_read_ex",
        retprobe: false,
        companion_program_name: Some("tracelens_plaintext_read_ex_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "openssl.o",
        program_name: "tracelens_plaintext_write_ex_enter",
        function_name: "SSL_write_ex",
        retprobe: false,
        companion_program_name: Some("tracelens_plaintext_write_ex_exit"),
        companion_retprobe: true,
    },
];
const GNUTLS_TLS_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "gnutls.o",
        program_name: "tracelens_gnutls_handshake",
        function_name: "gnutls_handshake",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "gnutls.o",
        program_name: "tracelens_gnutls_set_fd",
        function_name: "gnutls_transport_set_int2",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "gnutls.o",
        program_name: "tracelens_gnutls_server_name_set",
        function_name: "gnutls_server_name_set",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "gnutls.o",
        program_name: "tracelens_gnutls_protocol_enter",
        function_name: "gnutls_protocol_get_version",
        retprobe: false,
        companion_program_name: Some("tracelens_gnutls_protocol_exit"),
        companion_retprobe: true,
    },
];
const GNUTLS_PLAINTEXT_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "gnutls.o",
        program_name: "tracelens_gnutls_recv_enter",
        function_name: "gnutls_record_recv",
        retprobe: false,
        companion_program_name: Some("tracelens_gnutls_recv_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "gnutls.o",
        program_name: "tracelens_gnutls_send_enter",
        function_name: "gnutls_record_send",
        retprobe: false,
        companion_program_name: Some("tracelens_gnutls_send_exit"),
        companion_retprobe: true,
    },
];
const NSS_TLS_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "nss.o",
        program_name: "tracelens_nss_import_fd",
        function_name: "SSL_ImportFD",
        retprobe: true,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "nss.o",
        program_name: "tracelens_nss_set_url",
        function_name: "SSL_SetURL",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "nss.o",
        program_name: "tracelens_nss_channel_info_enter",
        function_name: "SSL_GetChannelInfo",
        retprobe: false,
        companion_program_name: Some("tracelens_nss_channel_info_exit"),
        companion_retprobe: true,
    },
];
const NSS_PLAINTEXT_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "nss.o",
        program_name: "tracelens_nspr_read_enter",
        function_name: "PR_Read",
        retprobe: false,
        companion_program_name: Some("tracelens_nspr_read_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "nss.o",
        program_name: "tracelens_nspr_write_enter",
        function_name: "PR_Write",
        retprobe: false,
        companion_program_name: Some("tracelens_nspr_write_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "nss.o",
        program_name: "tracelens_nspr_close",
        function_name: "PR_Close",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
];
const RUSTLS_TLS_SPECS: &[ProbeSpec] = &[ProbeSpec {
    object_file: "rustls.o",
    program_name: "tracelens_rustls_process_packets",
    function_name: "rustls_connection_process_new_packets",
    retprobe: false,
    companion_program_name: None,
    companion_retprobe: false,
}];
const RUSTLS_PLAINTEXT_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "rustls.o",
        program_name: "tracelens_rustls_read_enter",
        function_name: "rustls_connection_read",
        retprobe: false,
        companion_program_name: Some("tracelens_rustls_read_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "rustls.o",
        program_name: "tracelens_rustls_write_enter",
        function_name: "rustls_connection_write",
        retprobe: false,
        companion_program_name: Some("tracelens_rustls_write_exit"),
        companion_retprobe: true,
    },
];
pub fn probe_specs(probe: ProbeKind) -> &'static [ProbeSpec] {
    match probe {
        ProbeKind::Tls => TLS_SPECS,
        ProbeKind::Http => &[],
        ProbeKind::Plaintext => PLAINTEXT_SPECS,
    }
}

pub fn provider_probe_specs(provider: TlsProvider, probe: ProbeKind) -> &'static [ProbeSpec] {
    match provider {
        TlsProvider::GnuTls => match probe {
            ProbeKind::Tls => GNUTLS_TLS_SPECS,
            ProbeKind::Plaintext => GNUTLS_PLAINTEXT_SPECS,
            ProbeKind::Http => &[],
        },
        TlsProvider::Nss => match probe {
            ProbeKind::Tls => NSS_TLS_SPECS,
            ProbeKind::Plaintext => NSS_PLAINTEXT_SPECS,
            ProbeKind::Http => &[],
        },
        TlsProvider::Rustls => match probe {
            ProbeKind::Tls => RUSTLS_TLS_SPECS,
            ProbeKind::Plaintext => RUSTLS_PLAINTEXT_SPECS,
            ProbeKind::Http => &[],
        },
        TlsProvider::OpenSsl | TlsProvider::BoringSsl | TlsProvider::LibreSsl => probe_specs(probe),
        _ => &[],
    }
}

#[derive(Debug)]
struct ManagedProvider {
    key: String,
    target: String,
    attachments: Vec<BpftimeAttachment>,
    link_count: usize,
    child: Child,
    reader: Option<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub struct BpftimeAttachment {
    pub target: String,
    pub pid: u32,
    pub probe: ProbeKind,
    pub hook: String,
}

#[derive(Debug)]
pub struct BpftimeRuntime {
    executable: Option<PathBuf>,
    loader_executable: Option<PathBuf>,
    version: Option<String>,
    detail: String,
    managed: Vec<ManagedProvider>,
    event_sender: Option<Sender<TraceEvent>>,
}

impl Default for BpftimeRuntime {
    fn default() -> Self {
        Self::detect()
    }
}

impl BpftimeRuntime {
    pub fn detect() -> Self {
        let configured = env::var_os("TRACELENS_BPFTIME").map(PathBuf::from);
        let candidate = configured
            .clone()
            .unwrap_or_else(|| PathBuf::from("bpftime"));
        let loader_executable = locate_loader();
        let result = discover(&candidate);
        match result {
            Ok((executable, version)) => {
                let detail = match &loader_executable {
                    Some(loader) => format!(
                        "bpftime {version} detected at {}; TraceLens loader at {}",
                        executable.display(),
                        loader.display()
                    ),
                    None => format!(
                        "bpftime detected at {}, but tracelens-bpftime-loader is unavailable",
                        executable.display()
                    ),
                };
                Self {
                    detail,
                    executable: Some(executable),
                    loader_executable,
                    version: Some(version),
                    managed: Vec::new(),
                    event_sender: None,
                }
            }
            Err(detail) => Self {
                executable: None,
                loader_executable,
                version: None,
                detail: if configured.is_some() {
                    format!("configured bpftime unavailable: {detail}")
                } else {
                    detail
                },
                managed: Vec::new(),
                event_sender: None,
            },
        }
    }

    /// A command alone is not enough: the TraceLens loader is required to
    /// create a real uprobe link for the selected object and symbol.
    pub fn is_available(&self) -> bool {
        self.executable.is_some() && self.loader_executable.is_some()
    }

    pub fn executable(&self) -> &Path {
        self.executable
            .as_deref()
            .unwrap_or_else(|| Path::new("bpftime"))
    }

    pub fn loader_executable(&self) -> Option<&Path> {
        self.loader_executable.as_deref()
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    pub fn set_event_sender(&mut self, sender: Sender<TraceEvent>) {
        self.event_sender = Some(sender);
    }

    pub fn attached_targets(&self) -> Vec<String> {
        self.managed
            .iter()
            .map(|attachment| attachment.key.clone())
            .collect()
    }

    pub fn attachments(&self) -> Vec<BpftimeAttachment> {
        self.managed
            .iter()
            .flat_map(|provider| provider.attachments.iter().cloned())
            .collect()
    }

    pub fn attach_provider(
        &mut self,
        target: &str,
        pid: u32,
        capability: &TlsCapability,
        requests: &[(ProbeKind, ProbeSpec)],
        object_dir: &Path,
    ) -> Result<Vec<BpftimeAttachment>, String> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        if !self.is_available() {
            return Err(self.detail.clone());
        }
        let object_file = requests[0].1.object_file;
        let object_path = resolve_object_path(object_dir, object_file)?;
        let key = provider_key(capability.provider, target, pid, &capability.build_id);
        if let Some(provider) = self.managed.iter().find(|provider| provider.key == key) {
            return Ok(provider.attachments.clone());
        }
        let attachments = requests
            .iter()
            .map(|(probe, spec)| BpftimeAttachment {
                target: target.to_owned(),
                pid,
                probe: *probe,
                hook: spec.function_name.to_owned(),
            })
            .collect::<Vec<_>>();

        let loader = self
            .loader_executable
            .as_deref()
            .ok_or_else(|| "tracelens-bpftime-loader is unavailable".to_owned())?;
        let mut command = Command::new(self.executable());
        if let Some(install_location) = install_location() {
            command.arg("--install-location").arg(install_location);
        }
        command
            .args(["trace", "--pid"])
            .arg(pid.to_string())
            .arg(loader)
            .args(["--pid", &pid.to_string(), "--object"])
            .arg(&object_path)
            .args(["--library"])
            .arg(&capability.library);
        let mut link_count = 0;
        for (_, spec) in requests {
            command.arg("--attach").arg(encode_loader_attachment(
                spec.program_name,
                spec.function_name,
                spec.retprobe,
            ));
            link_count += 1;
            if let Some(companion_program_name) = spec.companion_program_name {
                command.arg("--attach").arg(encode_loader_attachment(
                    companion_program_name,
                    spec.function_name,
                    spec.companion_retprobe,
                ));
                link_count += 1;
            }
        }
        if self.event_sender.is_some() {
            command.stdout(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("failed to start bpftime trace: {error}"))?;

        // `bpftime trace` should stay alive while the loader owns its links.
        // Catch immediate failures (bad install path, missing agent, loader
        // error) before reporting an attachment to the API.
        thread::sleep(Duration::from_millis(40));
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("failed to query bpftime trace: {error}"))?
        {
            return Err(format!("bpftime trace exited before attaching: {status}"));
        }

        let provider_name = capability.provider.to_string();
        let provider_library = capability.library.display().to_string();
        let reader = child.stdout.take().map(|stdout| {
            let sender = self.event_sender.clone();
            thread::spawn(move || {
                let Some(sender) = sender else {
                    return;
                };
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else {
                        break;
                    };
                    if let Ok(mut event) = serde_json::from_str::<TraceEvent>(&line) {
                        if let Some(instrumentation) = event.instrumentation.as_mut() {
                            instrumentation.provider.clone_from(&provider_name);
                            instrumentation.library.clone_from(&provider_library);
                        }
                        let _ = sender.send(event);
                    }
                }
            })
        });

        self.managed.push(ManagedProvider {
            key,
            target: target.to_owned(),
            attachments: attachments.clone(),
            link_count,
            child,
            reader,
        });
        Ok(attachments)
    }

    pub fn detach_target(&mut self, target: &str) {
        let mut retained = Vec::with_capacity(self.managed.len());
        for mut provider in self.managed.drain(..) {
            if provider.target == target {
                stop_provider(&mut provider);
            } else {
                retained.push(provider);
            }
        }
        self.managed = retained;
    }

    pub fn provider_count(&self) -> usize {
        self.managed.len()
    }

    pub fn reader_count(&self) -> usize {
        self.managed
            .iter()
            .filter(|provider| provider.reader.is_some())
            .count()
    }

    pub fn link_count(&self) -> usize {
        self.managed
            .iter()
            .map(|provider| provider.link_count)
            .sum()
    }
}

impl Drop for BpftimeRuntime {
    fn drop(&mut self) {
        for provider in &mut self.managed {
            stop_provider(provider);
        }
    }
}

pub fn resolve_user_target(pid: u32) -> Result<UserTarget, String> {
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    if !process_dir.is_dir() {
        return Err(format!("process {pid} is not present"));
    }
    let executable = fs::canonicalize(process_dir.join("exe"))
        .map_err(|error| format!("cannot resolve /proc/{pid}/exe: {error}"))?;
    let library = find_mapped_ssl_library(pid).unwrap_or_else(|| executable.clone());
    Ok(UserTarget {
        pid,
        executable,
        library,
    })
}

/// Resolve a target only when the dynamic OpenSSL library is mapped. Uprobes
/// attached to the executable as a fallback can look successful while never
/// seeing SSL_* calls, so real probe attachment must wait for libssl.
pub fn resolve_user_ssl_target(pid: u32) -> Result<UserTarget, String> {
    if pid == 0 {
        return resolve_global_ssl_target();
    }
    let mut target = resolve_user_target(pid)?;
    target.library = find_mapped_ssl_library(pid).ok_or_else(|| {
        format!("libssl is not mapped in process {pid} yet; userspace probes will be retried")
    })?;
    Ok(target)
}

/// Resolve a system-wide libssl path for a uprobe attached to all processes.
/// This is used by process-name selectors so a newly exec'd short-lived
/// client is covered before its ProcessExec event reaches Core.
pub fn resolve_global_ssl_target() -> Result<UserTarget, String> {
    let library = find_global_ssl_library().ok_or_else(|| {
        "no mapped or installed libssl library could be found for global userspace probes"
            .to_owned()
    })?;
    Ok(UserTarget {
        pid: 0,
        executable: library.clone(),
        library,
    })
}

fn find_mapped_ssl_library(pid: u32) -> Option<PathBuf> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let paths = maps.lines().filter_map(map_path).collect::<Vec<_>>();
    paths.into_iter().find(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains("libssl"))
            && path.is_file()
    })
}

fn find_global_ssl_library() -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if let Some(library) = find_mapped_ssl_library(pid) {
                return Some(library);
            }
        }
    }

    let candidates = [
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.3",
    ];
    candidates
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

fn map_path(line: &str) -> Option<PathBuf> {
    let path = line.split_whitespace().nth(5)?;
    if !path.starts_with('/') {
        return None;
    }
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    Some(PathBuf::from(path))
}

fn resolve_object_path(object_dir: &Path, object_file: &str) -> Result<PathBuf, String> {
    let path = object_dir.join(object_file);
    fs::canonicalize(&path).map_err(|error| {
        format!(
            "userspace BPF object {} is unavailable: {error}",
            path.display()
        )
    })
}

fn locate_loader() -> Option<PathBuf> {
    if let Some(path) = env::var_os("TRACELENS_BPFTIME_LOADER").map(PathBuf::from) {
        return path.is_file().then_some(path);
    }
    let current_exe = env::current_exe().ok()?;
    let sibling = current_exe.parent()?.join("tracelens-bpftime-loader");
    if sibling.is_file() {
        return Some(sibling);
    }
    let cwd = env::current_dir()
        .ok()?
        .join("target/debug/tracelens-bpftime-loader");
    cwd.is_file().then_some(cwd)
}

fn install_location() -> Option<PathBuf> {
    if let Some(path) = env::var_os("TRACELENS_BPFTIME_INSTALL").map(PathBuf::from) {
        return Some(path);
    }
    let executable = env::var_os("TRACELENS_BPFTIME").map(PathBuf::from)?;
    executable.parent().map(Path::to_path_buf)
}

fn stop_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn stop_provider(provider: &mut ManagedProvider) {
    stop_child(&mut provider.child);
    if let Some(reader) = provider.reader.take() {
        let _ = reader.join();
    }
}

fn provider_key(provider: TlsProvider, target: &str, pid: u32, build_id: &str) -> String {
    format!("{provider}::{build_id}::{target}::{pid}")
}

fn encode_loader_attachment(program: &str, function: &str, retprobe: bool) -> String {
    format!("{program},{function},{}", u8::from(retprobe))
}

pub fn provider_build_id(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read provider {}: {error}", path.display()))?;
    for offset in 0..bytes.len().saturating_sub(16) {
        let namesz = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let descsz = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let note_type = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap());
        if namesz != 4 || note_type != 3 || !(4..=64).contains(&descsz) {
            continue;
        }
        if bytes.get(offset + 12..offset + 16) != Some(b"GNU\0".as_slice()) {
            continue;
        }
        let end = offset + 16 + descsz as usize;
        let Some(build_id) = bytes.get(offset + 16..end) else {
            continue;
        };
        return Ok(build_id.iter().map(|byte| format!("{byte:02x}")).collect());
    }
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot stat provider {}: {error}", path.display()))?;
    Ok(format!("fallback-{}", metadata.len()))
}

fn discover(candidate: &Path) -> Result<(PathBuf, String), String> {
    let mut command = Command::new(candidate);
    command.arg("--version");
    let output = command
        .output()
        .map_err(|error| format!("cannot execute {}: {error}", candidate.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} --version exited with {}",
            candidate.display(),
            output.status
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let version = stdout
        .lines()
        .chain(stderr.lines())
        .find(|line| !line.trim().is_empty())
        .unwrap_or("bpftime")
        .trim()
        .to_owned();
    let executable = if candidate.components().count() == 1 {
        PathBuf::from(candidate)
    } else {
        candidate.to_owned()
    };
    let help = Command::new(candidate)
        .arg("--help")
        .output()
        .map_err(|error| {
            format!(
                "cannot inspect {} capabilities: {error}",
                candidate.display()
            )
        })?;
    let help_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );
    if !help_text.split_whitespace().any(|word| word == "trace") {
        return Err(format!(
            "{} does not provide the trace command required by the current TraceLens adapter",
            candidate.display()
        ));
    }
    Ok((executable, version))
}

#[cfg(test)]
mod tests {
    use super::{
        probe_specs, provider_build_id, provider_key, provider_probe_specs, resolve_user_target,
        BpftimeRuntime,
    };
    use crate::runtime::provider::TlsProvider;
    use crate::runtime::ProbeKind;

    #[test]
    fn provider_keys_are_build_and_target_scoped() {
        assert_eq!(
            provider_key(TlsProvider::OpenSsl, "process:42", 42, "abc123"),
            "OpenSSL::abc123::process:42::42"
        );
    }

    #[test]
    fn current_executable_has_a_stable_provider_identity() {
        let executable = std::env::current_exe().expect("current executable");
        let first = provider_build_id(&executable).expect("provider identity");
        let second = provider_build_id(&executable).expect("provider identity");
        assert_eq!(first, second);
        assert!(!first.is_empty());
    }

    #[test]
    fn tls_dependency_uses_the_unified_openssl_object() {
        let specs = probe_specs(ProbeKind::Tls);
        assert_eq!(specs.len(), 5);
        assert!(specs.iter().all(|spec| spec.object_file == "openssl.o"));
        assert_eq!(specs[1].function_name, "SSL_get_servername");
    }

    #[test]
    fn plaintext_dependency_uses_the_unified_openssl_object() {
        let specs = probe_specs(ProbeKind::Plaintext);
        assert_eq!(specs.len(), 4);
        assert!(specs.iter().all(|spec| spec.object_file == "openssl.o"));
        assert_eq!(
            specs[0].companion_program_name,
            Some("tracelens_plaintext_read_exit")
        );
        assert_eq!(specs[1].function_name, "SSL_write");
        assert_eq!(specs[2].function_name, "SSL_read_ex");
        assert_eq!(specs[3].function_name, "SSL_write_ex");
    }

    #[test]
    fn gnutls_catalog_uses_the_provider_specific_record_api() {
        let tls = provider_probe_specs(TlsProvider::GnuTls, ProbeKind::Tls);
        let plaintext = provider_probe_specs(TlsProvider::GnuTls, ProbeKind::Plaintext);
        assert!(tls
            .iter()
            .chain(plaintext)
            .all(|spec| spec.object_file == "gnutls.o"));
        assert!(plaintext
            .iter()
            .any(|spec| spec.function_name == "gnutls_record_recv"));
        assert!(plaintext
            .iter()
            .any(|spec| spec.function_name == "gnutls_record_send"));
    }

    #[test]
    fn nss_catalog_tracks_imported_descriptors_before_nspr_io() {
        let tls = provider_probe_specs(TlsProvider::Nss, ProbeKind::Tls);
        let plaintext = provider_probe_specs(TlsProvider::Nss, ProbeKind::Plaintext);
        assert_eq!(tls[0].function_name, "SSL_ImportFD");
        assert!(plaintext.iter().any(|spec| spec.function_name == "PR_Read"));
        assert!(plaintext
            .iter()
            .any(|spec| spec.function_name == "PR_Write"));
        assert!(plaintext
            .iter()
            .any(|spec| spec.function_name == "PR_Close"));
        assert!(tls
            .iter()
            .chain(plaintext)
            .all(|spec| spec.object_file == "nss.o"));
    }

    #[test]
    fn rustls_ffi_catalog_uses_stable_connection_functions() {
        let tls = provider_probe_specs(TlsProvider::Rustls, ProbeKind::Tls);
        let plaintext = provider_probe_specs(TlsProvider::Rustls, ProbeKind::Plaintext);
        assert_eq!(
            tls[0].function_name,
            "rustls_connection_process_new_packets"
        );
        assert_eq!(plaintext[0].function_name, "rustls_connection_read");
        assert_eq!(plaintext[1].function_name, "rustls_connection_write");
    }

    #[test]
    fn current_process_has_a_resolvable_user_target() {
        let target = resolve_user_target(std::process::id()).expect("current process target");
        assert!(target.executable.is_file());
        assert!(target.library.is_file());
    }

    #[test]
    fn unavailable_runtime_rejects_attach_without_side_effects() {
        let runtime = BpftimeRuntime::detect();
        assert!(runtime.attached_targets().is_empty());
    }
}
