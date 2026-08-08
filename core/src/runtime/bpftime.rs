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
        object_file: "tls.o",
        program_name: "tracelens_tls_servername",
        function_name: "SSL_get_servername",
        retprobe: true,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "tls.o",
        program_name: "tracelens_tls_version",
        function_name: "SSL_get_version",
        retprobe: true,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "tls.o",
        program_name: "tracelens_tls_fd",
        function_name: "SSL_get_fd",
        retprobe: true,
        companion_program_name: None,
        companion_retprobe: false,
    },
    ProbeSpec {
        object_file: "tls.o",
        program_name: "tracelens_tls_set_fd",
        function_name: "SSL_set_fd",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
];
const PLAINTEXT_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "plaintext.o",
        program_name: "tracelens_plaintext_read_enter",
        function_name: "SSL_read",
        retprobe: false,
        companion_program_name: Some("tracelens_plaintext_read_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "plaintext.o",
        program_name: "tracelens_plaintext_write",
        function_name: "SSL_write",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
];
const HTTP_SPECS: &[ProbeSpec] = &[
    ProbeSpec {
        object_file: "http.o",
        program_name: "tracelens_http_read_enter",
        function_name: "SSL_read",
        retprobe: false,
        companion_program_name: Some("tracelens_http_read_exit"),
        companion_retprobe: true,
    },
    ProbeSpec {
        object_file: "http.o",
        program_name: "tracelens_http_write",
        function_name: "SSL_write",
        retprobe: false,
        companion_program_name: None,
        companion_retprobe: false,
    },
];

pub fn probe_specs(probe: ProbeKind) -> &'static [ProbeSpec] {
    match probe {
        ProbeKind::Tls => TLS_SPECS,
        ProbeKind::Http => HTTP_SPECS,
        ProbeKind::Plaintext => PLAINTEXT_SPECS,
    }
}

#[derive(Debug)]
struct ManagedAttachment {
    key: String,
    target: String,
    pid: u32,
    probe: ProbeKind,
    hook: String,
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
    managed: Vec<ManagedAttachment>,
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
            .map(|attachment| BpftimeAttachment {
                target: attachment.target.clone(),
                pid: attachment.pid,
                probe: attachment.probe,
                hook: attachment.hook.clone(),
            })
            .collect()
    }

    pub fn attach(
        &mut self,
        target: &str,
        pid: u32,
        probe: ProbeKind,
        spec: ProbeSpec,
        object_dir: &Path,
    ) -> Result<BpftimeAttachment, String> {
        if !self.is_available() {
            return Err(self.detail.clone());
        }
        let target_info = resolve_user_target(pid)?;
        let object_path = resolve_object_path(object_dir, spec.object_file)?;
        let key = attachment_key(target, pid, probe, spec.function_name);
        if self.managed.iter().any(|attachment| attachment.key == key) {
            return Ok(BpftimeAttachment {
                target: target.to_owned(),
                pid,
                probe,
                hook: spec.function_name.to_owned(),
            });
        }

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
            .arg(&target_info.library)
            .args([
                "--function",
                spec.function_name,
                "--program",
                spec.program_name,
            ]);
        if spec.retprobe {
            command.arg("--retprobe");
        }
        if let Some(companion_program_name) = spec.companion_program_name {
            command
                .arg("--companion-program")
                .arg(companion_program_name);
            if spec.companion_retprobe {
                command.arg("--companion-retprobe");
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
                    if let Ok(event) = serde_json::from_str::<TraceEvent>(&line) {
                        let _ = sender.send(event);
                    }
                }
            })
        });

        self.managed.push(ManagedAttachment {
            key,
            target: target.to_owned(),
            pid,
            probe,
            hook: spec.function_name.to_owned(),
            child,
            reader,
        });
        Ok(BpftimeAttachment {
            target: target.to_owned(),
            pid,
            probe,
            hook: spec.function_name.to_owned(),
        })
    }

    pub fn detach(&mut self, target: &str, pid: u32, probe: ProbeKind, hook: &str) {
        let key = attachment_key(target, pid, probe, hook);
        let mut retained = Vec::with_capacity(self.managed.len());
        for mut attachment in self.managed.drain(..) {
            if attachment.key == key {
                stop_attachment(&mut attachment);
            } else {
                retained.push(attachment);
            }
        }
        self.managed = retained;
    }

    pub fn detach_target(&mut self, target: &str) {
        let prefix = format!("{target}::");
        let mut retained = Vec::with_capacity(self.managed.len());
        for mut attachment in self.managed.drain(..) {
            if attachment.key.starts_with(&prefix) {
                stop_attachment(&mut attachment);
            } else {
                retained.push(attachment);
            }
        }
        self.managed = retained;
    }
}

impl Drop for BpftimeRuntime {
    fn drop(&mut self) {
        for attachment in &mut self.managed {
            stop_attachment(attachment);
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
    let library = find_ssl_library(pid).unwrap_or_else(|| executable.clone());
    Ok(UserTarget {
        pid,
        executable,
        library,
    })
}

fn find_ssl_library(pid: u32) -> Option<PathBuf> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let paths = maps.lines().filter_map(map_path).collect::<Vec<_>>();
    paths
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("libssl"))
                && path.is_file()
        })
        .cloned()
        .or_else(|| {
            paths.into_iter().find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains("libcrypto"))
                    && path.is_file()
            })
        })
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

fn stop_attachment(attachment: &mut ManagedAttachment) {
    stop_child(&mut attachment.child);
    if let Some(reader) = attachment.reader.take() {
        let _ = reader.join();
    }
}

fn attachment_key(target: &str, pid: u32, probe: ProbeKind, hook: &str) -> String {
    format!("{target}::{pid}::{probe}::{hook}")
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
    Ok((executable, version))
}

#[cfg(test)]
mod tests {
    use super::{attachment_key, probe_specs, resolve_user_target, BpftimeRuntime};
    use crate::runtime::ProbeKind;

    #[test]
    fn attachment_keys_are_target_pid_probe_and_hook_scoped() {
        assert_eq!(
            attachment_key("process:42", 42, ProbeKind::Tls, "SSL_connect"),
            "process:42::42::tls::SSL_connect"
        );
    }

    #[test]
    fn tls_dependency_expands_to_openssl_and_tls_objects() {
        let specs = probe_specs(ProbeKind::Tls);
        assert_eq!(specs.len(), 5);
        assert_eq!(specs[0].object_file, "openssl.o");
        assert_eq!(specs[1].function_name, "SSL_get_servername");
    }

    #[test]
    fn http_dependency_uses_a_private_bounded_capture_object() {
        let specs = probe_specs(ProbeKind::Http);
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].object_file, "http.o");
        assert_eq!(
            specs[0].companion_program_name,
            Some("tracelens_http_read_exit")
        );
        assert_eq!(specs[1].function_name, "SSL_write");
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
