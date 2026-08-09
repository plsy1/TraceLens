use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, RingBufferBuilder, UprobeOpts};
use tracelens_events::{
    EventSource, PlaintextDirection, PlaintextEventData, TlsEventData, TraceEvent,
};

use crate::capture::CaptureFeatures;
use crate::observation::ObservationLevel;

use super::{
    bpftime::{provider_probe_specs, BpftimeAttachment, BpftimeRuntime, ProbeSpec},
    probes_for_features,
    provider::{detect_global_tls, detect_process_tls, TlsCapability, TlsProvider},
    ProbeKind, RuntimeStatus, UserspaceRuntime,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeAttachment {
    pub target: String,
    pub pid: u32,
    pub probe: ProbeKind,
    pub hook: String,
    pub runtime: UserspaceRuntime,
}

#[derive(Debug)]
struct KernelUprobeProvider {
    target: String,
    _pid: u32,
    _build_id: String,
    attachments: Vec<ProbeAttachment>,
    _object: Option<Object>,
    _links: Vec<Link>,
    link_count: usize,
    stop_reader: Option<Arc<AtomicBool>>,
    reader: Option<JoinHandle<()>>,
}

#[derive(Debug, Default)]
pub struct KernelUprobeRuntime {
    providers: BTreeMap<String, KernelUprobeProvider>,
    dry_run: bool,
    event_sender: Option<Sender<TraceEvent>>,
}

impl KernelUprobeRuntime {
    fn attach_provider(
        &mut self,
        target: &str,
        pid: u32,
        capability: &TlsCapability,
        requests: &[(ProbeKind, ProbeSpec)],
        object_dir: &Path,
    ) -> Result<Vec<ProbeAttachment>, String> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }
        let attachments = requests
            .iter()
            .map(|(probe, spec)| ProbeAttachment {
                target: target.to_owned(),
                pid,
                probe: *probe,
                hook: spec.function_name.to_owned(),
                runtime: UserspaceRuntime::KernelUprobe,
            })
            .collect::<Vec<_>>();
        if self.dry_run {
            let key = provider_instance_key(capability.provider, target, pid, &capability.build_id);
            let link_count = requests
                .iter()
                .map(|(_, spec)| 1 + usize::from(spec.companion_program_name.is_some()))
                .sum();
            self.providers
                .entry(key)
                .or_insert_with(|| KernelUprobeProvider {
                    target: target.to_owned(),
                    _pid: pid,
                    _build_id: "dry-run".to_owned(),
                    attachments: attachments.clone(),
                    _object: None,
                    _links: Vec::new(),
                    link_count,
                    stop_reader: None,
                    reader: None,
                });
            return Ok(attachments);
        }

        let key = provider_instance_key(capability.provider, target, pid, &capability.build_id);
        if let Some(provider) = self.providers.get(&key) {
            return Ok(provider.attachments.clone());
        }
        let attach_pid = if pid == 0 { -1 } else { pid as i32 };
        let object_path = object_dir.join(requests[0].1.object_file);
        if !object_path.is_file() {
            return Err(format!(
                "userspace BPF object {} is unavailable",
                object_path.display()
            ));
        }
        let mut builder = ObjectBuilder::default();
        let open_object = builder
            .open_file(&object_path)
            .map_err(|error| format!("failed to open {}: {error}", object_path.display()))?;
        let mut object = open_object
            .load()
            .map_err(|error| format!("failed to load {}: {error}", object_path.display()))?;
        let attach_program = |object: &mut Object,
                              program_name: &str,
                              function_name: &str,
                              retprobe: bool|
         -> Result<Link, String> {
            let library = if function_name.starts_with("PR_") {
                capability
                    .auxiliary_libraries
                    .iter()
                    .find(|library| {
                        library
                            .file_name()
                            .is_some_and(|name| name == "libnspr4.so")
                    })
                    .ok_or_else(|| "NSS provider is missing libnspr4.so".to_owned())?
            } else {
                &capability.library
            };
            let program = object
                .progs_mut()
                .find(|program| program.name() == OsStr::new(program_name))
                .ok_or_else(|| {
                    format!(
                        "BPF program `{program_name}` is missing from {}",
                        object_path.display()
                    )
                })?;
            program
                .attach_uprobe_with_opts(
                    attach_pid,
                    library,
                    0,
                    UprobeOpts {
                        func_name: Some(function_name.to_owned()),
                        retprobe,
                        ..Default::default()
                    },
                )
                .map_err(|error| {
                    format!(
                        "failed to attach {function_name} to {} for {}: {error}",
                        library.display(),
                        if pid == 0 {
                            "all processes".to_owned()
                        } else {
                            format!("pid {pid}")
                        }
                    )
                })
        };
        let mut links = Vec::new();
        for (_, spec) in requests {
            links.push(attach_program(
                &mut object,
                spec.program_name,
                spec.function_name,
                spec.retprobe,
            )?);
            if let Some(companion_program_name) = spec.companion_program_name {
                links.push(attach_program(
                    &mut object,
                    companion_program_name,
                    spec.function_name,
                    spec.companion_retprobe,
                )?);
            }
        }

        let (stop_reader, reader) = if let Some(sender) = self.event_sender.clone() {
            if let Some(events) = object.maps().find(|map| map.name() == OsStr::new("events")) {
                let mut ring_buffer_builder = RingBufferBuilder::new();
                let provider = capability.provider.to_string();
                let library = capability.library.display().to_string();
                let auxiliary_library = capability
                    .auxiliary_libraries
                    .first()
                    .map(|library| library.display().to_string());
                ring_buffer_builder
                    .add(&events, move |data| {
                        if let Some(event) = decode_userspace_event(
                            data,
                            EventSource::Kernel,
                            &provider,
                            &library,
                            auxiliary_library.as_deref(),
                        ) {
                            let _ = sender.send(event);
                        }
                        0
                    })
                    .map_err(|error| {
                        format!(
                            "failed to register userspace event ring buffer for {}: {error}",
                            object_path.display()
                        )
                    })?;
                let ring_buffer = ring_buffer_builder.build().map_err(|error| {
                    format!(
                        "failed to build userspace event ring buffer for {}: {error}",
                        object_path.display()
                    )
                })?;
                let stop = Arc::new(AtomicBool::new(false));
                let reader_stop = Arc::clone(&stop);
                let reader = thread::spawn(move || {
                    while !reader_stop.load(Ordering::Relaxed) {
                        if ring_buffer.poll(Duration::from_millis(100)).is_err() {
                            break;
                        }
                    }
                });
                (Some(stop), Some(reader))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        self.providers.insert(
            key,
            KernelUprobeProvider {
                target: target.to_owned(),
                _pid: pid,
                _build_id: capability.build_id.clone(),
                attachments: attachments.clone(),
                _object: Some(object),
                link_count: links.len(),
                _links: links,
                stop_reader,
                reader,
            },
        );
        Ok(attachments)
    }

    fn detach_target(&mut self, target: &str) {
        let keys = self
            .providers
            .iter()
            .filter(|(_, provider)| provider.target == target)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(mut provider) = self.providers.remove(&key) {
                provider.stop();
            }
        }
    }

    fn attachments(&self) -> impl Iterator<Item = ProbeAttachment> + '_ {
        self.providers
            .values()
            .flat_map(|provider| provider.attachments.iter().cloned())
    }

    fn provider_count(&self) -> usize {
        self.providers.len()
    }

    fn reader_count(&self) -> usize {
        self.providers
            .values()
            .filter(|provider| provider.reader.is_some())
            .count()
    }

    fn link_count(&self) -> usize {
        self.providers
            .values()
            .map(|provider| provider.link_count)
            .sum()
    }
}

impl Drop for KernelUprobeRuntime {
    fn drop(&mut self) {
        for provider in self.providers.values_mut() {
            provider.stop();
        }
    }
}

impl KernelUprobeProvider {
    fn stop(&mut self) {
        if let Some(stop) = self.stop_reader.take() {
            stop.store(true, Ordering::Relaxed);
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[derive(Debug)]
pub struct ProbeRuntime {
    selected: UserspaceRuntime,
    kernel_uprobe_available: bool,
    object_dir: PathBuf,
    bpftime: BpftimeRuntime,
    kernel_uprobe: KernelUprobeRuntime,
    capabilities: Vec<TlsCapability>,
    errors: Vec<String>,
}

impl ProbeRuntime {
    pub fn new(status: &RuntimeStatus, object_dir: &Path) -> Self {
        Self {
            selected: status.userspace_runtime,
            kernel_uprobe_available: status.kernel_observation,
            object_dir: object_dir.to_owned(),
            bpftime: BpftimeRuntime::detect(),
            kernel_uprobe: KernelUprobeRuntime::default(),
            capabilities: Vec::new(),
            errors: Vec::new(),
        }
    }

    #[cfg(test)]
    fn new_for_test(status: &RuntimeStatus) -> Self {
        let mut runtime = Self::new(status, Path::new("missing"));
        runtime.kernel_uprobe.dry_run = true;
        runtime
    }

    pub fn selected(&self) -> UserspaceRuntime {
        self.selected
    }

    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    pub fn set_event_sender(&mut self, sender: Sender<TraceEvent>) {
        self.bpftime.set_event_sender(sender.clone());
        self.kernel_uprobe.event_sender = Some(sender);
    }

    pub fn set_features(
        &mut self,
        target: &str,
        features: CaptureFeatures,
        process_pids: &[u32],
    ) -> Vec<ProbeAttachment> {
        let mut attachments = Vec::new();
        self.errors.clear();
        let probes = probes_for_features(features);
        if probes.is_empty() {
            self.capabilities.clear();
            return attachments;
        }
        let global = target == "global" || target.starts_with("process-name:");
        let plans = if self.kernel_uprobe.dry_run {
            let pids = if global {
                vec![0]
            } else {
                process_pids.to_vec()
            };
            pids.into_iter()
                .map(|pid| {
                    (
                        pid,
                        TlsCapability {
                            provider: TlsProvider::OpenSsl,
                            library: PathBuf::from("dry-run-libssl.so"),
                            build_id: "dry-run".to_owned(),
                            version_hint: None,
                            auxiliary_libraries: Vec::new(),
                            modules: Vec::new(),
                            symbols: vec![
                                "SSL_connect".to_owned(),
                                "SSL_get_servername".to_owned(),
                                "SSL_get_version".to_owned(),
                                "SSL_get_fd".to_owned(),
                                "SSL_set_fd".to_owned(),
                                "SSL_read".to_owned(),
                                "SSL_write".to_owned(),
                                "SSL_read_ex".to_owned(),
                                "SSL_write_ex".to_owned(),
                            ],
                            supported: true,
                            reason: None,
                        },
                    )
                })
                .collect::<Vec<_>>()
        } else if global {
            detect_global_tls()
                .into_iter()
                .map(|capability| (0, capability))
                .collect::<Vec<_>>()
        } else {
            process_pids
                .iter()
                .flat_map(|pid| {
                    detect_process_tls(*pid)
                        .into_iter()
                        .map(move |capability| (*pid, capability))
                })
                .collect()
        };
        if plans.is_empty() {
            self.capabilities.clear();
            self.record_error(format!(
                "no supported TLS provider is currently loaded for {target}"
            ));
            return attachments;
        }
        self.capabilities = plans
            .iter()
            .map(|(_, capability)| capability.clone())
            .collect();
        self.capabilities
            .sort_by(|left, right| left.build_id.cmp(&right.build_id));
        self.capabilities
            .dedup_by(|left, right| left.build_id == right.build_id);
        for (pid, capability) in plans {
            if !capability.supported {
                continue;
            }
            let requests = probes
                .iter()
                .flat_map(|probe| {
                    provider_probe_specs(capability.provider, *probe)
                        .iter()
                        .filter(|spec| {
                            capability
                                .symbols
                                .iter()
                                .any(|symbol| symbol == spec.function_name)
                        })
                        .copied()
                        .map(move |spec| (*probe, spec))
                })
                .collect::<Vec<_>>();
            if requests.is_empty() {
                self.record_error(format!(
                    "{} at {} has no probe catalog",
                    capability.provider,
                    capability.library.display()
                ));
                continue;
            }
            match self.attach_provider(target, pid, &capability, &requests) {
                Ok(mut provider_attachments) => attachments.append(&mut provider_attachments),
                Err(error) => self.record_error(error),
            }
        }
        attachments
    }

    #[deprecated(note = "use set_features")]
    pub fn set_level(
        &mut self,
        target: &str,
        level: ObservationLevel,
        process_pids: &[u32],
    ) -> Vec<ProbeAttachment> {
        let features = CaptureFeatures::legacy_level(level as u8)
            .expect("ObservationLevel always maps to legacy CaptureFeatures");
        self.set_features(target, features, process_pids)
    }

    pub fn detach_target(&mut self, target: &str) {
        self.bpftime.detach_target(target);
        self.kernel_uprobe.detach_target(target);
    }

    /// Detach every userspace probe managed by this runtime. Capture lifecycle
    /// commands use this to make a stopped or reset capture release hooks
    /// immediately instead of waiting for the traced processes to exit.
    pub fn detach_all(&mut self) {
        let targets = self
            .attachments()
            .into_iter()
            .map(|attachment| attachment.target)
            .collect::<std::collections::BTreeSet<_>>();
        for target in targets {
            self.detach_target(&target);
        }
        self.capabilities.clear();
    }

    pub fn attachments(&self) -> Vec<ProbeAttachment> {
        let mut attachments = self
            .bpftime
            .attachments()
            .into_iter()
            .map(|attachment| ProbeAttachment {
                target: attachment.target,
                pid: attachment.pid,
                probe: attachment.probe,
                hook: attachment.hook,
                runtime: UserspaceRuntime::Bpftime,
            })
            .collect::<Vec<_>>();
        attachments.extend(self.kernel_uprobe.attachments());
        attachments.sort_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then_with(|| left.pid.cmp(&right.pid))
                .then_with(|| left.probe.cmp(&right.probe))
                .then_with(|| left.hook.cmp(&right.hook))
        });
        attachments
    }

    /// Return whether the managed links for a target exactly cover the
    /// probes required by an observation level. A process can emit its exec
    /// event before its dynamic SSL library is mapped, so an initial attach
    /// may be incomplete and needs a later retry.
    pub fn matches_features(&self, target: &str, features: CaptureFeatures) -> bool {
        let expected = probes_for_features(features)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        let actual = self
            .attachments()
            .into_iter()
            .filter(|attachment| attachment.target == target)
            .map(|attachment| attachment.probe)
            .collect::<std::collections::BTreeSet<_>>();
        expected == actual
    }

    #[deprecated(note = "use matches_features")]
    pub fn matches_level(&self, target: &str, level: ObservationLevel) -> bool {
        let features = CaptureFeatures::legacy_level(level as u8)
            .expect("ObservationLevel always maps to legacy CaptureFeatures");
        self.matches_features(target, features)
    }

    fn attach_provider(
        &mut self,
        target: &str,
        pid: u32,
        capability: &TlsCapability,
        requests: &[(ProbeKind, ProbeSpec)],
    ) -> Result<Vec<ProbeAttachment>, String> {
        if self.selected == UserspaceRuntime::Bpftime
            && pid != 0
            && capability.provider != TlsProvider::Nss
        {
            match self
                .bpftime
                .attach_provider(target, pid, capability, requests, &self.object_dir)
            {
                Ok(attachments) => {
                    return Ok(attachments
                        .into_iter()
                        .map(from_bpftime_attachment)
                        .collect())
                }
                Err(error) => self.record_error(error),
            }
        }
        if self.kernel_uprobe_available {
            return self.kernel_uprobe.attach_provider(
                target,
                pid,
                capability,
                requests,
                &self.object_dir,
            );
        }
        Err("no userspace probe runtime is available".to_owned())
    }

    pub fn diagnostics(&self) -> UserspaceProbeDiagnostics {
        UserspaceProbeDiagnostics {
            provider_instances: self.kernel_uprobe.provider_count() + self.bpftime.provider_count(),
            readers: self.kernel_uprobe.reader_count() + self.bpftime.reader_count(),
            links: self.kernel_uprobe.link_count() + self.bpftime.link_count(),
        }
    }

    pub fn capabilities(&self) -> &[TlsCapability] {
        &self.capabilities
    }

    fn record_error(&mut self, error: String) {
        if !self.errors.contains(&error) {
            self.errors.push(error);
        }
        if self.errors.len() > 32 {
            self.errors.remove(0);
        }
    }
}

fn from_bpftime_attachment(attachment: BpftimeAttachment) -> ProbeAttachment {
    ProbeAttachment {
        target: attachment.target,
        pid: attachment.pid,
        probe: attachment.probe,
        hook: attachment.hook,
        runtime: UserspaceRuntime::Bpftime,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserspaceProbeDiagnostics {
    pub provider_instances: usize,
    pub readers: usize,
    pub links: usize,
}

fn provider_instance_key(provider: TlsProvider, target: &str, pid: u32, build_id: &str) -> String {
    format!("{provider}::{build_id}::{target}::{pid}")
}

const EVENT_TLS_METADATA: u16 = 7;
const EVENT_PLAINTEXT: u16 = 8;
const EVENT_HTTP_CAPTURE: u16 = 11;
const TLS_NAME_LEN: usize = 128;
const TLS_VERSION_LEN: usize = 32;
const PLAINTEXT_MAX_LEN: usize = 16 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserTlsEvent {
    event_type: u16,
    _metadata_kind: u16,
    pid: u32,
    timestamp_ns: u64,
    ssl_object: u64,
    fd: i32,
    api_id: u32,
    sni: [u8; TLS_NAME_LEN],
    version: [u8; TLS_VERSION_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserPlaintextEvent {
    event_type: u16,
    direction: u16,
    pid: u32,
    timestamp_ns: u64,
    ssl_object: u64,
    fd: i32,
    payload_size: u32,
    truncated: u32,
    payload: [u8; PLAINTEXT_MAX_LEN],
}

fn decode_userspace_event(
    data: &[u8],
    source: EventSource,
    provider: &str,
    library: &str,
    auxiliary_library: Option<&str>,
) -> Option<TraceEvent> {
    let event_type = read_unaligned::<u16>(data)?;
    match event_type {
        EVENT_TLS_METADATA => decode_tls_event(data, source, provider, library),
        EVENT_PLAINTEXT => {
            decode_plaintext_event(data, source, provider, auxiliary_library.unwrap_or(library))
        }
        EVENT_HTTP_CAPTURE => {
            decode_http_capture_event(data, source, provider, auxiliary_library.unwrap_or(library))
        }
        _ => None,
    }
}

fn decode_tls_event(
    data: &[u8],
    source: EventSource,
    provider: &str,
    library: &str,
) -> Option<TraceEvent> {
    let event = read_unaligned::<UserTlsEvent>(data)?;
    if event.event_type != EVENT_TLS_METADATA || event.pid == 0 {
        return None;
    }
    Some(
        TraceEvent::tls_metadata(
            source,
            event.pid,
            TlsEventData {
                ssl_object: event.ssl_object,
                fd: (event.fd >= 0).then_some(event.fd),
                sni: bytes_to_string(&event.sni),
                version: bytes_to_string(&event.version),
            },
            event.timestamp_ns,
        )
        .with_instrumentation(provider, library, event.api_id as u16),
    )
}

fn decode_plaintext_event(
    data: &[u8],
    source: EventSource,
    provider: &str,
    library: &str,
) -> Option<TraceEvent> {
    let event = read_unaligned::<UserPlaintextEvent>(data)?;
    if event.event_type != EVENT_PLAINTEXT || event.pid == 0 {
        return None;
    }
    let direction = match event.direction & 0xff {
        1 => PlaintextDirection::Read,
        2 => PlaintextDirection::Write,
        _ => return None,
    };
    let payload_size = usize::try_from(event.payload_size).ok()?;
    let captured_size = payload_size.min(PLAINTEXT_MAX_LEN);
    Some(
        TraceEvent::plaintext(
            source,
            event.pid,
            PlaintextEventData {
                ssl_object: event.ssl_object,
                fd: (event.fd >= 0).then_some(event.fd),
                direction,
                data: String::from_utf8_lossy(&event.payload[..captured_size]).into_owned(),
                bytes: payload_size,
                truncated: event.truncated != 0 || payload_size > PLAINTEXT_MAX_LEN,
            },
            event.timestamp_ns,
        )
        .with_instrumentation(provider, library, event.direction >> 8),
    )
}

fn decode_http_capture_event(
    data: &[u8],
    source: EventSource,
    provider: &str,
    library: &str,
) -> Option<TraceEvent> {
    let event = read_unaligned::<UserPlaintextEvent>(data)?;
    if event.event_type != EVENT_HTTP_CAPTURE || event.pid == 0 {
        return None;
    }
    let direction = match event.direction & 0xff {
        1 => PlaintextDirection::Read,
        2 => PlaintextDirection::Write,
        _ => return None,
    };
    let payload_size = usize::try_from(event.payload_size).ok()?;
    let captured_size = payload_size.min(PLAINTEXT_MAX_LEN);
    Some(
        TraceEvent::http_capture(
            source,
            event.pid,
            PlaintextEventData {
                ssl_object: event.ssl_object,
                fd: (event.fd >= 0).then_some(event.fd),
                direction,
                data: String::from_utf8_lossy(&event.payload[..captured_size]).into_owned(),
                bytes: payload_size,
                truncated: event.truncated != 0 || payload_size > PLAINTEXT_MAX_LEN,
            },
            event.timestamp_ns,
        )
        .with_instrumentation(provider, library, event.direction >> 8),
    )
}

fn read_unaligned<T: Copy>(data: &[u8]) -> Option<T> {
    if data.len() < std::mem::size_of::<T>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr().cast::<T>()) })
}

fn bytes_to_string(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    (end > 0).then(|| String::from_utf8_lossy(&bytes[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        decode_userspace_event, ProbeRuntime, UserPlaintextEvent, UserTlsEvent, EVENT_HTTP_CAPTURE,
        PLAINTEXT_MAX_LEN, TLS_NAME_LEN, TLS_VERSION_LEN,
    };
    use crate::capture::{CaptureFeatures, CaptureModule};
    use crate::runtime::{RuntimeStatus, UserspaceRuntime};

    #[test]
    fn linux_fallback_can_track_probe_attachments() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let pid = std::process::id();
        let target = format!("process:{pid}");
        let tls = CaptureFeatures::from_modules([CaptureModule::Tls]);
        let attachments = runtime.set_features(&target, tls, &[pid]);
        assert_eq!(attachments.len(), 5);
        assert!(attachments
            .iter()
            .all(|attachment| attachment.runtime == UserspaceRuntime::KernelUprobe));
        assert_eq!(runtime.attachments().len(), 5);
        assert_eq!(runtime.diagnostics().provider_instances, 1);
        assert_eq!(runtime.diagnostics().links, 5);
        assert!(runtime.matches_features(&target, tls));
        assert!(!runtime.matches_features(
            &target,
            CaptureFeatures::from_modules([CaptureModule::Tls, CaptureModule::Plaintext]),
        ));
        runtime.detach_target(&target);
        assert!(runtime.attachments().is_empty());
    }

    #[test]
    fn metadata_only_features_do_not_create_an_empty_userspace_provider() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let features = CaptureFeatures::from_modules([
            CaptureModule::Process,
            CaptureModule::Connections,
            CaptureModule::Dns,
        ]);
        assert!(runtime.set_features("global", features, &[]).is_empty());
        assert_eq!(runtime.diagnostics(), Default::default());
    }

    #[test]
    fn decodes_tls_metadata_from_the_shared_ring_buffer_layout() {
        assert_eq!(std::mem::size_of::<UserTlsEvent>(), 192);
        let event = UserTlsEvent {
            event_type: 7,
            _metadata_kind: 2,
            pid: 7,
            timestamp_ns: 42,
            ssl_object: 0x1234,
            fd: 9,
            api_id: tracelens_events::TLS_API_OPENSSL_GET_SERVERNAME as u32,
            sni: {
                let mut value = [0_u8; TLS_NAME_LEN];
                value[..11].copy_from_slice(b"example.com");
                value
            },
            version: {
                let mut value = [0_u8; TLS_VERSION_LEN];
                value[..7].copy_from_slice(b"TLSv1.3");
                value
            },
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const UserTlsEvent).cast::<u8>(),
                std::mem::size_of::<UserTlsEvent>(),
            )
        };
        let decoded = decode_userspace_event(
            bytes,
            tracelens_events::EventSource::Kernel,
            "OpenSSL",
            "/lib/libssl.so",
            None,
        )
        .expect("TLS event");
        assert_eq!(decoded.pid, Some(7));
        assert_eq!(decoded.kind, tracelens_events::EventKind::TlsMetadata);
        assert_eq!(
            decoded
                .instrumentation
                .as_ref()
                .map(|source| source.api_function.as_str()),
            Some("SSL_get_servername")
        );
        match decoded.payload {
            tracelens_events::EventPayload::Tls {
                sni, version, fd, ..
            } => {
                assert_eq!(sni.as_deref(), Some("example.com"));
                assert_eq!(version.as_deref(), Some("TLSv1.3"));
                assert_eq!(fd, Some(9));
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
    }

    #[test]
    fn decodes_bounded_plaintext_from_the_shared_ring_buffer_layout() {
        assert_eq!(
            std::mem::size_of::<UserPlaintextEvent>(),
            40 + PLAINTEXT_MAX_LEN
        );
        let event = UserPlaintextEvent {
            event_type: 8,
            direction: 2 | (tracelens_events::TLS_API_OPENSSL_WRITE << 8),
            pid: 7,
            timestamp_ns: 42,
            ssl_object: 0x1234,
            fd: 9,
            payload_size: 900,
            truncated: 0,
            payload: {
                let mut value = [0_u8; PLAINTEXT_MAX_LEN];
                value.fill(b'x');
                value[..5].copy_from_slice(b"hello");
                value
            },
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const UserPlaintextEvent).cast::<u8>(),
                std::mem::size_of::<UserPlaintextEvent>(),
            )
        };
        let decoded = decode_userspace_event(
            bytes,
            tracelens_events::EventSource::Kernel,
            "OpenSSL",
            "/lib/libssl.so",
            None,
        )
        .expect("plaintext event");
        assert_eq!(decoded.kind, tracelens_events::EventKind::Plaintext);
        assert_eq!(
            decoded
                .instrumentation
                .as_ref()
                .map(|source| source.api_function.as_str()),
            Some("SSL_write")
        );
        match decoded.payload {
            tracelens_events::EventPayload::Plaintext {
                data,
                bytes,
                direction,
                truncated,
                ..
            } => {
                assert!(data.starts_with("hello"));
                assert_eq!(data.len(), 900);
                assert_eq!(bytes, 900);
                assert_eq!(direction, tracelens_events::PlaintextDirection::Write);
                assert!(!truncated);
            }
            payload => panic!("unexpected payload: {payload:?}"),
        }
    }

    #[test]
    fn decodes_http_capture_without_turning_it_into_a_plaintext_event() {
        let event = UserPlaintextEvent {
            event_type: EVENT_HTTP_CAPTURE,
            direction: 2,
            pid: 7,
            timestamp_ns: 42,
            ssl_object: 0x1234,
            fd: 9,
            payload_size: 18,
            truncated: 0,
            payload: {
                let mut value = [0_u8; PLAINTEXT_MAX_LEN];
                value[..18].copy_from_slice(b"GET / HTTP/1.1\r\n\r\n");
                value
            },
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&event as *const UserPlaintextEvent).cast::<u8>(),
                std::mem::size_of::<UserPlaintextEvent>(),
            )
        };
        let decoded = decode_userspace_event(
            bytes,
            tracelens_events::EventSource::Kernel,
            "OpenSSL",
            "/lib/libssl.so",
            None,
        )
        .expect("HTTP capture event");
        assert_eq!(decoded.kind, tracelens_events::EventKind::HttpCapture);
        assert!(matches!(
            decoded.payload,
            tracelens_events::EventPayload::HttpCapture { .. }
        ));
    }

    #[test]
    fn process_name_features_use_global_probe_attachments() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let features = CaptureFeatures::from_modules([CaptureModule::Tls, CaptureModule::Http]);
        let attachments = runtime.set_features("process-name:curl", features, &[]);
        assert_eq!(attachments.len(), 9);
        assert_eq!(runtime.diagnostics().provider_instances, 1);
        assert_eq!(runtime.diagnostics().links, 12);
        assert!(attachments.iter().all(|attachment| attachment.pid == 0));
        assert!(attachments
            .iter()
            .all(|attachment| attachment.target == "process-name:curl"));
        runtime.detach_target("process-name:curl");
        assert!(runtime.attachments().is_empty());
    }

    #[test]
    fn global_features_use_global_probe_attachments() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let features = CaptureFeatures::from_modules([CaptureModule::Tls, CaptureModule::Http]);
        let attachments = runtime.set_features("global", features, &[]);
        assert_eq!(attachments.len(), 9);
        assert_eq!(runtime.diagnostics().provider_instances, 1);
        assert!(attachments.iter().all(|attachment| attachment.pid == 0));
        assert!(attachments
            .iter()
            .all(|attachment| attachment.target == "global"));
        runtime.detach_target("global");
        assert!(runtime.attachments().is_empty());
    }

    #[test]
    fn http_feature_attaches_bounded_capture_pairs_without_http_probes() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let pid = std::process::id();
        let target = format!("process:{pid}");
        let features = CaptureFeatures::from_modules([CaptureModule::Tls, CaptureModule::Http]);
        let attachments = runtime.set_features(&target, features, &[pid]);
        assert_eq!(attachments.len(), 9);
        assert!(attachments
            .iter()
            .any(|attachment| attachment.probe == crate::runtime::ProbeKind::Plaintext));
        assert!(!attachments
            .iter()
            .any(|attachment| attachment.probe == crate::runtime::ProbeKind::Http));
        runtime.detach_target(&target);
    }

    #[test]
    fn plaintext_feature_attaches_read_pair_and_write_probe() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let pid = std::process::id();
        let target = format!("process:{pid}");
        let features =
            CaptureFeatures::from_modules([CaptureModule::Tls, CaptureModule::Plaintext]);
        let attachments = runtime.set_features(&target, features, &[pid]);
        assert_eq!(attachments.len(), 9);
        assert_eq!(runtime.attachments().len(), 9);
        runtime.detach_target(&target);
    }

    #[test]
    fn missing_process_has_no_fake_kernel_attachment() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new(&status, std::path::Path::new("missing"));
        let features = CaptureFeatures::from_modules([CaptureModule::Tls]);
        let attachments = runtime.set_features("process:999999", features, &[999999]);
        assert!(attachments.is_empty());
        assert!(!runtime.errors().is_empty());
    }
}
