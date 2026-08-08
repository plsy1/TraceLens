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

use crate::observation::ObservationLevel;

use super::{
    bpftime::{
        probe_specs, resolve_global_ssl_target, resolve_user_ssl_target, BpftimeAttachment,
        BpftimeRuntime, ProbeSpec,
    },
    probes_for_level, ProbeKind, RuntimeStatus, UserspaceRuntime,
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
struct KernelUprobeAttachment {
    target: String,
    pid: u32,
    probe: ProbeKind,
    hook: String,
    _object: Option<Object>,
    _links: Vec<Link>,
    stop_reader: Option<Arc<AtomicBool>>,
    reader: Option<JoinHandle<()>>,
}

#[derive(Debug, Default)]
pub struct KernelUprobeRuntime {
    attachments: BTreeMap<String, KernelUprobeAttachment>,
    dry_run: bool,
    event_sender: Option<Sender<TraceEvent>>,
}

impl KernelUprobeRuntime {
    fn attach(
        &mut self,
        target: &str,
        pid: u32,
        probe: ProbeKind,
        spec: ProbeSpec,
        object_dir: &Path,
    ) -> Result<ProbeAttachment, String> {
        let key = attachment_key(target, pid, probe, spec.function_name);
        if self.attachments.contains_key(&key) {
            return Ok(ProbeAttachment {
                target: target.to_owned(),
                pid,
                probe,
                hook: spec.function_name.to_owned(),
                runtime: UserspaceRuntime::KernelUprobe,
            });
        }

        if self.dry_run {
            self.attachments.insert(
                key,
                KernelUprobeAttachment {
                    target: target.to_owned(),
                    pid,
                    probe,
                    hook: spec.function_name.to_owned(),
                    _object: None,
                    _links: Vec::new(),
                    stop_reader: None,
                    reader: None,
                },
            );
            return Ok(ProbeAttachment {
                target: target.to_owned(),
                pid,
                probe,
                hook: spec.function_name.to_owned(),
                runtime: UserspaceRuntime::KernelUprobe,
            });
        }

        let target_info = if pid == 0 {
            resolve_global_ssl_target()?
        } else {
            resolve_user_ssl_target(pid)?
        };
        let attach_pid = if pid == 0 { -1 } else { pid as i32 };

        let object_path = object_dir.join(spec.object_file);
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
        let attach_program =
            |object: &mut Object, program_name: &str, retprobe: bool| -> Result<Link, String> {
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
                        &target_info.library,
                        0,
                        UprobeOpts {
                            func_name: Some(spec.function_name.to_owned()),
                            retprobe,
                            ..Default::default()
                        },
                    )
                    .map_err(|error| {
                        format!(
                            "failed to attach {} to {} for {}: {error}",
                            spec.function_name,
                            target_info.library.display(),
                            if pid == 0 {
                                "all processes".to_owned()
                            } else {
                                format!("pid {pid}")
                            }
                        )
                    })
            };
        let mut links = vec![attach_program(
            &mut object,
            spec.program_name,
            spec.retprobe,
        )?];
        if let Some(companion_program_name) = spec.companion_program_name {
            links.push(attach_program(
                &mut object,
                companion_program_name,
                spec.companion_retprobe,
            )?);
        }

        let (stop_reader, reader) = if let Some(sender) = self.event_sender.clone() {
            if let Some(events) = object.maps().find(|map| map.name() == OsStr::new("events")) {
                let mut ring_buffer_builder = RingBufferBuilder::new();
                ring_buffer_builder
                    .add(&events, move |data| {
                        if let Some(event) = decode_userspace_event(data, EventSource::Kernel) {
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

        self.attachments.insert(
            key,
            KernelUprobeAttachment {
                target: target.to_owned(),
                pid,
                probe,
                hook: spec.function_name.to_owned(),
                _object: Some(object),
                _links: links,
                stop_reader,
                reader,
            },
        );
        Ok(ProbeAttachment {
            target: target.to_owned(),
            pid,
            probe,
            hook: spec.function_name.to_owned(),
            runtime: UserspaceRuntime::KernelUprobe,
        })
    }

    fn detach_target(&mut self, target: &str) {
        let keys = self
            .attachments
            .iter()
            .filter(|(_, attachment)| attachment.target == target)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(mut attachment) = self.attachments.remove(&key) {
                attachment.stop();
            }
        }
    }

    fn attachments(&self) -> impl Iterator<Item = ProbeAttachment> + '_ {
        self.attachments.values().map(|attachment| ProbeAttachment {
            target: attachment.target.clone(),
            pid: attachment.pid,
            probe: attachment.probe,
            hook: attachment.hook.clone(),
            runtime: UserspaceRuntime::KernelUprobe,
        })
    }
}

impl Drop for KernelUprobeRuntime {
    fn drop(&mut self) {
        for attachment in self.attachments.values_mut() {
            attachment.stop();
        }
    }
}

impl KernelUprobeAttachment {
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

    pub fn set_level(
        &mut self,
        target: &str,
        level: ObservationLevel,
        process_pids: &[u32],
    ) -> Vec<ProbeAttachment> {
        let mut attachments = Vec::new();
        let process_pids = if target == "global" || target.starts_with("process-name:") {
            // PID 0 is the internal sentinel for a uprobe attached to all
            // processes. The Core scope filter drops unrelated events.
            vec![0]
        } else {
            process_pids.to_vec()
        };
        for probe in probes_for_level(level) {
            let specs = probe_specs(probe);
            if specs.is_empty() {
                if probe != ProbeKind::Http {
                    self.record_error(format!("no userspace BPF object is defined for {probe}"));
                }
                continue;
            }
            for spec in specs {
                for pid in process_pids.iter().copied() {
                    if let Some(attachment) = self.attach(target, pid, probe, *spec) {
                        attachments.push(attachment);
                    }
                }
            }
        }
        attachments
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
    pub fn matches_level(&self, target: &str, level: ObservationLevel) -> bool {
        let expected = probes_for_level(level)
            .into_iter()
            .flat_map(|probe| {
                probe_specs(probe)
                    .iter()
                    .map(move |spec| (probe, spec.function_name.to_owned()))
            })
            .collect::<std::collections::BTreeSet<_>>();
        let actual = self
            .attachments()
            .into_iter()
            .filter(|attachment| attachment.target == target)
            .map(|attachment| (attachment.probe, attachment.hook))
            .collect::<std::collections::BTreeSet<_>>();
        expected == actual
    }

    fn attach(
        &mut self,
        target: &str,
        pid: u32,
        probe: ProbeKind,
        spec: ProbeSpec,
    ) -> Option<ProbeAttachment> {
        if self.selected == UserspaceRuntime::Bpftime && pid != 0 {
            match self
                .bpftime
                .attach(target, pid, probe, spec, &self.object_dir)
            {
                Ok(attachment) => return Some(from_bpftime_attachment(attachment)),
                Err(error) => self.record_error(error),
            }
        }
        if self.kernel_uprobe_available {
            match self
                .kernel_uprobe
                .attach(target, pid, probe, spec, &self.object_dir)
            {
                Ok(attachment) => return Some(attachment),
                Err(error) => self.record_error(error),
            }
        }
        None
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

fn attachment_key(target: &str, pid: u32, probe: ProbeKind, hook: &str) -> String {
    format!("{target}::{pid}::{probe}::{hook}")
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
    _reserved: u32,
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

fn decode_userspace_event(data: &[u8], source: EventSource) -> Option<TraceEvent> {
    let event_type = read_unaligned::<u16>(data)?;
    match event_type {
        EVENT_TLS_METADATA => decode_tls_event(data, source),
        EVENT_PLAINTEXT => decode_plaintext_event(data, source),
        EVENT_HTTP_CAPTURE => decode_http_capture_event(data, source),
        _ => None,
    }
}

fn decode_tls_event(data: &[u8], source: EventSource) -> Option<TraceEvent> {
    let event = read_unaligned::<UserTlsEvent>(data)?;
    if event.event_type != EVENT_TLS_METADATA || event.pid == 0 {
        return None;
    }
    Some(TraceEvent::tls_metadata(
        source,
        event.pid,
        TlsEventData {
            ssl_object: event.ssl_object,
            fd: (event.fd >= 0).then_some(event.fd),
            sni: bytes_to_string(&event.sni),
            version: bytes_to_string(&event.version),
        },
        event.timestamp_ns,
    ))
}

fn decode_plaintext_event(data: &[u8], source: EventSource) -> Option<TraceEvent> {
    let event = read_unaligned::<UserPlaintextEvent>(data)?;
    if event.event_type != EVENT_PLAINTEXT || event.pid == 0 {
        return None;
    }
    let direction = match event.direction {
        1 => PlaintextDirection::Read,
        2 => PlaintextDirection::Write,
        _ => return None,
    };
    let payload_size = usize::try_from(event.payload_size).ok()?;
    let captured_size = payload_size.min(PLAINTEXT_MAX_LEN);
    Some(TraceEvent::plaintext(
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
    ))
}

fn decode_http_capture_event(data: &[u8], source: EventSource) -> Option<TraceEvent> {
    let event = read_unaligned::<UserPlaintextEvent>(data)?;
    if event.event_type != EVENT_HTTP_CAPTURE || event.pid == 0 {
        return None;
    }
    let direction = match event.direction {
        1 => PlaintextDirection::Read,
        2 => PlaintextDirection::Write,
        _ => return None,
    };
    let payload_size = usize::try_from(event.payload_size).ok()?;
    let captured_size = payload_size.min(PLAINTEXT_MAX_LEN);
    Some(TraceEvent::http_capture(
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
    ))
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
    use crate::observation::ObservationLevel;
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
        let attachments = runtime.set_level(&target, ObservationLevel::L3, &[pid]);
        assert_eq!(attachments.len(), 5);
        assert!(attachments
            .iter()
            .all(|attachment| attachment.runtime == UserspaceRuntime::KernelUprobe));
        assert_eq!(runtime.attachments().len(), 5);
        assert!(runtime.matches_level(&target, ObservationLevel::L3));
        assert!(!runtime.matches_level(&target, ObservationLevel::L5));
        runtime.detach_target(&target);
        assert!(runtime.attachments().is_empty());
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
            _reserved: 0,
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
        let decoded = decode_userspace_event(bytes, tracelens_events::EventSource::Kernel)
            .expect("TLS event");
        assert_eq!(decoded.pid, Some(7));
        assert_eq!(decoded.kind, tracelens_events::EventKind::TlsMetadata);
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
            direction: 2,
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
        let decoded = decode_userspace_event(bytes, tracelens_events::EventSource::Kernel)
            .expect("plaintext event");
        assert_eq!(decoded.kind, tracelens_events::EventKind::Plaintext);
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
        let decoded = decode_userspace_event(bytes, tracelens_events::EventSource::Kernel)
            .expect("HTTP capture event");
        assert_eq!(decoded.kind, tracelens_events::EventKind::HttpCapture);
        assert!(matches!(
            decoded.payload,
            tracelens_events::EventPayload::HttpCapture { .. }
        ));
    }

    #[test]
    fn process_name_level_uses_global_probe_attachments() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let attachments = runtime.set_level("process-name:curl", ObservationLevel::L4, &[]);
        assert_eq!(attachments.len(), 7);
        assert!(attachments.iter().all(|attachment| attachment.pid == 0));
        assert!(attachments
            .iter()
            .all(|attachment| attachment.target == "process-name:curl"));
        runtime.detach_target("process-name:curl");
        assert!(runtime.attachments().is_empty());
    }

    #[test]
    fn global_level_uses_global_probe_attachments() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let attachments = runtime.set_level("global", ObservationLevel::L4, &[]);
        assert_eq!(attachments.len(), 7);
        assert!(attachments.iter().all(|attachment| attachment.pid == 0));
        assert!(attachments
            .iter()
            .all(|attachment| attachment.target == "global"));
        runtime.detach_target("global");
        assert!(runtime.attachments().is_empty());
    }

    #[test]
    fn l4_attaches_bounded_capture_pairs_without_http_probes() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let pid = std::process::id();
        let target = format!("process:{pid}");
        let attachments = runtime.set_level(&target, ObservationLevel::L4, &[pid]);
        assert_eq!(attachments.len(), 7);
        assert!(attachments
            .iter()
            .any(|attachment| attachment.probe == crate::runtime::ProbeKind::Plaintext));
        assert!(!attachments
            .iter()
            .any(|attachment| attachment.probe == crate::runtime::ProbeKind::Http));
        runtime.detach_target(&target);
    }

    #[test]
    fn l5_attaches_read_pair_and_write_probe() {
        let status = RuntimeStatus {
            kernel_observation: true,
            userspace_runtime: UserspaceRuntime::KernelUprobe,
            detail: "test fallback".to_owned(),
        };
        let mut runtime = ProbeRuntime::new_for_test(&status);
        let pid = std::process::id();
        let target = format!("process:{pid}");
        let attachments = runtime.set_level(&target, ObservationLevel::L5, &[pid]);
        assert_eq!(attachments.len(), 7);
        assert_eq!(runtime.attachments().len(), 7);
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
        let attachments = runtime.set_level("process:999999", ObservationLevel::L3, &[999999]);
        assert!(attachments.is_empty());
        assert!(!runtime.errors().is_empty());
    }
}
