//! Kernel eBPF runtime and ring-buffer event decoder.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::{net::IpAddr, net::Ipv4Addr, net::Ipv6Addr};

use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder, RingBufferBuilder};
use tracelens_events::{
    ConnectionRef, ConnectionState, DnsEventData, Endpoint, EventKind, EventSource, FileEventData,
    ProcessRef, TcpState, TraceEvent, TransportProtocol,
};

use crate::capture::{CaptureFeatures, CaptureModule};
use crate::config::CoreConfig;
use crate::CaptureScope;

const EVENT_PROCESS_EXEC: u16 = 1;
const EVENT_PROCESS_EXIT: u16 = 2;
const EVENT_TCP_CONNECT: u16 = 3;
const EVENT_TCP_CLOSE: u16 = 4;
const EVENT_DNS_QUERY: u16 = 5;
const EVENT_DNS_RESPONSE: u16 = 6;
const EVENT_TCP_STATE: u16 = 9;
const EVENT_TCP_BYTES: u16 = 10;
const EVENT_FILE_OPEN: u16 = 12;
const EVENT_FILE_READ: u16 = 13;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;
const COMM_LEN: usize = 16;
const ADDR_LEN: usize = 16;
const DNS_PAYLOAD_LEN: usize = 512;
const FILE_PATH_LEN: usize = 256;
const SCOPE_GLOBAL: u32 = 0;
const SCOPE_PID: u32 = 1;
const SCOPE_COMM: u32 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelCaptureConfig {
    active: u32,
    scope_mode: u32,
    target_pid: u32,
    target_comm: [u8; COMM_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelProcessEvent {
    event_type: u16,
    _reserved: u16,
    pid: u32,
    comm: [u8; COMM_LEN],
    timestamp_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelNetworkEvent {
    event_type: u16,
    family: u16,
    pid: u32,
    socket_id: u64,
    timestamp_ns: u64,
    protocol: u16,
    local_port: u16,
    remote_port: u16,
    _reserved: u16,
    old_state: u32,
    new_state: u32,
    local_addr: [u8; ADDR_LEN],
    remote_addr: [u8; ADDR_LEN],
    sent_bytes: u64,
    received_bytes: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelDnsEvent {
    event_type: u16,
    protocol: u16,
    pid: u32,
    socket_id: u64,
    timestamp_ns: u64,
    payload_size: u32,
    payload: [u8; DNS_PAYLOAD_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelFileEvent {
    event_type: u16,
    _reserved: u16,
    pid: u32,
    timestamp_ns: u64,
    bytes: u64,
    path: [u8; FILE_PATH_LEN],
}

const PROCESS_PROGRAMS: &[&str] = &["tracelens_process_exec", "tracelens_process_exit"];
const CONNECTION_PROGRAMS: &[&str] = &[
    "tracelens_connect",
    "tracelens_connect_exit",
    "tracelens_close",
    "tracelens_tcp_state",
];
const TRAFFIC_PROGRAMS: &[&str] = &[
    "tracelens_sendto_enter",
    "tracelens_sendto_exit",
    "tracelens_recvfrom_enter",
    "tracelens_recvfrom_exit",
    "tracelens_sendmsg_enter",
    "tracelens_sendmsg_exit",
    "tracelens_recvmsg_enter",
    "tracelens_recvmsg_exit",
    "tracelens_write_enter",
    "tracelens_write_exit",
    "tracelens_read_enter",
    "tracelens_read_exit",
];
const FILE_PROGRAMS: &[&str] = &["tracelens_file_open"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelRuntimeState {
    Idle,
    Attaching,
    Capturing,
    Failed,
}

impl std::fmt::Display for KernelRuntimeState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Idle => "idle",
            Self::Attaching => "attaching",
            Self::Capturing => "capturing",
            Self::Failed => "failed",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRuntimeStatus {
    pub state: KernelRuntimeState,
    pub objects: Vec<String>,
    pub programs: Vec<String>,
    pub link_count: usize,
    pub capture_target: Option<String>,
    pub error: Option<String>,
}

impl Default for KernelRuntimeStatus {
    fn default() -> Self {
        Self {
            state: KernelRuntimeState::Idle,
            objects: Vec::new(),
            programs: Vec::new(),
            link_count: 0,
            capture_target: None,
            error: None,
        }
    }
}

enum KernelCommand {
    Apply {
        features: CaptureFeatures,
        target: CaptureScope,
        reply: mpsc::Sender<Result<KernelRuntimeStatus, String>>,
    },
    Stop {
        reply: mpsc::Sender<Result<KernelRuntimeStatus, String>>,
    },
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct KernelRuntimeController {
    commands: mpsc::Sender<KernelCommand>,
    status: Arc<Mutex<KernelRuntimeStatus>>,
}

impl KernelRuntimeController {
    pub fn spawn(config: CoreConfig, sender: mpsc::Sender<TraceEvent>) -> Self {
        let (commands, receiver) = mpsc::channel();
        let status = Arc::new(Mutex::new(KernelRuntimeStatus::default()));
        let worker_status = Arc::clone(&status);
        thread::spawn(move || kernel_worker(config, sender, receiver, worker_status));
        Self { commands, status }
    }

    pub fn apply_plan(
        &self,
        features: CaptureFeatures,
        target: CaptureScope,
    ) -> Result<KernelRuntimeStatus, String> {
        let (reply, response) = mpsc::channel();
        self.commands
            .send(KernelCommand::Apply {
                features,
                target,
                reply,
            })
            .map_err(|_| "kernel runtime worker is unavailable".to_owned())?;
        response
            .recv()
            .map_err(|_| "kernel runtime worker stopped before applying the plan".to_owned())?
    }

    pub fn stop(&self) -> Result<KernelRuntimeStatus, String> {
        let (reply, response) = mpsc::channel();
        self.commands
            .send(KernelCommand::Stop { reply })
            .map_err(|_| "kernel runtime worker is unavailable".to_owned())?;
        response
            .recv()
            .map_err(|_| "kernel runtime worker stopped before detaching".to_owned())?
    }

    pub fn status(&self) -> KernelRuntimeStatus {
        self.status
            .lock()
            .map(|status| status.clone())
            .unwrap_or(KernelRuntimeStatus {
                state: KernelRuntimeState::Failed,
                error: Some("kernel runtime status lock is poisoned".to_owned()),
                ..KernelRuntimeStatus::default()
            })
    }

    pub fn shutdown(&self) {
        let _ = self.commands.send(KernelCommand::Shutdown);
    }
}

fn kernel_worker(
    config: CoreConfig,
    sender: mpsc::Sender<TraceEvent>,
    commands: mpsc::Receiver<KernelCommand>,
    status: Arc<Mutex<KernelRuntimeStatus>>,
) {
    let mut command = match commands.recv() {
        Ok(command) => command,
        Err(_) => return,
    };
    loop {
        match command {
            KernelCommand::Apply {
                features,
                target,
                reply,
            } => {
                set_kernel_status(
                    &status,
                    KernelRuntimeStatus {
                        state: KernelRuntimeState::Attaching,
                        ..KernelRuntimeStatus::default()
                    },
                );
                match run_kernel_plan(
                    &config,
                    sender.clone(),
                    features,
                    target,
                    &commands,
                    &status,
                    &reply,
                ) {
                    Ok(next) => command = next,
                    Err(error) => {
                        set_kernel_status(
                            &status,
                            KernelRuntimeStatus {
                                state: KernelRuntimeState::Failed,
                                error: Some(error.clone()),
                                ..KernelRuntimeStatus::default()
                            },
                        );
                        let _ = reply.send(Err(error));
                        command = match commands.recv() {
                            Ok(command) => command,
                            Err(_) => return,
                        };
                    }
                }
            }
            KernelCommand::Stop { reply } => {
                let idle = KernelRuntimeStatus::default();
                set_kernel_status(&status, idle.clone());
                let _ = reply.send(Ok(idle));
                command = match commands.recv() {
                    Ok(command) => command,
                    Err(_) => return,
                };
            }
            KernelCommand::Shutdown => return,
        }
    }
}

fn run_kernel_plan(
    config: &CoreConfig,
    sender: mpsc::Sender<TraceEvent>,
    features: CaptureFeatures,
    target: CaptureScope,
    commands: &mpsc::Receiver<KernelCommand>,
    shared_status: &Arc<Mutex<KernelRuntimeStatus>>,
    apply_reply: &mpsc::Sender<Result<KernelRuntimeStatus, String>>,
) -> Result<KernelCommand, String> {
    let process_enabled = features.contains(CaptureModule::Process);
    let connections_enabled = features.contains(CaptureModule::Connections);
    let traffic_enabled = features.contains(CaptureModule::Traffic);
    let dns_enabled = features.contains(CaptureModule::Dns);
    let files_enabled = features.contains(CaptureModule::Files);

    let mut process_object = load_optional_object(config, "process.o", process_enabled)?;
    let mut network_object = load_optional_object(
        config,
        "network.o",
        connections_enabled || traffic_enabled || dns_enabled,
    )?;
    let mut file_object = load_optional_object(config, "file.o", files_enabled)?;

    for object in [&process_object, &network_object, &file_object]
        .into_iter()
        .flatten()
    {
        set_capture_scope(object, &target)?;
    }
    if let Some(object) = network_object.as_ref() {
        set_network_features(object, traffic_enabled, dns_enabled)?;
        if dns_enabled {
            set_dns_dependency_pids(object, &discover_dns_dependency_pids())?;
        }
    }

    let mut links = Vec::new();
    let mut programs = Vec::new();
    if let Some(object) = process_object.as_mut() {
        attach_programs(object, PROCESS_PROGRAMS, &mut links, &mut programs)?;
    }
    if let Some(object) = network_object.as_mut() {
        if connections_enabled {
            attach_programs(object, CONNECTION_PROGRAMS, &mut links, &mut programs)?;
        }
        if traffic_enabled || dns_enabled {
            attach_programs(object, TRAFFIC_PROGRAMS, &mut links, &mut programs)?;
        }
    }
    if let Some(object) = file_object.as_mut() {
        attach_programs(object, FILE_PROGRAMS, &mut links, &mut programs)?;
    }

    let process_cache = Rc::new(RefCell::new(HashMap::<u32, ProcessRef>::new()));
    let process_events = process_object
        .as_ref()
        .map(|object| find_map(object, "events"))
        .transpose()?;
    let network_events = network_object
        .as_ref()
        .map(|object| find_map(object, "events"))
        .transpose()?;
    let file_events = file_object
        .as_ref()
        .map(|object| find_map(object, "events"))
        .transpose()?;
    let mut ring_buffer_builder = RingBufferBuilder::new();
    if let Some(events) = process_events.as_ref() {
        let event_sender = sender.clone();
        let cache = Rc::clone(&process_cache);
        ring_buffer_builder
            .add(events, move |data| {
                if let Some(event) = decode_process_event(data) {
                    update_process_cache(&cache, &event);
                    let _ = event_sender.send(event);
                }
                0
            })
            .map_err(|error| format!("failed to register process ring buffer: {error}"))?;
    }
    if let Some(events) = network_events.as_ref() {
        let event_sender = sender.clone();
        let cache = Rc::clone(&process_cache);
        ring_buffer_builder
            .add(events, move |data| {
                if let Some(event) =
                    decode_network_event(data, &cache).or_else(|| decode_dns_event(data))
                {
                    let _ = event_sender.send(event);
                }
                0
            })
            .map_err(|error| format!("failed to register network ring buffer: {error}"))?;
    }
    if let Some(events) = file_events.as_ref() {
        ring_buffer_builder
            .add(events, move |data| {
                if let Some(event) = decode_file_event(data) {
                    let _ = sender.send(event);
                }
                0
            })
            .map_err(|error| format!("failed to register file ring buffer: {error}"))?;
    }
    let ring_buffer = ring_buffer_builder
        .build()
        .map_err(|error| format!("failed to build kernel ring buffer: {error}"))?;

    let mut objects = Vec::new();
    if process_object.is_some() {
        objects.push("process.o".to_owned());
    }
    if network_object.is_some() {
        objects.push("network.o".to_owned());
    }
    if file_object.is_some() {
        objects.push("file.o".to_owned());
    }
    let attached = KernelRuntimeStatus {
        state: KernelRuntimeState::Capturing,
        objects,
        link_count: links.len(),
        programs,
        capture_target: Some(target.to_string()),
        error: None,
    };
    set_kernel_status(shared_status, attached.clone());
    let _ = apply_reply.send(Ok(attached));

    loop {
        if let Ok(command) = commands.try_recv() {
            drop(ring_buffer);
            drop(links);
            let idle = KernelRuntimeStatus::default();
            set_kernel_status(shared_status, idle);
            return Ok(command);
        }
        ring_buffer
            .poll(Duration::from_millis(10))
            .map_err(|error| format!("kernel ring buffer stopped: {error}"))?;
    }
}

fn set_kernel_status(status: &Arc<Mutex<KernelRuntimeStatus>>, value: KernelRuntimeStatus) {
    if let Ok(mut status) = status.lock() {
        *status = value;
    }
}

fn load_optional_object(
    config: &CoreConfig,
    file: &str,
    enabled: bool,
) -> Result<Option<Object>, String> {
    if !enabled {
        return Ok(None);
    }
    let path = config.bpf_object_dir.join(file);
    ensure_object_exists(&path)?;
    load_object(&path).map(Some)
}

fn attach_programs(
    object: &mut Object,
    names: &[&str],
    links: &mut Vec<Link>,
    attached_names: &mut Vec<String>,
) -> Result<(), String> {
    for name in names {
        links.push(attach_program(object, name)?);
        attached_names.push((*name).to_owned());
    }
    Ok(())
}

fn set_network_features(object: &Object, traffic: bool, dns: bool) -> Result<(), String> {
    let map = find_map(object, "feature_config")?;
    let key = 0_u32.to_ne_bytes();
    let flags = u32::from(traffic) | (u32::from(dns) << 1);
    map.update(&key, &flags.to_ne_bytes(), MapFlags::ANY)
        .map_err(|error| format!("failed to configure network features: {error}"))
}

fn set_capture_scope(object: &Object, target: &CaptureScope) -> Result<(), String> {
    let map = find_map(object, "capture_config")?;
    let key = 0_u32.to_ne_bytes();
    let config = kernel_capture_config(target);
    let mut value = Vec::with_capacity(12 + COMM_LEN);
    value.extend_from_slice(&config.active.to_ne_bytes());
    value.extend_from_slice(&config.scope_mode.to_ne_bytes());
    value.extend_from_slice(&config.target_pid.to_ne_bytes());
    value.extend_from_slice(&config.target_comm);
    map.update(&key, &value, MapFlags::ANY)
        .map_err(|error| format!("failed to configure capture scope `{target}`: {error}"))
}

fn kernel_capture_config(target: &CaptureScope) -> KernelCaptureConfig {
    let mut config = KernelCaptureConfig {
        active: 1,
        scope_mode: SCOPE_GLOBAL,
        target_pid: 0,
        target_comm: [0; COMM_LEN],
    };
    match target {
        CaptureScope::Global => {}
        CaptureScope::Process(pid) => {
            config.scope_mode = SCOPE_PID;
            config.target_pid = *pid;
        }
        CaptureScope::ProcessName(name) => {
            config.scope_mode = SCOPE_COMM;
            let bytes = name.as_bytes();
            let length = bytes.len().min(COMM_LEN - 1);
            config.target_comm[..length].copy_from_slice(&bytes[..length]);
        }
    }
    config
}

fn set_dns_dependency_pids(object: &Object, pids: &[u32]) -> Result<(), String> {
    let map = find_map(object, "dependency_pids")?;
    for pid in pids {
        map.update(&pid.to_ne_bytes(), &[1], MapFlags::ANY)
            .map_err(|error| format!("failed to register DNS resolver PID {pid}: {error}"))?;
    }
    Ok(())
}

fn discover_dns_dependency_pids() -> Vec<u32> {
    let mut pids = fs::read_dir("/proc")
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| is_dns_dependency_pid(*pid))
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids
}

pub(crate) fn is_dns_dependency_name(name: &str) -> bool {
    matches!(
        name,
        "systemd-resolve"
            | "systemd-resolved"
            | "nscd"
            | "dnsmasq"
            | "unbound"
            | "named"
            | "resolved"
    )
}

pub(crate) fn is_dns_dependency_pid(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .is_some_and(|comm| is_dns_dependency_name(comm.trim()))
}

fn ensure_object_exists(path: &Path) -> Result<(), String> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!(
            "BPF object not found at {}; run `cmake -S . -B build -DTRACELENS_BUILD_BPF=ON && cmake --build build` first",
            path.display()
        ))
    }
}

fn load_object(path: &Path) -> Result<Object, String> {
    let mut builder = ObjectBuilder::default();
    let open_object = builder
        .open_file(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    open_object
        .load()
        .map_err(|error| format!("failed to load {}: {error}", path.display()))
}

fn attach_program(object: &mut Object, name: &str) -> Result<Link, String> {
    let program = object
        .progs_mut()
        .find(|program| program.name() == OsStr::new(name))
        .ok_or_else(|| format!("BPF program `{name}` is missing from object"))?;
    program
        .attach()
        .map_err(|error| format!("failed to attach BPF program `{name}`: {error}"))
}

fn find_map<'object>(
    object: &'object Object,
    name: &str,
) -> Result<impl MapCore + 'object, String> {
    object
        .maps()
        .find(|map| map.name() == OsStr::new(name))
        .ok_or_else(|| format!("BPF map `{name}` is missing from object"))
}

fn decode_process_event(data: &[u8]) -> Option<TraceEvent> {
    let event = read_unaligned::<KernelProcessEvent>(data)?;
    if event.pid == 0 {
        return None;
    }

    let executable = bytes_to_string(&event.comm).unwrap_or_else(|| "unknown".to_owned());
    let command_line = read_command_line(event.pid).unwrap_or_else(|| executable.clone());
    let ppid = read_parent_pid(event.pid);
    let kind = match event.event_type {
        EVENT_PROCESS_EXEC => EventKind::ProcessExec,
        EVENT_PROCESS_EXIT => EventKind::ProcessExit,
        _ => return None,
    };

    Some(TraceEvent::process_event(
        EventSource::Kernel,
        kind,
        event.pid,
        ppid,
        &executable,
        &command_line,
        event.timestamp_ns,
    ))
}

fn decode_network_event(
    data: &[u8],
    process_cache: &RefCell<HashMap<u32, ProcessRef>>,
) -> Option<TraceEvent> {
    let event = read_unaligned::<KernelNetworkEvent>(data)?;
    let remote_address = decode_address(event.family, event.remote_addr)?;
    let local_address = decode_address(event.family, event.local_addr);
    let kind = match event.event_type {
        EVENT_TCP_CONNECT => EventKind::TcpConnect,
        EVENT_TCP_CLOSE => EventKind::TcpClose,
        EVENT_TCP_STATE => EventKind::TcpStateChanged,
        EVENT_TCP_BYTES => EventKind::TcpBytes,
        _ => return None,
    };
    let mut tcp_state = match kind {
        EventKind::TcpConnect => Some(TcpState::Established),
        EventKind::TcpClose => Some(TcpState::Close),
        EventKind::TcpStateChanged | EventKind::TcpBytes => tcp_state(event.new_state),
        _ => None,
    };
    if kind == EventKind::TcpBytes
        && matches!(tcp_state, Some(TcpState::SynSent | TcpState::SynRecv))
        && (event.sent_bytes > 0 || event.received_bytes > 0)
    {
        tcp_state = Some(TcpState::Established);
    }
    let state = coarse_connection_state(tcp_state);
    let protocol = if event.protocol == IPPROTO_TCP {
        TransportProtocol::Tcp
    } else {
        TransportProtocol::Udp
    };
    let connection = ConnectionRef {
        id: format!("socket-{}", event.socket_id),
        protocol,
        local: (event.local_port != 0).then(|| Endpoint {
            address: local_address
                .map_or_else(|| "0.0.0.0".to_owned(), |address| address.to_string()),
            port: event.local_port,
        }),
        remote: Endpoint {
            address: remote_address.to_string(),
            port: event.remote_port,
        },
        state,
        tcp_state,
        sent_bytes: event.sent_bytes,
        received_bytes: event.received_bytes,
        domain: None,
    };

    Some(TraceEvent::connection_event_with_process(
        EventSource::Kernel,
        kind,
        event.pid,
        process_ref_for_pid(process_cache, event.pid, event.timestamp_ns),
        connection,
        event.timestamp_ns,
    ))
}

fn process_ref_for_pid(
    process_cache: &RefCell<HashMap<u32, ProcessRef>>,
    pid: u32,
    timestamp_ns: u64,
) -> Option<ProcessRef> {
    if let Some(process) = process_cache.borrow().get(&pid).cloned() {
        return Some(process);
    }
    let process = read_process_ref(pid, timestamp_ns);
    if let Some(process) = process.clone() {
        process_cache.borrow_mut().insert(pid, process);
    }
    process
}

fn update_process_cache(process_cache: &RefCell<HashMap<u32, ProcessRef>>, event: &TraceEvent) {
    let Some(pid) = event.pid else {
        return;
    };
    match &event.kind {
        EventKind::ProcessExec => {
            if let Some(process) = event.process.clone() {
                process_cache.borrow_mut().insert(pid, process);
            }
        }
        EventKind::ProcessExit => {
            process_cache.borrow_mut().remove(&pid);
        }
        _ => {}
    }
}

fn decode_dns_event(data: &[u8]) -> Option<TraceEvent> {
    let event = read_unaligned::<KernelDnsEvent>(data)?;
    let payload_size = usize::try_from(event.payload_size)
        .ok()?
        .min(DNS_PAYLOAD_LEN);
    let payload = &event.payload[..payload_size];
    let is_response = match event.event_type {
        EVENT_DNS_QUERY => false,
        EVENT_DNS_RESPONSE => true,
        _ => return None,
    };
    let protocol = match event.protocol {
        IPPROTO_TCP => TransportProtocol::Tcp,
        IPPROTO_UDP => TransportProtocol::Udp,
        _ => return None,
    };
    let dns = parse_dns_message(payload, is_response)?;
    let kind = if is_response {
        EventKind::DnsResponse
    } else {
        EventKind::DnsQuery
    };
    Some(TraceEvent::dns_event_with_data(
        EventSource::Kernel,
        kind,
        event.pid,
        DnsEventData {
            protocol,
            domain: dns.domain,
            addresses: dns.addresses,
            ttl_secs: dns.ttl_secs,
        },
        event.timestamp_ns,
    ))
}

fn decode_file_event(data: &[u8]) -> Option<TraceEvent> {
    let event = read_unaligned::<KernelFileEvent>(data)?;
    if event.pid == 0 {
        return None;
    }
    let path = bytes_to_string(&event.path)?;
    let kind = match event.event_type {
        EVENT_FILE_OPEN => EventKind::FileOpen,
        EVENT_FILE_READ => EventKind::FileRead,
        _ => return None,
    };
    Some(TraceEvent::file_event(
        EventSource::Kernel,
        kind,
        event.pid,
        FileEventData {
            path,
            bytes: event.bytes,
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
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_process_ref(pid: u32, timestamp_ns: u64) -> Option<ProcessRef> {
    let executable = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let command_line = read_command_line(pid);
    if executable.is_none() && command_line.is_none() {
        return None;
    }
    Some(ProcessRef {
        pid,
        ppid: read_parent_pid(pid),
        executable,
        command_line,
        start_time_ns: Some(timestamp_ns),
    })
}

fn read_command_line(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command_line = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    (!command_line.is_empty()).then_some(command_line)
}

fn read_parent_pid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("PPid:")
            .and_then(|value| value.trim().parse().ok())
    })
}

fn decode_address(family: u16, address: [u8; ADDR_LEN]) -> Option<IpAddr> {
    match family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        ))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address))),
        _ => None,
    }
}

fn coarse_connection_state(state: Option<TcpState>) -> ConnectionState {
    match state {
        Some(
            TcpState::Close
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::TimeWait
            | TcpState::CloseWait
            | TcpState::LastAck
            | TcpState::Closing,
        ) => ConnectionState::Closed,
        Some(TcpState::Established) => ConnectionState::Established,
        _ => ConnectionState::Connecting,
    }
}

fn tcp_state(value: u32) -> Option<TcpState> {
    Some(match value {
        1 => TcpState::Established,
        2 => TcpState::SynSent,
        3 => TcpState::SynRecv,
        4 => TcpState::FinWait1,
        5 => TcpState::FinWait2,
        6 => TcpState::TimeWait,
        7 => TcpState::Close,
        8 => TcpState::CloseWait,
        9 => TcpState::LastAck,
        10 => TcpState::Listen,
        11 => TcpState::Closing,
        12 => TcpState::NewSynRecv,
        _ => return None,
    })
}

struct ParsedDns {
    domain: String,
    addresses: Vec<String>,
    ttl_secs: u32,
}

fn parse_dns_message(data: &[u8], is_response: bool) -> Option<ParsedDns> {
    if data.len() < 12 {
        return None;
    }
    let flags = read_u16(data, 2)?;
    if ((flags & 0x8000) != 0) != is_response {
        return None;
    }
    let question_count = usize::from(read_u16(data, 4)?);
    if question_count == 0 {
        return None;
    }
    let mut offset = 12;
    let (domain, next) = read_dns_name(data, offset)?;
    offset = next;
    offset = offset.checked_add(4)?;
    if offset > data.len() {
        return None;
    }

    if !is_response {
        return Some(ParsedDns {
            domain,
            addresses: Vec::new(),
            ttl_secs: 0,
        });
    }

    for _ in 1..question_count {
        let (_, next) = read_dns_name(data, offset)?;
        offset = next.checked_add(4)?;
        if offset > data.len() {
            return None;
        }
    }

    let answer_count = usize::from(read_u16(data, 6)?);
    let mut addresses = Vec::new();
    let mut ttl_secs = u32::MAX;
    for _ in 0..answer_count {
        let (_, next) = read_dns_name(data, offset)?;
        offset = next;
        let record_type = read_u16(data, offset)?;
        let record_class = read_u16(data, offset.checked_add(2)?)?;
        let record_ttl = read_u32(data, offset.checked_add(4)?)?;
        let record_length = usize::from(read_u16(data, offset.checked_add(8)?)?);
        let record_data = offset.checked_add(10)?;
        let record_end = record_data.checked_add(record_length)?;
        if record_end > data.len() {
            return None;
        }
        if record_class == 1 && record_type == 1 && record_length == 4 {
            ttl_secs = ttl_secs.min(record_ttl);
            addresses.push(
                Ipv4Addr::new(
                    data[record_data],
                    data[record_data + 1],
                    data[record_data + 2],
                    data[record_data + 3],
                )
                .to_string(),
            );
        } else if record_class == 1 && record_type == 28 && record_length == 16 {
            ttl_secs = ttl_secs.min(record_ttl);
            let mut address = [0_u8; 16];
            address.copy_from_slice(&data[record_data..record_end]);
            addresses.push(Ipv6Addr::from(address).to_string());
        }
        offset = record_end;
    }
    Some(ParsedDns {
        domain,
        addresses,
        ttl_secs: if ttl_secs == u32::MAX { 0 } else { ttl_secs },
    })
}

fn read_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut cursor = offset;
    let mut next_offset = offset;
    let mut jumped = false;
    let mut labels = Vec::new();
    for _ in 0..128 {
        let length = *data.get(cursor)?;
        if length == 0 {
            if !jumped {
                next_offset = cursor.checked_add(1)?;
            }
            return Some((labels.join("."), next_offset));
        }
        if length & 0xc0 == 0xc0 {
            let pointer_low = *data.get(cursor.checked_add(1)?)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(pointer_low);
            if !jumped {
                next_offset = cursor.checked_add(2)?;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }
        let label_length = usize::from(length);
        let label_start = cursor.checked_add(1)?;
        let label_end = label_start.checked_add(label_length)?;
        let label = data.get(label_start..label_end)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        cursor = label_end;
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset.checked_add(1)?)?,
    ]))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset.checked_add(1)?)?,
        *data.get(offset.checked_add(2)?)?,
        *data.get(offset.checked_add(3)?)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::{
        decode_address, is_dns_dependency_name, kernel_capture_config, parse_dns_message,
        KernelDnsEvent, KernelNetworkEvent, KernelProcessEvent, KernelRuntimeController,
        KernelRuntimeState, CONNECTION_PROGRAMS, FILE_PROGRAMS, PROCESS_PROGRAMS, SCOPE_COMM,
        SCOPE_GLOBAL, SCOPE_PID, TRAFFIC_PROGRAMS,
    };
    use crate::capture::{CaptureFeatures, CaptureModule, CaptureProfile};
    use crate::config::CoreConfig;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::sync::mpsc;

    #[test]
    fn event_layout_matches_c_abi() {
        assert_eq!(std::mem::size_of::<KernelProcessEvent>(), 32);
        assert_eq!(std::mem::size_of::<KernelNetworkEvent>(), 88);
        assert_eq!(std::mem::size_of::<KernelDnsEvent>(), 544);
    }

    #[test]
    fn ipv4_address_is_decoded_from_network_bytes() {
        let mut address = [0; 16];
        address[..4].copy_from_slice(&[93, 184, 216, 34]);
        assert_eq!(
            decode_address(2, address),
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
    }

    #[test]
    fn dns_response_extracts_ipv4_answer() {
        let packet = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x5d,
            0xb8, 0xd8, 0x22,
        ];
        let parsed = parse_dns_message(&packet, true).expect("valid DNS response");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.addresses, vec!["93.184.216.34"]);
        assert_eq!(parsed.ttl_secs, 60);
    }

    #[test]
    fn profile_program_counts_match_the_modular_link_budget() {
        let count = |features: CaptureFeatures| {
            usize::from(features.contains(CaptureModule::Process)) * PROCESS_PROGRAMS.len()
                + usize::from(features.contains(CaptureModule::Connections))
                    * CONNECTION_PROGRAMS.len()
                + usize::from(
                    features.contains(CaptureModule::Traffic)
                        || features.contains(CaptureModule::Dns),
                ) * TRAFFIC_PROGRAMS.len()
                + usize::from(features.contains(CaptureModule::Files)) * FILE_PROGRAMS.len()
        };

        assert_eq!(count(CaptureProfile::Process.features()), 2);
        assert_eq!(count(CaptureProfile::Connections.features()), 6);
        assert_eq!(count(CaptureProfile::Network.features()), 18);
        assert_eq!(count(CaptureProfile::Security.features()), 19);
        assert!(TRAFFIC_PROGRAMS
            .iter()
            .all(|program| !program.starts_with("tracelens_dns_")));
    }

    #[test]
    fn capture_scope_is_encoded_for_bpf_maps() {
        let global = kernel_capture_config(&crate::CaptureScope::Global);
        assert_eq!(global.scope_mode, SCOPE_GLOBAL);

        let pid = kernel_capture_config(&crate::CaptureScope::Process(4242));
        assert_eq!(pid.scope_mode, SCOPE_PID);
        assert_eq!(pid.target_pid, 4242);

        let name = kernel_capture_config(&crate::CaptureScope::ProcessName(
            "very-long-process-name".to_owned(),
        ));
        assert_eq!(name.scope_mode, SCOPE_COMM);
        assert_eq!(&name.target_comm[..15], b"very-long-proce");
        assert_eq!(name.target_comm[15], 0);
    }

    #[test]
    fn only_known_dns_resolvers_are_scope_dependencies() {
        assert!(is_dns_dependency_name("systemd-resolve"));
        assert!(is_dns_dependency_name("dnsmasq"));
        assert!(!is_dns_dependency_name("curl"));
    }

    #[test]
    fn controller_reports_attach_failure_and_can_return_to_idle() {
        let (sender, _receiver) = mpsc::channel();
        let config = CoreConfig {
            bpf_object_dir: PathBuf::from("definitely-missing-bpf-objects"),
            ..CoreConfig::default()
        };
        let runtime = KernelRuntimeController::spawn(config, sender);

        assert_eq!(runtime.status().state, KernelRuntimeState::Idle);
        assert!(runtime
            .apply_plan(
                CaptureProfile::Process.features(),
                crate::CaptureScope::Global,
            )
            .is_err());
        assert_eq!(runtime.status().state, KernelRuntimeState::Failed);
        let stopped = runtime.stop().expect("stop failed runtime");
        assert_eq!(stopped.state, KernelRuntimeState::Idle);
        assert_eq!(stopped.link_count, 0);
        runtime.shutdown();
    }
}
