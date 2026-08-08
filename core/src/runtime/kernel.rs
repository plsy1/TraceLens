//! Kernel eBPF runtime and ring-buffer event decoder.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::{net::IpAddr, net::Ipv4Addr, net::Ipv6Addr};

use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, RingBufferBuilder};
use tracelens_events::{
    ConnectionRef, ConnectionState, Endpoint, EventKind, EventSource, TraceEvent, TransportProtocol,
};

use crate::config::CoreConfig;

const EVENT_PROCESS_EXEC: u16 = 1;
const EVENT_PROCESS_EXIT: u16 = 2;
const EVENT_TCP_CONNECT: u16 = 3;
const EVENT_TCP_CLOSE: u16 = 4;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const IPPROTO_TCP: u16 = 6;
const COMM_LEN: usize = 16;
const ADDR_LEN: usize = 16;

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
    local_addr: [u8; ADDR_LEN],
    remote_addr: [u8; ADDR_LEN],
    sent_bytes: u64,
    received_bytes: u64,
}

#[derive(Debug, Default)]
pub struct KernelRuntime {
    attached: bool,
}

impl KernelRuntime {
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    pub fn attach(&mut self) {
        self.attached = true;
    }

    pub fn detach(&mut self) {
        self.attached = false;
    }

    /// Load the Phase 2/3 objects, attach their tracepoints, and forward events.
    pub fn run(config: &CoreConfig, sender: Sender<TraceEvent>) -> Result<(), String> {
        let process_path = config.bpf_object_dir.join("process.o");
        let network_path = config.bpf_object_dir.join("network.o");
        ensure_object_exists(&process_path)?;
        ensure_object_exists(&network_path)?;

        let mut process_object = load_object(&process_path)?;
        let mut network_object = load_object(&network_path)?;

        let _process_exec_link = attach_program(&mut process_object, "tracelens_process_exec")?;
        let _process_exit_link = attach_program(&mut process_object, "tracelens_process_exit")?;
        let _connect_link = attach_program(&mut network_object, "tracelens_connect")?;
        let _connect_exit_link = attach_program(&mut network_object, "tracelens_connect_exit")?;
        let _close_link = attach_program(&mut network_object, "tracelens_close")?;

        let process_events = find_map(&process_object, "events")?;
        let network_events = find_map(&network_object, "events")?;
        let process_sender = sender.clone();
        let network_sender = sender;

        let mut ring_buffer_builder = RingBufferBuilder::new();
        ring_buffer_builder
            .add(&process_events, move |data| {
                if let Some(event) = decode_process_event(data) {
                    let _ = process_sender.send(event);
                }
                0
            })
            .map_err(|error| format!("failed to register process ring buffer: {error}"))?;
        ring_buffer_builder
            .add(&network_events, move |data| {
                if let Some(event) = decode_network_event(data) {
                    let _ = network_sender.send(event);
                }
                0
            })
            .map_err(|error| format!("failed to register network ring buffer: {error}"))?;

        let ring_buffer = ring_buffer_builder
            .build()
            .map_err(|error| format!("failed to build ring buffer: {error}"))?;

        loop {
            ring_buffer
                .poll(Duration::from_millis(500))
                .map_err(|error| format!("kernel ring buffer stopped: {error}"))?;
        }
    }
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

fn decode_network_event(data: &[u8]) -> Option<TraceEvent> {
    let event = read_unaligned::<KernelNetworkEvent>(data)?;
    let remote_address = decode_address(event.family, event.remote_addr)?;
    let local_address = decode_address(event.family, event.local_addr);
    let kind = match event.event_type {
        EVENT_TCP_CONNECT => EventKind::TcpConnect,
        EVENT_TCP_CLOSE => EventKind::TcpClose,
        _ => return None,
    };
    let state = if kind == EventKind::TcpClose {
        ConnectionState::Closed
    } else {
        ConnectionState::Established
    };
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
        sent_bytes: event.sent_bytes,
        received_bytes: event.received_bytes,
        domain: None,
    };

    Some(TraceEvent::connection_event(
        EventSource::Kernel,
        kind,
        event.pid,
        connection,
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

#[cfg(test)]
mod tests {
    use super::{decode_address, KernelNetworkEvent, KernelProcessEvent};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn event_layout_matches_c_abi() {
        assert_eq!(std::mem::size_of::<KernelProcessEvent>(), 32);
        assert_eq!(std::mem::size_of::<KernelNetworkEvent>(), 80);
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
}
