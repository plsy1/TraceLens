//! Kernel eBPF runtime and ring-buffer event decoder.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::Duration;
use std::{net::IpAddr, net::Ipv4Addr, net::Ipv6Addr};

use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, RingBufferBuilder};
use tracelens_events::{
    ConnectionRef, ConnectionState, DnsEventData, Endpoint, EventKind, EventSource, FileEventData,
    ProcessRef, TcpState, TraceEvent, TransportProtocol,
};

use crate::config::CoreConfig;

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

    /// Load the process/network/DNS objects, attach their tracepoints, and forward events.
    pub fn run(config: &CoreConfig, sender: Sender<TraceEvent>) -> Result<(), String> {
        let process_path = config.bpf_object_dir.join("process.o");
        let network_path = config.bpf_object_dir.join("network.o");
        let dns_path = config.bpf_object_dir.join("dns.o");
        let file_path = config.bpf_object_dir.join("file.o");
        ensure_object_exists(&process_path)?;
        ensure_object_exists(&network_path)?;
        ensure_object_exists(&dns_path)?;
        ensure_object_exists(&file_path)?;

        let mut process_object = load_object(&process_path)?;
        let mut network_object = load_object(&network_path)?;
        let mut dns_object = load_object(&dns_path)?;
        let mut file_object = load_object(&file_path)?;

        let _process_exec_link = attach_program(&mut process_object, "tracelens_process_exec")?;
        let _process_exit_link = attach_program(&mut process_object, "tracelens_process_exit")?;
        let _connect_link = attach_program(&mut network_object, "tracelens_connect")?;
        let _connect_exit_link = attach_program(&mut network_object, "tracelens_connect_exit")?;
        let _close_link = attach_program(&mut network_object, "tracelens_close")?;
        let _tcp_state_link = attach_program(&mut network_object, "tracelens_tcp_state")?;
        let _sendto_enter_link = attach_program(&mut network_object, "tracelens_sendto_enter")?;
        let _sendto_exit_link = attach_program(&mut network_object, "tracelens_sendto_exit")?;
        let _recvfrom_enter_link = attach_program(&mut network_object, "tracelens_recvfrom_enter")?;
        let _recvfrom_exit_link = attach_program(&mut network_object, "tracelens_recvfrom_exit")?;
        let _sendmsg_enter_link = attach_program(&mut network_object, "tracelens_sendmsg_enter")?;
        let _sendmsg_exit_link = attach_program(&mut network_object, "tracelens_sendmsg_exit")?;
        let _recvmsg_enter_link = attach_program(&mut network_object, "tracelens_recvmsg_enter")?;
        let _recvmsg_exit_link = attach_program(&mut network_object, "tracelens_recvmsg_exit")?;
        let _write_enter_link = attach_program(&mut network_object, "tracelens_write_enter")?;
        let _write_exit_link = attach_program(&mut network_object, "tracelens_write_exit")?;
        let _read_enter_link = attach_program(&mut network_object, "tracelens_read_enter")?;
        let _read_exit_link = attach_program(&mut network_object, "tracelens_read_exit")?;
        let _dns_send_link = attach_program(&mut dns_object, "tracelens_dns_send")?;
        let _dns_connect_enter_link =
            attach_program(&mut dns_object, "tracelens_dns_connect_enter")?;
        let _dns_connect_exit_link = attach_program(&mut dns_object, "tracelens_dns_connect_exit")?;
        let _dns_recv_enter_link = attach_program(&mut dns_object, "tracelens_dns_recv_enter")?;
        let _dns_recv_exit_link = attach_program(&mut dns_object, "tracelens_dns_recv_exit")?;
        let _dns_sendmsg_link = attach_program(&mut dns_object, "tracelens_dns_sendmsg")?;
        let _dns_recvmsg_link = attach_program(&mut dns_object, "tracelens_dns_recvmsg")?;
        let _dns_recvmsg_exit_link = attach_program(&mut dns_object, "tracelens_dns_recvmsg_exit")?;
        let _dns_write_link = attach_program(&mut dns_object, "tracelens_dns_write")?;
        let _dns_read_link = attach_program(&mut dns_object, "tracelens_dns_read")?;
        let _dns_read_exit_link = attach_program(&mut dns_object, "tracelens_dns_read_exit")?;
        let _dns_close_link = attach_program(&mut dns_object, "tracelens_dns_close")?;
        let _file_open_link = attach_program(&mut file_object, "tracelens_file_open")?;

        let process_events = find_map(&process_object, "events")?;
        let network_events = find_map(&network_object, "events")?;
        let dns_events = find_map(&dns_object, "events")?;
        let file_events = find_map(&file_object, "events")?;
        let process_sender = sender.clone();
        let network_sender = sender.clone();
        let dns_sender = sender;
        let file_sender = dns_sender.clone();

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
        ring_buffer_builder
            .add(&dns_events, move |data| {
                if let Some(event) = decode_dns_event(data) {
                    let _ = dns_sender.send(event);
                }
                0
            })
            .map_err(|error| format!("failed to register DNS ring buffer: {error}"))?;
        ring_buffer_builder
            .add(&file_events, move |data| {
                if let Some(event) = decode_file_event(data) {
                    let _ = file_sender.send(event);
                }
                0
            })
            .map_err(|error| format!("failed to register file ring buffer: {error}"))?;

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
        read_process_ref(event.pid, event.timestamp_ns),
        connection,
        event.timestamp_ns,
    ))
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
        decode_address, parse_dns_message, KernelDnsEvent, KernelNetworkEvent, KernelProcessEvent,
    };
    use std::net::{IpAddr, Ipv4Addr};

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
}
