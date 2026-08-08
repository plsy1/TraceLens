//! Load one TraceLens userspace BPF object and keep its uprobe link alive.
//!
//! This binary is intentionally small. `bpftime trace` runs it with the
//! bpftime syscall-server preload, so the normal libbpf object and uprobe
//! calls are redirected into bpftime's userspace runtime.

use std::env;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder, UprobeOpts};
use tracelens_events::{
    EventSource, PlaintextDirection, PlaintextEventData, TlsEventData, TraceEvent,
};

#[derive(Debug)]
struct Options {
    pid: u32,
    object: PathBuf,
    library: PathBuf,
    function: String,
    program: String,
    retprobe: bool,
    companion_program: Option<String>,
    companion_retprobe: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("tracelens-bpftime-loader: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = Options::from_args(env::args().skip(1))?;
    let mut builder = ObjectBuilder::default();
    let open_object = builder
        .open_file(&options.object)
        .map_err(|error| format!("failed to open {}: {error}", options.object.display()))?;
    let mut object = open_object
        .load()
        .map_err(|error| format!("failed to load {}: {error}", options.object.display()))?;
    let attach_program = |object: &mut libbpf_rs::Object, program_name: &str, retprobe: bool| {
        let program = object
            .progs_mut()
            .find(|program| program.name() == OsStr::new(program_name))
            .ok_or_else(|| {
                format!(
                    "program `{program_name}` is missing from {}",
                    options.object.display()
                )
            })?;
        program
            .attach_uprobe_with_opts(
                options.pid as i32,
                &options.library,
                0,
                UprobeOpts {
                    func_name: Some(options.function.clone()),
                    retprobe,
                    ..Default::default()
                },
            )
            .map_err(|error| {
                format!(
                    "failed to attach {} to {} for pid {}: {error}",
                    options.function,
                    options.library.display(),
                    options.pid
                )
            })
    };
    let mut _links = vec![attach_program(
        &mut object,
        &options.program,
        options.retprobe,
    )?];
    if let Some(companion_program) = options.companion_program.as_deref() {
        _links.push(attach_program(
            &mut object,
            companion_program,
            options.companion_retprobe,
        )?);
    }

    if let Some(events) = object.maps().find(|map| map.name() == OsStr::new("events")) {
        let mut ring_buffer_builder = RingBufferBuilder::new();
        ring_buffer_builder
            .add(&events, |data| {
                if let Some(event) = decode_userspace_event(data, EventSource::Bpftime) {
                    if let Ok(json) = serde_json::to_string(&event) {
                        println!("{json}");
                        let _ = io::stdout().flush();
                    }
                }
                0
            })
            .map_err(|error| format!("failed to register event ring buffer: {error}"))?;
        let ring_buffer = ring_buffer_builder
            .build()
            .map_err(|error| format!("failed to build event ring buffer: {error}"))?;

        eprintln!(
            "attached {} to {} for pid {}",
            options.function,
            options.library.display(),
            options.pid
        );
        loop {
            ring_buffer
                .poll(Duration::from_secs(1))
                .map_err(|error| format!("event ring buffer stopped: {error}"))?;
        }
    }

    eprintln!(
        "attached {} to {} for pid {}",
        options.function,
        options.library.display(),
        options.pid
    );
    loop {
        thread::park_timeout(Duration::from_secs(60));
    }
}

const EVENT_TLS_METADATA: u16 = 7;
const EVENT_PLAINTEXT: u16 = 8;
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
    let event_type = read_u16(data)?;
    match event_type {
        EVENT_TLS_METADATA => decode_tls_event(data, source),
        EVENT_PLAINTEXT => decode_plaintext_event(data, source),
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

fn read_u16(data: &[u8]) -> Option<u16> {
    if data.len() < std::mem::size_of::<u16>() {
        return None;
    }
    Some(u16::from_ne_bytes([data[0], data[1]]))
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

impl Options {
    fn from_args(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut pid = None;
        let mut object = None;
        let mut library = None;
        let mut function = None;
        let mut program = None;
        let mut retprobe = false;
        let mut companion_program = None;
        let mut companion_retprobe = false;
        while let Some(argument) = args.next() {
            let value = |name: &str, args: &mut dyn Iterator<Item = String>| {
                args.next()
                    .ok_or_else(|| format!("{name} requires a value"))
            };
            match argument.as_str() {
                "--pid" => {
                    pid = Some(
                        value("--pid", &mut args)?
                            .parse::<u32>()
                            .map_err(|_| "--pid must be a positive integer".to_owned())?,
                    )
                }
                "--object" => object = Some(PathBuf::from(value("--object", &mut args)?)),
                "--library" => library = Some(PathBuf::from(value("--library", &mut args)?)),
                "--function" => function = Some(value("--function", &mut args)?),
                "--program" => program = Some(value("--program", &mut args)?),
                "--retprobe" => retprobe = true,
                "--companion-program" => {
                    companion_program = Some(value("--companion-program", &mut args)?)
                }
                "--companion-retprobe" => companion_retprobe = true,
                "-h" | "--help" => {
                    println!("Usage: tracelens-bpftime-loader --pid PID --object PATH --library PATH --function SYMBOL --program NAME [--retprobe] [--companion-program NAME] [--companion-retprobe]");
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument `{unknown}`")),
            }
        }
        Ok(Self {
            pid: pid.ok_or_else(|| "--pid is required".to_owned())?,
            object: object.ok_or_else(|| "--object is required".to_owned())?,
            library: library.ok_or_else(|| "--library is required".to_owned())?,
            function: function.ok_or_else(|| "--function is required".to_owned())?,
            program: program.ok_or_else(|| "--program is required".to_owned())?,
            retprobe,
            companion_program,
            companion_retprobe,
        })
    }
}
