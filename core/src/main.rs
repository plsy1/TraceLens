use std::env;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tracelens_core::{config::CliOptions, Core};

// Global Web capture can briefly burst while provider discovery starts helper
// processes. Keep enough bounded headroom for that startup burst without
// returning to the unbounded memory growth of the old channel.
const EVENT_QUEUE_CAPACITY: usize = 2_048;
const EVENT_BATCH_LIMIT: usize = 2_048;

fn main() {
    let options = CliOptions::from_args(env::args().skip(1));

    if options.help {
        print_help();
        return;
    }

    if options.desktop_child {
        configure_desktop_lifetime();
    }

    if options.observe {
        run_observer(options);
        return;
    }

    let core = Core::new(options.config);
    let runtime = core.runtime_status();

    println!("TraceLens core {}", env!("CARGO_PKG_VERSION"));
    println!("Kernel observation: {}", runtime.kernel_observation);
    println!("Userspace runtime: {}", runtime.userspace_runtime);
    println!("Status: framework initialized; probes are not attached yet");

    if options.print_example_event {
        let event = Core::example_event();
        match serde_json::to_string_pretty(&event) {
            Ok(json) => println!("{json}"),
            Err(error) => eprintln!("failed to encode example event: {error}"),
        }
    }
}

fn print_help() {
    println!(
        "TraceLens core\n\n\
         Usage: tracelens-core [OPTIONS]\n\n\
         Options:\n\
           --config <PATH>          Select a configuration file (reserved)\n\
           --observe                Load kernel probes and serve the capture API (starts idle)\n\
           --desktop-child          Stop automatically when the desktop parent exits\n\
           --api-listen <ADDR>      API listen address (default: 127.0.0.1:8080)\n\
           --bpf-object-dir <PATH>  Directory containing compiled BPF objects\n\
           --storage <MODE>         Event storage: memory (default) or sqlite\n\
           --database <PATH>        Enable SQLite history at PATH\n\
           --memory-event-limit N   Maximum events retained in memory (default: 50000)\n\
           --print-example-event   Print the shared event schema as JSON\n\
           -h, --help              Show this help\n"
    );
}

#[cfg(target_os = "linux")]
fn configure_desktop_lifetime() {
    // pkexec preserves the desktop process as the parent of the elevated Core.
    // Ask the kernel to terminate Core if the GUI crashes or exits without
    // running its normal cleanup path, so uprobe links cannot be orphaned.
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
    }
    if unsafe { libc::getppid() } == 1 {
        std::process::exit(0);
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_desktop_lifetime() {}

fn run_observer(options: CliOptions) {
    let config = options.config;
    let core = match Core::open(config.clone()) {
        Ok(mut core) => {
            // The observer process starts as an armed tool, not an always-on
            // dashboard. Kernel probes remain detached until Start.
            core.enable_observer_capture_mode();
            core.stop_capture();
            Arc::new(Mutex::new(core))
        }
        Err(error) => {
            eprintln!("failed to initialize TraceLens storage: {error}");
            return;
        }
    };
    let (sender, receiver) = tracelens_core::runtime::event_channel(EVENT_QUEUE_CAPACITY);

    if let Ok(mut core) = core.lock() {
        core.set_probe_event_sender(sender.clone());
        core.set_kernel_runtime(
            tracelens_core::runtime::kernel::KernelRuntimeController::spawn(config.clone(), sender),
        );
    }

    let api_core = Arc::clone(&core);
    let api_listen = options.api_listen;
    thread::spawn(move || {
        if let Err(error) = tracelens_core::api::server::serve(api_core, api_listen) {
            eprintln!("API server stopped: {error}");
        }
    });

    println!("TraceLens core observer started");
    println!("BPF object directory: {}", config.bpf_object_dir.display());
    println!("API: http://{api_listen}");

    let mut last_userspace_refresh = Instant::now();
    loop {
        let mut events = Vec::with_capacity(EVENT_BATCH_LIMIT);
        match receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(first_event) => {
                events.push(first_event);
                events.extend(receiver.try_iter().take(EVENT_BATCH_LIMIT - 1));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if let Ok(mut core) = core.lock() {
            for event in events {
                core.ingest_event(event);
            }
            if last_userspace_refresh.elapsed() >= Duration::from_secs(2) {
                core.refresh_userspace_probes();
                last_userspace_refresh = Instant::now();
            }
        }
    }
}
