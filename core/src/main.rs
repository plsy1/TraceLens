use std::env;
use std::sync::{atomic::AtomicBool, mpsc, Arc, Mutex, TryLockError};
use std::thread;
use std::time::Duration;

use tracelens_core::{config::CliOptions, Core};

fn main() {
    let options = CliOptions::from_args(env::args().skip(1));

    if options.help {
        print_help();
        return;
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
           --api-listen <ADDR>      API listen address (default: 127.0.0.1:8080)\n\
           --bpf-object-dir <PATH>  Directory containing compiled BPF objects\n\
           --storage <MODE>         Event storage: memory (default) or sqlite\n\
           --database <PATH>        Enable SQLite history at PATH\n\
           --memory-event-limit N   Maximum events retained in memory (default: 50000)\n\
           --default-observation-level N  Baseline L1-L5 for all processes (default: 1)\n\
           --print-example-event   Print the shared event schema as JSON\n\
           -h, --help              Show this help\n"
    );
}

fn run_observer(options: CliOptions) {
    let config = options.config;
    let capture_gate = Arc::new(AtomicBool::new(false));
    let core = match Core::open(config.clone()) {
        Ok(mut core) => {
            // The observer process starts as an armed tool, not an always-on
            // dashboard. Kernel tracepoints may be loaded below, but Core
            // will discard their events until the UI presses Start.
            core.enable_observer_capture_mode();
            core.stop_capture();
            core.set_capture_gate(Arc::clone(&capture_gate));
            Arc::new(Mutex::new(core))
        }
        Err(error) => {
            eprintln!("failed to initialize TraceLens storage: {error}");
            return;
        }
    };
    let (sender, receiver) = mpsc::channel();

    if let Ok(mut core) = core.lock() {
        core.set_probe_event_sender(sender.clone());
    }

    let observer_config = config.clone();
    thread::spawn(move || {
        if let Err(error) = tracelens_core::runtime::kernel::KernelRuntime::run(
            &observer_config,
            sender,
            capture_gate,
        ) {
            eprintln!("kernel observer stopped: {error}");
        }
    });

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

    const EVENT_BATCH_LIMIT: usize = 256;
    while let Ok(first_event) = receiver.recv() {
        let mut events = Vec::with_capacity(EVENT_BATCH_LIMIT);
        events.push(first_event);
        events.extend(receiver.try_iter().take(EVENT_BATCH_LIMIT - 1));
        let core_guard = loop {
            match core.try_lock() {
                Ok(core) => break Some(core),
                Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(1)),
                Err(TryLockError::Poisoned(_)) => break None,
            }
        };
        if let Some(mut core) = core_guard {
            for event in events {
                core.ingest_event(event);
            }
        }
        thread::yield_now();
    }
}
