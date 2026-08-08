use std::env;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

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
           --observe                Attach Phase 2/3 kernel probes and serve the local API\n\
           --api-listen <ADDR>      API listen address (default: 127.0.0.1:8080)\n\
           --bpf-object-dir <PATH>  Directory containing compiled BPF objects\n\
           --print-example-event   Print the shared event schema as JSON\n\
           -h, --help              Show this help\n"
    );
}

fn run_observer(options: CliOptions) {
    let config = options.config;
    let core = Arc::new(Mutex::new(Core::new(config.clone())));
    let (sender, receiver) = mpsc::channel();

    let observer_config = config.clone();
    thread::spawn(move || {
        if let Err(error) =
            tracelens_core::runtime::kernel::KernelRuntime::run(&observer_config, sender)
        {
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

    for event in receiver {
        if let Ok(mut core) = core.lock() {
            core.ingest_event(event);
        }
    }
}
