use std::env;

use tracelens_core::{config::CliOptions, Core};

fn main() {
    let options = CliOptions::from_args(env::args().skip(1));

    if options.help {
        print_help();
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
           --print-example-event   Print the shared event schema as JSON\n\
           -h, --help              Show this help\n"
    );
}
