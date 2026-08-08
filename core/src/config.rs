use std::path::PathBuf;

use crate::observation::ObservationLevel;

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub default_observation_level: ObservationLevel,
    pub deep_inspection_timeout_secs: u64,
    pub database: PathBuf,
    pub bpf_object_dir: PathBuf,
    pub preferred_userspace_runtime: String,
    pub plaintext_storage: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            default_observation_level: ObservationLevel::L1,
            deep_inspection_timeout_secs: 300,
            database: PathBuf::from("tracelens.db"),
            bpf_object_dir: PathBuf::from("build/bpf/objects"),
            preferred_userspace_runtime: "bpftime".to_owned(),
            plaintext_storage: "memory".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct CliOptions {
    pub config: CoreConfig,
    pub api_listen: std::net::SocketAddr,
    pub observe: bool,
    pub print_example_event: bool,
    pub help: bool,
}

impl CliOptions {
    pub fn from_args<I>(args: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut config = CoreConfig::default();
        let mut api_listen = "127.0.0.1:8080"
            .parse()
            .expect("the default API address must be valid");
        let mut observe = false;
        let mut print_example_event = false;
        let mut help = false;
        let mut args = args.into_iter();

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--config" => {
                    // TOML loading is intentionally deferred until the config
                    // contract stabilizes. Keep the option in the CLI now.
                    let _ = args.next();
                }
                "--api-listen" => {
                    if let Some(value) = args.next() {
                        match value.parse() {
                            Ok(address) => api_listen = address,
                            Err(error) => {
                                eprintln!("warning: invalid API address `{value}`: {error}")
                            }
                        }
                    } else {
                        eprintln!("warning: --api-listen requires an address");
                    }
                }
                "--bpf-object-dir" => {
                    if let Some(value) = args.next() {
                        config.bpf_object_dir = PathBuf::from(value);
                    } else {
                        eprintln!("warning: --bpf-object-dir requires a path");
                    }
                }
                "--observe" => observe = true,
                "--print-example-event" => print_example_event = true,
                "-h" | "--help" => help = true,
                unknown => eprintln!("warning: ignoring unknown option: {unknown}"),
            }
        }

        Self {
            config,
            api_listen,
            observe,
            print_example_event,
            help,
        }
    }
}
