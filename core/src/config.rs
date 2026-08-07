use std::path::PathBuf;

use crate::observation::ObservationLevel;

#[derive(Debug, Clone)]
pub struct CoreConfig {
    pub default_observation_level: ObservationLevel,
    pub deep_inspection_timeout_secs: u64,
    pub database: PathBuf,
    pub preferred_userspace_runtime: String,
    pub plaintext_storage: String,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            default_observation_level: ObservationLevel::L1,
            deep_inspection_timeout_secs: 300,
            database: PathBuf::from("tracelens.db"),
            preferred_userspace_runtime: "bpftime".to_owned(),
            plaintext_storage: "memory".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct CliOptions {
    pub config: CoreConfig,
    pub print_example_event: bool,
    pub help: bool,
}

impl CliOptions {
    pub fn from_args<I>(args: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let config = CoreConfig::default();
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
                "--print-example-event" => print_example_event = true,
                "-h" | "--help" => help = true,
                unknown => eprintln!("warning: ignoring unknown option: {unknown}"),
            }
        }

        Self {
            config,
            print_example_event,
            help,
        }
    }
}
