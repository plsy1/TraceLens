use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObservationTarget {
    Process(u32),
    ProcessName(String),
    Connection(String),
    Domain(String),
}

impl fmt::Display for ObservationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process(pid) => write!(formatter, "process:{pid}"),
            Self::ProcessName(name) => write!(formatter, "process-name:{name}"),
            Self::Connection(id) => write!(formatter, "connection:{id}"),
            Self::Domain(domain) => write!(formatter, "domain:{domain}"),
        }
    }
}

impl FromStr for ObservationTarget {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (kind, identifier) = value.split_once(':').ok_or_else(|| {
            "target must use process:<pid>, process-name:<name>, connection:<id>, or domain:<name>"
                .to_owned()
        })?;
        if identifier.is_empty() {
            return Err("observation target identifier cannot be empty".to_owned());
        }
        match kind {
            "process" => {
                let pid = identifier
                    .parse::<u32>()
                    .map_err(|_| "process target PID must be a positive integer".to_owned())?;
                (pid > 0)
                    .then_some(Self::Process(pid))
                    .ok_or_else(|| "process target PID must be a positive integer".to_owned())
            }
            "process-name" => Ok(Self::ProcessName(identifier.to_owned())),
            "connection" => Ok(Self::Connection(identifier.to_owned())),
            "domain" => Ok(Self::Domain(identifier.to_owned())),
            _ => Err(format!("unsupported observation target kind: {kind}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationRequest {
    pub target: ObservationTarget,
    pub level: super::ObservationLevel,
    pub duration_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::ObservationTarget;
    use std::str::FromStr;

    #[test]
    fn parses_process_name_targets() {
        let target = ObservationTarget::from_str("process-name:curl").expect("target");
        assert_eq!(target, ObservationTarget::ProcessName("curl".to_owned()));
        assert_eq!(target.to_string(), "process-name:curl");
    }
}
