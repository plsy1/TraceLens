//! In-memory behavior graph read model.
//!
//! The graph is deliberately rebuilt from the live trackers on request. This
//! keeps the default memory-only mode cheap and avoids introducing a second
//! persistence layer for a view that is derived from events.

use std::collections::BTreeMap;

use serde::Serialize;
use tracelens_events::{EventKind, EventPayload};

use crate::{detection::RiskScore, storage::EventQuery, Core};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeKind {
    Process,
    Domain,
    Connection,
    File,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GraphNode {
    pub id: String,
    pub kind: GraphNodeKind,
    pub label: String,
    pub risk_score: RiskScore,
    pub pid: Option<u32>,
    pub connection_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub relation: String,
    pub event_count: usize,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BehaviorGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub updated_at_ns: u64,
}

pub fn build(core: &Core) -> BehaviorGraph {
    let mut nodes = BTreeMap::<String, GraphNode>::new();
    let mut edges = BTreeMap::<String, GraphEdge>::new();
    let mut updated_at_ns = 0;

    for record in core.processes().all() {
        updated_at_ns = updated_at_ns.max(record.last_seen_ns);
        let process = &record.identity;
        let id = process_id(process.pid);
        insert_node(
            &mut nodes,
            GraphNode {
                id: id.clone(),
                kind: GraphNodeKind::Process,
                label: process
                    .executable
                    .clone()
                    .unwrap_or_else(|| format!("pid {}", process.pid)),
                risk_score: core.risk_score_for_process(process.pid),
                pid: Some(process.pid),
                connection_id: None,
                metadata: process_metadata(process),
            },
        );
        if let Some(ppid) = process.ppid {
            let parent_id = process_id(ppid);
            insert_node(
                &mut nodes,
                GraphNode {
                    id: parent_id.clone(),
                    kind: GraphNodeKind::Process,
                    label: format!("pid {ppid}"),
                    risk_score: core.risk_score_for_process(ppid),
                    pid: Some(ppid),
                    connection_id: None,
                    metadata: BTreeMap::new(),
                },
            );
            add_edge(
                &mut edges,
                &parent_id,
                &id,
                "spawned",
                record.first_seen_ns,
                record.last_seen_ns,
            );
        }
    }

    for record in core.connections().all() {
        updated_at_ns = updated_at_ns.max(record.last_seen_ns);
        let connection = &record.connection;
        let connection_id = format!("connection:{}", connection.id);
        let connection_label = connection
            .domain
            .clone()
            .unwrap_or_else(|| format!("{}:{}", connection.remote.address, connection.remote.port));
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "remote_address".to_owned(),
            connection.remote.address.clone(),
        );
        metadata.insert("remote_port".to_owned(), connection.remote.port.to_string());
        metadata.insert(
            "protocol".to_owned(),
            format!("{:?}", connection.protocol).to_lowercase(),
        );
        metadata.insert(
            "state".to_owned(),
            format!("{:?}", connection.state).to_lowercase(),
        );
        insert_node(
            &mut nodes,
            GraphNode {
                id: connection_id.clone(),
                kind: GraphNodeKind::Connection,
                label: connection_label,
                risk_score: core.risk_score_for_connection(&connection.id),
                pid: record.pid,
                connection_id: Some(connection.id.clone()),
                metadata,
            },
        );
        if let Some(pid) = record.pid {
            let process_node_id = process_id(pid);
            insert_placeholder_process(&mut nodes, process_node_id.clone(), pid, record);
            add_edge(
                &mut edges,
                &process_node_id,
                &connection_id,
                "opened",
                record.first_seen_ns,
                record.last_seen_ns,
            );
        }
        if let Some(domain) = connection.domain.as_deref() {
            let domain_id = domain_id(domain);
            insert_node(
                &mut nodes,
                GraphNode {
                    id: domain_id.clone(),
                    kind: GraphNodeKind::Domain,
                    label: domain.to_owned(),
                    risk_score: core
                        .alerts()
                        .iter()
                        .filter(|alert| alert.domain.as_deref() == Some(domain))
                        .map(|alert| alert.risk_score)
                        .max_by(|left, right| left.0.total_cmp(&right.0))
                        .unwrap_or(RiskScore(0.0)),
                    pid: record.pid,
                    connection_id: None,
                    metadata: BTreeMap::new(),
                },
            );
            add_edge(
                &mut edges,
                &connection_id,
                &domain_id,
                "resolved_to",
                record.first_seen_ns,
                record.last_seen_ns,
            );
        }
    }

    for kind in [EventKind::FileOpen, EventKind::FileRead] {
        let Ok(page) = core.store().query(EventQuery {
            kind: Some(kind),
            limit: 200,
            ..EventQuery::default()
        }) else {
            continue;
        };
        for event in page.events {
            updated_at_ns = updated_at_ns.max(event.timestamp_ns);
            let EventPayload::File { path, bytes } = event.payload else {
                continue;
            };
            if !is_security_relevant_file(&path) {
                continue;
            }
            let file_id = file_id(&path);
            let mut metadata = BTreeMap::new();
            metadata.insert("path".to_owned(), path.clone());
            metadata.insert("bytes".to_owned(), bytes.to_string());
            insert_node(
                &mut nodes,
                GraphNode {
                    id: file_id.clone(),
                    kind: GraphNodeKind::File,
                    label: path,
                    risk_score: RiskScore(0.0),
                    pid: event.pid,
                    connection_id: None,
                    metadata,
                },
            );
            if let Some(pid) = event.pid {
                let process_node_id = process_id(pid);
                insert_placeholder_process_by_pid(&mut nodes, process_node_id.clone(), pid, core);
                let relation = if event.kind == EventKind::FileRead {
                    "read"
                } else {
                    "opened"
                };
                add_edge(
                    &mut edges,
                    &process_node_id,
                    &file_id,
                    relation,
                    event.timestamp_ns,
                    event.timestamp_ns,
                );
            }
        }
    }

    BehaviorGraph {
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
        updated_at_ns,
    }
}

fn insert_node(nodes: &mut BTreeMap<String, GraphNode>, node: GraphNode) {
    if let Some(existing) = nodes.get_mut(&node.id) {
        if node.risk_score.0 > existing.risk_score.0 {
            existing.risk_score = node.risk_score;
        }
        if existing.label.starts_with("pid ") && !node.label.starts_with("pid ") {
            existing.label = node.label;
        }
        existing.metadata.extend(node.metadata);
    } else {
        nodes.insert(node.id.clone(), node);
    }
}

fn insert_placeholder_process(
    nodes: &mut BTreeMap<String, GraphNode>,
    id: String,
    pid: u32,
    record: &crate::network::ConnectionRecord,
) {
    insert_node(
        nodes,
        GraphNode {
            id,
            kind: GraphNodeKind::Process,
            label: record
                .process
                .as_ref()
                .and_then(|process| process.executable.clone())
                .unwrap_or_else(|| format!("pid {pid}")),
            risk_score: RiskScore(0.0),
            pid: Some(pid),
            connection_id: None,
            metadata: BTreeMap::new(),
        },
    );
}

fn insert_placeholder_process_by_pid(
    nodes: &mut BTreeMap<String, GraphNode>,
    id: String,
    pid: u32,
    core: &Core,
) {
    let label = core
        .processes()
        .get(pid)
        .and_then(|record| record.identity.executable.clone())
        .unwrap_or_else(|| format!("pid {pid}"));
    insert_node(
        nodes,
        GraphNode {
            id,
            kind: GraphNodeKind::Process,
            label,
            risk_score: core.risk_score_for_process(pid),
            pid: Some(pid),
            connection_id: None,
            metadata: BTreeMap::new(),
        },
    );
}

fn add_edge(
    edges: &mut BTreeMap<String, GraphEdge>,
    source: &str,
    target: &str,
    relation: &str,
    first_seen_ns: u64,
    last_seen_ns: u64,
) {
    let id = format!("{source}|{relation}|{target}");
    if let Some(edge) = edges.get_mut(&id) {
        edge.event_count = edge.event_count.saturating_add(1);
        edge.first_seen_ns = edge.first_seen_ns.min(first_seen_ns);
        edge.last_seen_ns = edge.last_seen_ns.max(last_seen_ns);
    } else {
        edges.insert(
            id.clone(),
            GraphEdge {
                id,
                source: source.to_owned(),
                target: target.to_owned(),
                relation: relation.to_owned(),
                event_count: 1,
                first_seen_ns,
                last_seen_ns,
            },
        );
    }
}

fn process_metadata(process: &tracelens_events::ProcessRef) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    if let Some(command_line) = &process.command_line {
        metadata.insert("command_line".to_owned(), command_line.clone());
    }
    if let Some(ppid) = process.ppid {
        metadata.insert("ppid".to_owned(), ppid.to_string());
    }
    metadata
}

fn process_id(pid: u32) -> String {
    format!("process:{pid}")
}

fn domain_id(domain: &str) -> String {
    format!("domain:{domain}")
}

fn file_id(path: &str) -> String {
    format!("file:{path}")
}

fn is_security_relevant_file(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    if [
        "/proc/",
        "/sys/",
        "/dev/",
        "/usr/",
        "/lib/",
        "/run/",
        "/var/lib/",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
    {
        return false;
    }
    [
        "/etc/shadow",
        "/etc/passwd",
        "/.ssh/",
        "id_rsa",
        "id_ed25519",
        "credentials",
        "token",
        "secret",
        "/.aws/",
    ]
    .iter()
    .any(|marker| path.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::{build, GraphNodeKind};
    use crate::{config::CoreConfig, Core};
    use tracelens_events::{EventKind, EventSource, FileEventData, TraceEvent};

    #[test]
    fn builds_process_and_file_relationships() {
        let mut core = Core::new(CoreConfig::default());
        core.ingest_event(TraceEvent::process_exec(7, "python3", "python3 app.py", 1));
        core.ingest_event(TraceEvent::file_event(
            EventSource::Kernel,
            EventKind::FileOpen,
            7,
            FileEventData {
                path: "/home/user/.ssh/id_rsa".to_owned(),
                bytes: 0,
            },
            2,
        ));

        let graph = build(&core);
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.kind == GraphNodeKind::Process));
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.kind == GraphNodeKind::File));
        assert!(graph.edges.iter().any(|edge| edge.relation == "opened"));
    }
}
