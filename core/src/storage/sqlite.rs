use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{types::ToSql, Connection};
use serde_json::to_string;
use tracelens_events::{EventKind, TraceEvent};

use super::schema;

pub const DEFAULT_MEMORY_EVENT_LIMIT: usize = 50_000;

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub pid: Option<u32>,
    pub kind: Option<EventKind>,
    pub connection_id: Option<String>,
    /// Number of newest matching events to skip before returning older rows.
    pub offset: usize,
    pub limit: usize,
}

#[derive(Debug, Clone, Default)]
pub struct EventPage {
    pub events: Vec<TraceEvent>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

#[derive(Debug)]
struct MemoryEvent {
    sequence: u64,
    event: TraceEvent,
}

#[derive(Debug, Default)]
struct MemoryState {
    next_sequence: u64,
    capacity: usize,
    events: VecDeque<MemoryEvent>,
}

#[derive(Debug, Clone)]
enum StoreBackend {
    Memory(Arc<Mutex<MemoryState>>),
    Sqlite(Arc<Mutex<Connection>>),
}

#[derive(Debug, Clone)]
pub struct EventStore {
    backend: StoreBackend,
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl EventStore {
    /// Create the default non-persistent event store.
    pub fn new() -> Self {
        Self::memory(DEFAULT_MEMORY_EVENT_LIMIT)
    }

    pub fn memory(capacity: usize) -> Self {
        Self {
            backend: StoreBackend::Memory(Arc::new(Mutex::new(MemoryState {
                capacity: capacity.max(1),
                ..MemoryState::default()
            }))),
        }
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let connection = Connection::open(path)
            .map_err(|error| format!("failed to open database {}: {error}", path.display()))?;
        schema::initialize(&connection).map_err(|error| {
            format!("failed to initialize database {}: {error}", path.display())
        })?;
        Ok(Self {
            backend: StoreBackend::Sqlite(Arc::new(Mutex::new(connection))),
        })
    }

    pub fn try_insert(&self, event: &TraceEvent) -> Result<(), String> {
        match &self.backend {
            StoreBackend::Memory(state) => {
                let mut state = state
                    .lock()
                    .map_err(|_| "event store lock poisoned".to_owned())?;
                if let Some(existing) = state
                    .events
                    .iter_mut()
                    .find(|existing| existing.event.id == event.id)
                {
                    existing.event = event.clone();
                } else {
                    if state.events.len() >= state.capacity {
                        state.events.pop_front();
                    }
                    let sequence = state.next_sequence;
                    state.next_sequence = state.next_sequence.saturating_add(1);
                    state.events.push_back(MemoryEvent {
                        sequence,
                        event: event.clone(),
                    });
                }
                Ok(())
            }
            StoreBackend::Sqlite(connection) => try_insert_sqlite(connection, event),
        }
    }

    pub fn insert(&self, event: TraceEvent) {
        if let Err(error) = self.try_insert(&event) {
            eprintln!("TraceLens event store write failed: {error}");
        }
    }

    pub fn query(&self, query: EventQuery) -> Result<EventPage, String> {
        match &self.backend {
            StoreBackend::Memory(state) => query_memory(state, &query),
            StoreBackend::Sqlite(connection) => query_sqlite(connection, &query),
        }
    }

    pub fn len(&self) -> usize {
        self.query(EventQuery {
            limit: 1,
            ..EventQuery::default()
        })
        .map(|page| page.total)
        .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn snapshot(&self) -> Vec<TraceEvent> {
        let mut all_events = Vec::new();
        let mut offset = 0;
        loop {
            let page = match self.query(EventQuery {
                offset,
                limit: 200,
                ..EventQuery::default()
            }) {
                Ok(page) => page,
                Err(_) => return Vec::new(),
            };
            let mut page_events = page.events;
            let page_len = page_events.len();
            page_events.append(&mut all_events);
            all_events = page_events;
            if !page.has_more {
                return all_events;
            }
            offset = offset.saturating_add(page_len);
        }
    }
}

fn try_insert_sqlite(
    connection: &Arc<Mutex<Connection>>,
    event: &TraceEvent,
) -> Result<(), String> {
    let payload_json = to_string(event).map_err(|error| format!("encode event: {error}"))?;
    let timestamp_ns = i64::try_from(event.timestamp_ns)
        .map_err(|_| "event timestamp does not fit SQLite INTEGER".to_owned())?;
    let pid = event.pid.map(i64::from);
    let connection_id = event
        .connection
        .as_ref()
        .map(|connection| connection.id.as_str());
    let connection = connection
        .lock()
        .map_err(|_| "event store lock poisoned".to_owned())?;
    connection
        .execute(
            "\
                INSERT INTO timeline_events(
                    event_id, timestamp_ns, source, kind, pid, connection_id, payload_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(event_id) DO UPDATE SET
                    timestamp_ns = excluded.timestamp_ns,
                    source = excluded.source,
                    kind = excluded.kind,
                    pid = excluded.pid,
                    connection_id = excluded.connection_id,
                    payload_json = excluded.payload_json
                ",
            rusqlite::params![
                event.id,
                timestamp_ns,
                source_name(event.source),
                event_kind_name(event.kind),
                pid,
                connection_id,
                payload_json,
            ],
        )
        .map_err(|error| format!("persist event: {error}"))?;
    Ok(())
}

fn query_memory(state: &Arc<Mutex<MemoryState>>, query: &EventQuery) -> Result<EventPage, String> {
    let limit = query.limit.clamp(1, 200);
    let state = state
        .lock()
        .map_err(|_| "event store lock poisoned".to_owned())?;
    let mut matching = state
        .events
        .iter()
        .filter(|stored| matches_query(&stored.event, query))
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| {
        right
            .event
            .timestamp_ns
            .cmp(&left.event.timestamp_ns)
            .then_with(|| right.sequence.cmp(&left.sequence))
    });
    let total = matching.len();
    let offset = query.offset.min(total);
    let mut events = matching
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|stored| stored.event.clone())
        .collect::<Vec<_>>();
    events.reverse();
    Ok(EventPage {
        has_more: offset + events.len() < total,
        events,
        total,
        offset,
        limit,
    })
}

fn matches_query(event: &TraceEvent, query: &EventQuery) -> bool {
    query.pid.is_none_or(|pid| event.pid == Some(pid))
        && query.kind.is_none_or(|kind| event.kind == kind)
        && query.connection_id.as_ref().is_none_or(|connection_id| {
            event
                .connection
                .as_ref()
                .is_some_and(|connection| &connection.id == connection_id)
        })
}

fn query_sqlite(
    connection: &Arc<Mutex<Connection>>,
    query: &EventQuery,
) -> Result<EventPage, String> {
    let limit = query.limit.clamp(1, 200);
    let connection = connection
        .lock()
        .map_err(|_| "event store lock poisoned".to_owned())?;
    let (where_sql, values) = build_filter(query);
    let value_refs = values
        .iter()
        .map(|value| value.as_ref())
        .collect::<Vec<_>>();
    let count_sql = format!("SELECT COUNT(*) FROM timeline_events {where_sql}");
    let total: usize = connection
        .query_row(&count_sql, value_refs.as_slice(), |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| format!("count timeline events: {error}"))
        .and_then(|value| {
            usize::try_from(value).map_err(|_| "event count does not fit usize".to_owned())
        })?;
    let offset = query.offset.min(total);
    let data_sql = format!(
        "SELECT payload_json FROM timeline_events {where_sql} \
         ORDER BY timestamp_ns DESC, sequence DESC LIMIT ? OFFSET ?"
    );
    let mut data_values = values;
    data_values.push(Box::new(i64::try_from(limit).unwrap_or(200)));
    data_values.push(Box::new(i64::try_from(offset).unwrap_or(i64::MAX)));
    let data_refs = data_values
        .iter()
        .map(|value| value.as_ref())
        .collect::<Vec<_>>();
    let mut statement = connection
        .prepare(&data_sql)
        .map_err(|error| format!("prepare timeline query: {error}"))?;
    let rows = statement
        .query_map(data_refs.as_slice(), |row| row.get::<_, String>(0))
        .map_err(|error| format!("read timeline rows: {error}"))?;
    let mut events = rows
        .map(|row| {
            let payload = row.map_err(|error| format!("read timeline payload: {error}"))?;
            serde_json::from_str::<TraceEvent>(&payload)
                .map_err(|error| format!("decode timeline payload: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    events.reverse();

    Ok(EventPage {
        has_more: offset + events.len() < total,
        events,
        total,
        offset,
        limit,
    })
}

fn build_filter(query: &EventQuery) -> (String, Vec<Box<dyn ToSql>>) {
    let mut clauses = Vec::new();
    let mut values: Vec<Box<dyn ToSql>> = Vec::new();
    if let Some(pid) = query.pid {
        clauses.push("pid = ?".to_owned());
        values.push(Box::new(i64::from(pid)));
    }
    if let Some(kind) = query.kind {
        clauses.push("kind = ?".to_owned());
        values.push(Box::new(event_kind_name(kind)));
    }
    if let Some(connection_id) = &query.connection_id {
        clauses.push("connection_id = ?".to_owned());
        values.push(Box::new(connection_id.clone()));
    }
    if clauses.is_empty() {
        (String::new(), values)
    } else {
        (format!("WHERE {}", clauses.join(" AND ")), values)
    }
}

fn source_name(source: tracelens_events::EventSource) -> &'static str {
    match source {
        tracelens_events::EventSource::Kernel => "kernel",
        tracelens_events::EventSource::Bpftime => "bpftime",
        tracelens_events::EventSource::Core => "core",
    }
}

fn event_kind_name(kind: EventKind) -> &'static str {
    match kind {
        EventKind::ProcessExec => "process_exec",
        EventKind::ProcessExit => "process_exit",
        EventKind::TcpConnect => "tcp_connect",
        EventKind::TcpClose => "tcp_close",
        EventKind::TcpStateChanged => "tcp_state_changed",
        EventKind::TcpBytes => "tcp_bytes",
        EventKind::DnsQuery => "dns_query",
        EventKind::DnsResponse => "dns_response",
        EventKind::TlsMetadata => "tls_metadata",
        EventKind::Plaintext => "plaintext",
        EventKind::HttpCapture => "http_capture",
        EventKind::Http => "http",
        EventKind::FileOpen => "file_open",
        EventKind::FileRead => "file_read",
        EventKind::ObservationChanged => "observation_changed",
    }
}

#[cfg(test)]
mod tests {
    use super::{EventQuery, EventStore};
    use tracelens_events::{EventKind, TraceEvent};

    #[test]
    fn persists_events_and_filters_by_connection() {
        let store = EventStore::new();
        let first = TraceEvent::process_exec(7, "curl", "curl example.com", 1);
        let mut second = TraceEvent::process_exec(7, "curl", "curl example.com", 2);
        second.id = "connection-event".to_owned();
        second.kind = EventKind::TcpConnect;
        second.connection = Some(tracelens_events::ConnectionRef {
            id: "socket-7".to_owned(),
            protocol: tracelens_events::TransportProtocol::Tcp,
            local: None,
            remote: tracelens_events::Endpoint {
                address: "198.51.100.7".to_owned(),
                port: 443,
            },
            state: tracelens_events::ConnectionState::Established,
            tcp_state: Some(tracelens_events::TcpState::Established),
            sent_bytes: 0,
            received_bytes: 0,
            domain: None,
        });
        second.payload = tracelens_events::EventPayload::Connection {
            connection: second.connection.clone().expect("connection payload"),
        };
        store.try_insert(&first).expect("insert process event");
        store.try_insert(&second).expect("insert connection event");

        let page = store
            .query(EventQuery {
                connection_id: Some("socket-7".to_owned()),
                ..EventQuery::default()
            })
            .expect("query connection events");
        assert_eq!(page.total, 1);
        assert_eq!(page.events[0].id, "connection-event");
    }

    #[test]
    fn memory_store_evicts_oldest_events_at_capacity() {
        let store = EventStore::memory(2);
        store
            .try_insert(&TraceEvent::process_exec(7, "curl", "curl one", 1))
            .expect("insert first event");
        store
            .try_insert(&TraceEvent::process_exec(7, "curl", "curl two", 2))
            .expect("insert second event");
        store
            .try_insert(&TraceEvent::process_exec(7, "curl", "curl three", 3))
            .expect("insert third event");

        let page = store
            .query(EventQuery {
                limit: 10,
                ..EventQuery::default()
            })
            .expect("query memory events");
        assert_eq!(page.total, 2);
        assert_eq!(page.events[0].timestamp_ns, 2);
        assert_eq!(page.events[1].timestamp_ns, 3);
    }

    #[test]
    fn durable_store_is_available_after_reopening_the_database() {
        let path = std::env::temp_dir().join(format!(
            "tracelens-storage-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let event = TraceEvent::process_exec(9, "curl", "curl example.com", 7);
        {
            let store = EventStore::open(&path).expect("open durable store");
            store.try_insert(&event).expect("persist event");
        }
        let reopened = EventStore::open(&path).expect("reopen durable store");
        let page = reopened
            .query(EventQuery::default())
            .expect("query reopened store");
        assert_eq!(page.total, 1);
        assert_eq!(page.events[0].id, event.id);
        std::fs::remove_file(&path).expect("remove test database");
        let _ = std::fs::remove_file(format!("{}.wal", path.display()));
        let _ = std::fs::remove_file(format!("{}.shm", path.display()));
    }
}
