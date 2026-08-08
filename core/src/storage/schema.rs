//! SQLite schema and migration boundary for the optional durable event store.

use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 2;

pub fn initialize(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "\
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS schema_metadata (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS timeline_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            timestamp_ns INTEGER NOT NULL,
            source TEXT NOT NULL,
            kind TEXT NOT NULL,
            pid INTEGER,
            connection_id TEXT,
            payload_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_timeline_events_timestamp
            ON timeline_events(timestamp_ns, sequence);
        CREATE INDEX IF NOT EXISTS idx_timeline_events_pid_timestamp
            ON timeline_events(pid, timestamp_ns, sequence);
        CREATE INDEX IF NOT EXISTS idx_timeline_events_kind_timestamp
            ON timeline_events(kind, timestamp_ns, sequence);
        CREATE INDEX IF NOT EXISTS idx_timeline_events_connection_timestamp
            ON timeline_events(connection_id, timestamp_ns, sequence);

        INSERT INTO schema_metadata(key, value)
            VALUES ('schema_version', '2')
            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
        ",
    )
}
