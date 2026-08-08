use std::collections::HashMap;

use tracelens_events::TlsEventData;

use super::{TlsLibrary, TlsSession};

#[derive(Debug, Default)]
pub struct TlsTracker {
    sessions: HashMap<(u32, u64), TlsSession>,
    latest_by_process: HashMap<u32, (u64, u64)>,
}

impl TlsTracker {
    pub fn observe_event(
        &mut self,
        process_id: u32,
        data: TlsEventData,
        connection_id: Option<String>,
        timestamp_ns: u64,
    ) -> u64 {
        let requested_ssl_object = data.ssl_object;
        let key = if requested_ssl_object != 0 {
            (process_id, requested_ssl_object)
        } else {
            self.latest_by_process
                .get(&process_id)
                .map(|(ssl_object, _)| (process_id, *ssl_object))
                .unwrap_or((process_id, 0))
        };

        if requested_ssl_object != 0 && key.1 != 0 {
            self.merge_placeholder(process_id, key.1);
        }

        let session = self.sessions.entry(key).or_insert_with(|| TlsSession {
            process_id,
            ssl_object: key.1,
            library: TlsLibrary::OpenSsl,
            fd: None,
            connection_id: None,
            server_name: None,
            version: None,
            first_seen_ns: timestamp_ns,
            last_seen_ns: timestamp_ns,
        });
        session.last_seen_ns = timestamp_ns;
        if data.fd.is_some() {
            session.fd = data.fd;
        }
        if data.sni.is_some() {
            session.server_name = data.sni;
        }
        if data.version.is_some() {
            session.version = data.version;
        }
        if connection_id.is_some() {
            session.connection_id = connection_id;
        }
        self.latest_by_process
            .insert(process_id, (key.1, timestamp_ns));
        key.1
    }

    pub fn get(&self, process_id: u32, ssl_object: u64) -> Option<&TlsSession> {
        self.sessions.get(&(process_id, ssl_object))
    }

    pub fn latest_for_process(&self, process_id: u32) -> Option<&TlsSession> {
        let (ssl_object, _) = self.latest_by_process.get(&process_id)?;
        self.get(process_id, *ssl_object)
    }

    pub fn metadata_for_connection(&self, connection_id: &str) -> Option<&TlsSession> {
        self.sessions
            .values()
            .filter(|session| session.connection_id.as_deref() == Some(connection_id))
            .max_by_key(|session| session.last_seen_ns)
    }

    pub fn sessions(&self) -> impl Iterator<Item = &TlsSession> {
        self.sessions.values()
    }

    pub fn link_connection_for_fd(&mut self, process_id: u32, fd: i32, connection_id: &str) {
        for session in self.sessions.values_mut() {
            if session.process_id == process_id && session.fd == Some(fd) {
                session.connection_id = Some(connection_id.to_owned());
            }
        }
    }

    pub fn remove_process(&mut self, process_id: u32) {
        self.sessions
            .retain(|(session_pid, _), _| *session_pid != process_id);
        self.latest_by_process.remove(&process_id);
    }

    fn merge_placeholder(&mut self, process_id: u32, ssl_object: u64) {
        if ssl_object == 0 {
            return;
        }
        let Some(placeholder) = self.sessions.remove(&(process_id, 0)) else {
            return;
        };
        let session = self
            .sessions
            .entry((process_id, ssl_object))
            .or_insert_with(|| TlsSession {
                process_id,
                ssl_object,
                library: TlsLibrary::OpenSsl,
                fd: None,
                connection_id: None,
                server_name: None,
                version: None,
                first_seen_ns: placeholder.first_seen_ns,
                last_seen_ns: placeholder.last_seen_ns,
            });
        session.fd = session.fd.or(placeholder.fd);
        session.connection_id = session.connection_id.take().or(placeholder.connection_id);
        session.server_name = session.server_name.take().or(placeholder.server_name);
        session.version = session.version.take().or(placeholder.version);
        session.first_seen_ns = session.first_seen_ns.min(placeholder.first_seen_ns);
        session.last_seen_ns = session.last_seen_ns.max(placeholder.last_seen_ns);
    }
}

#[cfg(test)]
mod tests {
    use super::TlsTracker;
    use tracelens_events::TlsEventData;

    #[test]
    fn merges_partial_metadata_and_keeps_connection_link() {
        let mut tracker = TlsTracker::default();
        tracker.observe_event(
            7,
            TlsEventData {
                ssl_object: 0x10,
                fd: None,
                sni: None,
                version: Some("TLSv1.3".to_owned()),
            },
            None,
            1,
        );
        tracker.observe_event(
            7,
            TlsEventData {
                ssl_object: 0x10,
                fd: Some(4),
                sni: Some("example.com".to_owned()),
                version: None,
            },
            Some("socket-30064771076".to_owned()),
            2,
        );

        let session = tracker.get(7, 0x10).expect("TLS session");
        assert_eq!(session.server_name.as_deref(), Some("example.com"));
        assert_eq!(session.version.as_deref(), Some("TLSv1.3"));
        assert_eq!(session.fd, Some(4));
        assert_eq!(session.connection_id.as_deref(), Some("socket-30064771076"));
    }
}
