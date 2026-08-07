use std::collections::HashMap;

use super::TlsSession;

#[derive(Debug, Default)]
pub struct TlsTracker {
    sessions: HashMap<u64, TlsSession>,
}

impl TlsTracker {
    pub fn observe(&mut self, session: TlsSession) {
        self.sessions.insert(session.ssl_object, session);
    }

    pub fn get(&self, ssl_object: u64) -> Option<&TlsSession> {
        self.sessions.get(&ssl_object)
    }
}
