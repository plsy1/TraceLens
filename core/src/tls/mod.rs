pub mod openssl;
pub mod tracker;

pub use tracker::TlsTracker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsLibrary {
    OpenSsl,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TlsSession {
    pub process_id: u32,
    pub ssl_object: u64,
    pub library: TlsLibrary,
    pub fd: Option<i32>,
    pub connection_id: Option<String>,
    pub server_name: Option<String>,
    pub version: Option<String>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}
