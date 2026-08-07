pub mod openssl;
pub mod tracker;

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
    pub server_name: Option<String>,
    pub version: Option<String>,
}
