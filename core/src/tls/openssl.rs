//! OpenSSL-specific userspace probe coordination.

#[derive(Debug, Default)]
pub struct OpenSslInspector;

impl OpenSslInspector {
    pub fn library_name(&self) -> &'static str {
        "OpenSSL"
    }
}
