use super::{HttpRequest, HttpResponse};

#[derive(Debug, Default)]
pub struct HttpParser;

impl HttpParser {
    pub fn parse_request(&self, _buffer: &[u8]) -> Option<HttpRequest> {
        // HTTP/1.1 parsing is added after plaintext stream reassembly exists.
        None
    }

    pub fn parse_response(&self, _buffer: &[u8]) -> Option<HttpResponse> {
        None
    }
}
