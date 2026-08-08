pub mod parser;
pub mod policy;
pub mod stream;

pub use parser::{HttpParseResult, MAX_HEADER_BYTES, MAX_MESSAGE_BYTES};
pub use policy::{
    capture_body, payload_decision, HttpBody, PayloadDecision, MAX_TEXT_PREVIEW_BYTES,
};
pub use stream::{HttpMessage, HttpTracker, StreamReassembler, MAX_STREAM_BUFFER};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http11,
}

impl HttpVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http11 => "HTTP/1.1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub version: HttpVersion,
    pub method: String,
    pub host: Option<String>,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub body: HttpBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub content_length: Option<usize>,
    pub body: HttpBody,
}
