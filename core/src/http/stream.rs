use std::collections::HashMap;

use tracelens_events::PlaintextDirection;

use super::parser::{HttpParseResult, HttpParser};
use super::{HttpRequest, HttpResponse};

pub const MAX_STREAM_BUFFER: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

#[derive(Debug, Default)]
pub struct StreamReassembler {
    request_buffer: Vec<u8>,
    response_buffer: Vec<u8>,
    parser: HttpParser,
}

impl StreamReassembler {
    pub fn push(
        &mut self,
        direction: PlaintextDirection,
        bytes: &[u8],
        truncated: bool,
    ) -> Vec<HttpMessage> {
        let buffer = match direction {
            PlaintextDirection::Write => &mut self.request_buffer,
            PlaintextDirection::Read => &mut self.response_buffer,
        };
        if truncated {
            buffer.clear();
            return Vec::new();
        }
        if buffer.len().saturating_add(bytes.len()) > MAX_STREAM_BUFFER {
            buffer.clear();
            return Vec::new();
        }
        buffer.extend_from_slice(bytes);

        let mut messages = Vec::new();
        loop {
            let parsed = match direction {
                PlaintextDirection::Write => {
                    ParsedFrame::Request(self.parser.parse_request_frame(buffer))
                }
                PlaintextDirection::Read => {
                    ParsedFrame::Response(self.parser.parse_response_frame(buffer))
                }
            };
            match parsed {
                ParsedFrame::Request(HttpParseResult::Complete { message, consumed }) => {
                    buffer.drain(..consumed);
                    messages.push(HttpMessage::Request(message));
                }
                ParsedFrame::Response(HttpParseResult::Complete { message, consumed }) => {
                    buffer.drain(..consumed);
                    messages.push(HttpMessage::Response(message));
                }
                ParsedFrame::Request(HttpParseResult::Incomplete)
                | ParsedFrame::Response(HttpParseResult::Incomplete) => break,
                ParsedFrame::Request(HttpParseResult::Invalid)
                | ParsedFrame::Response(HttpParseResult::Invalid) => {
                    buffer.clear();
                    break;
                }
            }
        }
        messages
    }

    pub fn buffered_len(&self) -> usize {
        self.request_buffer.len() + self.response_buffer.len()
    }
}

enum ParsedFrame {
    Request(HttpParseResult<super::HttpRequest>),
    Response(HttpParseResult<super::HttpResponse>),
}

#[derive(Debug, Default)]
pub struct HttpTracker {
    streams: HashMap<String, StreamReassembler>,
}

impl HttpTracker {
    pub fn observe(
        &mut self,
        stream_key: &str,
        direction: PlaintextDirection,
        bytes: &[u8],
        truncated: bool,
    ) -> Vec<HttpMessage> {
        self.streams
            .entry(stream_key.to_owned())
            .or_default()
            .push(direction, bytes, truncated)
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpMessage, StreamReassembler};
    use tracelens_events::PlaintextDirection;

    #[test]
    fn reassembles_headers_across_plaintext_events() {
        let mut stream = StreamReassembler::default();
        assert!(stream
            .push(
                PlaintextDirection::Write,
                b"GET /health HTTP/1.1\r\nHost: ex",
                false,
            )
            .is_empty());
        let messages = stream.push(PlaintextDirection::Write, b"ample.com\r\n\r\n", false);
        assert_eq!(messages.len(), 1);
        let HttpMessage::Request(request) = &messages[0] else {
            panic!("expected request")
        };
        assert_eq!(request.host.as_deref(), Some("example.com"));
        assert_eq!(request.path, "/health");
        assert_eq!(stream.buffered_len(), 0);
    }

    #[test]
    fn keeps_request_and_response_directions_separate() {
        let mut stream = StreamReassembler::default();
        assert!(stream
            .push(PlaintextDirection::Write, b"GET / HTTP/1.1\r\n", false)
            .is_empty());
        assert!(stream
            .push(PlaintextDirection::Read, b"HTTP/1.1 204 No", false)
            .is_empty());
        let request = stream.push(PlaintextDirection::Write, b"Host: x\r\n\r\n", false);
        let response = stream.push(PlaintextDirection::Read, b" Content\r\n\r\n", false);
        assert!(matches!(request.as_slice(), [HttpMessage::Request(_)]));
        assert!(matches!(response.as_slice(), [HttpMessage::Response(_)]));
    }

    #[test]
    fn truncated_capture_resets_only_the_affected_direction() {
        let mut stream = StreamReassembler::default();
        stream.push(PlaintextDirection::Write, b"GET / HTTP/1.1\r\n", false);
        stream.push(PlaintextDirection::Write, b"Host: x", true);
        assert_eq!(stream.buffered_len(), 0);
        assert!(stream
            .push(
                PlaintextDirection::Read,
                b"HTTP/1.1 204 No Content\r\n\r\n",
                false
            )
            .iter()
            .any(|message| matches!(message, HttpMessage::Response(_))));
    }
}
