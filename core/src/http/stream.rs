use std::collections::HashMap;

use tracelens_events::PlaintextDirection;

use super::parser::{HttpParseResult, HttpParser};
use super::{HttpRequest, HttpResponse, PayloadDecision};

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
    request_policy: Option<PayloadDecision>,
    response_policy: Option<PayloadDecision>,
    request_gap: bool,
    response_gap: bool,
    parser: HttpParser,
}

impl StreamReassembler {
    pub fn push(
        &mut self,
        direction: PlaintextDirection,
        bytes: &[u8],
        truncated: bool,
    ) -> Vec<HttpMessage> {
        let gap = match direction {
            PlaintextDirection::Write => &mut self.request_gap,
            PlaintextDirection::Read => &mut self.response_gap,
        };
        let policy = {
            let buffer = match direction {
                PlaintextDirection::Write => &mut self.request_buffer,
                PlaintextDirection::Read => &mut self.response_buffer,
            };
            if *gap {
                // A truncated SSL call contains a prefix, not a complete
                // stream segment. We can parse a complete HTTP frame from
                // that prefix, but must not join its unknown tail to the
                // next SSL call.
                buffer.clear();
                match direction {
                    PlaintextDirection::Write => self.request_policy = None,
                    PlaintextDirection::Read => self.response_policy = None,
                }
                *gap = false;
            }
            if buffer.len().saturating_add(bytes.len()) > MAX_STREAM_BUFFER {
                buffer.clear();
                *gap = true;
                return Vec::new();
            }
            buffer.extend_from_slice(bytes);
            match direction {
                PlaintextDirection::Write => self.parser.request_payload_policy(buffer),
                PlaintextDirection::Read => self.parser.response_payload_policy(buffer),
            }
        };
        if let Some(policy) = policy {
            match direction {
                PlaintextDirection::Write => self.request_policy = Some(policy),
                PlaintextDirection::Read => self.response_policy = Some(policy),
            }
        }

        let mut messages = Vec::new();
        loop {
            let buffer = match direction {
                PlaintextDirection::Write => &mut self.request_buffer,
                PlaintextDirection::Read => &mut self.response_buffer,
            };
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
        if truncated {
            *gap = true;
        }
        messages
    }

    pub fn buffered_len(&self) -> usize {
        self.request_buffer.len() + self.response_buffer.len()
    }

    pub fn payload_policy(&self, direction: PlaintextDirection) -> Option<PayloadDecision> {
        match direction {
            PlaintextDirection::Write => self.request_policy,
            PlaintextDirection::Read => self.response_policy,
        }
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

    pub fn payload_policy(
        &self,
        stream_key: &str,
        direction: PlaintextDirection,
    ) -> Option<PayloadDecision> {
        self.streams
            .get(stream_key)
            .and_then(|stream| stream.payload_policy(direction))
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpMessage, PayloadDecision, StreamReassembler};
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
    fn truncated_capture_can_emit_a_complete_prefix_and_drops_the_unknown_tail() {
        let mut stream = StreamReassembler::default();
        let messages = stream.push(
            PlaintextDirection::Write,
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            true,
        );
        assert!(matches!(messages.as_slice(), [HttpMessage::Request(_)]));
        assert_eq!(stream.buffered_len(), 0);
        assert!(stream
            .push(PlaintextDirection::Write, b"Host: stale\r\n\r\n", false)
            .is_empty());
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

    #[test]
    fn aggregates_small_text_body_across_ssl_chunks() {
        let mut stream = StreamReassembler::default();
        assert!(stream
            .push(
                PlaintextDirection::Read,
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 11\r\n\r\nhello ",
                false,
            )
            .is_empty());
        let messages = stream.push(PlaintextDirection::Read, b"world", false);
        let HttpMessage::Response(response) = &messages[0] else {
            panic!("expected response")
        };
        assert_eq!(response.body.preview.as_deref(), Some("hello world"));
        assert_eq!(response.body.bytes, 11);
        assert_eq!(
            stream.payload_policy(PlaintextDirection::Read),
            Some(PayloadDecision::Capture)
        );
    }

    #[test]
    fn marks_binary_streams_without_retaining_body() {
        let mut stream = StreamReassembler::default();
        let messages = stream.push(
            PlaintextDirection::Read,
            b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\n\r\nPNG!",
            false,
        );
        let HttpMessage::Response(response) = &messages[0] else {
            panic!("expected response")
        };
        assert!(response.body.skipped);
        assert_eq!(response.body.preview, None);
        assert_eq!(response.body.bytes, 4);
        assert_eq!(
            stream.payload_policy(PlaintextDirection::Read),
            Some(PayloadDecision::Skip("binary_content"))
        );
    }
}
