use super::{HttpRequest, HttpResponse, HttpVersion};

pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

type ParsedHeaders = (Vec<(String, String)>, Option<usize>, bool);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpParseResult<T> {
    Incomplete,
    Invalid,
    Complete { message: T, consumed: usize },
}

#[derive(Debug, Default)]
pub struct HttpParser;

impl HttpParser {
    pub fn parse_request(&self, buffer: &[u8]) -> Option<HttpRequest> {
        match self.parse_request_frame(buffer) {
            HttpParseResult::Complete { message, .. } => Some(message),
            HttpParseResult::Incomplete | HttpParseResult::Invalid => None,
        }
    }

    pub fn parse_response(&self, buffer: &[u8]) -> Option<HttpResponse> {
        match self.parse_response_frame(buffer) {
            HttpParseResult::Complete { message, .. } => Some(message),
            HttpParseResult::Incomplete | HttpParseResult::Invalid => None,
        }
    }

    pub fn parse_request_frame(&self, buffer: &[u8]) -> HttpParseResult<HttpRequest> {
        let Some((header_end, lines)) = (match header_lines(buffer) {
            Ok(value) => value,
            Err(()) => return HttpParseResult::Invalid,
        }) else {
            return HttpParseResult::Incomplete;
        };
        let Some(start_line) = lines.first() else {
            return HttpParseResult::Invalid;
        };
        let mut parts = start_line.splitn(3, ' ');
        let Some(method) = parts.next().filter(|value| !value.is_empty()) else {
            return HttpParseResult::Invalid;
        };
        let Some(path) = parts.next().filter(|value| !value.is_empty()) else {
            return HttpParseResult::Invalid;
        };
        let Some(version) = parts.next() else {
            return HttpParseResult::Invalid;
        };
        if version != HttpVersion::Http11.as_str() || !is_token(method) {
            return HttpParseResult::Invalid;
        }

        let Some((headers, content_length, chunked)) = parse_headers(&lines[1..]) else {
            return HttpParseResult::Invalid;
        };
        let Some(consumed) = body_end(buffer, header_end, content_length, chunked) else {
            return HttpParseResult::Incomplete;
        };
        if consumed == usize::MAX {
            return HttpParseResult::Invalid;
        }

        let host = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.clone());
        HttpParseResult::Complete {
            message: HttpRequest {
                version: HttpVersion::Http11,
                method: method.to_owned(),
                host,
                path: path.to_owned(),
                headers,
                content_length,
            },
            consumed,
        }
    }

    pub fn parse_response_frame(&self, buffer: &[u8]) -> HttpParseResult<HttpResponse> {
        let Some((header_end, lines)) = (match header_lines(buffer) {
            Ok(value) => value,
            Err(()) => return HttpParseResult::Invalid,
        }) else {
            return HttpParseResult::Incomplete;
        };
        let Some(start_line) = lines.first() else {
            return HttpParseResult::Invalid;
        };
        let mut parts = start_line.splitn(3, ' ');
        let Some(version) = parts.next() else {
            return HttpParseResult::Invalid;
        };
        let Some(status) = parts.next() else {
            return HttpParseResult::Invalid;
        };
        if version != HttpVersion::Http11.as_str() || status.len() != 3 {
            return HttpParseResult::Invalid;
        }
        let Ok(status) = status.parse::<u16>() else {
            return HttpParseResult::Invalid;
        };
        let Some((headers, content_length, chunked)) = parse_headers(&lines[1..]) else {
            return HttpParseResult::Invalid;
        };
        let body_length = if (100..200).contains(&status) || status == 204 || status == 304 {
            Some(0)
        } else {
            content_length
        };
        let Some(consumed) = body_end(buffer, header_end, body_length, chunked) else {
            return HttpParseResult::Incomplete;
        };
        if consumed == usize::MAX {
            return HttpParseResult::Invalid;
        }

        HttpParseResult::Complete {
            message: HttpResponse {
                version: HttpVersion::Http11,
                status,
                reason: parts.next().unwrap_or_default().to_owned(),
                headers,
                content_length,
            },
            consumed,
        }
    }
}

fn header_lines(buffer: &[u8]) -> Result<Option<(usize, Vec<String>)>, ()> {
    let (header_end, delimiter_len) = if let Some(index) = find_bytes(buffer, b"\r\n\r\n") {
        (index + 4, 4)
    } else if let Some(index) = find_bytes(buffer, b"\n\n") {
        (index + 2, 2)
    } else {
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(());
        }
        return Ok(None);
    };
    if header_end > MAX_HEADER_BYTES {
        return Err(());
    }
    let header_block = &buffer[..header_end - delimiter_len];
    let text = std::str::from_utf8(header_block).map_err(|_| ())?;
    let lines = text
        .split('\n')
        .map(|line| line.trim_end_matches('\r').to_owned())
        .collect::<Vec<_>>();
    Ok(Some((header_end, lines)))
}

fn parse_headers(lines: &[String]) -> Option<ParsedHeaders> {
    let mut headers = Vec::with_capacity(lines.len());
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        if !is_token(name) {
            return None;
        }
        let name = name.to_owned();
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.parse::<usize>().ok()?;
            if length > MAX_MESSAGE_BYTES {
                return None;
            }
            if content_length.is_some_and(|existing| existing != length) {
                return None;
            }
            content_length = Some(length);
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        headers.push((name, value));
    }
    Some((headers, content_length, chunked))
}

fn body_end(
    buffer: &[u8],
    header_end: usize,
    content_length: Option<usize>,
    chunked: bool,
) -> Option<usize> {
    if chunked {
        return chunked_body_end(buffer, header_end);
    }
    let length = content_length.unwrap_or(0);
    let consumed = header_end.checked_add(length)?;
    if consumed > MAX_MESSAGE_BYTES {
        return Some(usize::MAX);
    }
    (buffer.len() >= consumed).then_some(consumed)
}

fn chunked_body_end(buffer: &[u8], body_start: usize) -> Option<usize> {
    let mut cursor = body_start;
    loop {
        let line_end = find_bytes(&buffer[cursor..], b"\r\n")?;
        let line_end = cursor + line_end;
        let size_text = std::str::from_utf8(&buffer[cursor..line_end]).ok()?;
        let size_text = size_text.split(';').next()?.trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        if size > MAX_MESSAGE_BYTES {
            return Some(usize::MAX);
        }
        cursor = line_end + 2;
        if size == 0 {
            if buffer[cursor..].starts_with(b"\r\n") {
                return Some(cursor + 2);
            }
            let trailer_end = find_bytes(&buffer[cursor..], b"\r\n\r\n")?;
            return Some(cursor + trailer_end + 4);
        }
        let chunk_end = cursor.checked_add(size)?;
        let data_end = chunk_end.checked_add(2)?;
        if data_end > buffer.len() {
            return None;
        }
        if &buffer[chunk_end..data_end] != b"\r\n" {
            return Some(usize::MAX);
        }
        cursor = data_end;
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::{HttpParseResult, HttpParser};
    use crate::http::{HttpVersion, MAX_HEADER_BYTES};

    #[test]
    fn parses_request_metadata_and_consumes_content_length() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabcGET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let parser = HttpParser;
        let first = parser.parse_request_frame(request);
        let HttpParseResult::Complete { message, consumed } = first else {
            panic!("request should parse")
        };
        assert_eq!(
            consumed,
            request.len() - b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n".len()
        );
        assert_eq!(message.version, HttpVersion::Http11);
        assert_eq!(message.method, "POST");
        assert_eq!(message.path, "/upload");
        assert_eq!(message.host.as_deref(), Some("example.com"));
        assert_eq!(message.content_length, Some(3));
    }

    #[test]
    fn parses_response_and_waits_for_partial_body() {
        let parser = HttpParser;
        let partial =
            parser.parse_response_frame(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe");
        assert_eq!(partial, HttpParseResult::Incomplete);
        let complete =
            parser.parse_response_frame(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        let HttpParseResult::Complete { message, .. } = complete else {
            panic!("response should parse")
        };
        assert_eq!(message.status, 200);
        assert_eq!(message.reason, "OK");
    }

    #[test]
    fn consumes_chunked_body_and_trailers_before_next_request() {
        let request = b"POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\nX-Trace: yes\r\n\r\nGET /next HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let HttpParseResult::Complete { message, consumed } =
            HttpParser.parse_request_frame(request)
        else {
            panic!("chunked request should parse")
        };
        assert_eq!(message.method, "POST");
        assert_eq!(message.content_length, None);
        assert_eq!(
            &request[consumed..],
            b"GET /next HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
    }

    #[test]
    fn rejects_oversized_headers() {
        let mut request = format!(
            "GET / HTTP/1.1\r\nX-Test: {}\r\n\r\n",
            "x".repeat(MAX_HEADER_BYTES)
        );
        request.push('\n');
        assert_eq!(
            HttpParser.parse_request_frame(request.as_bytes()),
            HttpParseResult::Invalid
        );
    }
}
