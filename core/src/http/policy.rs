//! Bounded payload handling for HTTP messages.
//!
//! The probes give us small, lossy chunks from `SSL_read`/`SSL_write`.  This
//! module is deliberately conservative: readable application text is kept as
//! a bounded preview, while media, archives, encoded bodies, and unknown
//! binary data keep only their HTTP metadata and byte count.

use std::io::Read;

use brotli::Decompressor;
use encoding_rs::Encoding;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};

pub const MAX_TEXT_PREVIEW_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadDecision {
    Capture,
    Skip(&'static str),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpBody {
    pub preview: Option<String>,
    pub bytes: usize,
    pub truncated: bool,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

impl HttpBody {
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Decide whether a body is safe and useful to retain before the complete
/// frame is available.  This is also used by the stream reassembler to stop
/// retaining binary bodies as soon as their headers arrive.
pub fn payload_decision(
    headers: &[(String, String)],
    content_length: Option<usize>,
) -> PayloadDecision {
    if content_length == Some(0) {
        return PayloadDecision::Capture;
    }

    let chunked = header_value(headers, "transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    });
    let has_body = content_length.is_some() || chunked;
    if !has_body {
        return PayloadDecision::Capture;
    }

    if let Some(encoding) = header_value(headers, "content-encoding") {
        let supported = encoding.split(',').all(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "identity" | "gzip" | "x-gzip" | "deflate" | "br" | "zstd"
            )
        });
        if !supported {
            return PayloadDecision::Skip("unsupported_content_encoding");
        }
    }

    let Some(content_type) = header_value(headers, "content-type") else {
        return PayloadDecision::Skip("unknown_content_type");
    };
    let content_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if is_text_content_type(&content_type) {
        if header_value(headers, "content-encoding").is_none()
            && content_length.is_some_and(|length| length > MAX_TEXT_PREVIEW_BYTES)
        {
            PayloadDecision::Skip("body_too_large")
        } else {
            PayloadDecision::Capture
        }
    } else if is_binary_content_type(&content_type) {
        PayloadDecision::Skip("binary_content")
    } else {
        PayloadDecision::Skip("unsupported_content_type")
    }
}

pub fn capture_body(
    headers: &[(String, String)],
    content_length: Option<usize>,
    body: &[u8],
) -> HttpBody {
    if body.is_empty() {
        return HttpBody::empty();
    }

    let decision = payload_decision(headers, content_length);
    if let PayloadDecision::Skip(reason) = decision {
        if reason != "unknown_content_type" || !is_probably_text(body) {
            return skipped_body(body.len(), reason);
        }
    }
    let decoded = match decode_content_encoding(headers, body) {
        Ok(decoded) => decoded,
        Err(reason) => return skipped_body(body.len(), reason),
    };
    if decoded.len() > MAX_TEXT_PREVIEW_BYTES {
        return skipped_body(body.len(), "body_too_large");
    }

    let Some(preview) = decode_text(headers, &decoded) else {
        return skipped_body(body.len(), "unsupported_text_encoding");
    };
    HttpBody {
        preview: Some(preview),
        bytes: body.len(),
        truncated: false,
        skipped: false,
        skip_reason: None,
    }
}

fn decode_content_encoding(
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let Some(value) = header_value(headers, "content-encoding") else {
        return Ok(body.to_vec());
    };
    let mut decoded = body.to_vec();
    for encoding in value.split(',').rev() {
        decoded = match encoding.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => decoded,
            "gzip" | "x-gzip" => read_bounded(GzDecoder::new(decoded.as_slice()))?,
            "deflate" => read_deflate_bounded(&decoded)?,
            "br" => read_bounded(Decompressor::new(decoded.as_slice(), 16 * 1024))?,
            "zstd" => read_bounded(
                zstd::stream::read::Decoder::new(decoded.as_slice())
                    .map_err(|_| "invalid_content_encoding")?,
            )?,
            _ => return Err("unsupported_content_encoding"),
        };
    }
    Ok(decoded)
}

fn read_deflate_bounded(body: &[u8]) -> Result<Vec<u8>, &'static str> {
    read_bounded(ZlibDecoder::new(body)).or_else(|_| read_bounded(DeflateDecoder::new(body)))
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>, &'static str> {
    let mut decoded = Vec::new();
    reader
        .take((MAX_TEXT_PREVIEW_BYTES + 1) as u64)
        .read_to_end(&mut decoded)
        .map_err(|_| "invalid_content_encoding")?;
    if decoded.len() > MAX_TEXT_PREVIEW_BYTES {
        return Err("body_too_large");
    }
    Ok(decoded)
}

fn decode_text(headers: &[(String, String)], body: &[u8]) -> Option<String> {
    let charset = header_value(headers, "content-type")
        .and_then(|value| {
            value.split(';').skip(1).find_map(|parameter| {
                let (name, value) = parameter.trim().split_once('=')?;
                name.eq_ignore_ascii_case("charset")
                    .then(|| value.trim().trim_matches(['\'', '"']))
            })
        })
        .unwrap_or("utf-8");
    let encoding = Encoding::for_label(charset.as_bytes())?;
    let (text, _, _) = encoding.decode(body);
    Some(text.into_owned())
}

fn skipped_body(bytes: usize, reason: &'static str) -> HttpBody {
    HttpBody {
        preview: None,
        bytes,
        truncated: false,
        skipped: true,
        skip_reason: Some(reason.to_owned()),
    }
}

fn is_probably_text(body: &[u8]) -> bool {
    let Ok(text) = str::from_utf8(body) else {
        return false;
    };
    text.chars()
        .all(|character| character.is_ascii_graphic() || character.is_ascii_whitespace())
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn is_text_content_type(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || content_type == "application/json"
        || content_type.ends_with("+json")
        || content_type == "application/xml"
        || content_type.ends_with("+xml")
        || matches!(
            content_type,
            "application/javascript"
                | "application/ecmascript"
                | "application/x-javascript"
                | "text/javascript"
                | "text/css"
                | "application/x-www-form-urlencoded"
                | "application/graphql"
        )
}

fn is_binary_content_type(content_type: &str) -> bool {
    content_type.starts_with("image/")
        || content_type.starts_with("audio/")
        || content_type.starts_with("video/")
        || content_type.starts_with("font/")
        || matches!(
            content_type,
            "application/octet-stream"
                | "application/zip"
                | "application/gzip"
                | "application/x-gzip"
                | "application/x-7z-compressed"
                | "application/x-rar-compressed"
                | "application/x-tar"
                | "application/pdf"
                | "application/wasm"
                | "application/protobuf"
                | "application/x-protobuf"
                | "multipart/form-data"
        )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use brotli::CompressorWriter;
    use flate2::{write::DeflateEncoder, write::GzEncoder, Compression};

    use super::{capture_body, payload_decision, PayloadDecision, MAX_TEXT_PREVIEW_BYTES};

    fn headers(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn captures_small_html_and_json_bodies() {
        let html_headers = headers(&[("Content-Type", "text/html; charset=utf-8")]);
        let json_headers = headers(&[("content-type", "application/json")]);
        assert_eq!(
            payload_decision(&html_headers, Some(4)),
            PayloadDecision::Capture
        );
        assert_eq!(
            capture_body(&json_headers, Some(4), br#"{"ok":true}"#).preview,
            Some(r#"{"ok":true}"#.to_owned())
        );
    }

    #[test]
    fn skips_media_and_large_text_without_retaining_body() {
        let media_headers = headers(&[("Content-Type", "video/mp4")]);
        let text_headers = headers(&[("Content-Type", "text/plain")]);
        let large = vec![b'x'; MAX_TEXT_PREVIEW_BYTES + 1];
        assert_eq!(
            capture_body(&media_headers, Some(large.len()), &large)
                .skip_reason
                .as_deref(),
            Some("binary_content")
        );
        assert_eq!(
            capture_body(&text_headers, Some(large.len()), &large)
                .skip_reason
                .as_deref(),
            Some("body_too_large")
        );
    }

    fn encoded_body(encoding: &str, body: &[u8]) -> Vec<u8> {
        match encoding {
            "gzip" => {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "deflate" => {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(body).unwrap();
                encoder.finish().unwrap()
            }
            "br" => {
                let mut encoded = Vec::new();
                let mut encoder = CompressorWriter::new(&mut encoded, 4096, 5, 22);
                encoder.write_all(body).unwrap();
                drop(encoder);
                encoded
            }
            "zstd" => zstd::stream::encode_all(body, 3).unwrap(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn decodes_compressed_text_with_a_bounded_preview() {
        for encoding in ["gzip", "deflate", "br", "zstd"] {
            let headers = headers(&[
                ("Content-Type", "application/json"),
                ("Content-Encoding", encoding),
            ]);
            let encoded = encoded_body(encoding, br#"{"ok":true}"#);
            assert_eq!(
                payload_decision(&headers, Some(encoded.len())),
                PayloadDecision::Capture
            );
            let body = capture_body(&headers, Some(encoded.len()), &encoded);
            assert_eq!(body.preview.as_deref(), Some(r#"{"ok":true}"#));
            assert_eq!(body.bytes, encoded.len());
            assert!(!body.skipped);
        }
    }

    #[test]
    fn rejects_a_compressed_body_that_expands_past_the_preview_limit() {
        let headers = headers(&[("Content-Type", "text/plain"), ("Content-Encoding", "gzip")]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&vec![b'x'; MAX_TEXT_PREVIEW_BYTES + 1])
            .unwrap();
        let encoded = encoder.finish().unwrap();
        let body = capture_body(&headers, Some(encoded.len()), &encoded);
        assert_eq!(body.preview, None);
        assert_eq!(body.skip_reason.as_deref(), Some("body_too_large"));
    }

    #[test]
    fn skips_unknown_content_encoding() {
        let headers = headers(&[
            ("Content-Type", "application/json"),
            ("Content-Encoding", "compress"),
        ]);
        assert_eq!(
            payload_decision(&headers, Some(10)),
            PayloadDecision::Skip("unsupported_content_encoding")
        );
    }

    #[test]
    fn decodes_declared_non_utf8_text() {
        let headers = headers(&[("Content-Type", "text/plain; charset=windows-1252")]);
        let body = capture_body(&headers, Some(4), b"caf\xe9");
        assert_eq!(body.preview.as_deref(), Some("café"));
    }
}
