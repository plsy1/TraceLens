pub mod parser;
pub mod stream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http11,
}

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub host: Option<String>,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}
