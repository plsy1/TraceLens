use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct DnsCache {
    records: HashMap<String, Vec<String>>,
}

impl DnsCache {
    pub fn insert(&mut self, domain: impl Into<String>, addresses: Vec<String>) {
        self.records.insert(domain.into(), addresses);
    }

    pub fn lookup(&self, domain: &str) -> Option<&[String]> {
        self.records.get(domain).map(Vec::as_slice)
    }
}
