use super::DnsCache;

#[derive(Debug, Default)]
pub struct DnsTracker {
    cache: DnsCache,
}

impl DnsTracker {
    pub fn observe_response(
        &mut self,
        domain: impl Into<String>,
        addresses: Vec<String>,
        ttl_secs: u32,
        timestamp_ns: u64,
    ) {
        self.cache.insert(domain, addresses, ttl_secs, timestamp_ns);
        self.cache.prune(timestamp_ns);
    }

    pub fn domain_for_address(&self, address: &str, timestamp_ns: u64) -> Option<String> {
        self.cache.domain_for_address(address, timestamp_ns)
    }

    pub fn domains(&self, timestamp_ns: u64) -> impl Iterator<Item = &str> {
        self.cache.domains(timestamp_ns)
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }
}
