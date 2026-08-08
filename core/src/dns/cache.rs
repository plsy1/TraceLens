use std::collections::HashMap;

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<String>,
    expires_at_ns: u64,
}

#[derive(Debug, Default)]
pub struct DnsCache {
    records: HashMap<String, DnsCacheEntry>,
}

impl DnsCache {
    pub fn insert(
        &mut self,
        domain: impl Into<String>,
        addresses: Vec<String>,
        ttl_secs: u32,
        timestamp_ns: u64,
    ) {
        let ttl_ns = u64::from(ttl_secs).saturating_mul(1_000_000_000);
        self.records.insert(
            domain.into(),
            DnsCacheEntry {
                addresses,
                expires_at_ns: timestamp_ns.saturating_add(ttl_ns),
            },
        );
    }

    pub fn lookup(&self, domain: &str, timestamp_ns: u64) -> Option<&[String]> {
        self.records
            .get(domain)
            .filter(|record| record.expires_at_ns >= timestamp_ns)
            .map(|record| record.addresses.as_slice())
    }

    pub fn domain_for_address(&self, address: &str, timestamp_ns: u64) -> Option<String> {
        self.records
            .iter()
            .find(|(_, record)| {
                record.expires_at_ns >= timestamp_ns
                    && record.addresses.iter().any(|item| item == address)
            })
            .map(|(domain, _)| domain.clone())
    }

    pub fn domains(&self, timestamp_ns: u64) -> impl Iterator<Item = &str> {
        self.records
            .iter()
            .filter(move |(_, record)| record.expires_at_ns >= timestamp_ns)
            .map(|(domain, _)| domain.as_str())
    }

    pub fn prune(&mut self, timestamp_ns: u64) {
        self.records
            .retain(|_, record| record.expires_at_ns >= timestamp_ns);
    }
}

#[cfg(test)]
mod tests {
    use super::DnsCache;

    #[test]
    fn entries_expire_and_reverse_lookup_addresses() {
        let mut cache = DnsCache::default();
        cache.insert(
            "example.com",
            vec!["93.184.216.34".to_owned()],
            2,
            1_000_000_000,
        );

        assert_eq!(
            cache.domain_for_address("93.184.216.34", 2_000_000_000),
            Some("example.com".to_owned())
        );
        assert!(cache.lookup("example.com", 3_000_000_001).is_none());
        assert!(cache
            .domain_for_address("93.184.216.34", 3_000_000_001)
            .is_none());
    }
}
