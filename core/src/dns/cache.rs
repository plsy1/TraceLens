use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsCacheKey {
    pid: Option<u32>,
    domain: String,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    addresses: Vec<String>,
    observed_at_ns: u64,
    expires_at_ns: u64,
}

#[derive(Debug, Default)]
pub struct DnsCache {
    records: HashMap<DnsCacheKey, DnsCacheEntry>,
}

impl DnsCache {
    pub fn insert(
        &mut self,
        domain: impl Into<String>,
        addresses: Vec<String>,
        ttl_secs: u32,
        timestamp_ns: u64,
    ) {
        self.insert_for_process(None, domain, addresses, ttl_secs, timestamp_ns);
    }

    pub fn insert_for_process(
        &mut self,
        pid: Option<u32>,
        domain: impl Into<String>,
        addresses: Vec<String>,
        ttl_secs: u32,
        timestamp_ns: u64,
    ) {
        let ttl_ns = u64::from(ttl_secs).saturating_mul(1_000_000_000);
        let domain = domain.into();
        self.records.insert(
            DnsCacheKey { pid, domain },
            DnsCacheEntry {
                addresses,
                observed_at_ns: timestamp_ns,
                expires_at_ns: timestamp_ns.saturating_add(ttl_ns),
            },
        );
    }

    pub fn lookup(&self, domain: &str, timestamp_ns: u64) -> Option<&[String]> {
        self.records
            .iter()
            .filter(|(key, record)| key.domain == domain && Self::is_active(record, timestamp_ns))
            .max_by_key(|(_, record)| record.observed_at_ns)
            .map(|(_, record)| record.addresses.as_slice())
    }

    pub fn lookup_for_process(
        &self,
        pid: u32,
        domain: &str,
        timestamp_ns: u64,
    ) -> Option<&[String]> {
        self.records
            .get(&DnsCacheKey {
                pid: Some(pid),
                domain: domain.to_owned(),
            })
            .filter(|record| Self::is_active(record, timestamp_ns))
            .map(|record| record.addresses.as_slice())
    }

    pub fn domain_for_address(&self, address: &str, timestamp_ns: u64) -> Option<String> {
        self.records
            .iter()
            .filter(|(_, record)| {
                Self::is_active(record, timestamp_ns)
                    && record.addresses.iter().any(|item| item == address)
            })
            .max_by_key(|(_, record)| record.observed_at_ns)
            .map(|(key, _)| key.domain.clone())
    }

    pub fn domain_for_process_address(
        &self,
        pid: u32,
        address: &str,
        timestamp_ns: u64,
    ) -> Option<String> {
        let process_match = self
            .records
            .iter()
            .filter(|(key, record)| {
                key.pid == Some(pid)
                    && Self::is_active(record, timestamp_ns)
                    && record.addresses.iter().any(|item| item == address)
            })
            .max_by_key(|(_, record)| record.observed_at_ns)
            .map(|(key, _)| key.domain.clone());

        process_match.or_else(|| {
            self.records
                .iter()
                .filter(|(key, record)| {
                    key.pid.is_none()
                        && Self::is_active(record, timestamp_ns)
                        && record.addresses.iter().any(|item| item == address)
                })
                .max_by_key(|(_, record)| record.observed_at_ns)
                .map(|(key, _)| key.domain.clone())
        })
    }

    pub fn domain_for_unscoped_address(&self, address: &str, timestamp_ns: u64) -> Option<String> {
        self.records
            .iter()
            .filter(|(key, record)| {
                key.pid.is_none()
                    && Self::is_active(record, timestamp_ns)
                    && record.addresses.iter().any(|item| item == address)
            })
            .max_by_key(|(_, record)| record.observed_at_ns)
            .map(|(key, _)| key.domain.clone())
    }

    pub fn domains(&self, timestamp_ns: u64) -> impl Iterator<Item = &str> {
        self.records
            .iter()
            .filter(move |(_, record)| Self::is_active(record, timestamp_ns))
            .map(|(key, _)| key.domain.as_str())
    }

    pub fn prune(&mut self, timestamp_ns: u64) {
        self.records
            .retain(|_, record| record.expires_at_ns > timestamp_ns);
    }

    fn is_active(record: &DnsCacheEntry, timestamp_ns: u64) -> bool {
        record.observed_at_ns <= timestamp_ns
            && record.expires_at_ns > timestamp_ns
            && !record.addresses.is_empty()
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
            cache.domain_for_address("93.184.216.34", 1_999_999_999),
            Some("example.com".to_owned())
        );
        assert!(cache.lookup("example.com", 3_000_000_001).is_none());
        assert!(cache
            .domain_for_address("93.184.216.34", 3_000_000_001)
            .is_none());
    }

    #[test]
    fn ignores_future_entries_and_prefers_process_scoped_mapping() {
        let mut cache = DnsCache::default();
        cache.insert_for_process(
            Some(10),
            "first.example",
            vec!["198.19.0.116".to_owned()],
            60,
            10,
        );
        cache.insert_for_process(
            Some(11),
            "second.example",
            vec!["198.19.0.116".to_owned()],
            60,
            20,
        );

        assert_eq!(
            cache.domain_for_process_address(10, "198.19.0.116", 15),
            Some("first.example".to_owned())
        );
        assert_eq!(
            cache.domain_for_process_address(11, "198.19.0.116", 25),
            Some("second.example".to_owned())
        );
        assert_eq!(
            cache.domain_for_process_address(12, "198.19.0.116", 15),
            None
        );
    }

    #[test]
    fn empty_response_invalidates_the_previous_mapping() {
        let mut cache = DnsCache::default();
        cache.insert_for_process(
            Some(10),
            "example.test",
            vec!["203.0.113.7".to_owned()],
            60,
            1,
        );
        cache.insert_for_process(Some(10), "example.test", Vec::new(), 60, 2);

        assert!(cache
            .domain_for_process_address(10, "203.0.113.7", 3)
            .is_none());
    }
}
