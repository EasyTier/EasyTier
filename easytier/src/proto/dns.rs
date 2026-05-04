use crate::dns::config::zone::Fallthrough;
use crate::proto::common::Url;
use crate::proto::utils::TransientDigest;
use hickory_proto::rr::LowerName;
use std::fmt::Write;

include!(concat!(env!("OUT_DIR"), "/dns.rs"));

impl HeartbeatRequest {
    pub fn update(&mut self, snapshot: DnsSnapshot) {
        self.digest = snapshot.digest().into();
        self.snapshot = Some(snapshot);
    }
}

impl ZoneData {
    pub fn new<Record: AsRef<str>>(
        origin: &LowerName,
        ttl: u32,
        records: impl IntoIterator<Item = Record>,
        forwarders: impl IntoIterator<Item = Url>,
        fallthrough: impl IntoIterator<Item = Fallthrough>,
    ) -> Self {
        let mut content = String::new();

        content.push_str("; EasyTier Magic DNS zone data\n");
        content.push_str("; https://github.com/easytier/easytier\n");

        let mut origin = origin.to_string();
        if !origin.ends_with('.') {
            origin.push('.');
        }

        writeln!(content, "$ORIGIN {}", origin).unwrap();
        writeln!(content, "$TTL {}", ttl).unwrap();

        for record in records {
            content.push_str(record.as_ref());
            content.push('\n');
        }

        let forwarders = forwarders.into_iter().collect();
        let fallthrough = fallthrough.into_iter().map(Into::into).collect();

        Self {
            content,
            forwarders,
            fallthrough,
        }
    }
}
