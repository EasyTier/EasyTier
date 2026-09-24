include!(concat!(env!("OUT_DIR"), "/dns.rs"));

#[cfg(feature = "json-rpc")]
include!(concat!(env!("OUT_DIR"), "/dns.serde.rs"));

impl HeartbeatRequest {
    pub fn update(&mut self, snapshot: DnsSnapshot) {
        use prost::Message;
        use sha2::{Digest, Sha256};
        self.digest = Sha256::digest(snapshot.encode_to_vec()).to_vec();
        self.snapshot = Some(snapshot);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Hash)]
#[cfg_attr(feature = "core", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "core", serde(untagged))]
pub enum Fallthrough {
    Any,
    ResponseCode(hickory_proto::op::ResponseCode),
}

impl From<hickory_proto::op::ResponseCode> for Fallthrough {
    fn from(code: hickory_proto::op::ResponseCode) -> Self {
        Self::ResponseCode(code)
    }
}

impl From<Fallthrough> for i32 {
    fn from(value: Fallthrough) -> Self {
        match value {
            Fallthrough::ResponseCode(code) => u16::from(code).into(),
            Fallthrough::Any => -1,
        }
    }
}

impl From<i32> for Fallthrough {
    fn from(value: i32) -> Self {
        match u16::try_from(value) {
            Ok(value) => Self::ResponseCode(value.into()),
            Err(_) => Self::Any,
        }
    }
}

impl ZoneData {
    pub fn new<Record: AsRef<str>>(
        origin: &hickory_proto::rr::LowerName,
        ttl: u32,
        records: impl IntoIterator<Item = Record>,
        forwarders: impl IntoIterator<Item = crate::common::Url>,
        fallthrough: impl IntoIterator<Item = Fallthrough>,
    ) -> Self {
        use std::fmt::Write as _;
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

