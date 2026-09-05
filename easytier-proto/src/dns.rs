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
