use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt::Display;

include!(concat!(env!("OUT_DIR"), "/dns.rs"));

pub trait DeterministicDigest: Serialize {
    fn digest(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).expect("failed to serialize the object to json");
        let mut hasher = Sha256::new();
        hasher.update(json);
        hasher.finalize().to_vec()
    }
}

impl DeterministicDigest for GetExportConfigResponse {}

impl DeterministicDigest for ZoneConfigPb {}

impl DeterministicDigest for DnsSnapshot {}

impl Display for ZoneConfigPb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "; EasyTier Magic DNS zone file")?;
        writeln!(f, "; https://github.com/easytier/easytier")?;

        if !self.forwarders.is_empty() {
            writeln!(f, "; Forwarders:")?;
            for forwarder in &self.forwarders {
                writeln!(f, "; \t{}", forwarder)?;
            }
        }
        writeln!(f)?;

        write!(f, "$ORIGIN {}", self.origin)?;
        if !self.origin.ends_with('.') {
            write!(f, ".")?;
        }
        writeln!(f)?;

        writeln!(f, "$TTL {}", self.ttl)?;

        writeln!(f)?;

        for record in &self.records {
            writeln!(f, "{}", record)?;
        }

        Ok(())
    }
}
