use crate::utils::DeterministicDigest;
use std::fmt::Display;

include!(concat!(env!("OUT_DIR"), "/dns.rs"));

impl HeartbeatRequest {
    pub fn update(&mut self, snapshot: DnsSnapshot) {
        self.digest = snapshot.digest();
        self.snapshot = Some(snapshot);
    }
}

impl Display for ZoneData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "; EasyTier Magic DNS zone data")?;
        writeln!(f, "; https://github.com/easytier/easytier")?;
        writeln!(f, "; {}", self.id.unwrap_or_default())?;

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

        for record in &self.records {
            writeln!(f, "{}", record)?;
        }

        Ok(())
    }
}
