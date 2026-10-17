use serde::{Deserialize, Serialize};

/// Desired UDP FEC transmit policy. A connection captures it when it is created.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FecConfig {
    /// Enable local FEC sending; a peer request can also enable it.
    pub enabled: bool,
    /// Request FEC sending from the peer on this connection.
    pub force_peer: bool,
    /// Adaptive repair byte budget as a percentage of source bytes, with a bounded burst.
    pub max_repair_percent: u32,
    /// Complete EasyTier UDP payload budget, excluding the IP and UDP headers.
    pub udp_payload_mtu: u32,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            force_peer: false,
            max_repair_percent: 30,
            udp_payload_mtu: 1400,
        }
    }
}

impl FecConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        anyhow::ensure!(
            (1..=100).contains(&self.max_repair_percent),
            "fec.max_repair_percent must be in 1..=100"
        );
        anyhow::ensure!(
            (576..=8192).contains(&self.udp_payload_mtu),
            "fec.udp_payload_mtu must be in 576..=8192 UDP payload bytes"
        );
        Ok(())
    }
}

impl From<easytier_proto::common::FecConfig> for FecConfig {
    fn from(value: easytier_proto::common::FecConfig) -> Self {
        let defaults = Self::default();
        Self {
            enabled: value.enabled.unwrap_or(defaults.enabled),
            force_peer: value.force_peer.unwrap_or(defaults.force_peer),
            max_repair_percent: value
                .max_repair_percent
                .unwrap_or(defaults.max_repair_percent),
            udp_payload_mtu: value.udp_payload_mtu.unwrap_or(defaults.udp_payload_mtu),
        }
    }
}

impl From<FecConfig> for easytier_proto::common::FecConfig {
    fn from(value: FecConfig) -> Self {
        Self {
            enabled: Some(value.enabled),
            force_peer: Some(value.force_peer),
            max_repair_percent: Some(value.max_repair_percent),
            udp_payload_mtu: Some(value.udp_payload_mtu),
        }
    }
}
