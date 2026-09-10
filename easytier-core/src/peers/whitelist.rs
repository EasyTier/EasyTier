//! Relay-network whitelist matching shared by the peer context and the
//! foreign-network manager. Kept in the peers kernel so both can depend on it
//! without depending on each other.

pub(crate) fn check_network_in_relay_whitelist(
    relay_network_whitelist: &str,
    network_name: &str,
) -> Result<(), anyhow::Error> {
    if relay_network_whitelist
        .split(' ')
        .map(wildmatch::WildMatch::new)
        .any(|whitelist| whitelist.matches(network_name))
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!("network {} not in whitelist", network_name))
    }
}
