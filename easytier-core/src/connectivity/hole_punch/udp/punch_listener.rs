use std::net::SocketAddr;

use quanta::Instant;

pub const MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReusableUdpPunchListener {
    pub running: bool,
    pub mapped_addr: SocketAddr,
    pub has_port_mapping_lease: bool,
    pub last_active_time: Instant,
}

pub fn can_reuse_public_listener(listener: &ReusableUdpPunchListener) -> bool {
    listener.running && !listener.mapped_addr.ip().is_unspecified()
}

pub fn can_reuse_port_mapping_listener(listener: &ReusableUdpPunchListener) -> bool {
    can_reuse_public_listener(listener) && listener.has_port_mapping_lease
}

pub fn select_reusable_public_listener_idx(
    listeners: &[ReusableUdpPunchListener],
) -> Option<usize> {
    listeners
        .iter()
        .enumerate()
        .filter(|(_, listener)| can_reuse_public_listener(listener))
        .max_by_key(|(_, listener)| listener.last_active_time)
        .map(|(idx, _)| idx)
}

pub fn select_reusable_port_mapping_listener_idx(
    listeners: &[ReusableUdpPunchListener],
) -> Option<usize> {
    listeners
        .iter()
        .enumerate()
        .filter(|(_, listener)| can_reuse_port_mapping_listener(listener))
        .max_by_key(|(_, listener)| listener.last_active_time)
        .map(|(idx, _)| idx)
}

pub fn should_create_public_listener(
    current_listener_count: usize,
    has_reusable_listener: bool,
    has_port_mapping_listener: bool,
    force_new_listener: bool,
    prefer_port_mapping: bool,
) -> bool {
    if current_listener_count >= MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS {
        return false;
    }

    if current_listener_count == 0 {
        return true;
    }

    if force_new_listener {
        return true;
    }

    if prefer_port_mapping && !has_port_mapping_listener {
        return true;
    }

    !has_reusable_listener
}

pub fn should_retry_public_listener_selection(
    force_new_listener: bool,
    current_listener_count: usize,
    prefer_port_mapping: bool,
    has_port_mapping_listener: bool,
) -> bool {
    if prefer_port_mapping && has_port_mapping_listener {
        return false;
    }

    !force_new_listener && current_listener_count < MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        time::Duration,
    };

    use super::*;

    fn listener(
        port: u16,
        running: bool,
        has_port_mapping_lease: bool,
        active_age: Duration,
    ) -> ReusableUdpPunchListener {
        ReusableUdpPunchListener {
            running,
            mapped_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            has_port_mapping_lease,
            last_active_time: Instant::now() - active_age,
        }
    }

    #[test]
    fn listener_selection_prefers_reuse_before_cap() {
        assert!(!should_create_public_listener(1, true, true, false, false));
        assert!(!should_create_public_listener(
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            false,
            false
        ));
    }

    #[test]
    fn listener_selection_creates_when_empty_or_no_reusable_listener() {
        assert!(should_create_public_listener(0, false, false, false, false));
        assert!(should_create_public_listener(1, false, false, false, false));
    }

    #[test]
    fn listener_selection_force_new_respects_cap() {
        assert!(should_create_public_listener(1, true, true, true, false));
        assert!(!should_create_public_listener(
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            true,
            false
        ));
    }

    #[test]
    fn listener_selection_prefers_port_mapping_until_available() {
        assert!(should_create_public_listener(1, true, false, false, true));
        assert!(!should_create_public_listener(1, true, true, false, true));
    }

    #[test]
    fn listener_selection_retry_respects_cap() {
        assert!(should_retry_public_listener_selection(
            false, 1, false, false
        ));
        assert!(!should_retry_public_listener_selection(
            false,
            MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            false,
            false
        ));
        assert!(!should_retry_public_listener_selection(
            true, 1, false, false
        ));
        assert!(!should_retry_public_listener_selection(
            false, 1, true, true
        ));
    }

    #[test]
    fn selects_most_recent_reusable_public_listener() {
        let listeners = vec![
            listener(1000, true, false, Duration::from_secs(10)),
            listener(1001, false, false, Duration::from_secs(1)),
            listener(1002, true, false, Duration::from_secs(2)),
        ];

        assert_eq!(select_reusable_public_listener_idx(&listeners), Some(2));
    }

    #[test]
    fn selects_most_recent_reusable_port_mapping_listener() {
        let listeners = vec![
            listener(1000, true, false, Duration::from_secs(1)),
            listener(1001, true, true, Duration::from_secs(10)),
            listener(1002, true, true, Duration::from_secs(2)),
        ];

        assert_eq!(
            select_reusable_port_mapping_listener_idx(&listeners),
            Some(2)
        );
    }

    #[test]
    fn unspecified_addr_is_not_reusable() {
        let mut listener = listener(1000, true, true, Duration::ZERO);
        listener.mapped_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 1000));

        assert!(!can_reuse_public_listener(&listener));
        assert!(!can_reuse_port_mapping_listener(&listener));
    }
}
