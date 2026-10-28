use super::*;

fn member_id(n: u128) -> SharedVirtualNicMemberId {
    uuid::Uuid::from_u128(n)
}

fn route(cidr: &str) -> SharedIpv4Route {
    let ip: Ipv4Inet = cidr.parse().unwrap();
    SharedIpv4Route::new(ip.address(), ip.network_length(), None)
}

#[test]
fn shared_route_and_mtu_follow_member_ownership() {
    let route = route("100.100.100.101/32");
    let mut ifcfg = SharedIfConfig::default();
    for (member, mtu) in [(member_id(1), 1400), (member_id(2), 1300)] {
        let old = ifcfg.effective();
        ifcfg.apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_routes: BTreeSet::from([route.clone()]),
                mtu: Some(mtu),
                ..Default::default()
            },
        );
        let next = ifcfg.effective();
        let delta = SharedIfConfigDelta::between(&old, &next);
        assert_eq!(
            delta.ipv4_routes.added.contains(&route),
            member == member_id(1)
        );
        assert!(delta.ipv4_routes.removed.is_empty());
        assert_eq!(next.mtu, Some(mtu));
    }
    assert_eq!(
        ifcfg.owners_of_ipv4_route(&route),
        BTreeSet::from([member_id(1), member_id(2)])
    );

    for (member, expected_mtu) in [(member_id(2), Some(1400)), (member_id(1), None)] {
        let old = ifcfg.effective();
        assert!(ifcfg.remove_member(member));
        let next = ifcfg.effective();
        let delta = SharedIfConfigDelta::between(&old, &next);
        assert!(delta.ipv4_routes.added.is_empty());
        assert_eq!(
            delta.ipv4_routes.removed.contains(&route),
            expected_mtu.is_none()
        );
        assert_eq!(next.mtu, expected_mtu);
    }
    assert!(ifcfg.owners_of_ipv4_route(&route).is_empty());
    assert!(!ifcfg.remove_member(member_id(1)));
}

#[test]
fn replacing_member_claims_releases_previous_addresses() {
    let first_ip: Ipv4Inet = "10.30.0.2/24".parse().unwrap();
    let second_ip: Ipv4Inet = "10.30.0.3/24".parse().unwrap();
    let mut ifcfg = SharedIfConfig::default();
    for ip in [first_ip, second_ip] {
        let old = ifcfg.effective();
        ifcfg.apply_member_claims(
            member_id(1),
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([ip]),
                ..Default::default()
            },
        );
        let delta = SharedIfConfigDelta::between(&old, &ifcfg.effective());
        assert_eq!(delta.ipv4_addresses.added, BTreeSet::from([ip]));
        assert_eq!(delta.ipv4_addresses.removed, old.ipv4_addresses);
        assert_eq!(
            ifcfg.claims_of(member_id(1)).ipv4_addresses,
            BTreeSet::from([ip])
        );
    }
}

#[test]
fn only_magic_dns_routes_can_overlap_between_members() {
    let address_claims = SharedIfConfigClaims {
        ipv4_addresses: BTreeSet::from(["100.100.100.101/32".parse().unwrap()]),
        ..Default::default()
    };
    let route_claims = SharedIfConfigClaims {
        ipv4_routes: BTreeSet::from([route("100.100.100.101/32")]),
        ..Default::default()
    };

    for (first, second, allowed) in [
        (&route_claims, &route_claims, true),
        (&address_claims, &address_claims, false),
        (&address_claims, &route_claims, false),
        (&route_claims, &address_claims, false),
    ] {
        let mut ifcfg = SharedIfConfig::default();
        ifcfg.apply_member_claims(member_id(1), first.clone());
        assert_eq!(ifcfg.ensure_disjoint(member_id(2), second).is_ok(), allowed);
        assert!(ifcfg.ensure_disjoint(member_id(1), second).is_ok());
    }
}

#[test]
fn route_source_hint_prefers_an_owner_address_inside_the_route() {
    let route = route("10.90.1.0/24");
    let mut ifcfg = SharedIfConfig::default();
    for (addresses, expected) in [
        (vec!["10.1.1.1/24"], "10.1.1.1"),
        (vec!["10.1.1.1/24", "10.90.1.1/24"], "10.90.1.1"),
    ] {
        ifcfg.apply_member_claims(
            member_id(1),
            SharedIfConfigClaims {
                ipv4_addresses: addresses
                    .into_iter()
                    .map(|ip| ip.parse().unwrap())
                    .collect(),
                ipv4_routes: BTreeSet::from([route.clone()]),
                ..Default::default()
            },
        );
        assert_eq!(
            ifcfg.ipv4_route_source_hint(&route),
            Some(expected.parse().unwrap())
        );
    }
}
