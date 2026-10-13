use std::sync::Mutex as StdMutex;

use crate::common::{ifcfg::IfConfiguerTrait, netns::NetNS};

use super::*;

const MEMBER: SharedVirtualNicMemberId = uuid::Uuid::from_u128(1);
const REGISTRATION: SharedVirtualNicMemberRegistrationId = uuid::Uuid::from_u128(10);

fn virtual_nic_config(mtu: u32, netns: Option<&str>) -> VirtualNicConfig {
    VirtualNicConfig::new("et0".to_owned(), mtu, NetNS::new(netns.map(str::to_owned)))
}

fn address_claims(ip: &str) -> SharedIfConfigClaims {
    SharedIfConfigClaims {
        ipv4_addresses: BTreeSet::from([ip.parse().unwrap()]),
        ..Default::default()
    }
}

fn registered_nic() -> SharedVirtualNic {
    let mut nic = SharedVirtualNic::new(virtual_nic_config(1500, None));
    nic.member_registrations.insert(MEMBER, REGISTRATION);
    nic.ifcfg
        .apply_member_claims(MEMBER, address_claims("10.50.0.2/24"));
    nic
}

#[derive(Debug, PartialEq, Eq)]
enum RouteChange {
    Add(SharedIpv4Route, Option<Ipv4Addr>),
    Remove(SharedIpv4Route, Option<Ipv4Addr>),
}

#[derive(Clone, Default)]
struct RecordingIfConfiger {
    routes: Arc<StdMutex<Vec<RouteChange>>>,
    fail_remove_ip: bool,
}

#[async_trait::async_trait]
impl IfConfiguerTrait for RecordingIfConfiger {
    async fn add_ipv4_route_with_source_hint(
        &self,
        _name: &str,
        address: Ipv4Addr,
        prefix: u8,
        cost: Option<i32>,
        source_hint: Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        self.routes.lock().unwrap().push(RouteChange::Add(
            SharedIpv4Route::new(address, prefix, cost),
            source_hint,
        ));
        Ok(())
    }

    async fn remove_ipv4_route_with_cost_and_source_hint(
        &self,
        _name: &str,
        address: Ipv4Addr,
        prefix: u8,
        cost: Option<i32>,
        source_hint: Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        self.routes.lock().unwrap().push(RouteChange::Remove(
            SharedIpv4Route::new(address, prefix, cost),
            source_hint,
        ));
        Ok(())
    }

    async fn remove_ip(&self, _name: &str, _ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if self.fail_remove_ip {
            return Err(anyhow::anyhow!("forced remove_ip failure").into());
        }
        Ok(())
    }
}

async fn set_ifcfg(nic: &SharedVirtualNic, ifcfg: RecordingIfConfiger) {
    let mut device = nic.nic.lock().await;
    device.set_ifname_for_test("et0".to_owned());
    device.set_ifcfg_for_test(Box::new(ifcfg));
}

#[tokio::test]
async fn conflicting_claims_leave_existing_configuration_intact() {
    for configure_os in [true, false] {
        let mut nic = SharedVirtualNic::new(virtual_nic_config(1500, None));
        let mut healthy = address_claims("10.144.1.1/24");
        healthy
            .ipv6_addresses
            .insert("fd00:1::1/64".parse().unwrap());
        nic.ifcfg.apply_member_claims(MEMBER, healthy.clone());
        let original = nic.ifcfg.effective();

        let mut conflicting_ipv6 = address_claims("10.144.2.1/24");
        // IPv4 is disjoint, but the later IPv6 claim overlaps the healthy member.
        conflicting_ipv6
            .ipv6_addresses
            .insert("fd00:1::2/64".parse().unwrap());
        let conflicting_route = SharedIfConfigClaims {
            ipv4_routes: BTreeSet::from([SharedIpv4Route::new(
                "10.144.0.0".parse().unwrap(),
                16,
                None,
            )]),
            ..Default::default()
        };
        for claims in [conflicting_ipv6, conflicting_route] {
            let rejected_member = uuid::Uuid::from_u128(2);
            let err = nic
                .apply_member_claims(rejected_member, claims, configure_os)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("overlaps member"));
            assert_eq!(nic.ifcfg.claims_of(MEMBER), healthy);
            assert_eq!(
                nic.ifcfg.claims_of(rejected_member),
                SharedIfConfigClaims::default()
            );
            assert!(nic.is_valid());
        }
        assert_eq!(nic.ifcfg.effective(), original);
    }
}

#[tokio::test]
async fn mobile_claims_do_not_configure_the_os_interface() {
    // There is no OS interface or ifname; native ifcfg calls would fail.
    let mut nic = SharedVirtualNic::new(virtual_nic_config(1500, None));
    let claims = SharedIfConfigClaims {
        ipv4_addresses: BTreeSet::from(["10.144.1.1/24".parse().unwrap()]),
        ipv6_addresses: BTreeSet::from(["fd00:1::1/64".parse().unwrap()]),
        ipv4_routes: BTreeSet::from([SharedIpv4Route::new(
            "10.145.0.0".parse().unwrap(),
            16,
            None,
        )]),
        ipv6_routes: BTreeSet::from([SharedIpv6Route::new("fd00:2::".parse().unwrap(), 64, None)]),
        mtu: Some(1300),
    };
    for claims in [claims, SharedIfConfigClaims::default()] {
        nic.apply_member_claims(MEMBER, claims.clone(), false)
            .await
            .unwrap();
        assert_eq!(nic.ifcfg.claims_of(MEMBER), claims);
        assert!(nic.is_valid());
    }
    #[cfg(mobile)]
    {
        nic.member_registrations.insert(MEMBER, REGISTRATION);
        nic.link_up().await.unwrap();
        nic.apply_member_mtu_for_registration(MEMBER, REGISTRATION, 1200)
            .await
            .unwrap();
        assert_eq!(nic.ifcfg.claims_of(MEMBER).mtu, Some(1200));
    }
}

#[tokio::test]
async fn stale_registration_cannot_update_or_remove_current_claims() {
    let mut nic = registered_nic();
    let original = nic.ifcfg.effective();
    let stale = uuid::Uuid::from_u128(9);
    nic.apply_member_claims_for_registration(MEMBER, stale, SharedIfConfigClaims::default())
        .await
        .unwrap();
    nic.apply_member_mtu_for_registration(MEMBER, stale, 1200)
        .await
        .unwrap();
    nic.remove_member_registration_claims(MEMBER, stale)
        .await
        .unwrap();
    assert_eq!(nic.ifcfg.effective(), original);
    assert_eq!(nic.member_registrations.get(&MEMBER), Some(&REGISTRATION));
}

#[cfg(not(mobile))]
#[tokio::test]
async fn failed_cleanup_and_replacement_invalidate_without_committing_claims() {
    for replacing in [false, true] {
        let mut nic = registered_nic();
        let original = nic.ifcfg.effective();
        set_ifcfg(
            &nic,
            RecordingIfConfiger {
                fail_remove_ip: true,
                ..Default::default()
            },
        )
        .await;
        let result = if replacing {
            nic.attach_member_registration(MEMBER, uuid::Uuid::from_u128(11))
                .await
        } else {
            nic.remove_member_registration_claims(MEMBER, REGISTRATION)
                .await
        };
        assert!(result.is_err(), "replacing={replacing}");
        assert!(!nic.is_valid());
        assert_eq!(nic.ifcfg.effective(), original);
        assert_eq!(
            nic.member_registrations.get(&MEMBER).copied(),
            replacing.then_some(REGISTRATION)
        );
    }
}

#[tokio::test]
async fn changed_route_source_is_removed_before_its_replacement_is_added() {
    let route = SharedIpv4Route::new("10.90.2.0".parse().unwrap(), 24, Some(10));
    let fallback = "10.1.2.1".parse().unwrap();
    let preferred = "10.90.2.1".parse().unwrap();
    for adding_owner in [true, false] {
        let mut nic = SharedVirtualNic::new(virtual_nic_config(1500, None));
        let ifcfg = RecordingIfConfiger::default();
        set_ifcfg(&nic, ifcfg.clone()).await;
        let mut claims = address_claims("10.1.2.1/24");
        claims.ipv4_routes.insert(route.clone());
        nic.ifcfg.apply_member_claims(MEMBER, claims);
        let mut with_owner = nic.ifcfg.clone();
        let mut claims = address_claims("10.90.2.1/24");
        claims.ipv4_routes.insert(route.clone());
        with_owner.apply_member_claims(uuid::Uuid::from_u128(2), claims);
        let (next, old_source, new_source) = if adding_owner {
            (with_owner, fallback, preferred)
        } else {
            (
                std::mem::replace(&mut nic.ifcfg, with_owner),
                preferred,
                fallback,
            )
        };
        nic.apply_ifcfg_update(&next).await.unwrap();
        let changes = ifcfg.routes.lock().unwrap();
        let mut expected = vec![
            RouteChange::Remove(route.clone(), Some(old_source)),
            RouteChange::Add(route.clone(), Some(new_source)),
        ];
        if cfg!(target_os = "linux") && !adding_owner {
            expected.push(RouteChange::Add(route.clone(), Some(new_source)));
        }
        assert_eq!(*changes, expected, "adding_owner={adding_owner}");
    }
}

#[tokio::test]
async fn removing_route_preserves_its_old_cost_and_source_hint() {
    let kept = SharedIpv4Route::new("10.90.4.0".parse().unwrap(), 24, Some(10));
    let removed = SharedIpv4Route {
        cost: Some(20),
        ..kept.clone()
    };
    let source = "10.90.4.1".parse().unwrap();
    let mut nic = SharedVirtualNic::new(virtual_nic_config(1500, None));
    let ifcfg = RecordingIfConfiger::default();
    set_ifcfg(&nic, ifcfg.clone()).await;
    let mut claims = address_claims("10.90.4.1/24");
    claims.ipv4_routes.extend([kept.clone(), removed.clone()]);
    nic.ifcfg.apply_member_claims(MEMBER, claims.clone());
    claims.ipv4_routes.remove(&removed);
    let mut next = nic.ifcfg.clone();
    next.apply_member_claims(MEMBER, claims);
    nic.apply_ifcfg_update(&next).await.unwrap();
    assert_eq!(
        *ifcfg.routes.lock().unwrap(),
        [RouteChange::Remove(removed, Some(source))]
    );
}

fn create_member(
    registry: &mut SharedVirtualNicRegistry,
    dev_name: &str,
    mtu: u32,
    netns: Option<&str>,
) -> SharedVirtualNicMember {
    registry.create_member(
        dev_name.to_owned(),
        virtual_nic_config(mtu, netns),
        uuid::Uuid::new_v4(),
        Arc::new(Notify::new()),
    )
}

#[test]
fn registry_shares_devices_only_within_the_same_name_and_namespace() {
    let mut registry = SharedVirtualNicRegistry::new();
    let first = create_member(&mut registry, "et0", 1400, Some("net-a"));
    for (name, netns, shared) in [
        ("et0", Some("net-a"), true),
        ("et0", Some("net-b"), false),
        ("et1", Some("net-a"), false),
        ("et0", None, false),
    ] {
        let next = create_member(&mut registry, name, 1300, netns);
        assert_eq!(Arc::ptr_eq(&first.shared_nic, &next.shared_nic), shared);
        assert_eq!(next.configured_mtu, 1300);
    }
    assert_eq!(first.configured_mtu, 1400);
}

#[test]
fn registry_replaces_invalid_devices() {
    let mut registry = SharedVirtualNicRegistry::new();
    let first = create_member(&mut registry, "et0", 1500, None);
    first.shared_nic.try_lock().unwrap().mark_invalid();
    assert!(
        registry
            .get("et0", &virtual_nic_config(1500, None))
            .is_none()
    );
    let next = create_member(&mut registry, "et0", 1500, None);
    assert!(!Arc::ptr_eq(&first.shared_nic, &next.shared_nic));
    assert!(Arc::ptr_eq(
        &registry
            .get("et0", &virtual_nic_config(1500, None))
            .unwrap(),
        &next.shared_nic,
    ));
}
