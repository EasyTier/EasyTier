#![cfg(all(feature = "magic-dns", feature = "tun"))]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::common::config::TomlConfigLoader;
use crate::common::global_ctx::tests::get_mock_global_ctx;
use crate::common::global_ctx::GlobalCtx;
use crate::connector::udp_hole_punch::tests::replace_stun_info_collector;
use crate::dns::node::DnsNode;
use crate::dns::peer_mgr::DnsPeerMgr;
use crate::dns::config::zone::ZoneConfigInner;
use crate::instance::instance::ArcNicCtx;
use crate::instance::virtual_nic::NicCtx;
use crate::peers::create_packet_recv_chan;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};
use crate::peers::tests::{connect_peer_manager, wait_route_appear};
use crate::proto::common::NatType;
use cidr::Ipv4Inet;
use hickory_client::client::{Client, ClientHandle as _};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr;
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::Protocol;
use hickory_server::authority::MessageRequest;
use hickory_server::server::Request;
use tokio::sync::Notify;

pub async fn prepare_env(dns_name: &str, tun_ip: Ipv4Inet) -> (Arc<PeerManager>, NicCtx) {
    prepare_env_with_tld_dns_zone(dns_name, tun_ip, None).await
}

pub async fn prepare_env_with_tld_dns_zone(
    dns_name: &str,
    tun_ip: Ipv4Inet,
    tld_dns_zone: Option<&str>,
) -> (Arc<PeerManager>, NicCtx) {
    let ctx = get_mock_global_ctx();
    ctx.set_hostname(dns_name.to_owned());
    ctx.set_ipv4(Some(tun_ip));

    let mut dns_config = ctx.config.get_dns();
    dns_config.set_name(dns_name);
    if let Some(zone) = tld_dns_zone {
        dns_config.domain = zone.parse().expect("invalid test dns zone");
    }
    ctx.config.set_dns(Some(dns_config));

    let (s, r) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, ctx, s));
    peer_mgr.run().await.unwrap();
    replace_stun_info_collector(peer_mgr.clone(), NatType::PortRestricted);

    let r = Arc::new(tokio::sync::Mutex::new(r));
    let mut virtual_nic = NicCtx::new(
        peer_mgr.get_global_ctx(),
        &peer_mgr,
        r,
        Arc::new(Notify::new()),
    );
    virtual_nic.run(Some(tun_ip), None).await.unwrap();

    (peer_mgr, virtual_nic)
}

pub fn start_dns_node(peer_mgr: Arc<PeerManager>, virtual_nic: NicCtx) -> DnsNode {
    let global_ctx = peer_mgr.get_global_ctx();
    let nic_ctx: ArcNicCtx = Arc::new(tokio::sync::Mutex::new(Some(Box::new(virtual_nic))));

    let dns_node = DnsNode::new(peer_mgr, global_ctx, nic_ctx);
    dns_node.start();
    dns_node
}

pub fn start_dns_node_without_nic(peer_mgr: Arc<PeerManager>) -> DnsNode {
    let global_ctx = peer_mgr.get_global_ctx();
    let nic_ctx: ArcNicCtx = Arc::new(tokio::sync::Mutex::new(None));

    let dns_node = DnsNode::new(peer_mgr, global_ctx, nic_ctx);
    dns_node.start();
    dns_node
}

pub async fn prepare_env_from_config_str(config_str: &str) -> Arc<PeerManager> {
    let config = TomlConfigLoader::new_from_str(config_str).expect("invalid test config");
    let ctx = Arc::new(GlobalCtx::new(config));

    let (s, _r) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, ctx, s));
    peer_mgr.run().await.unwrap();
    replace_stun_info_collector(peer_mgr.clone(), NatType::PortRestricted);

    peer_mgr
}

fn find_free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("failed to bind temp udp socket")
        .local_addr()
        .expect("failed to get local addr")
        .port()
}

pub async fn check_dns_record(fake_ip: &Ipv4Addr, domain: &str, expected_ip: &str) {
    check_dns_record_at(SocketAddr::new((*fake_ip).into(), 53), domain, expected_ip).await;
}

pub async fn check_dns_record_at(server_addr: SocketAddr, domain: &str, expected_ip: &str) {
    let expected = expected_ip.parse::<Ipv4Addr>().unwrap();
    let name = rr::Name::from_str(domain).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        let stream = UdpClientStream::builder(server_addr, TokioRuntimeProvider::default()).build();
        let (mut client, background) = Client::connect(stream).await.unwrap();
        let background_task = tokio::spawn(background);

        let query_result = tokio::time::timeout(
            Duration::from_secs(2),
            client.query(name.clone(), rr::DNSClass::IN, rr::RecordType::A),
        )
        .await;

        background_task.abort();
        let _ = background_task.await;

        let attempt_err = match query_result {
            Ok(Ok(response)) => {
                if response.answers().len() == 1 {
                    if let Some(resp) = response.answers().first() {
                        if resp.clone().into_parts().rdata.into_a().unwrap().0 == expected {
                            return;
                        }
                    }
                }
                format!("unexpected response: {:?}", response.answers())
            }
            Ok(Err(e)) => {
                format!("DNS query failed for domain '{domain}': {e}")
            }
            Err(_) => {
                format!("DNS query timed out for domain '{domain}'")
            }
        };

        if Instant::now() >= deadline {
            panic!(
                "DNS query failed unexpectedly for domain '{domain}' after retries: {attempt_err}"
            );
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn check_dns_record_missing(fake_ip: &Ipv4Addr, domain: &str) {
    check_dns_record_missing_at(SocketAddr::new((*fake_ip).into(), 53), domain).await;
}

pub async fn check_dns_record_missing_at(server_addr: SocketAddr, domain: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        let stream = UdpClientStream::builder(server_addr, TokioRuntimeProvider::default()).build();
        let (mut client, background) = Client::connect(stream).await.unwrap();
        let background_task = tokio::spawn(background);
        let query_result = tokio::time::timeout(
            Duration::from_secs(2),
            client.query(
                rr::Name::from_str(domain).unwrap(),
                rr::DNSClass::IN,
                rr::RecordType::A,
            ),
        )
        .await;
        background_task.abort();
        let _ = background_task.await;

        let attempt_err = match query_result {
            Ok(Ok(response)) => {
                if response.answers().is_empty() {
                    return;
                }
                format!("unexpected non-empty response: {:?}", response.answers())
            }
            Ok(Err(e)) => {
                format!("DNS query for missing record failed for domain '{domain}': {e}")
            }
            Err(_) => {
                format!("DNS query for missing record timed out for domain '{domain}'")
            }
        };

        if Instant::now() >= deadline {
            panic!(
                "missing-record query failed unexpectedly for domain '{domain}' after retries: {attempt_err}"
            );
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub fn new_request(name: &str, rtype: RecordType) -> anyhow::Result<Request> {
    let mut query = Message::new();
    query.set_id(0);
    query.set_message_type(MessageType::Query);
    query.set_op_code(OpCode::Query);
    query.set_recursion_desired(true);
    query.add_query(Query::query(Name::from_ascii(name)?, rtype));

    let mut request = Vec::new();
    let mut encoder = BinEncoder::new(&mut request);
    query.emit(&mut encoder)?;

    Ok(Request::new(
        MessageRequest::from_bytes(&request)?,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
        Protocol::Udp,
    ))
}

async fn wait_route_disappear(peer_mgr: Arc<PeerManager>, target_peer_id: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let has_route = peer_mgr
            .list_routes()
            .await
            .iter()
            .any(|r| r.peer_id == target_peer_id);
        if !has_route {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "route to peer {} did not disappear in time",
            target_peer_id
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn disconnect_all_peer_conns(a: Arc<PeerManager>, b: Arc<PeerManager>) {
    if let Some(conns) = a.get_peer_map().list_peer_conns(b.my_peer_id()).await {
        for conn in conns {
            let conn_id = conn.conn_id.parse().expect("invalid conn id");
            let _ = a.close_peer_conn(b.my_peer_id(), &conn_id).await;
        }
    }
    if let Some(conns) = b.get_peer_map().list_peer_conns(a.my_peer_id()).await {
        for conn in conns {
            let conn_id = conn.conn_id.parse().expect("invalid conn id");
            let _ = b.close_peer_conn(a.my_peer_id(), &conn_id).await;
        }
    }
}

async fn check_dns_unavailable_at(server_addr: SocketAddr, domain: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let name = rr::Name::from_str(domain).unwrap();

    loop {
        let stream = UdpClientStream::builder(server_addr, TokioRuntimeProvider::default()).build();
        let connect = Client::connect(stream).await;

        if let Ok((mut client, background)) = connect {
            let background_task = tokio::spawn(background);
            let query_result = tokio::time::timeout(
                Duration::from_secs(1),
                client.query(name.clone(), rr::DNSClass::IN, rr::RecordType::A),
            )
            .await;

            background_task.abort();
            let _ = background_task.await;

            match query_result {
                Ok(Ok(response)) if !response.answers().is_empty() => {
                    if Instant::now() >= deadline {
                        panic!(
                            "DNS endpoint {server_addr} still answered for '{domain}': {:?}",
                            response.answers()
                        );
                    }
                }
                _ => return,
            }
        } else {
            return;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_peer_zone_visibility(
    peer_mgr: Arc<PeerManager>,
    target_peer_id: u32,
    zone_origin_substr: &str,
    expected_visible: bool,
) {
    let dns = DnsPeerMgr::new(peer_mgr.clone(), peer_mgr.get_global_ctx());
    let deadline = Instant::now() + Duration::from_secs(20);

    loop {
        dns.refresh(target_peer_id).await;
        let visible = dns
            .snapshot()
            .zones
            .iter()
            .any(|z| z.origin.contains(zone_origin_substr));

        if visible == expected_visible {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "zone visibility mismatch for '{}': expected {}, got {}",
            zone_origin_substr,
            expected_visible,
            visible
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn cfg_with_listener(name: &str, ipv4: &str, domain: &str, listener_port: u16) -> String {
    format!(
        r#"
instance_name = "dns-int-{name}"
ipv4 = "{ipv4}"

[dns]
name = "{name}"
domain = "{domain}"
listeners = ["udp://127.0.0.1:{listener_port}"]
"#
    )
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_single_node_resolves_self_and_custom_zone() {
    let listener_port = find_free_udp_port();
    let config = format!(
        r#"
{}

[[dns.zone]]
origin = "services.alpha.et-test"
records = ["api IN A 10.77.0.7"]

[dns.zone.export]
whitelist = ["*"]
"#,
        cfg_with_listener("alpha", "10.144.144.11/24", "et-test", listener_port)
    );

    let peer_mgr = prepare_env_from_config_str(&config).await;
    let dns_node = start_dns_node_without_nic(peer_mgr);

    let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_port);
    check_dns_record_at(server_addr, "alpha.et-test.", "10.144.144.11").await;
    check_dns_record_at(server_addr, "api.services.alpha.et-test.", "10.77.0.7").await;

    dns_node.stop().await.unwrap();
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_two_nodes_sync_self_zone_and_exported_zone() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();

    let config_a = format!(
        r#"
{}

[[dns.zone]]
origin = "shared.mesh-test"
records = ["app IN A 10.66.0.8"]

[dns.zone.export]
whitelist = ["*"]
"#,
        cfg_with_listener("node-a", "10.144.144.21/24", "mesh-test", listener_a)
    );

    let config_b = cfg_with_listener("node-b", "10.144.144.22/24", "mesh-test", listener_b);

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;
    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .expect("route should appear");

    let node_a = start_dns_node_without_nic(peer_a);
    let node_b = start_dns_node_without_nic(peer_b);

    let addr_a = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_a);
    let addr_b = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_b);

    check_dns_record_at(addr_a, "node-b.mesh-test.", "10.144.144.22").await;
    check_dns_record_at(addr_b, "node-b.mesh-test.", "10.144.144.22").await;
    check_dns_record_at(addr_a, "app.shared.mesh-test.", "10.66.0.8").await;
    check_dns_record_at(addr_b, "app.shared.mesh-test.", "10.66.0.8").await;

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_zone_without_export_section_is_not_synced() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();

    let config_a = format!(
        r#"
{}

[[dns.zone]]
origin = "private.mesh-test"
records = ["secret IN A 10.99.0.9"]
"#,
        cfg_with_listener("local-a", "10.144.144.31/24", "mesh-test", listener_a)
    );

    let config_b = cfg_with_listener("local-b", "10.144.144.32/24", "mesh-test", listener_b);

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;
    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .expect("route should appear");

    // Export behavior is determined by whether `[dns.zone.export]` exists.
    // Verify from peer-sync view to avoid host-wide DNS-server election side effects.
    let dns_a = DnsPeerMgr::new(peer_a.clone(), peer_a.get_global_ctx());
    dns_a.register();

    let dns_b = DnsPeerMgr::new(peer_b.clone(), peer_b.get_global_ctx());
    dns_b.refresh(peer_a.my_peer_id()).await;

    let snapshot = dns_b.snapshot();
    assert!(
        !snapshot
            .zones
            .iter()
            .any(|z| z.origin.contains("private.mesh-test")),
        "zone without [dns.zone.export] should not be exported to peer snapshot"
    );
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_export_section_disabled_is_not_synced() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();

    let config_a = format!(
        r#"
{}

[[dns.zone]]
origin = "disabled.mesh-test"
records = ["secret IN A 10.99.1.9"]

[dns.zone.export]
disabled = true
"#,
        cfg_with_listener("local-da", "10.144.144.41/24", "mesh-test", listener_a)
    );

    let config_b = cfg_with_listener("local-db", "10.144.144.42/24", "mesh-test", listener_b);

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;
    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .expect("route should appear");

    let dns_a = DnsPeerMgr::new(peer_a.clone(), peer_a.get_global_ctx());
    dns_a.register();

    let dns_b = DnsPeerMgr::new(peer_b.clone(), peer_b.get_global_ctx());
    dns_b.refresh(peer_a.my_peer_id()).await;

    let snapshot = dns_b.snapshot();
    assert!(
        !snapshot
            .zones
            .iter()
            .any(|z| z.origin.contains("disabled.mesh-test")),
        "zone with [dns.zone.export] disabled=true should not be exported"
    );
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_patch_updates_zone_record_visible_on_query() {
    let listener = find_free_udp_port();
    let config = format!(
        r#"
{}

[[dns.zone]]
origin = "patch.mesh-test"
records = ["api IN A 10.80.0.1"]

[dns.zone.export]
"#,
        cfg_with_listener("patch-node", "10.144.149.11/24", "mesh-test", listener)
    );

    let peer = prepare_env_from_config_str(&config).await;
    let dns_node = start_dns_node_without_nic(peer.clone());
    let server_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener);

    check_dns_record_at(server_addr, "api.patch.mesh-test.", "10.80.0.1").await;

    let mut dns = peer.get_global_ctx().config.get_dns();
    let zone_idx = dns
        .zones
        .iter()
        .position(|z| z.origin.to_string().contains("patch.mesh-test"))
        .expect("patch zone should exist");
    let mut zone: ZoneConfigInner = dns.zones[zone_idx].clone().into();
    zone.records = vec!["api IN A 10.80.0.2".to_string()];
    dns.zones[zone_idx] = zone.try_into().expect("patch zone update should be valid");
    peer.get_global_ctx().config.set_dns(Some(dns));
    peer.get_global_ctx().issue_event(
        crate::common::global_ctx::GlobalCtxEvent::ConfigPatched(
            crate::proto::api::config::InstanceConfigPatch::default(),
        ),
    );

    check_dns_record_at(server_addr, "api.patch.mesh-test.", "10.80.0.2").await;

    dns_node.stop().await.unwrap();
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_patch_reloads_listener_binding() {
    let listener_old = find_free_udp_port();
    let listener_new = find_free_udp_port();
    let config = cfg_with_listener("listener-patch", "10.144.150.11/24", "mesh-test", listener_old);

    let peer = prepare_env_from_config_str(&config).await;
    let dns_node = start_dns_node_without_nic(peer.clone());

    let old_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_old);
    let new_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_new);
    check_dns_record_at(old_addr, "listener-patch.mesh-test.", "10.144.150.11").await;

    let mut dns = peer.get_global_ctx().config.get_dns();
    dns.listeners = vec![format!("udp://127.0.0.1:{listener_new}")
        .parse()
        .expect("invalid listener")]
    .into();
    peer.get_global_ctx().config.set_dns(Some(dns));
    peer.get_global_ctx().issue_event(
        crate::common::global_ctx::GlobalCtxEvent::ConfigPatched(
            crate::proto::api::config::InstanceConfigPatch::default(),
        ),
    );

    check_dns_record_at(new_addr, "listener-patch.mesh-test.", "10.144.150.11").await;
    check_dns_unavailable_at(old_addr, "listener-patch.mesh-test.").await;

    dns_node.stop().await.unwrap();
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_three_nodes_partition_and_recover_dns_propagation() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();
    let listener_c = find_free_udp_port();

    let config_a = cfg_with_listener("node-a7", "10.144.151.11/24", "mesh7-test", listener_a);
    let config_b = cfg_with_listener("node-b7", "10.144.151.12/24", "mesh7-test", listener_b);
    let config_c = format!(
        r#"
{}

[[dns.zone]]
origin = "shared-c7.mesh7-test"
records = ["svc IN A 10.77.7.7"]

[dns.zone.export]
"#,
        cfg_with_listener("node-c7", "10.144.151.13/24", "mesh7-test", listener_c)
    );

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;
    let peer_c = prepare_env_from_config_str(&config_c).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;
    wait_route_appear(peer_a.clone(), peer_c.clone())
        .await
        .expect("route a-c should appear via b");

    let node_a = start_dns_node_without_nic(peer_a.clone());
    let node_b = start_dns_node_without_nic(peer_b.clone());
    let node_c = start_dns_node_without_nic(peer_c.clone());

    let addr_a = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_a);
    check_dns_record_at(addr_a, "node-c7.mesh7-test.", "10.144.151.13").await;
    check_dns_record_at(addr_a, "svc.shared-c7.mesh7-test.", "10.77.7.7").await;
    wait_peer_zone_visibility(peer_a.clone(), peer_c.my_peer_id(), "node-c7.mesh7-test", true).await;
    wait_peer_zone_visibility(
        peer_a.clone(),
        peer_c.my_peer_id(),
        "shared-c7.mesh7-test",
        true,
    )
    .await;

    disconnect_all_peer_conns(peer_b.clone(), peer_c.clone()).await;
    wait_route_disappear(peer_a.clone(), peer_c.my_peer_id()).await;
    // Validate via peer-sync snapshot to avoid process-wide DNS-server election side effects.
    wait_peer_zone_visibility(peer_a.clone(), peer_c.my_peer_id(), "node-c7.mesh7-test", false)
        .await;
    wait_peer_zone_visibility(
        peer_a.clone(),
        peer_c.my_peer_id(),
        "shared-c7.mesh7-test",
        false,
    )
    .await;

    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;
    wait_route_appear(peer_a.clone(), peer_c.clone())
        .await
        .expect("route a-c should recover via b");

    wait_peer_zone_visibility(peer_a.clone(), peer_c.my_peer_id(), "node-c7.mesh7-test", true).await;
    wait_peer_zone_visibility(
        peer_a.clone(),
        peer_c.my_peer_id(),
        "shared-c7.mesh7-test",
        true,
    )
    .await;

    check_dns_record_at(addr_a, "node-c7.mesh7-test.", "10.144.151.13").await;
    check_dns_record_at(addr_a, "svc.shared-c7.mesh7-test.", "10.77.7.7").await;

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
    node_c.stop().await.unwrap();
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_three_nodes_chain_sync_self_and_exported_zone() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();
    let listener_c = find_free_udp_port();

    let config_a = cfg_with_listener("node-a3", "10.144.145.11/24", "mesh3-test", listener_a);
    let config_b = cfg_with_listener("node-b3", "10.144.145.12/24", "mesh3-test", listener_b);
    let config_c = format!(
        r#"
{}

[[dns.zone]]
origin = "shared-c.mesh3-test"
records = ["api IN A 10.66.1.8"]

[dns.zone.export]
"#,
        cfg_with_listener("node-c3", "10.144.145.13/24", "mesh3-test", listener_c)
    );

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;
    let peer_c = prepare_env_from_config_str(&config_c).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;
    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .expect("route a-b should appear");
    wait_route_appear(peer_b.clone(), peer_c.clone())
        .await
        .expect("route b-c should appear");
    wait_route_appear(peer_a.clone(), peer_c.clone())
        .await
        .expect("route a-c should appear via b");

    let node_a = start_dns_node_without_nic(peer_a);
    let node_b = start_dns_node_without_nic(peer_b);
    let node_c = start_dns_node_without_nic(peer_c);

    let addr_a = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_a);
    let addr_b = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_b);
    let addr_c = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_c);

    check_dns_record_at(addr_a, "node-c3.mesh3-test.", "10.144.145.13").await;
    check_dns_record_at(addr_b, "node-c3.mesh3-test.", "10.144.145.13").await;
    check_dns_record_at(addr_c, "node-a3.mesh3-test.", "10.144.145.11").await;
    check_dns_record_at(addr_a, "api.shared-c.mesh3-test.", "10.66.1.8").await;
    check_dns_record_at(addr_c, "api.shared-c.mesh3-test.", "10.66.1.8").await;

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
    node_c.stop().await.unwrap();
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_three_nodes_late_join_propagates_dns() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();
    let listener_c = find_free_udp_port();

    let config_a = cfg_with_listener("node-a4", "10.144.146.11/24", "mesh4-test", listener_a);
    let config_b = cfg_with_listener("node-b4", "10.144.146.12/24", "mesh4-test", listener_b);
    let config_c = format!(
        r#"
{}

[[dns.zone]]
origin = "joined.mesh4-test"
records = ["svc IN A 10.66.2.8"]

[dns.zone.export]
"#,
        cfg_with_listener("node-c4", "10.144.146.13/24", "mesh4-test", listener_c)
    );

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;
    let peer_c = prepare_env_from_config_str(&config_c).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .expect("route a-b should appear");

    let node_a = start_dns_node_without_nic(peer_a.clone());
    let node_b = start_dns_node_without_nic(peer_b.clone());

    let addr_a = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener_a);
    check_dns_record_missing_at(addr_a, "node-c4.mesh4-test.").await;

    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;
    wait_route_appear(peer_b.clone(), peer_c.clone())
        .await
        .expect("route b-c should appear");
    wait_route_appear(peer_a.clone(), peer_c.clone())
        .await
        .expect("route a-c should appear after c joins");

    let node_c = start_dns_node_without_nic(peer_c);

    check_dns_record_at(addr_a, "node-c4.mesh4-test.", "10.144.146.13").await;
    check_dns_record_at(addr_a, "svc.joined.mesh4-test.", "10.66.2.8").await;

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
    node_c.stop().await.unwrap();
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_three_nodes_zone_without_export_not_synced_across_hop() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();
    let listener_c = find_free_udp_port();

    let config_a = cfg_with_listener("node-a5", "10.144.147.11/24", "mesh5-test", listener_a);
    let config_b = cfg_with_listener("node-b5", "10.144.147.12/24", "mesh5-test", listener_b);
    let config_c = format!(
        r#"
{}

[[dns.zone]]
origin = "private-c.mesh5-test"
records = ["secret IN A 10.66.3.8"]
"#,
        cfg_with_listener("node-c5", "10.144.147.13/24", "mesh5-test", listener_c)
    );

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;
    let peer_c = prepare_env_from_config_str(&config_c).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    connect_peer_manager(peer_b.clone(), peer_c.clone()).await;
    wait_route_appear(peer_a.clone(), peer_c.clone())
        .await
        .expect("route a-c should appear via b");

    let dns_c = DnsPeerMgr::new(peer_c.clone(), peer_c.get_global_ctx());
    dns_c.register();

    let dns_a = DnsPeerMgr::new(peer_a.clone(), peer_a.get_global_ctx());
    dns_a.refresh(peer_c.my_peer_id()).await;

    let snapshot = dns_a.snapshot();
    assert!(
        !snapshot
            .zones
            .iter()
            .any(|z| z.origin.contains("private-c.mesh5-test")),
        "zone without [dns.zone.export] should not sync over multi-hop"
    );
}

#[tokio::test]
#[serial_test::serial(dns_integration_rpc)]
async fn config_string_two_nodes_peer_dns_offline_then_rejoin() {
    let listener_a = find_free_udp_port();
    let listener_b = find_free_udp_port();

    let config_a = cfg_with_listener("node-a6", "10.144.148.11/24", "mesh6-test", listener_a);
    let config_b = cfg_with_listener("node-b6", "10.144.148.12/24", "mesh6-test", listener_b);

    let peer_a = prepare_env_from_config_str(&config_a).await;
    let peer_b = prepare_env_from_config_str(&config_b).await;

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .expect("route should appear");

    let dns_b = DnsPeerMgr::new(peer_b.clone(), peer_b.get_global_ctx());
    dns_b.register();

    let dns_a_online = DnsPeerMgr::new(peer_a.clone(), peer_a.get_global_ctx());
    dns_a_online.refresh(peer_b.my_peer_id()).await;
    assert!(
        dns_a_online
            .snapshot()
            .zones
            .iter()
            .any(|z| z.origin.contains("node-b6.mesh6-test")),
        "peer B self zone should be visible after initial refresh"
    );

    // Simulate peer offline by closing all direct connections and waiting route withdrawal.
    if let Some(conns) = peer_a
        .get_peer_map()
        .list_peer_conns(peer_b.my_peer_id())
        .await
    {
        for conn in conns {
            let conn_id = conn.conn_id.parse().expect("invalid conn id");
            let _ = peer_a.close_peer_conn(peer_b.my_peer_id(), &conn_id).await;
        }
    }
    if let Some(conns) = peer_b
        .get_peer_map()
        .list_peer_conns(peer_a.my_peer_id())
        .await
    {
        for conn in conns {
            let conn_id = conn.conn_id.parse().expect("invalid conn id");
            let _ = peer_b.close_peer_conn(peer_a.my_peer_id(), &conn_id).await;
        }
    }

    wait_route_disappear(peer_a.clone(), peer_b.my_peer_id()).await;
    wait_route_disappear(peer_b.clone(), peer_a.my_peer_id()).await;

    // Cached remote zones should be purged after peer cache idle timeout.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let dns_a_offline = DnsPeerMgr::new(peer_a.clone(), peer_a.get_global_ctx());
    assert!(
        !dns_a_offline
            .snapshot()
            .zones
            .iter()
            .any(|z| z.origin.contains("node-b6.mesh6-test")),
        "peer B self zone should disappear after route withdrawal and cache expiry"
    );

    connect_peer_manager(peer_a.clone(), peer_b.clone()).await;
    wait_route_appear(peer_a.clone(), peer_b.clone())
        .await
        .expect("route should re-appear");

    let dns_a_rejoin = DnsPeerMgr::new(peer_a.clone(), peer_a.get_global_ctx());
    dns_a_rejoin.refresh(peer_b.my_peer_id()).await;
    assert!(
        dns_a_rejoin
            .snapshot()
            .zones
            .iter()
            .any(|z| z.origin.contains("node-b6.mesh6-test")),
        "peer B self zone should be restored after DNS RPC rejoins"
    );
}
