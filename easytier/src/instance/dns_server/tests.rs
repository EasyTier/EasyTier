use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use cidr::Ipv4Inet;
use hickory_client::client::{Client, ClientHandle as _};
use hickory_proto::rr;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::tests::get_mock_global_ctx;
use crate::connector::udp_hole_punch::tests::replace_stun_info_collector;

use crate::instance::dns_server::runner::DnsRunner;
use crate::instance::dns_server::server_instance::MagicDnsServerInstance;
use crate::instance::dns_server::{DEFAULT_ET_DNS_ZONE, MAGIC_DNS_FAKE_IP};
use crate::instance::virtual_nic::NicCtx;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};

use crate::peers::create_packet_recv_chan;
use crate::proto::api::instance::Route;
use crate::proto::common::NatType;
use crate::proto::magic_dns::{MagicDnsServerRpc as _, UpdateDnsRecordRequest};
use crate::proto::rpc_types::controller::{BaseController, Controller as _};

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

    if tld_dns_zone.is_some() {
        let mut flags = ctx.config.get_flags();
        flags.accept_dns = true; // Enable DNS
        if let Some(zone) = tld_dns_zone {
            flags.tld_dns_zone = zone.to_string();
        }
        ctx.config.set_flags(flags);
    }

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

pub async fn check_dns_record(fake_ip: &Ipv4Addr, domain: &str, expected_ip: &str) {
    let stream = UdpClientStream::builder(
        SocketAddr::new((*fake_ip).into(), 53),
        TokioRuntimeProvider::default(),
    )
    .build();
    let (mut client, background) = Client::connect(stream).await.unwrap();
    let background_task = tokio::spawn(background);
    let response = client
        .query(
            rr::Name::from_str(domain).unwrap(),
            rr::DNSClass::IN,
            rr::RecordType::A,
        )
        .await
        .unwrap_or_else(|e| panic!("DNS query failed unexpectedly for domain '{domain}': {e}"));
    background_task.abort();
    let _ = background_task.await;

    println!("Response: {:?}", response);

    assert_eq!(response.answers().len(), 1, "{:?}", response.answers());
    let resp = response.answers().first().unwrap();
    assert_eq!(
        resp.clone().into_parts().rdata.into_a().unwrap().0,
        expected_ip.parse::<Ipv4Addr>().unwrap()
    );
}

pub async fn check_dns_record_missing(fake_ip: &Ipv4Addr, domain: &str) {
    let stream = UdpClientStream::builder(
        SocketAddr::new((*fake_ip).into(), 53),
        TokioRuntimeProvider::default(),
    )
    .build();
    let (mut client, background) = Client::connect(stream).await.unwrap();
    let background_task = tokio::spawn(background);
    let response = client
        .query(
            rr::Name::from_str(domain).unwrap(),
            rr::DNSClass::IN,
            rr::RecordType::A,
        )
        .await
        .unwrap_or_else(|e| {
            panic!("DNS query for missing record failed unexpectedly for domain '{domain}': {e}")
        });
    background_task.abort();
    let _ = background_task.await;
    assert!(response.answers().is_empty(), "{:?}", response.answers());
}

#[tokio::test]
async fn test_magic_dns_server_instance() {
    let tun_ip = Ipv4Inet::from_str("10.144.144.10/24").unwrap();
    let (peer_mgr, virtual_nic) = prepare_env("test1", tun_ip).await;
    let tun_name = virtual_nic.ifname().await.unwrap();
    let fake_ip = Ipv4Addr::from_str("100.100.100.101").unwrap();
    let dns_server_inst =
        MagicDnsServerInstance::new(peer_mgr.clone(), Some(tun_name), tun_ip, fake_ip)
            .await
            .unwrap();

    let routes = [
        Route {
            hostname: "test1".to_string(),
            ipv4_addr: Some(Ipv4Inet::from_str("8.8.8.8/24").unwrap().into()),
            ..Default::default()
        },
        Route {
            hostname: "中文".to_string(),
            ipv4_addr: Some(Ipv4Inet::from_str("8.8.8.8/24").unwrap().into()),
            ..Default::default()
        },
        Route {
            hostname: ".invalid".to_string(),
            ipv4_addr: Some(Ipv4Inet::from_str("8.8.8.8/24").unwrap().into()),
            ..Default::default()
        },
    ];
    dns_server_inst
        .data
        .update_dns_records(routes.iter(), DEFAULT_ET_DNS_ZONE)
        .await
        .unwrap();

    check_dns_record(&fake_ip, "test1.et.net", "8.8.8.8").await;
    check_dns_record(&fake_ip, "中文.et.net", "8.8.8.8").await;
}

#[tokio::test]
async fn test_magic_dns_runner() {
    // Test first runner with default DNS settings
    {
        let tun_ip = Ipv4Inet::from_str("10.144.144.10/24").unwrap();
        let (peer_mgr, virtual_nic) = prepare_env("test1", tun_ip).await;
        let tun_name = virtual_nic.ifname().await.unwrap();
        let fake_ip = Ipv4Addr::from_str(MAGIC_DNS_FAKE_IP).unwrap();
        let mut dns_runner = DnsRunner::new(peer_mgr, Some(tun_name), tun_ip, fake_ip);

        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let t = tokio::spawn(async move {
            dns_runner.run(cancel_token_clone).await;
        });
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Test default settings: query should resolve test1.et.net to tunnel IP via default fake IP
        check_dns_record(&fake_ip, "test1.et.net", "10.144.144.10").await;

        cancel_token.cancel();
        t.await.unwrap();

        // Wait a bit for cleanup
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Test second runner with different TLD zone
    {
        let tun_ip = Ipv4Inet::from_str("10.144.144.20/24").unwrap();
        // NOTE: Using same fake IP to avoid system DNS configuration conflicts
        let custom_tld_zone = "custom.local."; // Different TLD zone is safer
        let (peer_mgr, virtual_nic) =
            prepare_env_with_tld_dns_zone("test2", tun_ip, Some(custom_tld_zone)).await;
        let tun_name = virtual_nic.ifname().await.unwrap();
        let fake_ip = Ipv4Addr::from_str(MAGIC_DNS_FAKE_IP).unwrap();
        let mut dns_runner = DnsRunner::new(peer_mgr, Some(tun_name), tun_ip, fake_ip);

        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();
        let t = tokio::spawn(async move {
            dns_runner.run(cancel_token_clone).await;
        });
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Test with same fake IP but different TLD zone
        check_dns_record(&fake_ip, "test2.custom.local", "10.144.144.20").await;

        cancel_token.cancel();
        t.await.unwrap();
    }
}

#[tokio::test]
async fn test_magic_dns_update_replaces_records_for_same_client() {
    let tun_ip = Ipv4Inet::from_str("100.100.100.0/24").unwrap();
    let ctx = get_mock_global_ctx();
    ctx.set_hostname("test1".to_string());
    ctx.set_ipv4(Some(tun_ip));

    let (s, _r) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, ctx, s));
    peer_mgr.run().await.unwrap();
    replace_stun_info_collector(peer_mgr.clone(), NatType::PortRestricted);

    let fake_ip = Ipv4Addr::from_str(MAGIC_DNS_FAKE_IP).unwrap();
    let dns_server_inst = MagicDnsServerInstance::new(peer_mgr.clone(), None, tun_ip, fake_ip)
        .await
        .unwrap();

    let mut ctrl = BaseController::default();
    ctrl.set_tunnel_info(Some(crate::proto::common::TunnelInfo {
        tunnel_type: "tcp".to_string(),
        local_addr: None,
        remote_addr: Some(crate::proto::common::Url {
            url: "tcp://127.0.0.1:54321".to_string(),
        }),
    }));

    dns_server_inst
        .data
        .update_dns_record(
            ctrl.clone(),
            UpdateDnsRecordRequest {
                zone: DEFAULT_ET_DNS_ZONE.to_string(),
                routes: vec![Route {
                    hostname: "test1".to_string(),
                    ipv4_addr: Some(Ipv4Inet::from_str("8.8.8.8/32").unwrap().into()),
                    ..Default::default()
                }],
            },
        )
        .await
        .unwrap();

    dns_server_inst
        .data
        .update_dns_record(
            ctrl,
            UpdateDnsRecordRequest {
                zone: DEFAULT_ET_DNS_ZONE.to_string(),
                routes: vec![Route {
                    hostname: "test1".to_string(),
                    ipv4_addr: Some(Ipv4Inet::from_str("1.1.1.1/32").unwrap().into()),
                    ..Default::default()
                }],
            },
        )
        .await
        .unwrap();

    let dns_records = dns_server_inst
        .data
        .get_dns_record(
            BaseController::default(),
            crate::proto::common::Void::default(),
        )
        .await
        .unwrap();
    let zone_records = dns_records.records.get(DEFAULT_ET_DNS_ZONE).unwrap();
    let a_records = zone_records
        .records
        .iter()
        .filter_map(|record| match record.record.as_ref() {
            Some(crate::proto::magic_dns::dns_record::Record::A(a))
                if a.name == "test1.et.net." =>
            {
                Some(a)
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(a_records.len(), 1, "{a_records:?}");
    let resolved_ip = Ipv4Addr::from(a_records[0].value.unwrap_or_default());
    assert_eq!(resolved_ip, Ipv4Addr::new(1, 1, 1, 1));

    let mut ctrl = BaseController::default();
    ctrl.set_tunnel_info(Some(crate::proto::common::TunnelInfo {
        tunnel_type: "tcp".to_string(),
        local_addr: None,
        remote_addr: Some(crate::proto::common::Url {
            url: "tcp://127.0.0.1:54321".to_string(),
        }),
    }));

    dns_server_inst
        .data
        .update_dns_record(
            ctrl,
            UpdateDnsRecordRequest {
                zone: DEFAULT_ET_DNS_ZONE.to_string(),
                routes: vec![],
            },
        )
        .await
        .unwrap();

    let dns_records = dns_server_inst
        .data
        .get_dns_record(
            BaseController::default(),
            crate::proto::common::Void::default(),
        )
        .await
        .unwrap();
    assert!(dns_records.records.get(DEFAULT_ET_DNS_ZONE).is_none());
}
