use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use cidr::Ipv4Inet;
use hickory_client::client::{Client, ClientHandle as _};
use hickory_proto::rr;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::tests::get_mock_global_ctx;
use crate::connector::udp_hole_punch::tests::replace_stun_info_collector;

use crate::instance::dns_server::runner::DnsRunner;
use crate::instance::dns_server::server_instance::MagicDnsServerInstance;
use crate::instance::dns_server::DEFAULT_ET_DNS_ZONE;
use crate::instance::virtual_nic::NicCtx;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};

use crate::peers::create_packet_recv_chan;
use crate::proto::cli::Route;
use crate::proto::common::NatType;

pub async fn prepare_env(dns_name: &str, tun_ip: Ipv4Inet) -> (Arc<PeerManager>, NicCtx) {
    let ctx = get_mock_global_ctx();
    ctx.set_hostname(dns_name.to_owned());
    ctx.set_ipv4(Some(tun_ip));
    let (s, r) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, ctx, s));
    peer_mgr.run().await.unwrap();
    replace_stun_info_collector(peer_mgr.clone(), NatType::PortRestricted);

    let r = Arc::new(tokio::sync::Mutex::new(r));
    let mut virtual_nic = NicCtx::new(peer_mgr.get_global_ctx(), &peer_mgr, r);
    virtual_nic.run(tun_ip).await.unwrap();

    (peer_mgr, virtual_nic)
}

pub async fn check_dns_record(fake_ip: &Ipv4Addr, domain: &str, expected_ip: &str) {
    let stream = UdpClientStream::builder(
        SocketAddr::new(fake_ip.clone().into(), 53),
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
        .unwrap();
    drop(background_task);

    println!("Response: {:?}", response);

    assert_eq!(response.answers().len(), 1, "{:?}", response.answers());
    let resp = response.answers().first().unwrap();
    assert_eq!(
        resp.clone().into_parts().rdata.into_a().unwrap().0,
        expected_ip.parse::<Ipv4Addr>().unwrap()
    );
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

    let routes = vec![Route {
        hostname: "test1".to_string(),
        ipv4_addr: Some(Ipv4Inet::from_str("8.8.8.8/24").unwrap().into()),
        ..Default::default()
    }];
    dns_server_inst
        .data
        .update_dns_records(routes.iter(), DEFAULT_ET_DNS_ZONE)
        .await
        .unwrap();

    check_dns_record(&fake_ip, "test1.et.net", "8.8.8.8").await;
}

#[tokio::test]
async fn test_magic_dns_runner() {
    let tun_ip = Ipv4Inet::from_str("10.144.144.10/24").unwrap();
    let (peer_mgr, virtual_nic) = prepare_env("test1", tun_ip).await;
    let tun_name = virtual_nic.ifname().await.unwrap();
    let fake_ip = Ipv4Addr::from_str("100.100.100.101").unwrap();
    let mut dns_runner = DnsRunner::new(peer_mgr, Some(tun_name), tun_ip, fake_ip);

    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();
    let t = tokio::spawn(async move {
        dns_runner.run(cancel_token_clone).await;
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    check_dns_record(&fake_ip, "test1.et.net", "10.144.144.10").await;

    // add a new dns runner
    let tun_ip2 = Ipv4Inet::from_str("10.144.144.20/24").unwrap();
    let (peer_mgr, virtual_nic) = prepare_env("test2", tun_ip2).await;
    let tun_name2 = virtual_nic.ifname().await.unwrap();
    let mut dns_runner2 = DnsRunner::new(peer_mgr, Some(tun_name2), tun_ip2, fake_ip);
    let cancel_token2 = CancellationToken::new();
    let cancel_token2_clone = cancel_token2.clone();
    let t2 = tokio::spawn(async move {
        dns_runner2.run(cancel_token2_clone).await;
    });
    tokio::time::sleep(Duration::from_secs(3)).await;
    check_dns_record(&fake_ip, "test1.et.net", "10.144.144.10").await;
    check_dns_record(&fake_ip, "test2.et.net", "10.144.144.20").await;

    // stop runner 1, runner 2 will take over the dns server
    cancel_token.cancel();
    t.await.unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    check_dns_record(&fake_ip, "test2.et.net", "10.144.144.20").await;

    cancel_token2.cancel();
    t2.await.unwrap();
}
