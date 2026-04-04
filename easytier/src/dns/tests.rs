#![cfg(all(feature = "magic-dns", feature = "tun"))]

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cidr::Ipv4Inet;
use hickory_client::client::{Client, ClientHandle as _};
use hickory_proto::rr;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use tokio::sync::Notify;

use crate::common::global_ctx::tests::get_mock_global_ctx;
use crate::connector::udp_hole_punch::tests::replace_stun_info_collector;
use crate::dns::node::DnsNode;
use crate::instance::instance::ArcNicCtx;
use crate::instance::virtual_nic::NicCtx;
use crate::peers::create_packet_recv_chan;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};
use crate::proto::common::NatType;

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

pub async fn check_dns_record(fake_ip: &Ipv4Addr, domain: &str, expected_ip: &str) {
    let expected = expected_ip.parse::<Ipv4Addr>().unwrap();
    let name = rr::Name::from_str(domain).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        let stream = UdpClientStream::builder(
            SocketAddr::new((*fake_ip).into(), 53),
            TokioRuntimeProvider::default(),
        )
        .build();
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
