use std::net::Ipv4Addr;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use cidr::Ipv4Inet;

use crate::common::global_ctx::tests::get_mock_global_ctx;
use crate::connector::udp_hole_punch::tests::replace_stun_info_collector;

use crate::instance::dns_server::server_instance::MagicDnsServerInstance;
use crate::instance::dns_server::DEFAULT_ET_DNS_ZONE;
use crate::instance::virtual_nic::NicCtx;
use crate::peers::peer_manager::{PeerManager, RouteAlgoType};

use crate::peers::create_packet_recv_chan;
use crate::proto::cli::Route;
use crate::proto::common::NatType;

#[tokio::test]
async fn test_magic_dns_server_instance() {
    let (s, r) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(
        RouteAlgoType::Ospf,
        get_mock_global_ctx(),
        s,
    ));
    peer_mgr.run().await.unwrap();
    replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);

    let r = Arc::new(tokio::sync::Mutex::new(r));
    let tun_ip = Ipv4Inet::from_str("10.144.144.10/24").unwrap();
    let mut virtual_nic = NicCtx::new(peer_mgr.get_global_ctx(), &peer_mgr, r);
    virtual_nic.run(tun_ip).await.unwrap();

    let tun_name = virtual_nic.ifname().await.unwrap();
    let fake_ip = Ipv4Addr::from_str("100.100.100.101").unwrap();
    let dns_server_inst = MagicDnsServerInstance::new(peer_mgr.clone(), tun_name, tun_ip, fake_ip)
        .await
        .unwrap();

    let routes = vec![Route {
        hostname: "test1".to_string(),
        ipv4_addr: Some(Ipv4Inet::from_str("8.8.8.8/24").unwrap().into()),
        ..Default::default()
    }];
    dns_server_inst
        .data
        .update_dns_records(&routes, DEFAULT_ET_DNS_ZONE)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(5000)).await;
}
