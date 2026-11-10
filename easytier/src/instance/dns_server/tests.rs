use easytier_proto::core_config::{DnsRecordRaw, DnsRecordType};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use cidr::Ipv4Inet;
use easytier_core::{
    config::toml::{DnsConfig, DnsZoneConfig},
    gateway::magic_dns::MagicDnsRoute,
    host::packet::{HostPacket, HostPacketChannelSink, HostPacketReceiver},
    process_runtime::CoreProcessRuntime,
};
use hickory_client::client::{Client, ClientHandle as _};
use hickory_proto::rr;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::udp::UdpClientStream;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::{ArcGlobalCtx, tests::get_mock_global_ctx};
use crate::instance::{
    composition::{NativeCoreInstance, runtime_core_host_adapters},
    config::test_core_instance_config,
};

use crate::instance::dns_server::runner::DnsRunner;
use crate::instance::dns_server::server_instance::MagicDnsServerInstance;
use crate::instance::dns_server::{DEFAULT_ET_DNS_ZONE, MAGIC_DNS_FAKE_IP};
use crate::instance::virtual_nic::NicCtx;
use crate::proto::api::instance::Route;
use crate::proto::magic_dns::{MagicDnsServerRpc as _, UpdateDnsRecordRequest};
use crate::proto::rpc_types::controller::{BaseController, Controller as _};

fn client_controller(port: u16) -> BaseController {
    let mut ctrl = BaseController::default();
    ctrl.set_tunnel_info(Some(crate::proto::common::TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        remote_addr: Some(crate::proto::common::Url {
            url: format!("tcp://127.0.0.1:{port}"),
        }),
        ..Default::default()
    }));
    ctrl
}

pub async fn prepare_env(
    dns_name: &str,
    tun_ip: Ipv4Inet,
) -> (ArcGlobalCtx, Arc<NativeCoreInstance>, NicCtx) {
    prepare_env_with_tld_dns_zone(dns_name, tun_ip, None).await
}

async fn build_test_core(ctx: ArcGlobalCtx) -> (Arc<NativeCoreInstance>, HostPacketReceiver) {
    let (packet_sink, packet_receiver) = tokio::sync::mpsc::channel::<HostPacket>(128);
    let adapters = runtime_core_host_adapters(
        ctx.clone(),
        CoreProcessRuntime::new(),
        Arc::new(HostPacketChannelSink::new(packet_sink)),
    );
    let core_instance = NativeCoreInstance::new(test_core_instance_config(&ctx), adapters).unwrap();
    core_instance.start().await.unwrap();
    (core_instance, HostPacketReceiver::new(packet_receiver))
}

pub async fn prepare_env_with_tld_dns_zone(
    dns_name: &str,
    tun_ip: Ipv4Inet,
    tld_dns_zone: Option<&str>,
) -> (ArcGlobalCtx, Arc<NativeCoreInstance>, NicCtx) {
    let ctx = get_mock_global_ctx();
    ctx.set_hostname(dns_name.to_owned());
    ctx.set_ipv4(Some(tun_ip));

    if let Some(zone) = tld_dns_zone {
        let mut flags = ctx.config.get_flags();
        flags.accept_dns = true; // Enable DNS
        ctx.set_flags(flags);
        let mut dns = ctx.config.get_dns().unwrap_or_default();
        dns.domain = Some(zone.to_string());
        ctx.config.set_dns(Some(dns));
    }

    let (core_instance, host_packet_rx) = build_test_core(ctx.clone()).await;
    let host_packet_rx = Arc::new(tokio::sync::Mutex::new(host_packet_rx));
    let mut virtual_nic = NicCtx::new(
        ctx.clone(),
        core_instance.packet_plane(),
        host_packet_rx,
        Arc::new(Notify::new()),
        Arc::new(tokio::sync::Mutex::new(
            crate::instance::shared_virtual_nic::SharedVirtualNicRegistry::new(),
        )),
    )
    .await;
    virtual_nic.run(Some(tun_ip), None).await.unwrap();

    (ctx, core_instance, virtual_nic)
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

#[tokio::test]
async fn test_magic_dns_server_instance() {
    let tun_ip = Ipv4Inet::from_str("10.144.144.10/24").unwrap();
    let (global_ctx, core_instance, virtual_nic) = prepare_env("test1", tun_ip).await;
    let tun_name = virtual_nic.ifname().await.unwrap();
    let fake_ip = Ipv4Addr::from_str("100.100.100.101").unwrap();

    let mut dns = global_ctx.config.get_dns().unwrap_or_default();
    dns.zone = Some(
        vec![DnsZoneConfig {
            origin: "example.test.".to_owned(),
            ttl: Some(60),
            records: Some(
                vec![DnsRecordRaw {
                    name: "svc".into(),
                    r#type: DnsRecordType::A as i32,
                    ttl: None,
                    value: Some("10.0.0.9".into()),
                }]
                .into(),
            ),
        }]
        .into(),
    );
    global_ctx.config.set_dns(Some(dns));

    let dns_server_inst = MagicDnsServerInstance::new(
        core_instance.packet_plane(),
        global_ctx,
        Some(tun_name),
        tun_ip,
        fake_ip,
    )
    .await
    .unwrap();

    check_dns_record(&fake_ip, "svc.example.test", "10.0.0.9").await;

    let routes = [
        MagicDnsRoute {
            hostname: "test1".to_string(),
            ipv4_addr: Some("8.8.8.8".parse().unwrap()),
        },
        MagicDnsRoute {
            hostname: "中文".to_string(),
            ipv4_addr: Some("8.8.8.8".parse().unwrap()),
        },
        MagicDnsRoute {
            hostname: ".invalid".to_string(),
            ipv4_addr: Some("8.8.8.8".parse().unwrap()),
        },
    ];
    dns_server_inst
        .data
        .update_dns_record(
            client_controller(54320),
            UpdateDnsRecordRequest {
                zone: DEFAULT_ET_DNS_ZONE.to_owned(),
                instance_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                dns: Some(DnsConfig::default()),
                routes: routes
                    .iter()
                    .map(|route| Route {
                        hostname: route.hostname.clone(),
                        ipv4_addr: route
                            .ipv4_addr
                            .map(|ip| Ipv4Inet::new(ip, 32).unwrap().into()),
                        ..Default::default()
                    })
                    .collect(),
            },
        )
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
        let (global_ctx, core_instance, virtual_nic) = prepare_env("test1", tun_ip).await;
        let tun_name = virtual_nic.ifname().await.unwrap();
        let fake_ip = Ipv4Addr::from_str(MAGIC_DNS_FAKE_IP).unwrap();
        let mut dns_runner = DnsRunner::new(
            core_instance.packet_plane(),
            global_ctx,
            Some(tun_name),
            tun_ip,
            fake_ip,
        );

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
        let (global_ctx, core_instance, virtual_nic) =
            prepare_env_with_tld_dns_zone("test2", tun_ip, Some(custom_tld_zone)).await;
        let tun_name = virtual_nic.ifname().await.unwrap();
        let fake_ip = Ipv4Addr::from_str(MAGIC_DNS_FAKE_IP).unwrap();
        let mut dns_runner = DnsRunner::new(
            core_instance.packet_plane(),
            global_ctx,
            Some(tun_name),
            tun_ip,
            fake_ip,
        );

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
    ctx.config.set_dns(Some(DnsConfig {
        domain: None,
        zone: Some(
            vec![DnsZoneConfig {
                origin: "example.test.".to_owned(),
                ttl: Some(60),
                records: Some(
                    vec![DnsRecordRaw {
                        name: "svc".into(),
                        r#type: DnsRecordType::A as i32,
                        ttl: None,
                        value: Some("10.0.0.9".into()),
                    }]
                    .into(),
                ),
            }]
            .into(),
        ),
    }));

    let (core_instance, _packet_receiver) = build_test_core(ctx.clone()).await;

    let fake_ip = Ipv4Addr::from_str(MAGIC_DNS_FAKE_IP).unwrap();
    let dns_server_inst =
        MagicDnsServerInstance::new(core_instance.packet_plane(), ctx, None, tun_ip, fake_ip)
            .await
            .unwrap();
    assert!(
        dns_server_inst
            .data
            .dns_server
            .read_catalog()
            .await
            .contains(&"example.test.".parse().unwrap())
    );

    let mut ctrl = BaseController::default();
    ctrl.set_tunnel_info(Some(crate::proto::common::TunnelInfo {
        tunnel_type: "tcp".to_string(),
        local_addr: None,
        remote_addr: Some(crate::proto::common::Url {
            url: "tcp://127.0.0.1:54321".to_string(),
        }),
        resolved_remote_addr: None,
    }));

    dns_server_inst
        .data
        .update_dns_record(
            ctrl.clone(),
            UpdateDnsRecordRequest {
                zone: DEFAULT_ET_DNS_ZONE.to_string(),
                instance_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                dns: Some(DnsConfig::default()),
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
                instance_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                dns: Some(DnsConfig::default()),
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
        resolved_remote_addr: None,
    }));

    dns_server_inst
        .data
        .update_dns_record(
            ctrl,
            UpdateDnsRecordRequest {
                zone: DEFAULT_ET_DNS_ZONE.to_string(),
                instance_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                dns: Some(DnsConfig::default()),
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
    assert!(
        dns_records
            .records
            .get(DEFAULT_ET_DNS_ZONE)
            .is_none_or(|zone| zone.records.is_empty())
    );
}

// The fake IP is inside the supplied subnet and Linux has no SystemConfig here,
// so this exercises real TCP publication/election without touching host DNS/TUN.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_magic_dns_runtime_clients_republish_after_election() {
    use hickory_proto::{
        op::{Message, Query},
        rr::{RData, RecordType},
    };
    use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, UdpPacket};

    async fn expect_record(
        core: &Arc<NativeCoreInstance>,
        packets: &mut HostPacketReceiver,
        name: &str,
        expected: Option<(&str, u32)>,
    ) {
        let mut query = Message::new();
        query.add_query(Query::query(name.parse().unwrap(), RecordType::A));
        let payload = query.to_vec().unwrap();
        let source = "10.50.0.100".parse::<Ipv4Addr>().unwrap();
        let destination = MAGIC_DNS_FAKE_IP.parse::<Ipv4Addr>().unwrap();
        let mut packet = vec![0u8; 28 + payload.len()];
        {
            let mut ipv4 = Ipv4Packet::new_unchecked(&mut packet);
            ipv4.set_version(4);
            ipv4.set_header_len(20);
            ipv4.set_total_len((28 + payload.len()) as u16);
            ipv4.set_hop_limit(64);
            ipv4.set_next_header(IpProtocol::Udp);
            ipv4.set_src_addr(source);
            ipv4.set_dst_addr(destination);
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut packet[20..]);
            udp.set_src_port(5353);
            udp.set_dst_port(53);
            udp.set_len((8 + payload.len()) as u16);
            udp.payload_mut().copy_from_slice(&payload);
            udp.fill_checksum(&IpAddress::Ipv4(source), &IpAddress::Ipv4(destination));
        }
        Ipv4Packet::new_unchecked(&mut packet).fill_checksum();
        let expected = expected.map(|(ip, ttl)| (ip.parse::<Ipv4Addr>().unwrap(), ttl));
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                core.packet_plane()
                    .send_local_ip_packet(HostPacket::copy_from_payload(&packet))
                    .await
                    .unwrap();
                if let Ok(Some(packet)) =
                    tokio::time::timeout(Duration::from_millis(100), packets.recv()).await
                {
                    let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
                    let udp = UdpPacket::new_checked(ipv4.payload()).unwrap();
                    let response = Message::from_vec(udp.payload()).unwrap();
                    let addresses = response
                        .answers()
                        .iter()
                        .filter_map(|record| match record.data() {
                            RData::A(ip) => Some((ip.0, record.ttl())),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    if addresses == expected.into_iter().collect::<Vec<_>>() {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("DNS record {name} did not converge to {expected:?}"));
    }

    fn dns(name: &str, ip: &str, ttl: u32) -> DnsConfig {
        DnsConfig {
            domain: Some("runtime.test".to_owned()),
            zone: Some(
                vec![DnsZoneConfig {
                    origin: "runtime.test".to_owned(),
                    ttl: Some(ttl),
                    records: Some(
                        vec![easytier_proto::core_config::DnsRecordRaw {
                            name: name.to_owned(),
                            r#type: easytier_proto::core_config::DnsRecordType::A as i32,
                            value: Some(ip.to_owned()),
                            ..Default::default()
                        }]
                        .into(),
                    ),
                }]
                .into(),
            ),
        }
    }

    fn start(
        core: &Arc<NativeCoreInstance>,
        ctx: ArcGlobalCtx,
    ) -> (CancellationToken, tokio::task::JoinHandle<()>) {
        let mut runner = DnsRunner::new(
            core.packet_plane(),
            ctx,
            None,
            "100.100.100.0/24".parse().unwrap(),
            MAGIC_DNS_FAKE_IP.parse().unwrap(),
        );
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move { runner.run(task_cancel).await });
        (cancel, task)
    }

    let ctx_a = get_mock_global_ctx();
    ctx_a.config.set_dns(Some(dns("first", "10.50.0.1", 60)));
    let ctx_b = get_mock_global_ctx();
    ctx_b.config.set_dns(Some(dns("second", "10.50.0.2", 60)));
    let (core_a, mut packets_a) = build_test_core(ctx_a.clone()).await;
    let (core_b, mut packets_b) = build_test_core(ctx_b.clone()).await;
    let (cancel_a, task_a) = start(&core_a, ctx_a.clone());
    expect_record(
        &core_a,
        &mut packets_a,
        "first.runtime.test.",
        Some(("10.50.0.1", 60)),
    )
    .await;
    let (cancel_b, task_b) = start(&core_b, ctx_b.clone());
    expect_record(
        &core_a,
        &mut packets_a,
        "second.runtime.test.",
        Some(("10.50.0.2", 60)),
    )
    .await;
    let status = super::client_instance::dns_status(ctx_b.get_id().to_string())
        .await
        .unwrap();
    assert!(status.published_dns.is_some());
    assert!(status.records.iter().any(|record| {
        record.effective.iter().any(|record| {
            record.name == "second.runtime.test." && record.value.as_deref() == Some("10.50.0.2")
        })
    }));

    // The route revision is unchanged: the next normal cycle still uploads DNS.
    ctx_b.config.set_dns(Some(dns("second", "10.50.0.3", 60)));
    expect_record(
        &core_a,
        &mut packets_a,
        "second.runtime.test.",
        Some(("10.50.0.3", 60)),
    )
    .await;
    ctx_b.config.set_dns(Some(DnsConfig {
        domain: Some("runtime.test".to_owned()),
        zone: Some(Vec::new().into()),
    }));
    expect_record(&core_a, &mut packets_a, "second.runtime.test.", None).await;
    ctx_a.config.set_dns(Some(dns("first", "10.50.0.1", 120)));
    expect_record(
        &core_a,
        &mut packets_a,
        "first.runtime.test.",
        Some(("10.50.0.1", 120)),
    )
    .await;
    ctx_a.config.set_dns(Some(dns("first", "10.50.0.1", 60)));
    expect_record(
        &core_a,
        &mut packets_a,
        "first.runtime.test.",
        Some(("10.50.0.1", 60)),
    )
    .await;
    ctx_b.config.set_dns(Some(dns("second", "10.50.0.5", 60)));
    expect_record(
        &core_a,
        &mut packets_a,
        "second.runtime.test.",
        Some(("10.50.0.5", 60)),
    )
    .await;

    cancel_a.cancel();
    task_a.await.unwrap();
    // The remaining runner elects itself and periodically re-uploads its saved configuration.
    expect_record(
        &core_b,
        &mut packets_b,
        "second.runtime.test.",
        Some(("10.50.0.5", 60)),
    )
    .await;
    expect_record(&core_b, &mut packets_b, "first.runtime.test.", None).await;
    let status = super::client_instance::dns_status(ctx_b.get_id().to_string())
        .await
        .unwrap();
    assert!(status.records.iter().any(|record| {
        record.effective.iter().any(|record| {
            record.name == "second.runtime.test." && record.value.as_deref() == Some("10.50.0.5")
        })
    }));
    let (cancel_a, task_a) = start(&core_a, ctx_a);
    expect_record(
        &core_b,
        &mut packets_b,
        "first.runtime.test.",
        Some(("10.50.0.1", 60)),
    )
    .await;
    expect_record(
        &core_b,
        &mut packets_b,
        "second.runtime.test.",
        Some(("10.50.0.5", 60)),
    )
    .await;

    cancel_a.cancel();
    task_a.await.unwrap();
    expect_record(&core_b, &mut packets_b, "first.runtime.test.", None).await;
    cancel_b.cancel();
    task_b.await.unwrap();
    core_a.stop().await;
    core_b.stop().await;
}
