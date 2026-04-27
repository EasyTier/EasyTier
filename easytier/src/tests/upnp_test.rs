use std::{
    ffi::OsStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use igd_next::{
    GetGenericPortMappingEntryError, PortMappingEntry, PortMappingProtocol, SearchOptions,
    aio::tokio::search_gateway,
};
use tempfile::TempDir;
use tokio::net::UdpSocket;

use super::{create_netns, del_netns, drop_insts, get_host_veth_name, ping_test};
use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        error::Error,
        global_ctx::{GlobalCtx, GlobalCtxEvent},
        netns::NetNS,
        stun::{MockStunInfoCollector, StunInfoCollectorTrait},
    },
    connector::udp_hole_punch::{UdpHolePunchConnector, common::UdpHolePunchListener},
    instance::instance::Instance,
    peers::{
        create_packet_recv_chan,
        peer_manager::{PeerManager, RouteAlgoType},
        tests::{connect_peer_manager, wait_route_appear, wait_route_appear_with_cost},
    },
    proto::common::{NatType, StunInfo},
    tunnel::{common::tests::wait_for_condition, ring::RingTunnelConnector},
};

const TEST_NS_A: &str = "upnp_a";
const TEST_NS_C: &str = "upnp_c";
const TEST_BRIDGE: &str = "br_upnp";
const TEST_WAN_IF: &str = "upnp_wan0";
const TEST_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(172, 31, 255, 1);
const TEST_CLIENT_A_IP: Ipv4Addr = Ipv4Addr::new(172, 31, 255, 2);
const TEST_CLIENT_C_IP: Ipv4Addr = Ipv4Addr::new(172, 31, 255, 3);
const TEST_EXTERNAL_IP: Ipv4Addr = Ipv4Addr::new(11, 22, 33, 44);
const TEST_CONTROL_PORT: u16 = 5000;
const TEST_IGD_DESCRIPTION: &str = "EasyTier udp hole punch";

const DUAL_NS_A: &str = "upnp2_a";
const DUAL_NS_C: &str = "upnp2_c";
const DUAL_LAN_A_BRIDGE: &str = "br_upnp2_a";
const DUAL_LAN_C_BRIDGE: &str = "br_upnp2_c";
const DUAL_WAN_BRIDGE: &str = "br_upnp2_wan";
const DUAL_GATEWAY_A_IP: Ipv4Addr = Ipv4Addr::new(172, 30, 1, 1);
const DUAL_GATEWAY_C_IP: Ipv4Addr = Ipv4Addr::new(172, 30, 2, 1);
const DUAL_CLIENT_A_IP: Ipv4Addr = Ipv4Addr::new(172, 30, 1, 2);
const DUAL_CLIENT_C_IP: Ipv4Addr = Ipv4Addr::new(172, 30, 2, 2);
const DUAL_EXTERNAL_A_IP: Ipv4Addr = Ipv4Addr::new(11, 22, 33, 1);
const DUAL_EXTERNAL_C_IP: Ipv4Addr = Ipv4Addr::new(11, 22, 33, 2);
const DUAL_GATEWAY_A_PORT: u16 = 5001;
const DUAL_GATEWAY_C_PORT: u16 = 5002;
const DUAL_WAN_IF_A: &str = "upnp2_wan_a";
const DUAL_WAN_IF_A_PEER: &str = "upnp2_wan_a_p";
const DUAL_WAN_IF_C: &str = "upnp2_wan_c";
const DUAL_WAN_IF_C_PEER: &str = "upnp2_wan_c_p";
const DUAL_GW_NS_A: &str = "upnp2_gw_a";
const DUAL_GW_NS_C: &str = "upnp2_gw_c";

struct UpnpIntegrationEnv {
    _tempdir: TempDir,
    child: Option<Child>,
}

impl UpnpIntegrationEnv {
    async fn new() -> anyhow::Result<Self> {
        cleanup_miniupnpd_processes();
        cleanup_test_net();
        create_test_net()?;

        let tempdir = tempfile::tempdir().context("create miniupnpd tempdir")?;
        let conf_path = tempdir.path().join("miniupnpd.conf");
        let leases_path = tempdir.path().join("miniupnpd.leases");
        std::fs::write(&leases_path, "").context("create miniupnpd lease file")?;
        std::fs::write(
            &conf_path,
            format!(
                "\
ext_ifname={TEST_WAN_IF}
listening_ip={TEST_BRIDGE}
port={TEST_CONTROL_PORT}
enable_natpmp=no
enable_upnp=yes
secure_mode=no
system_uptime=yes
lease_file={}
ext_ip={}
friendly_name=EasyTier Test IGD
model_name=EasyTier Test
serial=12345678
uuid=9f0c5a3a-c4f0-4f1e-b4df-8a8c7b1e2d00
allow 1024-65535 172.31.255.0/24 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
",
                leases_path.display(),
                TEST_EXTERNAL_IP
            ),
        )
        .context("write miniupnpd config")?;

        let miniupnpd_bin = find_miniupnpd_bin()?;
        let child = Command::new(miniupnpd_bin)
            .args(["-d", "-f"])
            .arg(&conf_path)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn miniupnpd")?;

        let env = Self {
            _tempdir: tempdir,
            child: Some(child),
        };
        env.wait_ready().await?;
        Ok(env)
    }

    async fn wait_ready(&self) -> anyhow::Result<()> {
        wait_for_condition(
            || async {
                tokio::net::TcpStream::connect((TEST_GATEWAY_IP, TEST_CONTROL_PORT))
                    .await
                    .is_ok()
            },
            Duration::from_secs(10),
        )
        .await;
        Ok(())
    }
}

impl Drop for UpnpIntegrationEnv {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        cleanup_miniupnpd_processes();
        cleanup_test_net();
    }
}

struct DualGatewayUpnpIntegrationEnv {
    _tempdir: TempDir,
    children: Vec<Child>,
}

struct DualGatewayConfig<'a> {
    name: &'a str,
    ext_if: &'a str,
    listening_ip: &'a str,
    port: u16,
    ext_ip: Ipv4Addr,
    uuid: &'a str,
    chain_name: &'a str,
    postrouting_chain_name: &'a str,
    allow_subnet: &'a str,
}

impl DualGatewayUpnpIntegrationEnv {
    async fn new() -> anyhow::Result<Self> {
        cleanup_miniupnpd_processes();
        cleanup_dual_gateway_test_net();
        create_dual_gateway_test_net()?;

        let tempdir = tempfile::tempdir().context("create dual miniupnpd tempdir")?;
        let gateway_a = write_dual_gateway_config(
            tempdir.path(),
            DualGatewayConfig {
                name: "gateway_a",
                ext_if: DUAL_WAN_IF_A,
                listening_ip: DUAL_LAN_A_BRIDGE,
                port: DUAL_GATEWAY_A_PORT,
                ext_ip: DUAL_EXTERNAL_A_IP,
                uuid: "9f0c5a3a-c4f0-4f1e-b4df-8a8c7b1e2d01",
                chain_name: "MINIUPNPD_A",
                postrouting_chain_name: "MINIUPNPD_A-POSTROUTING",
                allow_subnet: "172.30.1.0/24",
            },
        )?;
        let gateway_c = write_dual_gateway_config(
            tempdir.path(),
            DualGatewayConfig {
                name: "gateway_c",
                ext_if: DUAL_WAN_IF_C,
                listening_ip: DUAL_LAN_C_BRIDGE,
                port: DUAL_GATEWAY_C_PORT,
                ext_ip: DUAL_EXTERNAL_C_IP,
                uuid: "9f0c5a3a-c4f0-4f1e-b4df-8a8c7b1e2d02",
                chain_name: "MINIUPNPD_C",
                postrouting_chain_name: "MINIUPNPD_C-POSTROUTING",
                allow_subnet: "172.30.2.0/24",
            },
        )?;
        let pid_a = tempdir.path().join("gateway_a.pid");
        let pid_c = tempdir.path().join("gateway_c.pid");

        let miniupnpd_bin = find_miniupnpd_bin()?;
        let miniupnpd_bin_str = miniupnpd_bin
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 miniupnpd path: {}", miniupnpd_bin.display()))?;
        let pid_a_str = pid_a
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 pid path: {}", pid_a.display()))?;
        let pid_c_str = pid_c
            .to_str()
            .ok_or_else(|| anyhow!("non-utf8 pid path: {}", pid_c.display()))?;
        let child_a = Command::new("ip")
            .args([
                "netns",
                "exec",
                DUAL_GW_NS_A,
                miniupnpd_bin_str,
                "-d",
                "-P",
                pid_a_str,
                "-f",
            ])
            .arg(&gateway_a)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn gateway a miniupnpd")?;
        let child_c = Command::new("ip")
            .args([
                "netns",
                "exec",
                DUAL_GW_NS_C,
                miniupnpd_bin_str,
                "-d",
                "-P",
                pid_c_str,
                "-f",
            ])
            .arg(&gateway_c)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawn gateway c miniupnpd")?;

        let env = Self {
            _tempdir: tempdir,
            children: vec![child_a, child_c],
        };
        env.wait_ready().await?;
        Ok(env)
    }

    async fn wait_ready(&self) -> anyhow::Result<()> {
        wait_for_condition(
            || async {
                tcp_connect_in_ns(DUAL_NS_A, DUAL_GATEWAY_A_IP, DUAL_GATEWAY_A_PORT)
                    .await
                    .is_ok()
                    && tcp_connect_in_ns(DUAL_NS_C, DUAL_GATEWAY_C_IP, DUAL_GATEWAY_C_PORT)
                        .await
                        .is_ok()
            },
            Duration::from_secs(10),
        )
        .await;
        Ok(())
    }
}

impl Drop for DualGatewayUpnpIntegrationEnv {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        cleanup_miniupnpd_processes();
        cleanup_dual_gateway_test_net();
    }
}

#[derive(Clone)]
struct GatewayBackedStunCollector {
    netns: &'static str,
    client_ip: Ipv4Addr,
    external_ip: Ipv4Addr,
}

#[async_trait::async_trait]
impl StunInfoCollectorTrait for GatewayBackedStunCollector {
    fn get_stun_info(&self) -> StunInfo {
        StunInfo {
            udp_nat_type: NatType::PortRestricted as i32,
            tcp_nat_type: NatType::Unknown as i32,
            last_update_time: 0,
            min_port: 0,
            max_port: 0,
            public_ip: vec![self.external_ip.to_string()],
        }
    }

    async fn get_udp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error> {
        query_udp_mapping(self.netns, self.external_ip, self.client_ip, local_port).await
    }

    async fn get_udp_port_mapping_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<SocketAddr, Error> {
        query_udp_mapping(
            self.netns,
            self.external_ip,
            self.client_ip,
            udp.local_addr()?.port(),
        )
        .await
    }

    async fn get_tcp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error> {
        Ok(SocketAddr::new(IpAddr::V4(self.external_ip), local_port))
    }
}

fn create_test_net() -> anyhow::Result<()> {
    create_netns(TEST_NS_A, &format!("{TEST_CLIENT_A_IP}/24"), "fd10::2/64");
    create_netns(TEST_NS_C, &format!("{TEST_CLIENT_C_IP}/24"), "fd10::3/64");
    run_cmd(
        "ip",
        &["link", "add", "name", TEST_BRIDGE, "type", "bridge"],
    )?;
    for netns in [TEST_NS_A, TEST_NS_C] {
        run_cmd(
            "ip",
            &[
                "link",
                "set",
                get_host_veth_name(netns),
                "master",
                TEST_BRIDGE,
            ],
        )?;
    }

    run_cmd(
        "ip",
        &[
            "addr",
            "add",
            &format!("{TEST_GATEWAY_IP}/24"),
            "dev",
            TEST_BRIDGE,
        ],
    )?;
    run_cmd("ip", &["link", "add", TEST_WAN_IF, "type", "dummy"])?;
    run_cmd(
        "ip",
        &[
            "addr",
            "add",
            &format!("{TEST_EXTERNAL_IP}/24"),
            "dev",
            TEST_WAN_IF,
        ],
    )?;
    run_cmd("ip", &["link", "set", TEST_WAN_IF, "up"])?;
    run_cmd("ip", &["link", "set", TEST_BRIDGE, "up"])?;
    setup_iptables_rules()?;
    for (netns, guest_veth) in [(TEST_NS_A, "veth_upnp_a_g"), (TEST_NS_C, "veth_upnp_c_g")] {
        run_cmd(
            "ip",
            &[
                "netns",
                "exec",
                netns,
                "ip",
                "route",
                "add",
                "default",
                "via",
                &TEST_GATEWAY_IP.to_string(),
                "dev",
                guest_veth,
            ],
        )?;
    }
    run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    Ok(())
}

fn cleanup_test_net() {
    cleanup_iptables_rules();
    del_netns(TEST_NS_A);
    del_netns(TEST_NS_C);
    let _ = Command::new("ip")
        .args(["link", "del", TEST_BRIDGE])
        .output();
    let _ = Command::new("ip")
        .args(["link", "del", TEST_WAN_IF])
        .output();
}

fn write_dual_gateway_config(dir: &Path, config: DualGatewayConfig<'_>) -> anyhow::Result<PathBuf> {
    let conf_path = dir.join(format!("{}.conf", config.name));
    let lease_path = dir.join(format!("{}.leases", config.name));
    std::fs::write(&lease_path, "")
        .with_context(|| format!("create lease file for {}", config.name))?;
    std::fs::write(
        &conf_path,
        format!(
            "\
ext_ifname={ext_if}
listening_ip={listening_ip}
port={port}
enable_natpmp=no
enable_upnp=yes
secure_mode=no
system_uptime=yes
lease_file={}
ext_ip={ext_ip}
friendly_name=EasyTier Test IGD {name}
model_name=EasyTier Test
serial=12345678
uuid={uuid}
upnp_forward_chain={chain_name}
upnp_nat_chain={chain_name}
upnp_nat_postrouting_chain={postrouting_chain_name}
allow 1024-65535 {allow_subnet} 1024-65535
deny 0-65535 0.0.0.0/0 0-65535
",
            lease_path.display(),
            ext_if = config.ext_if,
            listening_ip = config.listening_ip,
            port = config.port,
            ext_ip = config.ext_ip,
            name = config.name,
            uuid = config.uuid,
            chain_name = config.chain_name,
            postrouting_chain_name = config.postrouting_chain_name,
            allow_subnet = config.allow_subnet,
        ),
    )
    .with_context(|| format!("write config for {}", config.name))?;
    Ok(conf_path)
}

async fn tcp_connect_in_ns(netns: &'static str, ip: Ipv4Addr, port: u16) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        let _g = NetNS::new(Some(netns.to_owned())).guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build runtime for tcp connect in netns")?
            .block_on(async move {
                tokio::net::TcpStream::connect((ip, port))
                    .await
                    .map(|_| ())
                    .context("tcp connect in netns")
            })
    })
    .await
    .context("join tcp connect in netns task")?
}

fn create_empty_netns(name: &str) -> anyhow::Result<()> {
    run_cmd("ip", &["netns", "add", name])?;
    run_cmd(
        "ip",
        &["netns", "exec", name, "ip", "link", "set", "lo", "up"],
    )?;
    Ok(())
}

fn run_cmd_in_netns<S: AsRef<OsStr>>(netns: &str, cmd: S, args: &[&str]) -> anyhow::Result<()> {
    let cmd = cmd.as_ref();
    let cmd_str = cmd
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 command path: {}", Path::new(cmd).display()))?;
    let mut full_args = vec!["netns", "exec", netns, cmd_str];
    full_args.extend_from_slice(args);
    run_cmd("ip", &full_args)
}

fn create_dual_gateway_test_net() -> anyhow::Result<()> {
    create_netns(DUAL_NS_A, &format!("{DUAL_CLIENT_A_IP}/24"), "fd20::2/64");
    create_netns(DUAL_NS_C, &format!("{DUAL_CLIENT_C_IP}/24"), "fd21::2/64");
    create_empty_netns(DUAL_GW_NS_A)?;
    create_empty_netns(DUAL_GW_NS_C)?;

    run_cmd(
        "ip",
        &[
            "link",
            "set",
            get_host_veth_name(DUAL_NS_A),
            "netns",
            DUAL_GW_NS_A,
        ],
    )?;
    run_cmd(
        "ip",
        &[
            "link",
            "set",
            get_host_veth_name(DUAL_NS_C),
            "netns",
            DUAL_GW_NS_C,
        ],
    )?;

    run_cmd_in_netns(
        DUAL_GW_NS_A,
        "ip",
        &["link", "add", "name", DUAL_LAN_A_BRIDGE, "type", "bridge"],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_C,
        "ip",
        &["link", "add", "name", DUAL_LAN_C_BRIDGE, "type", "bridge"],
    )?;
    run_cmd(
        "ip",
        &["link", "add", "name", DUAL_WAN_BRIDGE, "type", "bridge"],
    )?;

    run_cmd_in_netns(
        DUAL_GW_NS_A,
        "ip",
        &[
            "link",
            "set",
            get_host_veth_name(DUAL_NS_A),
            "master",
            DUAL_LAN_A_BRIDGE,
        ],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_C,
        "ip",
        &[
            "link",
            "set",
            get_host_veth_name(DUAL_NS_C),
            "master",
            DUAL_LAN_C_BRIDGE,
        ],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_A,
        "ip",
        &[
            "addr",
            "add",
            &format!("{DUAL_GATEWAY_A_IP}/24"),
            "dev",
            DUAL_LAN_A_BRIDGE,
        ],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_C,
        "ip",
        &[
            "addr",
            "add",
            &format!("{DUAL_GATEWAY_C_IP}/24"),
            "dev",
            DUAL_LAN_C_BRIDGE,
        ],
    )?;

    run_cmd(
        "ip",
        &[
            "link",
            "add",
            DUAL_WAN_IF_A,
            "type",
            "veth",
            "peer",
            "name",
            DUAL_WAN_IF_A_PEER,
        ],
    )?;
    run_cmd(
        "ip",
        &[
            "link",
            "add",
            DUAL_WAN_IF_C,
            "type",
            "veth",
            "peer",
            "name",
            DUAL_WAN_IF_C_PEER,
        ],
    )?;
    run_cmd("ip", &["link", "set", DUAL_WAN_IF_A, "netns", DUAL_GW_NS_A])?;
    run_cmd("ip", &["link", "set", DUAL_WAN_IF_C, "netns", DUAL_GW_NS_C])?;
    run_cmd(
        "ip",
        &["link", "set", DUAL_WAN_IF_A_PEER, "master", DUAL_WAN_BRIDGE],
    )?;
    run_cmd(
        "ip",
        &["link", "set", DUAL_WAN_IF_C_PEER, "master", DUAL_WAN_BRIDGE],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_A,
        "ip",
        &[
            "addr",
            "add",
            &format!("{DUAL_EXTERNAL_A_IP}/24"),
            "dev",
            DUAL_WAN_IF_A,
        ],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_C,
        "ip",
        &[
            "addr",
            "add",
            &format!("{DUAL_EXTERNAL_C_IP}/24"),
            "dev",
            DUAL_WAN_IF_C,
        ],
    )?;
    run_cmd("ip", &["link", "set", DUAL_WAN_BRIDGE, "up"])?;
    run_cmd("ip", &["link", "set", DUAL_WAN_IF_A_PEER, "up"])?;
    run_cmd("ip", &["link", "set", DUAL_WAN_IF_C_PEER, "up"])?;
    run_cmd_in_netns(
        DUAL_GW_NS_A,
        "ip",
        &["link", "set", DUAL_LAN_A_BRIDGE, "up"],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_A,
        "ip",
        &["link", "set", get_host_veth_name(DUAL_NS_A), "up"],
    )?;
    run_cmd_in_netns(DUAL_GW_NS_A, "ip", &["link", "set", DUAL_WAN_IF_A, "up"])?;
    run_cmd_in_netns(
        DUAL_GW_NS_C,
        "ip",
        &["link", "set", DUAL_LAN_C_BRIDGE, "up"],
    )?;
    run_cmd_in_netns(
        DUAL_GW_NS_C,
        "ip",
        &["link", "set", get_host_veth_name(DUAL_NS_C), "up"],
    )?;
    run_cmd_in_netns(DUAL_GW_NS_C, "ip", &["link", "set", DUAL_WAN_IF_C, "up"])?;

    setup_gateway_iptables_rules_in_netns(
        DUAL_GW_NS_A,
        DUAL_WAN_IF_A,
        DUAL_LAN_A_BRIDGE,
        "MINIUPNPD_A",
        "MINIUPNPD_A-POSTROUTING",
    )?;
    setup_gateway_iptables_rules_in_netns(
        DUAL_GW_NS_C,
        DUAL_WAN_IF_C,
        DUAL_LAN_C_BRIDGE,
        "MINIUPNPD_C",
        "MINIUPNPD_C-POSTROUTING",
    )?;

    run_cmd(
        "ip",
        &[
            "netns",
            "exec",
            DUAL_NS_A,
            "ip",
            "route",
            "add",
            "default",
            "via",
            &DUAL_GATEWAY_A_IP.to_string(),
            "dev",
            "veth_upnp2_a_g",
        ],
    )?;
    run_cmd(
        "ip",
        &[
            "netns",
            "exec",
            DUAL_NS_C,
            "ip",
            "route",
            "add",
            "default",
            "via",
            &DUAL_GATEWAY_C_IP.to_string(),
            "dev",
            "veth_upnp2_c_g",
        ],
    )?;
    run_cmd_in_netns(DUAL_GW_NS_A, "sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    run_cmd_in_netns(DUAL_GW_NS_C, "sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
    Ok(())
}

fn cleanup_dual_gateway_test_net() {
    cleanup_gateway_iptables_rules_in_netns(
        DUAL_GW_NS_A,
        DUAL_WAN_IF_A,
        DUAL_LAN_A_BRIDGE,
        "MINIUPNPD_A",
        "MINIUPNPD_A-POSTROUTING",
    );
    cleanup_gateway_iptables_rules_in_netns(
        DUAL_GW_NS_C,
        DUAL_WAN_IF_C,
        DUAL_LAN_C_BRIDGE,
        "MINIUPNPD_C",
        "MINIUPNPD_C-POSTROUTING",
    );

    del_netns(DUAL_NS_A);
    del_netns(DUAL_NS_C);
    del_netns(DUAL_GW_NS_A);
    del_netns(DUAL_GW_NS_C);
    for iface in [DUAL_WAN_BRIDGE, DUAL_WAN_IF_A_PEER, DUAL_WAN_IF_C_PEER] {
        let _ = Command::new("ip").args(["link", "del", iface]).output();
    }
}

fn cleanup_miniupnpd_processes() {
    let _ = Command::new("pkill").args(["-x", "miniupnpd"]).output();
}

fn setup_gateway_iptables_rules(
    ext_if: &str,
    lan_bridge: &str,
    chain_name: &str,
    postrouting_chain_name: &str,
) -> anyhow::Result<()> {
    cleanup_gateway_iptables_rules(ext_if, lan_bridge, chain_name, postrouting_chain_name);
    let iptables = find_iptables_legacy_bin()?;

    run_cmd(&iptables, &["-t", "nat", "-N", chain_name])?;
    run_cmd(
        &iptables,
        &[
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ],
    )?;
    run_cmd(&iptables, &["-t", "nat", "-N", postrouting_chain_name])?;
    run_cmd(
        &iptables,
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            ext_if,
            "-j",
            postrouting_chain_name,
        ],
    )?;
    run_cmd(&iptables, &["-t", "mangle", "-N", chain_name])?;
    run_cmd(
        &iptables,
        &[
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ],
    )?;
    run_cmd(&iptables, &["-N", chain_name])?;
    run_cmd(
        &iptables,
        &[
            "-A", "FORWARD", "-i", ext_if, "!", "-o", ext_if, "-j", chain_name,
        ],
    )?;
    run_cmd(
        &iptables,
        &[
            "-A", "FORWARD", "-i", lan_bridge, "-o", ext_if, "-j", "ACCEPT",
        ],
    )?;
    Ok(())
}

fn cleanup_gateway_iptables_rules(
    ext_if: &str,
    lan_bridge: &str,
    chain_name: &str,
    postrouting_chain_name: &str,
) {
    let Ok(iptables) = find_iptables_legacy_bin() else {
        return;
    };

    let _ = Command::new(&iptables)
        .args([
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            ext_if,
            "-j",
            postrouting_chain_name,
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-D", "FORWARD", "-i", ext_if, "!", "-o", ext_if, "-j", chain_name,
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-D", "FORWARD", "-i", lan_bridge, "-o", ext_if, "-j", "ACCEPT",
        ])
        .output();
    let _ = Command::new(&iptables).args(["-F", chain_name]).output();
    let _ = Command::new(&iptables).args(["-X", chain_name]).output();
    let _ = Command::new(&iptables)
        .args(["-t", "mangle", "-F", chain_name])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "mangle", "-X", chain_name])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-F", chain_name])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-X", chain_name])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-F", postrouting_chain_name])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-X", postrouting_chain_name])
        .output();
}

fn setup_gateway_iptables_rules_in_netns(
    netns: &str,
    ext_if: &str,
    lan_bridge: &str,
    chain_name: &str,
    postrouting_chain_name: &str,
) -> anyhow::Result<()> {
    cleanup_gateway_iptables_rules_in_netns(
        netns,
        ext_if,
        lan_bridge,
        chain_name,
        postrouting_chain_name,
    );
    let iptables = find_iptables_legacy_bin()?;

    run_cmd_in_netns(netns, &iptables, &["-t", "nat", "-N", chain_name])?;
    run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ],
    )?;
    run_cmd_in_netns(
        netns,
        &iptables,
        &["-t", "nat", "-N", postrouting_chain_name],
    )?;
    run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            ext_if,
            "-j",
            postrouting_chain_name,
        ],
    )?;
    run_cmd_in_netns(netns, &iptables, &["-t", "mangle", "-N", chain_name])?;
    run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ],
    )?;
    run_cmd_in_netns(netns, &iptables, &["-N", chain_name])?;
    run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-A", "FORWARD", "-i", ext_if, "!", "-o", ext_if, "-j", chain_name,
        ],
    )?;
    run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-A", "FORWARD", "-i", lan_bridge, "-o", ext_if, "-j", "ACCEPT",
        ],
    )?;
    Ok(())
}

fn cleanup_gateway_iptables_rules_in_netns(
    netns: &str,
    ext_if: &str,
    lan_bridge: &str,
    chain_name: &str,
    postrouting_chain_name: &str,
) {
    let Ok(iptables) = find_iptables_legacy_bin() else {
        return;
    };

    let _ = run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ],
    );
    let _ = run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            ext_if,
            "-j",
            postrouting_chain_name,
        ],
    );
    let _ = run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-i",
            ext_if,
            "-j",
            chain_name,
        ],
    );
    let _ = run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-D", "FORWARD", "-i", ext_if, "!", "-o", ext_if, "-j", chain_name,
        ],
    );
    let _ = run_cmd_in_netns(
        netns,
        &iptables,
        &[
            "-D", "FORWARD", "-i", lan_bridge, "-o", ext_if, "-j", "ACCEPT",
        ],
    );
    let _ = run_cmd_in_netns(netns, &iptables, &["-F", chain_name]);
    let _ = run_cmd_in_netns(netns, &iptables, &["-X", chain_name]);
    let _ = run_cmd_in_netns(netns, &iptables, &["-t", "mangle", "-F", chain_name]);
    let _ = run_cmd_in_netns(netns, &iptables, &["-t", "mangle", "-X", chain_name]);
    let _ = run_cmd_in_netns(netns, &iptables, &["-t", "nat", "-F", chain_name]);
    let _ = run_cmd_in_netns(netns, &iptables, &["-t", "nat", "-X", chain_name]);
    let _ = run_cmd_in_netns(
        netns,
        &iptables,
        &["-t", "nat", "-F", postrouting_chain_name],
    );
    let _ = run_cmd_in_netns(
        netns,
        &iptables,
        &["-t", "nat", "-X", postrouting_chain_name],
    );
}

fn setup_iptables_rules() -> anyhow::Result<()> {
    cleanup_iptables_rules();
    let iptables = find_iptables_legacy_bin()?;

    run_cmd(&iptables, &["-t", "nat", "-N", "MINIUPNPD"])?;
    run_cmd(
        &iptables,
        &[
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-i",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD",
        ],
    )?;
    run_cmd(&iptables, &["-t", "nat", "-N", "MINIUPNPD-POSTROUTING"])?;
    run_cmd(
        &iptables,
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD-POSTROUTING",
        ],
    )?;

    run_cmd(&iptables, &["-t", "mangle", "-N", "MINIUPNPD"])?;
    run_cmd(
        &iptables,
        &[
            "-t",
            "mangle",
            "-A",
            "PREROUTING",
            "-i",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD",
        ],
    )?;

    run_cmd(&iptables, &["-N", "MINIUPNPD"])?;
    run_cmd(
        &iptables,
        &[
            "-A",
            "FORWARD",
            "-i",
            TEST_WAN_IF,
            "!",
            "-o",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD",
        ],
    )?;
    run_cmd(
        &iptables,
        &[
            "-A",
            "FORWARD",
            "-i",
            TEST_BRIDGE,
            "-o",
            TEST_WAN_IF,
            "-j",
            "ACCEPT",
        ],
    )?;

    Ok(())
}

fn cleanup_iptables_rules() {
    let Ok(iptables) = find_iptables_legacy_bin() else {
        return;
    };

    let _ = Command::new(&iptables)
        .args([
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD",
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-o",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD-POSTROUTING",
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-t",
            "mangle",
            "-D",
            "PREROUTING",
            "-i",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD",
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-D",
            "FORWARD",
            "-i",
            TEST_WAN_IF,
            "!",
            "-o",
            TEST_WAN_IF,
            "-j",
            "MINIUPNPD",
        ])
        .output();
    let _ = Command::new(&iptables)
        .args([
            "-D",
            "FORWARD",
            "-i",
            TEST_BRIDGE,
            "-o",
            TEST_WAN_IF,
            "-j",
            "ACCEPT",
        ])
        .output();
    let _ = Command::new(&iptables).args(["-F", "MINIUPNPD"]).output();
    let _ = Command::new(&iptables).args(["-X", "MINIUPNPD"]).output();
    let _ = Command::new(&iptables)
        .args(["-t", "mangle", "-F", "MINIUPNPD"])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "mangle", "-X", "MINIUPNPD"])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-F", "MINIUPNPD"])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-X", "MINIUPNPD"])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-F", "MINIUPNPD-POSTROUTING"])
        .output();
    let _ = Command::new(&iptables)
        .args(["-t", "nat", "-X", "MINIUPNPD-POSTROUTING"])
        .output();
}

fn run_cmd<S: AsRef<OsStr>>(cmd: S, args: &[&str]) -> anyhow::Result<()> {
    let cmd = cmd.as_ref();
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("run command {}", Path::new(cmd).display()))?;
    if output.status.success() {
        return Ok(());
    }

    Err(anyhow!(
        "{} {:?} failed: stdout={}, stderr={}",
        Path::new(cmd).display(),
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn find_miniupnpd_bin() -> anyhow::Result<PathBuf> {
    for candidate in ["miniupnpd", "/usr/sbin/miniupnpd", "/sbin/miniupnpd"] {
        let path = Path::new(candidate);
        if candidate.contains('/') {
            if path.exists() {
                return Ok(path.to_path_buf());
            }
            continue;
        }

        if Command::new("sh")
            .args(["-c", &format!("command -v {candidate}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
        {
            return Ok(path.to_path_buf());
        }
    }

    bail!("miniupnpd binary not found; install miniupnpd and miniupnpd-iptables")
}

fn find_iptables_legacy_bin() -> anyhow::Result<PathBuf> {
    for candidate in [
        "/usr/sbin/iptables-legacy",
        "/sbin/iptables-legacy",
        "iptables-legacy",
    ] {
        let path = Path::new(candidate);
        if candidate.contains('/') {
            if path.exists() {
                return Ok(path.to_path_buf());
            }
            continue;
        }

        if Command::new("sh")
            .args(["-c", &format!("command -v {candidate}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
        {
            return Ok(path.to_path_buf());
        }
    }

    bail!("iptables-legacy binary not found; install iptables legacy backend")
}

async fn query_mappings(
    query_netns: &'static str,
    expected_external_ip: Ipv4Addr,
) -> Result<Vec<PortMappingEntry>, Error> {
    tokio::task::spawn_blocking(move || {
        let _g = NetNS::new(Some(query_netns.to_owned())).guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build runtime for test igd query")?
            .block_on(async move {
                let gateway = search_gateway(SearchOptions {
                    timeout: Some(Duration::from_secs(1)),
                    single_search_timeout: Some(Duration::from_millis(300)),
                    ..Default::default()
                })
                .await
                .context("discover igd gateway")?;

                let external_ip =
                    match gateway.get_external_ip().await.context("get external ip")? {
                        IpAddr::V4(ip) => ip,
                        ip => return Err(anyhow!("unexpected external ip family: {ip}")),
                    };

                let mut entries = Vec::new();
                for index in 0..64 {
                    match gateway.get_generic_port_mapping_entry(index).await {
                        Ok(entry) => {
                            if entry.protocol == PortMappingProtocol::UDP
                                && entry.port_mapping_description == TEST_IGD_DESCRIPTION
                            {
                                entries.push(entry);
                            }
                        }
                        Err(GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid) => break,
                        Err(err) => return Err(anyhow!(err.to_string())),
                    }
                }

                if external_ip != expected_external_ip {
                    return Err(anyhow!(
                        "unexpected external ip from gateway: expected {expected_external_ip}, got {external_ip}"
                    ));
                }

                Ok(entries)
            })
    })
    .await
    .context("join test igd query task")
    .map_err(Error::from)?
    .map_err(Error::from)
}

async fn query_udp_mapping(
    query_netns: &'static str,
    expected_external_ip: Ipv4Addr,
    client_ip: Ipv4Addr,
    local_port: u16,
) -> Result<SocketAddr, Error> {
    let entries = query_mappings(query_netns, expected_external_ip).await?;
    let client_ip = client_ip.to_string();
    let entry = entries
        .into_iter()
        .find(|entry| entry.internal_client == client_ip && entry.internal_port == local_port)
        .ok_or_else(|| Error::from(anyhow!("udp mapping not found for local port {local_port}")))?;
    Ok(SocketAddr::new(
        IpAddr::V4(expected_external_ip),
        entry.external_port,
    ))
}

async fn mapping_exists(local_port: u16) -> bool {
    query_udp_mapping(TEST_NS_A, TEST_EXTERNAL_IP, TEST_CLIENT_A_IP, local_port)
        .await
        .is_ok()
}

async fn create_test_peer_manager(
    inst_name: &str,
    netns: Option<&str>,
    disable_upnp: bool,
    stun_collector: Box<dyn StunInfoCollectorTrait>,
) -> Arc<PeerManager> {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(netns.map(ToOwned::to_owned));

    let global_ctx = Arc::new(GlobalCtx::new(config));
    if disable_upnp {
        let mut flags = global_ctx.get_flags();
        flags.disable_upnp = true;
        global_ctx.set_flags(flags);
    }
    global_ctx.replace_stun_info_collector(stun_collector);

    let (packet_tx, _packet_rx) = create_packet_recv_chan();
    let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, global_ctx, packet_tx));
    peer_mgr.run().await.unwrap();
    peer_mgr
}

fn create_test_instance_config(
    inst_name: &str,
    netns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(inst_name.to_owned());
    config.set_netns(netns.map(ToOwned::to_owned));
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_ipv6(Some(ipv6.parse().unwrap()));
    config.set_listeners(vec!["udp://0.0.0.0:11010".parse().unwrap()]);
    config
}

fn create_test_instance(
    inst_name: &str,
    netns: Option<&str>,
    ipv4: &str,
    ipv6: &str,
    stun_collector: Box<dyn StunInfoCollectorTrait>,
    configure_flags: impl FnOnce(&mut crate::common::config::Flags),
) -> Instance {
    let config = create_test_instance_config(inst_name, netns, ipv4, ipv6);
    let mut flags = config.get_flags();
    flags.disable_tcp_hole_punching = true;
    configure_flags(&mut flags);
    config.set_flags(flags);

    let instance = Instance::new(config);
    instance
        .get_global_ctx()
        .replace_stun_info_collector(stun_collector);
    instance
}

async fn wait_for_port_mapping_event(
    receiver: &mut tokio::sync::broadcast::Receiver<GlobalCtxEvent>,
) -> GlobalCtxEvent {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match receiver.recv().await.unwrap() {
                event @ GlobalCtxEvent::ListenerPortMappingEstablished { .. } => return event,
                _ => continue,
            }
        }
    })
    .await
    .expect("timed out waiting for port mapping event")
}

async fn timeout_stage<F, T>(stage: &str, duration: Duration, fut: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(duration, fut)
        .await
        .unwrap_or_else(|_| panic!("timed out at stage: {stage}"))
}

async fn peer_has_udp_conn_to_remote_addr(
    peer_mgr: Arc<PeerManager>,
    peer_id: u32,
    expected_remote_addr: SocketAddr,
) -> bool {
    let Some(conns) = peer_mgr.get_peer_map().list_peer_conns(peer_id).await else {
        return false;
    };

    conns.iter().any(|conn| {
        let Some(tunnel) = conn.tunnel.as_ref() else {
            return false;
        };
        if tunnel.tunnel_type != "udp" {
            return false;
        }

        let Some(remote_addr) = tunnel.remote_addr.as_ref().or(tunnel.remote_url.as_ref()) else {
            return false;
        };
        let remote_addr: url::Url = remote_addr.clone().into();
        let Some(host) = remote_addr.host_str() else {
            return false;
        };
        let Ok(remote_ip) = host.parse::<IpAddr>() else {
            return false;
        };

        remote_ip == expected_remote_addr.ip()
            && remote_addr.port() == Some(expected_remote_addr.port())
    })
}

#[tokio::test]
#[serial_test::serial(upnp)]
async fn udp_hole_punch_listener_establishes_upnp_mapping() {
    let _env = UpnpIntegrationEnv::new().await.unwrap();
    let peer_mgr = create_test_peer_manager(
        "upnp-test-listener",
        Some(TEST_NS_A),
        false,
        Box::new(GatewayBackedStunCollector {
            netns: TEST_NS_A,
            client_ip: TEST_CLIENT_A_IP,
            external_ip: TEST_EXTERNAL_IP,
        }),
    )
    .await;
    let mut event_rx = peer_mgr.get_global_ctx().subscribe();

    let listener = UdpHolePunchListener::new(peer_mgr.clone()).await.unwrap();
    let local_port = listener.get_socket().await.local_addr().unwrap().port();

    let event = wait_for_port_mapping_event(&mut event_rx).await;
    let mapped_addr = query_udp_mapping(TEST_NS_A, TEST_EXTERNAL_IP, TEST_CLIENT_A_IP, local_port)
        .await
        .unwrap();

    match event {
        GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener,
            mapped_listener,
            backend,
        } => {
            let expected_external_ip = TEST_EXTERNAL_IP.to_string();
            assert_eq!(backend, "igd");
            assert_eq!(local_listener.scheme(), "udp");
            assert_eq!(local_listener.port(), Some(local_port));
            assert_eq!(mapped_listener.scheme(), "udp");
            assert_eq!(
                mapped_listener.host_str(),
                Some(expected_external_ip.as_str())
            );
            assert_eq!(mapped_listener.port(), Some(mapped_addr.port()));
        }
        other => panic!("unexpected event: {other:?}"),
    }

    assert!(mapping_exists(local_port).await);

    drop(listener);

    wait_for_condition(
        || async { !mapping_exists(local_port).await },
        Duration::from_secs(10),
    )
    .await;
}

#[tokio::test]
#[serial_test::serial(upnp)]
async fn udp_hole_punch_listener_skips_upnp_when_disabled() {
    let _env = UpnpIntegrationEnv::new().await.unwrap();
    let peer_mgr = create_test_peer_manager(
        "upnp-test-disabled",
        Some(TEST_NS_A),
        true,
        Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::PortRestricted,
        }),
    )
    .await;
    let mut event_rx = peer_mgr.get_global_ctx().subscribe();

    let listener = UdpHolePunchListener::new(peer_mgr.clone()).await.unwrap();
    let local_port = listener.get_socket().await.local_addr().unwrap().port();

    let event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv()).await;
    assert!(event.is_err(), "unexpected port mapping event: {event:?}");
    assert!(!mapping_exists(local_port).await);

    drop(listener);
}

#[tokio::test]
#[serial_test::serial(upnp)]
async fn udp_hole_punch_succeeds_via_upnp_mappings_with_different_external_ports() {
    let _env = DualGatewayUpnpIntegrationEnv::new().await.unwrap();

    let p_a = create_test_peer_manager(
        "upnp-test-a",
        Some(DUAL_NS_A),
        false,
        Box::new(GatewayBackedStunCollector {
            netns: DUAL_NS_A,
            client_ip: DUAL_CLIENT_A_IP,
            external_ip: DUAL_EXTERNAL_A_IP,
        }),
    )
    .await;
    let mut event_rx_a = p_a.get_global_ctx().subscribe();
    let p_b = create_test_peer_manager(
        "upnp-test-b",
        None,
        false,
        Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }),
    )
    .await;
    let p_c = create_test_peer_manager(
        "upnp-test-c",
        Some(DUAL_NS_C),
        false,
        Box::new(GatewayBackedStunCollector {
            netns: DUAL_NS_C,
            client_ip: DUAL_CLIENT_C_IP,
            external_ip: DUAL_EXTERNAL_C_IP,
        }),
    )
    .await;
    let mut event_rx_c = p_c.get_global_ctx().subscribe();

    connect_peer_manager(p_a.clone(), p_b.clone()).await;
    connect_peer_manager(p_b.clone(), p_c.clone()).await;
    timeout_stage(
        "wait_route_appear(a,c)",
        Duration::from_secs(10),
        wait_route_appear(p_a.clone(), p_c.clone()),
    )
    .await
    .unwrap();
    timeout_stage(
        "wait_route_appear_with_cost(a,c,2)",
        Duration::from_secs(10),
        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(2)),
    )
    .await
    .unwrap();
    let mut hole_punching_a = UdpHolePunchConnector::new(p_a.clone());
    let mut hole_punching_c = UdpHolePunchConnector::new(p_c.clone());
    hole_punching_a.run_as_client().await.unwrap();
    hole_punching_c.run_as_server().await.unwrap();

    timeout_stage(
        "udp_hole_punch_run_immediately(a)",
        Duration::from_secs(10),
        hole_punching_a.run_immediately_for_test(),
    )
    .await;

    let event_a = timeout_stage(
        "wait_port_mapping_event(a)",
        Duration::from_secs(15),
        wait_for_port_mapping_event(&mut event_rx_a),
    )
    .await;
    let event_c = timeout_stage(
        "wait_port_mapping_event(c)",
        Duration::from_secs(15),
        wait_for_port_mapping_event(&mut event_rx_c),
    )
    .await;

    let (local_port_a, mapped_port_a) = match event_a {
        GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener,
            mapped_listener,
            backend,
        } => {
            assert_eq!(backend, "igd");
            (
                local_listener.port().unwrap(),
                mapped_listener.port().unwrap(),
            )
        }
        other => panic!("unexpected event for a: {other:?}"),
    };
    let (local_port_c, mapped_port_c) = match event_c {
        GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener,
            mapped_listener,
            backend,
        } => {
            assert_eq!(backend, "igd");
            (
                local_listener.port().unwrap(),
                mapped_listener.port().unwrap(),
            )
        }
        other => panic!("unexpected event for c: {other:?}"),
    };

    assert_ne!(mapped_port_a, local_port_a);
    assert_ne!(mapped_port_c, local_port_c);

    let mapped_addr_a = timeout_stage(
        "query_udp_mapping(a)",
        Duration::from_secs(10),
        query_udp_mapping(
            DUAL_NS_A,
            DUAL_EXTERNAL_A_IP,
            DUAL_CLIENT_A_IP,
            local_port_a,
        ),
    )
    .await
    .unwrap();
    let mapped_addr_c = timeout_stage(
        "query_udp_mapping(c)",
        Duration::from_secs(10),
        query_udp_mapping(
            DUAL_NS_C,
            DUAL_EXTERNAL_C_IP,
            DUAL_CLIENT_C_IP,
            local_port_c,
        ),
    )
    .await
    .unwrap();

    assert_eq!(mapped_addr_a.port(), mapped_port_a);
    assert_eq!(mapped_addr_c.port(), mapped_port_c);

    timeout_stage(
        "wait_route_cost_1_after_udp_hole_punch",
        Duration::from_secs(15),
        wait_for_condition(
            || {
                let p_a = p_a.clone();
                let p_c = p_c.clone();
                async move {
                    let a_ok = p_a
                        .list_routes()
                        .await
                        .iter()
                        .any(|route| route.peer_id == p_c.my_peer_id() && route.cost == 1);
                    let c_ok = p_c
                        .list_routes()
                        .await
                        .iter()
                        .any(|route| route.peer_id == p_a.my_peer_id() && route.cost == 1);
                    a_ok && c_ok
                }
            },
            Duration::from_secs(15),
        ),
    )
    .await;

    assert_ne!(mapped_addr_a.port(), local_port_a);
    assert_ne!(mapped_addr_c.port(), local_port_c);
}

#[tokio::test]
#[serial_test::serial(upnp)]
async fn instances_build_direct_connection_via_upnp_udp_hole_punch() {
    let _env = DualGatewayUpnpIntegrationEnv::new().await.unwrap();

    let mut inst_a = create_test_instance(
        "upnp-inst-a",
        Some(DUAL_NS_A),
        "10.144.200.1/24",
        "fd20::1/64",
        Box::new(GatewayBackedStunCollector {
            netns: DUAL_NS_A,
            client_ip: DUAL_CLIENT_A_IP,
            external_ip: DUAL_EXTERNAL_A_IP,
        }),
        |flags| flags.need_p2p = true,
    );
    let mut event_rx_a = inst_a.get_global_ctx().subscribe();

    let mut inst_b = create_test_instance(
        "upnp-inst-b",
        None,
        "10.144.200.2/24",
        "fd20::2/64",
        Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }),
        |_| {},
    );

    let mut inst_c = create_test_instance(
        "upnp-inst-c",
        Some(DUAL_NS_C),
        "10.144.200.3/24",
        "fd20::3/64",
        Box::new(GatewayBackedStunCollector {
            netns: DUAL_NS_C,
            client_ip: DUAL_CLIENT_C_IP,
            external_ip: DUAL_EXTERNAL_C_IP,
        }),
        |flags| flags.need_p2p = true,
    );
    let mut event_rx_c = inst_c.get_global_ctx().subscribe();

    inst_a.run().await.unwrap();
    inst_b.run().await.unwrap();
    inst_c.run().await.unwrap();

    inst_a
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", inst_b.id()).parse().unwrap(),
        ));
    inst_c
        .get_conn_manager()
        .add_connector(RingTunnelConnector::new(
            format!("ring://{}", inst_b.id()).parse().unwrap(),
        ));

    timeout_stage(
        "wait_route_appear(inst_a, inst_c)",
        Duration::from_secs(10),
        wait_route_appear(inst_a.get_peer_manager(), inst_c.get_peer_manager()),
    )
    .await
    .unwrap();
    timeout_stage(
        "wait_route_cost_2(inst_a -> inst_c)",
        Duration::from_secs(10),
        wait_route_appear_with_cost(inst_a.get_peer_manager(), inst_c.peer_id(), Some(2)),
    )
    .await
    .unwrap();

    timeout_stage(
        "ping_over_relay_before_p2p",
        Duration::from_secs(10),
        wait_for_condition(
            || async { ping_test(DUAL_NS_A, "10.144.200.3", None).await },
            Duration::from_secs(10),
        ),
    )
    .await;

    let event_a = timeout_stage(
        "wait_instance_port_mapping_event(a)",
        Duration::from_secs(15),
        wait_for_port_mapping_event(&mut event_rx_a),
    )
    .await;
    let event_c = timeout_stage(
        "wait_instance_port_mapping_event(c)",
        Duration::from_secs(15),
        wait_for_port_mapping_event(&mut event_rx_c),
    )
    .await;

    let (local_port_a, mapped_port_a) = match event_a {
        GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener,
            mapped_listener,
            backend,
        } => {
            assert_eq!(backend, "igd");
            (
                local_listener.port().unwrap(),
                mapped_listener.port().unwrap(),
            )
        }
        other => panic!("unexpected instance event for a: {other:?}"),
    };
    let (local_port_c, mapped_port_c) = match event_c {
        GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener,
            mapped_listener,
            backend,
        } => {
            assert_eq!(backend, "igd");
            (
                local_listener.port().unwrap(),
                mapped_listener.port().unwrap(),
            )
        }
        other => panic!("unexpected instance event for c: {other:?}"),
    };

    assert_ne!(mapped_port_a, local_port_a);
    assert_ne!(mapped_port_c, local_port_c);

    let mapped_addr_a = timeout_stage(
        "query_instance_udp_mapping(a)",
        Duration::from_secs(10),
        query_udp_mapping(
            DUAL_NS_A,
            DUAL_EXTERNAL_A_IP,
            DUAL_CLIENT_A_IP,
            local_port_a,
        ),
    )
    .await
    .unwrap();
    let mapped_addr_c = timeout_stage(
        "query_instance_udp_mapping(c)",
        Duration::from_secs(10),
        query_udp_mapping(
            DUAL_NS_C,
            DUAL_EXTERNAL_C_IP,
            DUAL_CLIENT_C_IP,
            local_port_c,
        ),
    )
    .await
    .unwrap();

    assert_eq!(mapped_addr_a.port(), mapped_port_a);
    assert_eq!(mapped_addr_c.port(), mapped_port_c);

    timeout_stage(
        "wait_instance_direct_peer_via_upnp_and_route_cost_1",
        Duration::from_secs(20),
        wait_for_condition(
            || {
                let peer_mgr_a = inst_a.get_peer_manager();
                let peer_mgr_c = inst_c.get_peer_manager();
                let peer_id_a = inst_a.peer_id();
                let peer_id_c = inst_c.peer_id();
                async move {
                    peer_mgr_a.get_peer_map().has_peer(peer_id_c)
                        && peer_mgr_c.get_peer_map().has_peer(peer_id_a)
                        && peer_mgr_a
                            .list_routes()
                            .await
                            .iter()
                            .any(|route| route.peer_id == peer_id_c && route.cost == 1)
                        && peer_mgr_c
                            .list_routes()
                            .await
                            .iter()
                            .any(|route| route.peer_id == peer_id_a && route.cost == 1)
                        && peer_has_udp_conn_to_remote_addr(
                            peer_mgr_a.clone(),
                            peer_id_c,
                            mapped_addr_c,
                        )
                        .await
                        && peer_has_udp_conn_to_remote_addr(
                            peer_mgr_c.clone(),
                            peer_id_a,
                            mapped_addr_a,
                        )
                        .await
                }
            },
            Duration::from_secs(20),
        ),
    )
    .await;

    timeout_stage(
        "ping_over_direct_p2p_after_upnp",
        Duration::from_secs(10),
        wait_for_condition(
            || async { ping_test(DUAL_NS_A, "10.144.200.3", None).await },
            Duration::from_secs(10),
        ),
    )
    .await;

    drop_insts(vec![inst_a, inst_b, inst_c]).await;
}
