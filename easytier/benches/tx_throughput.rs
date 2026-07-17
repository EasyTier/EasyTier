use std::{
    net::IpAddr,
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::BytesMut;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

use easytier::{
    common::config::{ConfigLoader, TomlConfigLoader},
    instance::instance::Instance,
    tunnel::{
        packet_def::ZCPacket, ring::RingTunnelConnector, tcp::TcpTunnelConnector,
        udp::UdpTunnelConnector,
    },
};

const VIRTUAL_IP_A: &str = "10.144.144.1";
const VIRTUAL_IP_B: &str = "10.144.144.2";
const DEFAULT_DOCKER_SUBNET: &str = "172.31.250.0/24";
const DEFAULT_DOCKER_IP_A: &str = "172.31.250.2";
const DEFAULT_DOCKER_IP_B: &str = "172.31.250.3";
const DEFAULT_TUNNEL_PORT: u16 = 35521;

#[derive(Clone, Copy, Debug)]
enum TunnelKind {
    Ring,
    Tcp,
    Udp,
}

impl TunnelKind {
    fn as_str(self) -> &'static str {
        match self {
            TunnelKind::Ring => "ring",
            TunnelKind::Tcp => "tcp",
            TunnelKind::Udp => "udp",
        }
    }
}

impl FromStr for TunnelKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ring" => Ok(TunnelKind::Ring),
            "tcp" => Ok(TunnelKind::Tcp),
            "udp" => Ok(TunnelKind::Udp),
            other => Err(format!(
                "unsupported TX_THROUGHPUT_TUNNEL={other:?}; expected ring, tcp, or udp"
            )),
        }
    }
}

struct BenchTopology {
    _docker: Option<DockerNetns>,
    inst_a: Instance,
    _inst_b: Instance,
    dst: IpAddr,
    packet: ZCPacket,
}

struct DockerNetns {
    network: String,
    container_a: String,
    container_b: String,
    netns_a: String,
    netns_b: String,
    ip_a: String,
    netns_a_path: PathBuf,
    netns_b_path: PathBuf,
}

impl DockerNetns {
    fn create() -> Self {
        let id = unique_id();
        let image = env_string("TX_THROUGHPUT_DOCKER_IMAGE", "busybox:latest");
        let network = env_string("TX_THROUGHPUT_DOCKER_NET", &format!("easytier-bench-{id}"));
        let subnet = env_string("TX_THROUGHPUT_DOCKER_SUBNET", DEFAULT_DOCKER_SUBNET);
        let ip_a = env_string("TX_THROUGHPUT_DOCKER_IP_A", DEFAULT_DOCKER_IP_A);
        let ip_b = env_string("TX_THROUGHPUT_DOCKER_IP_B", DEFAULT_DOCKER_IP_B);
        let container_a = format!("easytier-bench-a-{id}");
        let container_b = format!("easytier-bench-b-{id}");
        let netns_a = format!("easytier-bench-a-{id}");
        let netns_b = format!("easytier-bench-b-{id}");

        docker(&[
            "network", "create", "--driver", "bridge", "--subnet", &subnet, &network,
        ]);

        let mut docker_netns = Self {
            network,
            container_a,
            container_b,
            netns_a,
            netns_b,
            ip_a: ip_a.clone(),
            netns_a_path: PathBuf::new(),
            netns_b_path: PathBuf::new(),
        };

        docker_netns.start_container(&docker_netns.container_a, &ip_a, &image);
        docker_netns.start_container(&docker_netns.container_b, &ip_b, &image);

        let pid_a = docker(&["inspect", "-f", "{{.State.Pid}}", &docker_netns.container_a]);
        let pid_b = docker(&["inspect", "-f", "{{.State.Pid}}", &docker_netns.container_b]);

        docker_netns.netns_a_path = register_netns(&docker_netns.netns_a, &pid_a);
        docker_netns.netns_b_path = register_netns(&docker_netns.netns_b, &pid_b);
        docker_netns
    }

    fn start_container(&self, name: &str, ip: &str, image: &str) {
        docker(&[
            "run",
            "-d",
            "--name",
            name,
            "--network",
            &self.network,
            "--ip",
            ip,
            image,
            "sleep",
            "3600",
        ]);
    }
}

impl Drop for DockerNetns {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.netns_a_path);
        let _ = std::fs::remove_file(&self.netns_b_path);
        docker_ignore(&["rm", "-f", &self.container_a, &self.container_b]);
        docker_ignore(&["network", "rm", &self.network]);
    }
}

fn bench_tx_throughput(c: &mut Criterion) {
    let tunnel = env_string("TX_THROUGHPUT_TUNNEL", "ring")
        .parse::<TunnelKind>()
        .unwrap_or_else(|err| panic!("{err}"));
    let packet_size = env_parse("TX_THROUGHPUT_PKT_SIZE", 1400usize);
    const MIN_PKT_SIZE: usize = 28; // IPv4 (20) + UDP (8) header
    assert!(
        packet_size >= MIN_PKT_SIZE,
        "TX_THROUGHPUT_PKT_SIZE={packet_size} is smaller than the minimum {MIN_PKT_SIZE} (IPv4+UDP headers)"
    );
    let worker_threads = env_parse("TX_THROUGHPUT_WORKER_THREADS", 4usize);
    let inflight_depth = env_parse("TX_THROUGHPUT_INFLIGHT", 64usize).max(1);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .expect("create tokio runtime");

    let topology = runtime.block_on(setup_topology(tunnel, packet_size));
    let peer_manager = topology.inst_a.get_peer_manager();
    let packet = topology.packet.clone();
    let dst = topology.dst;

    eprintln!(
        "tx_throughput: tunnel={} inflight={} workers={} pkt_size={}",
        tunnel.as_str(),
        inflight_depth.max(1),
        worker_threads,
        packet_size
    );

    let mut group = c.benchmark_group("tx_throughput");
    group.throughput(Throughput::Bytes(packet_size as u64));

    // Serial baseline: one packet in flight at a time.
    // Measures per-packet CPU cost (TX injection latency).
    group.bench_function(tunnel.as_str(), |b| {
        b.iter_custom(|iterations| {
            let pm = peer_manager.clone();
            let pkt = packet.clone();
            runtime.block_on(async move {
                let start = Instant::now();
                for _ in 0..iterations {
                    pm.send_msg_by_ip(pkt.clone(), dst, false)
                        .await
                        .expect("send packet by EasyTier IP");
                }
                start.elapsed()
            })
        });
    });

    // Saturate: spawn TX_THROUGHPUT_INFLIGHT worker tasks, each independently
    // pumping send_msg_by_ip. Work is distributed across tokio worker threads,
    // exposing the peer manager + tunnel's true aggregate throughput ceiling.
    // With TX_THROUGHPUT_INFLIGHT=1 it degrades to the serial baseline.
    group.bench_function(format!("{}-saturate", tunnel.as_str()), |b| {
        b.iter_custom(|iterations| {
            let pm = peer_manager.clone();
            let pkt = packet.clone();
            let concurrency = inflight_depth.min(iterations as usize).max(1);
            runtime.block_on(async move {
                let counter = Arc::new(AtomicU64::new(iterations));
                let start = Instant::now();
                let mut handles = Vec::with_capacity(concurrency);
                for _ in 0..concurrency {
                    let pm = pm.clone();
                    let pkt = pkt.clone();
                    let counter = counter.clone();
                    handles.push(tokio::spawn(async move {
                        loop {
                            if counter
                                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |cur| {
                                    if cur > 0 { Some(cur - 1) } else { None }
                                })
                                .is_err()
                            {
                                return;
                            }
                            pm.send_msg_by_ip(pkt.clone(), dst, false)
                                .await
                                .expect("send packet by EasyTier IP");
                        }
                    }));
                }
                for h in handles {
                    h.await.expect("saturate worker task panicked");
                }
                start.elapsed()
            })
        });
    });

    group.finish();

    runtime.block_on(async move {
        drop(topology);
    });
}

async fn setup_topology(tunnel: TunnelKind, packet_size: usize) -> BenchTopology {
    let tunnel_port = env_parse("TX_THROUGHPUT_TUNNEL_PORT", DEFAULT_TUNNEL_PORT);
    let docker = match tunnel {
        TunnelKind::Ring => None,
        TunnelKind::Tcp | TunnelKind::Udp => Some(DockerNetns::create()),
    };

    let (netns_a, netns_b) = match &docker {
        Some(docker) => (Some(docker.netns_a.clone()), Some(docker.netns_b.clone())),
        None => (None, None),
    };
    let listeners_a = match tunnel {
        TunnelKind::Ring => Vec::new(),
        TunnelKind::Tcp | TunnelKind::Udp => vec![
            format!("{}://0.0.0.0:{}", tunnel.as_str(), tunnel_port)
                .parse()
                .unwrap(),
        ],
    };

    let mut inst_a = Instance::new(no_tun_config("hot-a", VIRTUAL_IP_A, netns_a, listeners_a));
    let mut inst_b = Instance::new(no_tun_config("hot-b", VIRTUAL_IP_B, netns_b, Vec::new()));

    inst_a.run().await.expect("inst_a run");
    inst_b.run().await.expect("inst_b run");

    match tunnel {
        TunnelKind::Ring => inst_b
            .get_conn_manager()
            .add_connector(RingTunnelConnector::new(
                format!("ring://{}", inst_a.id()).parse().unwrap(),
            )),
        TunnelKind::Tcp => inst_b
            .get_conn_manager()
            .add_connector(TcpTunnelConnector::new(
                format!(
                    "tcp://{}:{}",
                    docker.as_ref().expect("tcp benchmark needs Docker").ip_a,
                    tunnel_port
                )
                .parse()
                .unwrap(),
            )),
        TunnelKind::Udp => inst_b
            .get_conn_manager()
            .add_connector(UdpTunnelConnector::new(
                format!(
                    "udp://{}:{}",
                    docker.as_ref().expect("udp benchmark needs Docker").ip_a,
                    tunnel_port
                )
                .parse()
                .unwrap(),
            )),
    }

    wait_for_routes(&inst_a, &inst_b).await;

    BenchTopology {
        _docker: docker,
        inst_a,
        _inst_b: inst_b,
        dst: VIRTUAL_IP_B.parse().unwrap(),
        packet: make_data_packet(VIRTUAL_IP_A, VIRTUAL_IP_B, packet_size),
    }
}

async fn wait_for_routes(inst_a: &Instance, inst_b: &Instance) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let routes_a = inst_a.get_peer_manager().list_routes().await;
            let routes_b = inst_b.get_peer_manager().list_routes().await;
            if !routes_a.is_empty() && !routes_b.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("EasyTier routes did not converge within 15s");
}

fn make_data_packet(src: &str, dst: &str, total_size: usize) -> ZCPacket {
    use std::net::Ipv4Addr;

    let hdr_len = 28;
    let payload_len = total_size.saturating_sub(hdr_len);
    let ip_total_len = (hdr_len + payload_len) as u16;
    let mut buf = BytesMut::with_capacity(total_size);

    buf.extend_from_slice(&[
        0x45,
        0x00,
        (ip_total_len >> 8) as u8,
        (ip_total_len & 0xff) as u8,
        0x00,
        0x00,
        0x40,
        0x00,
        0x40,
        0x11,
        0x00,
        0x00,
    ]);
    let src: Ipv4Addr = src.parse().unwrap();
    buf.extend_from_slice(&src.octets());
    let dst: Ipv4Addr = dst.parse().unwrap();
    buf.extend_from_slice(&dst.octets());

    let udp_len = (8 + payload_len) as u16;
    buf.extend_from_slice(&[
        0x30,
        0x39,
        0xd4,
        0x31,
        (udp_len >> 8) as u8,
        (udp_len & 0xff) as u8,
        0x00,
        0x00,
    ]);

    buf.resize(total_size, 0xaa);
    ZCPacket::new_with_payload(&buf)
}

fn no_tun_config(
    name: &str,
    ipv4: &str,
    netns: Option<String>,
    listeners: Vec<url::Url>,
) -> TomlConfigLoader {
    let config = TomlConfigLoader::default();
    config.set_inst_name(name.to_owned());
    config.set_netns(netns);
    config.set_ipv4(Some(ipv4.parse().unwrap()));
    config.set_listeners(listeners);
    let mut flags = config.get_flags();
    flags.no_tun = true;
    config.set_flags(flags);
    config
}

fn register_netns(name: &str, pid: &str) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        let dir = PathBuf::from("/var/run/netns");
        std::fs::create_dir_all(&dir).expect("create /var/run/netns");
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        std::os::unix::fs::symlink(format!("/proc/{pid}/ns/net"), &path)
            .expect("link Docker netns into /var/run/netns");
        path
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, pid);
        panic!("Docker netns benchmark requires Linux");
    }
}

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run docker {args:?}: {err}"));
    if !output.status.success() {
        panic!(
            "docker {:?} failed with status {:?}: {}",
            args,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn docker_ignore(args: &[&str]) {
    let _ = Command::new("docker")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn env_parse<T>(name: &str, default: T) -> T
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|err| panic!("invalid {name}={value:?}: {err}")),
        Err(_) => default,
    }
}

fn criterion_config() -> Criterion {
    let measurement_secs = env_parse("TX_THROUGHPUT_MEASUREMENT_SECS", 10u64);
    let warmup_secs = env_parse("TX_THROUGHPUT_WARMUP_SECS", 3u64);
    let sample_size = env_parse("TX_THROUGHPUT_SAMPLE_SIZE", 10usize).max(10);

    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .warm_up_time(Duration::from_secs(warmup_secs))
        .sample_size(sample_size)
}

fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos();
    format!("{}-{nanos}", std::process::id())
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_tx_throughput
}
criterion_main!(benches);
