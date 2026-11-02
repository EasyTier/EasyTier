use std::{collections::hash_map::DefaultHasher, hash::Hasher, net::SocketAddr};

#[cfg(any(feature = "faketcp", feature = "websocket", feature = "wireguard"))]
use crate::common::dns::socket_addrs;
use crate::common::error::Error;
use derive_more::{From, TryInto};
#[cfg(any(feature = "faketcp", feature = "websocket", feature = "wireguard"))]
use easytier_core::tunnel::{IpVersion, TunnelError};
use strum::{Display, EnumString, IntoStaticStr, VariantArray};

pub(crate) mod protocol;

#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "websocket")]
pub mod websocket;

pub fn build_url_from_socket_addr(addr: &String, scheme: &str) -> url::Url {
    if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
        let url_str = format!("{}://0.0.0.0", scheme);
        let mut ret_url = url::Url::parse(url_str.as_str())
            .unwrap_or_else(|_| panic!("invalid url: {}", url_str));
        ret_url.set_ip_host(sock_addr.ip()).unwrap();
        ret_url.set_port(Some(sock_addr.port())).unwrap();
        ret_url
    } else {
        url::Url::parse(format!("{}://{}", scheme, addr).as_str()).unwrap()
    }
}

#[async_trait::async_trait]
#[cfg(any(feature = "faketcp", feature = "websocket", feature = "wireguard"))]
pub(crate) trait FromUrl {
    async fn from_url(url: url::Url, ip_version: IpVersion) -> Result<Self, TunnelError>
    where
        Self: Sized;
}

#[async_trait::async_trait]
#[cfg(any(feature = "faketcp", feature = "websocket", feature = "wireguard"))]
impl FromUrl for SocketAddr {
    async fn from_url(url: url::Url, ip_version: IpVersion) -> Result<Self, TunnelError> {
        let addrs = socket_addrs(&url, || {
            (&url)
                .try_into()
                .ok()
                .and_then(|s: TunnelScheme| s.try_into().ok())
                .map(IpScheme::default_port)
        })
        .await
        .map_err(|e| {
            TunnelError::InvalidAddr(format!(
                "failed to resolve socket addr, url: {}, error: {}",
                url, e
            ))
        })?;
        tracing::debug!(?addrs, ?ip_version, ?url, "convert url to socket addrs");
        let addrs = addrs
            .into_iter()
            .filter(|addr| match ip_version {
                IpVersion::V4 => addr.is_ipv4(),
                IpVersion::V6 => addr.is_ipv6(),
                IpVersion::Both => true,
            })
            .collect::<Vec<_>>();

        use rand::seq::SliceRandom;
        // randomly select one address
        addrs
            .choose(&mut rand::thread_rng())
            .copied()
            .ok_or(TunnelError::NoDnsRecordFound(ip_version))
    }
}

pub struct TunnelUrl {
    inner: url::Url,
}

impl From<url::Url> for TunnelUrl {
    fn from(url: url::Url) -> Self {
        TunnelUrl { inner: url }
    }
}

impl From<TunnelUrl> for url::Url {
    fn from(url: TunnelUrl) -> Self {
        url.into_inner()
    }
}

impl TunnelUrl {
    pub fn into_inner(self) -> url::Url {
        self.inner
    }

    pub fn bind_dev(&self) -> Option<String> {
        self.inner.path().strip_prefix("/").and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(String::from_utf8(percent_encoding::percent_decode_str(s).collect()).unwrap())
            }
        })
    }
}

pub fn generate_digest_from_str(str1: &str, str2: &str, digest: &mut [u8]) {
    let mut hasher = DefaultHasher::new();
    hasher.write(str1.as_bytes());
    hasher.write(str2.as_bytes());

    assert_eq!(digest.len() % 8, 0, "digest length must be multiple of 8");

    let shard_count = digest.len() / 8;
    for i in 0..shard_count {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Display, EnumString, IntoStaticStr, VariantArray)]
#[strum(serialize_all = "lowercase")]
pub enum IpScheme {
    Tcp,
    Udp,
    #[cfg(feature = "wireguard")]
    Wg,
    #[cfg(feature = "quic")]
    Quic,
    #[cfg(feature = "websocket")]
    Ws,
    #[cfg(feature = "websocket")]
    Wss,
    #[cfg(feature = "faketcp")]
    FakeTcp,
}

impl IpScheme {
    pub fn port_offset(self) -> u16 {
        let scheme: &'static str = self.into();
        easytier_core::connectivity::protocol::protocol_port_offset(scheme)
            .expect("IpScheme must have core protocol metadata")
    }

    pub fn default_port(self) -> u16 {
        let scheme: &'static str = self.into();
        easytier_core::connectivity::protocol::protocol_default_port(scheme)
            .expect("IpScheme must have core protocol metadata")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, EnumString, From, TryInto)]
#[strum(serialize_all = "lowercase")]
pub enum TunnelScheme {
    #[strum(disabled)]
    Ip(IpScheme),
    #[cfg(unix)]
    Unix,
    // Only for connector
    Http,
    Https,
    Ring,
    Txt,
    Srv,
}

impl TryFrom<&url::Url> for TunnelScheme {
    type Error = Error;

    fn try_from(value: &url::Url) -> Result<Self, Self::Error> {
        let scheme = value.scheme();
        scheme.parse().or_else(|_| {
            Ok(TunnelScheme::Ip(
                scheme
                    .parse()
                    .map_err(|_| Error::InvalidUrl(value.to_string()))?,
            ))
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use atomic_shim::AtomicU64;
    use std::{sync::Arc, time::Instant};

    use anyhow::Context as _;
    use futures::{Future, SinkExt, StreamExt};
    use tokio_util::bytes::{BufMut, Bytes, BytesMut};
    use tokio_util::task::AbortOnDropHandle;

    use easytier_core::{
        connectivity::protocol::raw::TunnelDialer, packet::ZCPacket, socket::SocketListener,
        tunnel::Tunnel,
    };

    use crate::common::netns::NetNS;

    #[cfg(target_os = "windows")]
    #[test]
    fn interface_snapshot_lookup_smoke_test() {
        // The process-global cache may expire between reads. Identity checks
        // belong to the isolated helper tests in common::network instead.
        for _ in 0..2 {
            let ifaces = crate::common::network::get_interfaces_cached()
                .expect("interface lookup should work");
            assert!(!ifaces.is_empty());
        }
    }

    // Diagnostic probe for the issue #2735 slow candidate loop: run with
    // `cargo test -p easytier --lib probe_interface_lookup -- --ignored --nocapture`.
    // Compare only IP-to-name and name-to-index lookups, not socket binding.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "diagnostic probe; enumerates live Windows adapters"]
    fn probe_interface_lookup_latency_with_and_without_cache() {
        use network_interface::{NetworkInterface, NetworkInterfaceConfig};
        use std::net::IpAddr;

        type EnumerateInterfaces = fn() -> Option<Arc<Vec<NetworkInterface>>>;

        fn lookup_index(ip: IpAddr, enumerate: EnumerateInterfaces) -> Option<u32> {
            let ifaces = enumerate()?;
            let name = &ifaces
                .iter()
                .find(|iface| iface.addr.iter().any(|addr| addr.ip() == ip))?
                .name;
            let ifaces = enumerate()?;
            ifaces
                .iter()
                .find(|iface| iface.name == *name)
                .map(|iface| iface.index)
        }

        let ifaces = NetworkInterface::show().unwrap();
        let candidates: Vec<_> = ifaces
            .iter()
            .flat_map(|iface| {
                iface.addr.iter().filter_map(move |addr| {
                    matches!(addr.ip(), IpAddr::V4(_)).then(|| (iface.name.clone(), addr.ip()))
                })
            })
            .collect();
        println!("IPv4 lookup candidates ({}):", candidates.len());

        let providers: [(&str, EnumerateInterfaces); 2] = [
            ("uncached", || NetworkInterface::show().ok().map(Arc::new)),
            ("cached", crate::common::network::get_interfaces_cached),
        ];
        for (label, enumerate) in providers {
            let mut total = std::time::Duration::ZERO;
            for (name, ip) in &candidates {
                let start = Instant::now();
                let index = lookup_index(*ip, enumerate);
                let elapsed = start.elapsed();
                total += elapsed;
                println!("  [{label}] {ip:>16} ({name}): lookup {elapsed:?}, index={index:?}");
            }
            println!(
                "{label} lookup total: {total:?} ({} candidates)",
                candidates.len()
            );
        }
    }

    pub async fn _tunnel_echo_server(tunnel: Box<dyn Tunnel>, once: bool) {
        let (mut recv, mut send) = tunnel.split();

        if !once {
            while let Some(item) = recv.next().await {
                let Ok(msg) = item else {
                    break;
                };
                tracing::debug!(?msg, "recv a msg, try echo back");
                if send.send(msg).await.is_err() {
                    break;
                }
            }
        } else {
            let Some(ret) = recv.next().await else {
                panic!("recv error");
            };

            if ret.is_err() {
                tracing::debug!(?ret, "recv error");
                return;
            }

            let res = ret.unwrap();
            tracing::debug!(?res, "recv a msg, try echo back");
            send.send(res).await.unwrap();
        }
        let _ = send.flush().await;
        let _ = send.close().await;

        tracing::warn!("echo server exit...");
    }

    #[tokio::test]
    async fn echo_server_stops_on_read_error() {
        use easytier_core::tunnel::{TunnelError, wrapper::TunnelWrapper};

        let mut failed = false;
        let reader = futures::stream::poll_fn(move |_| {
            assert!(!failed, "a terminal read error must not be polled again");
            failed = true;
            std::task::Poll::Ready(Some(Err::<ZCPacket, _>(TunnelError::IOError(
                std::io::ErrorKind::NotConnected.into(),
            ))))
        });
        let writer = futures::sink::drain().sink_map_err(|err| -> TunnelError { match err {} });

        _tunnel_echo_server(Box::new(TunnelWrapper::new(reader, writer, None)), false).await;
    }

    async fn _tunnel_pingpong_netns<L, C>(
        mut listener: L,
        connector: C,
        l_netns: NetNS,
        c_netns: NetNS,
        buf: Vec<u8>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<()>
    where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        tokio::time::timeout(timeout, l_netns.run_async(|| listener.listen()))
            .await
            .context("listener setup timed out")?
            .context("listener setup failed")?;

        let lis = AbortOnDropHandle::new(tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            println!("accept: {:?}", ret.info());
            assert_eq!(
                url::Url::from(ret.info().unwrap().local_addr.unwrap()),
                listener.local_url()
            );
            _tunnel_echo_server(ret, false).await
        }));

        let tunnel = tokio::time::timeout(timeout, c_netns.run_async(|| connector.connect()))
            .await
            .context("connect timed out")?
            .context("connect failed")?;
        println!("connect: {:?}", tunnel.info());

        if connector.remote_url().scheme() == "faketcp" {
            // listener need some time to start capturing packet
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        assert_eq!(
            url::Url::from(tunnel.info().unwrap().remote_addr.unwrap()),
            connector.remote_url(),
        );

        let (mut recv, mut send) = tunnel.split();

        tokio::time::timeout(
            timeout,
            send.send(ZCPacket::new_with_payload(buf.as_slice())),
        )
        .await
        .context("send timed out")?
        .context("send failed")?;

        let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), recv.next())
            .await
            .context("echo timed out")?
            .context("tunnel closed before echo")?
            .context("echo read failed")?;
        println!("echo back: {:?}", ret);
        assert_eq!(ret.payload(), Bytes::from(buf));

        tokio::time::timeout(std::time::Duration::from_secs(1), send.close())
            .await
            .context("client close timed out")?
            .context("client close failed")?;

        if ["udp", "wg"].contains(&connector.remote_url().scheme()) {
            lis.abort();
            let _ = lis.await;
        } else {
            // lis should finish in 1 second
            let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), lis).await;
            ret.context("echo server shutdown timed out")?
                .context("echo server task failed")?;
        }
        Ok(())
    }

    pub(crate) async fn _tunnel_pingpong_netns_with_timeout<L, C>(
        listener: L,
        connector: C,
        l_netns: NetNS,
        c_netns: NetNS,
        buf: Vec<u8>,
        timeout: std::time::Duration,
    ) -> Result<(), anyhow::Error>
    where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        // Each phase has its own deadline; connection setup must not consume
        // the echo or shutdown budget. Dropping the caller cancels both tasks.
        let handle = AbortOnDropHandle::new(tokio::spawn(async move {
            _tunnel_pingpong_netns(listener, connector, l_netns, c_netns, buf, timeout).await
        }));

        match handle.await {
            Ok(result) => {
                result.inspect_err(|error| eprintln!("tunnel pingpong failed: {error:#}"))
            }
            Err(join_err) => {
                if join_err.is_panic() {
                    let payload = join_err.into_panic();
                    let msg = match payload.downcast::<String>() {
                        Ok(s) => *s,
                        Err(payload) => match payload.downcast::<&str>() {
                            Ok(s) => (*s).to_string(),
                            Err(_) => "non-string panic payload".to_string(),
                        },
                    };
                    Err(anyhow::anyhow!("task panicked: {}", msg))
                } else {
                    Err(anyhow::anyhow!("task cancelled"))
                }
            }
        }
    }

    pub(crate) async fn _tunnel_bench_netns<L, C>(
        mut listener: L,
        connector: C,
        netns_l: NetNS,
        netns_c: NetNS,
        meter: Option<&(dyn Fn() -> u64 + Sync)>,
    ) -> (usize, Option<(u64, std::time::Duration)>)
    where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        {
            let _g = netns_l.guard();
            listener.listen().await.unwrap();
        }

        let bps = Arc::new(AtomicU64::new(0));
        let bps_clone = bps.clone();

        let lis = tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            // _tunnel_echo_server(ret, false).await
            let (mut r, _s) = ret.split();
            let now = Instant::now();
            let mut count = 0;
            let warmup = std::time::Duration::from_secs(1);
            while let Some(Ok(p)) = r.next().await {
                let elapsed = now.elapsed();
                if elapsed < warmup {
                    continue;
                }
                count += p.payload_len();
                let elapsed = (elapsed - warmup).as_secs();
                if elapsed >= 1 {
                    bps_clone.store(count as u64 / elapsed, std::sync::atomic::Ordering::Relaxed);
                }
            }
        });

        let tunnel = {
            let _g = netns_c.guard();
            connector.connect().await.unwrap()
        };

        let (_recv, mut send) = tunnel.split();

        // prepare a 4k buffer with random data
        let mut send_buf = BytesMut::new();
        for _ in 0..64 {
            send_buf.put_i128(rand::random::<i128>());
        }

        let now = Instant::now();
        let mut meter_base = None;
        while now.elapsed().as_secs() < 10 {
            // Skip the initial burst so the metered window reflects the
            // sustained rate the limiter enforces.
            if meter_base.is_none() && now.elapsed() >= std::time::Duration::from_secs(1) {
                meter_base = meter.map(|meter| (meter(), now.elapsed()));
            }
            // send.feed(item)
            let item = ZCPacket::new_with_payload(send_buf.as_ref());
            send.feed(item).await.unwrap();
        }
        let metered = match (meter_base, meter) {
            (Some((metered, started)), Some(meter)) => {
                Some((meter().saturating_sub(metered), now.elapsed() - started))
            }
            _ => None,
        };

        send.close().await.unwrap();
        drop(send);
        drop(connector);
        drop(tunnel);

        tracing::warn!("wait for recv to finish...");
        let bps = bps.load(std::sync::atomic::Ordering::Acquire);
        println!("bps: {}", bps);

        lis.abort();
        (bps as usize, metered)
    }

    pub async fn wait_for_condition<F, FRet>(condition: F, timeout: std::time::Duration)
    where
        F: FnMut() -> FRet + Send,
        FRet: Future<Output = bool>,
    {
        wait_for_condition_named(condition, timeout, "condition").await
    }

    /// Like [`wait_for_condition`], but the panic names the gate that timed out.
    pub async fn wait_for_condition_named<F, FRet>(
        mut condition: F,
        timeout: std::time::Duration,
        what: &str,
    ) where
        F: FnMut() -> FRet + Send,
        FRet: Future<Output = bool>,
    {
        let now = std::time::Instant::now();
        while now.elapsed() < timeout {
            if condition().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(condition().await, "Timeout waiting for {what}")
    }
}
