use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::rpc::{NatType, StunInfo};
use anyhow::Context;
use crossbeam::atomic::AtomicCell;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tracing::Level;

use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::rfc5780::attributes::ChangeRequest;
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};

use crate::common::error::Error;

use super::stun_codec_ext::*;

struct HostResolverIter {
    hostnames: Vec<String>,
    ips: Vec<SocketAddr>,
}

impl HostResolverIter {
    fn new(hostnames: Vec<String>) -> Self {
        Self {
            hostnames,
            ips: vec![],
        }
    }

    #[async_recursion::async_recursion]
    async fn next(&mut self) -> Option<SocketAddr> {
        if self.ips.is_empty() {
            if self.hostnames.is_empty() {
                return None;
            }

            let host = self.hostnames.remove(0);
            match lookup_host(&host).await {
                Ok(ips) => {
                    self.ips = ips.collect();
                }
                Err(e) => {
                    tracing::warn!(?host, ?e, "lookup host for stun failed");
                    return self.next().await;
                }
            };
        }

        Some(self.ips.remove(0))
    }
}

#[derive(Debug, Clone, Copy)]
struct BindRequestResponse {
    source_addr: SocketAddr,
    send_to_addr: SocketAddr,
    recv_from_addr: SocketAddr,
    mapped_socket_addr: Option<SocketAddr>,
    changed_socket_addr: Option<SocketAddr>,

    ip_changed: bool,
    port_changed: bool,

    real_ip_changed: bool,
    real_port_changed: bool,
}

impl BindRequestResponse {
    pub fn get_mapped_addr_no_check(&self) -> &SocketAddr {
        self.mapped_socket_addr.as_ref().unwrap()
    }
}

#[derive(Debug, Clone)]
struct Stun {
    stun_server: SocketAddr,
    req_repeat: u8,
    resp_timeout: Duration,
}

impl Stun {
    pub fn new(stun_server: SocketAddr) -> Self {
        Self {
            stun_server,
            req_repeat: 1,
            resp_timeout: Duration::from_millis(3000),
        }
    }

    #[tracing::instrument(skip(self, buf))]
    async fn wait_stun_response<'a, const N: usize>(
        &self,
        buf: &'a mut [u8; N],
        udp: &UdpSocket,
        tids: &Vec<u128>,
        expected_ip_changed: bool,
        expected_port_changed: bool,
        stun_host: &SocketAddr,
    ) -> Result<(Message<Attribute>, SocketAddr), Error> {
        let mut now = tokio::time::Instant::now();
        let deadline = now + self.resp_timeout;

        while now < deadline {
            let mut udp_buf = [0u8; 1500];
            let (len, remote_addr) =
                tokio::time::timeout(deadline - now, udp.recv_from(udp_buf.as_mut_slice()))
                    .await??;
            now = tokio::time::Instant::now();

            if len < 20 {
                continue;
            }

            // TODO:: we cannot borrow `buf` directly in udp recv_from, so we copy it here
            unsafe { std::ptr::copy(udp_buf.as_ptr(), buf.as_ptr() as *mut u8, len) };

            let mut decoder = MessageDecoder::<Attribute>::new();
            let Ok(msg) = decoder
                .decode_from_bytes(&buf[..len])
                .with_context(|| format!("decode stun msg {:?}", buf))?
            else {
                continue;
            };

            tracing::debug!(b = ?&udp_buf[..len], ?tids, ?remote_addr, ?stun_host, "recv stun response, msg: {:#?}", msg);

            if msg.class() != MessageClass::SuccessResponse
                || msg.method() != BINDING
                || !tids.contains(&tid_to_u128(&msg.transaction_id()))
            {
                continue;
            }

            // some stun server use changed socket even we don't ask for.
            if expected_ip_changed && stun_host.ip() == remote_addr.ip() {
                continue;
            }

            if expected_port_changed
                && stun_host.ip() == remote_addr.ip()
                && stun_host.port() == remote_addr.port()
            {
                continue;
            }

            return Ok((msg, remote_addr));
        }

        Err(Error::Unknown)
    }

    fn extrace_mapped_addr(msg: &Message<Attribute>) -> Option<SocketAddr> {
        let mut mapped_addr = None;
        for x in msg.attributes() {
            match x {
                Attribute::MappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(addr.address());
                    }
                }
                Attribute::XorMappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(addr.address());
                    }
                }
                _ => {}
            }
        }
        mapped_addr
    }

    fn extract_changed_addr(msg: &Message<Attribute>) -> Option<SocketAddr> {
        let mut changed_addr = None;
        for x in msg.attributes() {
            match x {
                Attribute::OtherAddress(m) => {
                    if changed_addr.is_none() {
                        let _ = changed_addr.insert(m.address());
                    }
                }
                Attribute::ChangedAddress(m) => {
                    if changed_addr.is_none() {
                        let _ = changed_addr.insert(m.address());
                    }
                }
                _ => {}
            }
        }
        changed_addr
    }

    #[tracing::instrument(ret, err, level = Level::DEBUG)]
    pub async fn bind_request(
        &self,
        source_port: u16,
        change_ip: bool,
        change_port: bool,
    ) -> Result<BindRequestResponse, Error> {
        let stun_host = self.stun_server;
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", source_port)).await?;

        // repeat req in case of packet loss
        let mut tids = vec![];
        for _ in 0..self.req_repeat {
            let tid = rand::random::<u32>();
            // let tid = 1;
            let mut buf = [0u8; 28];
            // memset buf
            unsafe { std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len()) };

            let mut message =
                Message::<Attribute>::new(MessageClass::Request, BINDING, u128_to_tid(tid as u128));
            message.add_attribute(ChangeRequest::new(change_ip, change_port));

            // Encodes the message
            let mut encoder = MessageEncoder::new();
            let msg = encoder
                .encode_into_bytes(message.clone())
                .with_context(|| "encode stun message")?;

            tids.push(tid as u128);
            tracing::trace!(?message, ?msg, tid, "send stun request");
            udp.send_to(msg.as_slice().into(), &stun_host).await?;
        }

        tracing::trace!("waiting stun response");
        let mut buf = [0; 1620];
        let (msg, recv_addr) = self
            .wait_stun_response(&mut buf, &udp, &tids, change_ip, change_port, &stun_host)
            .await?;

        let changed_socket_addr = Self::extract_changed_addr(&msg);
        let real_ip_changed = stun_host.ip() != recv_addr.ip();
        let real_port_changed = stun_host.port() != recv_addr.port();

        let resp = BindRequestResponse {
            source_addr: udp.local_addr()?,
            send_to_addr: stun_host,
            recv_from_addr: recv_addr,
            mapped_socket_addr: Self::extrace_mapped_addr(&msg),
            changed_socket_addr,
            ip_changed: change_ip,
            port_changed: change_port,

            real_ip_changed,
            real_port_changed,
        };

        tracing::debug!(
            ?stun_host,
            ?recv_addr,
            ?changed_socket_addr,
            "finish stun bind request"
        );

        Ok(resp)
    }
}

pub struct UdpNatTypeDetector {
    stun_servers: Vec<String>,
}

impl UdpNatTypeDetector {
    pub fn new(stun_servers: Vec<String>) -> Self {
        Self { stun_servers }
    }

    pub async fn get_udp_nat_type(&self, mut source_port: u16) -> NatType {
        // Like classic STUN (rfc3489). Detect NAT behavior for UDP.
        // Modified from rfc3489. Requires at least two STUN servers.
        let mut ret_test1_1 = None;
        let mut ret_test1_2 = None;
        let mut ret_test2 = None;
        let mut ret_test3 = None;

        if source_port == 0 {
            let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            source_port = udp.local_addr().unwrap().port();
        }

        let mut succ = false;
        let mut ips = HostResolverIter::new(self.stun_servers.clone());
        while let Some(server_ip) = ips.next().await {
            let stun = Stun::new(server_ip.clone());
            let ret = stun.bind_request(source_port, false, false).await;
            if ret.is_err() {
                // Try another STUN server
                continue;
            }
            if ret_test1_1.is_none() {
                ret_test1_1 = ret.ok();
                continue;
            }
            ret_test1_2 = ret.ok();
            let ret = stun.bind_request(source_port, true, true).await;
            if let Ok(resp) = ret {
                if !resp.real_ip_changed || !resp.real_port_changed {
                    tracing::debug!(
                        ?server_ip,
                        ?ret,
                        "stun bind request return with unchanged ip and port"
                    );
                    // Try another STUN server
                    continue;
                }
            }
            ret_test2 = ret.ok();
            ret_test3 = stun.bind_request(source_port, false, true).await.ok();
            tracing::debug!(?ret_test3, "stun bind request with changed port");
            succ = true;
            break;
        }

        if !succ {
            return NatType::Unknown;
        }

        tracing::debug!(
            ?ret_test1_1,
            ?ret_test1_2,
            ?ret_test2,
            ?ret_test3,
            "finish stun test, try to detect nat type"
        );

        let ret_test1_1 = ret_test1_1.unwrap();
        let ret_test1_2 = ret_test1_2.unwrap();

        if ret_test1_1.mapped_socket_addr != ret_test1_2.mapped_socket_addr {
            return NatType::Symmetric;
        }

        if ret_test1_1.mapped_socket_addr.is_some()
            && ret_test1_1.source_addr == ret_test1_1.mapped_socket_addr.unwrap()
        {
            if !ret_test2.is_none() {
                return NatType::OpenInternet;
            } else {
                return NatType::SymUdpFirewall;
            }
        } else {
            if let Some(ret_test2) = ret_test2 {
                if source_port == ret_test2.get_mapped_addr_no_check().port()
                    && source_port == ret_test1_1.get_mapped_addr_no_check().port()
                {
                    return NatType::NoPat;
                } else {
                    return NatType::FullCone;
                }
            } else {
                if !ret_test3.is_none() {
                    return NatType::Restricted;
                } else {
                    return NatType::PortRestricted;
                }
            }
        }
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait StunInfoCollectorTrait: Send + Sync {
    fn get_stun_info(&self) -> StunInfo;
    async fn get_udp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error>;
}

pub struct StunInfoCollector {
    stun_servers: Arc<RwLock<Vec<String>>>,
    udp_nat_type: Arc<AtomicCell<(NatType, std::time::Instant)>>,
    redetect_notify: Arc<tokio::sync::Notify>,
    tasks: JoinSet<()>,
}

#[async_trait::async_trait]
impl StunInfoCollectorTrait for StunInfoCollector {
    fn get_stun_info(&self) -> StunInfo {
        let (typ, time) = self.udp_nat_type.load();
        StunInfo {
            udp_nat_type: typ as i32,
            tcp_nat_type: 0,
            last_update_time: time.elapsed().as_secs() as i64,
        }
    }

    async fn get_udp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error> {
        let stun_servers = self.stun_servers.read().await.clone();
        let mut ips = HostResolverIter::new(stun_servers.clone());
        while let Some(server) = ips.next().await {
            let stun = Stun::new(server.clone());
            let Ok(ret) = stun.bind_request(local_port, false, false).await else {
                tracing::warn!(?server, "stun bind request failed");
                continue;
            };
            if let Some(mapped_addr) = ret.mapped_socket_addr {
                return Ok(mapped_addr);
            }
        }
        Err(Error::NotFound)
    }
}

impl StunInfoCollector {
    pub fn new(stun_servers: Vec<String>) -> Self {
        let mut ret = Self {
            stun_servers: Arc::new(RwLock::new(stun_servers)),
            udp_nat_type: Arc::new(AtomicCell::new((
                NatType::Unknown,
                std::time::Instant::now(),
            ))),
            redetect_notify: Arc::new(tokio::sync::Notify::new()),
            tasks: JoinSet::new(),
        };

        ret.start_stun_routine();

        ret
    }

    pub fn new_with_default_servers() -> Self {
        Self::new(Self::get_default_servers())
    }

    pub fn get_default_servers() -> Vec<String> {
        // NOTICE: we may need to choose stun stun server based on geo location
        // stun server cross nation may return a external ip address with high latency and loss rate
        vec![
            "stun.miwifi.com:3478".to_string(),
            "stun.qq.com:3478".to_string(),
            // "stun.chat.bilibili.com:3478".to_string(), // bilibili's stun server doesn't repond to change_ip and change_port
            "fwa.lifesizecloud.com:3478".to_string(),
            "stun.isp.net.au:3478".to_string(),
            "stun.nextcloud.com:3478".to_string(),
            "stun.freeswitch.org:3478".to_string(),
            "stun.voip.blackberry.com:3478".to_string(),
            "stunserver.stunprotocol.org:3478".to_string(),
            "stun.sipnet.com:3478".to_string(),
            "stun.radiojar.com:3478".to_string(),
            "stun.sonetel.com:3478".to_string(),
            "stun.voipgate.com:3478".to_string(),
            "stun.counterpath.com:3478".to_string(),
            "180.235.108.91:3478".to_string(),
            "193.22.2.248:3478".to_string(),
        ]
    }

    fn start_stun_routine(&mut self) {
        let stun_servers = self.stun_servers.clone();
        let udp_nat_type = self.udp_nat_type.clone();
        let redetect_notify = self.redetect_notify.clone();
        self.tasks.spawn(async move {
            loop {
                let detector = UdpNatTypeDetector::new(stun_servers.read().await.clone());
                let old_nat_type = udp_nat_type.load().0;
                let mut ret = NatType::Unknown;
                for _ in 1..5 {
                    // if nat type degrade, sleep and retry. so result can be relatively stable.
                    ret = detector.get_udp_nat_type(0).await;
                    if ret == NatType::Unknown || ret <= old_nat_type {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                udp_nat_type.store((ret, std::time::Instant::now()));

                let sleep_sec = match ret {
                    NatType::Unknown => 15,
                    _ => 60,
                };
                tracing::info!(?ret, ?sleep_sec, "finish udp nat type detect");

                tokio::select! {
                    _ = redetect_notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                }
            }
        });
    }

    pub fn update_stun_info(&self) {
        self.redetect_notify.notify_one();
    }

    pub async fn set_stun_servers(&self, stun_servers: Vec<String>) {
        *self.stun_servers.write().await = stun_servers;
        self.update_stun_info();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn enable_log() {
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::TRACE.into())
            .from_env()
            .unwrap()
            .add_directive("tarpc=error".parse().unwrap());
        tracing_subscriber::fmt::fmt()
            .pretty()
            .with_env_filter(filter)
            .init();
    }

    #[tokio::test]
    async fn test_stun_bind_request() {
        enable_log();
        // miwifi / qq seems not correctly responde to change_ip and change_port, they always try to change the src ip and port.
        // let mut ips = HostResolverIter::new(vec!["stun1.l.google.com:19302".to_string()]);
        let mut ips_ = HostResolverIter::new(vec!["stun.canets.org:3478".to_string()]);
        let mut ips = vec![];
        while let Some(ip) = ips_.next().await {
            ips.push(ip);
        }
        println!("ip: {:?}", ips);
        for ip in ips.iter() {
            let stun = Stun::new(ip.clone());
            let _rs = stun.bind_request(12345, true, true).await;
        }
    }

    #[tokio::test]
    async fn test_udp_nat_type_detect() {
        let detector = UdpNatTypeDetector::new(vec![
            "stun.counterpath.com:3478".to_string(),
            "180.235.108.91:3478".to_string(),
        ]);
        let ret = detector.get_udp_nat_type(0).await;

        assert_ne!(ret, NatType::Unknown);
    }
}
