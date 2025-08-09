use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::proto::common::{NatType, StunInfo};
use anyhow::Context;
use chrono::Local;
use crossbeam::atomic::AtomicCell;
use rand::seq::IteratorRandom;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinSet;
use tracing::{Instrument, Level};

use bytecodec::{DecodeExt, EncodeExt};
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};

use crate::common::error::Error;

use super::dns::resolve_txt_record;
use super::stun_codec_ext::*;

struct HostResolverIter {
    hostnames: Vec<String>,
    ips: Vec<SocketAddr>,
    max_ip_per_domain: u32,
    use_ipv6: bool,
}

impl HostResolverIter {
    fn new(hostnames: Vec<String>, max_ip_per_domain: u32, use_ipv6: bool) -> Self {
        Self {
            hostnames,
            ips: vec![],
            max_ip_per_domain,
            use_ipv6,
        }
    }

    async fn get_txt_record(domain_name: &str) -> Result<Vec<String>, Error> {
        let txt_data = resolve_txt_record(domain_name).await?;
        Ok(txt_data.split(" ").map(|x| x.to_string()).collect())
    }

    #[async_recursion::async_recursion]
    async fn next(&mut self) -> Option<SocketAddr> {
        if self.ips.is_empty() {
            if self.hostnames.is_empty() {
                return None;
            }

            let host = self.hostnames.remove(0);
            let host = if host.contains(':') {
                host
            } else {
                format!("{}:3478", host)
            };

            if host.starts_with("txt:") {
                let domain_name = host.trim_start_matches("txt:");
                match Self::get_txt_record(domain_name).await {
                    Ok(hosts) => {
                        tracing::info!(
                            ?domain_name,
                            ?hosts,
                            "get txt record success when resolve stun server"
                        );
                        // insert hosts to the head of hostnames
                        self.hostnames.splice(0..0, hosts.into_iter());
                    }
                    Err(e) => {
                        tracing::warn!(
                            ?domain_name,
                            ?e,
                            "get txt record failed when resolve stun server"
                        );
                    }
                }
                return self.next().await;
            }

            let use_ipv6 = self.use_ipv6;

            match lookup_host(&host).await {
                Ok(ips) => {
                    self.ips = ips
                        .filter(|x| if use_ipv6 { x.is_ipv6() } else { x.is_ipv4() })
                        .choose_multiple(&mut rand::thread_rng(), self.max_ip_per_domain as usize);

                    if self.ips.is_empty() {
                        return self.next().await;
                    }
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

#[derive(Debug, Clone)]
struct StunPacket {
    data: Vec<u8>,
    addr: SocketAddr,
}

type StunPacketReceiver = tokio::sync::broadcast::Receiver<StunPacket>;

#[derive(Debug, Clone, Copy)]
struct BindRequestResponse {
    local_addr: SocketAddr,
    stun_server_addr: SocketAddr,

    recv_from_addr: SocketAddr,
    mapped_socket_addr: Option<SocketAddr>,
    changed_socket_addr: Option<SocketAddr>,

    change_ip: bool,
    change_port: bool,

    real_ip_changed: bool,
    real_port_changed: bool,

    latency_us: u32,
}

impl BindRequestResponse {
    pub fn get_mapped_addr_no_check(&self) -> &SocketAddr {
        self.mapped_socket_addr.as_ref().unwrap()
    }
}

#[derive(Debug, Clone)]
struct StunClient {
    stun_server: SocketAddr,
    resp_timeout: Duration,
    req_repeat: u32,
    socket: Arc<UdpSocket>,
    stun_packet_receiver: Arc<Mutex<StunPacketReceiver>>,
}

impl StunClient {
    pub fn new(
        stun_server: SocketAddr,
        socket: Arc<UdpSocket>,
        stun_packet_receiver: StunPacketReceiver,
    ) -> Self {
        Self {
            stun_server,
            resp_timeout: Duration::from_millis(3000),
            req_repeat: 2,
            socket,
            stun_packet_receiver: Arc::new(Mutex::new(stun_packet_receiver)),
        }
    }

    #[tracing::instrument(skip(self, buf))]
    async fn wait_stun_response<'a, const N: usize>(
        &self,
        buf: &'a mut [u8; N],
        tids: &Vec<u32>,
        expected_ip_changed: bool,
        expected_port_changed: bool,
        stun_host: &SocketAddr,
    ) -> Result<(Message<Attribute>, SocketAddr), Error> {
        let mut now = tokio::time::Instant::now();
        let deadline = now + self.resp_timeout;

        while now < deadline {
            let mut locked_receiver = self.stun_packet_receiver.lock().await;
            let stun_packet_raw = tokio::time::timeout(deadline - now, locked_receiver.recv())
                .await?
                .with_context(|| "recv stun packet from broadcast channel error")?;
            now = tokio::time::Instant::now();

            let (len, remote_addr) = (stun_packet_raw.data.len(), stun_packet_raw.addr);

            if len < 20 {
                continue;
            }

            let udp_buf = stun_packet_raw.data;

            // TODO:: we cannot borrow `buf` directly in udp recv_from, so we copy it here
            unsafe { std::ptr::copy(udp_buf.as_ptr(), buf.as_ptr() as *mut u8, len) };

            let mut decoder = MessageDecoder::<Attribute>::new();
            let Ok(msg) = decoder
                .decode_from_bytes(&buf[..len])
                .with_context(|| format!("decode stun msg {:?}", buf))?
            else {
                continue;
            };

            tracing::trace!(b = ?&udp_buf[..len], ?tids, ?remote_addr, ?stun_host, "recv stun response, msg: {:#?}", msg);

            if msg.class() != MessageClass::SuccessResponse
                || msg.method() != BINDING
                || !tids.contains(&tid_to_u32(&msg.transaction_id()))
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

    #[tracing::instrument(ret, level = Level::TRACE)]
    pub async fn bind_request(
        self,
        change_ip: bool,
        change_port: bool,
    ) -> Result<BindRequestResponse, Error> {
        let stun_host = self.stun_server;
        // repeat req in case of packet loss
        let mut tids = vec![];

        for _ in 0..self.req_repeat {
            let tid = rand::random::<u32>();
            // let tid = 1;
            let mut buf = [0u8; 28];
            // memset buf
            unsafe { std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len()) };

            let mut message =
                Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(tid));
            message.add_attribute(ChangeRequest::new(change_ip, change_port));

            // Encodes the message
            let mut encoder = MessageEncoder::new();
            let msg = encoder
                .encode_into_bytes(message.clone())
                .with_context(|| "encode stun message")?;
            tids.push(tid);
            tracing::trace!(?message, ?msg, tid, "send stun request");
            self.socket.send_to(msg.as_slice(), &stun_host).await?;
        }

        let now = Instant::now();

        tracing::trace!("waiting stun response");
        let mut buf = [0; 1620];
        let (msg, recv_addr) = self
            .wait_stun_response(&mut buf, &tids, change_ip, change_port, &stun_host)
            .await?;

        let changed_socket_addr = Self::extract_changed_addr(&msg);
        let real_ip_changed = stun_host.ip() != recv_addr.ip();
        let real_port_changed = stun_host.port() != recv_addr.port();

        let resp = BindRequestResponse {
            local_addr: self.socket.local_addr()?,
            stun_server_addr: stun_host,
            recv_from_addr: recv_addr,
            mapped_socket_addr: Self::extrace_mapped_addr(&msg),
            changed_socket_addr,
            change_ip,
            change_port,

            real_ip_changed,
            real_port_changed,

            latency_us: now.elapsed().as_micros() as u32,
        };

        tracing::trace!(
            ?stun_host,
            ?recv_addr,
            ?changed_socket_addr,
            "finish stun bind request"
        );

        Ok(resp)
    }
}

struct StunClientBuilder {
    udp: Arc<UdpSocket>,
    task_set: JoinSet<()>,
    stun_packet_sender: broadcast::Sender<StunPacket>,
}

impl StunClientBuilder {
    pub fn new(udp: Arc<UdpSocket>) -> Self {
        let (stun_packet_sender, _) = broadcast::channel(1024);
        let mut task_set = JoinSet::new();

        let udp_clone = udp.clone();
        let stun_packet_sender_clone = stun_packet_sender.clone();
        task_set.spawn(
            async move {
                let mut buf = [0; 1620];
                tracing::trace!("start stun packet listener");
                loop {
                    let Ok((len, addr)) = udp_clone.recv_from(&mut buf).await else {
                        tracing::error!("udp recv_from error");
                        break;
                    };
                    let data = buf[..len].to_vec();
                    tracing::trace!(?addr, ?data, "recv udp stun packet");
                    let _ = stun_packet_sender_clone.send(StunPacket { data, addr });
                }
            }
            .instrument(tracing::info_span!("stun_packet_listener")),
        );

        Self {
            udp,
            task_set,
            stun_packet_sender,
        }
    }

    pub fn new_stun_client(&self, stun_server: SocketAddr) -> StunClient {
        StunClient::new(
            stun_server,
            self.udp.clone(),
            self.stun_packet_sender.subscribe(),
        )
    }

    pub async fn stop(&mut self) {
        self.task_set.abort_all();
        while self.task_set.join_next().await.is_some() {}
    }
}

#[derive(Debug, Clone)]
pub struct UdpNatTypeDetectResult {
    source_addr: SocketAddr,
    stun_resps: Vec<BindRequestResponse>,
    // if we are easy symmetric nat, we need to test with another port to check inc or dec
    extra_bind_test: Option<BindRequestResponse>,
}

impl UdpNatTypeDetectResult {
    fn new(source_addr: SocketAddr, stun_resps: Vec<BindRequestResponse>) -> Self {
        Self {
            source_addr,
            stun_resps,
            extra_bind_test: None,
        }
    }

    fn has_ip_changed_resp(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.real_ip_changed {
                return true;
            }
        }
        false
    }

    fn has_port_changed_resp(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.real_port_changed {
                return true;
            }
        }
        false
    }

    fn is_open_internet(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.mapped_socket_addr == Some(self.source_addr) {
                return true;
            }
        }
        false
    }

    fn is_pat(&self) -> bool {
        for resp in self.stun_resps.iter() {
            if resp.mapped_socket_addr.map(|x| x.port()) == Some(self.source_addr.port()) {
                return true;
            }
        }
        false
    }

    fn stun_server_count(&self) -> usize {
        // find resp with distinct stun server
        self.stun_resps
            .iter()
            .map(|x| x.recv_from_addr)
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn is_cone(&self) -> bool {
        // if unique mapped addr count is less than stun server count, it is cone
        let mapped_addr_count = self
            .stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr)
            .collect::<BTreeSet<_>>()
            .len();
        mapped_addr_count == 1
    }

    pub fn nat_type(&self) -> NatType {
        if self.stun_server_count() < 2 {
            return NatType::Unknown;
        }

        if self.is_cone() {
            if self.has_ip_changed_resp() {
                if self.is_open_internet() {
                    NatType::OpenInternet
                } else if self.is_pat() {
                    NatType::NoPat
                } else {
                    NatType::FullCone
                }
            } else if self.has_port_changed_resp() {
                NatType::Restricted
            } else {
                NatType::PortRestricted
            }
        } else if !self.stun_resps.is_empty() {
            if self.public_ips().len() != 1
                || self.usable_stun_resp_count() <= 1
                || self.max_port() - self.min_port() > 15
                || self.extra_bind_test.is_none()
                || self
                    .extra_bind_test
                    .as_ref()
                    .unwrap()
                    .mapped_socket_addr
                    .is_none()
            {
                NatType::Symmetric
            } else {
                let extra_bind_test = self.extra_bind_test.as_ref().unwrap();
                let extra_port = extra_bind_test.mapped_socket_addr.unwrap().port();

                let max_port_diff = extra_port.saturating_sub(self.max_port());
                let min_port_diff = self.min_port().saturating_sub(extra_port);
                if max_port_diff != 0 && max_port_diff < 100 {
                    NatType::SymmetricEasyInc
                } else if min_port_diff != 0 && min_port_diff < 100 {
                    NatType::SymmetricEasyDec
                } else {
                    NatType::Symmetric
                }
            }
        } else {
            NatType::Unknown
        }
    }

    pub fn public_ips(&self) -> Vec<IpAddr> {
        self.stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr.map(|x| x.ip()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn collect_available_stun_server(&self) -> Vec<SocketAddr> {
        let mut ret = vec![];
        for resp in self.stun_resps.iter() {
            if !ret.contains(&resp.stun_server_addr) {
                ret.push(resp.stun_server_addr);
            }
        }
        ret
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.source_addr
    }

    pub fn extend_result(&mut self, other: UdpNatTypeDetectResult) {
        self.stun_resps.extend(other.stun_resps);
    }

    pub fn min_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr.map(|x| x.port()))
            .min()
            .unwrap_or(0)
    }

    pub fn max_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|x| x.mapped_socket_addr.map(|x| x.port()))
            .max()
            .unwrap_or(u16::MAX)
    }

    pub fn usable_stun_resp_count(&self) -> usize {
        self.stun_resps
            .iter()
            .filter(|x| x.mapped_socket_addr.is_some())
            .count()
    }
}

pub struct UdpNatTypeDetector {
    stun_server_hosts: Vec<String>,
    max_ip_per_domain: u32,
}

impl UdpNatTypeDetector {
    pub fn new(stun_server_hosts: Vec<String>, max_ip_per_domain: u32) -> Self {
        Self {
            stun_server_hosts,
            max_ip_per_domain,
        }
    }

    async fn get_extra_bind_result(
        &self,
        source_port: u16,
        stun_server: SocketAddr,
    ) -> Result<BindRequestResponse, Error> {
        let udp = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", source_port)).await?);
        let client_builder = StunClientBuilder::new(udp.clone());
        client_builder
            .new_stun_client(stun_server)
            .bind_request(false, false)
            .await
    }

    pub async fn detect_nat_type(&self, source_port: u16) -> Result<UdpNatTypeDetectResult, Error> {
        let udp = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", source_port)).await?);
        self.detect_nat_type_with_socket(udp).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn detect_nat_type_with_socket(
        &self,
        udp: Arc<UdpSocket>,
    ) -> Result<UdpNatTypeDetectResult, Error> {
        let mut stun_servers = vec![];
        let mut host_resolver = HostResolverIter::new(
            self.stun_server_hosts.clone(),
            self.max_ip_per_domain,
            false,
        );
        while let Some(addr) = host_resolver.next().await {
            stun_servers.push(addr);
        }

        let client_builder = StunClientBuilder::new(udp.clone());
        let mut stun_task_set = JoinSet::new();

        for stun_server in stun_servers.iter() {
            stun_task_set.spawn(
                client_builder
                    .new_stun_client(*stun_server)
                    .bind_request(false, false),
            );
            stun_task_set.spawn(
                client_builder
                    .new_stun_client(*stun_server)
                    .bind_request(false, true),
            );
            stun_task_set.spawn(
                client_builder
                    .new_stun_client(*stun_server)
                    .bind_request(true, true),
            );
        }

        let mut bind_resps = vec![];
        while let Some(resp) = stun_task_set.join_next().await {
            if let Ok(Ok(resp)) = resp {
                bind_resps.push(resp);
            }
        }

        Ok(UdpNatTypeDetectResult::new(udp.local_addr()?, bind_resps))
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
    stun_servers_v6: Arc<RwLock<Vec<String>>>,
    udp_nat_test_result: Arc<RwLock<Option<UdpNatTypeDetectResult>>>,
    public_ipv6: Arc<AtomicCell<Option<Ipv6Addr>>>,
    nat_test_result_time: Arc<AtomicCell<chrono::DateTime<Local>>>,
    redetect_notify: Arc<tokio::sync::Notify>,
    tasks: std::sync::Mutex<JoinSet<()>>,
    started: AtomicBool,
}

#[async_trait::async_trait]
impl StunInfoCollectorTrait for StunInfoCollector {
    fn get_stun_info(&self) -> StunInfo {
        self.start_stun_routine();

        let Some(result) = self.udp_nat_test_result.read().unwrap().clone() else {
            return Default::default();
        };
        StunInfo {
            udp_nat_type: result.nat_type() as i32,
            tcp_nat_type: 0,
            last_update_time: self.nat_test_result_time.load().timestamp(),
            public_ip: result
                .public_ips()
                .iter()
                .map(|x| x.to_string())
                .chain(self.public_ipv6.load().map(|x| x.to_string()))
                .collect(),
            min_port: result.min_port() as u32,
            max_port: result.max_port() as u32,
        }
    }

    async fn get_udp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error> {
        self.start_stun_routine();

        let mut stun_servers = self
            .udp_nat_test_result
            .read()
            .unwrap()
            .clone()
            .map(|x| x.collect_available_stun_server())
            .unwrap_or_default();

        if stun_servers.is_empty() {
            let mut host_resolver =
                HostResolverIter::new(self.stun_servers.read().unwrap().clone(), 2, false);
            while let Some(addr) = host_resolver.next().await {
                stun_servers.push(addr);
                if stun_servers.len() >= 2 {
                    break;
                }
            }
        }

        if stun_servers.is_empty() {
            return Err(Error::NotFound);
        }

        let udp = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", local_port)).await?);
        let mut client_builder = StunClientBuilder::new(udp.clone());

        for server in stun_servers.iter() {
            let Ok(ret) = client_builder
                .new_stun_client(*server)
                .bind_request(false, false)
                .await
            else {
                tracing::warn!(?server, "stun bind request failed");
                continue;
            };
            if let Some(mapped_addr) = ret.mapped_socket_addr {
                // make sure udp socket is available after return ok.
                client_builder.stop().await;
                return Ok(mapped_addr);
            }
        }

        Err(Error::NotFound)
    }
}

impl StunInfoCollector {
    pub fn new(stun_servers: Vec<String>) -> Self {
        Self {
            stun_servers: Arc::new(RwLock::new(stun_servers)),
            stun_servers_v6: Arc::new(RwLock::new(Self::get_default_servers_v6())),
            udp_nat_test_result: Arc::new(RwLock::new(None)),
            public_ipv6: Arc::new(AtomicCell::new(None)),
            nat_test_result_time: Arc::new(AtomicCell::new(Local::now())),
            redetect_notify: Arc::new(tokio::sync::Notify::new()),
            tasks: std::sync::Mutex::new(JoinSet::new()),
            started: AtomicBool::new(false),
        }
    }

    pub fn new_with_default_servers() -> Self {
        Self::new(Self::get_default_servers())
    }

    pub fn get_default_servers() -> Vec<String> {
        // NOTICE: we may need to choose stun server based on geolocation
        // stun server cross nation may return an external ip address with high latency and loss rate
        [
            "txt:stun.easytier.cn",
            "stun.miwifi.com",
            "stun.chat.bilibili.com",
            "stun.hitv.com",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect()
    }

    pub fn get_default_servers_v6() -> Vec<String> {
        ["txt:stun-v6.easytier.cn"]
            .iter()
            .map(|x| x.to_string())
            .collect()
    }

    async fn get_public_ipv6(servers: &[String]) -> Option<Ipv6Addr> {
        let mut ips = HostResolverIter::new(servers.to_vec(), 10, true);
        while let Some(ip) = ips.next().await {
            let Ok(udp_socket) = UdpSocket::bind("[::]:0".to_string()).await else {
                break;
            };
            let udp = Arc::new(udp_socket);
            let ret = StunClientBuilder::new(udp.clone())
                .new_stun_client(ip)
                .bind_request(false, false)
                .await;
            tracing::debug!(?ret, "finish ipv6 udp nat type detect");
            if let Ok(Some(IpAddr::V6(v6))) = ret.map(|x| x.mapped_socket_addr.map(|x| x.ip())) {
                return Some(v6);
            }
        }
        None
    }

    fn start_stun_routine(&self) {
        if self.started.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        self.started
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let stun_servers = self.stun_servers.clone();
        let udp_nat_test_result = self.udp_nat_test_result.clone();
        let udp_test_time = self.nat_test_result_time.clone();
        let redetect_notify = self.redetect_notify.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let servers = stun_servers.read().unwrap().clone();
                // use first three and random choose one from the rest
                let servers = servers
                    .iter()
                    .take(2)
                    .chain(servers.iter().skip(2).choose(&mut rand::thread_rng()))
                    .map(|x| x.to_string())
                    .collect();
                let detector = UdpNatTypeDetector::new(servers, 1);
                let mut ret = detector.detect_nat_type(0).await;
                tracing::debug!(?ret, "finish udp nat type detect");

                let mut nat_type = NatType::Unknown;
                if let Ok(resp) = &ret {
                    tracing::debug!(?resp, "got udp nat type detect result");
                    nat_type = resp.nat_type();
                }

                // if nat type is symmtric, detect with another port to gather more info
                if nat_type == NatType::Symmetric {
                    let old_resp = ret.as_mut().unwrap();
                    tracing::debug!(?old_resp, "start get extra bind result");
                    let available_stun_servers = old_resp.collect_available_stun_server();
                    for server in available_stun_servers.iter() {
                        let ret = detector
                            .get_extra_bind_result(0, *server)
                            .await
                            .with_context(|| "get extra bind result failed");
                        tracing::debug!(?ret, "finish udp nat type detect with another port");
                        if let Ok(resp) = ret {
                            old_resp.extra_bind_test = Some(resp);
                            break;
                        }
                    }
                }

                let mut sleep_sec = 10;
                if let Ok(resp) = &ret {
                    udp_test_time.store(Local::now());
                    *udp_nat_test_result.write().unwrap() = Some(resp.clone());
                    if nat_type != NatType::Unknown
                        && (nat_type != NatType::Symmetric || resp.extra_bind_test.is_some())
                    {
                        sleep_sec = 600
                    }
                }

                tokio::select! {
                    _ = redetect_notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                }
            }
        });

        // for ipv6
        let stun_servers = self.stun_servers_v6.clone();
        let stored_ipv6 = self.public_ipv6.clone();
        let redetect_notify = self.redetect_notify.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let servers = stun_servers.read().unwrap().clone();
                if let Some(x) = Self::get_public_ipv6(&servers).await {
                    stored_ipv6.store(Some(x))
                }

                let sleep_sec = if stored_ipv6.load().is_none() {
                    60
                } else {
                    360
                };

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
}

pub struct MockStunInfoCollector {
    pub udp_nat_type: NatType,
}

#[async_trait::async_trait]
impl StunInfoCollectorTrait for MockStunInfoCollector {
    fn get_stun_info(&self) -> StunInfo {
        StunInfo {
            udp_nat_type: self.udp_nat_type as i32,
            tcp_nat_type: NatType::Unknown as i32,
            last_update_time: std::time::Instant::now().elapsed().as_secs() as i64,
            min_port: 100,
            max_port: 200,
            public_ip: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }

    async fn get_udp_port_mapping(&self, mut port: u16) -> Result<std::net::SocketAddr, Error> {
        if port == 0 {
            port = 40144;
        }
        Ok(format!("127.0.0.1:{}", port).parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::{udp::UdpTunnelListener, TunnelListener};

    use super::*;

    #[tokio::test]
    async fn test_udp_nat_type_detector() {
        let collector = StunInfoCollector::new_with_default_servers();
        collector.update_stun_info();
        loop {
            let ret = collector.get_stun_info();
            if ret.udp_nat_type != NatType::Unknown as i32 {
                println!("{:#?}", ret);
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let port_mapping = collector.get_udp_port_mapping(3000).await;
        println!("{:#?}", port_mapping);
    }

    #[tokio::test]
    async fn test_internal_stun_server() {
        let mut udp_server1 = UdpTunnelListener::new("udp://0.0.0.0:55555".parse().unwrap());
        let mut udp_server2 = UdpTunnelListener::new("udp://0.0.0.0:55535".parse().unwrap());

        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            udp_server1.listen().await.unwrap();
            loop {
                udp_server1.accept().await.unwrap();
            }
        });
        tasks.spawn(async move {
            udp_server2.listen().await.unwrap();
            loop {
                udp_server2.accept().await.unwrap();
            }
        });

        let stun_servers = vec!["127.0.0.1:55555".to_string(), "127.0.0.1:55535".to_string()];
        let detector = UdpNatTypeDetector::new(stun_servers, 1);
        let ret = detector.detect_nat_type(0).await;
        println!("{:#?}, {:?}", ret, ret.as_ref().unwrap().nat_type());
        assert_eq!(ret.unwrap().nat_type(), NatType::Restricted);
    }

    #[tokio::test]
    async fn test_txt_public_stun_server() {
        let stun_servers = vec!["txt:stun.easytier.cn".to_string()];
        let detector = UdpNatTypeDetector::new(stun_servers, 1);
        for _ in 0..5 {
            let ret = detector.detect_nat_type(0).await;
            println!("{:#?}, {:?}", ret, ret.as_ref().unwrap().nat_type());
            if ret.is_ok() {
                assert!(!ret.unwrap().stun_resps.is_empty());
                return;
            }
        }
        debug_assert!(
            false,
            "should not reach here, stun server should be available"
        );
    }

    #[tokio::test]
    async fn test_v4_stun() {
        let mut udp_server = UdpTunnelListener::new("udp://0.0.0.0:55355".parse().unwrap());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            udp_server.listen().await.unwrap();
            loop {
                udp_server.accept().await.unwrap();
            }
        });
        let stun_servers = vec!["127.0.0.1:55355".to_string()];

        let detector = UdpNatTypeDetector::new(stun_servers, 1);
        let ret = detector.detect_nat_type(0).await;
        println!("{:#?}, {:?}", ret, ret.as_ref().unwrap().nat_type());
        assert_eq!(ret.unwrap().nat_type(), NatType::Restricted);
    }

    #[tokio::test]
    async fn test_v6_stun() {
        let mut udp_server = UdpTunnelListener::new("udp://[::]:55355".parse().unwrap());
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            udp_server.listen().await.unwrap();
            loop {
                udp_server.accept().await.unwrap();
            }
        });
        let stun_servers = vec!["::1:55355".to_string()];
        let ret = StunInfoCollector::get_public_ipv6(&stun_servers).await;
        println!("{:#?}", ret);
    }
}
