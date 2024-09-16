use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
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

use super::stun_codec_ext::*;

struct HostResolverIter {
    hostnames: Vec<String>,
    ips: Vec<SocketAddr>,
    max_ip_per_domain: u32,
}

impl HostResolverIter {
    fn new(hostnames: Vec<String>, max_ip_per_domain: u32) -> Self {
        Self {
            hostnames,
            ips: vec![],
            max_ip_per_domain,
        }
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

            match lookup_host(&host).await {
                Ok(ips) => {
                    self.ips = ips
                        .filter(|x| x.is_ipv4())
                        .choose_multiple(&mut rand::thread_rng(), self.max_ip_per_domain as usize);
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
        tids: &Vec<u128>,
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
                || !tids.contains(&tid_to_u128(&msg.transaction_id()))
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
                Message::<Attribute>::new(MessageClass::Request, BINDING, u128_to_tid(tid as u128));
            message.add_attribute(ChangeRequest::new(change_ip, change_port));

            // Encodes the message
            let mut encoder = MessageEncoder::new();
            let msg = encoder
                .encode_into_bytes(message.clone())
                .with_context(|| "encode stun message")?;
            tids.push(tid as u128);
            tracing::trace!(?message, ?msg, tid, "send stun request");
            self.socket
                .send_to(msg.as_slice().into(), &stun_host)
                .await?;
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
        while let Some(_) = self.task_set.join_next().await {}
    }
}

#[derive(Debug, Clone)]
pub struct UdpNatTypeDetectResult {
    source_addr: SocketAddr,
    stun_resps: Vec<BindRequestResponse>,
}

impl UdpNatTypeDetectResult {
    fn new(source_addr: SocketAddr, stun_resps: Vec<BindRequestResponse>) -> Self {
        Self {
            source_addr,
            stun_resps,
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
        return false;
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
            .map(|x| x.stun_server_addr)
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
        mapped_addr_count < self.stun_server_count()
    }

    pub fn nat_type(&self) -> NatType {
        if self.stun_server_count() < 2 {
            return NatType::Unknown;
        }

        if self.is_cone() {
            if self.has_ip_changed_resp() {
                if self.is_open_internet() {
                    return NatType::OpenInternet;
                } else if self.is_pat() {
                    return NatType::NoPat;
                } else {
                    return NatType::FullCone;
                }
            } else if self.has_port_changed_resp() {
                return NatType::Restricted;
            } else {
                return NatType::PortRestricted;
            }
        } else if !self.stun_resps.is_empty() {
            return NatType::Symmetric;
        } else {
            return NatType::Unknown;
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
        let mut host_resolver =
            HostResolverIter::new(self.stun_server_hosts.clone(), self.max_ip_per_domain);
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
    udp_nat_test_result: Arc<RwLock<Option<UdpNatTypeDetectResult>>>,
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
            public_ip: result.public_ips().iter().map(|x| x.to_string()).collect(),
            min_port: result.min_port() as u32,
            max_port: result.max_port() as u32,
        }
    }

    async fn get_udp_port_mapping(&self, local_port: u16) -> Result<SocketAddr, Error> {
        self.start_stun_routine();

        let stun_servers = self
            .udp_nat_test_result
            .read()
            .unwrap()
            .clone()
            .map(|x| x.collect_available_stun_server())
            .ok_or(Error::NotFound)?;

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
            udp_nat_test_result: Arc::new(RwLock::new(None)),
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
        // NOTICE: we may need to choose stun stun server based on geo location
        // stun server cross nation may return a external ip address with high latency and loss rate
        vec![
            "stun.miwifi.com",
            "stun.cdnbye.com",
            "stun.hitv.com",
            "stun.chat.bilibili.com",
            "stun.douyucdn.cn:18000",
            "fwa.lifesizecloud.com",
            "global.turn.twilio.com",
            "turn.cloudflare.com",
            "stun.isp.net.au",
            "stun.nextcloud.com",
            "stun.freeswitch.org",
            "stun.voip.blackberry.com",
            "stunserver.stunprotocol.org",
            "stun.sipnet.com",
            "stun.radiojar.com",
            "stun.sonetel.com",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect()
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
                let ret = detector.detect_nat_type(0).await;
                tracing::debug!(?ret, "finish udp nat type detect");
                let mut nat_type = NatType::Unknown;
                let sleep_sec = match &ret {
                    Ok(resp) => {
                        *udp_nat_test_result.write().unwrap() = Some(resp.clone());
                        udp_test_time.store(Local::now());
                        nat_type = resp.nat_type();
                        if nat_type == NatType::Unknown {
                            15
                        } else {
                            600
                        }
                    }
                    _ => 15,
                };

                // if nat type is symmtric, detect with another port to gather more info
                if nat_type == NatType::Symmetric {
                    let old_resp = ret.unwrap();
                    let old_local_port = old_resp.local_addr().port();
                    let new_port = if old_local_port >= 65535 {
                        old_local_port - 1
                    } else {
                        old_local_port + 1
                    };
                    let ret = detector.detect_nat_type(new_port).await;
                    tracing::debug!(?ret, "finish udp nat type detect with another port");
                    if let Ok(resp) = ret {
                        udp_nat_test_result.write().unwrap().as_mut().map(|x| {
                            x.extend_result(resp);
                        });
                    }
                }

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
            ..Default::default()
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
}
