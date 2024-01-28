use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use crossbeam::atomic::AtomicCell;
use easytier_rpc::{NatType, StunInfo};
use stun_format::Attr;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::RwLock;
use tokio::task::JoinSet;

use crate::common::error::Error;

struct Stun {
    stun_server: String,
    req_repeat: u8,
    resp_timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
struct BindRequestResponse {
    source_addr: SocketAddr,
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

impl Stun {
    pub fn new(stun_server: String) -> Self {
        Self {
            stun_server,
            req_repeat: 3,
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
    ) -> Result<(stun_format::Msg<'a>, SocketAddr), Error> {
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

            let msg = stun_format::Msg::<'a>::from(&buf[..]);
            tracing::trace!(b = ?&udp_buf[..len], ?msg, ?tids, ?remote_addr, "recv stun response");

            if msg.typ().is_none() || msg.tid().is_none() {
                continue;
            }

            if !matches!(
                msg.typ().as_ref().unwrap(),
                stun_format::MsgType::BindingResponse
            ) || !tids.contains(msg.tid().as_ref().unwrap())
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

    fn stun_addr(addr: stun_format::SocketAddr) -> SocketAddr {
        match addr {
            stun_format::SocketAddr::V4(ip, port) => {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
            }
            stun_format::SocketAddr::V6(ip, port) => {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
            }
        }
    }

    fn extrace_mapped_addr(msg: &stun_format::Msg) -> Option<SocketAddr> {
        let mut mapped_addr = None;
        for x in msg.attrs_iter() {
            match x {
                Attr::MappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(Self::stun_addr(addr));
                    }
                }
                Attr::XorMappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(Self::stun_addr(addr));
                    }
                }
                _ => {}
            }
        }
        mapped_addr
    }

    fn extract_changed_addr(msg: &stun_format::Msg) -> Option<SocketAddr> {
        let mut changed_addr = None;
        for x in msg.attrs_iter() {
            match x {
                Attr::ChangedAddress(addr) => {
                    if changed_addr.is_none() {
                        let _ = changed_addr.insert(Self::stun_addr(addr));
                    }
                }
                _ => {}
            }
        }
        changed_addr
    }

    pub async fn bind_request(
        &self,
        source_port: u16,
        change_ip: bool,
        change_port: bool,
    ) -> Result<BindRequestResponse, Error> {
        let stun_host = lookup_host(&self.stun_server)
            .await?
            .next()
            .ok_or(Error::NotFound)?;
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", source_port)).await?;

        // repeat req in case of packet loss
        let mut tids = vec![];
        for _ in 0..self.req_repeat {
            let mut buf = [0u8; 28];
            // memset buf
            unsafe { std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len()) };
            let mut msg = stun_format::MsgBuilder::from(buf.as_mut_slice());
            msg.typ(stun_format::MsgType::BindingRequest).unwrap();
            let tid = rand::random::<u32>();
            msg.tid(tid as u128).unwrap();
            if change_ip || change_port {
                msg.add_attr(Attr::ChangeRequest {
                    change_ip,
                    change_port,
                })
                .unwrap();
            }

            tids.push(tid as u128);
            tracing::trace!(b = ?msg.as_bytes(), tid, "send stun request");
            udp.send_to(msg.as_bytes(), &stun_host).await?;
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
            mapped_socket_addr: Self::extrace_mapped_addr(&msg),
            changed_socket_addr,
            ip_changed: change_ip,
            port_changed: change_port,

            real_ip_changed,
            real_port_changed,
        };

        tracing::info!(
            ?stun_host,
            ?recv_addr,
            ?changed_socket_addr,
            "finish stun bind request"
        );

        Ok(resp)
    }
}

struct UdpNatTypeDetector {
    stun_servers: Vec<String>,
}

impl UdpNatTypeDetector {
    pub fn new(stun_servers: Vec<String>) -> Self {
        Self { stun_servers }
    }

    async fn get_udp_nat_type(&self, mut source_port: u16) -> NatType {
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
        for server_ip in &self.stun_servers {
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
                if !resp.ip_changed || !resp.port_changed {
                    // Try another STUN server
                    continue;
                }
            }
            ret_test2 = ret.ok();
            ret_test3 = stun.bind_request(source_port, false, true).await.ok();
            succ = true;
            break;
        }

        if !succ {
            return NatType::Unknown;
        }

        tracing::info!(
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
        for server in stun_servers.iter() {
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

    fn start_stun_routine(&mut self) {
        let stun_servers = self.stun_servers.clone();
        let udp_nat_type = self.udp_nat_type.clone();
        let redetect_notify = self.redetect_notify.clone();
        self.tasks.spawn(async move {
            loop {
                let detector = UdpNatTypeDetector::new(stun_servers.read().await.clone());
                let ret = detector.get_udp_nat_type(0).await;
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

    #[tokio::test]
    async fn test_stun_bind_request() {
        // miwifi / qq seems not correctly responde to change_ip and change_port, they always try to change the src ip and port.
        let stun = Stun::new("stun1.l.google.com:19302".to_string());
        // let stun = Stun::new("180.235.108.91:3478".to_string());
        // let stun = Stun::new("193.22.2.248:3478".to_string());
        // let stun = Stun::new("stun.chat.bilibili.com:3478".to_string());
        // let stun = Stun::new("stun.miwifi.com:3478".to_string());

        // github actions are port restricted nat, so we only test last one.

        // let rs = stun.bind_request(12345, true, true).await.unwrap();
        // assert!(rs.ip_changed);
        // assert!(rs.port_changed);

        // let rs = stun.bind_request(12345, true, false).await.unwrap();
        // assert!(rs.ip_changed);
        // assert!(!rs.port_changed);

        // let rs = stun.bind_request(12345, false, true).await.unwrap();
        // assert!(!rs.ip_changed);
        // assert!(rs.port_changed);

        let rs = stun.bind_request(12345, false, false).await.unwrap();
        assert!(!rs.ip_changed);
        assert!(!rs.port_changed);
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
