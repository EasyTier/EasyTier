// try connect peers directly, with either its public ip or lan ip

use std::{
    collections::HashSet,
    net::{Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    common::{
        dns::socket_addrs, error::Error, global_ctx::ArcGlobalCtx, stun::StunInfoCollectorTrait,
        PeerId,
    },
    connector::udp_hole_punch::handle_rpc_result,
    peers::{
        peer_conn::PeerConnId,
        peer_manager::PeerManager,
        peer_rpc::PeerRpcManager,
        peer_rpc_service::DirectConnectorManagerRpcServer,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        peer_rpc::{
            DirectConnectorRpc, DirectConnectorRpcClientFactory, DirectConnectorRpcServer,
            GetIpListRequest, GetIpListResponse, SendV6HolePunchPacketRequest,
        },
        rpc_types::controller::BaseController,
    },
    tunnel::{udp::UdpTunnelConnector, IpVersion},
    use_global_var,
};

use crate::proto::cli::PeerConnInfo;
use anyhow::Context;
use rand::Rng;
use tokio::{net::UdpSocket, task::JoinSet, time::timeout};
use url::Host;

use super::{create_connector_by_url, udp_hole_punch};

pub const DIRECT_CONNECTOR_SERVICE_ID: u32 = 1;
pub const DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC: u64 = 300;

static TESTING: AtomicBool = AtomicBool::new(false);

#[async_trait::async_trait]
pub trait PeerManagerForDirectConnector {
    async fn list_peers(&self) -> Vec<PeerId>;
    async fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>>;
    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager>;
}

#[async_trait::async_trait]
impl PeerManagerForDirectConnector for PeerManager {
    async fn list_peers(&self) -> Vec<PeerId> {
        let mut ret = vec![];
        let allow_public_server = use_global_var!(DIRECT_CONNECT_TO_PUBLIC_SERVER);

        let routes = self.list_routes().await;
        for r in routes.iter().filter(|r| {
            r.feature_flag
                .map(|r| allow_public_server || !r.is_public_server)
                .unwrap_or(true)
        }) {
            ret.push(r.peer_id);
        }

        ret
    }

    async fn list_peer_conns(&self, peer_id: PeerId) -> Option<Vec<PeerConnInfo>> {
        self.get_peer_map().list_peer_conns(peer_id).await
    }

    fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.get_peer_rpc_mgr()
    }
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstBlackListItem(PeerId, String);

#[derive(Hash, Eq, PartialEq, Clone)]
struct DstListenerUrlBlackListItem(PeerId, String);

struct DirectConnectorManagerData {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    dst_listener_blacklist: timedmap::TimedMap<DstListenerUrlBlackListItem, ()>,
    peer_black_list: timedmap::TimedMap<PeerId, ()>,
}

impl DirectConnectorManagerData {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        Self {
            global_ctx,
            peer_manager,
            dst_listener_blacklist: timedmap::TimedMap::new(),
            peer_black_list: timedmap::TimedMap::new(),
        }
    }

    async fn remote_send_v6_hole_punch_packet(
        &self,
        dst_peer_id: PeerId,
        local_socket: &UdpSocket,
        remote_url: &url::Url,
    ) -> Result<(), Error> {
        let global_ctx = self.peer_manager.get_global_ctx();
        let listener_port = remote_url.port().ok_or(anyhow::anyhow!(
            "failed to parse port from remote url: {}",
            remote_url
        ))?;
        let connector_ip = global_ctx
            .get_stun_info_collector()
            .get_stun_info()
            .public_ip
            .iter()
            .find(|x| x.contains(":"))
            .ok_or(anyhow::anyhow!(
                "failed to get public ipv6 address from stun info"
            ))?
            .parse::<std::net::Ipv6Addr>()
            .with_context(|| {
                format!(
                    "failed to parse public ipv6 address from stun info: {:?}",
                    global_ctx.get_stun_info_collector().get_stun_info()
                )
            })?;
        let connector_addr = SocketAddr::new(
            std::net::IpAddr::V6(connector_ip),
            local_socket.local_addr()?.port(),
        );

        let rpc_stub = self
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
            self.peer_manager.my_peer_id(),
            dst_peer_id,
            global_ctx.get_network_name(),
        );

        rpc_stub
            .send_v6_hole_punch_packet(
                BaseController::default(),
                SendV6HolePunchPacketRequest {
                    listener_port: listener_port as u32,
                    connector_addr: Some(connector_addr.into()),
                },
            )
            .await
            .with_context(|| {
                format!(
                    "do rpc, send v6 hole punch packet to peer {} at {}",
                    dst_peer_id, remote_url
                )
            })?;

        Ok(())
    }

    async fn connect_to_public_ipv6(
        &self,
        dst_peer_id: PeerId,
        remote_url: &url::Url,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let local_socket = Arc::new(
            UdpSocket::bind("[::]:0")
                .await
                .with_context(|| format!("failed to bind local socket for {}", remote_url))?,
        );

        // ask remote to send v6 hole punch packet
        // and no matter what the result is, continue to connect
        let _ = self
            .remote_send_v6_hole_punch_packet(dst_peer_id, &local_socket, &remote_url)
            .await;

        let udp_connector = UdpTunnelConnector::new(remote_url.clone());
        let remote_addr = super::check_scheme_and_get_socket_addr::<SocketAddr>(
            &remote_url,
            "udp",
            IpVersion::V6,
        )
        .await?;
        let ret = udp_connector
            .try_connect_with_socket(local_socket, remote_addr)
            .await?;

        // NOTICE: must add as directly connected tunnel
        self.peer_manager.add_client_tunnel(ret, true).await
    }

    async fn do_try_connect_to_ip(&self, dst_peer_id: PeerId, addr: String) -> Result<(), Error> {
        let connector = create_connector_by_url(&addr, &self.global_ctx, IpVersion::Both).await?;
        let remote_url = connector.remote_url();
        let (peer_id, conn_id) =
            if remote_url.scheme() == "udp" && matches!(remote_url.host(), Some(Host::Ipv6(_))) {
                self.connect_to_public_ipv6(dst_peer_id, &remote_url)
                    .await?
            } else {
                timeout(
                    std::time::Duration::from_secs(3),
                    self.peer_manager.try_direct_connect(connector),
                )
                .await??
            };

        if peer_id != dst_peer_id && !TESTING.load(Ordering::Relaxed) {
            tracing::info!(
                "connect to ip succ: {}, but peer id mismatch, expect: {}, actual: {}",
                addr,
                dst_peer_id,
                peer_id
            );
            self.peer_manager.close_peer_conn(peer_id, &conn_id).await?;
            return Err(Error::InvalidUrl(addr));
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn try_connect_to_ip(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        addr: String,
    ) -> Result<(), Error> {
        let mut rand_gen = rand::rngs::OsRng::default();
        let backoff_ms = vec![1000, 2000, 4000];
        let mut backoff_idx = 0;

        tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start");

        self.dst_listener_blacklist.cleanup();

        if self
            .dst_listener_blacklist
            .contains(&DstListenerUrlBlackListItem(
                dst_peer_id.clone(),
                addr.clone(),
            ))
        {
            return Err(Error::UrlInBlacklist);
        }

        loop {
            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }

            tracing::debug!(?dst_peer_id, ?addr, "try_connect_to_ip start one round");
            let ret = self.do_try_connect_to_ip(dst_peer_id, addr.clone()).await;
            tracing::debug!(?ret, ?dst_peer_id, ?addr, "try_connect_to_ip return");
            if ret.is_ok() {
                return Ok(());
            }

            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }

            if backoff_idx < backoff_ms.len() {
                let delta = backoff_ms[backoff_idx] >> 1;
                assert!(delta > 0);
                assert!(delta < backoff_ms[backoff_idx]);

                tokio::time::sleep(Duration::from_millis(
                    (backoff_ms[backoff_idx] + rand_gen.gen_range(-delta..delta)) as u64,
                ))
                .await;

                backoff_idx += 1;
                continue;
            } else {
                self.dst_listener_blacklist.insert(
                    DstListenerUrlBlackListItem(dst_peer_id.clone(), addr),
                    (),
                    std::time::Duration::from_secs(DIRECT_CONNECTOR_BLACKLIST_TIMEOUT_SEC),
                );
                return ret;
            }
        }
    }

    async fn spawn_direct_connect_task(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: &GetIpListResponse,
        listener: &url::Url,
        tasks: &mut JoinSet<Result<(), Error>>,
    ) {
        let Ok(mut addrs) = socket_addrs(listener, || None).await else {
            tracing::error!(?listener, "failed to parse socket address from listener");
            return;
        };
        let listener_host = addrs.pop();
        tracing::info!(?listener_host, ?listener, "try direct connect to peer");
        match listener_host {
            Some(SocketAddr::V4(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    ip_list
                        .interface_ipv4s
                        .iter()
                        .chain(ip_list.public_ipv4.iter())
                        .for_each(|ip| {
                            let mut addr = (*listener).clone();
                            if addr.set_host(Some(ip.to_string().as_str())).is_ok() {
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id.clone(),
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for interface ipv4"
                                );
                            }
                        });
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    tasks.spawn(Self::try_connect_to_ip(
                        self.clone(),
                        dst_peer_id.clone(),
                        listener.to_string(),
                    ));
                }
            }
            Some(SocketAddr::V6(s_addr)) => {
                if s_addr.ip().is_unspecified() {
                    // for ipv6, only try public ip
                    ip_list
                        .interface_ipv6s
                        .iter()
                        .chain(ip_list.public_ipv6.iter())
                        .filter_map(|x| Ipv6Addr::from_str(&x.to_string()).ok())
                        .filter(|x| {
                            TESTING.load(Ordering::Relaxed)
                                || (!x.is_loopback()
                                    && !x.is_unspecified()
                                    && !x.is_unique_local()
                                    && !x.is_unicast_link_local()
                                    && !x.is_multicast())
                        })
                        .collect::<HashSet<_>>()
                        .iter()
                        .for_each(|ip| {
                            let mut addr = (*listener).clone();
                            if addr
                                .set_host(Some(format!("[{}]", ip.to_string()).as_str()))
                                .is_ok()
                            {
                                tasks.spawn(Self::try_connect_to_ip(
                                    self.clone(),
                                    dst_peer_id.clone(),
                                    addr.to_string(),
                                ));
                            } else {
                                tracing::error!(
                                    ?ip,
                                    ?listener,
                                    ?dst_peer_id,
                                    "failed to set host for public ipv6"
                                );
                            }
                        });
                } else if !s_addr.ip().is_loopback() || TESTING.load(Ordering::Relaxed) {
                    tasks.spawn(Self::try_connect_to_ip(
                        self.clone(),
                        dst_peer_id.clone(),
                        listener.to_string(),
                    ));
                }
            }
            p => {
                tracing::error!(?p, ?listener, "failed to parse ip version from listener");
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect_internal(
        self: &Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> Result<(), Error> {
        let enable_ipv6 = self.global_ctx.get_flags().enable_ipv6;
        let available_listeners = ip_list
            .listeners
            .clone()
            .into_iter()
            .map(Into::<url::Url>::into)
            .filter_map(|l| if l.scheme() != "ring" { Some(l) } else { None })
            .filter(|l| l.port().is_some() && l.host().is_some())
            .filter(|l| enable_ipv6 || !matches!(l.host().unwrap().to_owned(), Host::Ipv6(_)))
            .collect::<Vec<_>>();

        tracing::debug!(?available_listeners, "got available listeners");

        if available_listeners.is_empty() {
            return Err(anyhow::anyhow!("peer {} have no valid listener", dst_peer_id).into());
        }

        let default_protocol = self.global_ctx.get_flags().default_protocol;
        // sort available listeners, default protocol has the highest priority, udp is second, others just random
        // highest priority is in the last
        let mut available_listeners = available_listeners;
        available_listeners.sort_by_key(|l| {
            let scheme = l.scheme();
            if scheme == default_protocol {
                3
            } else if scheme == "udp" {
                2
            } else {
                1
            }
        });

        while !available_listeners.is_empty() {
            let mut tasks = JoinSet::new();
            let mut listener_list = vec![];

            let cur_scheme = available_listeners.last().unwrap().scheme().to_owned();
            while let Some(listener) = available_listeners.last() {
                if listener.scheme() != cur_scheme {
                    break;
                }

                tracing::debug!("try direct connect to peer with listener: {}", listener);
                self.spawn_direct_connect_task(
                    dst_peer_id.clone(),
                    &ip_list,
                    &listener,
                    &mut tasks,
                )
                .await;

                listener_list.push(listener.clone().to_string());
                available_listeners.pop();
            }

            let ret = tasks.join_all().await;
            tracing::debug!(
                ?ret,
                ?dst_peer_id,
                ?cur_scheme,
                ?listener_list,
                "all tasks finished for current scheme"
            );

            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                tracing::info!(
                    "direct connect to peer {} success, has direct conn",
                    dst_peer_id
                );
                return Ok(());
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn do_try_direct_connect(
        self: Arc<DirectConnectorManagerData>,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        let mut backoff =
            udp_hole_punch::BackOff::new(vec![1000, 2000, 2000, 5000, 5000, 10000, 30000, 60000]);
        let mut attempt = 0;
        loop {
            if self.peer_black_list.contains(&dst_peer_id) {
                return Err(anyhow::anyhow!("peer {} is blacklisted", dst_peer_id).into());
            }

            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(backoff.next_backoff())).await;
            }
            attempt += 1;

            let peer_manager = self.peer_manager.clone();
            tracing::debug!("try direct connect to peer: {}", dst_peer_id);

            let rpc_stub = peer_manager
                .get_peer_rpc_mgr()
                .rpc_client()
                .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
                peer_manager.my_peer_id(),
                dst_peer_id,
                self.global_ctx.get_network_name(),
            );

            let ip_list = rpc_stub
                .get_ip_list(BaseController::default(), GetIpListRequest {})
                .await;
            let ip_list = handle_rpc_result(ip_list, dst_peer_id, &self.peer_black_list)
                .with_context(|| format!("get ip list from peer {}", dst_peer_id))?;

            tracing::info!(ip_list = ?ip_list, dst_peer_id = ?dst_peer_id, "got ip list");

            let ret = self
                .do_try_direct_connect_internal(dst_peer_id, ip_list)
                .await;
            tracing::info!(?ret, ?dst_peer_id, "do_try_direct_connect return");

            if peer_manager.has_directly_connected_conn(dst_peer_id) {
                tracing::info!(
                    "direct connect to peer {} success, has direct conn",
                    dst_peer_id
                );
                return Ok(());
            }
        }
    }
}

impl std::fmt::Debug for DirectConnectorManagerData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectConnectorManagerData")
            .field("peer_manager", &self.peer_manager)
            .finish()
    }
}

pub struct DirectConnectorManager {
    global_ctx: ArcGlobalCtx,
    data: Arc<DirectConnectorManagerData>,
    client: PeerTaskManager<DirectConnectorLauncher>,
    tasks: JoinSet<()>,
}

#[derive(Clone)]
struct DirectConnectorLauncher(Arc<DirectConnectorManagerData>);

#[async_trait::async_trait]
impl PeerTaskLauncher for DirectConnectorLauncher {
    type Data = Arc<DirectConnectorManagerData>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();

    fn new_data(&self, _peer_mgr: Arc<PeerManager>) -> Self::Data {
        self.0.clone()
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        data.peer_black_list.cleanup();
        let my_peer_id = data.peer_manager.my_peer_id();
        data.peer_manager
            .list_peers()
            .await
            .into_iter()
            .filter(|peer_id| {
                *peer_id != my_peer_id
                    && !data.peer_manager.has_directly_connected_conn(*peer_id)
                    && !data.peer_black_list.contains(peer_id)
            })
            .collect()
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> tokio::task::JoinHandle<Result<Self::TaskRet, anyhow::Error>> {
        let data = data.clone();
        tokio::spawn(async move { data.do_try_direct_connect(item).await.map_err(Into::into) })
    }

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

impl DirectConnectorManager {
    pub fn new(global_ctx: ArcGlobalCtx, peer_manager: Arc<PeerManager>) -> Self {
        let data = Arc::new(DirectConnectorManagerData::new(
            global_ctx.clone(),
            peer_manager.clone(),
        ));
        let client = PeerTaskManager::new(DirectConnectorLauncher(data.clone()), peer_manager);
        Self {
            global_ctx,
            data,
            client,
            tasks: JoinSet::new(),
        }
    }

    pub fn run(&mut self) {
        if self.global_ctx.get_flags().disable_p2p {
            return;
        }

        self.run_as_server();
        self.run_as_client();
    }

    pub fn run_as_server(&mut self) {
        self.data
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DirectConnectorRpcServer::new(DirectConnectorManagerRpcServer::new(
                    self.global_ctx.clone(),
                )),
                &self.data.global_ctx.get_network_name(),
            );
    }

    pub fn run_as_client(&mut self) {
        self.client.start();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        connector::direct::{
            DirectConnectorManager, DirectConnectorManagerData, DstListenerUrlBlackListItem,
        },
        instance::listeners::ListenerManager,
        peers::tests::{
            connect_peer_manager, create_mock_peer_manager, wait_route_appear,
            wait_route_appear_with_cost,
        },
        proto::peer_rpc::GetIpListResponse,
    };

    use super::TESTING;

    #[tokio::test]
    async fn direct_connector_mapped_listener() {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        let p_x = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        connect_peer_manager(p_c.clone(), p_x.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
        wait_route_appear(p_a.clone(), p_x.clone()).await.unwrap();

        let mut f = p_a.get_global_ctx().get_flags();
        f.bind_device = false;
        p_a.get_global_ctx().config.set_flags(f);

        p_c.get_global_ctx()
            .config
            .set_mapped_listeners(Some(vec!["tcp://127.0.0.1:11334".parse().unwrap()]));

        p_x.get_global_ctx()
            .config
            .set_listeners(vec!["tcp://0.0.0.0:11334".parse().unwrap()]);
        let mut lis_x = ListenerManager::new(p_x.get_global_ctx(), p_x.clone());
        lis_x.prepare_listeners().await.unwrap();
        lis_x.run().await.unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut dm_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut dm_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());
        dm_a.run_as_client();
        dm_c.run_as_server();
        // p_c's mapped listener is p_x's listener, so p_a should connect to p_x directly

        wait_route_appear_with_cost(p_a.clone(), p_x.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn direct_connector_basic_test(
        #[values("tcp", "udp", "wg")] proto: &str,
        #[values("true", "false")] ipv6: bool,
    ) {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);

        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;
        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;

        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        p_c.get_global_ctx()
            .get_ip_collector()
            .collect_ip_addrs()
            .await;

        tokio::time::sleep(std::time::Duration::from_secs(4)).await;

        let mut dm_a = DirectConnectorManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut dm_c = DirectConnectorManager::new(p_c.get_global_ctx(), p_c.clone());

        dm_a.run_as_client();
        dm_c.run_as_server();

        let port = if proto == "wg" { 11040 } else { 11041 };
        if !ipv6 {
            p_c.get_global_ctx().config.set_listeners(vec![format!(
                "{}://0.0.0.0:{}",
                proto, port
            )
            .parse()
            .unwrap()]);
        } else {
            p_c.get_global_ctx()
                .config
                .set_listeners(vec![format!("{}://[::]:{}", proto, port).parse().unwrap()]);
        }
        let mut f = p_c.get_global_ctx().config.get_flags();
        f.enable_ipv6 = ipv6;
        p_c.get_global_ctx().config.set_flags(f);
        let mut lis_c = ListenerManager::new(p_c.get_global_ctx(), p_c.clone());
        lis_c.prepare_listeners().await.unwrap();

        lis_c.run().await.unwrap();

        wait_route_appear_with_cost(p_a.clone(), p_c.my_peer_id(), Some(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn direct_connector_scheme_blacklist() {
        TESTING.store(true, std::sync::atomic::Ordering::Relaxed);
        let p_a = create_mock_peer_manager().await;
        let data = Arc::new(DirectConnectorManagerData::new(
            p_a.get_global_ctx(),
            p_a.clone(),
        ));
        let mut ip_list = GetIpListResponse::default();
        ip_list
            .listeners
            .push("tcp://127.0.0.1:10222".parse().unwrap());

        ip_list
            .interface_ipv4s
            .push("127.0.0.1".parse::<std::net::Ipv4Addr>().unwrap().into());

        data.do_try_direct_connect_internal(1, ip_list.clone())
            .await
            .unwrap();

        assert!(data
            .dst_listener_blacklist
            .contains(&DstListenerUrlBlackListItem(
                1,
                "tcp://127.0.0.1:10222".parse().unwrap()
            )));
    }
}
