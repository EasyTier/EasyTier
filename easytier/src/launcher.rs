use crate::common::config::{ConfigFileControl, PortForwardConfig};
use crate::proto::api::{self, manage};
use crate::proto::rpc_types::controller::BaseController;
use crate::rpc_service::InstanceRpcService;
use crate::{
    common::{
        config::{
            gen_default_flags, ConfigLoader, NetworkIdentity, PeerConfig, TomlConfigLoader,
            VpnPortalConfig,
        },
        constants::EASYTIER_VERSION,
        global_ctx::{EventBusSubscriber, GlobalCtxEvent},
    },
    instance::instance::Instance,
    proto::api::instance::list_peer_route_pair,
};
use anyhow::Context;
use chrono::{DateTime, Local};
use std::net::SocketAddr;
use std::{
    collections::VecDeque,
    sync::{atomic::AtomicBool, Arc, RwLock},
};
use tokio::{sync::broadcast, task::JoinSet};

pub type MyNodeInfo = crate::proto::api::manage::MyNodeInfo;

type ArcMutApiService = Arc<RwLock<Option<Arc<dyn InstanceRpcService>>>>;

#[derive(serde::Serialize, Clone)]
pub struct Event {
    time: DateTime<Local>,
    event: GlobalCtxEvent,
}

struct EasyTierData {
    events: RwLock<VecDeque<Event>>,
    tun_fd: Arc<RwLock<Option<i32>>>,
    event_subscriber: RwLock<broadcast::Sender<GlobalCtxEvent>>,
    instance_stop_notifier: Arc<tokio::sync::Notify>,
}

impl Default for EasyTierData {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            event_subscriber: RwLock::new(tx),
            events: RwLock::new(VecDeque::new()),
            tun_fd: Arc::new(RwLock::new(None)),
            instance_stop_notifier: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

pub struct EasyTierLauncher {
    instance_alive: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    api_service: ArcMutApiService,
    running_cfg: String,
    error_msg: Arc<RwLock<Option<String>>>,
    data: Arc<EasyTierData>,
}

impl EasyTierLauncher {
    pub fn new() -> Self {
        let instance_alive = Arc::new(AtomicBool::new(false));
        Self {
            instance_alive,
            thread_handle: None,
            api_service: Arc::new(RwLock::new(None)),
            error_msg: Arc::new(RwLock::new(None)),
            running_cfg: String::new(),
            stop_flag: Arc::new(AtomicBool::new(false)),
            data: Arc::new(EasyTierData::default()),
        }
    }

    async fn handle_easytier_event(event: GlobalCtxEvent, data: &EasyTierData) {
        let mut events = data.events.write().unwrap();
        let _ = data.event_subscriber.read().unwrap().send(event.clone());
        events.push_front(Event {
            time: chrono::Local::now(),
            event,
        });
        if events.len() > 20 {
            events.pop_back();
        }
    }

    #[cfg(any(target_os = "android", target_env = "ohos"))]
    async fn run_routine_for_android(
        instance: &Instance,
        data: &EasyTierData,
        tasks: &mut JoinSet<()>,
    ) {
        let global_ctx = instance.get_global_ctx();
        let peer_mgr = instance.get_peer_manager();
        let nic_ctx = instance.get_nic_ctx();
        let peer_packet_receiver = instance.get_peer_packet_receiver();
        let arc_tun_fd = data.tun_fd.clone();

        tasks.spawn(async move {
            let mut old_tun_fd = arc_tun_fd.read().unwrap().clone();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let tun_fd = arc_tun_fd.read().unwrap().clone();
                if tun_fd != old_tun_fd && tun_fd.is_some() {
                    let res = Instance::setup_nic_ctx_for_android(
                        nic_ctx.clone(),
                        global_ctx.clone(),
                        peer_mgr.clone(),
                        peer_packet_receiver.clone(),
                        tun_fd.unwrap(),
                    )
                    .await;
                    if res.is_ok() {
                        old_tun_fd = tun_fd;
                    }
                }
            }
        });
    }

    async fn easytier_routine(
        cfg: TomlConfigLoader,
        stop_signal: Arc<tokio::sync::Notify>,
        api_service: ArcMutApiService,
        data: Arc<EasyTierData>,
    ) -> Result<(), anyhow::Error> {
        let mut instance = Instance::new(cfg);
        let mut tasks = JoinSet::new();

        // Subscribe to global context events
        let global_ctx = instance.get_global_ctx();
        let data_c = data.clone();
        tasks.spawn(async move {
            let mut receiver = global_ctx.subscribe();
            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        Self::handle_easytier_event(event.clone(), &data_c).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // do nothing currently
                        receiver = receiver.resubscribe();
                    }
                }
            }
        });

        #[cfg(any(target_os = "android", target_env = "ohos"))]
        Self::run_routine_for_android(&instance, &data, &mut tasks).await;

        instance.run().await?;

        api_service
            .write()
            .unwrap()
            .replace(Arc::new(instance.get_api_rpc_service()));
        drop(api_service);

        stop_signal.notified().await;

        tasks.abort_all();
        drop(tasks);

        instance.clear_resources().await;
        drop(instance);

        Ok(())
    }

    pub fn start<F>(&mut self, cfg_generator: F)
    where
        F: FnOnce() -> Result<TomlConfigLoader, anyhow::Error> + Send + Sync,
    {
        let error_msg = self.error_msg.clone();
        let cfg = match cfg_generator() {
            Err(e) => {
                error_msg.write().unwrap().replace(e.to_string());
                return;
            }
            Ok(cfg) => cfg,
        };

        self.running_cfg = cfg.dump();

        let stop_flag = self.stop_flag.clone();

        let instance_alive = self.instance_alive.clone();
        instance_alive.store(true, std::sync::atomic::Ordering::Relaxed);

        let data = self.data.clone();
        let api_service = self.api_service.clone();

        self.thread_handle = Some(std::thread::spawn(move || {
            let rt = if cfg.get_flags().multi_thread {
                let worker_threads = 2.max(cfg.get_flags().multi_thread_count as usize);
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(worker_threads)
                    .enable_all()
                    .build()
            } else {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
            }
            .unwrap();

            let stop_notifier = Arc::new(tokio::sync::Notify::new());

            let stop_notifier_clone = stop_notifier.clone();
            rt.spawn(async move {
                while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                stop_notifier_clone.notify_one();
            });

            let notifier = data.instance_stop_notifier.clone();
            let ret = rt.block_on(Self::easytier_routine(
                cfg,
                stop_notifier.clone(),
                api_service,
                data,
            ));
            if let Err(e) = ret {
                error_msg.write().unwrap().replace(format!("{:?}", e));
            }
            instance_alive.store(false, std::sync::atomic::Ordering::Relaxed);
            notifier.notify_one();
        }));
    }

    pub fn error_msg(&self) -> Option<String> {
        self.error_msg.read().unwrap().clone()
    }

    pub fn running(&self) -> bool {
        self.instance_alive
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn get_events(&self) -> Vec<Event> {
        let events = self.data.events.read().unwrap();
        events.iter().cloned().collect()
    }

    pub fn get_api_service(&self) -> Option<Arc<dyn InstanceRpcService>> {
        match self.api_service.read() {
            Ok(guard) => guard.clone(),
            Err(e) => {
                tracing::error!("Failed to acquire read lock for api_service: {:?}", e);
                None
            }
        }
    }
}

impl Default for EasyTierLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EasyTierLauncher {
    fn drop(&mut self) {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.thread_handle.take() {
            if let Err(e) = handle.join() {
                println!("Error when joining thread: {:?}", e);
            }
        }
    }
}

pub type NetworkInstanceRunningInfo = crate::proto::api::manage::NetworkInstanceRunningInfo;

pub struct NetworkInstance {
    config: TomlConfigLoader,
    launcher: Option<EasyTierLauncher>,
    config_file_control: ConfigFileControl,
}

impl NetworkInstance {
    pub fn new(config: TomlConfigLoader, config_file_control: ConfigFileControl) -> Self {
        Self {
            config,
            launcher: None,
            config_file_control,
        }
    }

    pub fn is_easytier_running(&self) -> bool {
        self.launcher.is_some() && self.launcher.as_ref().unwrap().running()
    }

    pub async fn get_running_info(&self) -> anyhow::Result<NetworkInstanceRunningInfo> {
        let launcher = self.launcher.as_ref().ok_or_else(|| {
            anyhow::anyhow!("instance is not running, please start the instance first")
        })?;
        let api_service = self.get_api_service().ok_or_else(|| {
            anyhow::anyhow!("failed to get api service, instance may not be running")
        })?;
        let ctrl = BaseController::default();

        let peers = api_service
            .get_peer_manage_service()
            .list_peer(ctrl.clone(), api::instance::ListPeerRequest::default())
            .await?
            .peer_infos;
        let my_info = api_service
            .get_peer_manage_service()
            .show_node_info(ctrl.clone(), api::instance::ShowNodeInfoRequest::default())
            .await?
            .node_info
            .ok_or_else(|| anyhow::anyhow!("failed to get my node info"))?;
        let vpn_portal_cfg = api_service
            .get_vpn_portal_service()
            .get_vpn_portal_info(
                ctrl.clone(),
                api::instance::GetVpnPortalInfoRequest::default(),
            )
            .await?
            .vpn_portal_info
            .map(|i| i.client_config);
        let routes = api_service
            .get_peer_manage_service()
            .list_route(ctrl.clone(), api::instance::ListRouteRequest::default())
            .await?
            .routes;
        let peer_route_pairs = list_peer_route_pair(peers.clone(), routes.clone());
        let foreign_network_summary = api_service
            .get_peer_manage_service()
            .get_foreign_network_summary(
                ctrl.clone(),
                api::instance::GetForeignNetworkSummaryRequest::default(),
            )
            .await?
            .summary;
        let dev_name = api_service
            .get_config_service()
            .get_config(ctrl.clone(), api::config::GetConfigRequest::default())
            .await?
            .config
            .ok_or_else(|| anyhow::anyhow!("failed to get config"))?
            .dev_name
            .unwrap_or_else(|| "".to_string());

        Ok(NetworkInstanceRunningInfo {
            dev_name,
            my_node_info: Some(MyNodeInfo {
                virtual_ipv4: my_info
                    .ipv4_addr
                    .parse::<cidr::Ipv4Inet>()
                    .ok()
                    .map(Into::into),
                hostname: my_info.hostname,
                version: EASYTIER_VERSION.to_string(),
                ips: my_info.ip_list,
                stun_info: my_info.stun_info,
                listeners: my_info
                    .listeners
                    .into_iter()
                    .map(|s| s.parse::<url::Url>().unwrap().into())
                    .collect(),
                vpn_portal_cfg,
            }),
            events: launcher
                .get_events()
                .iter()
                .map(|e| serde_json::to_string(e).unwrap())
                .collect(),
            routes,
            peers,
            peer_route_pairs,
            running: launcher.running(),
            error_msg: launcher.error_msg(),
            foreign_network_summary,
        })
    }

    pub fn get_inst_name(&self) -> String {
        self.config.get_inst_name()
    }

    pub fn get_network_name(&self) -> String {
        self.config.get_network_identity().network_name
    }

    pub fn set_tun_fd(&mut self, tun_fd: i32) {
        if let Some(launcher) = self.launcher.as_ref() {
            launcher.data.tun_fd.write().unwrap().replace(tun_fd);
        }
    }

    pub fn start(&mut self) -> Result<EventBusSubscriber, anyhow::Error> {
        if self.is_easytier_running() {
            return Ok(self.subscribe_event().unwrap());
        }

        let launcher = EasyTierLauncher::new();
        self.launcher = Some(launcher);
        let ev = self.subscribe_event().unwrap();

        self.launcher
            .as_mut()
            .unwrap()
            .start(|| Ok(self.config.clone()));

        Ok(ev)
    }

    pub fn subscribe_event(&self) -> Option<broadcast::Receiver<GlobalCtxEvent>> {
        self.launcher
            .as_ref()
            .map(|launcher| launcher.data.event_subscriber.read().unwrap().subscribe())
    }

    pub fn get_stop_notifier(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.launcher
            .as_ref()
            .map(|launcher| launcher.data.instance_stop_notifier.clone())
    }

    pub fn get_config_file_control(&self) -> &ConfigFileControl {
        &self.config_file_control
    }

    pub fn get_latest_error_msg(&self) -> Option<String> {
        if let Some(launcher) = self.launcher.as_ref() {
            launcher.error_msg.read().unwrap().clone()
        } else {
            None
        }
    }

    pub fn get_api_service(&self) -> Option<Arc<dyn InstanceRpcService>> {
        self.launcher
            .as_ref()
            .and_then(|launcher| launcher.get_api_service())
    }
}

pub fn add_proxy_network_to_config(
    proxy_network: &str,
    cfg: &TomlConfigLoader,
) -> Result<(), anyhow::Error> {
    let parts: Vec<&str> = proxy_network.split("->").collect();
    let real_cidr = parts[0]
        .parse()
        .with_context(|| format!("failed to parse proxy network: {}", parts[0]))?;

    if parts.len() > 2 {
        return Err(anyhow::anyhow!(
                    "invalid proxy network format: {}, support format: <real_cidr> or <real_cidr>-><mapped_cidr>, example:
                    10.0.0.0/24 or 10.0.0.0/24->192.168.0.0/24",
                    proxy_network
                ));
    }

    let mapped_cidr = if parts.len() == 2 {
        Some(
            parts[1]
                .parse()
                .with_context(|| format!("failed to parse mapped network: {}", parts[1]))?,
        )
    } else {
        None
    };
    cfg.add_proxy_cidr(real_cidr, mapped_cidr)?;
    Ok(())
}

pub type NetworkingMethod = crate::proto::api::manage::NetworkingMethod;
pub type NetworkConfig = crate::proto::api::manage::NetworkConfig;

impl NetworkConfig {
    pub fn gen_config(&self) -> Result<TomlConfigLoader, anyhow::Error> {
        let cfg = TomlConfigLoader::default();
        cfg.set_id(
            self.instance_id
                .clone()
                .unwrap_or(uuid::Uuid::new_v4().to_string())
                .parse()
                .with_context(|| format!("failed to parse instance id: {:?}", self.instance_id))?,
        );
        cfg.set_hostname(self.hostname.clone());
        cfg.set_dhcp(self.dhcp.unwrap_or_default());
        cfg.set_inst_name(self.network_name.clone().unwrap_or_default());
        cfg.set_network_identity(NetworkIdentity::new(
            self.network_name.clone().unwrap_or_default(),
            self.network_secret.clone().unwrap_or_default(),
        ));

        if !cfg.get_dhcp() {
            let virtual_ipv4 = self.virtual_ipv4.clone().unwrap_or_default();
            if !virtual_ipv4.is_empty() {
                let ip = format!("{}/{}", virtual_ipv4, self.network_length.unwrap_or(24))
                    .parse()
                    .with_context(|| {
                        format!(
                            "failed to parse ipv4 inet address: {}, {:?}",
                            virtual_ipv4, self.network_length
                        )
                    })?;
                cfg.set_ipv4(Some(ip));
            }
        }

        match NetworkingMethod::try_from(self.networking_method.unwrap_or_default())
            .unwrap_or_default()
        {
            NetworkingMethod::PublicServer => {
                let public_server_url = self.public_server_url.clone().unwrap_or_default();
                cfg.set_peers(vec![PeerConfig {
                    uri: public_server_url.parse().with_context(|| {
                        format!("failed to parse public server uri: {}", public_server_url)
                    })?,
                }]);
            }
            NetworkingMethod::Manual => {
                let mut peers = vec![];
                for peer_url in self.peer_urls.iter() {
                    if peer_url.is_empty() {
                        continue;
                    }
                    peers.push(PeerConfig {
                        uri: peer_url
                            .parse()
                            .with_context(|| format!("failed to parse peer uri: {}", peer_url))?,
                    });
                }

                cfg.set_peers(peers);
            }
            NetworkingMethod::Standalone => {}
        }

        let mut listener_urls = vec![];
        for listener_url in self.listener_urls.iter() {
            if listener_url.is_empty() {
                continue;
            }
            listener_urls.push(
                listener_url
                    .parse()
                    .with_context(|| format!("failed to parse listener uri: {}", listener_url))?,
            );
        }
        cfg.set_listeners(listener_urls);

        for n in self.proxy_cidrs.iter() {
            add_proxy_network_to_config(n, &cfg)?;
        }

        if !self.port_forwards.is_empty() {
            cfg.set_port_forwards(
                self.port_forwards
                    .iter()
                    .filter(|pf| !pf.bind_ip.is_empty() && !pf.dst_ip.is_empty())
                    .filter_map(|pf| {
                        let bind_addr =
                            format!("{}:{}", pf.bind_ip, pf.bind_port).parse::<SocketAddr>();
                        let dst_addr =
                            format!("{}:{}", pf.dst_ip, pf.dst_port).parse::<SocketAddr>();

                        match (bind_addr, dst_addr) {
                            (Ok(bind_addr), Ok(dst_addr)) => Some(PortForwardConfig {
                                bind_addr,
                                dst_addr,
                                proto: pf.proto.clone(),
                            }),
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>(),
            );
        }

        if self.enable_vpn_portal.unwrap_or_default() {
            let cidr = format!(
                "{}/{}",
                self.vpn_portal_client_network_addr
                    .clone()
                    .unwrap_or_default(),
                self.vpn_portal_client_network_len.unwrap_or(24)
            );
            cfg.set_vpn_portal_config(VpnPortalConfig {
                client_cidr: cidr
                    .parse()
                    .with_context(|| format!("failed to parse vpn portal client cidr: {}", cidr))?,
                wireguard_listen: format!(
                    "0.0.0.0:{}",
                    self.vpn_portal_listen_port.unwrap_or_default()
                )
                .parse()
                .with_context(|| {
                    format!(
                        "failed to parse vpn portal wireguard listen port. {:?}",
                        self.vpn_portal_listen_port
                    )
                })?,
            });
        }

        if self.enable_manual_routes.unwrap_or_default() {
            let mut routes = Vec::<cidr::Ipv4Cidr>::with_capacity(self.routes.len());
            for route in self.routes.iter() {
                routes.push(
                    route
                        .parse()
                        .with_context(|| format!("failed to parse route: {}", route))?,
                );
            }
            cfg.set_routes(Some(routes));
        }

        if !self.exit_nodes.is_empty() {
            let mut exit_nodes = Vec::<std::net::IpAddr>::with_capacity(self.exit_nodes.len());
            for node in self.exit_nodes.iter() {
                exit_nodes.push(
                    node.parse()
                        .with_context(|| format!("failed to parse exit node: {}", node))?,
                );
            }
            cfg.set_exit_nodes(exit_nodes);
        }

        if self.enable_socks5.unwrap_or_default() {
            if let Some(socks5_port) = self.socks5_port {
                cfg.set_socks5_portal(Some(
                    format!("socks5://0.0.0.0:{}", socks5_port).parse().unwrap(),
                ));
            }
        }

        if !self.mapped_listeners.is_empty() {
            cfg.set_mapped_listeners(Some(
                self.mapped_listeners
                    .iter()
                    .map(|s| {
                        s.parse()
                            .with_context(|| format!("mapped listener is not a valid url: {}", s))
                            .unwrap()
                    })
                    .map(|s: url::Url| {
                        if s.port().is_none() {
                            panic!("mapped listener port is missing: {}", s);
                        }
                        s
                    })
                    .collect(),
            ));
        }

        let mut flags = gen_default_flags();
        if let Some(latency_first) = self.latency_first {
            flags.latency_first = latency_first;
        }

        if let Some(dev_name) = self.dev_name.clone() {
            flags.dev_name = dev_name;
        }

        if let Some(use_smoltcp) = self.use_smoltcp {
            flags.use_smoltcp = use_smoltcp;
        }

        if let Some(disable_ipv6) = self.disable_ipv6 {
            flags.enable_ipv6 = !disable_ipv6;
        }

        if let Some(enable_kcp_proxy) = self.enable_kcp_proxy {
            flags.enable_kcp_proxy = enable_kcp_proxy;
        }

        if let Some(disable_kcp_input) = self.disable_kcp_input {
            flags.disable_kcp_input = disable_kcp_input;
        }

        if let Some(enable_quic_proxy) = self.enable_quic_proxy {
            flags.enable_quic_proxy = enable_quic_proxy;
        }

        if let Some(disable_quic_input) = self.disable_quic_input {
            flags.disable_quic_input = disable_quic_input;
        }

        if let Some(quic_listen_port) = self.quic_listen_port {
            flags.quic_listen_port = quic_listen_port as u32;
        }

        if let Some(disable_p2p) = self.disable_p2p {
            flags.disable_p2p = disable_p2p;
        }

        if let Some(p2p_only) = self.p2p_only {
            flags.p2p_only = p2p_only;
        }

        if let Some(bind_device) = self.bind_device {
            flags.bind_device = bind_device;
        }

        if let Some(no_tun) = self.no_tun {
            flags.no_tun = no_tun;
        }

        if let Some(enable_exit_node) = self.enable_exit_node {
            flags.enable_exit_node = enable_exit_node;
        }

        if let Some(relay_all_peer_rpc) = self.relay_all_peer_rpc {
            flags.relay_all_peer_rpc = relay_all_peer_rpc;
        }

        if let Some(multi_thread) = self.multi_thread {
            flags.multi_thread = multi_thread;
        }

        if let Some(proxy_forward_by_system) = self.proxy_forward_by_system {
            flags.proxy_forward_by_system = proxy_forward_by_system;
        }

        if let Some(disable_encryption) = self.disable_encryption {
            flags.enable_encryption = !disable_encryption;
        }

        if self.enable_relay_network_whitelist.unwrap_or_default() {
            if !self.relay_network_whitelist.is_empty() {
                flags.relay_network_whitelist = self.relay_network_whitelist.join(" ");
            } else {
                flags.relay_network_whitelist = "".to_string();
            }
        }

        if let Some(disable_udp_hole_punching) = self.disable_udp_hole_punching {
            flags.disable_udp_hole_punching = disable_udp_hole_punching;
        }

        if let Some(disable_sym_hole_punching) = self.disable_sym_hole_punching {
            flags.disable_sym_hole_punching = disable_sym_hole_punching;
        }

        if let Some(enable_magic_dns) = self.enable_magic_dns {
            flags.accept_dns = enable_magic_dns;
        }

        if let Some(mtu) = self.mtu {
            flags.mtu = mtu as u32;
        }

        if let Some(enable_private_mode) = self.enable_private_mode {
            flags.private_mode = enable_private_mode;
        }

        if let Some(encryption_algorithm) = self.encryption_algorithm.clone() {
            flags.encryption_algorithm = encryption_algorithm;
        }

        if let Some(data_compress_algo) = self.data_compress_algo {
            if data_compress_algo < 1 {
                flags.data_compress_algo = 1;
            } else {
                flags.data_compress_algo = data_compress_algo
            }
        }

        cfg.set_flags(flags);
        Ok(cfg)
    }

    pub fn new_from_config(config: impl ConfigLoader) -> Result<Self, anyhow::Error> {
        let default_config = TomlConfigLoader::default();

        let mut result = Self {
            ..Default::default()
        };

        result.instance_id = Some(config.get_id().to_string());
        if config.get_hostname() != default_config.get_hostname() {
            result.hostname = Some(config.get_hostname());
        }

        result.dhcp = Some(config.get_dhcp());

        let network_identity = config.get_network_identity();
        result.network_name = Some(network_identity.network_name.clone());
        result.network_secret = network_identity.network_secret.clone();

        if let Some(ipv4) = config.get_ipv4() {
            result.virtual_ipv4 = Some(ipv4.address().to_string());
            result.network_length = Some(ipv4.network_length() as i32);
        }

        let peers = config.get_peers();
        match peers.len() {
            1 => {
                result.networking_method = Some(NetworkingMethod::PublicServer as i32);
                result.public_server_url = Some(peers[0].uri.to_string());
            }
            0 => {
                result.networking_method = Some(NetworkingMethod::Standalone as i32);
            }
            _ => {
                result.networking_method = Some(NetworkingMethod::Manual as i32);
                result.peer_urls = peers.iter().map(|p| p.uri.to_string()).collect();
            }
        }

        result.listener_urls = config
            .get_listeners()
            .unwrap_or_default()
            .iter()
            .map(|l| l.to_string())
            .collect();

        result.proxy_cidrs = config
            .get_proxy_cidrs()
            .iter()
            .map(|c| {
                if let Some(mapped) = c.mapped_cidr {
                    format!("{}->{}", c.cidr, mapped)
                } else {
                    c.cidr.to_string()
                }
            })
            .collect();

        let port_forwards = config.get_port_forwards();
        if !port_forwards.is_empty() {
            result.port_forwards = port_forwards
                .iter()
                .map(|f| manage::PortForwardConfig {
                    proto: f.proto.clone(),
                    bind_ip: f.bind_addr.ip().to_string(),
                    bind_port: f.bind_addr.port() as u32,
                    dst_ip: f.dst_addr.ip().to_string(),
                    dst_port: f.dst_addr.port() as u32,
                })
                .collect();
        }

        if let Some(vpn_config) = config.get_vpn_portal_config() {
            result.enable_vpn_portal = Some(true);

            let cidr = vpn_config.client_cidr;
            result.vpn_portal_client_network_addr = Some(cidr.first_address().to_string());
            result.vpn_portal_client_network_len = Some(cidr.network_length() as i32);

            result.vpn_portal_listen_port = Some(vpn_config.wireguard_listen.port() as i32);
        }

        if let Some(routes) = config.get_routes() {
            if !routes.is_empty() {
                result.enable_manual_routes = Some(true);
                result.routes = routes.iter().map(|r| r.to_string()).collect();
            }
        }

        let exit_nodes = config.get_exit_nodes();
        if !exit_nodes.is_empty() {
            result.exit_nodes = exit_nodes.iter().map(|n| n.to_string()).collect();
        }

        if let Some(socks5_portal) = config.get_socks5_portal() {
            result.enable_socks5 = Some(true);
            result.socks5_port = socks5_portal.port().map(|p| p as i32);
        }

        let mapped_listeners = config.get_mapped_listeners();
        if !mapped_listeners.is_empty() {
            result.mapped_listeners = mapped_listeners.iter().map(|l| l.to_string()).collect();
        }

        let flags = config.get_flags();
        result.latency_first = Some(flags.latency_first);
        result.dev_name = Some(flags.dev_name.clone());
        result.use_smoltcp = Some(flags.use_smoltcp);
        result.disable_ipv6 = Some(!flags.enable_ipv6);
        result.enable_kcp_proxy = Some(flags.enable_kcp_proxy);
        result.disable_kcp_input = Some(flags.disable_kcp_input);
        result.enable_quic_proxy = Some(flags.enable_quic_proxy);
        result.disable_quic_input = Some(flags.disable_quic_input);
        result.quic_listen_port = Some(flags.quic_listen_port as i32);
        result.disable_p2p = Some(flags.disable_p2p);
        result.p2p_only = Some(flags.p2p_only);
        result.bind_device = Some(flags.bind_device);
        result.no_tun = Some(flags.no_tun);
        result.enable_exit_node = Some(flags.enable_exit_node);
        result.relay_all_peer_rpc = Some(flags.relay_all_peer_rpc);
        result.multi_thread = Some(flags.multi_thread);
        result.proxy_forward_by_system = Some(flags.proxy_forward_by_system);
        result.disable_encryption = Some(!flags.enable_encryption);
        result.disable_udp_hole_punching = Some(flags.disable_udp_hole_punching);
        result.disable_sym_hole_punching = Some(flags.disable_sym_hole_punching);
        result.enable_magic_dns = Some(flags.accept_dns);
        result.mtu = Some(flags.mtu as i32);
        result.enable_private_mode = Some(flags.private_mode);

        if !flags.relay_network_whitelist.is_empty() && flags.relay_network_whitelist != "*" {
            result.enable_relay_network_whitelist = Some(true);
            result.relay_network_whitelist = flags
                .relay_network_whitelist
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::config::ConfigLoader;
    use rand::Rng;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn gen_default_config() -> crate::common::config::TomlConfigLoader {
        let config = crate::common::config::TomlConfigLoader::default();
        config.set_id(uuid::Uuid::new_v4());
        config.set_dhcp(false);
        config.set_inst_name("default".to_string());
        config.set_listeners(vec![]);
        config
    }

    #[test]
    fn test_network_config_conversion_basic() -> Result<(), anyhow::Error> {
        let config = gen_default_config();

        let network_config = super::NetworkConfig::new_from_config(&config)?;

        let generated_config = network_config.gen_config()?;

        let config_str = config.dump();
        let generated_config_str = generated_config.dump();

        assert_eq!(
                config_str, generated_config_str,
                "Generated config does not match original config:\nOriginal:\n{}\n\nGenerated:\n{}\nNetwork Config: {}\n",
                config_str, generated_config_str, serde_json::to_string(&network_config).unwrap()
        );
        Ok(())
    }

    #[test]
    fn test_network_config_conversion_random() -> Result<(), anyhow::Error> {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let config = gen_default_config();

            config.set_id(uuid::Uuid::new_v4());

            config.set_dhcp(rng.gen_bool(0.5));

            if rng.gen_bool(0.7) {
                let hostname = format!("host-{}", rng.gen::<u16>());
                config.set_hostname(Some(hostname));
            }

            config.set_network_identity(crate::common::config::NetworkIdentity::new(
                format!("network-{}", rng.gen::<u16>()),
                format!("secret-{}", rng.gen::<u64>()),
            ));
            config.set_inst_name(config.get_network_identity().network_name.clone());

            if !config.get_dhcp() {
                let addr = Ipv4Addr::new(
                    rng.gen_range(1..254),
                    rng.gen_range(0..255),
                    rng.gen_range(0..255),
                    rng.gen_range(1..254),
                );
                let prefix_len = rng.gen_range(1..31);
                let ipv4 = format!("{}/{}", addr, prefix_len).parse().unwrap();
                config.set_ipv4(Some(ipv4));
            }

            let peer_count = rng.gen_range(0..3);
            let mut peers = Vec::new();
            for _ in 0..peer_count {
                let port = rng.gen_range(10000..60000);
                let protocol = if rng.gen_bool(0.5) { "tcp" } else { "udp" };
                let uri = format!("{}://127.0.0.1:{}", protocol, port)
                    .parse()
                    .unwrap();
                peers.push(crate::common::config::PeerConfig { uri });
            }
            config.set_peers(peers);

            if rng.gen_bool(0.7) {
                let listener_count = rng.gen_range(0..3);
                let mut listeners = Vec::new();
                for _ in 0..listener_count {
                    let port = rng.gen_range(10000..60000);
                    let protocol = if rng.gen_bool(0.5) { "tcp" } else { "udp" };
                    listeners.push(format!("{}://0.0.0.0:{}", protocol, port).parse().unwrap());
                }
                config.set_listeners(listeners);
            }

            if rng.gen_bool(0.6) {
                let proxy_count = rng.gen_range(0..3);
                for _ in 0..proxy_count {
                    let network = format!(
                        "{}.{}.{}.0/{}",
                        rng.gen_range(1..254),
                        rng.gen_range(0..255),
                        rng.gen_range(0..255),
                        rng.gen_range(24..30)
                    )
                    .parse::<cidr::Ipv4Cidr>()
                    .unwrap();

                    let mapped_network = if rng.gen_bool(0.5) {
                        Some(
                            format!(
                                "{}.{}.{}.0/{}",
                                rng.gen_range(1..254),
                                rng.gen_range(0..255),
                                rng.gen_range(0..255),
                                network.network_length()
                            )
                            .parse::<cidr::Ipv4Cidr>()
                            .unwrap(),
                        )
                    } else {
                        None
                    };
                    config.add_proxy_cidr(network, mapped_network).unwrap();
                }
            }

            if rng.gen_bool(0.5) {
                let vpn_network = format!(
                    "{}.{}.{}.0/{}",
                    rng.gen_range(10..173),
                    rng.gen_range(0..255),
                    rng.gen_range(0..255),
                    rng.gen_range(24..30)
                );
                let vpn_port = rng.gen_range(10000..60000);
                config.set_vpn_portal_config(crate::common::config::VpnPortalConfig {
                    client_cidr: vpn_network.parse().unwrap(),
                    wireguard_listen: format!("0.0.0.0:{}", vpn_port).parse().unwrap(),
                });
            }

            if rng.gen_bool(0.6) {
                let route_count = rng.gen_range(1..3);
                let mut routes = Vec::new();
                for _ in 0..route_count {
                    let route = format!(
                        "{}.{}.{}.0/{}",
                        rng.gen_range(1..254),
                        rng.gen_range(0..255),
                        rng.gen_range(0..255),
                        rng.gen_range(24..30)
                    );
                    routes.push(route.parse().unwrap());
                }
                config.set_routes(Some(routes));
            }

            if rng.gen_bool(0.4) {
                let node_count = rng.gen_range(1..3);
                let mut nodes = Vec::new();
                for _ in 0..node_count {
                    let ip = Ipv4Addr::new(
                        rng.gen_range(1..254),
                        rng.gen_range(0..255),
                        rng.gen_range(0..255),
                        rng.gen_range(1..254),
                    );
                    nodes.push(IpAddr::V4(ip));
                    // gen ipv6
                    let ip = Ipv6Addr::new(
                        rng.gen_range(0..65535),
                        rng.gen_range(0..65535),
                        rng.gen_range(0..65535),
                        rng.gen_range(0..65535),
                        rng.gen_range(0..65535),
                        rng.gen_range(0..65535),
                        rng.gen_range(0..65535),
                        rng.gen_range(0..65535),
                    );
                    nodes.push(IpAddr::V6(ip));
                }
                config.set_exit_nodes(nodes);
            }

            if rng.gen_bool(0.5) {
                let socks5_port = rng.gen_range(10000..60000);
                config.set_socks5_portal(Some(
                    format!("socks5://0.0.0.0:{}", socks5_port).parse().unwrap(),
                ));
            }

            if rng.gen_bool(0.4) {
                let count = rng.gen_range(1..3);
                let mut mapped_listeners = Vec::new();
                for _ in 0..count {
                    let port = rng.gen_range(10000..60000);
                    mapped_listeners.push(format!("tcp://0.0.0.0:{}", port).parse().unwrap());
                }
                config.set_mapped_listeners(Some(mapped_listeners));
            }

            if rng.gen_bool(0.9) {
                let mut flags = crate::common::config::gen_default_flags();
                flags.latency_first = rng.gen_bool(0.5);
                flags.dev_name = format!("etun{}", rng.gen_range(0..10));
                flags.use_smoltcp = rng.gen_bool(0.3);
                flags.enable_ipv6 = rng.gen_bool(0.8);
                flags.enable_kcp_proxy = rng.gen_bool(0.5);
                flags.disable_kcp_input = rng.gen_bool(0.3);
                flags.enable_quic_proxy = rng.gen_bool(0.5);
                flags.disable_quic_input = rng.gen_bool(0.3);
                flags.disable_p2p = rng.gen_bool(0.2);
                flags.p2p_only = rng.gen_bool(0.2);
                flags.bind_device = rng.gen_bool(0.3);
                flags.no_tun = rng.gen_bool(0.1);
                flags.enable_exit_node = rng.gen_bool(0.4);
                flags.relay_all_peer_rpc = rng.gen_bool(0.5);
                flags.multi_thread = rng.gen_bool(0.7);
                flags.proxy_forward_by_system = rng.gen_bool(0.3);
                flags.enable_encryption = rng.gen_bool(0.8);
                flags.disable_udp_hole_punching = rng.gen_bool(0.2);
                flags.accept_dns = rng.gen_bool(0.6);
                flags.mtu = rng.gen_range(1200..1500);
                flags.private_mode = rng.gen_bool(0.3);

                if rng.gen_bool(0.4) {
                    flags.relay_network_whitelist = (0..rng.gen_range(1..3))
                        .map(|_| {
                            format!(
                                "{}.{}.0.0/16",
                                rng.gen_range(10..192),
                                rng.gen_range(0..255)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(" ");
                }

                config.set_flags(flags);
            }

            let network_config = super::NetworkConfig::new_from_config(&config)?;
            let generated_config = network_config.gen_config()?;
            generated_config.set_peers(generated_config.get_peers()); // Ensure peers field is not None

            let config_str = config.dump();
            let generated_config_str = generated_config.dump();

            assert_eq!(
                config_str, generated_config_str,
                "Generated config does not match original config:\nOriginal:\n{}\n\nGenerated:\n{}\nNetwork Config: {}\n",
                config_str, generated_config_str, serde_json::to_string(&network_config).unwrap()
            );
        }

        Ok(())
    }
}
