use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc, RwLock},
};

use crate::{
    common::{
        config::{
            gen_default_flags, ConfigLoader, NetworkIdentity, PeerConfig, TomlConfigLoader,
            VpnPortalConfig,
        },
        constants::EASYTIER_VERSION,
        global_ctx::{EventBusSubscriber, GlobalCtxEvent},
        stun::StunInfoCollectorTrait,
    },
    instance::instance::Instance,
    peers::rpc_service::PeerManagerRpcService,
    proto::cli::{list_peer_route_pair, PeerInfo, Route},
};
use anyhow::Context;
use chrono::{DateTime, Local};
use tokio::{sync::broadcast, task::JoinSet};

pub type MyNodeInfo = crate::proto::web::MyNodeInfo;

#[derive(serde::Serialize, Clone)]
pub struct Event {
    time: DateTime<Local>,
    event: GlobalCtxEvent,
}

struct EasyTierData {
    events: RwLock<VecDeque<Event>>,
    my_node_info: RwLock<MyNodeInfo>,
    routes: RwLock<Vec<Route>>,
    peers: RwLock<Vec<PeerInfo>>,
    tun_fd: Arc<RwLock<Option<i32>>>,
    tun_dev_name: RwLock<String>,
    event_subscriber: RwLock<broadcast::Sender<GlobalCtxEvent>>,
    instance_stop_notifier: Arc<tokio::sync::Notify>,
}

impl Default for EasyTierData {
    fn default() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            event_subscriber: RwLock::new(tx),
            events: RwLock::new(VecDeque::new()),
            my_node_info: RwLock::new(MyNodeInfo::default()),
            routes: RwLock::new(Vec::new()),
            peers: RwLock::new(Vec::new()),
            tun_fd: Arc::new(RwLock::new(None)),
            tun_dev_name: RwLock::new(String::new()),
            instance_stop_notifier: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

pub struct EasyTierLauncher {
    instance_alive: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    running_cfg: String,
    fetch_node_info: bool,

    error_msg: Arc<RwLock<Option<String>>>,
    data: Arc<EasyTierData>,
}

impl EasyTierLauncher {
    pub fn new(fetch_node_info: bool) -> Self {
        let instance_alive = Arc::new(AtomicBool::new(false));
        Self {
            instance_alive,
            thread_handle: None,
            error_msg: Arc::new(RwLock::new(None)),
            running_cfg: String::new(),
            fetch_node_info,

            stop_flag: Arc::new(AtomicBool::new(false)),
            data: Arc::new(EasyTierData::default()),
        }
    }

    async fn handle_easytier_event(event: GlobalCtxEvent, data: &EasyTierData) {
        let mut events = data.events.write().unwrap();
        let _ = data.event_subscriber.read().unwrap().send(event.clone());
        events.push_front(Event {
            time: chrono::Local::now(),
            event: event,
        });
        if events.len() > 20 {
            events.pop_back();
        }
    }

    #[cfg(target_os = "android")]
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
        data: Arc<EasyTierData>,
        fetch_node_info: bool,
    ) -> Result<(), anyhow::Error> {
        let mut instance = Instance::new(cfg);
        let peer_mgr = instance.get_peer_manager();

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

        // update my node info
        if fetch_node_info {
            let data_c = data.clone();
            let global_ctx_c = instance.get_global_ctx();
            let peer_mgr_c = peer_mgr.clone();
            let vpn_portal = instance.get_vpn_portal_inst();
            tasks.spawn(async move {
                loop {
                    // Update TUN Device Name
                    *data_c.tun_dev_name.write().unwrap() =
                        global_ctx_c.get_flags().dev_name.clone();

                    let node_info = MyNodeInfo {
                        virtual_ipv4: global_ctx_c.get_ipv4().map(|ip| ip.into()),
                        hostname: global_ctx_c.get_hostname(),
                        version: EASYTIER_VERSION.to_string(),
                        ips: Some(global_ctx_c.get_ip_collector().collect_ip_addrs().await),
                        stun_info: Some(global_ctx_c.get_stun_info_collector().get_stun_info()),
                        listeners: global_ctx_c
                            .get_running_listeners()
                            .into_iter()
                            .map(Into::into)
                            .collect(),
                        vpn_portal_cfg: Some(
                            vpn_portal
                                .lock()
                                .await
                                .dump_client_config(peer_mgr_c.clone())
                                .await,
                        ),
                    };
                    *data_c.my_node_info.write().unwrap() = node_info.clone();
                    *data_c.routes.write().unwrap() = peer_mgr_c.list_routes().await;
                    *data_c.peers.write().unwrap() = PeerManagerRpcService::new(peer_mgr_c.clone())
                        .list_peers()
                        .await;
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
        }

        #[cfg(target_os = "android")]
        Self::run_routine_for_android(&instance, &data, &mut tasks).await;

        instance.run().await?;
        stop_signal.notified().await;

        tasks.abort_all();
        drop(tasks);

        Ok(())
    }

    fn check_tcp_available(port: u16) -> bool {
        let s = format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap();
        std::net::TcpListener::bind(s).is_ok()
    }

    fn select_proper_rpc_port(cfg: &TomlConfigLoader) {
        let Some(mut f) = cfg.get_rpc_portal() else {
            return;
        };

        if f.port() == 0 {
            for i in 15888..15900 {
                if Self::check_tcp_available(i) {
                    f.set_port(i);
                    cfg.set_rpc_portal(f);
                    break;
                }
            }
        }
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

        Self::select_proper_rpc_port(&cfg);

        let stop_flag = self.stop_flag.clone();

        let instance_alive = self.instance_alive.clone();
        instance_alive.store(true, std::sync::atomic::Ordering::Relaxed);

        let data = self.data.clone();
        let fetch_node_info = self.fetch_node_info;

        self.thread_handle = Some(std::thread::spawn(move || {
            let rt = if cfg.get_flags().multi_thread {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
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
                data,
                fetch_node_info,
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

    pub fn get_dev_name(&self) -> String {
        self.data.tun_dev_name.read().unwrap().clone()
    }

    pub fn get_events(&self) -> Vec<Event> {
        let events = self.data.events.read().unwrap();
        events.iter().cloned().collect()
    }

    pub fn get_node_info(&self) -> MyNodeInfo {
        self.data.my_node_info.read().unwrap().clone()
    }

    pub fn get_routes(&self) -> Vec<Route> {
        self.data.routes.read().unwrap().clone()
    }

    pub fn get_peers(&self) -> Vec<PeerInfo> {
        self.data.peers.read().unwrap().clone()
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

pub type NetworkInstanceRunningInfo = crate::proto::web::NetworkInstanceRunningInfo;

pub struct NetworkInstance {
    config: TomlConfigLoader,
    launcher: Option<EasyTierLauncher>,

    fetch_node_info: bool,
}

impl NetworkInstance {
    pub fn new(config: TomlConfigLoader) -> Self {
        Self {
            config,
            launcher: None,
            fetch_node_info: true,
        }
    }

    pub fn set_fetch_node_info(mut self, fetch_node_info: bool) -> Self {
        self.fetch_node_info = fetch_node_info;
        self
    }

    pub fn is_easytier_running(&self) -> bool {
        self.launcher.is_some() && self.launcher.as_ref().unwrap().running()
    }

    pub fn get_running_info(&self) -> Option<NetworkInstanceRunningInfo> {
        if self.launcher.is_none() {
            return None;
        }

        let launcher = self.launcher.as_ref().unwrap();

        let peers = launcher.get_peers();
        let routes = launcher.get_routes();
        let peer_route_pairs = list_peer_route_pair(peers.clone(), routes.clone());

        Some(NetworkInstanceRunningInfo {
            dev_name: launcher.get_dev_name(),
            my_node_info: Some(launcher.get_node_info()),
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
        })
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

        let launcher = EasyTierLauncher::new(self.fetch_node_info);
        self.launcher = Some(launcher);
        let ev = self.subscribe_event().unwrap();

        self.launcher
            .as_mut()
            .unwrap()
            .start(|| Ok(self.config.clone()));

        Ok(ev)
    }

    fn subscribe_event(&self) -> Option<broadcast::Receiver<GlobalCtxEvent>> {
        if let Some(launcher) = self.launcher.as_ref() {
            Some(launcher.data.event_subscriber.read().unwrap().subscribe())
        } else {
            None
        }
    }

    pub async fn wait(&self) -> Option<String> {
        if let Some(launcher) = self.launcher.as_ref() {
            launcher.data.instance_stop_notifier.notified().await;
            launcher.error_msg.read().unwrap().clone()
        } else {
            None
        }
    }
}

pub type NetworkingMethod = crate::proto::web::NetworkingMethod;
pub type NetworkConfig = crate::proto::web::NetworkConfig;

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
            if virtual_ipv4.len() > 0 {
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
            cfg.add_proxy_cidr(
                n.parse()
                    .with_context(|| format!("failed to parse proxy network: {}", n))?,
            );
        }

        cfg.set_rpc_portal(
            format!("0.0.0.0:{}", self.rpc_port.unwrap_or_default())
                .parse()
                .with_context(|| format!("failed to parse rpc portal port: {:?}", self.rpc_port))?,
        );

        if self.rpc_portal_whitelists.is_empty() {
            cfg.set_rpc_portal_whitelist(None);
        } else {
            cfg.set_rpc_portal_whitelist(Some(
                self.rpc_portal_whitelists
                    .iter()
                    .map(|s| {
                        s.parse()
                            .with_context(|| format!("failed to parse rpc portal whitelist: {}", s))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ));
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

        if self.exit_nodes.len() > 0 {
            let mut exit_nodes = Vec::<std::net::Ipv4Addr>::with_capacity(self.exit_nodes.len());
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

        if self.mapped_listeners.len() > 0 {
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

        if let Some(enable_kcp_proxy) = self.enable_kcp_proxy {
            flags.enable_kcp_proxy = enable_kcp_proxy;
        }

        if let Some(disable_kcp_input) = self.disable_kcp_input {
            flags.disable_kcp_input = disable_kcp_input;
        }

        if let Some(disable_p2p) = self.disable_p2p {
            flags.disable_p2p = disable_p2p;
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
            if self.relay_network_whitelist.len() > 0 {
                flags.relay_network_whitelist = self.relay_network_whitelist.join(" ");
            } else {
                flags.relay_network_whitelist = "".to_string();
            }
        }

        if let Some(disable_udp_hole_punching) = self.disable_udp_hole_punching {
            flags.disable_udp_hole_punching = disable_udp_hole_punching;
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

        cfg.set_flags(flags);
        Ok(cfg)
    }
}
