use std::{
    collections::VecDeque,
    sync::{atomic::AtomicBool, Arc, RwLock},
};

use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        constants::EASYTIER_VERSION,
        global_ctx::GlobalCtxEvent,
        stun::StunInfoCollectorTrait,
    },
    instance::instance::Instance,
    peers::rpc_service::PeerManagerRpcService,
    proto::{
        cli::{PeerInfo, Route},
        common::StunInfo,
        peer_rpc::GetIpListResponse,
    },
    utils::{list_peer_route_pair, PeerRoutePair},
};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct MyNodeInfo {
    pub virtual_ipv4: String,
    pub hostname: String,
    pub version: String,
    pub ips: GetIpListResponse,
    pub stun_info: StunInfo,
    pub listeners: Vec<String>,
    pub vpn_portal_cfg: Option<String>,
}

#[derive(Default, Clone)]
struct EasyTierData {
    events: Arc<RwLock<VecDeque<(DateTime<Local>, GlobalCtxEvent)>>>,
    node_info: Arc<RwLock<MyNodeInfo>>,
    routes: Arc<RwLock<Vec<Route>>>,
    peers: Arc<RwLock<Vec<PeerInfo>>>,
    tun_fd: Arc<RwLock<Option<i32>>>,
    tun_dev_name: Arc<RwLock<String>>,
}

pub struct EasyTierLauncher {
    instance_alive: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
    running_cfg: String,

    error_msg: Arc<RwLock<Option<String>>>,
    data: EasyTierData,
}

impl EasyTierLauncher {
    pub fn new() -> Self {
        let instance_alive = Arc::new(AtomicBool::new(false));
        Self {
            instance_alive,
            thread_handle: None,
            error_msg: Arc::new(RwLock::new(None)),
            running_cfg: String::new(),

            stop_flag: Arc::new(AtomicBool::new(false)),
            data: EasyTierData::default(),
        }
    }

    async fn handle_easytier_event(event: GlobalCtxEvent, data: EasyTierData) {
        let mut events = data.events.write().unwrap();
        events.push_back((chrono::Local::now(), event));
        if events.len() > 100 {
            events.pop_front();
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
        data: EasyTierData,
    ) -> Result<(), anyhow::Error> {
        let mut instance = Instance::new(cfg);
        let peer_mgr = instance.get_peer_manager();

        let mut tasks = JoinSet::new();

        // Subscribe to global context events
        let global_ctx = instance.get_global_ctx();
        let data_c = data.clone();
        tasks.spawn(async move {
            let mut receiver = global_ctx.subscribe();
            while let Ok(event) = receiver.recv().await {
                Self::handle_easytier_event(event, data_c.clone()).await;
            }
        });

        // update my node info
        let data_c = data.clone();
        let global_ctx_c = instance.get_global_ctx();
        let peer_mgr_c = peer_mgr.clone();
        let vpn_portal = instance.get_vpn_portal_inst();
        tasks.spawn(async move {
            loop {

                // Update TUN Device Name
                *data_c.tun_dev_name.write().unwrap() = global_ctx_c.get_flags().dev_name.clone();

                let node_info = MyNodeInfo {
                    virtual_ipv4: global_ctx_c
                        .get_ipv4()
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                    hostname: global_ctx_c.get_hostname(),
                    version: EASYTIER_VERSION.to_string(),
                    ips: global_ctx_c.get_ip_collector().collect_ip_addrs().await,
                    stun_info: global_ctx_c.get_stun_info_collector().get_stun_info(),
                    listeners: global_ctx_c
                        .get_running_listeners()
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                    vpn_portal_cfg: Some(
                        vpn_portal
                            .lock()
                            .await
                            .dump_client_config(peer_mgr_c.clone())
                            .await,
                    ),
                };
                *data_c.node_info.write().unwrap() = node_info.clone();
                *data_c.routes.write().unwrap() = peer_mgr_c.list_routes().await;
                *data_c.peers.write().unwrap() = PeerManagerRpcService::new(peer_mgr_c.clone())
                    .list_peers()
                    .await;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        #[cfg(target_os = "android")]
        Self::run_routine_for_android(&instance, &data, &mut tasks).await;

        instance.run().await?;
        stop_signal.notified().await;

        tasks.abort_all();
        drop(tasks);

        Ok(())
    }

    pub fn start<F>(&mut self, cfg_generator: F)
    where
        F: FnOnce() -> Result<TomlConfigLoader, anyhow::Error> + Send + Sync,
    {
        let error_msg = self.error_msg.clone();
        let cfg = cfg_generator();
        if let Err(e) = cfg {
            error_msg.write().unwrap().replace(e.to_string());
            return;
        }

        self.running_cfg = cfg.as_ref().unwrap().dump();

        let stop_flag = self.stop_flag.clone();

        let instance_alive = self.instance_alive.clone();
        instance_alive.store(true, std::sync::atomic::Ordering::Relaxed);

        let data = self.data.clone();

        self.thread_handle = Some(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            let stop_notifier = Arc::new(tokio::sync::Notify::new());

            let stop_notifier_clone = stop_notifier.clone();
            rt.spawn(async move {
                while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                stop_notifier_clone.notify_one();
            });

            let ret = rt.block_on(Self::easytier_routine(
                cfg.unwrap(),
                stop_notifier.clone(),
                data,
            ));
            if let Err(e) = ret {
                error_msg.write().unwrap().replace(e.to_string());
            }
            instance_alive.store(false, std::sync::atomic::Ordering::Relaxed);
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

    pub fn get_events(&self) -> Vec<(DateTime<Local>, GlobalCtxEvent)> {
        let events = self.data.events.read().unwrap();
        events.iter().cloned().collect()
    }

    pub fn get_node_info(&self) -> MyNodeInfo {
        self.data.node_info.read().unwrap().clone()
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

#[derive(Deserialize, Serialize, Debug)]
pub struct NetworkInstanceRunningInfo {
    pub dev_name: String,
    pub my_node_info: MyNodeInfo,
    pub events: Vec<(DateTime<Local>, GlobalCtxEvent)>,
    pub node_info: MyNodeInfo,
    pub routes: Vec<Route>,
    pub peers: Vec<PeerInfo>,
    pub peer_route_pairs: Vec<PeerRoutePair>,
    pub running: bool,
    pub error_msg: Option<String>,
}

pub struct NetworkInstance {
    config: TomlConfigLoader,
    launcher: Option<EasyTierLauncher>,
}

impl NetworkInstance {
    pub fn new(config: TomlConfigLoader) -> Self {
        Self {
            config,
            launcher: None,
        }
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
            my_node_info: launcher.get_node_info(),
            events: launcher.get_events(),
            node_info: launcher.get_node_info(),
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

    pub fn start(&mut self) -> Result<(), anyhow::Error> {
        if self.is_easytier_running() {
            return Ok(());
        }

        let mut launcher = EasyTierLauncher::new();
        launcher.start(|| Ok(self.config.clone()));

        self.launcher = Some(launcher);
        Ok(())
    }
}
