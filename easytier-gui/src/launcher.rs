use std::{
    collections::VecDeque,
    sync::{atomic::AtomicBool, Arc, RwLock},
};

use chrono::{DateTime, Local};
use easytier::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        global_ctx::GlobalCtxEvent,
        stun::StunInfoCollectorTrait,
    },
    instance::instance::Instance,
    peers::rpc_service::PeerManagerRpcService,
    rpc::{
        cli::{PeerInfo, Route, StunInfo},
        peer::GetIpListResponse,
    },
};

#[derive(Default, Clone)]
pub struct MyNodeInfo {
    pub virtual_ipv4: String,
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

    async fn easytier_routine(
        cfg: TomlConfigLoader,
        stop_signal: Arc<tokio::sync::Notify>,
        data: EasyTierData,
    ) -> Result<(), anyhow::Error> {
        let mut instance = Instance::new(cfg);
        let peer_mgr = instance.get_peer_manager();

        // Subscribe to global context events
        let global_ctx = instance.get_global_ctx();
        let data_c = data.clone();
        tokio::spawn(async move {
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
        tokio::spawn(async move {
            loop {
                let node_info = MyNodeInfo {
                    virtual_ipv4: global_ctx_c
                        .get_ipv4()
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
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

        instance.run().await?;
        stop_signal.notified().await;
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

    pub fn running_cfg(&self) -> String {
        self.running_cfg.clone()
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
