use std::{collections::BTreeMap, sync::Arc};

use dashmap::DashMap;

use crate::{
    common::{
        config::{ConfigLoader, TomlConfigLoader},
        global_ctx::{EventBusSubscriber, GlobalCtxEvent},
        scoped_task::ScopedTask,
    },
    launcher::{ConfigSource, NetworkInstance, NetworkInstanceRunningInfo},
    proto,
};

pub struct NetworkInstanceManager {
    instance_map: Arc<DashMap<uuid::Uuid, NetworkInstance>>,
    instance_stop_tasks: Arc<DashMap<uuid::Uuid, ScopedTask<()>>>,
    stop_check_notifier: Arc<tokio::sync::Notify>,
}

impl NetworkInstanceManager {
    pub fn new() -> Self {
        NetworkInstanceManager {
            instance_map: Arc::new(DashMap::new()),
            instance_stop_tasks: Arc::new(DashMap::new()),
            stop_check_notifier: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn start_instance_task(&self, instance_id: uuid::Uuid) -> Result<(), anyhow::Error> {
        let instance = self
            .instance_map
            .get(&instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {} not found", instance_id))?;

        let instance_stop_notifier = instance.get_stop_notifier();
        let instance_config_source = instance.get_config_source();
        let instance_event_receiver = match instance.get_config_source() {
            ConfigSource::Cli | ConfigSource::File => Some(instance.subscribe_event()),
            _ => None,
        };

        let instance_map = self.instance_map.clone();
        let instance_stop_tasks = self.instance_stop_tasks.clone();

        let stop_check_notifier = self.stop_check_notifier.clone();
        self.instance_stop_tasks.insert(
            instance_id,
            ScopedTask::from(tokio::spawn(async move {
                let Some(instance_stop_notifier) = instance_stop_notifier else {
                    return;
                };
                let _t = if let Some(event) = instance_event_receiver.flatten() {
                    Some(ScopedTask::from(handle_event(instance_id, event)))
                } else {
                    None
                };
                instance_stop_notifier.notified().await;
                if let Some(instance) = instance_map.get(&instance_id) {
                    if let Some(e) = instance.get_latest_error_msg() {
                        tracing::error!(?e, ?instance_id, "instance stopped with error");
                        eprintln!("instance {} stopped with error: {}", instance_id, e);
                    }
                }
                match instance_config_source {
                    ConfigSource::Cli | ConfigSource::File => {
                        instance_map.remove(&instance_id);
                    }
                    ConfigSource::Web | ConfigSource::GUI | ConfigSource::FFI => {}
                }
                instance_stop_tasks.remove(&instance_id);
                stop_check_notifier.notify_waiters();
            })),
        );
        Ok(())
    }

    pub fn run_network_instance(
        &self,
        cfg: TomlConfigLoader,
        source: ConfigSource,
    ) -> Result<(), anyhow::Error> {
        let instance_id = cfg.get_id();
        if self.instance_map.contains_key(&instance_id) {
            anyhow::bail!("instance {} already exists", instance_id);
        }

        let mut instance = NetworkInstance::new(cfg, source);
        instance.start()?;

        self.instance_map.insert(instance_id, instance);
        self.start_instance_task(instance_id)?;
        Ok(())
    }

    pub fn retain_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> Result<Vec<uuid::Uuid>, anyhow::Error> {
        self.instance_map.retain(|k, _| instance_ids.contains(k));
        Ok(self.list_network_instance_ids())
    }

    pub fn delete_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> Result<Vec<uuid::Uuid>, anyhow::Error> {
        self.instance_map.retain(|k, _| !instance_ids.contains(k));
        Ok(self.list_network_instance_ids())
    }

    pub fn collect_network_infos(
        &self,
    ) -> Result<BTreeMap<uuid::Uuid, NetworkInstanceRunningInfo>, anyhow::Error> {
        let mut ret = BTreeMap::new();
        for instance in self.instance_map.iter() {
            if let Some(info) = instance.get_running_info() {
                ret.insert(instance.key().clone(), info);
            }
        }
        Ok(ret)
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instance_map
            .iter()
            .map(|item| item.key().clone())
            .collect()
    }

    pub fn set_tun_fd(&self, instance_id: &uuid::Uuid, fd: i32) -> Result<(), anyhow::Error> {
        let mut instance = self
            .instance_map
            .get_mut(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance not found"))?;
        instance.set_tun_fd(fd);
        Ok(())
    }

    pub async fn wait(&self) {
        while self.instance_map.len() > 0 {
            self.stop_check_notifier.notified().await;
        }
    }
}

#[tracing::instrument]
fn handle_event(
    instance_id: uuid::Uuid,
    mut events: EventBusSubscriber,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Ok(e) = events.recv().await {
                match e {
                    GlobalCtxEvent::PeerAdded(p) => {
                        print_event(instance_id, format!("new peer added. peer_id: {}", p));
                    }

                    GlobalCtxEvent::PeerRemoved(p) => {
                        print_event(instance_id, format!("peer removed. peer_id: {}", p));
                    }

                    GlobalCtxEvent::PeerConnAdded(p) => {
                        print_event(
                            instance_id,
                            format!(
                                "new peer connection added. conn_info: {}",
                                peer_conn_info_to_string(p)
                            ),
                        );
                    }

                    GlobalCtxEvent::PeerConnRemoved(p) => {
                        print_event(
                            instance_id,
                            format!(
                                "peer connection removed. conn_info: {}",
                                peer_conn_info_to_string(p)
                            ),
                        );
                    }

                    GlobalCtxEvent::ListenerAddFailed(p, msg) => {
                        print_event(
                            instance_id,
                            format!("listener add failed. listener: {}, msg: {}", p, msg),
                        );
                    }

                    GlobalCtxEvent::ListenerAcceptFailed(p, msg) => {
                        print_event(
                            instance_id,
                            format!("listener accept failed. listener: {}, msg: {}", p, msg),
                        );
                    }

                    GlobalCtxEvent::ListenerAdded(p) => {
                        if p.scheme() == "ring" {
                            continue;
                        }
                        print_event(instance_id, format!("new listener added. listener: {}", p));
                    }

                    GlobalCtxEvent::ConnectionAccepted(local, remote) => {
                        print_event(
                            instance_id,
                            format!(
                                "new connection accepted. local: {}, remote: {}",
                                local, remote
                            ),
                        );
                    }

                    GlobalCtxEvent::ConnectionError(local, remote, err) => {
                        print_event(
                            instance_id,
                            format!(
                                "connection error. local: {}, remote: {}, err: {}",
                                local, remote, err
                            ),
                        );
                    }

                    GlobalCtxEvent::TunDeviceReady(dev) => {
                        print_event(instance_id, format!("tun device ready. dev: {}", dev));
                    }

                    GlobalCtxEvent::TunDeviceError(err) => {
                        print_event(instance_id, format!("tun device error. err: {}", err));
                    }

                    GlobalCtxEvent::Connecting(dst) => {
                        print_event(instance_id, format!("connecting to peer. dst: {}", dst));
                    }

                    GlobalCtxEvent::ConnectError(dst, ip_version, err) => {
                        print_event(
                            instance_id,
                            format!(
                                "connect to peer error. dst: {}, ip_version: {}, err: {}",
                                dst, ip_version, err
                            ),
                        );
                    }

                    GlobalCtxEvent::VpnPortalClientConnected(portal, client_addr) => {
                        print_event(
                            instance_id,
                            format!(
                                "vpn portal client connected. portal: {}, client_addr: {}",
                                portal, client_addr
                            ),
                        );
                    }

                    GlobalCtxEvent::VpnPortalClientDisconnected(portal, client_addr) => {
                        print_event(
                            instance_id,
                            format!(
                                "vpn portal client disconnected. portal: {}, client_addr: {}",
                                portal, client_addr
                            ),
                        );
                    }

                    GlobalCtxEvent::DhcpIpv4Changed(old, new) => {
                        print_event(
                            instance_id,
                            format!("dhcp ip changed. old: {:?}, new: {:?}", old, new),
                        );
                    }

                    GlobalCtxEvent::DhcpIpv4Conflicted(ip) => {
                        print_event(instance_id, format!("dhcp ip conflict. ip: {:?}", ip));
                    }

                    GlobalCtxEvent::PortForwardAdded(cfg) => {
                        print_event(
                            instance_id,
                            format!(
                                "port forward added. local: {}, remote: {}, proto: {}",
                                cfg.bind_addr.unwrap().to_string(),
                                cfg.dst_addr.unwrap().to_string(),
                                cfg.socket_type().as_str_name()
                            ),
                        );
                    }
                }
            } else {
                events = events.resubscribe();
            }
        }
    })
}

fn print_event(instance_id: uuid::Uuid, msg: String) {
    println!(
        "{}: [{}] {}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        instance_id,
        msg
    );
}

fn peer_conn_info_to_string(p: proto::cli::PeerConnInfo) -> String {
    format!(
        "my_peer_id: {}, dst_peer_id: {}, tunnel_info: {:?}",
        p.my_peer_id, p.peer_id, p.tunnel
    )
}
