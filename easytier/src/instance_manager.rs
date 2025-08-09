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

impl Default for NetworkInstanceManager {
    fn default() -> Self {
        Self::new()
    }
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

        match instance.get_config_source() {
            ConfigSource::FFI | ConfigSource::GUI => {
                // FFI and GUI have no tokio runtime, so we don't need to spawn a task
                return Ok(());
            }
            _ => {
                if tokio::runtime::Handle::try_current().is_err() {
                    return Err(anyhow::anyhow!(
                        "tokio runtime not found, cannot start instance task"
                    ));
                }
            }
        }

        let instance_stop_notifier = instance.get_stop_notifier();
        let instance_event_receiver = match instance.get_config_source() {
            ConfigSource::Cli | ConfigSource::File | ConfigSource::Web => {
                Some(instance.subscribe_event())
            }
            ConfigSource::GUI | ConfigSource::FFI => None,
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
                let _t = instance_event_receiver
                    .flatten()
                    .map(|event| ScopedTask::from(handle_event(instance_id, event)));
                instance_stop_notifier.notified().await;
                if let Some(instance) = instance_map.get(&instance_id) {
                    if let Some(e) = instance.get_latest_error_msg() {
                        tracing::error!(?e, ?instance_id, "instance stopped with error");
                        eprintln!("instance {} stopped with error: {}", instance_id, e);
                    }
                }
                stop_check_notifier.notify_one();
                instance_stop_tasks.remove(&instance_id);
            })),
        );
        Ok(())
    }

    pub fn run_network_instance(
        &self,
        cfg: TomlConfigLoader,
        source: ConfigSource,
    ) -> Result<uuid::Uuid, anyhow::Error> {
        let instance_id = cfg.get_id();
        if self.instance_map.contains_key(&instance_id) {
            anyhow::bail!("instance {} already exists", instance_id);
        }

        let mut instance = NetworkInstance::new(cfg, source);
        instance.start()?;

        self.instance_map.insert(instance_id, instance);
        self.start_instance_task(instance_id)?;
        Ok(instance_id)
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
                ret.insert(*instance.key(), info);
            }
        }
        Ok(ret)
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instance_map.iter().map(|item| *item.key()).collect()
    }

    pub fn get_network_instance_name(&self, instance_id: &uuid::Uuid) -> Option<String> {
        self.instance_map
            .get(instance_id)
            .map(|instance| instance.value().get_inst_name())
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
        while self
            .instance_map
            .iter()
            .any(|item| item.value().is_easytier_running())
        {
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
                                cfg.bind_addr.unwrap(),
                                cfg.dst_addr.unwrap(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn it_works() {
        let manager = NetworkInstanceManager::new();
        let cfg_str = r#"
            listeners = []
            "#;

        let port = crate::utils::find_free_tcp_port(10012..65534).expect("no free tcp port found");

        let instance_id1 = manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str)
                    .inspect(|c| {
                        c.set_listeners(vec![format!("tcp://0.0.0.0:{}", port).parse().unwrap()]);
                    })
                    .unwrap(),
                ConfigSource::Cli,
            )
            .unwrap();
        let instance_id2 = manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::File,
            )
            .unwrap();
        let instance_id3 = manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::GUI,
            )
            .unwrap();
        let instance_id4 = manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::Web,
            )
            .unwrap();
        let instance_id5 = manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::FFI,
            )
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await; // to make instance actually started

        assert!(!crate::utils::check_tcp_available(port));

        assert!(manager.instance_map.contains_key(&instance_id1));
        assert!(manager.instance_map.contains_key(&instance_id2));
        assert!(manager.instance_map.contains_key(&instance_id3));
        assert!(manager.instance_map.contains_key(&instance_id4));
        assert!(manager.instance_map.contains_key(&instance_id5));
        assert_eq!(manager.list_network_instance_ids().len(), 5);
        assert_eq!(manager.instance_stop_tasks.len(), 3); // FFI and GUI instance does not have a stop task

        manager
            .delete_network_instance(vec![instance_id3, instance_id4, instance_id5])
            .unwrap();
        assert!(!manager.instance_map.contains_key(&instance_id3));
        assert!(!manager.instance_map.contains_key(&instance_id4));
        assert!(!manager.instance_map.contains_key(&instance_id5));
        assert_eq!(manager.list_network_instance_ids().len(), 2);
    }

    #[test]
    #[serial_test::serial]
    fn test_no_tokio_runtime() {
        let manager = NetworkInstanceManager::new();
        let cfg_str = r#"
            listeners = []
            "#;

        let port = crate::utils::find_free_tcp_port(10012..65534).expect("no free tcp port found");

        assert!(manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::Cli,
            )
            .is_err());
        assert!(manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::File,
            )
            .is_err());
        assert!(manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str)
                    .inspect(|c| {
                        c.set_listeners(vec![format!("tcp://0.0.0.0:{}", port).parse().unwrap()]);
                    })
                    .unwrap(),
                ConfigSource::GUI,
            )
            .is_ok());
        assert!(manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::Web,
            )
            .is_err());
        assert!(manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str).unwrap(),
                ConfigSource::FFI,
            )
            .is_ok());

        std::thread::sleep(std::time::Duration::from_secs(1)); // wait instance actually started

        assert!(!crate::utils::check_tcp_available(port));

        assert_eq!(manager.list_network_instance_ids().len(), 5);
        assert_eq!(
            manager
                .instance_map
                .iter()
                .map(|item| item.is_easytier_running())
                .filter(|x| *x)
                .count(),
            5
        ); // stop tasks failed not affect instance running status
        assert_eq!(manager.instance_stop_tasks.len(), 0);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_single_instance_failed() {
        let free_tcp_port =
            crate::utils::find_free_tcp_port(10012..65534).expect("no free tcp port found");

        for config_source in [ConfigSource::Cli, ConfigSource::File] {
            let _port_holder =
                std::net::TcpListener::bind(format!("0.0.0.0:{}", free_tcp_port)).unwrap();

            let cfg_str = format!(
                r#"
            listeners = ["tcp://0.0.0.0:{}"]
            "#,
                free_tcp_port
            );

            let manager = NetworkInstanceManager::new();
            manager
                .run_network_instance(
                    TomlConfigLoader::new_from_str(cfg_str.as_str()).unwrap(),
                    config_source.clone(),
                )
                .unwrap();

            tokio::select! {
                _ = manager.wait() => {
                    assert_eq!(manager.list_network_instance_ids().len(), 1);
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    panic!("instance manager with single failed instance({:?}) should not running", config_source);
                }
            }
        }
        for config_source in [ConfigSource::Web, ConfigSource::GUI, ConfigSource::FFI] {
            let _port_holder =
                std::net::TcpListener::bind(format!("0.0.0.0:{}", free_tcp_port)).unwrap();

            let cfg_str = format!(
                r#"
            listeners = ["tcp://0.0.0.0:{}"]
            "#,
                free_tcp_port
            );

            let manager = NetworkInstanceManager::new();
            manager
                .run_network_instance(
                    TomlConfigLoader::new_from_str(cfg_str.as_str()).unwrap(),
                    config_source.clone(),
                )
                .unwrap();

            assert_eq!(manager.list_network_instance_ids().len(), 1);
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_multiple_instances_one_failed() {
        let free_tcp_port =
            crate::utils::find_free_tcp_port(10012..65534).expect("no free tcp port found");

        let manager = NetworkInstanceManager::new();
        let cfg_str = format!(
            r#"
            listeners = ["tcp://0.0.0.0:{}"]
            [flags]
            enable_ipv6 = false
            "#,
            free_tcp_port
        );

        manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str.as_str()).unwrap(),
                ConfigSource::Cli,
            )
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        manager
            .run_network_instance(
                TomlConfigLoader::new_from_str(cfg_str.as_str()).unwrap(),
                ConfigSource::Cli,
            )
            .unwrap();

        tokio::select! {
            _ = manager.wait() => {
                panic!("instance manager with multiple instances one failed should still running");
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                assert_eq!(manager.list_network_instance_ids().len(), 2);
            }
        }
    }
}
