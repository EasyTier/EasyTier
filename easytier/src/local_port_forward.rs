use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{bail, Context};
use tokio::io::copy_bidirectional;
use tokio::sync::Mutex;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::common::{
    config::LocalPortForwardRule,
    global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
};

struct BridgeTask {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

impl BridgeTask {
    fn new(cancel: CancellationToken, handle: JoinHandle<()>) -> Self {
        Self { cancel, handle }
    }

    async fn stop(self) {
        self.cancel.cancel();
        if let Err(err) = self.handle.await {
            tracing::debug!("bridge task join finished with error: {:?}", err);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LocalPortForwardRuntimeRule {
    proto: String,
    listen: SocketAddr,
    target: SocketAddr,
    listen_from_dhcp: bool,
}

impl LocalPortForwardRuntimeRule {
    fn from_rule(rule: &LocalPortForwardRule, listen: SocketAddr) -> Self {
        Self {
            proto: rule.proto.clone(),
            listen,
            target: rule.target,
            listen_from_dhcp: rule.listen_from_dhcp,
        }
    }

    fn to_event_rule(&self) -> LocalPortForwardRule {
        LocalPortForwardRule {
            proto: self.proto.clone(),
            listen: self.listen,
            target: self.target,
            listen_from_dhcp: self.listen_from_dhcp,
        }
    }
}

pub struct LocalPortForwarder {
    tasks: Arc<Mutex<HashMap<LocalPortForwardRuntimeRule, BridgeTask>>>,
    configured_rules: Arc<Mutex<Vec<LocalPortForwardRule>>>,
    dhcp_watch_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    global_ctx: ArcGlobalCtx,
}

impl LocalPortForwarder {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            configured_rules: Arc::new(Mutex::new(Vec::new())),
            dhcp_watch_task: Arc::new(Mutex::new(None)),
            global_ctx,
        }
    }

    pub async fn apply_rules(&self, rules: &[LocalPortForwardRule]) -> anyhow::Result<()> {
        {
            let mut guard = self.configured_rules.lock().await;
            *guard = rules.to_vec();
        }
        self.reconcile().await
    }

    pub async fn shutdown(&self) {
        if let Some(handle) = self.dhcp_watch_task.lock().await.take() {
            handle.abort();
            let _ = handle.await;
        }

        let mut guard = self.tasks.lock().await;
        let tasks: Vec<_> = guard.drain().map(|(_, task)| task).collect();
        drop(guard);

        for task in tasks {
            task.stop().await;
        }
    }

    pub async fn start_dhcp_watch(self: &Arc<Self>) {
        let mut guard = self.dhcp_watch_task.lock().await;
        if guard.is_some() {
            return;
        }
        let mut subscriber = self.global_ctx.subscribe();
        let this = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            loop {
                match subscriber.recv().await {
                    Ok(GlobalCtxEvent::DhcpIpv4Changed(_, _)) => {
                        if let Some(strong) = this.upgrade() {
                            if let Err(err) = strong.reconcile().await {
                                tracing::error!(
                                    "failed to refresh local port forward after DHCP change: {:?}",
                                    err
                                );
                            }
                        } else {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        });
        *guard = Some(handle);
    }

    async fn reconcile(&self) -> anyhow::Result<()> {
        let configured_rules = { self.configured_rules.lock().await.clone() };
        let resolved_rules = self.resolve_rules(&configured_rules)?;

        let mut guard = self.tasks.lock().await;
        let existing: HashSet<LocalPortForwardRuntimeRule> = guard.keys().cloned().collect();
        let desired: HashSet<LocalPortForwardRuntimeRule> =
            resolved_rules.iter().cloned().collect();

        let to_remove: Vec<LocalPortForwardRuntimeRule> =
            existing.difference(&desired).cloned().collect();
        let to_add: Vec<LocalPortForwardRuntimeRule> =
            desired.difference(&existing).cloned().collect();

        let mut tasks_to_stop = Vec::new();
        for rule in to_remove {
            if let Some(task) = guard.remove(&rule) {
                tasks_to_stop.push(task);
            }
        }
        drop(guard);

        for task in tasks_to_stop {
            task.stop().await;
        }

        for rule in to_add {
            let bridge_task = Self::spawn_bridge_task(rule.clone())
                .await
                .with_context(|| format!("failed to start local port forward for {:?}", rule))?;
            {
                let mut guard = self.tasks.lock().await;
                guard.insert(rule.clone(), bridge_task);
            }
            self.global_ctx
                .issue_event(GlobalCtxEvent::LocalPortForwardAdded(rule.to_event_rule()));
        }

        Ok(())
    }

    fn resolve_rules(
        &self,
        rules: &[LocalPortForwardRule],
    ) -> anyhow::Result<Vec<LocalPortForwardRuntimeRule>> {
        let mut resolved = Vec::with_capacity(rules.len());
        let mut waiting_for_dhcp = false;

        for rule in rules {
            if rule.listen_from_dhcp {
                if let Some(ipv4) = self.global_ctx.get_ipv4() {
                    let listen = SocketAddr::new(IpAddr::V4(ipv4.address()), rule.listen.port());
                    resolved.push(LocalPortForwardRuntimeRule::from_rule(rule, listen));
                } else {
                    waiting_for_dhcp = true;
                }
            } else {
                resolved.push(LocalPortForwardRuntimeRule::from_rule(rule, rule.listen));
            }
        }

        if waiting_for_dhcp {
            tracing::debug!("local port forward rules waiting for DHCP IPv4 assignment");
        }

        Ok(resolved)
    }

    async fn spawn_bridge_task(rule: LocalPortForwardRuntimeRule) -> anyhow::Result<BridgeTask> {
        match rule.proto.as_str() {
            "tcp" => Self::spawn_tcp_bridge_task(rule).await,
            "udp" => Self::spawn_udp_bridge_task(rule).await,
            other => bail!("unsupported local port forward protocol: {}", other),
        }
    }

    async fn spawn_tcp_bridge_task(
        rule: LocalPortForwardRuntimeRule,
    ) -> anyhow::Result<BridgeTask> {
        let listen = rule.listen;
        let target = rule.target;

        let listener = TcpListener::bind(listen)
            .await
            .with_context(|| format!("failed to bind local port forward (tcp) {}", listen))?;
        tracing::info!(
            "local port forward (tcp) listening on {}, targeting {}",
            listen,
            target
        );

        let cancel = CancellationToken::new();
        let cancel_token = cancel.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        tracing::info!("local port forward (tcp) on {} shutting down", listen);
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((inbound, remote_addr)) => {
                                tracing::debug!(
                                    "local port forward (tcp) accepted connection from {} on {}, forwarding to {}",
                                    remote_addr,
                                    listen,
                                    target
                                );
                                Self::spawn_tcp_connection_handler(inbound, target);
                            }
                            Err(err) => {
                                tracing::error!(
                                    "local port forward (tcp) accept error on {}: {:?}",
                                    listen,
                                    err
                                );
                            }
                        }
                    }
                }
            }
        });

        Ok(BridgeTask::new(cancel, handle))
    }

    async fn spawn_udp_bridge_task(
        rule: LocalPortForwardRuntimeRule,
    ) -> anyhow::Result<BridgeTask> {
        let listen = rule.listen;
        let target = rule.target;

        let socket = Arc::new(
            UdpSocket::bind(listen)
                .await
                .with_context(|| format!("failed to bind local port forward (udp) {}", listen))?,
        );
        tracing::info!(
            "local port forward (udp) listening on {}, targeting {}",
            listen,
            target
        );

        let clients: Arc<Mutex<HashMap<SocketAddr, UdpClientEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let cancel = CancellationToken::new();
        let cancel_token = cancel.clone();
        let socket_clone = socket.clone();
        let clients_clone = clients.clone();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        break;
                    }
                    recv_res = socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, src_addr)) => {
                                if let Err(err) = Self::handle_udp_datagram(
                                    &socket_clone,
                                    &clients_clone,
                                    &cancel_token,
                                    listen,
                                    target,
                                    src_addr,
                                    &buf[..len],
                                ).await {
                                    tracing::error!("local port forward (udp) handling error: {:?}", err);
                                }
                            }
                            Err(err) => {
                                tracing::error!("local port forward (udp) recv error on {}: {:?}", listen, err);
                            }
                        }
                    }
                }
            }

            // cleanup client tasks
            let mut guard = clients_clone.lock().await;
            for (_, entry) in guard.drain() {
                entry.cancel.cancel();
                let _ = entry.handle.await;
            }
        });

        Ok(BridgeTask::new(cancel, handle))
    }

    async fn handle_udp_datagram(
        listener: &Arc<UdpSocket>,
        clients: &Arc<Mutex<HashMap<SocketAddr, UdpClientEntry>>>,
        cancel: &CancellationToken,
        listen_addr: SocketAddr,
        target_addr: SocketAddr,
        src_addr: SocketAddr,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let outbound_socket = {
            let mut guard = clients.lock().await;
            if let Some(entry) = guard.get(&src_addr) {
                entry.socket.clone()
            } else {
                let outbound = Arc::new(
                    UdpSocket::bind(unspecified_addr(listen_addr.ip()))
                        .await
                        .with_context(|| {
                            format!("failed to bind udp client socket for {}", src_addr)
                        })?,
                );
                outbound.connect(target_addr).await.with_context(|| {
                    format!(
                        "local port forward (udp) failed to connect to {}",
                        target_addr
                    )
                })?;

                let client_cancel = CancellationToken::new();
                let listener_clone = listener.clone();
                let cancel_clone = cancel.clone();
                let client_cancel_clone = client_cancel.clone();
                let outbound_clone = outbound.clone();
                let client_addr = src_addr;
                let handle = tokio::spawn(async move {
                    let mut buf = vec![0u8; 65_536];
                    loop {
                        tokio::select! {
                            _ = cancel_clone.cancelled() => break,
                            _ = client_cancel_clone.cancelled() => break,
                            recv_res = outbound_clone.recv(&mut buf) => {
                                match recv_res {
                                    Ok(len) => {
                                        if let Err(err) = listener_clone.send_to(&buf[..len], client_addr).await {
                                            tracing::debug!(
                                                "local port forward (udp) failed to send back to {}: {:?}",
                                                client_addr,
                                                err
                                            );
                                            break;
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!("local port forward (udp) outbound recv error: {:?}", err);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });

                guard.insert(
                    src_addr,
                    UdpClientEntry {
                        socket: outbound.clone(),
                        cancel: client_cancel,
                        handle,
                    },
                );
                outbound
            }
        };

        if let Err(err) = outbound_socket.send(payload).await {
            tracing::debug!(
                "local port forward (udp) failed to forward packet from {} to {}: {:?}",
                src_addr,
                target_addr,
                err
            );
        }
        Ok(())
    }

    fn spawn_tcp_connection_handler(mut inbound: TcpStream, target: SocketAddr) {
        tokio::spawn(async move {
            match TcpStream::connect(target).await {
                Ok(mut outbound) => {
                    if let Err(err) = copy_bidirectional(&mut inbound, &mut outbound).await {
                        tracing::debug!(
                            "local port forward (tcp) connection error ({:?} -> {}): {:?}",
                            inbound.peer_addr().ok(),
                            target,
                            err
                        );
                    }
                }
                Err(err) => {
                    tracing::error!(
                        "local port forward (tcp) failed to connect to {}: {:?}",
                        target,
                        err
                    );
                }
            }
        });
    }
}

struct UdpClientEntry {
    socket: Arc<UdpSocket>,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

fn unspecified_addr(ip: IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}
