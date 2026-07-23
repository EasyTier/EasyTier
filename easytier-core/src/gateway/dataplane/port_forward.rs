//! Port-forwarding facet of the gateway dataplane: TCP and UDP port-forward
//! listeners, the UDP client map, and the idle-entry reaper.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use crossbeam::atomic::AtomicCell;
use quanta::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

use tokio::{select, task::JoinSet};

use crate::{
    config::gateway::PortForwardConfig,
    gateway::{
        GatewayEvent,
        socks5::{AsyncTcpConnector, Socks5Entry},
    },
    socket::{
        tcp::{
            TcpListenOptions, TcpSocketPurpose, VirtualTcpListener, VirtualTcpListenerFactory,
            VirtualTcpSocket, VirtualTcpSocketFactory,
        },
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

use super::{
    GatewayEntryData, GatewayModule, GatewayTcpStream, GatewayUdpSocket, Socks5AutoConnector,
    UDP_ENTRY, UdpClientInfo, UdpClientKey,
};
use crate::foundation::task::reap_joinset_background;

impl<H> GatewayModule<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub(crate) async fn reload_port_forwards(
        &self,
        cfgs: &[PortForwardConfig],
    ) -> anyhow::Result<()> {
        if !self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        self.apply_port_forwards(cfgs).await
    }

    pub(super) async fn apply_port_forwards(
        &self,
        cfgs: &[PortForwardConfig],
    ) -> anyhow::Result<()> {
        // remove entries not in new cfg
        self.cancel_tokens.retain(|k, _| {
            cfgs.iter().any(|cfg| {
                if cfg.dst_addr.ip().is_unspecified() {
                    k.bind_addr == cfg.bind_addr && k.proto == cfg.proto
                } else {
                    k == cfg
                }
            })
        });
        // add new ones
        for cfg in cfgs {
            if !self.cancel_tokens.contains_key(cfg) {
                self.add_port_forward(cfg.clone()).await?;
            }
        }
        self.port_forward_list_change_notifier.notify_one();
        Ok(())
    }

    async fn handle_port_forward_connection<S>(
        mut incoming_socket: S,
        connector: Box<dyn AsyncTcpConnector<S = GatewayTcpStream> + Send>,
        dst_addr: SocketAddr,
    ) where
        S: VirtualTcpSocket,
    {
        tracing::trace!(?dst_addr, "port forward: connecting to destination");
        let outgoing_socket = match connector.tcp_connect(dst_addr, 10).await {
            Ok(socket) => socket,
            Err(e) => {
                tracing::error!("port forward: failed to connect to destination: {:?}", e);
                return;
            }
        };
        tracing::trace!(?dst_addr, "port forward: connected to destination");

        let mut outgoing_socket = outgoing_socket;
        match tokio::io::copy_bidirectional(&mut incoming_socket, &mut outgoing_socket).await {
            Ok((from_client, from_server)) => {
                tracing::info!(
                    "port forward connection finished: client->server: {} bytes, server->client: {} bytes",
                    from_client,
                    from_server
                );
            }
            Err(e) => {
                tracing::error!("port forward connection error: {:?}", e);
            }
        }
    }

    async fn add_port_forward(&self, cfg: PortForwardConfig) -> anyhow::Result<()> {
        match cfg.proto.to_lowercase().as_str() {
            "tcp" => {
                self.add_tcp_port_forward(&cfg).await?;
            }
            "udp" => {
                self.add_udp_port_forward(&cfg).await?;
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported protocol: {}, only support udp / tcp",
                    cfg.proto
                ));
            }
        }
        self.events.emit(GatewayEvent::PortForwardAdded(cfg));
        Ok(())
    }

    async fn add_tcp_port_forward(&self, cfg: &PortForwardConfig) -> anyhow::Result<()> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let options = TcpListenOptions::port_forward(bind_addr);
        let bind = options
            .bind
            .clone()
            .with_context(self.socket_context.clone());
        let listener = self.host.bind_tcp(options.with_bind(bind)).await?;

        let net = self.net.clone();
        let entries = self.entries.clone();
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        tokio::spawn(reap_joinset_background(tasks.clone(), "tcp port forward"));
        let forward_tasks = tasks;
        let transport_proxy = self.transport_proxy.clone();
        let peer_mgr = self.peer_manager.clone();
        let host = self.host.clone();
        let socket_context = self.socket_context.clone();
        let cancel_token = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel_token.clone().drop_guard());

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let (incoming_socket, addr) = select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        tracing::info!("port forward for {:?} cancelled", bind_addr);
                        break;
                    }
                    res = listener.accept() => {
                        match res {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::error!("port forward accept error = {:?}", err);
                                continue;
                            }
                        }
                    }
                };

                tracing::info!(
                    "port forward: accept new connection from {:?} to {:?}",
                    bind_addr,
                    dst_addr
                );

                let (smoltcp_net, net_ipv4) = {
                    let net_guard = net.lock().await;
                    (
                        net_guard.as_ref().map(|net| net.smoltcp_net.clone()),
                        net_guard.as_ref().map(|net| net.ipv4_addr),
                    )
                };
                tracing::trace!(
                    ?bind_addr,
                    ?dst_addr,
                    client_addr = ?addr,
                    has_smoltcp_net = smoltcp_net.is_some(),
                    ?net_ipv4,
                    entry_count = entries.count(),
                    entries_len = entries.len(),
                    "port forward: preparing connector"
                );

                let connector = Socks5AutoConnector {
                    transport_proxy: transport_proxy.clone(),
                    peer_mgr: peer_mgr.clone(),
                    entries: entries.clone(),
                    smoltcp_net,
                    src_addr: addr,
                    host: host.clone(),
                    socket_context: socket_context.clone(),
                    kernel_purpose: TcpSocketPurpose::PortForward,
                    inner_connector: parking_lot::Mutex::new(None),
                };

                forward_tasks
                    .lock()
                    .unwrap()
                    .spawn(Self::handle_port_forward_connection(
                        incoming_socket,
                        Box::new(connector),
                        dst_addr,
                    ));
            }
        });

        Ok(())
    }

    #[tracing::instrument(name = "add_udp_port_forward", skip(self))]
    async fn add_udp_port_forward(&self, cfg: &PortForwardConfig) -> anyhow::Result<()> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let socket = self
            .host
            .bind_udp(
                UdpBindOptions::port_forward(bind_addr).with_context(self.socket_context.clone()),
            )
            .await?;

        let entries = self.entries.clone();
        let net = self.net.clone();
        let host = self.host.clone();
        let socket_context = self.socket_context.clone();
        let udp_client_map = self.udp_client_map.clone();
        let udp_forward_task = self.udp_forward_task.clone();
        let cancel_token = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel_token.clone().drop_guard());

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                // we set the max buffer size of smoltcp to 8192, so we need to use a buffer size that is less than 8192 here.
                let mut buf = vec![0u8; 8192];
                let (len, addr) = select! {
                    biased;
                    _ = cancel_token.cancelled() => {
                        tracing::info!("udp port forward for {:?} cancelled", bind_addr);
                        break;
                    }
                    res = socket.recv_from(&mut buf) => {
                        match res {
                            Ok(result) => result,
                            Err(err) => {
                                tracing::error!("udp port forward recv error = {:?}", err);
                                continue;
                            }
                        }
                    }
                };

                tracing::trace!(
                    "udp port forward recv packet from {:?}, len = {}",
                    addr,
                    len
                );

                let udp_client_key = UdpClientKey {
                    client_addr: addr,
                    dst_addr,
                };

                let binded_socket = udp_client_map.get(&udp_client_key);
                let client_info = match binded_socket {
                    Some(s) => s.clone(),
                    None => {
                        // reserve a port so os will not use it to connect to the virtual network
                        let binded_socket = host
                            .bind_udp(
                                UdpBindOptions::port_lease("0.0.0.0:0".parse().unwrap())
                                    .with_context(socket_context.clone()),
                            )
                            .await;
                        let binded_socket = match binded_socket {
                            Ok(socket) => socket,
                            Err(error) => {
                                tracing::error!(?error, "udp port forward bind error");
                                continue;
                            }
                        };
                        let mut local_addr = binded_socket.local_addr().unwrap();
                        let Some(cur_ipv4) = net.lock().await.as_ref().map(|net| net.ipv4_addr) else {
                            continue;
                        };
                        local_addr.set_ip(cur_ipv4.address().into());

                        let entry_key = Socks5Entry {
                            src: local_addr,
                            dst: dst_addr,
                            kind: UDP_ENTRY,
                        };

                        tracing::debug!("udp port forward binded socket = {:?}, entry_key = {:?}", local_addr, entry_key);

                        let client_info = Arc::new(UdpClientInfo {
                            port_holder_socket: binded_socket,
                            local_addr,
                            last_active: AtomicCell::new(Instant::now()),
                            entry_key,
                        });
                        udp_client_map.insert(udp_client_key.clone(), client_info.clone());
                        client_info
                    }
                };

                client_info.last_active.store(Instant::now());

                let udp_socket = match entries.with_entry(&client_info.entry_key, |data| {
                    match data {
                        GatewayEntryData::Udp((socket, _)) => socket.clone(),
                        _ => panic!("udp entry data is not udp entry data"),
                    }
                }) {
                    Some(socket) => socket,
                    None => {
                        let guard = net.lock().await;
                        let Some(net) = guard.as_ref() else {
                            continue;
                        };
                        let local_addr = net.ipv4_addr;
                        let sokcs_udp = if dst_addr.ip() == local_addr.address() {
                            GatewayUdpSocket::Host(client_info.port_holder_socket.clone())
                        } else {
                            tracing::debug!("udp port forward bind new smol udp socket, {:?}", local_addr);
                            GatewayUdpSocket::SmolUdpSocket(
                                net.smoltcp_net
                                    .udp_bind(SocketAddr::new(
                                        IpAddr::V4(local_addr.address()),
                                        client_info.local_addr.port(),
                                    ))
                                    .await
                                    .unwrap(),
                            )
                        };
                        let socks_udp = Arc::new(sokcs_udp);
                        entries.insert(
                            client_info.entry_key.clone(),
                            GatewayEntryData::Udp((socks_udp.clone(), udp_client_key.clone())),
                        );

                        let socks = socket.clone();
                        let client_addr = addr;
                        udp_forward_task.insert(
                            udp_client_key.clone(),
                            AbortOnDropHandle::new(tokio::spawn(async move {
                                loop {
                                    let mut buf = vec![0u8; 8192];
                                    match socks_udp.recv_from(&mut buf).await {
                                        Ok((len, dst_addr)) => {
                                            tracing::trace!(
                                                "udp port forward recv response packet from {:?}, len = {}, client_addr = {:?}",
                                                dst_addr,
                                                len,
                                                client_addr
                                            );
                                            if let Err(e) = socks.send_to(&buf[..len], client_addr).await {
                                                tracing::error!("udp forward send error = {:?}", e);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!("udp forward recv error = {:?}", e);
                                        }
                                    }
                                }
                            })),
                        );

                        entries
                            .with_entry(&client_info.entry_key, |data| match data {
                                GatewayEntryData::Udp((socket, _)) => socket.clone(),
                                _ => panic!("udp entry data is not udp entry data"),
                            })
                            .unwrap()
                    }
                };

                if let Err(e) = udp_socket.send_to(&buf[..len], dst_addr).await {
                    tracing::error!(?dst_addr, ?len, "udp port forward send error = {:?}", e);
                } else {
                    tracing::trace!(?dst_addr, ?len, "udp port forward send packet success");
                }
            }
        });

        // clean up task
        let udp_client_map = self.udp_client_map.clone();
        let udp_forward_task = self.udp_forward_task.clone();
        let entries = self.entries.clone();
        let cancel_tokens = self.cancel_tokens.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = Instant::now();
                udp_client_map.retain(|_, client_info| {
                    now.duration_since(client_info.last_active.load()).as_secs() < 600
                });
                udp_forward_task.retain(|k, _| udp_client_map.contains_key(k));
                entries.retain(|_, data| match data {
                    GatewayEntryData::Udp((_, udp_client_key)) => {
                        udp_client_map.contains_key(udp_client_key)
                    }
                    _ => true,
                });

                udp_client_map.shrink_to_fit();
                udp_forward_task.shrink_to_fit();
                entries.shrink_to_fit();
                cancel_tokens.shrink_to_fit();
            }
        });

        Ok(())
    }
}
