use std::{
    collections::{BTreeSet, HashMap},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Weak},
};

use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use tokio::{
    sync::{Mutex, Notify, RwLock, mpsc},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    common::{
        config::ConfigLoader,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        netns::NetNS,
    },
    instance::{
        proxy_cidrs_monitor::ProxyCidrsMonitor,
        virtual_nic::{NicCtx, VirtualNic},
    },
    peers::{PacketRecvChanReceiver, peer_manager::PeerManager, recv_packet_from_chan},
    tunnel::{Tunnel, packet_def::ZCPacket},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SharedTunAccess {
    Native,
    #[cfg(mobile)]
    MobileFd(i32),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct SharedTunKey {
    netns: Option<String>,
    access: SharedTunAccess,
}

impl SharedTunKey {
    fn new(netns: &NetNS, access: SharedTunAccess) -> Self {
        Self {
            netns: netns.name(),
            access,
        }
    }
}

pub struct SharedTunAttach {
    pub handle: SharedTunMemberHandle,
    pub ifname: String,
}

pub enum SharedTunAttachError {
    Fallback(String),
    Fatal(Error),
}

impl From<Error> for SharedTunAttachError {
    fn from(value: Error) -> Self {
        Self::Fatal(value)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MemberClaims {
    ipv4: Option<cidr::Ipv4Inet>,
    ipv6: Option<cidr::Ipv6Inet>,
    owned_proxy_v4_routes: BTreeSet<cidr::Ipv4Cidr>,
    proxy_v4_routes: BTreeSet<cidr::Ipv4Cidr>,
    effective_mtu: u16,
    default_route_v4: bool,
    default_route_v6: bool,
}

impl MemberClaims {
    fn local_v4_prefix(&self) -> Option<cidr::Ipv4Cidr> {
        self.ipv4.map(|ipv4| ipv4.network())
    }

    fn shared_route_v4_prefixes(&self) -> BTreeSet<cidr::Ipv4Cidr> {
        let mut ret = self.owned_proxy_v4_routes.clone();
        if self.default_route_v4 {
            ret.insert(cidr::Ipv4Cidr::new(Ipv4Addr::UNSPECIFIED, 0).unwrap());
        }
        ret
    }

    fn reachable_v4_prefixes(&self) -> BTreeSet<cidr::Ipv4Cidr> {
        let mut ret = self.proxy_v4_routes.clone();
        if self.default_route_v4 {
            ret.insert(cidr::Ipv4Cidr::new(Ipv4Addr::UNSPECIFIED, 0).unwrap());
        }
        ret
    }

    fn dispatch_v4_prefixes(&self) -> BTreeSet<cidr::Ipv4Cidr> {
        let mut ret = self.shared_route_v4_prefixes();
        if let Some(prefix) = self.local_v4_prefix() {
            ret.insert(prefix);
        }
        ret
    }

    fn local_v6_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        self.ipv6.map(|ipv6| ipv6.network())
    }

    fn shared_route_v6_prefixes(&self) -> BTreeSet<cidr::Ipv6Cidr> {
        let mut ret = BTreeSet::new();
        if self.default_route_v6 {
            ret.insert(cidr::Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0).unwrap());
        }
        ret
    }

    fn dispatch_v6_prefixes(&self) -> BTreeSet<cidr::Ipv6Cidr> {
        let mut ret = self.shared_route_v6_prefixes();
        if let Some(prefix) = self.local_v6_prefix() {
            ret.insert(prefix);
        }
        ret
    }
}

#[derive(Clone)]
struct MemberRuntimeContext {
    device: Arc<SharedTunDevice>,
    slot: Arc<SharedTunMemberSlot>,
    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AppliedConfig {
    ipv4_addrs: BTreeSet<(Ipv4Addr, u8)>,
    ipv6_addrs: BTreeSet<(Ipv6Addr, u8)>,
    ipv4_routes: BTreeSet<cidr::Ipv4Cidr>,
    ipv6_routes: BTreeSet<cidr::Ipv6Cidr>,
    mtu: Option<u16>,
}

struct SharedTunMemberSlot {
    instance_id: uuid::Uuid,
    global_ctx: ArcGlobalCtx,
    peer_manager: Weak<PeerManager>,
    claims: RwLock<MemberClaims>,
    close_notifier: Arc<Notify>,
}

struct SharedTunDevice {
    key: SharedTunKey,
    nic: Arc<Mutex<VirtualNic>>,
    ifname: String,
    writer_tx: mpsc::Sender<ZCPacket>,
    members: RwLock<HashMap<uuid::Uuid, Arc<SharedTunMemberSlot>>>,
    current_config: Mutex<AppliedConfig>,
    cancel: CancellationToken,
    tasks: Mutex<JoinSet<()>>,
}

pub struct SharedTunMemberHandle {
    device: Arc<SharedTunDevice>,
    member_id: uuid::Uuid,
    cancel: CancellationToken,
    tasks: JoinSet<()>,
    shutdown: bool,
}

static SHARED_TUN_REGISTRY: Lazy<SharedTunRegistry> = Lazy::new(SharedTunRegistry::default);

#[derive(Default)]
struct SharedTunRegistry {
    devices: Mutex<HashMap<SharedTunKey, Arc<SharedTunDevice>>>,
}

struct SharedTunAttachRequest {
    key: SharedTunKey,
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    close_notifier: Arc<Notify>,
    claims: MemberClaims,
    access: SharedTunAccess,
}

pub async fn try_attach_shared_tun(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
    close_notifier: Arc<Notify>,
    access: SharedTunAccess,
) -> Result<SharedTunAttach, SharedTunAttachError> {
    if global_ctx.config.get_flags().no_tun {
        return Err(SharedTunAttachError::Fallback(
            "shared tun is disabled when no_tun is enabled".to_owned(),
        ));
    }

    let proxy_v4_routes =
        ProxyCidrsMonitor::diff_proxy_cidrs(peer_manager.as_ref(), &global_ctx, &BTreeSet::new())
            .await
            .0;
    let claims = build_member_claims(&global_ctx, proxy_v4_routes);
    let key = SharedTunKey::new(&global_ctx.net_ns, access.clone());

    SHARED_TUN_REGISTRY
        .attach(SharedTunAttachRequest {
            global_ctx,
            peer_manager,
            peer_packet_receiver,
            close_notifier,
            key,
            claims,
            access,
        })
        .await
}

impl SharedTunRegistry {
    async fn attach(
        &self,
        request: SharedTunAttachRequest,
    ) -> Result<SharedTunAttach, SharedTunAttachError> {
        let SharedTunAttachRequest {
            key,
            global_ctx,
            peer_manager,
            peer_packet_receiver,
            close_notifier,
            claims,
            access,
        } = request;

        let device = {
            let mut devices = self.devices.lock().await;
            if let Some(device) = devices.get(&key) {
                device.clone()
            } else {
                let device = SharedTunDevice::new(key.clone(), global_ctx.clone(), access)
                    .await
                    .map_err(SharedTunAttachError::Fatal)?;
                devices.insert(key.clone(), device.clone());
                device
            }
        };

        let handle = match device
            .attach_member(
                global_ctx.clone(),
                peer_manager,
                peer_packet_receiver,
                close_notifier,
                claims,
            )
            .await
        {
            Ok(handle) => handle,
            Err(err) => return Err(SharedTunAttachError::Fallback(err)),
        };

        Ok(SharedTunAttach {
            handle,
            ifname: device.ifname.clone(),
        })
    }

    async fn remove_if_unused(&self, key: &SharedTunKey, device: &Arc<SharedTunDevice>) {
        let should_shutdown = {
            let mut devices = self.devices.lock().await;
            if let Some(existing) = devices.get(key)
                && Arc::ptr_eq(existing, device)
                && device.member_count().await == 0
            {
                devices.remove(key);
                true
            } else {
                false
            }
        };

        if should_shutdown {
            device.shutdown().await;
        }
    }
}

impl SharedTunDevice {
    async fn new(
        key: SharedTunKey,
        global_ctx: ArcGlobalCtx,
        access: SharedTunAccess,
    ) -> Result<Arc<Self>, Error> {
        let mut nic = VirtualNic::new(global_ctx);
        let tunnel = match access {
            SharedTunAccess::Native => nic.create_dev().await?,
            #[cfg(mobile)]
            SharedTunAccess::MobileFd(fd) => nic.create_dev_for_mobile(fd).await?,
        };

        let ifname = nic.ifname().to_owned();
        let (stream, sink) = tunnel.split();
        let (writer_tx, writer_rx) = mpsc::channel(256);

        let device = Arc::new(Self {
            key,
            nic: Arc::new(Mutex::new(nic)),
            ifname,
            writer_tx,
            members: RwLock::new(HashMap::new()),
            current_config: Mutex::new(AppliedConfig::default()),
            cancel: CancellationToken::new(),
            tasks: Mutex::new(JoinSet::new()),
        });
        device.start_runtime_tasks(stream, sink, writer_rx).await;
        Ok(device)
    }

    async fn start_runtime_tasks(
        self: &Arc<Self>,
        mut stream: std::pin::Pin<Box<dyn crate::tunnel::ZCPacketStream>>,
        mut sink: std::pin::Pin<Box<dyn crate::tunnel::ZCPacketSink>>,
        mut writer_rx: mpsc::Receiver<ZCPacket>,
    ) {
        let cancel = self.cancel.clone();
        let reader_device = self.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    item = stream.next() => {
                        let Some(item) = item else {
                            reader_device.fail_all_members("shared tun reader closed").await;
                            break;
                        };

                        match item {
                            Ok(packet) => reader_device.dispatch_packet(packet).await,
                            Err(err) => {
                                tracing::error!(?err, "shared tun reader error");
                                reader_device.fail_all_members("shared tun reader error").await;
                                break;
                            }
                        }
                    }
                }
            }
        });

        let cancel = self.cancel.clone();
        let writer_device = self.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    packet = writer_rx.recv() => {
                        let Some(packet) = packet else {
                            break;
                        };
                        if let Err(err) = sink.send(packet).await {
                            tracing::error!(?err, "shared tun writer error");
                            writer_device.fail_all_members("shared tun writer error").await;
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn attach_member(
        self: &Arc<Self>,
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        close_notifier: Arc<Notify>,
        claims: MemberClaims,
    ) -> Result<SharedTunMemberHandle, String> {
        let dev_name = global_ctx.get_flags().dev_name;
        if !dev_name.is_empty() && dev_name != self.ifname {
            return Err(format!(
                "shared tun device {} does not match requested dev_name {}",
                self.ifname, dev_name
            ));
        }

        self.validate_claims(global_ctx.get_id(), &claims).await?;

        let slot = Arc::new(SharedTunMemberSlot {
            instance_id: global_ctx.get_id(),
            global_ctx: global_ctx.clone(),
            peer_manager: Arc::downgrade(&peer_manager),
            claims: RwLock::new(claims),
            close_notifier,
        });
        self.members
            .write()
            .await
            .insert(slot.instance_id, slot.clone());

        if let Err(err) = self.apply_config().await {
            self.members.write().await.remove(&slot.instance_id);
            return Err(format!("failed to apply shared tun config: {err}"));
        }

        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let runtime_ctx = MemberRuntimeContext {
            device: self.clone(),
            slot: slot.clone(),
            peer_packet_receiver,
        };
        self.spawn_peer_to_tun_task(&mut tasks, runtime_ctx.clone(), cancel.clone());
        self.spawn_member_refresh_task(&mut tasks, runtime_ctx, global_ctx, cancel.clone());

        Ok(SharedTunMemberHandle {
            device: self.clone(),
            member_id: slot.instance_id,
            cancel,
            tasks,
            shutdown: false,
        })
    }

    async fn update_member_claims(
        &self,
        member_id: uuid::Uuid,
        claims: MemberClaims,
    ) -> Result<(), String> {
        self.validate_claims(member_id, &claims).await?;
        let slot = {
            let members = self.members.read().await;
            members.get(&member_id).cloned()
        }
        .ok_or_else(|| format!("shared tun member {} not found", member_id))?;
        *slot.claims.write().await = claims;
        self.apply_config()
            .await
            .map_err(|err| format!("failed to apply shared tun config: {err}"))?;
        Ok(())
    }

    fn spawn_peer_to_tun_task(
        &self,
        tasks: &mut JoinSet<()>,
        runtime_ctx: MemberRuntimeContext,
        member_cancel: CancellationToken,
    ) {
        let writer_tx = self.writer_tx.clone();
        let device_cancel = self.cancel.clone();
        tasks.spawn(async move {
            let mut packet_recv = runtime_ctx.peer_packet_receiver.lock().await;
            loop {
                tokio::select! {
                    _ = device_cancel.cancelled() => break,
                    _ = member_cancel.cancelled() => break,
                    packet = recv_packet_from_chan(&mut packet_recv) => {
                        let Ok(packet) = packet else {
                            break;
                        };
                        if writer_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }

    fn spawn_member_refresh_task(
        &self,
        tasks: &mut JoinSet<()>,
        runtime_ctx: MemberRuntimeContext,
        global_ctx: ArcGlobalCtx,
        member_cancel: CancellationToken,
    ) {
        let device_cancel = self.cancel.clone();
        tasks.spawn(async move {
            let mut event_receiver = global_ctx.subscribe();
            let mut cur_proxy_cidrs = runtime_ctx.slot.claims.read().await.proxy_v4_routes.clone();

            loop {
                tokio::select! {
                    _ = device_cancel.cancelled() => break,
                    _ = member_cancel.cancelled() => break,
                    event = event_receiver.recv() => {
                        let Some(event) = handle_member_event(&mut event_receiver, event) else {
                            break;
                        };

                        if !should_refresh_member_claims(&event) {
                            continue;
                        }

                        let Some(peer_manager) = runtime_ctx.slot.peer_manager.upgrade() else {
                            break;
                        };
                        let (new_proxy_cidrs, _, _) = ProxyCidrsMonitor::diff_proxy_cidrs(
                            peer_manager.as_ref(),
                            &runtime_ctx.slot.global_ctx,
                            &cur_proxy_cidrs,
                        )
                        .await;
                        cur_proxy_cidrs = new_proxy_cidrs.clone();

                        let claims = build_member_claims(&runtime_ctx.slot.global_ctx, new_proxy_cidrs);
                        if let Err(err) = runtime_ctx
                            .device
                            .update_member_claims(runtime_ctx.slot.instance_id, claims)
                            .await
                        {
                            tracing::warn!(instance_id = %runtime_ctx.slot.instance_id, %err, "shared tun member update failed");
                            runtime_ctx
                                .slot
                                .global_ctx
                                .issue_event(GlobalCtxEvent::TunDeviceFallback(err.clone()));
                            runtime_ctx.slot.close_notifier.notify_one();
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn validate_claims(
        &self,
        member_id: uuid::Uuid,
        claims: &MemberClaims,
    ) -> Result<(), String> {
        let others = {
            let members = self.members.read().await;
            members
                .iter()
                .filter(|(id, _)| **id != member_id)
                .map(|(_, slot)| slot.clone())
                .collect::<Vec<_>>()
        };

        for other in others {
            let other_claims = other.claims.read().await.clone();
            if let (Some(left), Some(right)) = (claims.ipv4, other_claims.ipv4)
                && left.address() == right.address()
            {
                return Err(format!(
                    "shared tun conflict: duplicated IPv4 address {}",
                    left.address()
                ));
            }
            if let (Some(left), Some(right)) = (claims.ipv6, other_claims.ipv6)
                && left.address() == right.address()
            {
                return Err(format!(
                    "shared tun conflict: duplicated IPv6 address {}",
                    left.address()
                ));
            }

            for prefix in claims.shared_route_v4_prefixes() {
                if other_claims.dispatch_v4_prefixes().contains(&prefix) {
                    return Err(format!(
                        "shared tun conflict: duplicated IPv4 route prefix {}",
                        prefix
                    ));
                }
            }
            if let Some(prefix) = claims.local_v4_prefix()
                && other_claims.shared_route_v4_prefixes().contains(&prefix)
            {
                return Err(format!(
                    "shared tun conflict: duplicated IPv4 route prefix {}",
                    prefix
                ));
            }

            for prefix in claims.shared_route_v6_prefixes() {
                if other_claims.dispatch_v6_prefixes().contains(&prefix) {
                    return Err(format!(
                        "shared tun conflict: duplicated IPv6 route prefix {}",
                        prefix
                    ));
                }
            }
            if let Some(prefix) = claims.local_v6_prefix()
                && other_claims.shared_route_v6_prefixes().contains(&prefix)
            {
                return Err(format!(
                    "shared tun conflict: duplicated IPv6 route prefix {}",
                    prefix
                ));
            }
        }

        Ok(())
    }

    async fn dispatch_packet(&self, packet: ZCPacket) {
        let owner = self.select_owner(&packet).await;
        let Some(slot) = owner else {
            tracing::trace!("shared tun dropped packet without owner");
            return;
        };
        let Some(peer_manager) = slot.peer_manager.upgrade() else {
            tracing::trace!(instance_id = %slot.instance_id, "shared tun owner peer manager dropped");
            return;
        };

        NicCtx::forward_nic_packet_to_peers(packet, peer_manager.as_ref()).await;
    }

    async fn select_owner(&self, packet: &ZCPacket) -> Option<Arc<SharedTunMemberSlot>> {
        let members = {
            let members = self.members.read().await;
            members.values().cloned().collect::<Vec<_>>()
        };

        let payload = packet.payload();
        if payload.is_empty() {
            return None;
        }

        match payload[0] >> 4 {
            4 => self.select_owner_ipv4(payload, members).await,
            6 => self.select_owner_ipv6(payload, members).await,
            _ => None,
        }
    }

    async fn select_owner_ipv4(
        &self,
        payload: &[u8],
        members: Vec<Arc<SharedTunMemberSlot>>,
    ) -> Option<Arc<SharedTunMemberSlot>> {
        let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(payload)?;
        for slot in &members {
            let claims = slot.claims.read().await;
            if claims
                .ipv4
                .map(|inet| inet.address() == ipv4.get_source())
                .unwrap_or(false)
            {
                return Some(slot.clone());
            }
        }

        let dst = ipv4.get_destination();
        let mut best_owned: Option<(u8, Arc<SharedTunMemberSlot>)> = None;
        for slot in &members {
            let claims = slot.claims.read().await;
            for prefix in claims.dispatch_v4_prefixes() {
                if prefix.contains(&dst) {
                    let prefix_len = prefix.network_length();
                    if best_owned
                        .as_ref()
                        .map(|(best_len, _)| prefix_len > *best_len)
                        .unwrap_or(true)
                    {
                        best_owned = Some((prefix_len, slot.clone()));
                    }
                }
            }
        }

        if let Some((_, slot)) = best_owned {
            return Some(slot);
        }

        let mut best_reachable: Option<(u8, Arc<SharedTunMemberSlot>)> = None;
        for slot in members {
            let claims = slot.claims.read().await;
            for prefix in claims.reachable_v4_prefixes() {
                if prefix.contains(&dst) {
                    let prefix_len = prefix.network_length();
                    if best_reachable
                        .as_ref()
                        .map(|(best_len, _)| prefix_len > *best_len)
                        .unwrap_or(true)
                    {
                        best_reachable = Some((prefix_len, slot.clone()));
                    }
                }
            }
        }

        best_reachable.map(|(_, slot)| slot)
    }

    async fn select_owner_ipv6(
        &self,
        payload: &[u8],
        members: Vec<Arc<SharedTunMemberSlot>>,
    ) -> Option<Arc<SharedTunMemberSlot>> {
        let ipv6 = pnet::packet::ipv6::Ipv6Packet::new(payload)?;
        for slot in &members {
            let claims = slot.claims.read().await;
            if claims
                .ipv6
                .map(|inet| inet.address() == ipv6.get_source())
                .unwrap_or(false)
            {
                return Some(slot.clone());
            }
        }

        let dst = ipv6.get_destination();
        let mut best: Option<(u8, Arc<SharedTunMemberSlot>)> = None;
        for slot in members {
            let claims = slot.claims.read().await;
            for prefix in claims.dispatch_v6_prefixes() {
                if prefix.contains(&dst) {
                    let prefix_len = prefix.network_length();
                    if best
                        .as_ref()
                        .map(|(best_len, _)| prefix_len > *best_len)
                        .unwrap_or(true)
                    {
                        best = Some((prefix_len, slot.clone()));
                    }
                }
            }
        }

        best.map(|(_, slot)| slot)
    }

    async fn apply_config(&self) -> Result<(), Error> {
        let slots = {
            let members = self.members.read().await;
            members.values().cloned().collect::<Vec<_>>()
        };

        let mut desired = AppliedConfig::default();
        for slot in slots {
            let claims = slot.claims.read().await.clone();
            if let Some(ipv4) = claims.ipv4 {
                desired
                    .ipv4_addrs
                    .insert((ipv4.address(), ipv4.network_length()));
                #[cfg(any(
                    all(target_os = "macos", not(feature = "macos-ne")),
                    target_os = "freebsd"
                ))]
                desired.ipv4_routes.insert(ipv4.network());
            }
            if let Some(ipv6) = claims.ipv6 {
                desired
                    .ipv6_addrs
                    .insert((ipv6.address(), ipv6.network_length()));
                #[cfg(any(
                    all(target_os = "macos", not(feature = "macos-ne")),
                    target_os = "freebsd"
                ))]
                desired.ipv6_routes.insert(ipv6.network());
            }
            desired
                .ipv4_routes
                .extend(claims.proxy_v4_routes.iter().copied());
            desired.mtu = Some(match desired.mtu {
                Some(cur) => cur.min(claims.effective_mtu),
                None => claims.effective_mtu,
            });
        }

        let mut current = self.current_config.lock().await;
        if *current == desired {
            return Ok(());
        }

        let nic = self.nic.lock().await;
        nic.link_up().await?;
        if current.mtu != desired.mtu
            && let Some(mtu) = desired.mtu
        {
            nic.set_mtu(mtu).await?;
        }

        if current.ipv4_addrs != desired.ipv4_addrs {
            nic.remove_ip(None).await?;
            for (addr, prefix) in desired.ipv4_addrs.iter().copied() {
                nic.add_ip(addr, prefix as i32).await?;
            }
        }
        if current.ipv6_addrs != desired.ipv6_addrs {
            nic.remove_ipv6(None).await?;
            for (addr, prefix) in desired.ipv6_addrs.iter().copied() {
                nic.add_ipv6(addr, prefix as i32).await?;
            }
        }

        for prefix in current.ipv4_routes.difference(&desired.ipv4_routes) {
            nic.remove_route(prefix.first_address(), prefix.network_length())
                .await?;
        }
        for prefix in desired.ipv4_routes.difference(&current.ipv4_routes) {
            nic.add_route(prefix.first_address(), prefix.network_length())
                .await?;
        }

        for prefix in current.ipv6_routes.difference(&desired.ipv6_routes) {
            nic.remove_ipv6_route(prefix.first_address(), prefix.network_length())
                .await?;
        }
        for prefix in desired.ipv6_routes.difference(&current.ipv6_routes) {
            nic.add_ipv6_route(prefix.first_address(), prefix.network_length())
                .await?;
        }

        *current = desired;
        Ok(())
    }

    async fn detach_member(&self, member_id: uuid::Uuid) {
        self.members.write().await.remove(&member_id);
        if let Err(err) = self.apply_config().await {
            tracing::warn!(instance_id = %member_id, ?err, "failed to reconcile shared tun after detach");
        }
    }

    async fn member_count(&self) -> usize {
        self.members.read().await.len()
    }

    async fn fail_all_members(&self, reason: &str) {
        self.cancel.cancel();
        let members = {
            let members = self.members.read().await;
            members.values().cloned().collect::<Vec<_>>()
        };
        for slot in members {
            slot.global_ctx
                .issue_event(GlobalCtxEvent::TunDeviceError(reason.to_owned()));
            slot.close_notifier.notify_one();
        }
    }

    async fn shutdown(&self) {
        self.cancel.cancel();
        let mut tasks = self.tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

impl SharedTunMemberHandle {
    pub async fn shutdown(mut self) {
        if self.shutdown {
            return;
        }
        self.shutdown = true;
        self.cancel.cancel();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.device.detach_member(self.member_id).await;
        SHARED_TUN_REGISTRY
            .remove_if_unused(&self.device.key, &self.device)
            .await;
    }
}

impl Drop for SharedTunMemberHandle {
    fn drop(&mut self) {
        if self.shutdown {
            return;
        }
        self.cancel.cancel();
        self.tasks.abort_all();
        let device = self.device.clone();
        let member_id = self.member_id;
        let key = self.device.key.clone();
        tokio::spawn(async move {
            device.detach_member(member_id).await;
            SHARED_TUN_REGISTRY.remove_if_unused(&key, &device).await;
        });
    }
}

fn handle_member_event(
    event_receiver: &mut tokio::sync::broadcast::Receiver<GlobalCtxEvent>,
    event: Result<GlobalCtxEvent, tokio::sync::broadcast::error::RecvError>,
) -> Option<GlobalCtxEvent> {
    match event {
        Ok(event) => Some(event),
        Err(tokio::sync::broadcast::error::RecvError::Closed) => None,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
            *event_receiver = event_receiver.resubscribe();
            Some(GlobalCtxEvent::ProxyCidrsUpdated(Vec::new(), Vec::new()))
        }
    }
}

fn should_refresh_member_claims(event: &GlobalCtxEvent) -> bool {
    matches!(
        event,
        GlobalCtxEvent::ProxyCidrsUpdated(_, _)
            | GlobalCtxEvent::ConfigPatched(_)
            | GlobalCtxEvent::DhcpIpv4Changed(_, _)
    )
}

fn build_member_claims(
    global_ctx: &ArcGlobalCtx,
    proxy_v4_routes: BTreeSet<cidr::Ipv4Cidr>,
) -> MemberClaims {
    let flags = global_ctx.get_flags();
    let effective_mtu = flags
        .mtu
        .saturating_sub(if flags.enable_encryption { 20 } else { 0 });
    let enable_exit_node = global_ctx.enable_exit_node();
    MemberClaims {
        ipv4: global_ctx.get_ipv4(),
        ipv6: global_ctx.get_ipv6(),
        owned_proxy_v4_routes: collect_owned_proxy_v4_routes(global_ctx),
        proxy_v4_routes,
        effective_mtu: effective_mtu as u16,
        default_route_v4: enable_exit_node,
        default_route_v6: enable_exit_node,
    }
}

fn collect_owned_proxy_v4_routes(global_ctx: &ArcGlobalCtx) -> BTreeSet<cidr::Ipv4Cidr> {
    let mut routes = global_ctx
        .config
        .get_proxy_cidrs()
        .into_iter()
        .map(|cfg| cfg.mapped_cidr.unwrap_or(cfg.cidr))
        .collect::<BTreeSet<_>>();

    if let Some(cidr) = global_ctx.get_vpn_portal_cidr() {
        routes.insert(cidr);
    }

    routes
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::MemberClaims;

    #[test]
    fn nested_prefixes_are_distinct() {
        let mut left = MemberClaims::default();
        left.owned_proxy_v4_routes
            .insert(cidr::Ipv4Cidr::from_str("10.0.0.0/16").unwrap());

        let mut right = MemberClaims::default();
        right
            .owned_proxy_v4_routes
            .insert(cidr::Ipv4Cidr::from_str("10.0.1.0/24").unwrap());

        assert_ne!(left.dispatch_v4_prefixes(), right.dispatch_v4_prefixes());
    }

    #[test]
    fn exit_node_adds_default_prefix() {
        let claims = MemberClaims {
            default_route_v4: true,
            ..Default::default()
        };

        assert!(
            claims
                .dispatch_v4_prefixes()
                .contains(&cidr::Ipv4Cidr::from_str("0.0.0.0/0").unwrap())
        );
    }

    #[test]
    fn identical_local_v4_subnets_do_not_conflict_in_dispatch() {
        let left = MemberClaims {
            ipv4: Some(cidr::Ipv4Inet::from_str("10.144.145.1/24").unwrap()),
            ..Default::default()
        };

        let right = MemberClaims {
            ipv4: Some(cidr::Ipv4Inet::from_str("10.144.145.2/24").unwrap()),
            ..Default::default()
        };

        assert_eq!(left.local_v4_prefix(), right.local_v4_prefix());
        assert!(left.shared_route_v4_prefixes().is_empty());
        assert!(right.shared_route_v4_prefixes().is_empty());
    }

    #[test]
    fn learned_proxy_routes_do_not_become_owned_claims() {
        let mut claims = MemberClaims::default();
        claims
            .proxy_v4_routes
            .insert(cidr::Ipv4Cidr::from_str("10.1.2.0/24").unwrap());

        assert!(claims.shared_route_v4_prefixes().is_empty());
        assert!(
            claims
                .reachable_v4_prefixes()
                .contains(&cidr::Ipv4Cidr::from_str("10.1.2.0/24").unwrap())
        );
    }
}
