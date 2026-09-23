use crate::instance::virtual_nic::NicCtx;
use easytier_core::host::packet::HostPacketReceiver;
use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Arc, OnceLock},
};
use tokio::{
    sync::{Mutex, watch},
    task::JoinSet,
};

#[cfg(feature = "magic-dns")]
use crate::dns::{
    host::{DnsHost, DnsInterfaceState},
    system::{self, SystemConfig, SystemConfigurator},
};
#[cfg(feature = "magic-dns")]
use uuid::Uuid;

struct NicCtxContainer {
    nic: NicCtx,
    primary_ips: HashSet<IpAddr>,
    #[cfg(feature = "magic-dns")]
    dns: DnsResources,
}

#[cfg(feature = "magic-dns")]
#[derive(Default)]
struct DnsResources {
    owner: Option<Uuid>,
    addresses: HashSet<IpAddr>,
    system: Option<Box<dyn SystemConfigurator>>,
    system_config: Option<SystemConfig>,
}

#[cfg(feature = "magic-dns")]
impl NicCtxContainer {
    async fn release_dns(&mut self) -> anyhow::Result<()> {
        // macOS resolver paths are shared across interface generations. Cleanup
        // finishes under the slot lock before a replacement may publish settings.
        if let Some(system) = self.dns.system.as_ref() {
            system.clean()?;
        }
        self.dns.system = None;
        self.dns.system_config = None;
        let addresses = self.dns.addresses.clone();
        for ip in addresses {
            remove_address(&self.nic, ip).await?;
            self.dns.addresses.remove(&ip);
        }
        self.dns.owner = None;
        Ok(())
    }
}

struct NicState {
    generation: u64,
    nic: Option<NicCtxContainer>,
    drain: JoinSet<()>,
}

#[derive(Clone)]
pub(super) struct TunNicState {
    state: Arc<Mutex<NicState>>,
    receiver: Arc<OnceLock<Arc<Mutex<HostPacketReceiver>>>>,
    changed: watch::Sender<(u64, bool)>,
}

impl std::fmt::Debug for TunNicState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunNicState").finish_non_exhaustive()
    }
}

impl TunNicState {
    pub(super) fn empty() -> Self {
        Self {
            state: Arc::new(Mutex::new(NicState {
                generation: 0,
                nic: None,
                drain: JoinSet::new(),
            })),
            receiver: Arc::new(OnceLock::new()),
            changed: watch::channel((0, false)).0,
        }
    }

    pub(super) fn install_receiver(&self, receiver: HostPacketReceiver) -> anyhow::Result<()> {
        self.receiver
            .set(Arc::new(Mutex::new(receiver)))
            .map_err(|_| anyhow::anyhow!("native packet receiver is already installed"))
    }

    pub(super) fn receiver(&self) -> Arc<Mutex<HostPacketReceiver>> {
        self.receiver
            .get()
            .expect("packet receiver must be installed before preparing TUN")
            .clone()
    }

    pub(super) async fn stop(&self) {
        let mut state = self.state.lock().await;
        #[cfg(feature = "magic-dns")]
        if let Some(nic) = state.nic.as_mut()
            && let Err(error) = nic.release_dns().await
        {
            tracing::warn!(?error, "failed to clean old DNS interface resources");
        }
        state.nic = None;
        state.drain.abort_all();
        while state.drain.join_next().await.is_some() {}
        state.generation += 1;
        self.changed.send_replace((state.generation, false));
    }

    pub(super) async fn drain(&self) {
        self.stop().await;
        let receiver = self.receiver();
        self.state.lock().await.drain.spawn(async move {
            let mut receiver = receiver.lock().await;
            while let Some(packet) = receiver.recv().await {
                tracing::trace!(?packet, "discarded packet without a native interface");
            }
        });
    }

    pub(super) async fn install(&self, nic: NicCtx, primary_ips: HashSet<IpAddr>) {
        self.stop().await;
        let mut state = self.state.lock().await;
        state.nic = Some(NicCtxContainer {
            nic,
            primary_ips,
            #[cfg(feature = "magic-dns")]
            dns: DnsResources::default(),
        });
        state.generation += 1;
        self.changed.send_replace((state.generation, !cfg!(mobile)));
    }
}

#[cfg(feature = "magic-dns")]
async fn remove_address(nic: &NicCtx, ip: IpAddr) -> anyhow::Result<()> {
    match ip {
        IpAddr::V4(ip) => nic.remove_ipv4_from_tun_device(ip.into()).await?,
        IpAddr::V6(ip) => nic.remove_ipv6_from_tun_device(ip.into()).await?,
    }
    Ok(())
}

#[cfg(feature = "magic-dns")]
#[async_trait::async_trait]
impl DnsHost for TunNicState {
    fn subscribe(&self) -> watch::Receiver<DnsInterfaceState> {
        let mut changed = self.changed.subscribe();
        let initial = *changed.borrow_and_update();
        let (output, receiver) = watch::channel(DnsInterfaceState {
            generation: initial.0,
            available: initial.1,
        });
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = output.closed() => break,
                    result = changed.changed() => {
                        if result.is_err() { break; }
                        let state = *changed.borrow_and_update();
                        output.send_replace(DnsInterfaceState { generation: state.0, available: state.1 });
                    }
                }
            }
        });
        receiver
    }

    async fn addresses(
        &self,
        owner: Uuid,
        generation: u64,
        desired: &HashSet<IpAddr>,
    ) -> anyhow::Result<HashSet<IpAddr>> {
        // Mobile Hosts receive a platform-configured fd and cannot add desktop IPs.
        if cfg!(mobile) {
            return Ok(HashSet::new());
        }
        let mut state = self.state.lock().await;
        anyhow::ensure!(
            state.generation == generation,
            "DNS interface changed; retry"
        );
        let Some(entry) = state.nic.as_mut() else {
            return Ok(HashSet::new());
        };
        anyhow::ensure!(
            entry.dns.owner.is_none_or(|active| active == owner),
            "DNS interface already leased"
        );
        entry.dns.owner = Some(owner);
        let removed: Vec<_> = entry.dns.addresses.difference(desired).copied().collect();
        for ip in removed {
            remove_address(&entry.nic, ip).await?;
            entry.dns.addresses.remove(&ip);
        }
        let mut available = HashSet::new();
        for &ip in desired {
            if entry.primary_ips.contains(&ip) || entry.dns.addresses.contains(&ip) {
                available.insert(ip);
                continue;
            }
            let result = match ip {
                IpAddr::V4(ip) => entry.nic.add_ipv4_to_tun_device(ip.into()).await,
                IpAddr::V6(ip) => entry.nic.add_ipv6_to_tun_device(ip.into()).await,
            };
            match result {
                Ok(()) => {
                    entry.dns.addresses.insert(ip);
                    available.insert(ip);
                }
                Err(error) => {
                    tracing::warn!(?ip, ?error, "DNS address not yet available; will retry")
                }
            }
        }
        Ok(available)
    }

    async fn system_dns(
        &self,
        owner: Uuid,
        generation: u64,
        config: &SystemConfig,
    ) -> anyhow::Result<()> {
        if cfg!(mobile) {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        anyhow::ensure!(
            state.generation == generation,
            "DNS interface changed; retry"
        );
        let Some(entry) = state.nic.as_mut() else {
            return Ok(());
        };
        anyhow::ensure!(
            entry.dns.owner.is_none_or(|active| active == owner),
            "DNS interface already leased"
        );
        entry.dns.owner = Some(owner);
        if entry.dns.system_config.as_ref() == Some(config) {
            return Ok(());
        }
        if config.nameservers.is_empty() {
            if let Some(system) = entry.dns.system.as_ref() {
                system.clean()?;
            }
            entry.dns.system_config = Some(config.clone());
            return Ok(());
        }
        if entry.dns.system.is_none()
            && let Some(ifname) = entry.nic.ifname().await
        {
            entry.dns.system = system::get(&ifname)?;
        }
        if let Some(system) = entry.dns.system.as_ref() {
            system.set_dns(config)?;
        }
        entry.dns.system_config = Some(config.clone());
        Ok(())
    }

    async fn release(&self, owner: Uuid) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if let Some(entry) = state.nic.as_mut()
            && entry.dns.owner == Some(owner)
        {
            entry.release_dns().await?;
        }
        Ok(())
    }

    async fn clear_system_dns(&self, owner: Uuid) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if let Some(entry) = state.nic.as_mut()
            && entry.dns.owner == Some(owner)
        {
            if let Some(system) = entry.dns.system.as_ref() {
                system.clean()?;
            }
            entry.dns.system = None;
            entry.dns.system_config = None;
        }
        Ok(())
    }
}
