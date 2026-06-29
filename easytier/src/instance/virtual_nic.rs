use byteorder::WriteBytesExt as _;
use cidr::{Ipv4Inet, Ipv6Inet};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Weak},
};
use bytes::Buf;
use tokio::{
    sync::{Mutex, Notify},
    task::JoinSet,
};
#[cfg(target_os = "windows")]
use tokio_util::task::AbortOnDropHandle;
use tun::AsyncReadExt;
use tun::{
    AbstractDevice, AsyncDevice, AsyncReader, AsyncWriteExt, AsyncWriter, Configuration, Layer,
};
use zerocopy::{NativeEndian, NetworkEndian};

#[cfg(target_os = "windows")]
use crate::common::ifcfg::RegistryManager;
use crate::utils::buf::{BufMargins, BufPool};
use crate::utils::net;
use crate::utils::net::Segmenter;
use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        ifcfg::{IfConfiger, IfConfiguerTrait},
        log,
    },
    instance::proxy_cidrs_monitor::ProxyCidrsMonitor,
    peers::{PacketRecvChanReceiver, peer_manager::PeerManager, recv_packet_from_chan},
    tunnel::packet_def::{TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
};

// region tun
pub struct TunRx {
    reader: AsyncReader,

    packets: u64,
    bytes: u64,
    errors: u64,

    buf: BufPool,
    margins: BufMargins,

    has_pi: bool,
    #[cfg(target_os = "linux")]
    has_vnet_hdr: bool,

    max_packet_size: usize,
}

impl TunRx {
    pub fn new(reader: AsyncReader, has_pi: bool, has_vnet_hdr: bool, mtu: usize) -> Self {
        debug_assert!(!has_vnet_hdr || cfg!(target_os = "linux"));

        let mut header = ZCPacketType::NIC.get_packet_offsets().payload_offset;

        if has_pi {
            header -= net::PI_LEN;
        }
        #[cfg(target_os = "linux")]
        if has_vnet_hdr {
            header -= net::VNET_HDR_LEN;
        }

        let max_packet_size = if has_vnet_hdr { 1 << 16 } else { mtu };

        Self {
            reader,
            packets: 0,
            bytes: 0,
            errors: 0,
            buf: BufPool::new(1 << 20),
            margins: BufMargins {
                header,
                trailer: TAIL_RESERVED_SIZE,
            },
            has_pi,
            #[cfg(target_os = "linux")]
            has_vnet_hdr,
            max_packet_size,
        }
    }

    pub async fn recv(&mut self) -> io::Result<ZCPacket> {
        let mut writer = self
            .buf
            .writer(self.max_packet_size + self.margins.size(), self.margins);
        let slice = writer.as_slice();
        let buf =
            unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, slice.len()) };
        let written = match self.reader.read(buf).await {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => n,
            Err(e) => {
                self.errors += 1;
                return Err(e);
            }
        };
        writer.commit(written);

        self.packets += 1;
        self.bytes += written as u64;

        let mut packet = writer.split();
        packet.truncate(packet.len() - self.margins.trailer);

        #[cfg(target_os = "linux")]
        if self.has_vnet_hdr {
            net::write_checksum(&mut packet[self.margins.header..], self.has_pi);
        }

        Ok(ZCPacket::new_from_buf(packet, ZCPacketType::NIC))
    }
}

trait ProtoExt {
    fn infer(payload: &[u8]) -> Self;
    fn into_pi(self) -> Result<u16, io::Error>;
}

impl ProtoExt for EtherType {
    fn infer(payload: &[u8]) -> Self {
        if payload.is_empty() {
            return EtherType(0xFFFF);
        }
        match payload[0] >> 4 {
            4 => EtherTypes::Ipv4,
            6 => EtherTypes::Ipv6,
            _ => EtherType(0xFFFF),
        }
    }

    fn into_pi(self) -> Result<u16, io::Error> {
        let (ipv4, ipv6) = cfg_select! {
            any(target_os = "linux", target_os = "android", target_env = "ohos") => {{
                use nix::libc;
                (libc::ETH_P_IP as _, libc::ETH_P_IPV6 as _)
            }}
            any(target_os = "macos", target_os = "ios", target_os = "freebsd") => {{
                use nix::libc;
                (libc::PF_INET as _, libc::PF_INET6 as _)
            }}
            _ => return unimplemented!(),
        };
        match self {
            EtherTypes::Ipv4 => Ok(ipv4),
            EtherTypes::Ipv6 => Ok(ipv6),
            _ => Err(io::Error::other("neither an IPv4 nor IPv6 packet")),
        }
    }
}

pub struct TunTx {
    writer: AsyncWriter,

    packets: u64,
    bytes: u64,
    errors: u64,

    pi_len: usize,
    vnet_hdr_len: usize,

    segmenter: Segmenter,
}

impl TunTx {
    pub fn new(writer: AsyncWriter, has_pi: bool, has_vnet_hdr: bool, mtu: usize) -> Self {
        let pi_len = if has_pi { 4 } else { 0 };
        let vnet_hdr_len = if has_vnet_hdr {
            cfg_select! {
                target_os = "linux" => net::VNET_HDR_LEN,
                _ => unreachable!(),
            }
        } else {
            0
        };

        TunTx {
            writer,
            packets: 0,
            bytes: 0,
            errors: 0,
            pi_len,
            vnet_hdr_len,
            segmenter: Segmenter::new(mtu, vnet_hdr_len),
        }
    }

    pub fn has_pi(&self) -> bool {
        self.pi_len > 0
    }

    pub fn has_vnet_hdr(&self) -> bool {
        self.vnet_hdr_len > 0
    }

    pub fn hdr_len(&self) -> usize {
        self.vnet_hdr_len + self.pi_len
    }

    async fn write(&mut self, frame: &[u8]) -> io::Result<()> {
        self.writer
            .write(frame)
            .await
            .inspect(|_| {
                self.packets += 1;
                self.bytes += frame.len() as u64;
            })
            .inspect_err(|_| {
                self.errors += 1;
            })
    }

    pub async fn send(&mut self, item: ZCPacket) -> io::Result<()> {
        let hdr_len = self.hdr_len();

        let mut frame = {
            let offset = item.payload_offset();
            let mut inner = item.inner();
            inner.advance(offset - hdr_len);
            inner
        };
        let (hdr, packet) = frame.split_at_mut(hdr_len);

        if self.has_pi() {
            let mut pi = &mut hdr[hdr_len - self.pi_len..];
            pi.write_u16::<NativeEndian>(0)?;
            pi.write_u16::<NetworkEndian>(EtherType::infer(packet).into_pi()?)?;
        }

        if let Some(frames) = self.segmenter.segment(hdr, packet) {
            for frame in frames.into_iter() {
                self.write(&frame).await?;
            }
            Ok(())
        } else {
            self.write(&frame).await
        }
    }
}
// endregion

pub struct VirtualNic {
    global_ctx: ArcGlobalCtx,

    ifname: Option<String>,
    ifcfg: Box<dyn IfConfiguerTrait + Send + Sync + 'static>,
    gso: AtomicBool,
}

impl Drop for VirtualNic {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if let Some(ref ifname) = self.ifname {
                // Try to clean up firewall rules, but don't panic in destructor
                if let Err(error) = crate::arch::windows::remove_interface_firewall_rules(ifname) {
                    log::warn!(
                        %error,
                        "failed to remove firewall rules for interface {}",
                        ifname
                    );
                }
            }
        }
    }
}

impl VirtualNic {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            ifname: None,
            ifcfg: Box::new(IfConfiger {}),
            gso: AtomicBool::new(false),
        }
    }

    /// Check and create TUN device node if necessary on Linux systems
    #[cfg(target_os = "linux")]
    async fn ensure_tun_device_node() {
        const TUN_DEV_PATH: &str = "/dev/net/tun";
        const TUN_DIR_PATH: &str = "/dev/net";

        // Check if /dev/net/tun already exists
        if tokio::fs::metadata(TUN_DEV_PATH).await.is_ok() {
            tracing::debug!("TUN device node {} already exists", TUN_DEV_PATH);
            return;
        }

        tracing::info!(
            "TUN device node {} not found, attempting to create",
            TUN_DEV_PATH
        );

        // Check if TUN kernel module is available
        let tun_module_available = tokio::fs::metadata("/proc/net/dev").await.is_ok()
            && (tokio::fs::read_to_string("/proc/modules").await)
                .map(|content| content.contains("tun"))
                .unwrap_or(false);

        if !tun_module_available {
            log::warn!("TUN kernel module may not be available.");
            log::warn!("\tYou may need to load it with: sudo modprobe tun.");
        }

        // Try to create /dev/net directory if it doesn't exist
        if tokio::fs::metadata(TUN_DIR_PATH).await.is_err() {
            if let Err(error) = tokio::fs::create_dir_all(TUN_DIR_PATH).await {
                log::warn!(
                    ?error,
                    "Failed to create directory {}. TUN device creation may fail. Continuing anyway.",
                    TUN_DIR_PATH
                );
                log::warn!(
                    "\tYou may need to run with root privileges or manually create the TUN device."
                );
                Self::print_troubleshooting_info();
                return;
            }
            tracing::info!("Created directory {}", TUN_DIR_PATH);
        }

        // Try to create the TUN device node
        // Major number 10, minor number 200 for /dev/net/tun
        let dev_node = nix::sys::stat::makedev(10, 200);

        match nix::sys::stat::mknod(
            TUN_DEV_PATH,
            nix::sys::stat::SFlag::S_IFCHR,
            nix::sys::stat::Mode::from_bits(0o600).unwrap(),
            dev_node,
        ) {
            Ok(_) => {
                log::info!("Successfully created TUN device node {}", TUN_DEV_PATH);
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Failed to create TUN device node {}. Continuing anyway.",
                    TUN_DEV_PATH,
                );
                Self::print_troubleshooting_info();
            }
        }
    }

    /// Print troubleshooting information for TUN device issues
    #[cfg(target_os = "linux")]
    fn print_troubleshooting_info() {
        log::info!(
            "Possible solutions:\
            \n\t1. Run with root privileges: sudo ./easytier-core [options]\
            \n\t2. Manually create TUN device: sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200\
            \n\t3. Load TUN kernel module: sudo modprobe tun\
            \n\t4. Use --no-tun flag if TUN functionality is not needed\
            \n\t5. Check if your system/container supports TUN devices\
            \nNote: TUN functionality may still work if the kernel supports dynamic device creation."
        );
    }

    /// For non-Linux systems, this is a no-op
    #[cfg(not(target_os = "linux"))]
    async fn ensure_tun_device_node() -> Result<(), Error> {
        Ok(())
    }

    /// FreeBSD specific: Rename a TUN interface
    #[cfg(target_os = "freebsd")]
    async fn rename_tun_interface(old_name: &str, new_name: &str) -> Result<(), Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg(old_name)
            .arg("name")
            .arg(new_name)
            .output()
            .await?;

        if output.status.success() {
            tracing::info!(
                "Successfully renamed interface {} to {}",
                old_name,
                new_name
            );
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                "Failed to rename interface {} to {}: {}",
                old_name,
                new_name,
                stderr
            );
            // Return Ok even if rename fails, as it's not critical
            Ok(())
        }
    }

    /// FreeBSD specific: List all TUN interface names
    #[cfg(target_os = "freebsd")]
    async fn list_tun_names() -> Result<Vec<String>, Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg("-g")
            .arg("tun")
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tun_names: Vec<String> = stdout
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            tracing::debug!("Found TUN interfaces: {:?}", tun_names);
            Ok(tun_names)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to list TUN interfaces: {}", stderr);
            Ok(Vec::new())
        }
    }

    /// FreeBSD specific: Get interface information
    #[cfg(target_os = "freebsd")]
    async fn get_interface_info(ifname: &str) -> Result<String, Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg("-v")
            .arg(ifname)
            .output()
            .await?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(
                anyhow::anyhow!("Failed to get interface details for {}: {}", ifname, stderr)
                    .into(),
            )
        }
    }

    /// FreeBSD specific: Extract original name from interface information
    #[cfg(target_os = "freebsd")]
    fn extract_original_name(ifinfo: &str) -> Option<String> {
        ifinfo
            .lines()
            .find(|line| line.trim().starts_with("drivername:"))
            .and_then(|line| line.trim().split_whitespace().nth(1))
            .map(|name| name.to_string())
    }

    /// FreeBSD specific: Check if interface is used by any process
    #[cfg(target_os = "freebsd")]
    fn is_interface_used(ifinfo: &str) -> bool {
        ifinfo.contains("Opened by PID")
    }

    /// FreeBSD specific: Restore TUN interface name to its original value
    #[cfg(target_os = "freebsd")]
    async fn restore_tun_name(dev_name: &str) -> Result<(), Error> {
        let tun_names = Self::list_tun_names().await?;

        // Check if desired dev_name is in use
        if tun_names.iter().any(|name| name == dev_name) {
            tracing::debug!(
                "Desired dev_name {} is in TUN interfaces list, checking if it can be renamed",
                dev_name
            );

            let ifinfo = Self::get_interface_info(dev_name).await?;

            // Check if interface is not occupied
            if !Self::is_interface_used(&ifinfo) {
                // Extract original name
                if let Some(orig_name) = Self::extract_original_name(&ifinfo) {
                    if orig_name != dev_name {
                        tracing::info!(
                            "Restoring dev_name {} to original name {}",
                            dev_name,
                            orig_name
                        );
                        // Rename interface
                        Self::rename_tun_interface(dev_name, &orig_name).await?;
                    }
                }
            } else {
                tracing::debug!(
                    "Interface {} is opened by a process, skipping rename",
                    dev_name
                );
            }
        }

        Ok(())
    }

    async fn create_tun(&self) -> Result<tun::platform::Device, Error> {
        let mut config = Configuration::default();
        config.layer(Layer::L3);

        // FreeBSD specific: Check and restore TUN interfaces before creating new one
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            if !dev_name.is_empty() {
                // Restore TUN interface name if needed, ignoring errors as it's not critical
                let _ = Self::restore_tun_name(&dev_name).await;
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check and create TUN device node if necessary (Linux only)
            Self::ensure_tun_device_node().await;

            let dev_name = self.global_ctx.get_flags().dev_name;
            if !dev_name.is_empty() {
                config.tun_name(&dev_name);
            }
        }

        #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });

        #[cfg(target_os = "windows")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            match crate::arch::windows::add_self_to_firewall_allowlist() {
                Ok(_) => tracing::info!("add_self_to_firewall_allowlist successful!"),
                Err(error) => {
                    log::warn!(%error, "Failed to add Easytier to firewall allowlist, Subnet proxy and KCP proxy may not work properly.");
                    log::warn!(
                        "You can add firewall rules manually, or use --use-smoltcp to run with user-space TCP/IP stack."
                    );
                }
            }

            match RegistryManager::reg_delete_obsoleted_items(&dev_name) {
                Ok(_) => tracing::trace!("delete successful!"),
                Err(e) => tracing::error!("An error occurred: {}", e),
            }

            if !dev_name.is_empty() {
                config.tun_name(&dev_name);
            } else {
                use rand::distributions::Distribution as _;
                let c = crate::arch::windows::interface_count()?;
                let mut rng = rand::thread_rng();
                let s: String = rand::distributions::Alphanumeric
                    .sample_iter(&mut rng)
                    .take(4)
                    .map(char::from)
                    .collect::<String>()
                    .to_lowercase();

                let random_dev_name = format!("et_{}_{}", c, s);
                config.tun_name(random_dev_name.clone());

                let mut flags = self.global_ctx.get_flags();
                flags.dev_name = random_dev_name.clone();
                self.global_ctx.set_flags(flags);
            }

            config.platform_config(|config| {
                config.skip_config(true);
                config.ring_cap(Some(std::cmp::min(
                    config.min_ring_cap() * 32,
                    config.max_ring_cap(),
                )));
            });
        }

        config.up();

        let _g = self.global_ctx.net_ns.guard();

        let (dev, gso) = cfg_select! {
            all(target_os = "linux", not(target_env = "ohos")) => {{
                let gso = self.global_ctx.config.get_flags().gso;
                config.platform_config(|c| { c.vnet_hdr(gso); });
                let dev = tun::create(&config)?;

                if gso {
                    let enabled = unsafe {
                        nix::libc::ioctl(
                            std::os::fd::AsRawFd::as_raw_fd(&dev) as nix::libc::c_int,
                            nix::libc::TUNSETOFFLOAD,
                            nix::libc::TUN_F_CSUM | nix::libc::TUN_F_TSO4 | nix::libc::TUN_F_TSO6,
                        )
                    } == 0;

                    if enabled {
                        log::info!("GSO enabled");
                        (dev, true)
                    } else {
                        log::warn!(error =? io::Error::last_os_error(), "failed to enable GSO on TUN, falling back");
                        drop(dev);
                        config.platform_config(|c| { c.vnet_hdr(false); });
                        (tun::create(&config)?, false)
                    }
                } else {
                    (dev, false)
                }
            }}
            _ => (tun::create(&config)?, false),
        };

        self.gso.store(gso, Ordering::Relaxed);

        Ok(dev)
    }

    #[cfg(mobile)]
    pub async fn create_dev_for_mobile(
        &mut self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<(TunRx, TunTx), Error> {
        log::debug!(%tun_fd);
        let mut config = Configuration::default();
        config.layer(Layer::L3);

        #[cfg(any(target_os = "ios", all(target_os = "macos", feature = "macos-ne")))]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });

        config.raw_fd(tun_fd);
        config.close_fd_on_drop(false);
        config.up();

        let has_pi = cfg!(any(
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne")
        ));
        let dev = tun::create(&config)?;
        let mtu = dev.mtu()?.into();
        let dev = AsyncDevice::new(dev)?;
        let (reader, writer) = dev.split();
        self.ifname = Some(format!("tunfd_{}", tun_fd));
        Ok((
            TunRx::new(reader, has_pi, false, mtu),
            TunTx::new(writer, has_pi, false, mtu),
        ))
    }

    pub async fn create_dev(&mut self) -> Result<(TunRx, TunTx), Error> {
        let dev = self.create_tun().await?;

        #[cfg(not(target_os = "freebsd"))]
        let ifname = dev.tun_name()?;

        #[cfg(target_os = "freebsd")]
        let mut ifname = dev.tun_name()?;
        self.ifcfg.wait_interface_show(ifname.as_str()).await?;

        // FreeBSD TUN interface rename functionality
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            if !dev_name.is_empty() && dev_name != ifname {
                // Use ifconfig to rename the TUN interface
                if Self::rename_tun_interface(&ifname, &dev_name).await.is_ok() {
                    ifname = dev_name;
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(guid) = RegistryManager::find_interface_guid(&ifname) {
                if let Err(e) = RegistryManager::disable_dynamic_updates(&guid) {
                    tracing::error!(
                        "Failed to disable dhcp for interface {} {}: {}",
                        ifname,
                        guid,
                        e
                    );
                }

                // Disable NetBIOS over TCP/IP
                if let Err(e) = RegistryManager::disable_netbios(&guid) {
                    tracing::error!(
                        "Failed to disable netbios for interface {} {}: {}",
                        ifname,
                        guid,
                        e
                    );
                }
            }
        }

        let dev = AsyncDevice::new(dev)?;

        let flags = self.global_ctx.config.get_flags();
        let mtu = {
            let mut mtu = flags.mtu;
            if flags.enable_encryption {
                mtu -= 20;
            }
            // set mtu by ourselves, rust-tun does not handle it correctly on windows
            let _g = self.global_ctx.net_ns.guard();
            self.ifcfg.set_mtu(ifname.as_str(), mtu).await?;
            mtu as usize
        };

        let gso = self.gso.load(Ordering::Relaxed);
        let has_pi = cfg!(all(target_os = "macos", not(feature = "macos-ne")));
        let (reader, writer) = dev.split();

        #[cfg(target_os = "windows")]
        {
            // Add firewall rules for virtual NIC interface to allow all traffic
            match crate::arch::windows::add_interface_to_firewall_allowlist(&ifname) {
                Ok(_) => {
                    tracing::info!(
                        "Successfully configured Windows Firewall for interface: {}",
                        ifname
                    );
                }
                Err(error) => {
                    log::warn!(%error, "Failed to configure Windows Firewall for interface {}\
                    \n\tThis may cause connectivity issues with ping and other network functions.\
                    \n\tPlease run as Administrator or manually configure Windows Firewall.\
                    \n\tAlternatively, you can disable Windows Firewall for testing purposes.", ifname);
                }
            }
        }

        self.ifname = Some(ifname.to_owned());
        Ok((
            TunRx::new(reader, has_pi, gso, mtu),
            TunTx::new(writer, has_pi, gso, mtu),
        ))
    }

    pub fn ifname(&self) -> &str {
        self.ifname.as_ref().unwrap().as_str()
    }

    pub async fn link_up(&self) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.set_link_status(self.ifname(), true).await?;
        Ok(())
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_route(self.ifname(), address, cidr, None)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        self.add_ipv6_route_with_cost(address, cidr, None).await
    }

    pub async fn add_ipv6_route_with_cost(
        &self,
        address: Ipv6Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_route(self.ifname(), address, cidr, cost)
            .await?;
        Ok(())
    }

    pub async fn remove_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .remove_ipv6_route(self.ifname(), address, cidr)
            .await?;
        Ok(())
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ip(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ipv6(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub fn get_ifcfg(&self) -> impl IfConfiguerTrait + use<> {
        IfConfiger {}
    }
}

pub struct NicCtx {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Weak<PeerManager>,
    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,

    close_notifier: Arc<Notify>,

    nic: Arc<Mutex<VirtualNic>>,
    tasks: JoinSet<()>,

    #[cfg(target_os = "windows")]
    windows_udp_broadcast_relay: Option<AbortOnDropHandle<()>>,
}

impl NicCtx {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: &Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        close_notifier: Arc<Notify>,
    ) -> Self {
        NicCtx {
            global_ctx: global_ctx.clone(),
            peer_mgr: Arc::downgrade(peer_manager),
            peer_packet_receiver,

            close_notifier,

            nic: Arc::new(Mutex::new(VirtualNic::new(global_ctx))),
            tasks: JoinSet::new(),

            #[cfg(target_os = "windows")]
            windows_udp_broadcast_relay: None,
        }
    }

    pub async fn ifname(&self) -> Option<String> {
        let nic = self.nic.lock().await;
        nic.ifname.as_ref().map(|s| s.to_owned())
    }

    pub async fn assign_ipv4_to_tun_device(&self, ipv4_addr: cidr::Ipv4Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ip(None).await?;
        nic.add_ip(ipv4_addr.address(), ipv4_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            nic.add_route(ipv4_addr.first_address(), ipv4_addr.network_length())
                .await?;
        }
        Ok(())
    }

    pub async fn assign_ipv6_to_tun_device(&self, ipv6_addr: cidr::Ipv6Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ipv6(None).await?;
        nic.add_ipv6(ipv6_addr.address(), ipv6_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            nic.add_ipv6_route(ipv6_addr.first_address(), ipv6_addr.network_length())
                .await?;
        }
        Ok(())
    }

    async fn do_forward_nic_to_peers_ipv4(ret: ZCPacket, mgr: &PeerManager) {
        if let Some(ipv4) = Ipv4Packet::new(ret.payload()) {
            if ipv4.get_version() != 4 {
                tracing::info!("[USER_PACKET] not ipv4 packet: {:?}", ipv4);
                return;
            }
            let dst_ipv4 = ipv4.get_destination();
            let src_ipv4 = ipv4.get_source();
            let my_ipv4 = mgr.get_global_ctx().get_ipv4().map(|x| x.address());
            tracing::trace!(
                ?ret,
                ?src_ipv4,
                ?dst_ipv4,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            // Subnet A is proxied as 10.0.0.0/24, and Subnet B is also proxied as 10.0.0.0/24.
            //
            // Subnet A has received a route advertised by Subnet B. As a result, A can reach
            // the physical subnet 10.0.0.0/24 directly and has also added a virtual route for
            // the same subnet 10.0.0.0/24. However, the physical route has a higher priority
            // (lower metric) than the virtual one.
            //
            // When A sends a UDP packet to a non-existent IP within this subnet, the packet
            // cannot be delivered on the physical network and is instead routed to the virtual
            // network interface.
            //
            // The virtual interface receives the packet and forwards it to itself, which triggers
            // the subnet proxy logic. The subnet proxy then attempts to send another packet to
            // the same destination address, causing the same process to repeat and creating an
            // infinite loop. Therefore, we must avoid re-sending packets back to ourselves
            // when the subnet proxy itself is the originator of the packet.
            //
            // However, there is a special scenario to consider: when A acts as a gateway,
            // packets from devices behind A may be forwarded by the OS to the ET (e.g., an
            // eBPF or tunneling component), which happens to proxy the subnet. In this case,
            // the packet’s source IP is not A’s own IP, and we must allow such packets to be
            // sent to the virtual interface (i.e., "sent to ourselves") to maintain correct
            // forwarding behavior. Thus, loop prevention should only apply when the source IP
            // belongs to the local host.
            let send_ret = mgr
                .send_msg_by_ip(ret, IpAddr::V4(dst_ipv4), Some(src_ipv4) == my_ipv4)
                .await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv4 packet");
        }
    }

    async fn do_forward_nic_to_peers_ipv6(ret: ZCPacket, mgr: &PeerManager) {
        if let Some(ipv6) = Ipv6Packet::new(ret.payload()) {
            if ipv6.get_version() != 6 {
                tracing::info!("[USER_PACKET] not ipv6 packet: {:?}", ipv6);
                return;
            }
            let src_ipv6 = ipv6.get_source();
            let dst_ipv6 = ipv6.get_destination();
            let is_local_src = mgr.get_global_ctx().is_ip_local_ipv6(&src_ipv6);
            tracing::trace!(
                ?ret,
                ?src_ipv6,
                ?dst_ipv6,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            if src_ipv6.is_unicast_link_local() && !is_local_src {
                // do not route link local packet to other nodes unless the address is assigned by user
                return;
            }

            // TODO: use zero-copy
            let send_ret = mgr
                .send_msg_by_ip(ret, IpAddr::V6(dst_ipv6), is_local_src)
                .await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv6 packet");
        }
    }

    fn do_forward_nic_to_peers(&mut self, mut rx: TunRx) -> Result<(), Error> {
        // read from nic and write to corresponding tunnel
        let Some(mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let close_notifier = self.close_notifier.clone();
        self.tasks.spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(packet) => match EtherType::infer(packet.payload()) {
                        EtherTypes::Ipv4 => {
                            Self::do_forward_nic_to_peers_ipv4(packet, mgr.as_ref()).await
                        }
                        EtherTypes::Ipv6 => {
                            Self::do_forward_nic_to_peers_ipv6(packet, mgr.as_ref()).await
                        }
                        _ => tracing::warn!(?packet, "[USER_PACKET] unknown IP version"),
                    },
                    Err(error) => {
                        if error.kind() == ErrorKind::WouldBlock {
                            break;
                        }
                        tracing::error!(?error, "do_forward_nic_to_peers rx error");
                    }
                }
            }
            close_notifier.notify_one();
            tracing::error!("nic closed when recving from it");
        });

        Ok(())
    }

    fn do_forward_peers_to_nic(&mut self, mut tx: TunTx) {
        let channel = self.peer_packet_receiver.clone();
        let close_notifier = self.close_notifier.clone();
        self.tasks.spawn(async move {
            // unlock until coroutine finished
            let mut channel = channel.lock().await;
            while let Ok(packet) = recv_packet_from_chan(&mut channel).await {
                tracing::trace!(
                    "[USER_PACKET] forward packet from peers to nic. packet: {:?}",
                    packet
                );
                if let Err(error) = tx.send(packet).await {
                    tracing::error!(?error, "do_forward_tunnel_to_nic tx error");
                }
            }
            close_notifier.notify_one();
            tracing::error!("nic closed when sending to it");
        });
    }

    #[cfg(target_os = "windows")]
    fn start_windows_udp_broadcast_relay(&mut self, virtual_ipv4: Ipv4Inet) {
        if !self.global_ctx.get_flags().enable_udp_broadcast_relay {
            return;
        }

        let Some(peer_manager) = self.peer_mgr.upgrade() else {
            tracing::warn!("peer manager is dropped, skip Windows UDP broadcast relay");
            return;
        };

        match super::windows_udp_broadcast::start(peer_manager, virtual_ipv4) {
            Ok(handle) => {
                self.windows_udp_broadcast_relay = Some(handle);
                tracing::info!("Windows UDP broadcast relay started");
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to start Windows UDP broadcast relay; administrator privileges are required"
                );
            }
        }
    }

    async fn apply_route_changes(
        ifcfg: &impl IfConfiguerTrait,
        ifname: &str,
        net_ns: &crate::common::netns::NetNS,
        cur_proxy_cidrs: &mut BTreeSet<cidr::Ipv4Cidr>,
        added: Vec<cidr::Ipv4Cidr>,
        removed: Vec<cidr::Ipv4Cidr>,
    ) {
        tracing::debug!(?added, ?removed, "applying proxy_cidrs route changes");

        // Remove routes
        for cidr in removed {
            if !cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .remove_ipv4_route(ifname, cidr.first_address(), cidr.network_length())
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "remove route failed.",
                );
            }
            cur_proxy_cidrs.remove(&cidr);
        }

        // Add routes
        for cidr in added {
            if cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .add_ipv4_route(ifname, cidr.first_address(), cidr.network_length(), None)
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "add route failed.",
                );
            }
            cur_proxy_cidrs.insert(cidr);
        }
    }

    async fn apply_public_ipv6_route_changes(
        ifcfg: &impl IfConfiguerTrait,
        ifname: &str,
        net_ns: &crate::common::netns::NetNS,
        cur_routes: &mut BTreeSet<cidr::Ipv6Inet>,
        added: Vec<cidr::Ipv6Inet>,
        removed: Vec<cidr::Ipv6Inet>,
    ) {
        for route in removed {
            if !cur_routes.contains(&route) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .remove_ipv6_route(ifname, route.address(), route.network_length())
                .await;
            if ret.is_err() {
                tracing::trace!(route = ?route, err = ?ret, "remove public ipv6 route failed");
            }
            cur_routes.remove(&route);
        }

        for route in added {
            if cur_routes.contains(&route) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .add_ipv6_route(ifname, route.address(), route.network_length(), None)
                .await;
            if ret.is_err() {
                tracing::trace!(route = ?route, err = ?ret, "add public ipv6 route failed");
            } else {
                cur_routes.insert(route);
            }
        }
    }

    async fn run_proxy_cidrs_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let ifname = nic.ifname().to_owned();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::<cidr::Ipv4Cidr>::new();

            // Initial sync: get current proxy_cidrs state and apply routes
            let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                peer_mgr.as_ref(),
                &global_ctx,
                &cur_proxy_cidrs,
            )
            .await;
            Self::apply_route_changes(
                &ifcfg,
                &ifname,
                &net_ns,
                &mut cur_proxy_cidrs,
                added,
                removed,
            )
            .await;

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("event bus closed, stopping proxy_cidrs route updater");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!(
                            "event bus lagged in proxy_cidrs route updater, doing full sync"
                        );
                        event_receiver = event_receiver.resubscribe();
                        // Full sync after lagged to recover consistent state
                        let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                            peer_mgr.as_ref(),
                            &global_ctx,
                            &cur_proxy_cidrs,
                        )
                        .await;
                        GlobalCtxEvent::ProxyCidrsUpdated(added, removed)
                    }
                };

                // Only handle ProxyCidrsUpdated events
                let (added, removed) = match event {
                    GlobalCtxEvent::ProxyCidrsUpdated(added, removed) => (added, removed),
                    _ => continue,
                };

                Self::apply_route_changes(
                    &ifcfg,
                    &ifname,
                    &net_ns,
                    &mut cur_proxy_cidrs,
                    added,
                    removed,
                )
                .await;
            }
        });

        Ok(())
    }

    async fn run_public_ipv6_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let ifname = nic.ifname().to_owned();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut cur_routes = BTreeSet::<cidr::Ipv6Inet>::new();
            let initial_routes = peer_mgr.list_public_ipv6_routes().await;
            let initial_added = initial_routes.iter().copied().collect::<Vec<_>>();
            Self::apply_public_ipv6_route_changes(
                &ifcfg,
                &ifname,
                &net_ns,
                &mut cur_routes,
                initial_added,
                Vec::new(),
            )
            .await;

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = peer_mgr.list_public_ipv6_routes().await;
                        let added = latest.difference(&cur_routes).copied().collect::<Vec<_>>();
                        let removed = cur_routes.difference(&latest).copied().collect::<Vec<_>>();
                        GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed)
                    }
                };

                let (added, removed) = match event {
                    GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed) => (added, removed),
                    _ => continue,
                };

                Self::apply_public_ipv6_route_changes(
                    &ifcfg,
                    &ifname,
                    &net_ns,
                    &mut cur_routes,
                    added,
                    removed,
                )
                .await;
            }
        });

        Ok(())
    }

    async fn run_public_ipv6_addr_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let nic = self.nic.clone();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut current_addr = peer_mgr.get_my_public_ipv6_addr().await;
            if let Some(addr) = current_addr {
                let nic = nic.lock().await;
                if let Err(err) = nic.link_up().await {
                    tracing::warn!(?err, "failed to bring public ipv6 nic link up");
                }
                if let Err(err) = nic.add_ipv6(addr.address(), addr.network_length() as i32).await {
                    tracing::warn!(addr = ?addr, ?err, "failed to add public ipv6 address");
                }
                if let Err(err) = nic
                    .add_ipv6_route_with_cost(Ipv6Addr::UNSPECIFIED, 0, Some(5))
                    .await
                {
                    tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to add default public ipv6 route");
                }
            }

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = peer_mgr.get_my_public_ipv6_addr().await;
                        GlobalCtxEvent::PublicIpv6Changed(current_addr, latest)
                    }
                };

                let (old, new) = match event {
                    GlobalCtxEvent::PublicIpv6Changed(old, new) => (old, new),
                    _ => continue,
                };

                current_addr = new;
                let nic = nic.lock().await;
                if let Err(err) = nic.link_up().await {
                    tracing::warn!(?err, "failed to bring public ipv6 nic link up");
                }
                if let Some(old) = old {
                    if let Err(err) = nic.remove_ipv6_route(Ipv6Addr::UNSPECIFIED, 0).await {
                        tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to remove default public ipv6 route");
                    }
                    if let Err(err) = nic.remove_ipv6(Some(old)).await {
                        tracing::warn!(addr = ?old, ?err, "failed to remove old public ipv6 address");
                    }
                }
                if let Some(new) = new {
                    if let Err(err) = nic.add_ipv6(new.address(), new.network_length() as i32).await
                    {
                        tracing::warn!(addr = ?new, ?err, "failed to add public ipv6 address");
                    }
                    if let Err(err) = nic
                        .add_ipv6_route_with_cost(Ipv6Addr::UNSPECIFIED, 0, Some(5))
                        .await
                    {
                        tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to add default public ipv6 route");
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn run(
        &mut self,
        ipv4_addr: Option<cidr::Ipv4Inet>,
        ipv6_addr: Option<cidr::Ipv6Inet>,
    ) -> Result<(), Error> {
        let (rx, tx) = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev().await {
                Ok(ret) => {
                    #[cfg(target_os = "windows")]
                    {
                        let dev_name = self.global_ctx.get_flags().dev_name;
                        let _ = RegistryManager::reg_change_catrgory_in_profile(&dev_name);
                    }

                    #[cfg(any(
                        all(target_os = "macos", not(feature = "macos-ne")),
                        target_os = "freebsd"
                    ))]
                    {
                        // remove the 10.0.0.0/24 route (which is added by rust-tun by default)
                        let _ = nic
                            .ifcfg
                            .remove_ipv4_route(nic.ifname(), "10.0.0.0".parse().unwrap(), 24)
                            .await;
                    }

                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceReady(nic.ifname().to_string()));
                    ret
                }
                Err(err) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceError(err.to_string()));
                    return Err(err);
                }
            }
        };

        self.do_forward_nic_to_peers(rx)?;
        self.do_forward_peers_to_nic(tx);

        // Assign IPv4 address if provided
        if let Some(ipv4_addr) = ipv4_addr {
            self.assign_ipv4_to_tun_device(ipv4_addr).await?;
            #[cfg(target_os = "windows")]
            self.start_windows_udp_broadcast_relay(ipv4_addr);
        }

        // Assign IPv6 address if provided
        if let Some(ipv6_addr) = ipv6_addr {
            self.assign_ipv6_to_tun_device(ipv6_addr).await?;
        }

        self.run_proxy_cidrs_route_updater().await?;
        self.run_public_ipv6_route_updater().await?;
        // Keep the updater running so runtime config patches can enable auto mode
        // without recreating the NIC.
        self.run_public_ipv6_addr_updater().await?;

        Ok(())
    }

    #[cfg(mobile)]
    pub async fn run_for_mobile(&mut self, tun_fd: std::os::fd::RawFd) -> Result<(), Error> {
        let (rx, tx) = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev_for_mobile(tun_fd).await {
                Ok(ret) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceReady(nic.ifname().to_string()));
                    ret
                }
                Err(err) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceError(err.to_string()));
                    return Err(err);
                }
            }
        };

        self.do_forward_nic_to_peers(rx)?;
        self.do_forward_peers_to_nic(tx);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{error::Error, global_ctx::tests::get_mock_global_ctx};

    use super::VirtualNic;

    async fn run_test_helper() -> Result<VirtualNic, Error> {
        let mut dev = VirtualNic::new(get_mock_global_ctx());
        let (_rx, _tx) = dev.create_dev().await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        dev.link_up().await?;
        dev.remove_ip(None).await?;
        dev.add_ip("10.144.111.1".parse().unwrap(), 24).await?;
        Ok(dev)
    }

    #[tokio::test]
    async fn tun_test() {
        let _dev = run_test_helper().await.unwrap();

        // let mut stream = nic.pin_recv_stream();
        // while let Some(item) = stream.next().await {
        //     println!("item: {:?}", item);
        // }

        // let framed = dev.into_framed();
        // let (mut s, mut b) = framed.split();
        // loop {
        //     let tmp = b.next().await.unwrap().unwrap();
        //     let tmp = EthernetPacket::new(tmp.get_bytes());
        //     println!("ret: {:?}", tmp.unwrap());
        // }
    }
}
