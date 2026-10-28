use std::{
    collections::BTreeSet,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::common::{
    error::Error,
    global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    ifcfg::{IfConfiger, IfConfiguerTrait},
    netns::NetNS,
};

use easytier_core::{
    host::packet::{HostPacket, HostPacketReceiver},
    instance::CorePacketPlane,
    packet::{TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
    tunnel::{
        StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
        framed::{FramedWriter, ZCPacketToBytes, reserve_buf},
        wrapper::TunnelWrapper,
    },
};

use byteorder::WriteBytesExt as _;
use bytes::{Buf, BufMut, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{SinkExt, Stream, StreamExt, lock::BiLock, ready};
use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
#[cfg(target_os = "windows")]
use tokio_util::task::AbortOnDropHandle;
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};
use zerocopy::{NativeEndian, NetworkEndian};

#[cfg(target_os = "windows")]
use crate::common::ifcfg::RegistryManager;

use super::shared_virtual_nic::{ArcSharedVirtualNicRegistry, SharedVirtualNicMember};

pin_project! {
    pub struct TunStream {
        #[pin]
        l: BiLock<AsyncDevice>,
        cur_buf: BytesMut,
        has_packet_info: bool,
        payload_offset: usize,
    }
}

impl TunStream {
    pub fn new(l: BiLock<AsyncDevice>, has_packet_info: bool) -> Self {
        let mut payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset;
        if has_packet_info {
            payload_offset -= 4;
        }
        Self {
            l,
            cur_buf: BytesMut::new(),
            has_packet_info,
            payload_offset,
        }
    }
}

impl Stream for TunStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<StreamItem>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        reserve_buf(self_mut.cur_buf, 2500, 4 * 1024);
        if self_mut.cur_buf.is_empty() {
            unsafe {
                self_mut.cur_buf.set_len(*self_mut.payload_offset);
            }
        }
        let buf = self_mut.cur_buf.chunk_mut().as_mut_ptr();
        let buf = unsafe { std::slice::from_raw_parts_mut(buf, 2500) };
        let mut buf = ReadBuf::new(buf);

        let ret = ready!(g.as_pin_mut().poll_read(cx, &mut buf));
        let len = buf.filled().len();
        if len == 0 {
            return Poll::Ready(None);
        }
        unsafe { self_mut.cur_buf.advance_mut(len + TAIL_RESERVED_SIZE) };

        let mut ret_buf = self_mut.cur_buf.split();
        let cur_len = ret_buf.len();
        ret_buf.truncate(cur_len - TAIL_RESERVED_SIZE);

        match ret {
            Ok(_) => Poll::Ready(Some(Ok(ZCPacket::new_from_buf(ret_buf, ZCPacketType::NIC)))),
            Err(err) => {
                tracing::error!("tun stream error: {:?}", err);
                Poll::Ready(None)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
enum PacketProtocol {
    #[default]
    IPv4,
    IPv6,
    Other,
}

// Note: the protocol in the packet information header is platform dependent.
impl PacketProtocol {
    #[cfg(any(target_os = "linux", target_os = "android", target_env = "ohos"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::ETH_P_IP as u16),
            PacketProtocol::IPv6 => Ok(libc::ETH_P_IPV6 as u16),
            PacketProtocol::Other => Err(io::Error::other("neither an IPv4 nor IPv6 packet")),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::PF_INET as u16),
            PacketProtocol::IPv6 => Ok(libc::PF_INET6 as u16),
            PacketProtocol::Other => Err(io::Error::other("neither an IPv4 nor IPv6 packet")),
        }
    }

    #[cfg(target_os = "windows")]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        unimplemented!()
    }
}

/// Infer the protocol based on the first nibble in the packet buffer.
fn infer_proto(buf: &[u8]) -> PacketProtocol {
    match buf[0] >> 4 {
        4 => PacketProtocol::IPv4,
        6 => PacketProtocol::IPv6,
        _ => PacketProtocol::Other,
    }
}

struct TunZCPacketToBytes {
    has_packet_info: bool,
}

impl TunZCPacketToBytes {
    pub fn new(has_packet_info: bool) -> Self {
        Self { has_packet_info }
    }

    pub fn fill_packet_info(
        &self,
        mut buf: &mut [u8],
        proto: PacketProtocol,
    ) -> Result<(), io::Error> {
        // flags is always 0
        buf.write_u16::<NativeEndian>(0)?;
        // write the protocol as network byte order
        buf.write_u16::<NetworkEndian>(proto.into_pi_field()?)?;
        Ok(())
    }
}

impl ZCPacketToBytes for TunZCPacketToBytes {
    fn zcpacket_into_bytes(&self, zc_packet: ZCPacket) -> Result<Bytes, TunnelError> {
        let payload_offset = zc_packet.payload_offset();
        let mut inner = zc_packet.inner();
        // we have peer manager header, so payload offset must larger than 4
        assert!(payload_offset >= 4);

        let ret = if self.has_packet_info {
            inner.advance(payload_offset - 4);
            let proto = infer_proto(&inner[4..]);
            self.fill_packet_info(&mut inner[0..4], proto)?;
            inner
        } else {
            inner.advance(payload_offset);
            inner
        };

        tracing::debug!(?ret, ?payload_offset, "convert zc packet to tun packet");

        Ok(ret.into())
    }
}

pin_project! {
    pub struct TunAsyncWrite {
        #[pin]
        l: BiLock<AsyncDevice>,
    }
}

impl AsyncWrite for TunAsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

pub struct VirtualNicConfig {
    dev_name: String,
    mtu: u32,
    net_ns: NetNS,
}

impl VirtualNicConfig {
    pub fn new(dev_name: String, mtu: u32, net_ns: NetNS) -> Self {
        Self {
            dev_name,
            mtu,
            net_ns,
        }
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    pub fn net_ns_name(&self) -> Option<String> {
        self.net_ns.name()
    }
}

pub struct VirtualNic {
    config: VirtualNicConfig,

    ifname: Option<String>,
    ifcfg: Box<dyn IfConfiguerTrait + Send + Sync + 'static>,

    // Keep the name reserved through firewall cleanup. The device
    // itself may already have disappeared when its forwarding tasks stop.
    #[cfg(target_os = "windows")]
    name_reservation: Option<std::os::windows::io::OwnedHandle>,
}

impl Drop for VirtualNic {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        self.clear_windows_device();
    }
}

impl VirtualNic {
    #[cfg(target_os = "windows")]
    pub(crate) fn clear_windows_device(&mut self) {
        if let Some(ifname) = self.ifname.take() {
            // Try to clean up firewall rules, but don't panic in destructor
            if let Err(error) = crate::arch::windows::remove_interface_firewall_rules(&ifname) {
                tracing::warn!(
                    %error,
                    "failed to remove firewall rules for interface {}",
                    ifname
                );
            }
        }
        self.name_reservation.take();
    }

    pub fn new(config: VirtualNicConfig) -> Self {
        Self {
            config,
            ifname: None,
            ifcfg: Box::new(IfConfiger::default()),
            #[cfg(target_os = "windows")]
            name_reservation: None,
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
            tracing::warn!("TUN kernel module may not be available.");
            tracing::warn!("\tYou may need to load it with: sudo modprobe tun.");
        }

        // Try to create /dev/net directory if it doesn't exist
        if tokio::fs::metadata(TUN_DIR_PATH).await.is_err() {
            if let Err(error) = tokio::fs::create_dir_all(TUN_DIR_PATH).await {
                tracing::warn!(
                    ?error,
                    "Failed to create directory {}. TUN device creation may fail. Continuing anyway.",
                    TUN_DIR_PATH
                );
                tracing::warn!(
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
                tracing::info!("Successfully created TUN device node {}", TUN_DEV_PATH);
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
        tracing::info!(
            "Possible solutions:\
            \n\t1. Run with root privileges: sudo ./easytier-core [options]\
            \n\t2. Manually create TUN device: sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200\
            \n\t3. Load TUN kernel module: sudo modprobe tun\
            \n\t4. Use --no-tun flag if TUN functionality is not needed\
            \n\t5. Check if your system/container supports TUN devices\
            \nNote: TUN functionality may still work if the kernel supports dynamic device creation."
        );
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

    async fn create_tun(&mut self) -> Result<tun::platform::Device, Error> {
        let mut config = Configuration::default();
        config.layer(Layer::L3);

        // FreeBSD specific: Check and restore TUN interfaces before creating new one
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.config.dev_name.clone();

            if !dev_name.is_empty() {
                // Restore TUN interface name if needed, ignoring errors as it's not critical
                let _ = Self::restore_tun_name(&dev_name).await;
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check and create TUN device node if necessary (Linux only)
            Self::ensure_tun_device_node().await;

            let dev_name = self.config.dev_name.clone();
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
            if self.name_reservation.is_none() {
                let (name, reservation) =
                    crate::arch::windows::reserve_tun_name(&self.config.dev_name)?;
                self.config.dev_name = name;
                self.name_reservation = Some(reservation);
            }
            let dev_name = self.config.dev_name.clone();

            match crate::arch::windows::add_self_to_firewall_allowlist() {
                Ok(_) => tracing::info!("add_self_to_firewall_allowlist successful!"),
                Err(error) => {
                    tracing::warn!(%error, "Failed to add Easytier to firewall allowlist, Subnet proxy and KCP proxy may not work properly.");
                    tracing::warn!(
                        "You can add firewall rules manually, or use --use-smoltcp to run with user-space TCP/IP stack."
                    );
                }
            }

            config.tun_name(&dev_name);
            config.platform_config(|config| {
                // Wintun uses the GUID for Windows network profile identity.
                // Include the name so explicitly shared NICs use the same GUID.
                let identity = format!("https://easytier.rs/wintun/{}", dev_name.to_lowercase());
                config.device_guid(
                    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, identity.as_bytes()).as_u128(),
                );
                config.skip_config(true);
                config.ring_cap(Some(std::cmp::min(
                    config.min_ring_cap() * 32,
                    config.max_ring_cap(),
                )));
            });
        }

        config.up();

        let _g = self.config.net_ns.guard();
        Ok(tun::create(&config)?)
    }

    #[cfg(any(mobile, all(test, unix)))]
    pub fn set_mobile_tun_fd_name(&mut self, tun_fd: std::os::fd::RawFd) {
        self.ifname = Some(format!("tunfd_{}", tun_fd));
    }

    #[cfg(any(mobile, all(test, unix)))]
    pub async fn create_dev_for_mobile(
        &mut self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<Box<dyn Tunnel>, Error> {
        tracing::debug!(%tun_fd);
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

        let has_packet_info = cfg!(any(
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne")
        ));
        let dev = tun::create(&config)?;
        let dev = AsyncDevice::new(dev)?;
        let (a, b) = BiLock::new(dev);
        let ft = TunnelWrapper::new(
            TunStream::new(a, has_packet_info),
            FramedWriter::new_with_converter(
                TunAsyncWrite { l: b },
                TunZCPacketToBytes::new(has_packet_info),
            ),
            None,
        );

        self.set_mobile_tun_fd_name(tun_fd);

        Ok(Box::new(ft))
    }

    pub async fn create_dev(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        let dev = self.create_tun().await?;

        #[cfg(not(target_os = "freebsd"))]
        let ifname = dev.tun_name()?;

        #[cfg(target_os = "freebsd")]
        let mut ifname = dev.tun_name()?;
        self.ifcfg.wait_interface_show(ifname.as_str()).await?;

        // FreeBSD TUN interface rename functionality
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.config.dev_name.clone();

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

        {
            // set mtu by ourselves, rust-tun does not handle it correctly on windows
            let _g = self.config.net_ns.guard();
            self.ifcfg.set_mtu(ifname.as_str(), self.config.mtu).await?;
        }

        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            // remove the 10.0.0.0/24 route (which is added by rust-tun by default)
            let _ = self
                .ifcfg
                .remove_ipv4_route(&ifname, "10.0.0.0".parse().unwrap(), 24)
                .await;
        }

        let has_packet_info = cfg!(all(target_os = "macos", not(feature = "macos-ne")));
        let (a, b) = BiLock::new(dev);
        let ft = TunnelWrapper::new(
            TunStream::new(a, has_packet_info),
            FramedWriter::new_with_converter(
                TunAsyncWrite { l: b },
                TunZCPacketToBytes::new(has_packet_info),
            ),
            None,
        );

        self.ifname = Some(ifname.to_owned());

        #[cfg(target_os = "windows")]
        {
            // Add firewall rules for virtual NIC interface to allow all traffic
            match crate::arch::windows::add_interface_to_firewall_allowlist(&ifname) {
                Ok(_) => {
                    tracing::info!(
                        "Successfully configured Windows Firewall for interface: {}",
                        ifname
                    );
                    tracing::info!(
                        "All protocols (TCP/UDP/ICMP) are now allowed on interface: {}",
                        ifname
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "Failed to configure Windows Firewall for interface {}\
                    \n\tThis may cause connectivity issues with ping and other network functions.\
                    \n\tPlease run as Administrator or manually configure Windows Firewall.\
                    \n\tAlternatively, you can disable Windows Firewall for testing purposes.", ifname);
                }
            }
        }

        Ok(Box::new(ft))
    }

    pub fn ifname(&self) -> &str {
        self.ifname.as_ref().unwrap().as_str()
    }

    pub async fn link_up(&self) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg.set_link_status(self.ifname(), true).await?;
        Ok(())
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        self.add_route_with_cost(address, cidr, None).await
    }

    pub async fn add_route_with_cost(
        &self,
        address: Ipv4Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        self.add_route_with_cost_and_source_hint(address, cidr, cost, None)
            .await
    }

    pub async fn add_route_with_cost_and_source_hint(
        &self,
        address: Ipv4Addr,
        cidr: u8,
        cost: Option<i32>,
        source_hint: Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg
            .add_ipv4_route_with_source_hint(self.ifname(), address, cidr, cost, source_hint)
            .await?;
        Ok(())
    }

    pub async fn remove_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg
            .remove_ipv4_route(self.ifname(), address, cidr)
            .await?;
        Ok(())
    }

    pub async fn remove_route_with_cost_and_source_hint(
        &self,
        address: Ipv4Addr,
        cidr: u8,
        cost: Option<i32>,
        source_hint: Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg
            .remove_ipv4_route_with_cost_and_source_hint(
                self.ifname(),
                address,
                cidr,
                cost,
                source_hint,
            )
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
        let _g = self.config.net_ns.guard();
        self.ifcfg
            .add_ipv6_route(self.ifname(), address, cidr, cost)
            .await?;
        Ok(())
    }

    pub async fn remove_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg
            .remove_ipv6_route(self.ifname(), address, cidr)
            .await?;
        Ok(())
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg.remove_ip(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg.remove_ipv6(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg
            .add_ipv4_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg
            .add_ipv6_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub async fn set_mtu(&self, mtu: u32) -> Result<(), Error> {
        let _g = self.config.net_ns.guard();
        self.ifcfg.set_mtu(self.ifname(), mtu).await?;
        Ok(())
    }

    pub fn configured_mtu(&self) -> u32 {
        self.config.mtu
    }

    #[cfg(test)]
    pub(crate) fn set_ifname_for_test(&mut self, ifname: String) {
        self.ifname = Some(ifname);
    }

    #[cfg(test)]
    pub(crate) fn set_ifcfg_for_test(
        &mut self,
        ifcfg: Box<dyn IfConfiguerTrait + Send + Sync + 'static>,
    ) {
        self.ifcfg = ifcfg;
    }

    pub fn get_ifcfg(&self) -> IfConfiger {
        IfConfiger::default()
    }
}

#[derive(Clone)]
pub enum NicBackend {
    Dedicated(Arc<Mutex<VirtualNic>>),
    Shared(SharedVirtualNicMember),
}

impl NicBackend {
    pub async fn create_dev(&self) -> Result<Box<dyn Tunnel>, Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.create_dev().await,
            Self::Shared(member) => member.create_dev().await,
        }
    }

    #[cfg(mobile)]
    pub async fn create_dev_for_mobile(
        &self,
        tun_fd: std::os::fd::RawFd,
        replace_tun_fd: bool,
    ) -> Result<Box<dyn Tunnel>, Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.create_dev_for_mobile(tun_fd).await,
            Self::Shared(member) => member.create_dev_for_mobile(tun_fd, replace_tun_fd).await,
        }
    }

    pub async fn ifname(&self) -> Option<String> {
        match self {
            Self::Dedicated(nic) => nic
                .lock()
                .await
                .ifname
                .as_ref()
                .map(|ifname| ifname.to_owned()),
            Self::Shared(member) => {
                let shared_nic = member.shared_nic();
                let nic = {
                    let shared_nic = shared_nic.lock().await;
                    shared_nic.nic()
                };
                nic.lock()
                    .await
                    .ifname
                    .as_ref()
                    .map(|ifname| ifname.to_owned())
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    /// Returns a raw ifcfg handle and interface name for platform cleanup.
    ///
    /// This does not carry `VirtualNic`'s netns guard. Use the typed
    /// `NicBackend` methods for normal IP and route configuration.
    pub async fn ifcfg_and_ifname(&self) -> Result<(IfConfiger, String), Error> {
        match self {
            Self::Dedicated(nic) => {
                let nic = nic.lock().await;
                Ok((nic.get_ifcfg(), nic.ifname().to_owned()))
            }
            Self::Shared(member) => member.ifcfg_and_ifname().await,
        }
    }

    pub async fn link_up(&self) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.link_up().await,
            Self::Shared(member) => member.link_up().await,
        }
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.add_route(address, cidr).await,
            Self::Shared(member) => member.add_route(address, cidr).await,
        }
    }

    pub async fn add_route_with_cost(
        &self,
        address: Ipv4Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => {
                nic.lock()
                    .await
                    .add_route_with_cost(address, cidr, cost)
                    .await
            }
            Self::Shared(member) => member.add_route_with_cost(address, cidr, cost).await,
        }
    }

    pub async fn remove_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.remove_route(address, cidr).await,
            Self::Shared(member) => member.remove_route(address, cidr).await,
        }
    }

    pub async fn add_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.add_ipv6_route(address, cidr).await,
            Self::Shared(member) => member.add_ipv6_route(address, cidr).await,
        }
    }

    pub async fn add_ipv6_route_with_cost(
        &self,
        address: Ipv6Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => {
                nic.lock()
                    .await
                    .add_ipv6_route_with_cost(address, cidr, cost)
                    .await
            }
            Self::Shared(member) => member.add_ipv6_route_with_cost(address, cidr, cost).await,
        }
    }

    pub async fn remove_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.remove_ipv6_route(address, cidr).await,
            Self::Shared(member) => member.remove_ipv6_route(address, cidr).await,
        }
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.remove_ip(ip).await,
            Self::Shared(member) => member.remove_ip(ip).await,
        }
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.remove_ipv6(ip).await,
            Self::Shared(member) => member.remove_ipv6(ip).await,
        }
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.add_ip(ip, cidr).await,
            Self::Shared(member) => member.add_ip(ip, cidr).await,
        }
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        match self {
            Self::Dedicated(nic) => nic.lock().await.add_ipv6(ip, cidr).await,
            Self::Shared(member) => member.add_ipv6(ip, cidr).await,
        }
    }
}

pub struct NicCtx {
    global_ctx: ArcGlobalCtx,
    packet_plane: Arc<CorePacketPlane>,
    peer_packet_receiver: Arc<Mutex<HostPacketReceiver>>,

    close_notifier: Arc<Notify>,

    backend: NicBackend,
    tasks: JoinSet<()>,

    #[cfg(target_os = "windows")]
    windows_udp_broadcast_relay: Option<AbortOnDropHandle<()>>,
}

impl NicCtx {
    fn virtual_nic_config(global_ctx: &ArcGlobalCtx) -> VirtualNicConfig {
        let flags = global_ctx.get_flags();
        let mut mtu = flags.mtu;
        if flags.enable_encryption {
            mtu -= 20;
        }

        let dev_name = flags.dev_name;

        VirtualNicConfig::new(dev_name, mtu, global_ctx.net_ns.clone())
    }

    pub(crate) fn shared_route_backend_for_dns(&self) -> Option<NicBackend> {
        match self.backend {
            NicBackend::Dedicated(_) => None,
            NicBackend::Shared(_) => Some(self.backend.clone()),
        }
    }

    fn new_with_backend(
        global_ctx: ArcGlobalCtx,
        packet_plane: Arc<CorePacketPlane>,
        peer_packet_receiver: Arc<Mutex<HostPacketReceiver>>,
        close_notifier: Arc<Notify>,
        backend: NicBackend,
    ) -> Self {
        NicCtx {
            global_ctx: global_ctx.clone(),
            packet_plane,
            peer_packet_receiver,

            close_notifier,

            backend,
            tasks: JoinSet::new(),

            #[cfg(target_os = "windows")]
            windows_udp_broadcast_relay: None,
        }
    }

    pub(crate) async fn new(
        global_ctx: ArcGlobalCtx,
        packet_plane: Arc<CorePacketPlane>,
        peer_packet_receiver: Arc<Mutex<HostPacketReceiver>>,
        close_notifier: Arc<Notify>,
        registry: ArcSharedVirtualNicRegistry,
    ) -> Self {
        let nic_config = Self::virtual_nic_config(&global_ctx);
        #[cfg(mobile)]
        let nic_config = VirtualNicConfig {
            dev_name: String::new(),
            net_ns: NetNS::new(None),
            ..nic_config
        };
        // Only an explicitly configured name opts into sharing.
        let backend = if cfg!(mobile) || !global_ctx.get_flags().dev_name.is_empty() {
            NicBackend::Shared(registry.lock().await.create_member(
                nic_config.dev_name.clone(),
                nic_config,
                global_ctx.get_id(),
                close_notifier.clone(),
            ))
        } else {
            NicBackend::Dedicated(Arc::new(Mutex::new(VirtualNic::new(nic_config))))
        };

        Self::new_with_backend(
            global_ctx,
            packet_plane,
            peer_packet_receiver,
            close_notifier,
            backend,
        )
    }

    pub async fn ifname(&self) -> Option<String> {
        self.backend.ifname().await
    }

    pub(crate) async fn shutdown(&mut self) {
        // The forwarding tasks own the TUN stream and sink. Wait until both
        // release the device before another NIC with the same name is created.
        self.tasks.shutdown().await;
    }

    async fn tun_ifname(&self) -> Result<String, Error> {
        self.backend
            .ifname()
            .await
            .ok_or_else(|| anyhow::anyhow!("tun device has no interface name").into())
    }

    pub async fn assign_ipv4_to_tun_device(&self, ipv4_addr: cidr::Ipv4Inet) -> Result<(), Error> {
        self.backend.link_up().await?;
        self.backend.remove_ip(None).await?;
        self.backend
            .add_ip(ipv4_addr.address(), ipv4_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            self.backend
                .add_route(ipv4_addr.first_address(), ipv4_addr.network_length())
                .await?;
        }
        Ok(())
    }

    pub async fn assign_ipv6_to_tun_device(&self, ipv6_addr: cidr::Ipv6Inet) -> Result<(), Error> {
        self.backend.link_up().await?;
        self.backend.remove_ipv6(None).await?;
        self.backend
            .add_ipv6(ipv6_addr.address(), ipv6_addr.network_length() as i32)
            .await?;
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            self.backend
                .add_ipv6_route(ipv6_addr.first_address(), ipv6_addr.network_length())
                .await?;
        }
        Ok(())
    }

    async fn do_forward_nic_to_peers(ret: ZCPacket, packet_plane: &CorePacketPlane) {
        if ret.payload().is_empty() {
            return;
        }
        tracing::trace!(
            ?ret,
            "[USER_PACKET] recv new packet from tun device and forward to peers."
        );
        if let Err(error) = packet_plane
            .send_ip_packet(HostPacket::from_tun_packet(ret))
            .await
        {
            tracing::trace!(?error, "[USER_PACKET] send_msg failed");
        }
    }

    fn do_forward_nic_to_peers_task(
        &mut self,
        mut stream: Pin<Box<dyn ZCPacketStream>>,
    ) -> Result<(), Error> {
        // read from nic and write to corresponding tunnel
        let packet_plane = self.packet_plane.clone();
        let close_notifier = self.close_notifier.clone();
        self.tasks.spawn(async move {
            while let Some(ret) = stream.next().await {
                if ret.is_err() {
                    tracing::error!("read from nic failed: {:?}", ret);
                    break;
                }
                Self::do_forward_nic_to_peers(ret.unwrap(), packet_plane.as_ref()).await;
            }
            close_notifier.notify_one();
            tracing::error!("nic closed when recving from it");
        });

        Ok(())
    }

    fn do_forward_peers_to_nic(&mut self, mut sink: Pin<Box<dyn ZCPacketSink>>) {
        let channel = self.peer_packet_receiver.clone();
        let close_notifier = self.close_notifier.clone();
        self.tasks.spawn(async move {
            // unlock until coroutine finished
            let mut channel = channel.lock().await;
            while let Some(packet) = channel.recv().await {
                tracing::trace!(
                    "[USER_PACKET] forward packet from peers to nic. packet: {:?}",
                    packet
                );
                let ret = sink.send(packet.into_tun_packet()).await;
                if ret.is_err() {
                    tracing::error!(?ret, "do_forward_tunnel_to_nic sink error");
                }
            }
            close_notifier.notify_one();
            tracing::error!("nic closed when sending to it");
        });
    }

    fn start_tunnel_forwarding(&mut self, tunnel: Box<dyn Tunnel>) -> Result<(), Error> {
        let (stream, sink) = tunnel.split();

        self.do_forward_nic_to_peers_task(stream)?;
        self.do_forward_peers_to_nic(sink);

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn start_windows_udp_broadcast_relay(&mut self, virtual_ipv4: Ipv4Inet) {
        if !self.global_ctx.get_flags().enable_udp_broadcast_relay {
            return;
        }

        match super::windows_udp_broadcast::start(
            self.packet_plane.clone(),
            self.global_ctx.clone(),
            virtual_ipv4,
        ) {
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
        backend: &NicBackend,
        cur_proxy_cidrs: &mut BTreeSet<cidr::Ipv4Cidr>,
        added: Vec<cidr::Ipv4Cidr>,
        removed: Vec<cidr::Ipv4Cidr>,
    ) -> Result<(), Error> {
        tracing::debug!(?added, ?removed, "applying proxy_cidrs route changes");

        // Remove routes
        for cidr in removed {
            if !cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            let ret = backend
                .remove_route(cidr.first_address(), cidr.network_length())
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
        let mut first_error = None;
        for cidr in added {
            if cur_proxy_cidrs.contains(&cidr) {
                continue;
            }
            match backend
                .add_route(cidr.first_address(), cidr.network_length())
                .await
            {
                Ok(()) => {
                    cur_proxy_cidrs.insert(cidr);
                }
                Err(err) => {
                    tracing::error!(?cidr, ?err, "add route failed");
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    async fn apply_public_ipv6_route_changes(
        backend: &NicBackend,
        cur_routes: &mut BTreeSet<cidr::Ipv6Inet>,
        added: Vec<cidr::Ipv6Inet>,
        removed: Vec<cidr::Ipv6Inet>,
    ) {
        for route in removed {
            if !cur_routes.contains(&route) {
                continue;
            }
            let ret = backend
                .remove_ipv6_route(route.address(), route.network_length())
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
            let ret = backend
                .add_ipv6_route(route.address(), route.network_length())
                .await;
            if ret.is_err() {
                tracing::trace!(route = ?route, err = ?ret, "add public ipv6 route failed");
            } else {
                cur_routes.insert(route);
            }
        }
    }

    async fn run_proxy_cidrs_route_updater(&mut self) -> Result<(), Error> {
        let packet_plane = self.packet_plane.clone();
        let global_ctx = self.global_ctx.clone();
        let backend = self.backend.clone();
        let mut event_receiver = global_ctx.subscribe();

        let mut cur_proxy_cidrs = BTreeSet::<cidr::Ipv4Cidr>::new();

        // Initial sync: get current proxy_cidrs state and apply routes
        let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await else {
            tracing::error!("proxy CIDR monitor host is unavailable");
            return Ok(());
        };
        if let Err(err) =
            Self::apply_route_changes(&backend, &mut cur_proxy_cidrs, diff.added, diff.removed)
                .await
            && matches!(&backend, NicBackend::Shared(_))
        {
            return Err(err);
        }

        self.tasks.spawn(async move {
            loop {
                let should_sync = match event_receiver.recv().await {
                    Ok(GlobalCtxEvent::ProxyCidrsUpdated(_, _)) => true,
                    Ok(_) => false,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("event bus closed, stopping proxy_cidrs route updater");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!(
                            "event bus lagged in proxy_cidrs route updater, doing full sync"
                        );
                        event_receiver = event_receiver.resubscribe();
                        true
                    }
                };
                if !should_sync {
                    continue;
                }

                // Full sync also retries routes that previously failed to apply.
                let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await else {
                    tracing::error!("proxy CIDR monitor host is unavailable");
                    return;
                };

                if let Err(err) = Self::apply_route_changes(
                    &backend,
                    &mut cur_proxy_cidrs,
                    diff.added,
                    diff.removed,
                )
                .await
                {
                    tracing::error!(?err, "failed to update proxy CIDR routes");
                }
            }
        });

        Ok(())
    }

    async fn run_public_ipv6_route_updater(&mut self) -> Result<(), Error> {
        let packet_plane = self.packet_plane.clone();
        let global_ctx = self.global_ctx.clone();
        let backend = self.backend.clone();
        let mut event_receiver = global_ctx.subscribe();

        let mut cur_routes = BTreeSet::<cidr::Ipv6Inet>::new();
        let initial_routes = packet_plane.public_ipv6_routes().await;
        let initial_added = initial_routes.iter().copied().collect::<Vec<_>>();
        Self::apply_public_ipv6_route_changes(&backend, &mut cur_routes, initial_added, Vec::new())
            .await;

        self.tasks.spawn(async move {
            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = packet_plane.public_ipv6_routes().await;
                        let added = latest.difference(&cur_routes).copied().collect::<Vec<_>>();
                        let removed = cur_routes.difference(&latest).copied().collect::<Vec<_>>();
                        GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed)
                    }
                };

                let (added, removed) = match event {
                    GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed) => (added, removed),
                    _ => continue,
                };

                Self::apply_public_ipv6_route_changes(&backend, &mut cur_routes, added, removed)
                    .await;
            }
        });

        Ok(())
    }

    async fn run_public_ipv6_addr_updater(&mut self) -> Result<(), Error> {
        let packet_plane = self.packet_plane.clone();
        let global_ctx = self.global_ctx.clone();
        let backend = self.backend.clone();
        let mut event_receiver = global_ctx.subscribe();

        let mut current_addr = packet_plane.public_ipv6_addr().await;
        if let Some(addr) = current_addr {
            if let Err(err) = backend.link_up().await {
                tracing::warn!(?err, "failed to bring public ipv6 nic link up");
            }
            if let Err(err) = backend
                .add_ipv6(addr.address(), addr.network_length() as i32)
                .await
            {
                tracing::warn!(addr = ?addr, ?err, "failed to add public ipv6 address");
            }
            if let Err(err) = backend
                .add_ipv6_route_with_cost(Ipv6Addr::UNSPECIFIED, 0, Some(5))
                .await
            {
                tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to add default public ipv6 route");
            }
        }

        self.tasks.spawn(async move {
            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = packet_plane.public_ipv6_addr().await;
                        GlobalCtxEvent::PublicIpv6Changed(current_addr, latest)
                    }
                };

                let (old, new) = match event {
                    GlobalCtxEvent::PublicIpv6Changed(old, new) => (old, new),
                    _ => continue,
                };

                current_addr = new;
                if let Err(err) = backend.link_up().await {
                    tracing::warn!(?err, "failed to bring public ipv6 nic link up");
                }
                if let Some(old) = old {
                    if let Err(err) = backend
                        .remove_ipv6_route(Ipv6Addr::UNSPECIFIED, 0)
                        .await
                    {
                        tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to remove default public ipv6 route");
                    }
                    if let Err(err) = backend.remove_ipv6(Some(old)).await {
                        tracing::warn!(addr = ?old, ?err, "failed to remove old public ipv6 address");
                    }
                }
                if let Some(new) = new {
                    if let Err(err) = backend
                        .add_ipv6(new.address(), new.network_length() as i32)
                        .await
                    {
                        tracing::warn!(addr = ?new, ?err, "failed to add public ipv6 address");
                    }
                    if let Err(err) = backend
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
        let tunnel = match self.backend.create_dev().await {
            Ok(ret) => {
                let ifname = self.tun_ifname().await?;

                #[cfg(target_os = "windows")]
                {
                    let _ = RegistryManager::reg_change_catrgory_in_profile(&ifname);
                }

                self.global_ctx.set_tun_device_ready(ifname);
                ret
            }
            Err(err) => {
                self.global_ctx.set_tun_device_error(err.to_string());
                return Err(err);
            }
        };

        self.start_tunnel_forwarding(tunnel)?;

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

    #[cfg(any(mobile, test))]
    pub(crate) async fn mobile_tun_claims(
        global_ctx: &ArcGlobalCtx,
        packet_plane: &CorePacketPlane,
    ) -> super::shared_virtual_nic::SharedIfConfigClaims {
        use super::shared_virtual_nic::{SharedIfConfigClaims, SharedIpv4Route, SharedIpv6Route};
        let mut claims = SharedIfConfigClaims::default();
        claims.ipv4_addresses.extend(global_ctx.get_ipv4());
        claims.ipv6_addresses.extend(global_ctx.get_ipv6());
        if let Some(diff) = packet_plane.proxy_cidr_diff(&BTreeSet::new()).await {
            claims
                .ipv4_routes
                .extend(diff.current.into_iter().map(|route| {
                    SharedIpv4Route::new(route.first_address(), route.network_length(), None)
                }));
        }
        claims
            .ipv6_routes
            .extend(
                packet_plane
                    .public_ipv6_routes()
                    .await
                    .into_iter()
                    .map(|route| {
                        SharedIpv6Route::new(route.first_address(), route.network_length(), None)
                    }),
            );
        if let Some(address) = packet_plane.public_ipv6_addr().await {
            claims.ipv6_addresses.insert(address);
            claims
                .ipv6_routes
                .insert(SharedIpv6Route::new(Ipv6Addr::UNSPECIFIED, 0, Some(5)));
        }
        claims
    }

    #[cfg(mobile)]
    pub(crate) async fn current_mobile_tun_claims(
        &self,
    ) -> Option<super::shared_virtual_nic::SharedIfConfigClaims> {
        match &self.backend {
            NicBackend::Shared(member) => Some(member.claims().await),
            NicBackend::Dedicated(_) => None,
        }
    }

    #[cfg(any(mobile, test))]
    async fn apply_mobile_tun_claims(
        &self,
        claims: super::shared_virtual_nic::SharedIfConfigClaims,
    ) -> Result<(), Error> {
        let NicBackend::Shared(member) = &self.backend else {
            return Err(anyhow::anyhow!("mobile TUN requires a shared NIC").into());
        };
        member.replace_claims(claims).await
    }

    #[cfg(test)]
    async fn configure_mobile_tun(&mut self) -> Result<(), Error> {
        let claims = Self::mobile_tun_claims(&self.global_ctx, &self.packet_plane).await;
        self.apply_mobile_tun_claims(claims).await?;
        self.run_proxy_cidrs_route_updater().await?;
        self.run_public_ipv6_route_updater().await?;
        self.run_public_ipv6_addr_updater().await?;
        Ok(())
    }

    #[cfg(mobile)]
    pub async fn run_for_mobile(
        &mut self,
        tun_fd: std::os::fd::RawFd,
        replace_tun_fd: bool,
        claims: super::shared_virtual_nic::SharedIfConfigClaims,
    ) -> Result<(), Error> {
        // Reject the entire member configuration before touching the shared fd.
        self.apply_mobile_tun_claims(claims).await?;
        let (tunnel, ifname) = match self
            .backend
            .create_dev_for_mobile(tun_fd, replace_tun_fd)
            .await
        {
            Ok(ret) => {
                let ifname = self.tun_ifname().await?;
                (ret, ifname)
            }
            Err(err) => {
                self.global_ctx.set_tun_device_error(err.to_string());
                return Err(err);
            }
        };

        self.run_proxy_cidrs_route_updater().await?;
        self.run_public_ipv6_route_updater().await?;
        self.run_public_ipv6_addr_updater().await?;

        self.global_ctx.set_tun_device_ready(ifname);

        self.start_tunnel_forwarding(tunnel)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{error::Error, global_ctx::tests::get_mock_global_ctx};

    use super::{NicCtx, VirtualNic};

    #[cfg(target_os = "windows")]
    #[rstest::rstest]
    #[case(None)]
    #[case(Some("et_test_restart"))]
    #[tokio::test]
    #[ignore = "requires Administrator privileges and wintun.dll"]
    async fn windows_device_identity_survives_recreation(#[case] dev_name: Option<&str>) {
        use crate::{
            arch::windows::list_interface_firewall_rules,
            common::{
                config::{ConfigLoader, TomlConfigLoader},
                ifcfg::RegistryManager,
            },
            instance::test_instance::TestInstance,
        };
        use easytier_core::process_runtime::CoreProcessRuntime;

        let process = CoreProcessRuntime::new();
        let registry = TestInstance::new_shared_virtual_nic_registry();
        let new_instance = |config: TomlConfigLoader| {
            if let Some(dev_name) = dev_name {
                let mut flags = config.get_flags();
                flags.dev_name = dev_name.to_owned();
                config.set_flags(flags);
            }
            TestInstance::new_with_process_runtime_and_shared_virtual_nic_registry(
                config,
                process.clone(),
                registry.clone(),
            )
        };
        let config =
            TomlConfigLoader::new_from_str("ipv4 = \"198.18.26.1/30\"\nlisteners = []").unwrap();
        let mut first = new_instance(config);
        let saved_config = first.get_global_ctx().config.dump();
        first.run().await.unwrap();
        let name = first.get_global_ctx().get_tun_device_name().unwrap();
        let guid = RegistryManager::find_interface_guid(&name).unwrap();
        assert_eq!(list_interface_firewall_rules(&name).unwrap().len(), 8);
        // The resolved name is runtime state, not an explicit request to share
        // the device when this GlobalCtx next recreates its NIC.
        assert_eq!(
            first.get_global_ctx().get_flags().dev_name,
            dev_name.unwrap_or_default(),
        );
        assert_eq!(
            registry
                .lock()
                .await
                .get_by_dev_name_for_test(&name)
                .is_some(),
            dev_name.is_some(),
        );

        // Keep B running while A is stopped and recreated, as in issue #110.
        let other_config =
            TomlConfigLoader::new_from_str("ipv4 = \"198.18.27.1/30\"\nlisteners = []").unwrap();
        let mut other = new_instance(other_config);
        other.run().await.unwrap();
        let other_name = other.get_global_ctx().get_tun_device_name().unwrap();
        let other_guid = RegistryManager::find_interface_guid(&other_name).unwrap();
        if dev_name.is_some() {
            assert_eq!(name, other_name);
            assert_eq!(guid, other_guid);
        } else {
            assert_ne!(name, other_name);
            assert_ne!(guid, other_guid);
        }
        first.clear_resources().await;

        for _ in 0..10 {
            let config = TomlConfigLoader::new_from_str(&saved_config).unwrap();
            let mut restarted = new_instance(config);
            restarted.run().await.unwrap();
            assert_eq!(
                restarted.get_global_ctx().get_tun_device_name().unwrap(),
                name
            );
            assert_eq!(RegistryManager::find_interface_guid(&name).unwrap(), guid);
            assert_eq!(
                RegistryManager::find_interface_guid(&other_name).unwrap(),
                other_guid,
            );
            assert_eq!(list_interface_firewall_rules(&name).unwrap().len(), 8);
            restarted.clear_resources().await;
            assert_eq!(list_interface_firewall_rules(&other_name).unwrap().len(), 8);
            if dev_name.is_none() {
                assert!(list_interface_firewall_rules(&name).unwrap().is_empty());
            }
        }
        other.clear_resources().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !list_interface_firewall_rules(&other_name)
                .unwrap()
                .is_empty()
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn mobile_configuration_registers_ipv6_and_tracks_public_updates() {
        use std::{net::UdpSocket, process::Command, sync::Arc, time::Duration};

        use easytier_core::{
            host::packet::{HostPacket, HostPacketChannelSink, HostPacketReceiver},
            process_runtime::CoreProcessRuntime,
        };
        use futures::{FutureExt, StreamExt};
        use smoltcp::wire::{IpProtocol, Ipv6Packet};
        use tokio::sync::{Mutex, Notify, mpsc};

        use super::{IfConfiger, NicBackend, VirtualNicConfig};
        use crate::{
            common::{global_ctx::GlobalCtxEvent, ifcfg::IfConfiguerTrait, netns::NetNS},
            instance::{
                composition::{NativeCoreInstance, runtime_core_host_adapters},
                config::test_core_instance_config,
                shared_virtual_nic::SharedVirtualNicRegistry,
            },
        };

        let namespace = format!("mobile-{}", uuid::Uuid::new_v4());
        assert!(
            Command::new("ip")
                .args(["netns", "add", &namespace])
                .status()
                .unwrap()
                .success()
        );
        guarden::defer! {
            let _ = Command::new("ip")
                .args(["netns", "del", &namespace])
                .status();
        }
        let net_ns = NetNS::new(Some(namespace.clone()));
        // Avoid DAD probes and use an unowned source to test destination claims.
        {
            let _guard = net_ns.guard();
            std::fs::write("/proc/sys/net/ipv6/conf/default/accept_dad", "0").unwrap();
            // Keep automatic link-local traffic out of the member packet streams.
            std::fs::write("/proc/sys/net/ipv6/conf/default/addr_gen_mode", "1").unwrap();
            let ifcfg = IfConfiger::default();
            ifcfg.set_link_status("lo", true).await.unwrap();
            ifcfg
                .add_ipv6_ip("lo", "fdff::1".parse().unwrap(), 128)
                .await
                .unwrap();
        }
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv4(None);
        global_ctx.set_ipv6(Some("fd00::1/64".parse().unwrap()));
        let (packet_sink, packet_receiver) = mpsc::channel::<HostPacket>(1);
        let core = NativeCoreInstance::new(
            test_core_instance_config(&global_ctx),
            runtime_core_host_adapters(
                global_ctx.clone(),
                CoreProcessRuntime::new(),
                Arc::new(HostPacketChannelSink::new(packet_sink)),
            ),
        )
        .unwrap();
        let mut registry = SharedVirtualNicRegistry::new();
        let members = [1, 2].map(|id| {
            registry.create_member(
                "mobile-test".to_owned(),
                VirtualNicConfig::new("mobile-test".to_owned(), 1500, net_ns.clone()),
                uuid::Uuid::from_u128(id),
                Arc::new(Notify::new()),
            )
        });
        let (mut other_stream, _other_sink) = members[0].create_dev().await.unwrap().split();
        let (mut stream, _sink) = members[1].create_dev().await.unwrap().split();
        let mut nic = NicCtx::new_with_backend(
            global_ctx.clone(),
            core.packet_plane(),
            Arc::new(Mutex::new(HostPacketReceiver::new(packet_receiver))),
            Arc::new(Notify::new()),
            NicBackend::Shared(members[1].clone()),
        );

        nic.configure_mobile_tun().await.unwrap();
        // Claims are installed before start_tunnel_forwarding is called.
        let ifname = nic.tun_ifname().await.unwrap();
        assert!(
            net_ns
                .run(|| IfConfiger::list_addresses(&ifname))
                .unwrap()
                .contains(&"fd00::1/64".parse().unwrap())
        );
        // Linux completes IPv6 address activation asynchronously, even without DAD probes.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match net_ns.run(|| UdpSocket::bind("[fd00::1]:0")) {
                    Ok(_) => break,
                    Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(err) => panic!("failed to bind the configured IPv6 address: {err}"),
                }
            }
        })
        .await
        .unwrap();
        let route = "2001:db8:1::/64".parse().unwrap();
        let public_addr = "2001:db8:2::1/128".parse().unwrap();
        for (event, source, destination) in [
            (None, "fdff::1", "fd00::2"),
            (
                Some(GlobalCtxEvent::PublicIpv6RoutesUpdated(vec![route], vec![])),
                "fdff::1",
                "2001:db8:1::2",
            ),
            (
                Some(GlobalCtxEvent::PublicIpv6Changed(None, Some(public_addr))),
                "2001:db8:2::1",
                "2001:db8:3::2",
            ),
        ] {
            if let Some(event) = event {
                global_ctx.issue_event(event);
            }
            let source = source.parse::<std::net::Ipv6Addr>().unwrap();
            let destination = destination.parse::<std::net::Ipv6Addr>().unwrap();
            let shared_nic = members[1].shared_nic();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    // Do not race an updater's OS change and dispatcher publication.
                    let guard = shared_nic.lock().await;
                    let sent = net_ns.run(|| {
                        UdpSocket::bind((source, 0))?.send_to(b"mobile-ipv6", (destination, 12345))
                    });
                    drop(guard);
                    if sent.is_ok() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let packet = stream.next().await.unwrap().unwrap();
                let ipv6 = Ipv6Packet::new_checked(packet.payload()).unwrap();
                assert_eq!(ipv6.src_addr(), source);
                assert_eq!(ipv6.dst_addr(), destination);
                assert_eq!(ipv6.next_header(), IpProtocol::Udp);
                assert_eq!(&ipv6.payload()[8..], b"mobile-ipv6");
            })
            .await
            .unwrap();
            assert!(other_stream.next().now_or_never().is_none());
        }
    }

    async fn run_test_helper() -> Result<VirtualNic, Error> {
        let global_ctx = get_mock_global_ctx();
        let mut dev = VirtualNic::new(NicCtx::virtual_nic_config(&global_ctx));
        let _tunnel = dev.create_dev().await?;

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
