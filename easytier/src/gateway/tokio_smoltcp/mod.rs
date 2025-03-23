// most code is copied from https://github.com/spacemeowx2/tokio-smoltcp

//! An asynchronous wrapper for smoltcp.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};

use device::BufferDevice;
use futures::Future;
use reactor::Reactor;
pub use smoltcp;
use smoltcp::{
    iface::{Config, Interface, Routes},
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr},
};
pub use socket::{TcpListener, TcpStream, UdpSocket};
pub use socket_allocator::BufferSize;
use tokio::sync::Notify;

/// The async devices.
pub mod channel_device;
pub mod device;
mod reactor;
mod socket;
mod socket_allocator;

/// Can be used to create a forever timestamp in neighbor.
// The 60_000 is the same as NeighborCache::ENTRY_LIFETIME.
pub const FOREVER: Instant =
    Instant::from_micros_const(i64::max_value() - Duration::from_millis(60_000).micros() as i64);

pub struct Neighbor {
    pub protocol_addr: IpAddress,
    pub hardware_addr: HardwareAddress,
    pub timestamp: Instant,
}

/// A config for a `Net`.
///
/// This is used to configure the `Net`.
#[non_exhaustive]
pub struct NetConfig {
    pub interface_config: Config,
    pub ip_addr: IpCidr,
    pub gateway: Vec<IpAddress>,
    pub buffer_size: BufferSize,
}

impl NetConfig {
    pub fn new(interface_config: Config, ip_addr: IpCidr, gateway: Vec<IpAddress>) -> Self {
        Self {
            interface_config,
            ip_addr,
            gateway,
            buffer_size: Default::default(),
        }
    }
}

/// `Net` is the main interface to the network stack.
/// Socket creation and configuration is done through the `Net` interface.
///
/// When `Net` is dropped, all sockets are closed and the network stack is stopped.
pub struct Net {
    reactor: Arc<Reactor>,
    ip_addr: IpCidr,
    from_port: AtomicU16,
    stopper: Arc<Notify>,
}

impl std::fmt::Debug for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Net")
            .field("ip_addr", &self.ip_addr)
            .field("from_port", &self.from_port)
            .finish()
    }
}

impl Net {
    /// Creates a new `Net` instance. It panics if the medium is not supported.
    pub fn new<D: device::AsyncDevice + 'static>(device: D, config: NetConfig) -> Net {
        let (net, fut) = Self::new2(device, config);
        tokio::spawn(fut);
        net
    }

    fn new2<D: device::AsyncDevice + 'static>(
        device: D,
        config: NetConfig,
    ) -> (Net, impl Future<Output = io::Result<()>> + Send) {
        let mut buffer_device = BufferDevice::new(device.capabilities().clone());
        let mut iface = Interface::new(config.interface_config, &mut buffer_device, Instant::now());
        let ip_addr = config.ip_addr;
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(ip_addr).unwrap();
        });
        for gateway in config.gateway {
            match gateway {
                IpAddress::Ipv4(v4) => {
                    iface.routes_mut().add_default_ipv4_route(v4).unwrap();
                }
                IpAddress::Ipv6(v6) => {
                    iface.routes_mut().add_default_ipv6_route(v6).unwrap();
                }
                #[allow(unreachable_patterns)]
                _ => panic!("Unsupported address"),
            };
        }

        let stopper = Arc::new(Notify::new());
        let (reactor, fut) = Reactor::new(
            device,
            iface,
            buffer_device,
            config.buffer_size,
            stopper.clone(),
        );

        (
            Net {
                reactor: Arc::new(reactor),
                ip_addr: config.ip_addr,
                from_port: AtomicU16::new(10001),
                stopper,
            },
            fut,
        )
    }
    pub fn get_address(&self) -> IpAddr {
        self.ip_addr.address().into()
    }
    pub fn get_port(&self) -> u16 {
        self.from_port
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                Some(if x > 60000 { 10000 } else { x + 1 })
            })
            .unwrap()
    }
    /// Creates a new TcpListener, which will be bound to the specified address.
    pub async fn tcp_bind(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        let addr = self.set_address(addr);
        TcpListener::new(self.reactor.clone(), addr.into()).await
    }
    /// Opens a TCP connection to a remote host.
    pub async fn tcp_connect(&self, addr: SocketAddr, local_port: u16) -> io::Result<TcpStream> {
        TcpStream::connect(
            self.reactor.clone(),
            (self.ip_addr.address(), local_port).into(),
            addr.into(),
        )
        .await
    }

    /// This function will create a new UDP socket and attempt to bind it to the `addr` provided.
    pub async fn udp_bind(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let addr = self.set_address(addr);
        UdpSocket::new(self.reactor.clone(), addr.into()).await
    }

    fn set_address(&self, mut addr: SocketAddr) -> SocketAddr {
        if addr.ip().is_unspecified() {
            addr.set_ip(match self.ip_addr.address() {
                IpAddress::Ipv4(ip) => Ipv4Addr::from(ip).into(),
                IpAddress::Ipv6(ip) => Ipv6Addr::from(ip).into(),
                #[allow(unreachable_patterns)]
                _ => panic!("address must not be unspecified"),
            });
        }
        if addr.port() == 0 {
            addr.set_port(self.get_port());
        }
        addr
    }

    /// Enable or disable the AnyIP capability.
    pub fn set_any_ip(&self, any_ip: bool) {
        let iface = self.reactor.iface().clone();
        let mut iface: parking_lot::lock_api::MutexGuard<'_, parking_lot::RawMutex, Interface> =
            iface.lock();
        iface.set_any_ip(any_ip);
    }

    /// Get whether AnyIP is enabled.
    pub fn any_ip(&self) -> bool {
        let iface = self.reactor.iface().clone();
        let iface = iface.lock();
        iface.any_ip()
    }

    pub fn routes<F: FnOnce(&Routes)>(&self, f: F) {
        let iface = self.reactor.iface().clone();
        let iface = iface.lock();
        let routes = iface.routes();
        f(routes)
    }

    pub fn routes_mut<F: FnOnce(&mut Routes)>(&self, f: F) {
        let iface = self.reactor.iface().clone();
        let mut iface = iface.lock();
        let routes = iface.routes_mut();
        f(routes)
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.stopper.notify_waiters()
    }
}
