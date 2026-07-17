use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use easytier_core::{
    connectivity::host::environment::HostConnectorEnvironmentServices,
    instance::PacketSink,
    host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord}, socket::{
        IpVersion, NetNamespace, SocketContext,
        
        host::{
            HostSocketHandle, HostSocketRuntime,
            dns::{HostDnsResolver, wasi::WasiHostDnsIo},
            environment::{
                HostConnectorEnvironmentServiceAdapter,
                wasi::WasiHostConnectorEnvironmentIo,
            },
            factory::HostSocketFactory,
            listener::HostTcpListenerFactory,
            packet::{HostPacketSink, HostPacketSinkHandle, wasi::WasiHostPacketIo},
            udp::wasi::WasiHostUdpIo,
            wasi::WasiHostTcpIo,
            wasi_backend::WasiHostSocketBackend,
        },
        tcp::{
            TcpConnectOptions, TcpListenOptions, VirtualTcpListener, VirtualTcpListenerFactory,
            VirtualTcpSocketFactory,
        },
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    runtime::{Builder, Runtime},
    time::sleep,
};

const TIMER_PROGRESS: u32 = 1 << 0;
const SECOND_SOCKET_PROGRESS: u32 = 1 << 1;
const PENDING_READ_COMPLETED: u32 = 1 << 2;
const PENDING_READ_ISOLATED: u32 = 1 << 3;
const DONE: u32 = 1 << 4;
const FACTORY_TCP_PROGRESS: u32 = 1 << 5;
const FACTORY_UDP_PROGRESS: u32 = 1 << 6;
const ERROR: u32 = 1 << 31;

thread_local! {
    static PROBE: RefCell<Option<Probe>> = const { RefCell::new(None) };
    static UDP_PROBE: RefCell<Option<UdpProbe>> = const { RefCell::new(None) };
    static FACTORY_PROBE: RefCell<Option<FactoryProbe>> = const { RefCell::new(None) };
    static FACTORY_ERROR_PROBE: RefCell<Option<FactoryProbe>> = const { RefCell::new(None) };
    static LISTENER_PROBE: RefCell<Option<FactoryProbe>> = const { RefCell::new(None) };
    static DNS_PROBE: RefCell<Option<FactoryProbe>> = const { RefCell::new(None) };
    static PACKET_PROBE: RefCell<Option<FactoryProbe>> = const { RefCell::new(None) };
    static ENVIRONMENT_PROBE: RefCell<Option<FactoryProbe>> = const { RefCell::new(None) };
}

struct Probe {
    runtime: Runtime,
    status: Arc<AtomicU32>,
    sockets: HostSocketRuntime,
}

struct UdpProbe {
    runtime: Runtime,
    status: Arc<AtomicU32>,
    sockets: HostSocketRuntime,
}

struct FactoryProbe {
    runtime: Runtime,
    status: Arc<AtomicU32>,
    sockets: HostSocketRuntime,
}

fn tcp_stream(
    sockets: &HostSocketRuntime,
    io: Arc<WasiHostTcpIo>,
    handle: u64,
) -> easytier_core::host::HostTcpStream {
    sockets.tcp_stream(
        io,
        HostSocketHandle(handle),
        "192.0.2.1:10000".parse().unwrap(),
        "192.0.2.2:11013".parse().unwrap(),
        None,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn init_opaque_probe(pending_handle: u64, active_handle: u64) -> i32 {
    PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }

        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -2,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let tcp_io = Arc::new(WasiHostTcpIo::default());

        let pending_status = status.clone();
        let pending_stream = tcp_stream(&sockets, tcp_io.clone(), pending_handle);
        runtime.spawn(async move {
            let mut stream = pending_stream;
            let mut byte = [0_u8; 1];
            let _ = stream.read_exact(&mut byte).await;
            pending_status.fetch_or(PENDING_READ_COMPLETED, Ordering::SeqCst);
        });

        let active_status = status.clone();
        let active_stream = tcp_stream(&sockets, tcp_io, active_handle);
        runtime.spawn(async move {
            let mut stream = active_stream;
            let mut byte = [0_u8; 1];
            let result = async {
                stream.read_exact(&mut byte).await?;
                stream.write_all(&byte).await?;
                stream.flush().await
            }
            .await;
            match result {
                Ok(()) => {
                    active_status.fetch_or(SECOND_SOCKET_PROGRESS, Ordering::SeqCst);
                }
                Err(_) => {
                    active_status.fetch_or(ERROR | 1, Ordering::SeqCst);
                }
            }
        });

        let timer_status = status.clone();
        runtime.spawn(async move {
            sleep(Duration::from_millis(50)).await;
            timer_status.fetch_or(TIMER_PROGRESS, Ordering::SeqCst);
        });

        *slot = Some(Probe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_opaque_probe() -> u32 {
    PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 2;
        };

        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });

        let status = probe.status.load(Ordering::SeqCst);
        if status & ERROR == 0
            && status & (TIMER_PROGRESS | SECOND_SOCKET_PROGRESS)
                == TIMER_PROGRESS | SECOND_SOCKET_PROGRESS
        {
            if status & PENDING_READ_COMPLETED == 0 {
                probe
                    .status
                    .fetch_or(PENDING_READ_ISOLATED | DONE, Ordering::SeqCst);
            } else {
                probe.status.fetch_or(ERROR | 3, Ordering::SeqCst);
            }
        }

        probe.status.load(Ordering::SeqCst)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn init_udp_probe(handle: u64) -> i32 {
    UDP_PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }

        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -2,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let socket = Arc::new(sockets.udp_socket(
            Arc::new(WasiHostUdpIo::default()),
            HostSocketHandle(handle),
            "127.0.0.1:11013".parse().unwrap(),
        ));

        let task_status = status.clone();
        runtime.spawn(async move {
            let mut buffer = [0_u8; 64];
            let result = async {
                let (length, peer_addr) = socket.recv_from(&mut buffer).await?;
                if &buffer[..length] != b"udp" {
                    return Err(std::io::Error::other("unexpected UDP payload"));
                }
                let sent = socket.send_to(&buffer[..length], peer_addr).await?;
                if sent != length {
                    return Err(std::io::Error::other("short UDP send"));
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    task_status.fetch_or(DONE, Ordering::SeqCst);
                }
                Err(_) => {
                    task_status.fetch_or(ERROR | 4, Ordering::SeqCst);
                }
            }
        });

        *slot = Some(UdpProbe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_udp_probe() -> u32 {
    UDP_PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 5;
        };
        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });
        probe.status.load(Ordering::SeqCst)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn init_factory_probe(tcp_port: u32, udp_port: u32) -> i32 {
    FACTORY_PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }
        let Ok(tcp_port) = u16::try_from(tcp_port) else {
            return -2;
        };
        let Ok(udp_port) = u16::try_from(udp_port) else {
            return -3;
        };
        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -4,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let factory = Arc::new(HostSocketFactory::new(
            sockets.clone(),
            Arc::new(WasiHostSocketBackend::default()),
        ));

        let tcp_status = status.clone();
        let tcp_factory = factory.clone();
        runtime.spawn(async move {
            let result: Result<(), String> = async {
                let remote_addr = std::net::SocketAddr::from(([127, 0, 0, 1], tcp_port));
                let mut stream = tcp_factory
                    .connect_tcp(TcpConnectOptions::direct_connect(remote_addr))
                    .await
                    .map_err(|error| error.to_string())?;
                stream
                    .write_all(b"factory-tcp")
                    .await
                    .map_err(|error| error.to_string())?;
                stream.flush().await.map_err(|error| error.to_string())?;
                let mut echo = [0_u8; 11];
                stream
                    .read_exact(&mut echo)
                    .await
                    .map_err(|error| error.to_string())?;
                if &echo != b"factory-tcp" {
                    return Err("factory TCP echo mismatch".to_owned());
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    tcp_status.fetch_or(FACTORY_TCP_PROGRESS, Ordering::SeqCst);
                }
                Err(_) => {
                    tcp_status.fetch_or(ERROR | 6, Ordering::SeqCst);
                }
            }
        });

        let udp_status = status.clone();
        runtime.spawn(async move {
            let result: Result<(), String> = async {
                let socket = factory
                    .bind_udp(UdpBindOptions::direct_connect())
                    .await
                    .map_err(|error| error.to_string())?;
                let remote_addr = std::net::SocketAddr::from(([127, 0, 0, 1], udp_port));
                socket
                    .send_to(b"factory-udp", remote_addr)
                    .await
                    .map_err(|error| error.to_string())?;
                let mut echo = [0_u8; 11];
                let (length, peer_addr) = socket
                    .recv_from(&mut echo)
                    .await
                    .map_err(|error| error.to_string())?;
                if length != echo.len() || &echo != b"factory-udp" || peer_addr != remote_addr {
                    return Err("factory UDP echo mismatch".to_owned());
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    udp_status.fetch_or(FACTORY_UDP_PROGRESS, Ordering::SeqCst);
                }
                Err(_) => {
                    udp_status.fetch_or(ERROR | 7, Ordering::SeqCst);
                }
            }
        });

        *slot = Some(FactoryProbe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_factory_probe() -> u32 {
    FACTORY_PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 8;
        };
        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });
        let status = probe.status.load(Ordering::SeqCst);
        if status & ERROR == 0
            && status & (FACTORY_TCP_PROGRESS | FACTORY_UDP_PROGRESS)
                == FACTORY_TCP_PROGRESS | FACTORY_UDP_PROGRESS
        {
            probe.status.fetch_or(DONE, Ordering::SeqCst);
        }
        probe.status.load(Ordering::SeqCst)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn init_factory_error_probe() -> i32 {
    FACTORY_ERROR_PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }
        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -2,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let factory = HostSocketFactory::new(
            sockets.clone(),
            Arc::new(WasiHostSocketBackend::default()),
        );
        let task_status = status.clone();
        runtime.spawn(async move {
            let remote_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
            let code = match factory.connect_tcp(TcpConnectOptions::socks5(remote_addr)).await {
                Err(error) => match error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .map(std::io::Error::kind)
                {
                    Some(std::io::ErrorKind::ConnectionRefused) => 1,
                    Some(std::io::ErrorKind::ConnectionAborted) => 2,
                    Some(std::io::ErrorKind::ConnectionReset) => 3,
                    Some(std::io::ErrorKind::NotConnected) => 4,
                    _ => 5,
                },
                Ok(_) => ERROR | 9,
            };
            task_status.store(DONE | code, Ordering::SeqCst);
        });
        *slot = Some(FactoryProbe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_factory_error_probe() -> u32 {
    FACTORY_ERROR_PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 10;
        };
        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });
        probe.status.load(Ordering::SeqCst)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn init_listener_probe(port: u32) -> i32 {
    LISTENER_PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }
        let Ok(port) = u16::try_from(port) else {
            return -2;
        };
        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -3,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let factory = HostTcpListenerFactory::new(
            sockets.clone(),
            Arc::new(WasiHostSocketBackend::default()),
        );
        let task_status = status.clone();
        runtime.spawn(async move {
            let result: Result<(), String> = async {
                let local_addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                let listener = factory
                    .bind_tcp(TcpListenOptions::manual_connect(local_addr))
                    .await
                    .map_err(|error| error.to_string())?;
                let (mut stream, _) = listener.accept().await.map_err(|error| error.to_string())?;
                let mut payload = [0_u8; 8];
                stream
                    .read_exact(&mut payload)
                    .await
                    .map_err(|error| error.to_string())?;
                if &payload != b"listener" {
                    return Err("listener payload mismatch".to_owned());
                }
                stream
                    .write_all(&payload)
                    .await
                    .map_err(|error| error.to_string())?;
                stream.flush().await.map_err(|error| error.to_string())?;
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    task_status.fetch_or(DONE, Ordering::SeqCst);
                }
                Err(_) => {
                    task_status.fetch_or(ERROR | 9, Ordering::SeqCst);
                }
            }
        });
        *slot = Some(FactoryProbe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_listener_probe() -> u32 {
    LISTENER_PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 10;
        };
        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });
        probe.status.load(Ordering::SeqCst)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn init_dns_probe() -> i32 {
    DNS_PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }
        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -2,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let resolver = HostDnsResolver::new(sockets.clone(), Arc::new(WasiHostDnsIo));
        let task_status = status.clone();
        runtime.spawn(async move {
            let result: Result<(), String> = async {
                let addresses = resolver
                    .resolve(DnsQuery::new(
                        "peer.example",
                        SocketContext {
                            ip_version: IpVersion::Both,
                            socket_mark: Some(7),
                            netns: Some(NetNamespace::new("mihomo")),
                        },
                    ))
                    .await
                    .map_err(|error| error.to_string())?;
                if addresses
                    != vec![
                        "192.0.2.1".parse::<std::net::IpAddr>().unwrap(),
                        "2001:db8::1".parse::<std::net::IpAddr>().unwrap(),
                    ]
                {
                    return Err("DNS address result mismatch".to_owned());
                }

                let txt = resolver
                    .resolve_txt(DnsQuery::new(
                        "_easytier.example",
                        SocketContext {
                            ip_version: IpVersion::V4,
                            socket_mark: None,
                            netns: None,
                        },
                    ))
                    .await
                    .map_err(|error| error.to_string())?;
                if txt != "tcp://peer.example:11010" {
                    return Err("DNS TXT result mismatch".to_owned());
                }

                let srv = resolver
                    .resolve_srv(DnsQuery::new(
                        "_easytier._udp.example",
                        SocketContext {
                            ip_version: IpVersion::V6,
                            socket_mark: Some(9),
                            netns: Some(NetNamespace::new("")),
                        },
                    ))
                    .await
                    .map_err(|error| error.to_string())?;
                if srv
                    != vec![DnsSrvRecord {
                        priority: 10,
                        weight: 20,
                        port: 11010,
                        target: "peer.example.".to_owned(),
                    }]
                {
                    return Err("DNS SRV result mismatch".to_owned());
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    task_status.fetch_or(DONE, Ordering::SeqCst);
                }
                Err(_) => {
                    task_status.fetch_or(ERROR | 11, Ordering::SeqCst);
                }
            }
        });
        *slot = Some(FactoryProbe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_dns_probe() -> u32 {
    DNS_PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 12;
        };
        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });
        probe.status.load(Ordering::SeqCst)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn init_packet_probe(handle: u64) -> i32 {
    PACKET_PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }
        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -2,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let sink = HostPacketSink::new(
            sockets.clone(),
            Arc::new(WasiHostPacketIo),
            HostPacketSinkHandle(handle),
        );
        let task_status = status.clone();
        runtime.spawn(async move {
            let result = async {
                sink.write_packet(b"first-packet".to_vec()).await?;
                sink.write_packet(b"second-packet".to_vec()).await
            }
            .await;
            match result {
                Ok(()) => {
                    task_status.fetch_or(DONE, Ordering::SeqCst);
                }
                Err(_) => {
                    task_status.fetch_or(ERROR | 13, Ordering::SeqCst);
                }
            }
        });
        *slot = Some(FactoryProbe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_packet_probe() -> u32 {
    PACKET_PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 14;
        };
        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });
        probe.status.load(Ordering::SeqCst)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn init_environment_probe() -> i32 {
    ENVIRONMENT_PROBE.with_borrow_mut(|slot| {
        if slot.is_some() {
            return -1;
        }
        let runtime = match Builder::new_current_thread().enable_time().build() {
            Ok(runtime) => runtime,
            Err(_) => return -2,
        };
        let status = Arc::new(AtomicU32::new(0));
        let sockets = HostSocketRuntime::new();
        let services = Arc::new(HostConnectorEnvironmentServiceAdapter::new(
            sockets.clone(),
            Arc::new(WasiHostConnectorEnvironmentIo),
        ));
        let task_status = status.clone();
        runtime.spawn(async move {
            let result: Result<(), String> = async {
                let local = services
                    .local_addr_for_remote(
                        "203.0.113.2:443".parse().unwrap(),
                        easytier_core::socket::SocketContext::default(),
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                if local != "192.0.2.10:40000".parse().unwrap() {
                    return Err("local route result mismatch".to_owned());
                }
                Ok(())
            }
            .await;
            match result {
                Ok(()) => {
                    task_status.fetch_or(DONE, Ordering::SeqCst);
                }
                Err(_) => {
                    task_status.fetch_or(ERROR | 15, Ordering::SeqCst);
                }
            }
        });
        *slot = Some(FactoryProbe {
            runtime,
            status,
            sockets,
        });
        0
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn drive_environment_probe() -> u32 {
    ENVIRONMENT_PROBE.with_borrow_mut(|slot| {
        let Some(probe) = slot.as_mut() else {
            return ERROR | 16;
        };
        probe.sockets.notify_completions();
        probe
            .runtime
            .block_on(async { tokio::task::yield_now().await });
        probe.status.load(Ordering::SeqCst)
    })
}
