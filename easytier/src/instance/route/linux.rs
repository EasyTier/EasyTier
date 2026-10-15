use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io,
    net::IpAddr,
    time::Duration,
};

use anyhow::Context as _;
use cidr::IpCidr;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    libc,
    sched::{CloneFlags, setns},
};
use tokio::{io::unix::AsyncFd, sync::oneshot};

use crate::common::{
    ifcfg::netlink_wire::{
        MessageBuilder, MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR,
        NLM_F_EXCL, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NetlinkDecode, NetlinkEncode,
        RTM_DELROUTE, RTM_GETROUTE, RTM_NEWROUTE, RouteMessage, RouteMessageBuilder, RouteType,
        netlink_error_code,
    },
    netns::{NetNS, ROOT_NETNS_NAME},
};

use super::{Route, RouteBackend, RouteError};

/// One writer's reusable socket, bound to its network namespace at creation.
/// Readiness and ACK waiting stay on the async runtime; only socket setup uses
/// a short-lived thread so namespace changes cannot leak into runtime workers.
pub struct PlatformRouteBackend {
    socket: AsyncFd<Socket>,
    sequence: u32,
    timeout: Duration,
}

impl PlatformRouteBackend {
    pub async fn new(net_ns: NetNS) -> anyhow::Result<Self> {
        let (sender, receiver) = oneshot::channel();
        std::thread::Builder::new()
            .name("easytier-route-socket".into())
            .spawn(move || {
                let result = (|| -> anyhow::Result<Socket> {
                    if let Some(name) = net_ns.name() {
                        let path = if name == ROOT_NETNS_NAME {
                            "/proc/1/ns/net".to_owned()
                        } else {
                            format!("/var/run/netns/{name}")
                        };
                        let namespace = File::open(&path)
                            .with_context(|| format!("open network namespace {path}"))?;
                        setns(&namespace, CloneFlags::CLONE_NEWNET)
                            .context("enter route network namespace")?;
                    }
                    let mut socket = Socket::new(NETLINK_ROUTE)?;
                    socket.bind_auto()?;
                    socket.connect(&SocketAddr::new(0, 0))?;
                    socket.set_non_blocking(true)?;
                    Ok(socket)
                })();
                let _ = sender.send(result);
            })?;
        let socket = receiver
            .await
            .context("route socket setup thread stopped")??;
        Ok(Self {
            socket: AsyncFd::new(socket)?,
            sequence: 0,
            timeout: Duration::from_secs(2),
        })
    }

    async fn send(&self, request: &[u8], sent: &mut bool) -> io::Result<()> {
        loop {
            let mut ready = self.socket.writable().await?;
            match ready.try_io(|socket| {
                let result = socket.get_ref().send(request, 0);
                // WouldBlock has not queued a datagram. Any other attempted
                // send is conservatively uncertain until a matching ACK.
                *sent = !matches!(&result, Err(error) if error.kind() == io::ErrorKind::WouldBlock);
                result
            }) {
                Ok(Ok(len)) if len == request.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::Error::other("short netlink datagram send")),
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }

    async fn receive(&self) -> io::Result<Vec<u8>> {
        loop {
            let mut ready = self.socket.readable().await?;
            match ready.try_io(|socket| socket.get_ref().recv_from_full()) {
                Ok(Ok((bytes, sender))) if sender.port_number() == 0 => return Ok(bytes),
                Ok(Ok(_)) => continue,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Err(error),
                Err(_) => continue,
            }
        }
    }

    async fn request(
        &mut self,
        request: MessageBuilder,
        kind: ReplyKind,
    ) -> Result<Vec<RouteMessage>, RequestFailure> {
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            RequestFailure::io(io::Error::other("netlink sequence exhausted"), false)
        })?;
        let request = request
            .sequence(self.sequence)
            .finish()
            .map_err(|error| RequestFailure::io(error, false))?;
        let mut reply = Reply::new(self.sequence, kind);
        let mut sent = false;
        let result = tokio::time::timeout(self.timeout, async {
            self.send(&request, &mut sent)
                .await
                .map_err(|error| RequestFailure::io(error, sent))?;
            loop {
                let bytes = self
                    .receive()
                    .await
                    .map_err(|error| RequestFailure::io(error, sent))?;
                if reply.accept(&bytes).map_err(|error| match error {
                    ReplyFailure::Kernel(errno) => RequestFailure::Kernel(errno),
                    ReplyFailure::Io(error) => RequestFailure::io(error, sent),
                })? {
                    return Ok(reply.routes);
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| {
            Err(RequestFailure::io(
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "netlink response deadline exceeded",
                ),
                sent,
            ))
        })
    }

    async fn contains(&mut self, route: &Route) -> Result<bool, RouteError> {
        Ok(self
            .existing(&BTreeSet::from([route.clone()]))
            .await?
            .contains(route))
    }

    async fn dump(&mut self, family: u8) -> Result<Vec<RouteMessage>, RouteError> {
        let mut header = RouteMessage::dump_header();
        header[0] = family;
        let mut request = MessageBuilder::new(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP);
        request.append_bytes(&header);
        self.request(request, ReplyKind::Dump)
            .await
            .map_err(|error| error.into_route_error(false))
    }
}

#[async_trait::async_trait]
impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError> {
        let request = route_request(
            route,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )?;
        match self.request(request, ReplyKind::Ack).await {
            Ok(_) => Ok(Some(route.clone())),
            Err(RequestFailure::Kernel(libc::EEXIST)) => {
                if self.contains(route).await? {
                    Ok(None)
                } else {
                    Err(RouteError::Failed(anyhow::anyhow!(
                        "route conflict: EEXIST without an equivalent route: {route:?}"
                    )))
                }
            }
            Err(error) => Err(error.into_route_error(true)),
        }
    }

    async fn remove(&mut self, route: &Route) -> Result<Option<()>, RouteError> {
        let request = route_request(route, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK)?;
        match self.request(request, ReplyKind::Ack).await {
            Ok(_) => Ok(Some(())),
            Err(RequestFailure::Kernel(libc::ESRCH | libc::ENOENT)) => Ok(None),
            Err(error) => Err(error.into_route_error(true)),
        }
    }

    async fn existing(&mut self, routes: &BTreeSet<Route>) -> Result<BTreeSet<Route>, RouteError> {
        let mut requested = BTreeMap::<_, Vec<&Route>>::new();
        let mut families = BTreeSet::new();
        for route in routes {
            requested
                .entry(physical_key(route))
                .or_default()
                .push(route);
            families.insert(family(route.destination));
        }
        let mut existing = BTreeSet::new();
        // Exceptional inspection batches use one dump per family, regardless
        // of how many isolated keys need checking. No steady-state dumps.
        for family in families {
            for message in self.dump(family).await? {
                if let Some(key) = direct_key(&message).map_err(|e| RouteError::Failed(e.into()))? {
                    if let Some(matches) = requested.get(&key) {
                        existing.extend(matches.iter().map(|route| (*route).clone()));
                    }
                }
            }
        }
        Ok(existing)
    }
}

fn family(destination: IpCidr) -> u8 {
    match destination {
        IpCidr::V4(_) => libc::AF_INET as u8,
        IpCidr::V6(_) => libc::AF_INET6 as u8,
    }
}

fn route_request(
    route: &Route,
    message_type: u16,
    flags: u16,
) -> Result<MessageBuilder, RouteError> {
    // Linux treats a zero delete priority as a wildcard. Resolve defaults
    // before constructing Route, and never emit an ambiguous delete request.
    if route.metric == 0 || route.interface.ifindex == 0 {
        return Err(RouteError::Failed(anyhow::anyhow!(
            "route metric and interface index must be nonzero"
        )));
    }
    let message = RouteMessageBuilder::new(family(route.destination))
        .destination(
            route.destination.first_address(),
            route.destination.network_length(),
        )
        .oif(route.interface.ifindex)
        .priority(route.metric)
        .table(libc::RT_TABLE_MAIN.into())
        .static_protocol()
        .universe_scope()
        .route_type(RouteType::Unicast)
        .build();
    let mut request = MessageBuilder::new(message_type, flags);
    let mut bytes = Vec::new();
    message
        .write_to(&mut bytes)
        .map_err(|error| RouteError::Failed(error.into()))?;
    request.append_bytes(&bytes);
    Ok(request)
}

fn physical_key(route: &Route) -> (IpCidr, u32, u32) {
    (route.destination, route.interface.ifindex, route.metric)
}

fn direct_key(message: &RouteMessage) -> io::Result<Option<(IpCidr, u32, u32)>> {
    if message.table()? != u32::from(libc::RT_TABLE_MAIN)
        || message.protocol() != libc::RTPROT_STATIC
        || message.scope() != libc::RT_SCOPE_UNIVERSE
        || message.route_type() != RouteType::Unicast
        || !message.is_direct()
    {
        return Ok(None);
    }
    let Some(ifindex) = message.oif() else {
        return Ok(None);
    };
    let unspecified = match message.family() as i32 {
        libc::AF_INET => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        libc::AF_INET6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        _ => return Ok(None),
    };
    let destination = message.destination().copied().unwrap_or(unspecified);
    let destination = IpCidr::new(destination, message.dst_len())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some((destination, ifindex, message.priority()?)))
}

#[cfg(test)]
fn equivalent(message: &RouteMessage, route: &Route) -> io::Result<bool> {
    Ok(direct_key(message)? == Some(physical_key(route)))
}

#[derive(Clone, Copy)]
enum ReplyKind {
    Ack,
    Dump,
}

struct Reply {
    sequence: u32,
    kind: ReplyKind,
    routes: Vec<RouteMessage>,
}

impl Reply {
    fn new(sequence: u32, kind: ReplyKind) -> Self {
        Self {
            sequence,
            kind,
            routes: Vec::new(),
        }
    }

    fn accept(&mut self, bytes: &[u8]) -> Result<bool, ReplyFailure> {
        for frame in MessageIter::new(bytes) {
            let (header, payload) = frame.map_err(ReplyFailure::Io)?;
            if header.sequence != self.sequence {
                continue;
            }
            if header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(ReplyFailure::Io(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "netlink dump interrupted",
                )));
            }
            match header.message_type {
                NLMSG_ERROR => {
                    let errno = netlink_error_code(payload).map_err(ReplyFailure::Io)?;
                    if errno > 0 {
                        return Err(ReplyFailure::Io(io::Error::other(
                            "invalid positive netlink errno",
                        )));
                    }
                    if errno != 0 {
                        return Err(ReplyFailure::Kernel(errno.checked_abs().ok_or_else(
                            || ReplyFailure::Io(io::Error::other("invalid netlink errno")),
                        )?));
                    }
                    if matches!(self.kind, ReplyKind::Ack) {
                        return Ok(true);
                    }
                }
                NLMSG_DONE if matches!(self.kind, ReplyKind::Dump) => {
                    let errno = netlink_error_code(payload).map_err(ReplyFailure::Io)?;
                    if errno > 0 {
                        return Err(ReplyFailure::Io(io::Error::other(
                            "invalid positive netlink errno",
                        )));
                    }
                    if errno != 0 {
                        return Err(ReplyFailure::Kernel(errno.checked_abs().ok_or_else(
                            || ReplyFailure::Io(io::Error::other("invalid netlink errno")),
                        )?));
                    }
                    return Ok(true);
                }
                RTM_NEWROUTE if matches!(self.kind, ReplyKind::Dump) => {
                    self.routes
                        .push(RouteMessage::from_bytes(payload).map_err(ReplyFailure::Io)?);
                }
                _ => {
                    return Err(ReplyFailure::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected netlink response",
                    )));
                }
            }
        }
        Ok(false)
    }
}

#[derive(Debug)]
enum ReplyFailure {
    Kernel(i32),
    Io(io::Error),
}
enum RequestFailure {
    Kernel(i32),
    Io { source: io::Error, sent: bool },
}

impl RequestFailure {
    fn io(source: io::Error, sent: bool) -> Self {
        Self::Io { source, sent }
    }
    fn into_route_error(self, mutation: bool) -> RouteError {
        match self {
            Self::Kernel(errno) => RouteError::Failed(io::Error::from_raw_os_error(errno).into()),
            Self::Io { source, sent: true } if mutation => RouteError::Unknown(source.into()),
            Self::Io { source, .. } => RouteError::Failed(source.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::route::DeviceId;
    use std::{future::Future, os::fd::AsRawFd, process::Command};

    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    struct CountedBackend {
        backend: PlatformRouteBackend,
        writes: Arc<AtomicU32>,
        queries: Arc<AtomicU32>,
    }
    #[async_trait::async_trait]
    impl RouteBackend for CountedBackend {
        async fn add(&mut self, route: &Route) -> Result<Option<Route>, RouteError> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.backend.add(route).await
        }
        async fn remove(&mut self, route: &Route) -> Result<Option<()>, RouteError> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.backend.remove(route).await
        }
        async fn existing(
            &mut self,
            routes: &BTreeSet<Route>,
        ) -> Result<BTreeSet<Route>, RouteError> {
            self.queries.fetch_add(1, Ordering::Relaxed);
            self.backend.existing(routes).await
        }
    }

    fn route(destination: &str, ifindex: u32, metric: u32) -> Route {
        Route {
            destination: destination.parse().unwrap(),
            interface: DeviceId::new(ifindex, None),
            metric,
        }
    }

    fn frame(sequence: u32, message_type: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let mut builder = MessageBuilder::new(message_type, flags).sequence(sequence);
        builder.append_bytes(payload);
        builder.finish().unwrap()
    }

    #[test]
    fn late_ack_cannot_complete_a_new_request() {
        let mut reply = Reply::new(2, ReplyKind::Ack);
        assert!(
            !reply
                .accept(&frame(1, NLMSG_ERROR, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
        assert!(
            reply
                .accept(&frame(2, NLMSG_ERROR, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
    }

    #[test]
    fn dump_waits_for_done_and_rejects_interruptions() {
        let mut reply = Reply::new(3, ReplyKind::Dump);
        assert!(
            !reply
                .accept(&frame(3, NLMSG_ERROR, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
        assert!(
            reply
                .accept(&frame(3, NLMSG_DONE, 0, &0_i32.to_ne_bytes()))
                .unwrap()
        );
        let mut interrupted = Reply::new(3, ReplyKind::Dump);
        assert!(
            interrupted
                .accept(&frame(3, NLMSG_DONE, NLM_F_DUMP_INTR, &0_i32.to_ne_bytes()))
                .is_err()
        );
    }

    #[test]
    fn malformed_and_error_responses_do_not_report_success() {
        for errno in [libc::EEXIST, i32::MIN] {
            let mut reply = Reply::new(1, ReplyKind::Ack);
            assert!(
                reply
                    .accept(&frame(1, NLMSG_ERROR, 0, &errno.to_ne_bytes()))
                    .is_err()
            );
        }
        let mut reply = Reply::new(1, ReplyKind::Ack);
        assert!(matches!(
            reply.accept(&frame(1, NLMSG_ERROR, 0, &(-libc::EPERM).to_ne_bytes())),
            Err(ReplyFailure::Kernel(libc::EPERM))
        ));
        assert!(reply.accept(&frame(1, NLMSG_ERROR, 0, &[])).is_err());
    }

    #[test]
    fn add_and_delete_use_the_same_complete_route_key() {
        for destination in ["10.71.0.0/24", "2001:db8:71::/64", "0.0.0.0/0", "::/0"] {
            let route = route(destination, 7, 65535);
            for message_type in [RTM_NEWROUTE, RTM_DELROUTE] {
                let bytes = route_request(&route, message_type, NLM_F_REQUEST | NLM_F_ACK)
                    .unwrap()
                    .finish()
                    .unwrap();
                let (header, payload) = MessageIter::new(&bytes).next().unwrap().unwrap();
                assert_eq!(header.message_type, message_type);
                let message = RouteMessage::from_bytes(payload).unwrap();
                assert!(equivalent(&message, &route).unwrap());
                assert!(
                    !equivalent(
                        &message,
                        &Route {
                            metric: 5,
                            ..route.clone()
                        }
                    )
                    .unwrap()
                );
                assert!(
                    !equivalent(
                        &message,
                        &Route {
                            interface: DeviceId::new(8, None),
                            ..route.clone()
                        }
                    )
                    .unwrap()
                );
            }
        }
        assert!(route_request(&route("10.71.0.0/24", 7, 0), RTM_DELROUTE, NLM_F_REQUEST).is_err());
    }

    #[tokio::test]
    async fn invalid_namespace_is_a_setup_error_without_panic() {
        assert!(
            PlatformRouteBackend::new(NetNS::new(Some(format!(
                "easytier-missing-{}",
                uuid::Uuid::new_v4()
            ))))
            .await
            .is_err()
        );
    }

    fn ip(args: &[&str]) -> String {
        let mut command = Command::new("ip");
        if args.iter().any(|arg| arg.contains(':')) {
            command.arg("-6");
        }
        let output = command.args(args).output().unwrap();
        assert!(
            output.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn dummy(name: &str) -> u32 {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["link", "set", name, "up"]);
        let names =
            serde_json::from_str::<serde_json::Value>(&ip(&["-j", "link", "show", name])).unwrap();
        names[0]["ifindex"].as_u64().unwrap() as u32
    }

    fn kernel_test<F, Fut>(test: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()>,
    {
        std::thread::spawn(move || {
            nix::sched::unshare(CloneFlags::CLONE_NEWNET)
                .expect("kernel tests need a private network namespace");
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(test());
        })
        .join()
        .unwrap();
    }

    #[test]
    #[ignore = "requires namespace privileges; creates a private network namespace"]
    fn kernel_add_equivalent_delete_preserves_other_metrics_and_tables() {
        kernel_test(|| async {
            let ifindex = dummy("et-route");
            let mut backend = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
            let fd = backend.socket.get_ref().as_raw_fd();
            for destination in ["10.71.0.0/24", "2001:db8:71::/64"] {
                let route = route(destination, ifindex, 65535);
                assert_eq!(backend.add(&route).await.unwrap(), Some(route.clone()));
                assert_eq!(backend.add(&route).await.unwrap(), None);
                ip(&[
                    "route",
                    "add",
                    destination,
                    "dev",
                    "et-route",
                    "metric",
                    "5",
                    "proto",
                    "static",
                    "scope",
                    "global",
                ]);
                ip(&[
                    "route",
                    "add",
                    destination,
                    "dev",
                    "et-route",
                    "metric",
                    "65535",
                    "proto",
                    "static",
                    "scope",
                    "global",
                    "table",
                    "123",
                ]);
                assert_eq!(backend.remove(&route).await.unwrap(), Some(()));
                assert_eq!(backend.remove(&route).await.unwrap(), None);
                let main = serde_json::from_str::<serde_json::Value>(&ip(&[
                    "-j",
                    "route",
                    "show",
                    "table",
                    "main",
                    "exact",
                    destination,
                ]))
                .unwrap();
                let other = serde_json::from_str::<serde_json::Value>(&ip(&[
                    "-j",
                    "route",
                    "show",
                    "table",
                    "123",
                    "exact",
                    destination,
                ]))
                .unwrap();
                assert_eq!(main.as_array().unwrap().len(), 1);
                assert_eq!(main[0]["metric"], 5);
                assert_eq!(other.as_array().unwrap().len(), 1);
            }
            assert_eq!(fd, backend.socket.get_ref().as_raw_fd());
        });
    }

    #[test]
    #[ignore = "requires namespace privileges; creates a private network namespace"]
    fn kernel_manager_scale_and_incremental_updates() {
        kernel_test(|| async {
            use crate::common::global_ctx::tests::get_mock_global_ctx;
            use crate::instance::route::RouteMgr;
            use easytier_core::{
                config::{
                    peers::PeerRuntimeSnapshot,
                    runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
                },
                host::route::{RouteDemand, RouteHandle, RouteRegistry},
            };
            use std::{
                net::Ipv4Addr,
                sync::{
                    Arc,
                    atomic::{AtomicU32, Ordering},
                },
                time::Instant,
            };
            use tokio_util::sync::CancellationToken;

            let ifindex = dummy("et-scale");
            for count in [100, 1_000, 10_000] {
                let ctx = get_mock_global_ctx();
                let device = ctx.tun_devices.attach_external("et-scale".into(), ifindex);
                ctx.tun_devices.mark_ready(device.registration());
                let routes = RouteRegistry::default();
                let handle = RouteHandle::new(routes.clone());
                let config = CoreRuntimeConfigStore::new(
                    CoreRuntimeConfig::default(),
                    Arc::new(PeerRuntimeSnapshot::default()),
                );
                let writes = Arc::new(AtomicU32::new(0));
                let queries = Arc::new(AtomicU32::new(0));
                let backend = CountedBackend {
                    backend: PlatformRouteBackend::new(NetNS::new(None)).await.unwrap(),
                    writes: writes.clone(),
                    queries: queries.clone(),
                };
                let mut manager =
                    RouteMgr::new(ctx, backend, routes, config, CancellationToken::new());
                let mut destinations: BTreeSet<_> = (0..count)
                    .map(|i| IpCidr::new(IpAddr::V4(Ipv4Addr::from(0x0a800000 + i)), 32).unwrap())
                    .collect();
                let registration = handle
                    .register(RouteDemand::additional(destinations.clone()))
                    .unwrap();
                let start = Instant::now();
                manager.reconcile().await;
                let initial = start.elapsed();
                assert_eq!(handle.status().ready.len(), count as usize);
                assert_eq!(manager.next_wakeup_time(), None);
                let before = writes.load(Ordering::Relaxed);
                assert_eq!(before, count);
                let start = Instant::now();
                for _ in 0..10 {
                    manager.reconcile().await;
                }
                let unchanged = start.elapsed();
                assert_eq!(
                    writes.load(Ordering::Relaxed),
                    before,
                    "unchanged inputs must not perform kernel writes"
                );
                assert_eq!(
                    queries.load(Ordering::Relaxed),
                    0,
                    "healthy state must not inspect kernel routes"
                );
                destinations
                    .remove(&IpCidr::new(IpAddr::V4(Ipv4Addr::from(0x0a800000)), 32).unwrap());
                destinations.insert(
                    IpCidr::new(IpAddr::V4(Ipv4Addr::from(0x0a800000 + count)), 32).unwrap(),
                );
                registration
                    .replace(RouteDemand::additional(destinations.clone()))
                    .unwrap();
                let start = Instant::now();
                manager.reconcile().await;
                let incremental = start.elapsed();
                assert_eq!(
                    writes.load(Ordering::Relaxed) - before,
                    2,
                    "one removal and one addition"
                );
                assert_eq!(handle.status().ready.len(), count as usize);
                let start = Instant::now();
                manager.perform_shutdown_cleanup().await.unwrap();
                let cleanup = start.elapsed();
                assert_eq!(writes.load(Ordering::Relaxed), count * 2 + 2);
                destinations
                    .insert(IpCidr::new(IpAddr::V4(Ipv4Addr::from(0x0a800000)), 32).unwrap());
                // independent read-only evidence, including the removed key:
                let mut checker = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
                let existing = checker
                    .existing(
                        &destinations
                            .into_iter()
                            .map(|destination| Route {
                                destination,
                                interface: device.id().clone(),
                                metric: 65535,
                            })
                            .collect(),
                    )
                    .await
                    .unwrap();
                assert!(existing.is_empty());
                eprintln!(
                    "routes={count} initial={initial:?} unchanged_10={unchanged:?} incremental={incremental:?} cleanup={cleanup:?}"
                );
            }
        });
    }

    #[cfg(all(feature = "tun", not(mobile)))]
    async fn tun_lifetime_case(persistent: bool) {
        use crate::{
            common::global_ctx::tests::get_mock_global_ctx,
            instance::{
                route::RouteMgr,
                virtual_nic::{VirtualNic, VirtualNicConfig},
            },
        };
        use easytier_core::{
            config::{
                peers::PeerRuntimeSnapshot,
                runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
            },
            host::route::{RouteDemand, RouteHandle, RouteRegistry},
        };
        use tokio_util::sync::CancellationToken;

        let ctx = get_mock_global_ctx();
        let name = if persistent { "et-persist" } else { "et-owned" };
        let mut flags = ctx.get_flags();
        flags.dev_name = name.into();
        ctx.set_flags(flags);
        if persistent {
            let mut config = tun::Configuration::default();
            config.tun_name(name).layer(tun::Layer::L3);
            let device = tun::create(&config).unwrap();
            assert_eq!(
                unsafe { libc::ioctl(device.as_raw_fd(), libc::TUNSETPERSIST as libc::Ioctl, 1) },
                0
            );
            drop(device);
        }
        let mut nic = VirtualNic::new(VirtualNicConfig::new(
            name.into(),
            ctx.get_flags().mtu,
            ctx.net_ns.clone(),
        ))
        .with_device_state(ctx.tun_devices.clone());
        let tunnel = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match nic.create_dev().await {
                    Ok(tunnel) => break tunnel,
                    Err(crate::common::error::Error::TunError(tun::Error::Io(error)))
                        if persistent && error.raw_os_error() == Some(libc::EBUSY) =>
                    {
                        // The synchronous setup fd was closed above; its
                        // kernel file can still be retiring under load.
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Err(error) => panic!("unable to attach test TUN: {error:?}"),
                }
            }
        })
        .await
        .expect("persistent setup fd did not finish retiring");
        nic.link_up().await.unwrap();
        nic.add_ip("10.88.0.1".parse().unwrap(), 24).await.unwrap();
        let active = ctx.tun_devices.snapshot().active.unwrap();
        assert_eq!(
            active.id.host_instance.is_none(),
            persistent,
            "TUNGETIFF must distinguish persistent attachment"
        );
        ctx.tun_devices.mark_ready(active.registration);
        let (reader, writer) = tunnel.split();
        let routes = RouteRegistry::default();
        let handle = RouteHandle::new(routes.clone());
        let config = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        let writes = Arc::new(AtomicU32::new(0));
        let backend = CountedBackend {
            backend: PlatformRouteBackend::new(NetNS::new(None)).await.unwrap(),
            writes: writes.clone(),
            queries: Arc::new(AtomicU32::new(0)),
        };
        let mut manager = RouteMgr::new(
            ctx.clone(),
            backend,
            routes,
            config,
            CancellationToken::new(),
        );
        let target = Route {
            destination: "100.100.100.101/32".parse().unwrap(),
            interface: active.id.clone(),
            metric: 65535,
        };
        let registration = handle
            .register(RouteDemand::additional([target.destination]))
            .unwrap();
        manager.reconcile().await;
        assert_eq!(handle.status().ready.len(), 1);
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        let wanted = BTreeSet::from([target]);
        let mut checker = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
        drop(nic);
        assert!(
            ctx.tun_devices
                .snapshot()
                .live
                .contains_key(&active.registration),
            "metadata does not own fd lifetime"
        );
        drop(reader);
        assert!(
            ctx.tun_devices
                .snapshot()
                .live
                .contains_key(&active.registration),
            "one IO half still owns the actual fd"
        );
        assert_eq!(checker.existing(&wanted).await.unwrap(), wanted);
        drop(writer);
        let facts = ctx.tun_devices.snapshot();
        assert!(!facts.live.contains_key(&active.registration));
        assert_eq!(facts.destroyed(&active.id), !persistent);
        let ifname = std::ffi::CString::new(name).unwrap();
        if persistent {
            assert_eq!(
                unsafe { libc::if_nametoindex(ifname.as_ptr()) },
                active.id.ifindex
            );
            assert_eq!(checker.existing(&wanted).await.unwrap(), wanted);
        } else {
            // fd ownership ends synchronously, but kernel file reclamation
            // and concurrent interface queries are not a userspace barrier.
            // Verify the actual cascade with bounded, read-only observation.
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if checker.existing(&wanted).await.unwrap().is_empty()
                        && unsafe { libc::if_nametoindex(ifname.as_ptr()) } == 0
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("nonpersistent TUN and routes were not reclaimed");
        }
        manager.reconcile().await;
        assert_eq!(
            writes.load(Ordering::Relaxed),
            if persistent { 2 } else { 1 },
            "only persistent TUN requires explicit deletion"
        );
        assert!(handle.status().ready.is_empty());
        assert!(checker.existing(&wanted).await.unwrap().is_empty());
        manager.perform_shutdown_cleanup().await.unwrap();
        drop(registration);
    }

    #[cfg(all(feature = "tun", not(mobile)))]
    #[test]
    #[ignore = "requires root, TUN node and private network namespace"]
    fn kernel_tun_last_io_owner_proves_nonpersistent_route_cascade() {
        kernel_test(|| tun_lifetime_case(false));
    }

    #[cfg(all(feature = "tun", not(mobile)))]
    #[test]
    #[ignore = "requires root, TUN node and private network namespace"]
    fn kernel_tun_persistent_attachment_requires_explicit_route_cleanup() {
        kernel_test(|| tun_lifetime_case(true));
    }

    #[cfg(all(feature = "tun", feature = "public-ipv6-provider", not(mobile)))]
    #[test]
    #[ignore = "requires root, TUN node and private network namespace"]
    fn kernel_public_ipv6_producers_follow_peer_leases_and_shutdown() {
        kernel_test(|| async {
            use crate::{
                common::config::{ConfigLoader as _, TomlConfig},
                instance::test_instance::TestInstance,
            };
            use easytier_core::{
                process_runtime::CoreProcessRuntime, tunnel::ring::create_ring_tunnel_pair,
            };

            dummy("et-wan");
            ip(&[
                "-6",
                "addr",
                "add",
                "240e:1234:abcd::1/64",
                "dev",
                "et-wan",
                "nodad",
            ]);
            let provider_config = TomlConfig::default();
            provider_config.set_ipv4(Some("10.88.0.1/24".parse().unwrap()));
            provider_config.set_ipv6_public_addr_provider(true);
            provider_config
                .set_ipv6_public_addr_prefix(Some("240e:1234:abcd::/64".parse().unwrap()));
            let client_config = TomlConfig::default();
            client_config.set_ipv4(Some("10.88.0.2/24".parse().unwrap()));
            client_config.set_ipv6_public_addr_auto(true);
            let mut provider =
                TestInstance::new_with_process_runtime(provider_config, CoreProcessRuntime::new());
            let mut client =
                TestInstance::new_with_process_runtime(client_config, CoreProcessRuntime::new());
            provider.run().await.unwrap();
            client.run().await.unwrap();
            let provider_core = provider.get_core_instance();
            let client_core = client.get_core_instance();
            let provider_ctx = provider.get_global_ctx();
            let client_ctx = client.get_global_ctx();
            let provider_handle = provider_ctx.get_route_handle().unwrap();
            let client_handle = client_ctx.get_route_handle().unwrap();
            let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
            let (server, connected) = tokio::join!(
                provider_core
                    .peer_manager()
                    .add_tunnel_as_server(server_tunnel),
                client_core.peer_manager().add_client_tunnel(client_tunnel),
            );
            server.unwrap();
            connected.unwrap();
            let (lease, provider_route, default_route) =
                tokio::time::timeout(Duration::from_secs(15), async {
                    loop {
                        if let Some(lease) = client_core.packet_plane().public_ipv6_addr().await {
                            let provider_device =
                                provider_ctx.tun_devices.snapshot().active.unwrap();
                            let client_device = client_ctx.tun_devices.snapshot().active.unwrap();
                            let provider_route = Route {
                                destination: IpCidr::new(
                                    IpAddr::V6(lease.first_address()),
                                    lease.network_length(),
                                )
                                .unwrap(),
                                interface: provider_device.id,
                                metric: 65535,
                            };
                            let default_route = Route {
                                destination: "::/0".parse().unwrap(),
                                interface: client_device.id,
                                metric: 5,
                            };
                            let mut checker =
                                PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
                            let wanted =
                                BTreeSet::from([provider_route.clone(), default_route.clone()]);
                            if checker.existing(&wanted).await.unwrap() == wanted {
                                break (lease, provider_route, default_route);
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("public IPv6 lease did not produce kernel routes");
            assert!(
                provider_core
                    .packet_plane()
                    .public_ipv6_routes()
                    .await
                    .contains(&lease)
            );
            assert!(
                provider_handle
                    .status()
                    .ready
                    .iter()
                    .any(|route| route.destination == provider_route.destination
                        && route.metric.get() == 65535)
            );
            assert!(
                client_handle
                    .status()
                    .ready
                    .iter()
                    .any(|route| route.destination == default_route.destination
                        && route.metric.get() == 5)
            );
            let provider_claim = provider_ctx
                .tun_devices
                .snapshot()
                .active
                .unwrap()
                .registration;
            let client_claim = client_ctx
                .tun_devices
                .snapshot()
                .active
                .unwrap()
                .registration;
            let mut disabled = crate::instance::config::test_runtime_instance_config(&provider_ctx);
            disabled.services.public_ipv6_provider.provider_enabled = false;
            provider_core.update_runtime_config(disabled).await.unwrap();
            tokio::time::timeout(Duration::from_secs(15), async {
                let mut checker = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
                loop {
                    let wanted = BTreeSet::from([provider_route.clone(), default_route.clone()]);
                    if provider_core
                        .packet_plane()
                        .public_ipv6_routes()
                        .await
                        .is_empty()
                        && client_core
                            .packet_plane()
                            .public_ipv6_addr()
                            .await
                            .is_none()
                        && checker.existing(&wanted).await.unwrap().is_empty()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("public IPv6 withdrawal did not remove live-device routes");
            assert_eq!(
                provider_ctx
                    .tun_devices
                    .snapshot()
                    .active
                    .unwrap()
                    .registration,
                provider_claim
            );
            assert_eq!(
                client_ctx
                    .tun_devices
                    .snapshot()
                    .active
                    .unwrap()
                    .registration,
                client_claim
            );
            client.clear_resources().await;
            provider.clear_resources().await;
            assert!(client_handle.status().closed);
            assert!(provider_handle.status().closed);
            let mut checker = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
            assert!(
                checker
                    .existing(&BTreeSet::from([provider_route, default_route]))
                    .await
                    .unwrap()
                    .is_empty()
            );
        });
    }

    #[test]
    #[ignore = "requires namespace privileges; creates a private network namespace"]
    fn kernel_inspection_batches_families_and_keeps_requested_generations() {
        kernel_test(|| async {
            let ifindex = dummy("et-route");
            let mut backend = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
            let v4 = route("10.71.0.0/24", ifindex, 65535);
            let v6 = route("2001:db8:71::/64", ifindex, 65535);
            backend.add(&v4).await.unwrap();
            backend.add(&v6).await.unwrap();
            let generated = Route {
                interface: DeviceId::new(ifindex, Some(42)),
                ..v4.clone()
            };
            let wanted = BTreeSet::from([
                v4.clone(),
                v6.clone(),
                generated.clone(),
                route("10.72.0.0/24", ifindex, 65535),
                route("2001:db8:72::/64", ifindex, 65535),
                route("10.71.0.0/24", ifindex, 5),
            ]);
            let before = backend.sequence;
            assert_eq!(
                backend.existing(&wanted).await.unwrap(),
                BTreeSet::from([v4, v6, generated])
            );
            assert_eq!(backend.sequence - before, 2, "one dump per family");
            let before = backend.sequence;
            assert!(backend.existing(&BTreeSet::new()).await.unwrap().is_empty());
            assert_eq!(backend.sequence, before, "no queries for empty input");
        });
    }

    #[test]
    #[ignore = "requires namespace privileges; creates a private network namespace"]
    fn kernel_non_equivalent_eexist_is_a_conflict() {
        kernel_test(|| async {
            let a = dummy("et-a");
            dummy("et-b");
            ip(&[
                "route",
                "add",
                "10.72.0.0/24",
                "dev",
                "et-b",
                "metric",
                "65535",
                "proto",
                "static",
                "scope",
                "global",
            ]);
            let mut backend = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
            assert!(matches!(
                backend.add(&route("10.72.0.0/24", a, 65535)).await,
                Err(RouteError::Failed(_))
            ));
            let existing = serde_json::from_str::<serde_json::Value>(&ip(&[
                "-j",
                "route",
                "show",
                "exact",
                "10.72.0.0/24",
            ]))
            .unwrap();
            assert_eq!(existing[0]["dev"], "et-b");
        });
    }

    #[test]
    #[ignore = "requires namespace privileges; creates a private network namespace"]
    fn kernel_missing_ack_is_unknown_and_late_ack_is_ignored() {
        kernel_test(|| async {
            let ifindex = dummy("et-route");
            let mut backend = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
            let first = route("10.73.0.0/24", ifindex, 65535);
            let second = route("10.74.0.0/24", ifindex, 65535);
            let request = route_request(
                &first,
                RTM_NEWROUTE,
                NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            )
            .unwrap()
            .sequence(1)
            .finish()
            .unwrap();
            backend.sequence = 1;
            backend.send(&request, &mut false).await.unwrap();
            // The first ACK is deliberately left queued. It must not be used
            // as the second request's success indication.
            assert_eq!(backend.add(&second).await.unwrap(), Some(second.clone()));
            assert!(backend.contains(&first).await.unwrap());
            backend.timeout = Duration::from_millis(50);
            let request = route_request(&first, RTM_DELROUTE, NLM_F_REQUEST).unwrap();
            let failure = backend
                .request(request, ReplyKind::Ack)
                .await
                .err()
                .expect("an operation without ACK must time out");
            assert!(matches!(
                failure.into_route_error(true),
                RouteError::Unknown(_)
            ));
            assert!(
                !backend.contains(&first).await.unwrap(),
                "the timed-out delete actually reached the kernel"
            );
            assert_eq!(backend.remove(&second).await.unwrap(), Some(()));
        });
    }

    #[test]
    #[ignore = "requires namespace privileges; creates a private network namespace"]
    fn kernel_socket_remains_bound_to_its_creation_namespace() {
        kernel_test(|| async {
            let ifindex = dummy("et-route");
            let mut backend = PlatformRouteBackend::new(NetNS::new(None)).await.unwrap();
            let owned = route("10.75.0.0/24", ifindex, 65535);
            backend.add(&owned).await.unwrap();
            let original = File::open("/proc/thread-self/ns/net").unwrap();
            nix::sched::unshare(CloneFlags::CLONE_NEWNET).unwrap();
            assert_eq!(dummy("et-route"), ifindex);
            ip(&[
                "route",
                "add",
                "10.75.0.0/24",
                "dev",
                "et-route",
                "metric",
                "65535",
                "proto",
                "static",
                "scope",
                "global",
            ]);
            assert_eq!(backend.remove(&owned).await.unwrap(), Some(()));
            let other = serde_json::from_str::<serde_json::Value>(&ip(&[
                "-j",
                "route",
                "show",
                "exact",
                "10.75.0.0/24",
            ]))
            .unwrap();
            assert_eq!(other.as_array().unwrap().len(), 1);
            setns(&original, CloneFlags::CLONE_NEWNET).unwrap();
            assert!(!backend.contains(&owned).await.unwrap());
        });
    }
}
