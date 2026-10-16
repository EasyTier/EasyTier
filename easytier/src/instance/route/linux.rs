use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    num::NonZeroU32,
    time::Duration,
};

use cidr::IpCidr;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::libc;
use tokio::{io::unix::AsyncFd, runtime::Handle};

use crate::common::{
    ifcfg::netlink_wire::{
        MessageBuilder, MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR,
        NLM_F_EXCL, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NetlinkDecode, NetlinkEncode,
        RTM_DELROUTE, RTM_GETROUTE, RTM_NEWROUTE, RouteMessage, RouteMessageBuilder, RouteType,
        netlink_error_code,
    },
    netns::PlatformNamespace,
};

use super::{OsRoute, RouteBackend, RouteError};

/// One writer's reusable socket, bound to its network namespace at creation.
/// Readiness and ACK waiting stay on the async runtime; only socket setup uses
/// a short-lived thread so namespace changes cannot leak into runtime workers.
pub(crate) struct PlatformRouteBackend {
    socket: AsyncFd<Socket>,
    sequence: u32,
    timeout: Duration,
}

impl PlatformRouteBackend {
    pub(crate) fn new(namespace: &PlatformNamespace, executor: &Handle) -> anyhow::Result<Self> {
        let socket = namespace.run(|| -> io::Result<Socket> {
            let mut socket = Socket::new(NETLINK_ROUTE)?;
            socket.bind_auto()?;
            socket.connect(&SocketAddr::new(0, 0))?;
            socket.set_non_blocking(true)?;
            Ok(socket)
        })??;
        // Explicit registration on the host-owned Reactor, even when a first
        // caller enters from a short-lived instance runtime.
        let _entered = executor.enter();
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

    #[cfg(test)]
    async fn contains(&mut self, route: &OsRoute) -> Result<bool, RouteError> {
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

impl RouteBackend for PlatformRouteBackend {
    async fn add(&mut self, route: &OsRoute) -> Result<(), RouteError> {
        let request = route_request(
            route,
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )?;
        self.request(request, ReplyKind::Ack)
            .await
            .map(|_| ())
            .map_err(|error| error.into_route_error(true))
    }

    async fn remove(&mut self, route: &OsRoute) -> Result<(), RouteError> {
        let request = route_request(route, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK)?;
        self.request(request, ReplyKind::Ack)
            .await
            .map(|_| ())
            .map_err(|error| error.into_route_error(true))
    }

    async fn existing(
        &mut self,
        routes: &BTreeSet<OsRoute>,
    ) -> Result<BTreeSet<OsRoute>, RouteError> {
        let mut requested = BTreeMap::<_, Vec<&OsRoute>>::new();
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
    route: &OsRoute,
    message_type: u16,
    flags: u16,
) -> Result<MessageBuilder, RouteError> {
    // Linux treats a zero delete priority as a wildcard. Resolve defaults
    // before constructing OsRoute, and never emit an ambiguous delete request.
    if route.ifindex == 0
        || route.table == 0
        || route
            .preferred_source
            .is_some_and(|source| source.is_ipv4() != route.destination.first_address().is_ipv4())
    {
        return Err(RouteError::Failed(anyhow::anyhow!(
            "invalid resolved route parameters"
        )));
    }
    let message = RouteMessageBuilder::new(family(route.destination))
        .destination(
            route.destination.first_address(),
            route.destination.network_length(),
        )
        .oif(route.ifindex)
        .priority(route.metric.get())
        .table(route.table)
        .static_protocol()
        .universe_scope()
        .route_type(RouteType::Unicast);
    let message = if let Some(source) = route.preferred_source {
        message.preferred_source(source)
    } else {
        message
    }
    .build();
    let mut request = MessageBuilder::new(message_type, flags);
    let mut bytes = Vec::new();
    message
        .write_to(&mut bytes)
        .map_err(|error| RouteError::Failed(error.into()))?;
    request.append_bytes(&bytes);
    Ok(request)
}

fn physical_key(route: &OsRoute) -> (u32, IpCidr, u32, NonZeroU32, Option<IpAddr>) {
    (
        route.table,
        route.destination,
        route.ifindex,
        route.metric,
        route.preferred_source,
    )
}

fn direct_key(
    message: &RouteMessage,
) -> io::Result<Option<(u32, IpCidr, u32, NonZeroU32, Option<IpAddr>)>> {
    if message.protocol() != libc::RTPROT_STATIC
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
    let Some(metric) = NonZeroU32::new(message.priority()?) else {
        return Ok(None);
    };
    Ok(Some((
        message.table()?,
        destination,
        ifindex,
        metric,
        message.preferred_source()?,
    )))
}

#[cfg(test)]
fn equivalent(message: &RouteMessage, route: &OsRoute) -> io::Result<bool> {
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

    fn ip(namespace: &crate::common::netns::NetNS, args: &[&str]) {
        let output = namespace
            .run(|| std::process::Command::new("ip").args(args).output())
            .unwrap()
            .unwrap();
        assert!(
            output.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn dummy(namespace: &crate::common::netns::NetNS, name: &str) -> u32 {
        ip(namespace, &["link", "add", name, "type", "dummy"]);
        ip(namespace, &["link", "set", name, "up"]);
        namespace
            .run(|| nix::net::if_::if_nametoindex(name))
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn kernel_exclusive_slots_and_exact_delete_preserve_other_routes() {
        let namespace = crate::common::netns::isolated_namespace_for_test().unwrap();
        let a = dummy(&namespace, "et-a");
        let b = dummy(&namespace, "et-b");
        let shared = crate::host_runtime::native_host_runtime()
            .shared_executor()
            .unwrap();
        let mut backend = PlatformRouteBackend::new(namespace.platform(), &shared).unwrap();
        for prefix in ["198.18.71.0/24", "2001:db8:71::/64"] {
            let first = route(prefix, a, 65535);
            backend.add(&first).await.unwrap();
            assert!(
                backend
                    .add(&first)
                    .await
                    .unwrap_err()
                    .is_errno(libc::EEXIST)
            );
            let conflict = OsRoute {
                ifindex: b,
                ..first.clone()
            };
            assert_eq!(first.slot(), conflict.slot());
            assert!(
                backend
                    .add(&conflict)
                    .await
                    .unwrap_err()
                    .is_errno(libc::EEXIST)
            );
            assert!(
                backend
                    .existing(&BTreeSet::from([conflict.clone()]))
                    .await
                    .unwrap()
                    .is_empty()
            );
            let alternate = OsRoute {
                metric: NonZeroU32::new(65534).unwrap(),
                ..conflict.clone()
            };
            let other_table = OsRoute {
                table: 501,
                ..conflict.clone()
            };
            backend.add(&alternate).await.unwrap();
            backend.add(&other_table).await.unwrap();
            let wanted = BTreeSet::from([first.clone(), alternate.clone(), other_table.clone()]);
            assert_eq!(backend.existing(&wanted).await.unwrap(), wanted);
            assert!(
                backend.remove(&conflict).await.is_err(),
                "wrong interface cannot delete the owned route"
            );
            assert!(backend.contains(&first).await.unwrap());
            backend.remove(&first).await.unwrap();
            assert_eq!(
                backend.existing(&wanted).await.unwrap(),
                BTreeSet::from([alternate.clone(), other_table.clone()])
            );
            backend.remove(&alternate).await.unwrap();
            backend.remove(&other_table).await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn kernel_missing_ack_remains_unknown_and_late_ack_is_not_reused() {
        let namespace = crate::common::netns::isolated_namespace_for_test().unwrap();
        let index = dummy(&namespace, "et-a");
        let shared = crate::host_runtime::native_host_runtime()
            .shared_executor()
            .unwrap();
        let mut backend = PlatformRouteBackend::new(namespace.platform(), &shared).unwrap();
        let first = route("198.18.72.0/24", index, 65535);
        let second = route("198.18.73.0/24", index, 65535);
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
        backend.add(&second).await.unwrap();
        assert!(backend.contains(&first).await.unwrap());
        backend.timeout = Duration::from_millis(50);
        let request = route_request(&first, RTM_DELROUTE, NLM_F_REQUEST).unwrap();
        let error = backend
            .request(request, ReplyKind::Ack)
            .await
            .err()
            .expect("successful delete without ACK must time out");
        assert!(matches!(
            error.into_route_error(true),
            RouteError::Unknown(_)
        ));
        assert!(!backend.contains(&first).await.unwrap());
        backend.remove(&second).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace"]
    async fn kernel_backend_reactor_outlives_the_first_instance_executor() {
        use crate::common::native_executor::NativeExecutor;
        let namespace = crate::common::netns::isolated_namespace_for_test().unwrap();
        let index = dummy(&namespace, "et-a");
        let first = NativeExecutor::new(false, 1).unwrap();
        let mut backend = first
            .handle()
            .spawn(async move {
                let shared = crate::host_runtime::native_host_runtime()
                    .shared_executor()
                    .unwrap();
                PlatformRouteBackend::new(namespace.platform(), &shared).unwrap()
            })
            .await
            .unwrap();
        first.request_shutdown();
        tokio::time::timeout(Duration::from_secs(5), first.wait_stopped())
            .await
            .unwrap();
        let owned = route("198.18.74.0/24", index, 65535);
        backend.add(&owned).await.unwrap();
        assert!(backend.contains(&owned).await.unwrap());
        backend.remove(&owned).await.unwrap();
    }
    fn route(destination: &str, ifindex: u32, metric: u32) -> OsRoute {
        OsRoute {
            table: 254,
            destination: destination.parse().unwrap(),
            ifindex,
            metric: NonZeroU32::new(metric).unwrap(),
            preferred_source: None,
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
                        &OsRoute {
                            metric: NonZeroU32::new(5).unwrap(),
                            preferred_source: None,
                            ..route.clone()
                        }
                    )
                    .unwrap()
                );
                assert!(
                    !equivalent(
                        &message,
                        &OsRoute {
                            ifindex: 8,
                            ..route.clone()
                        }
                    )
                    .unwrap()
                );
            }
        }
        assert!(
            route_request(
                &route("10.71.0.0/24", 0, 65535),
                RTM_DELROUTE,
                NLM_F_REQUEST
            )
            .is_err()
        );
    }
}
