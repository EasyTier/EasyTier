use std::{
    ffi::CString,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZero,
    os::fd::AsRawFd,
};

use anyhow::Context;
use async_trait::async_trait;
use cidr::IpInet;
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage},
    route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteMessage, RouteProtocol, RouteScope,
        RouteType,
    },
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use nix::{
    ifaddrs::getifaddrs,
    libc::{self, ifreq, ioctl, Ioctl, SIOCGIFFLAGS, SIOCGIFMTU, SIOCSIFFLAGS, SIOCSIFMTU},
    net::if_::InterfaceFlags,
    sys::socket::SockaddrLike as _,
};
use pnet::ipnetwork::ip_mask_to_prefix;

use super::{route::Route, Error, IfConfiguerTrait};

pub(crate) fn dummy_socket() -> Result<std::net::UdpSocket, Error> {
    Ok(std::net::UdpSocket::bind("0:0")?)
}

fn build_ifreq(name: &str) -> ifreq {
    let c_str = CString::new(name).unwrap();
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = c_str.as_bytes_with_nul();
    for (i, &b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn send_netlink_req<T: NetlinkDeserializable + NetlinkSerializable + Debug>(
    req: T,
    flags: u16,
) -> Result<Socket, Error> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut req: NetlinkMessage<T> =
        NetlinkMessage::new(NetlinkHeader::default(), NetlinkPayload::InnerMessage(req));
    req.header.flags = flags;

    req.finalize();
    let mut buf = vec![0; req.header.length as _];
    req.serialize(&mut buf);

    tracing::debug!("net link request >>> {:?}", req);
    socket.send(&buf, 0)?;

    Ok(socket)
}

fn send_netlink_req_and_wait_one_resp<T: NetlinkDeserializable + NetlinkSerializable + Debug>(
    req: T,
    is_remove: bool,
) -> Result<(), Error> {
    let socket = send_netlink_req(
        req,
        NLM_F_ACK | NLM_F_CREATE | NLM_F_REQUEST | if !is_remove { NLM_F_EXCL } else { 0 },
    )?;
    let resp = socket.recv_from_full()?;
    let ret = NetlinkMessage::<T>::deserialize(&resp.0)
        .with_context(|| "Failed to deserialize netlink message")?;

    tracing::debug!("net link response <<< {:?}", ret);

    match ret.payload {
        NetlinkPayload::Error(e) => {
            if e.code == NonZero::new(0) {
                return Ok(());
            } else {
                return Err(e.to_io().into());
            }
        }
        p => {
            tracing::error!("Unexpected netlink response: {:?}", p);
            return Err(anyhow::anyhow!("Unexpected netlink response").into());
        }
    }
}

fn addr_to_ip(addr: RouteAddress) -> Option<IpAddr> {
    match addr {
        RouteAddress::Inet(addr) => Some(addr.into()),
        RouteAddress::Inet6(addr) => Some(addr.into()),
        _ => None,
    }
}

impl From<RouteMessage> for Route {
    fn from(msg: RouteMessage) -> Self {
        let mut gateway = None;
        let mut source = None;
        let mut source_hint = None;
        let mut destination = None;
        let mut ifindex = None;
        let mut metric = None;

        for attr in msg.attributes {
            match attr {
                RouteAttribute::Source(addr) => {
                    source = addr_to_ip(addr);
                }
                RouteAttribute::PrefSource(addr) => {
                    source_hint = addr_to_ip(addr);
                }
                RouteAttribute::Destination(addr) => {
                    destination = addr_to_ip(addr);
                }
                RouteAttribute::Gateway(addr) => {
                    gateway = addr_to_ip(addr);
                }
                RouteAttribute::Oif(i) => {
                    ifindex = Some(i);
                }
                RouteAttribute::Priority(priority) => {
                    metric = Some(priority);
                }
                _ => {}
            }
        }
        // rtnetlink gives None instead of 0.0.0.0 for the default route, but we'll convert to 0 here to make it match the other platforms
        let destination = destination.unwrap_or_else(|| match msg.header.address_family {
            AddressFamily::Inet => Ipv4Addr::UNSPECIFIED.into(),
            AddressFamily::Inet6 => Ipv6Addr::UNSPECIFIED.into(),
            _ => panic!("invalid destination family"),
        });
        Self {
            destination,
            prefix: msg.header.destination_prefix_length,
            source,
            source_prefix: msg.header.source_prefix_length,
            source_hint,
            gateway,
            ifindex,
            table: msg.header.table,
            metric,
        }
    }
}

pub struct NetlinkIfConfiger {}

impl NetlinkIfConfiger {
    fn get_interface_index(name: &str) -> Result<u32, Error> {
        let name = CString::new(name).with_context(|| "failed to convert interface name")?;
        match unsafe { libc::if_nametoindex(name.as_ptr()) } {
            0 => Err(std::io::Error::last_os_error().into()),
            n => Ok(n),
        }
    }

    fn get_prefix_len(name: &str, ip: Ipv4Addr) -> Result<u8, Error> {
        let addrs = Self::list_addresses(name)?;
        for addr in addrs {
            if addr.address() == IpAddr::V4(ip) {
                return Ok(addr.network_length());
            }
        }
        Err(Error::NotFound)
    }

    fn remove_one_ip(name: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let mut message = AddressMessage::default();
        message.header.prefix_len = prefix_len;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V4(ip)));

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::DelAddress(message),
            true,
        )
    }

    pub(crate) fn mtu_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        value: libc::c_int,
    ) -> Result<u32, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let dummy_socket = dummy_socket()?;

        let mut ifr: ifreq = build_ifreq(name);

        unsafe {
            ifr.ifr_ifru.ifru_mtu = value;

            // 使用ioctl获取MTU
            if ioctl(dummy_socket.as_raw_fd(), op.try_into().unwrap(), &ifr) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu as u32 })
    }

    fn mtu(name: &str) -> Result<u32, Error> {
        Self::mtu_op(name, SIOCGIFMTU, 0)
    }

    pub fn list_addresses(name: &str) -> Result<Vec<IpInet>, Error> {
        let mut result = vec![];

        for interface in getifaddrs()
            .with_context(|| "failed to call getifaddrs")?
            .filter(|x| x.interface_name == name)
        {
            let (Some(address), Some(netmask)) = (interface.address, interface.netmask) else {
                continue;
            };

            use nix::sys::socket::AddressFamily::{Inet, Inet6};

            let (address, netmask) = match (address.family(), netmask.family()) {
                (Some(Inet), Some(Inet)) => (
                    IpAddr::V4(address.as_sockaddr_in().unwrap().ip().into()),
                    IpAddr::V4(netmask.as_sockaddr_in().unwrap().ip().into()),
                ),
                (Some(Inet6), Some(Inet6)) => (
                    IpAddr::V6(address.as_sockaddr_in6().unwrap().ip()),
                    IpAddr::V6(netmask.as_sockaddr_in6().unwrap().ip()),
                ),
                (_, _) => continue,
            };

            let prefix = ip_mask_to_prefix(netmask).unwrap();

            result.push(IpInet::new(address, prefix).unwrap());
        }
        Ok(result)
    }

    pub(crate) fn set_flags_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        flags: InterfaceFlags,
    ) -> Result<InterfaceFlags, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let mut req = build_ifreq(name);
        req.ifr_ifru.ifru_flags = flags.bits() as _;

        let socket = dummy_socket()?;

        unsafe {
            if ioctl(socket.as_raw_fd(), op.try_into().unwrap(), &req) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(InterfaceFlags::from_bits_truncate(
                req.ifr_ifru.ifru_flags as _,
            ))
        }
    }

    pub(crate) fn set_flags(name: &str, flags: InterfaceFlags) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCSIFFLAGS, flags)
    }

    pub(crate) fn get_flags(name: &str) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCGIFFLAGS, InterfaceFlags::empty())
    }

    fn list_routes() -> Result<Vec<RouteMessage>, Error> {
        let mut message = RouteMessage::default();

        message.header.table = RouteHeader::RT_TABLE_UNSPEC;
        message.header.protocol = RouteProtocol::Unspec;

        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;

        message.header.address_family = AddressFamily::Inet;
        message.header.destination_prefix_length = 0;
        message.header.source_prefix_length = 0;

        let s = send_netlink_req(
            RouteNetlinkMessage::GetRoute(message),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;

        let mut ret_vec = vec![];

        let mut resp = Vec::<u8>::new();
        loop {
            if resp.len() == 0 {
                let (new_resp, _) = s.recv_from_full()?;
                resp = new_resp;
            }
            let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp)
                .with_context(|| "Failed to deserialize netlink message")?;
            resp = resp.split_off(ret.buffer_len());

            tracing::debug!("net link response <<< {:?}", ret);

            match ret.payload {
                NetlinkPayload::Error(e) => {
                    if e.code == NonZero::new(0) {
                        continue;
                    } else {
                        return Err(e.to_io().into());
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
                    tracing::debug!("net link response <<< {:?}", m);
                    ret_vec.push(m);
                }
                NetlinkPayload::Done(_) => {
                    break;
                }
                p => {
                    tracing::error!("Unexpected netlink response: {:?}", p);
                    return Err(anyhow::anyhow!("Unexpected netlink response").into());
                }
            }
        }

        Ok(ret_vec)
    }
}

#[async_trait]
impl IfConfiguerTrait for NetlinkIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let mut message = RouteMessage::default();

        message.header.table = RouteHeader::RT_TABLE_MAIN;
        message.header.protocol = RouteProtocol::Static;
        message.header.scope = RouteScope::Universe;
        message.header.kind = RouteType::Unicast;
        message.header.address_family = AddressFamily::Inet;
        // metric
        message
            .attributes
            .push(RouteAttribute::Priority(cost.unwrap_or(65535) as u32));
        // output interface
        message
            .attributes
            .push(RouteAttribute::Oif(NetlinkIfConfiger::get_interface_index(
                name,
            )?));
        // source address
        message.header.destination_prefix_length = cidr_prefix;
        message
            .attributes
            .push(RouteAttribute::Destination(RouteAddress::Inet(address)));

        send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::NewRoute(message), false)
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let routes = Self::list_routes()?;
        let ifidx = NetlinkIfConfiger::get_interface_index(name)?;

        for msg in routes {
            let other_route: Route = msg.clone().into();
            if other_route.destination == std::net::IpAddr::V4(address)
                && other_route.prefix == cidr_prefix
                && other_route.ifindex == Some(ifidx)
            {
                send_netlink_req_and_wait_one_resp(RouteNetlinkMessage::DelRoute(msg), true)?;
                return Ok(());
            }
        }

        Ok(())
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let mut message = AddressMessage::default();

        message.header.prefix_len = cidr_prefix;
        message.header.index = NetlinkIfConfiger::get_interface_index(name)?;
        message.header.family = AddressFamily::Inet;

        message
            .attributes
            .push(AddressAttribute::Address(std::net::IpAddr::V4(address)));

        // for IPv4 the IFA_LOCAL address can be set to the same value as
        // IFA_ADDRESS
        message
            .attributes
            .push(AddressAttribute::Local(std::net::IpAddr::V4(address)));

        // set the IFA_BROADCAST address as well
        if cidr_prefix == 32 {
            message
                .attributes
                .push(AddressAttribute::Broadcast(address));
        } else {
            let ip_addr = u32::from(address);
            let brd = Ipv4Addr::from((0xffff_ffff_u32) >> u32::from(cidr_prefix) | ip_addr);
            message.attributes.push(AddressAttribute::Broadcast(brd));
        };

        send_netlink_req_and_wait_one_resp::<RouteNetlinkMessage>(
            RouteNetlinkMessage::NewAddress(message),
            false,
        )
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        let mut flags = Self::get_flags(name)?;
        flags.set(InterfaceFlags::IFF_UP, up);
        Self::set_flags(name, flags)?;
        Ok(())
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Addr>) -> Result<(), Error> {
        if ip.is_none() {
            let addrs = Self::list_addresses(name)?;
            for addr in addrs {
                if let IpAddr::V4(ipv4) = addr.address() {
                    Self::remove_one_ip(name, ipv4, addr.network_length())?;
                }
            }
        } else {
            let ip = ip.unwrap();
            let prefix_len = Self::get_prefix_len(name, ip)?;
            Self::remove_one_ip(name, ip, prefix_len)?;
        }

        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        Self::mtu_op(name, SIOCSIFMTU, mtu as libc::c_int)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY_IFACE_NAME: &str = "dummy";

    fn run_cmd(cmd: &str) -> String {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("failed to execute process");
        String::from_utf8(output.stdout).unwrap()
    }

    struct PrepareEnv {}
    impl PrepareEnv {
        fn new() -> Self {
            let _ = run_cmd(&format!("sudo ip link add {} type dummy", DUMMY_IFACE_NAME));
            PrepareEnv {}
        }
    }

    impl Drop for PrepareEnv {
        fn drop(&mut self) {
            let _ = run_cmd(&format!("sudo ip link del {}", DUMMY_IFACE_NAME));
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn addr_test() {
        let _prepare_env = PrepareEnv::new();
        let ifcfg = NetlinkIfConfiger {};
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        ifcfg
            .add_ipv4_ip(DUMMY_IFACE_NAME, "10.44.44.4".parse().unwrap(), 24)
            .await
            .unwrap();

        let addrs = NetlinkIfConfiger::list_addresses(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0].address(),
            IpAddr::V4("10.44.44.4".parse().unwrap())
        );
        assert_eq!(addrs[0].network_length(), 24);

        NetlinkIfConfiger::remove_one_ip(DUMMY_IFACE_NAME, "10.44.44.4".parse().unwrap(), 24)
            .unwrap();

        let addrs = NetlinkIfConfiger::list_addresses(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(addrs.len(), 0);

        let old_mtu = NetlinkIfConfiger::mtu(DUMMY_IFACE_NAME).unwrap();
        assert_ne!(old_mtu, 0);

        let new_mtu = old_mtu + 1;
        ifcfg.set_mtu(DUMMY_IFACE_NAME, new_mtu).await.unwrap();

        let mtu = NetlinkIfConfiger::mtu(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(mtu, new_mtu);

        ifcfg
            .set_link_status(DUMMY_IFACE_NAME, false)
            .await
            .unwrap();
        ifcfg.set_link_status(DUMMY_IFACE_NAME, true).await.unwrap();
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn route_test() {
        let _prepare_env = PrepareEnv::new();
        let ret = NetlinkIfConfiger::list_routes().unwrap();

        let ifcfg = NetlinkIfConfiger {};
        println!("{:?}", ret);

        ifcfg.set_link_status(DUMMY_IFACE_NAME, true).await.unwrap();

        ifcfg
            .add_ipv4_route(DUMMY_IFACE_NAME, "10.5.5.0".parse().unwrap(), 24, None)
            .await
            .unwrap();

        let routes = NetlinkIfConfiger::list_routes()
            .unwrap()
            .into_iter()
            .map(Route::from)
            .map(|x| x.destination)
            .collect::<Vec<_>>();
        assert!(routes.contains(&IpAddr::V4("10.5.5.0".parse().unwrap())));

        ifcfg
            .remove_ipv4_route(DUMMY_IFACE_NAME, "10.5.5.0".parse().unwrap(), 24)
            .await
            .unwrap();
        let routes = NetlinkIfConfiger::list_routes()
            .unwrap()
            .into_iter()
            .map(Route::from)
            .map(|x| x.destination)
            .collect::<Vec<_>>();
        assert!(!routes.contains(&IpAddr::V4("10.5.5.0".parse().unwrap())));
    }
}
