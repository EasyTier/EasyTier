use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use nix::libc;

// Minimal Linux rtnetlink wire support used by ifcfg. Fixed headers and integer
// attributes use native byte order; IP address attributes contain network-order octets.
pub(crate) const NLM_F_REQUEST: u16 = 0x01;
pub(crate) const NLM_F_ACK: u16 = 0x04;
pub(crate) const NLM_F_DUMP_INTR: u16 = 0x10;
pub(crate) const NLM_F_DUMP: u16 = 0x300;
pub(crate) const NLM_F_EXCL: u16 = 0x200;
pub(crate) const NLM_F_CREATE: u16 = 0x400;

pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;
pub(crate) const RTM_NEWADDR: u16 = 20;
pub(crate) const RTM_DELADDR: u16 = 21;
pub(crate) const RTM_NEWROUTE: u16 = 24;
pub(crate) const RTM_DELROUTE: u16 = 25;
pub(crate) const RTM_GETROUTE: u16 = 26;
pub(crate) const RTM_NEWNEIGH: u16 = 28;
pub(crate) const RTM_DELNEIGH: u16 = 29;
pub(crate) const RTM_GETNEIGH: u16 = 30;

const NLMSG_HEADER_LEN: usize = 16;
const ATTRIBUTE_HEADER_LEN: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_BROADCAST: u16 = 4;

const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_OIF: u16 = 4;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;

const NDA_DST: u16 = 1;
const NTF_PROXY: u8 = 0x08;
const NUD_PERMANENT: u16 = 0x80;

fn align4(len: usize) -> Option<usize> {
    len.checked_add(3).map(|len| len & !3)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_u16(bytes: &[u8]) -> io::Result<u16> {
    bytes
        .get(..2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_ne_bytes)
        .ok_or_else(|| invalid_data("truncated netlink u16"))
}

fn read_u32(bytes: &[u8]) -> io::Result<u32> {
    bytes
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_ne_bytes)
        .ok_or_else(|| invalid_data("truncated netlink u32"))
}

fn read_i32(bytes: &[u8]) -> io::Result<i32> {
    bytes
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(i32::from_ne_bytes)
        .ok_or_else(|| invalid_data("truncated netlink i32"))
}

#[derive(Debug)]
pub(crate) struct MessageBuilder {
    bytes: Vec<u8>,
}

impl MessageBuilder {
    pub(crate) fn new(message_type: u16, flags: u16) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(&message_type.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        Self { bytes }
    }

    pub(crate) fn append_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn finish(mut self) -> io::Result<Vec<u8>> {
        let len = u32::try_from(self.bytes.len())
            .map_err(|_| invalid_data("netlink message is too large"))?;
        self.bytes[..4].copy_from_slice(&len.to_ne_bytes());
        Ok(self.bytes)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct MessageHeader {
    pub(crate) message_type: u16,
    pub(crate) flags: u16,
}

pub(crate) struct MessageIter<'a> {
    bytes: &'a [u8],
}

impl<'a> MessageIter<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> Iterator for MessageIter<'a> {
    type Item = io::Result<(MessageHeader, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        if self.bytes.len() < NLMSG_HEADER_LEN {
            self.bytes = &[];
            return Some(Err(invalid_data("truncated netlink header")));
        }

        let len = match read_u32(self.bytes) {
            Ok(len) => len as usize,
            Err(err) => {
                self.bytes = &[];
                return Some(Err(err));
            }
        };
        if len < NLMSG_HEADER_LEN || len > self.bytes.len() {
            self.bytes = &[];
            return Some(Err(invalid_data("invalid netlink message length")));
        }
        let aligned_len = match align4(len) {
            Some(len) => len,
            None => {
                self.bytes = &[];
                return Some(Err(invalid_data("netlink message length overflow")));
            }
        };
        if aligned_len > self.bytes.len() {
            self.bytes = &[];
            return Some(Err(invalid_data("truncated netlink message padding")));
        }

        let message_type = read_u16(&self.bytes[4..]).expect("header length checked");
        let flags = read_u16(&self.bytes[6..]).expect("header length checked");
        let payload = &self.bytes[NLMSG_HEADER_LEN..len];
        self.bytes = &self.bytes[aligned_len..];
        Some(Ok((
            MessageHeader {
                message_type,
                flags,
            },
            payload,
        )))
    }
}

pub(crate) fn netlink_error_code(payload: &[u8]) -> io::Result<i32> {
    read_i32(payload)
}

#[derive(Clone, Debug)]
struct Attribute {
    kind: u16,
    value: Vec<u8>,
}

impl Attribute {
    fn new(kind: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }

    fn write_to(&self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let len = ATTRIBUTE_HEADER_LEN
            .checked_add(self.value.len())
            .ok_or_else(|| invalid_data("netlink attribute length overflow"))?;
        let len = u16::try_from(len).map_err(|_| invalid_data("netlink attribute is too large"))?;
        bytes.extend_from_slice(&len.to_ne_bytes());
        bytes.extend_from_slice(&self.kind.to_ne_bytes());
        bytes.extend_from_slice(&self.value);
        let aligned_len = align4(bytes.len())
            .ok_or_else(|| invalid_data("netlink attribute alignment overflow"))?;
        bytes.resize(aligned_len, 0);
        Ok(())
    }
}

fn parse_attributes(mut bytes: &[u8]) -> io::Result<Vec<Attribute>> {
    let mut attributes = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(invalid_data("truncated netlink attribute header"));
        }
        let len = read_u16(bytes)? as usize;
        if len < ATTRIBUTE_HEADER_LEN || len > bytes.len() {
            return Err(invalid_data("invalid netlink attribute length"));
        }
        let kind = read_u16(&bytes[2..])?;
        attributes.push(Attribute::new(
            kind,
            bytes[ATTRIBUTE_HEADER_LEN..len].to_vec(),
        ));

        let aligned_len =
            align4(len).ok_or_else(|| invalid_data("netlink attribute length overflow"))?;
        if aligned_len > bytes.len() {
            return Err(invalid_data("truncated netlink attribute padding"));
        }
        bytes = &bytes[aligned_len..];
    }
    Ok(attributes)
}

fn write_attributes(attributes: &[Attribute], bytes: &mut Vec<u8>) -> io::Result<()> {
    for attribute in attributes {
        attribute.write_to(bytes)?;
    }
    Ok(())
}

fn ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn parse_ip(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET if bytes.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        libc::AF_INET6 if bytes.len() == 16 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).ok()?,
        ))),
        _ => None,
    }
}

pub(crate) trait NetlinkEncode {
    fn write_to(&self, bytes: &mut Vec<u8>) -> io::Result<()>;
}

pub(crate) trait NetlinkDecode: Sized {
    const MESSAGE_TYPE: u16;

    fn from_bytes(bytes: &[u8]) -> io::Result<Self>;
}

#[derive(Clone, Debug)]
pub(crate) struct AddressMessage {
    family: u8,
    prefix_len: u8,
    ifindex: u32,
    attributes: Vec<Attribute>,
}

impl AddressMessage {
    pub(crate) fn new(family: u8, ifindex: u32, prefix_len: u8, address: IpAddr) -> Self {
        Self {
            family,
            prefix_len,
            ifindex,
            attributes: vec![Attribute::new(IFA_ADDRESS, ip_bytes(address))],
        }
    }

    pub(crate) fn local(mut self, address: IpAddr) -> Self {
        self.attributes
            .push(Attribute::new(IFA_LOCAL, ip_bytes(address)));
        self
    }

    pub(crate) fn broadcast(mut self, address: Ipv4Addr) -> Self {
        self.attributes
            .push(Attribute::new(IFA_BROADCAST, address.octets().to_vec()));
        self
    }
}

impl NetlinkEncode for AddressMessage {
    fn write_to(&self, bytes: &mut Vec<u8>) -> io::Result<()> {
        bytes.extend_from_slice(&[self.family, self.prefix_len, 0, 0]);
        bytes.extend_from_slice(&self.ifindex.to_ne_bytes());
        write_attributes(&self.attributes, bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RouteType {
    Unicast,
    Blackhole,
    Other(u8),
}

impl RouteType {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::Unicast,
            6 => Self::Blackhole,
            value => Self::Other(value),
        }
    }

    fn raw(self) -> u8 {
        match self {
            Self::Unicast => 1,
            Self::Blackhole => 6,
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RouteMessage {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    route_type: u8,
    flags: u32,
    attributes: Vec<Attribute>,
    destination: Option<IpAddr>,
    source: Option<IpAddr>,
    oif: Option<u32>,
}

impl RouteMessage {
    pub(crate) fn family(&self) -> u8 {
        self.family
    }

    pub(crate) fn dst_len(&self) -> u8 {
        self.dst_len
    }

    pub(crate) fn src_len(&self) -> u8 {
        self.src_len
    }

    pub(crate) fn route_type(&self) -> RouteType {
        RouteType::from_raw(self.route_type)
    }

    pub(crate) fn destination(&self) -> Option<&IpAddr> {
        self.destination.as_ref()
    }

    pub(crate) fn source(&self) -> Option<&IpAddr> {
        self.source.as_ref()
    }

    pub(crate) fn oif(&self) -> Option<u32> {
        self.oif
    }
}

impl RouteMessage {
    pub(crate) fn dump_header() -> Vec<u8> {
        vec![0; 12]
    }
}

impl NetlinkDecode for RouteMessage {
    const MESSAGE_TYPE: u16 = RTM_NEWROUTE;

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 12 {
            return Err(invalid_data("truncated route message"));
        }
        let family = bytes[0];
        let attributes = parse_attributes(&bytes[12..])?;
        let destination = attributes
            .iter()
            .find(|attribute| attribute.kind & NLA_TYPE_MASK == RTA_DST)
            .and_then(|attribute| parse_ip(family, &attribute.value));
        let source = attributes
            .iter()
            .find(|attribute| attribute.kind & NLA_TYPE_MASK == RTA_SRC)
            .and_then(|attribute| parse_ip(family, &attribute.value));
        let oif = attributes
            .iter()
            .find(|attribute| attribute.kind & NLA_TYPE_MASK == RTA_OIF)
            .and_then(|attribute| read_u32(&attribute.value).ok());

        Ok(Self {
            family,
            dst_len: bytes[1],
            src_len: bytes[2],
            tos: bytes[3],
            table: bytes[4],
            protocol: bytes[5],
            scope: bytes[6],
            route_type: bytes[7],
            flags: read_u32(&bytes[8..])?,
            attributes,
            destination,
            source,
            oif,
        })
    }
}

impl NetlinkEncode for RouteMessage {
    fn write_to(&self, bytes: &mut Vec<u8>) -> io::Result<()> {
        bytes.extend_from_slice(&[
            self.family,
            self.dst_len,
            self.src_len,
            self.tos,
            self.table,
            self.protocol,
            self.scope,
            self.route_type,
        ]);
        bytes.extend_from_slice(&self.flags.to_ne_bytes());
        write_attributes(&self.attributes, bytes)
    }
}

#[derive(Debug)]
pub(crate) struct RouteMessageBuilder {
    message: RouteMessage,
}

impl RouteMessageBuilder {
    pub(crate) fn new(family: u8) -> Self {
        Self {
            message: RouteMessage {
                family,
                dst_len: 0,
                src_len: 0,
                tos: 0,
                table: 0,
                protocol: 0,
                scope: 0,
                route_type: 0,
                flags: 0,
                attributes: Vec::new(),
                destination: None,
                source: None,
                oif: None,
            },
        }
    }

    pub(crate) fn destination(mut self, address: IpAddr, prefix_len: u8) -> Self {
        self.message.dst_len = prefix_len;
        self.message.destination = Some(address);
        self.message
            .attributes
            .push(Attribute::new(RTA_DST, ip_bytes(address)));
        self
    }

    pub(crate) fn oif(mut self, ifindex: u32) -> Self {
        self.message.oif = Some(ifindex);
        self.message
            .attributes
            .push(Attribute::new(RTA_OIF, ifindex.to_ne_bytes().to_vec()));
        self
    }

    pub(crate) fn priority(mut self, priority: u32) -> Self {
        self.message.attributes.push(Attribute::new(
            RTA_PRIORITY,
            priority.to_ne_bytes().to_vec(),
        ));
        self
    }

    pub(crate) fn table(mut self, table: u32) -> Self {
        if let Ok(table) = u8::try_from(table) {
            self.message.table = table;
        } else {
            self.message
                .attributes
                .push(Attribute::new(RTA_TABLE, table.to_ne_bytes().to_vec()));
        }
        self
    }

    pub(crate) fn static_protocol(mut self) -> Self {
        self.message.protocol = libc::RTPROT_STATIC;
        self
    }

    pub(crate) fn universe_scope(mut self) -> Self {
        self.message.scope = libc::RT_SCOPE_UNIVERSE;
        self
    }

    pub(crate) fn route_type(mut self, route_type: RouteType) -> Self {
        self.message.route_type = route_type.raw();
        self
    }

    pub(crate) fn build(self) -> RouteMessage {
        self.message
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NeighborMessage {
    family: u8,
    ifindex: u32,
    state: u16,
    flags: u8,
    kind: u8,
    attributes: Vec<Attribute>,
    destination: Option<IpAddr>,
}

impl NeighborMessage {
    pub(crate) fn proxy(ifindex: u32, address: Ipv6Addr) -> Self {
        Self {
            family: libc::AF_INET6 as u8,
            ifindex,
            state: NUD_PERMANENT,
            flags: NTF_PROXY,
            kind: 0,
            attributes: vec![Attribute::new(NDA_DST, address.octets().to_vec())],
            destination: Some(IpAddr::V6(address)),
        }
    }

    pub(crate) fn proxy_dump_header(family: u8) -> Vec<u8> {
        let mut bytes = vec![family, 0, 0, 0];
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(&0_u16.to_ne_bytes());
        bytes.extend_from_slice(&[NTF_PROXY, 0]);
        bytes
    }

    pub(crate) fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub(crate) fn is_proxy(&self) -> bool {
        self.flags & NTF_PROXY != 0
    }

    pub(crate) fn destination(&self) -> Option<&IpAddr> {
        self.destination.as_ref()
    }
}

impl NetlinkDecode for NeighborMessage {
    const MESSAGE_TYPE: u16 = RTM_NEWNEIGH;

    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 12 {
            return Err(invalid_data("truncated neighbor message"));
        }
        let family = bytes[0];
        let attributes = parse_attributes(&bytes[12..])?;
        let destination = attributes
            .iter()
            .find(|attribute| attribute.kind & NLA_TYPE_MASK == NDA_DST)
            .and_then(|attribute| parse_ip(family, &attribute.value));
        Ok(Self {
            family,
            ifindex: read_u32(&bytes[4..])?,
            state: read_u16(&bytes[8..])?,
            flags: bytes[10],
            kind: bytes[11],
            attributes,
            destination,
        })
    }
}

impl NetlinkEncode for NeighborMessage {
    fn write_to(&self, bytes: &mut Vec<u8>) -> io::Result<()> {
        bytes.extend_from_slice(&[self.family, 0, 0, 0]);
        bytes.extend_from_slice(&self.ifindex.to_ne_bytes());
        bytes.extend_from_slice(&self.state.to_ne_bytes());
        bytes.extend_from_slice(&[self.flags, self.kind]);
        write_attributes(&self.attributes, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<T: NetlinkEncode>(message: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        message.write_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn route_round_trip_preserves_unknown_attributes() {
        let mut message = RouteMessageBuilder::new(libc::AF_INET6 as u8)
            .destination("2001:db8::".parse().unwrap(), 64)
            .oif(7)
            .priority(42)
            .table(libc::RT_TABLE_MAIN.into())
            .static_protocol()
            .universe_scope()
            .route_type(RouteType::Unicast)
            .build();
        message
            .attributes
            .push(Attribute::new(0x4321, vec![1, 2, 3, 4, 5]));

        let bytes = encode(&message);
        let decoded = RouteMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.destination(), message.destination());
        assert_eq!(decoded.oif(), Some(7));
        assert_eq!(decoded.route_type(), RouteType::Unicast);
        assert_eq!(encode(&decoded), bytes);
    }

    #[test]
    fn route_parser_reads_ipv6_source_prefix() {
        let mut bytes = vec![
            libc::AF_INET6 as u8,
            0,
            56,
            0,
            libc::RT_TABLE_MAIN,
            libc::RTPROT_STATIC,
            libc::RT_SCOPE_UNIVERSE,
            RouteType::Unicast.raw(),
        ];
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        Attribute::new(
            RTA_SRC,
            "2001:db8:1::"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        )
        .write_to(&mut bytes)
        .unwrap();

        let message = RouteMessage::from_bytes(&bytes).unwrap();
        assert_eq!(message.src_len(), 56);
        assert_eq!(message.source(), Some(&"2001:db8:1::".parse().unwrap()));
    }

    #[test]
    fn neighbor_proxy_round_trip() {
        let message = NeighborMessage::proxy(9, "2001:db8::1".parse().unwrap());
        let decoded = NeighborMessage::from_bytes(&encode(&message)).unwrap();
        assert_eq!(decoded.ifindex(), 9);
        assert!(decoded.is_proxy());
        assert_eq!(decoded.destination(), message.destination());
    }

    #[test]
    fn message_iterator_rejects_truncated_padding() {
        let mut bytes = MessageBuilder::new(RTM_GETROUTE, NLM_F_REQUEST)
            .finish()
            .unwrap();
        bytes[0..4].copy_from_slice(&17_u32.to_ne_bytes());
        bytes.push(0);
        assert!(MessageIter::new(&bytes).next().unwrap().is_err());
    }
}
