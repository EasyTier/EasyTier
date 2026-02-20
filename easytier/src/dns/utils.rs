use crate::proto;
use crate::proto::utils::RepeatedMessageModel;
use anyhow::{anyhow, Error};
use derive_more::{Deref, DerefMut};
use hickory_proto::rr::{LowerName, RecordType};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup};
use hickory_server::authority::{
    Authority, LookupControlFlow, LookupObject, LookupOptions, MessageRequest, UpdateResult,
    ZoneType,
};
use hickory_server::server::RequestInfo;
use idna::AsciiDenyList;
use itertools::Itertools;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use url::Url;

pub fn sanitize(name: &str) -> String {
    let dot = name.ends_with('.');
    let mut name = idna::domain_to_ascii_cow(name.as_ref(), AsciiDenyList::EMPTY)
        .unwrap_or_default()
        .into_owned()
        .to_lowercase()
        .split('.')
        .map(|label| {
            label
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .take(63)
                .collect::<String>()
                .trim_matches('-')
                .to_string()
        })
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    name.truncate(253);
    if dot {
        name.push('.');
    }
    name
}

pub fn parse(name: &str) -> LowerName {
    if let Ok(name) = name.parse() {
        name
    } else {
        let sanitized = sanitize(name);
        tracing::debug!("invalid hostname: {}, sanitized to: {}", name, sanitized);
        sanitized.parse().unwrap_or_default()
    }
}

static DNS_SUPPORTED_PROTOCOLS: [Protocol; 2] = [
    Protocol::Udp,
    Protocol::Tcp,
    // Protocol::Tls,
    // Protocol::Https,
    // Protocol::Quic,
    // Protocol::H3,
];

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct NameServerAddr {
    pub(super) protocol: Protocol,
    pub(super) addr: SocketAddr,
}

impl From<NameServerAddr> for NameServerConfig {
    fn from(value: NameServerAddr) -> Self {
        Self::new(value.addr, value.protocol)
    }
}

impl From<NameServerConfig> for NameServerAddr {
    fn from(value: NameServerConfig) -> Self {
        Self {
            protocol: value.protocol,
            addr: value.socket_addr,
        }
    }
}

impl From<SocketAddr> for NameServerAddr {
    fn from(value: SocketAddr) -> Self {
        Self {
            protocol: Protocol::Udp,
            addr: value,
        }
    }
}

impl From<IpAddr> for NameServerAddr {
    fn from(value: IpAddr) -> Self {
        SocketAddr::new(value, 53).into()
    }
}

impl From<NameServerAddr> for Url {
    fn from(value: NameServerAddr) -> Self {
        Url::parse(&format!("{}://{}", value.protocol, value.addr)).unwrap()
    }
}

impl TryFrom<&Url> for NameServerAddr {
    type Error = Error;

    fn try_from(value: &Url) -> Result<Self, Self::Error> {
        let scheme = value.scheme();
        let protocol = *DNS_SUPPORTED_PROTOCOLS
            .iter()
            .find(|p| p.to_string() == scheme)
            .ok_or(anyhow!("unsupported scheme: {}", scheme))?;
        let addr = value.host_str().ok_or(anyhow!("host not found"))?;
        let addr = addr
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map_err(|e| anyhow!("invalid ip address '{}': {}", addr, e))?;
        let port = if let Some(port) = value.port() {
            port
        } else {
            match protocol {
                Protocol::Udp | Protocol::Tcp => 53,
                _ => return Err(anyhow!("port not found")),
            }
        };

        Ok(Self {
            protocol,
            addr: SocketAddr::new(addr, port),
        })
    }
}

impl From<NameServerAddr> for proto::common::Url {
    fn from(value: NameServerAddr) -> Self {
        Url::from(value).into()
    }
}

impl TryFrom<&proto::common::Url> for NameServerAddr {
    type Error = Error;

    fn try_from(value: &proto::common::Url) -> Result<Self, Self::Error> {
        Self::try_from(&Url::try_from(value)?)
    }
}

impl FromStr for NameServerAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macro_rules! try_parse {
            ($($t:ty),+) => {
                $( if let Ok(v) = s.parse::<$t>() { return Ok(v.into()); } )+
            };
        }

        try_parse!(IpAddr, SocketAddr);

        (&Url::parse(s)?).try_into()
    }
}

impl Display for NameServerAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(Url::from(*self).as_str())
    }
}

pub(super) type NameServerAddrGroup = RepeatedMessageModel<NameServerAddr>;

impl From<NameServerAddrGroup> for NameServerConfigGroup {
    fn from(value: NameServerAddrGroup) -> Self {
        value.into_iter().map_into().collect_vec().into()
    }
}

impl From<NameServerConfigGroup> for NameServerAddrGroup {
    fn from(value: NameServerConfigGroup) -> Self {
        value
            .into_inner()
            .into_iter()
            .map_into()
            .collect_vec()
            .into()
    }
}

#[derive(Deref, DerefMut)]
pub struct ChainedAuthority<A>(pub(super) A)
where
    A: Authority,
    A::Lookup: LookupObject + 'static;

impl<A> From<A> for ChainedAuthority<A>
where
    A: Authority,
    A::Lookup: LookupObject + 'static,
{
    fn from(value: A) -> Self {
        Self(value)
    }
}

#[async_trait::async_trait]
impl<A> Authority for ChainedAuthority<A>
where
    A: Authority,
    A::Lookup: LookupObject + 'static,
{
    type Lookup = A::Lookup;

    #[inline]
    fn zone_type(&self) -> ZoneType {
        self.0.zone_type()
    }
    #[inline]
    fn is_axfr_allowed(&self) -> bool {
        self.0.is_axfr_allowed()
    }
    #[inline]
    async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
        self.0.update(update).await
    }
    #[inline]
    fn origin(&self) -> &LowerName {
        self.0.origin()
    }
    #[inline]
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.0.lookup(name, rtype, lookup_options).await
    }
    #[inline]
    async fn consult(
        &self,
        name: &LowerName,
        rtype: RecordType,
        lookup_options: LookupOptions,
        last_result: LookupControlFlow<Box<dyn LookupObject>>,
    ) -> LookupControlFlow<Box<dyn LookupObject>> {
        if let Some(Ok(l)) = last_result.map_result() {
            LookupControlFlow::Break(Ok(l))
        } else {
            self.0
                .lookup(name, rtype, lookup_options)
                .await
                .map(|l| Box::new(l) as _)
        }
    }
    #[inline]
    async fn search(
        &self,
        request_info: RequestInfo<'_>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.0.search(request_info, lookup_options).await
    }
    #[inline]
    async fn get_nsec_records(
        &self,
        name: &LowerName,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<Self::Lookup> {
        self.0.get_nsec_records(name, lookup_options).await
    }
}
