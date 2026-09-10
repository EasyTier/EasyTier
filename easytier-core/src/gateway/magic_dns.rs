mod records;

#[cfg(feature = "proxy-packet")]
mod packet;

pub use records::{
    MagicDnsRecordSnapshot, MagicDnsRecordStore, MagicDnsRoute, MagicDnsRouteAdvertisement,
    MagicDnsRoutePublisher, MagicDnsRouteSnapshot, MagicDnsRouteSource,
    run_magic_dns_route_publisher,
};

#[cfg(feature = "proxy-packet")]
pub(crate) use packet::magic_dns_packet_filter;
#[cfg(feature = "proxy-packet")]
pub use packet::{
    MagicDnsQuery, MagicDnsQueryResolver, MagicDnsResolverRegistration, process_magic_dns_packet,
};
