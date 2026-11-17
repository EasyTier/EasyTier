mod configuration;
mod records;

#[cfg(feature = "proxy-packet")]
mod packet;

pub use configuration::{Zone, configured_zones, dns_domain, normalized_dns, parse_origin};
pub use records::{
    MagicDnsRecordSnapshot, MagicDnsRecordStore, MagicDnsRoute, MagicDnsRouteAdvertisement,
    MagicDnsRoutePublisher, MagicDnsRouteSnapshot, MagicDnsRouteSource,
    run_magic_dns_route_publisher,
};

#[cfg(feature = "proxy-packet")]
pub use packet::{
    MagicDnsQuery, MagicDnsQueryResolver, MagicDnsQueryResult, MagicDnsResolverRegistration,
};
#[cfg(feature = "proxy-packet")]
pub(crate) use packet::{MagicDnsResolverState, magic_dns_packet_filter};
