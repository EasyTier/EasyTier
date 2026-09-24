use hickory_proto::rr::LowerName;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::LazyLock;
use idna::AsciiDenyList;

pub mod addr;
pub mod base;
#[allow(clippy::module_inception)]
pub mod dns;
pub mod policy;
pub mod zone;

pub use addr::*;
pub use base::*;
pub use dns::*;
pub use policy::*;
pub use zone::*;

pub static DNS_DEFAULT_DOMAIN: LazyLock<LowerName> =
    LazyLock::new(|| LowerName::from_str("et.net.").unwrap());
pub static DNS_DEFAULT_ADDRESSES: LazyLock<NameServerAddrGroup> =
    LazyLock::new(|| IpAddr::from_str("100.100.100.101").unwrap().into());

pub fn sanitize(name: impl AsRef<str>) -> String {
    let name = name.as_ref();
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
