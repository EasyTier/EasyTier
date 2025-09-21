use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Default timeout for a gateway search.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for each broadcast response during a gateway search.
#[allow(dead_code)]
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Gateway search configuration
///
/// SearchOptions::default() should suffice for most situations.
///
/// # Example
/// To customize only a few options you can use `Default::default()` or `SearchOptions::default()` and the
/// [struct update syntax](https://doc.rust-lang.org/book/ch05-01-defining-structs.html#creating-instances-from-other-instances-with-struct-update-syntax).
/// ```
/// # use std::time::Duration;
/// # use igd_next::SearchOptions;
/// let opts = SearchOptions {
///     timeout: Some(Duration::from_secs(60)),
///     ..Default::default()
/// };
/// ```
pub struct SearchOptions {
    /// Bind address for UDP socket (defaults to all `0.0.0.0`)
    pub bind_addr: SocketAddr,
    /// Broadcast address for discovery packets (defaults to `239.255.255.250:1900`)
    pub broadcast_address: SocketAddr,
    /// Timeout for a search iteration (defaults to 10s)
    pub timeout: Option<Duration>,
    /// Timeout for a single search response (defaults to 5s)
    pub single_search_timeout: Option<Duration>,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            bind_addr: (IpAddr::from([0, 0, 0, 0]), 0).into(),
            broadcast_address: "239.255.255.250:1900".parse().unwrap(),
            timeout: Some(DEFAULT_TIMEOUT),
            single_search_timeout: Some(RESPONSE_TIMEOUT),
        }
    }
}
