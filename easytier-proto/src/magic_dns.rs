include!(concat!(env!("OUT_DIR"), "/magic_dns.rs"));
#[cfg(feature = "json-rpc")]
include!(concat!(env!("OUT_DIR"), "/magic_dns.serde.rs"));
