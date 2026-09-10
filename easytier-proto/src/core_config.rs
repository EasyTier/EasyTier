include!(concat!(env!("OUT_DIR"), "/core_config.rs"));
#[cfg(feature = "json-rpc")]
include!(concat!(env!("OUT_DIR"), "/core_config.serde.rs"));
