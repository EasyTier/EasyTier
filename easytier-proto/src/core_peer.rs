pub mod peer {
    include!(concat!(env!("OUT_DIR"), "/core.peer.rs"));
    #[cfg(feature = "json-rpc")]
    include!(concat!(env!("OUT_DIR"), "/core.peer.serde.rs"));
}
