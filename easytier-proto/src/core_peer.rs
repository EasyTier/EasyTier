pub mod peer {
    include!(concat!(env!("OUT_DIR"), "/core.peer.rs"));
    include!(concat!(env!("OUT_DIR"), "/core.peer.serde.rs"));
}
