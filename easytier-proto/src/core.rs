#[allow(clippy::all)]
mod generated {
    pub use crate::*;

    pub mod core {
        pub mod config {
            include!(concat!(env!("OUT_DIR"), "/core.config.rs"));
            #[cfg(feature = "json-rpc")]
            include!(concat!(env!("OUT_DIR"), "/core.config.serde.rs"));
        }

        pub mod peer {
            include!(concat!(env!("OUT_DIR"), "/core.peer.rs"));
            #[cfg(feature = "json-rpc")]
            include!(concat!(env!("OUT_DIR"), "/core.peer.serde.rs"));
        }
    }
}
pub use generated::core::*;
