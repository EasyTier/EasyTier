#[allow(clippy::all)]
mod generated {
    pub use crate::*;

    pub mod core {
        pub mod peer {
            include!(concat!(env!("OUT_DIR"), "/core.peer.rs"));
            #[cfg(feature = "json-rpc")]
            include!(concat!(env!("OUT_DIR"), "/core.peer.serde.rs"));
        }
    }
}
use generated::core;

pub mod peer {
    pub use super::core::peer::*;
}
