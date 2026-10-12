#[allow(clippy::all)]
mod generated {
    pub use crate::*;

    pub mod core_config {
        include!(concat!(env!("OUT_DIR"), "/core_config.rs"));
        #[cfg(feature = "json-rpc")]
        include!(concat!(env!("OUT_DIR"), "/core_config.serde.rs"));
    }
}
pub use generated::core_config::*;
