#[allow(clippy::all)]
mod generated {
    pub use crate::*;

    pub mod magic_dns {
        include!(concat!(env!("OUT_DIR"), "/magic_dns.rs"));
        #[cfg(feature = "json-rpc")]
        include!(concat!(env!("OUT_DIR"), "/magic_dns.serde.rs"));
    }
}
pub use generated::magic_dns::*;
