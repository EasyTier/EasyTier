#[allow(clippy::all)]
mod generated {
    pub use crate::*;

    pub mod web {
        include!(concat!(env!("OUT_DIR"), "/web.rs"));
        include!(concat!(env!("OUT_DIR"), "/web.serde.rs"));
    }
}
pub use generated::web::*;
