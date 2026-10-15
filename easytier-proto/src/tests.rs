#[allow(clippy::all)]
mod generated {
    #[allow(unused_imports)]
    pub use crate::*;

    pub mod tests {
        include!(concat!(env!("OUT_DIR"), "/tests.rs"));
        include!(concat!(env!("OUT_DIR"), "/tests.serde.rs"));
    }
}
pub use generated::tests::*;
