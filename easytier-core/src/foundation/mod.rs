//! Infrastructure Modules with no domain dependency.
//!
//! Everything in `foundation` may be used by any layer, and nothing here may
//! depend on a domain Module. See `CONTEXT.md` "Module layers".

pub mod stats;
pub(crate) mod task;
pub(crate) mod time;
pub(crate) mod token_bucket;
