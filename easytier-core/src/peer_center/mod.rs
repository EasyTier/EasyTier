// peer_center is used to collect peer info into one peer node.
// the center node is selected with the following rules:
// 1. has smallest peer id
// 2. TODO: has allow_to_be_center peer feature
// peer center is not guaranteed to be stable and can be changed when peer enter or leave.
// it's used to reduce the cost to exchange infos between peers.

mod instance;
mod server;
mod service;

#[derive(thiserror::Error, Debug, serde::Deserialize, serde::Serialize)]
pub enum Error {
    #[error("Digest not match, need provide full peer info to center server.")]
    DigestMismatch,
    #[error("Not center server")]
    NotCenterServer,
}

pub type Digest = u64;
