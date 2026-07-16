pub const MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS: u64 = 1000;

pub const OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC: u64 = 10;

pub const MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK: u32 = 3;

pub const DIRECT_CONNECT_TO_PUBLIC_SERVER: bool = true;

// must make it true in future.
pub const HMAC_SECRET_DIGEST: bool = false;

pub const UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID: u32 = 2;

pub const WIN_SERVICE_WORK_DIR_REG_KEY: &str = "SOFTWARE\\EasyTier\\Service\\WorkDir";

pub const EASYTIER_VERSION: &str = git_version::git_version!(
    args = ["--abbrev=8", "--always", "--dirty=~"],
    prefix = concat!(env!("CARGO_PKG_VERSION"), "-"),
    suffix = "",
    fallback = env!("CARGO_PKG_VERSION")
);
