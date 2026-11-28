pub const MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS: u64 = 1000;

pub const OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC: u64 = 10;

pub const MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK: u32 = 3;

pub const DIRECT_CONNECT_TO_PUBLIC_SERVER: bool = true;

// must make it true in future.
pub const HMAC_SECRET_DIGEST: bool = false;

pub const WIN_SERVICE_WORK_DIR_REG_KEY: &str = "SOFTWARE\\EasyTier\\Service\\WorkDir";

const RAW_VERSION: &str = git_version::git_version!(
    args = ["--abbrev=8", "--always", "--dirty=~"],
    prefix = concat!(env!("CARGO_PKG_VERSION"), "-"),
    suffix = env!("EASYTIER_COMMIT_DATE"),
    fallback = env!("CARGO_PKG_VERSION")
);

pub const EASYTIER_VERSION: &str = {
    const VERSION_BYTES: [u8; RAW_VERSION.len()] = {
        let mut version = [0; RAW_VERSION.len()];
        version.copy_from_slice(RAW_VERSION.as_bytes());

        let date_len = env!("EASYTIER_COMMIT_DATE").len();
        if let Some(marker_index) = version.len().checked_sub(date_len + 1)
            && version[marker_index] == b'~'
        {
            let (_, suffix) = version.split_at_mut(marker_index);
            suffix.rotate_left(1);
        }

        version
    };
    match str::from_utf8(&VERSION_BYTES) {
        Ok(version) => version,
        Err(_) => panic!("version must be valid UTF-8"),
    }
};
