use std::net::IpAddr;

use cidr::IpCidr;

/// OS parameters for the supported main-table, static, directly attached route.
/// Application ownership and device generations never cross the backend boundary.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OsRoute {
    pub destination: IpCidr,
    pub ifindex: u32,
    pub metric: u32,
    pub preferred_source: Option<IpAddr>,
}

/// Concrete device identity in Linux/OS.
/// Note: `ifname` is kept in Host for display/parsing only,
/// and does NOT participate in route equality.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DeviceId {
    /// Kernel interface index
    pub ifindex: u32,
    /// Host-managed instance identifier for TUN/VPN device.
    /// External interfaces (e.g. eth0) have None.
    pub host_instance: Option<u64>,
}

impl DeviceId {
    pub fn new(ifindex: u32, host_instance: Option<u64>) -> Self {
        Self {
            ifindex,
            host_instance,
        }
    }
}

/// Unified route model
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Route {
    pub destination: IpCidr,
    pub interface: DeviceId,
    pub metric: u32,
    pub preferred_source: Option<IpAddr>,
}

impl Route {
    pub fn os_route(&self) -> OsRoute {
        OsRoute {
            destination: self.destination,
            ifindex: self.interface.ifindex,
            metric: self.metric,
            preferred_source: self.preferred_source,
        }
    }
}

/// Standard error type for route operations
#[derive(thiserror::Error, Debug)]
pub enum RouteError {
    #[error("route operation failed deterministically: {0}")]
    Failed(anyhow::Error),
    #[error("route operation outcome is unknown: {0}")]
    Unknown(anyhow::Error),
}

impl RouteError {
    pub fn is_already_exists(&self) -> bool {
        matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists))
    }

    pub fn is_not_found(&self) -> bool {
        #[cfg(unix)]
        if self.is_errno(nix::libc::ESRCH) {
            return true;
        }
        matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound))
    }

    pub fn is_errno(&self, errno: i32) -> bool {
        matches!(self, Self::Failed(error) if error.downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(errno)))
    }
}

/// Report returned when stop cleanup cannot be completed cleanly
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupIncomplete {
    pub uncleaned_routes: Vec<Route>,
    pub unknown_routes: Vec<Route>,
    pub reason: String,
}

/// Per-item exponential backoff retry state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryState {
    pub attempts: u32,
    pub next_retry: tokio::time::Instant,
}

impl RetryState {
    pub fn new(now: tokio::time::Instant, base_millis: u64) -> Self {
        Self {
            attempts: 1,
            next_retry: now + std::time::Duration::from_millis(base_millis),
        }
    }

    pub fn record_failure(&mut self, now: tokio::time::Instant) {
        self.attempts = self.attempts.saturating_add(1);
        // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms, max 5000ms
        let shift = self.attempts.saturating_sub(1).min(6);
        let backoff_ms = (100u64.saturating_mul(1 << shift)).min(5000);
        self.next_retry = now + std::time::Duration::from_millis(backoff_ms);
    }
}
