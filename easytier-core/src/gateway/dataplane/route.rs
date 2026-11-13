//! Pure route selection for TCP data-plane connections.

use super::{DataPlaneError, DataPlaneErrorKind, DataPlaneResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataPlaneRoutePolicy {
    OverlayOnly,
    OverlayOrDirect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DataPlaneTransportPreference {
    SmoltcpOnly,
    PreferKcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DataPlaneTcpRoute {
    LocalEndpoint,
    LocalHost,
    Smoltcp,
    Kcp,
    Direct,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DataPlaneTcpRouteInput {
    pub policy: DataPlaneRoutePolicy,
    pub transport: DataPlaneTransportPreference,
    pub local_endpoint: bool,
    pub local_virtual_destination: bool,
    pub overlay_destination: bool,
    pub smoltcp_ready: bool,
    pub kcp_ready: bool,
    pub kcp_allowed: bool,
}

impl DataPlaneTcpRouteInput {
    pub(super) fn select(self) -> DataPlaneResult<DataPlaneTcpRoute> {
        if self.local_endpoint {
            return self
                .smoltcp_ready
                .then_some(DataPlaneTcpRoute::LocalEndpoint)
                .ok_or_else(path_not_ready);
        }
        if self.local_virtual_destination {
            return Ok(DataPlaneTcpRoute::LocalHost);
        }
        if self.overlay_destination {
            if self.transport == DataPlaneTransportPreference::PreferKcp
                && self.kcp_ready
                && self.kcp_allowed
            {
                return Ok(DataPlaneTcpRoute::Kcp);
            }
            return self
                .smoltcp_ready
                .then_some(DataPlaneTcpRoute::Smoltcp)
                .ok_or_else(path_not_ready);
        }
        if self.policy == DataPlaneRoutePolicy::OverlayOrDirect {
            return Ok(DataPlaneTcpRoute::Direct);
        }
        Err(DataPlaneError::new(
            DataPlaneErrorKind::NoOverlayRoute,
            "destination has no EasyTier overlay route",
        ))
    }
}

fn path_not_ready() -> DataPlaneError {
    DataPlaneError::new(
        DataPlaneErrorKind::PathNotReady,
        "selected EasyTier data-plane path is not ready",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay() -> DataPlaneTcpRouteInput {
        DataPlaneTcpRouteInput {
            policy: DataPlaneRoutePolicy::OverlayOnly,
            transport: DataPlaneTransportPreference::SmoltcpOnly,
            local_endpoint: false,
            local_virtual_destination: false,
            overlay_destination: true,
            smoltcp_ready: true,
            kcp_ready: false,
            kcp_allowed: false,
        }
    }

    #[test]
    fn overlay_only_rejects_unrelated_destination() {
        let input = DataPlaneTcpRouteInput {
            overlay_destination: false,
            ..overlay()
        };

        assert_eq!(
            input.select().unwrap_err().kind(),
            DataPlaneErrorKind::NoOverlayRoute
        );
    }

    #[test]
    fn gateway_policy_can_select_direct_host_route() {
        let input = DataPlaneTcpRouteInput {
            policy: DataPlaneRoutePolicy::OverlayOrDirect,
            overlay_destination: false,
            ..overlay()
        };

        assert_eq!(input.select().unwrap(), DataPlaneTcpRoute::Direct);
    }

    #[test]
    fn smoltcp_only_ignores_available_kcp() {
        let input = DataPlaneTcpRouteInput {
            kcp_ready: true,
            kcp_allowed: true,
            ..overlay()
        };

        assert_eq!(input.select().unwrap(), DataPlaneTcpRoute::Smoltcp);
    }

    #[test]
    fn gateway_preference_selects_allowed_ready_kcp() {
        let input = DataPlaneTcpRouteInput {
            transport: DataPlaneTransportPreference::PreferKcp,
            kcp_ready: true,
            kcp_allowed: true,
            ..overlay()
        };

        assert_eq!(input.select().unwrap(), DataPlaneTcpRoute::Kcp);
    }

    #[test]
    fn known_overlay_without_a_ready_path_is_not_direct() {
        let input = DataPlaneTcpRouteInput {
            policy: DataPlaneRoutePolicy::OverlayOrDirect,
            smoltcp_ready: false,
            ..overlay()
        };

        assert_eq!(
            input.select().unwrap_err().kind(),
            DataPlaneErrorKind::PathNotReady
        );
    }

    #[test]
    fn local_endpoint_precedes_local_host_mapping() {
        let input = DataPlaneTcpRouteInput {
            local_endpoint: true,
            local_virtual_destination: true,
            ..overlay()
        };

        assert_eq!(input.select().unwrap(), DataPlaneTcpRoute::LocalEndpoint);
    }
}
