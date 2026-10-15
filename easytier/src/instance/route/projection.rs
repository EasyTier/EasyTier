use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

use easytier_core::host::route::{RouteSet, RouteSpec};

use super::scope::RouteInput;

/// Validated per-member route intent and concrete source-selection parameters.
/// NIC membership validation and dispatcher updates stay above the OS backend.
pub(crate) struct RouteProjection {
    pub scopes: BTreeMap<u64, RouteSet>,
    pub sources: BTreeMap<RouteSpec, Option<IpAddr>>,
}

impl RouteProjection {
    pub fn from_inputs(inputs: &[(Arc<RouteInput>, RouteSet)]) -> Self {
        Self {
            scopes: inputs
                .iter()
                .map(|(input, routes)| (input.id, routes.clone()))
                .collect(),
            sources: BTreeMap::new(),
        }
    }
}
