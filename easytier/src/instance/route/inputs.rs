use std::{collections::BTreeMap, sync::Arc};

use easytier_core::host::route::{RouteSet, resolve_route_demands};
use registry::Registry;
use tokio::sync::watch;

use super::scope::RouteInput;

pub(crate) struct ScopeWatch {
    pub input: Arc<RouteInput>,
    declarations: watch::Receiver<()>,
    config: watch::Receiver<u64>,
    attachment: watch::Receiver<Option<super::scope::RouteAttachment>>,
    pub previous: RouteSet,
}

impl ScopeWatch {
    fn new(input: Arc<RouteInput>) -> Self {
        input.observe();
        Self {
            declarations: input.scope.routes().subscribe(),
            config: input.scope.config().subscribe_service_runtime_changes(),
            attachment: input.scope.subscribe_attachment(),
            input,
            previous: RouteSet::new(),
        }
    }

    pub fn baseline(&mut self) {
        self.declarations.mark_unchanged();
        self.config.mark_unchanged();
        self.attachment.mark_unchanged();
    }

    pub fn has_changed(&self) -> bool {
        self.declarations.has_changed().unwrap_or(true)
            || self.config.has_changed().unwrap_or(true)
            || self.attachment.has_changed().unwrap_or(true)
    }

    pub async fn changed(&mut self) {
        tokio::select! {
            _ = self.declarations.changed() => {},
            _ = self.config.changed() => {},
            _ = self.attachment.changed() => {},
        }
    }

    pub fn desired(&self) -> RouteSet {
        if !self.input.is_ready() {
            return RouteSet::new();
        }
        let config = self.input.scope.config().snapshot();
        resolve_route_demands(
            &self.input.scope.routes().snapshot(),
            config.services.manual_routes.as_ref(),
        )
    }
}

/// Subscribe to newly attached scopes before reading any of their inputs.
/// The manager multiplexes these receivers directly; no forwarding tasks or
/// duplicated configuration/declaration projections are needed.
pub(crate) fn synchronize(
    scopes: &mut BTreeMap<u64, ScopeWatch>,
    inputs: &Registry<RouteInput>,
) -> Vec<ScopeWatch> {
    let current: BTreeMap<_, _> = inputs
        .snapshot()
        .into_iter()
        .map(|input| (input.id, input))
        .collect();
    let removed = scopes
        .keys()
        .filter(|id| !current.contains_key(id))
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .filter_map(|id| scopes.remove(&id))
        .collect();
    for (id, input) in current {
        scopes.entry(id).or_insert_with(|| ScopeWatch::new(input));
    }
    for scope in scopes.values_mut() {
        scope.baseline();
    }
    removed
}
