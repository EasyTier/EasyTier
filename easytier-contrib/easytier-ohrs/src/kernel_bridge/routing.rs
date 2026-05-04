use crate::config::repository::load_config_json;
use crate::runtime::state::runtime_state::RuntimeInstanceState;
use easytier::proto::api::manage::NetworkConfig;
use ipnet::IpNet;
use std::collections::HashSet;

pub(crate) fn load_manual_routes(config_id: &str) -> Vec<String> {
    load_config_json(config_id)
        .and_then(|raw| serde_json::from_str::<NetworkConfig>(&raw).ok())
        .map(|config| config.routes)
        .unwrap_or_default()
}

fn normalize_route_cidr(route: &str) -> Option<String> {
    route.parse::<IpNet>().ok().map(|network| match network {
        IpNet::V4(net) => net.trunc().to_string(),
        IpNet::V6(net) => net.trunc().to_string(),
    })
}

fn simplify_routes(routes: Vec<String>) -> Vec<String> {
    let mut parsed = routes
        .into_iter()
        .filter_map(|route| normalize_route_cidr(&route))
        .filter_map(|route| route.parse::<IpNet>().ok())
        .collect::<Vec<_>>();
    parsed.sort_by(|left, right| {
        left.prefix_len()
            .cmp(&right.prefix_len())
            .then_with(|| left.network().to_string().cmp(&right.network().to_string()))
    });

    let mut simplified = Vec::<IpNet>::new();
    'outer: for route in parsed {
        for existing in &simplified {
            if existing.contains(&route.network()) && existing.prefix_len() <= route.prefix_len() {
                continue 'outer;
            }
        }
        simplified.retain(|existing| {
            !(route.contains(&existing.network()) && route.prefix_len() <= existing.prefix_len())
        });
        simplified.push(route);
    }

    let mut seen = HashSet::new();
    simplified
        .into_iter()
        .map(|route| route.to_string())
        .filter(|route| seen.insert(route.clone()))
        .collect()
}

pub(crate) fn aggregate_tun_routes(instance: &RuntimeInstanceState) -> Vec<String> {
    let virtual_ipv4_cidr = instance
        .my_node_info
        .as_ref()
        .and_then(|info| info.virtual_ipv4_cidr.clone());
    let manual_routes = load_manual_routes(&instance.config_id);
    let proxy_cidrs = instance
        .routes
        .iter()
        .flat_map(|route| route.proxy_cidrs.iter().cloned())
        .collect::<Vec<_>>();
    let mut raw_routes = Vec::new();

    if let Some(cidr) = virtual_ipv4_cidr.clone() {
        raw_routes.push(cidr);
    }

    raw_routes.extend(manual_routes.iter().cloned());
    raw_routes.extend(proxy_cidrs.iter().cloned());
    simplify_routes(raw_routes)
}

pub(crate) fn aggregate_requested_tun_routes(instances: &[RuntimeInstanceState]) -> Vec<String> {
    let mut aggregated_routes = Vec::new();
    let mut seen_routes = HashSet::new();
    for instance in instances.iter().filter(|instance| instance.tun_required) {
        for route in aggregate_tun_routes(instance) {
            if seen_routes.insert(route.clone()) {
                aggregated_routes.push(route);
            }
        }
    }
    aggregated_routes
}
