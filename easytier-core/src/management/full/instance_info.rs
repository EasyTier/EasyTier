use easytier_proto::api::{
    instance::{PeerInfo, list_peer_route_pair},
    manage::{MyNodeInfo, NetworkInstanceRunningInfo},
};

use crate::{
    config::toml::ConfigLoader as _,
    instance::{CoreInstance, CoreInstanceHost, CoreInstanceState},
};

/// Builds the process-level running snapshot directly from one core Instance.
pub async fn network_instance_running_info<H>(
    instance: &CoreInstance<H>,
) -> anyhow::Result<NetworkInstanceRunningInfo>
where
    H: CoreInstanceHost,
{
    let running = !matches!(
        instance.state(),
        CoreInstanceState::Created | CoreInstanceState::Stopped
    );
    if !instance.is_ready() {
        return Ok(NetworkInstanceRunningInfo {
            running,
            error_msg: instance.latest_error(),
            ..Default::default()
        });
    }

    let peers = instance
        .peer_snapshots()
        .await
        .into_iter()
        .map(|snapshot| PeerInfo {
            peer_id: snapshot.peer_id,
            default_conn_id: snapshot.default_conn_id.map(Into::into),
            directly_connected_conns: snapshot
                .directly_connected_conns
                .into_iter()
                .map(Into::into)
                .collect(),
            conns: snapshot.conns.into_iter().map(Into::into).collect(),
        })
        .collect::<Vec<_>>();
    let node = instance.node_snapshot().await;
    let routes = instance
        .route_snapshots()
        .await
        .into_iter()
        .map(Into::into)
        .collect::<Vec<_>>();
    let peer_route_pairs = list_peer_route_pair(peers.clone(), routes.clone());
    let vpn_portal_cfg = Some(instance.vpn_portal_info().await.client_config);
    let dev_name = instance
        .toml_config()
        .map(|config| config.get_flags().dev_name)
        .unwrap_or_default();

    Ok(NetworkInstanceRunningInfo {
        dev_name,
        my_node_info: Some(MyNodeInfo {
            virtual_ipv4: node.ipv4_addr.map(Into::into),
            hostname: node.hostname,
            version: node.version,
            ips: Some(node.ip_list),
            stun_info: Some(node.stun_info),
            listeners: node.listeners.into_iter().map(Into::into).collect(),
            vpn_portal_cfg,
            peer_id: node.peer_id,
        }),
        events: instance.management_events(),
        routes,
        peers,
        peer_route_pairs,
        running,
        error_msg: instance.latest_error(),
        foreign_network_summary: Some(instance.foreign_network_route_summary().await),
    })
}
