pub use easytier_core::token_bucket::*;

#[cfg(test)]
mod tests {
    use crate::{
        connector::udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        peers::{
            foreign_network_manager::tests::create_mock_peer_manager_for_foreign_network,
            tests::connect_peer_manager,
        },
        proto::common::NatType,
        tunnel::common::tests::wait_for_condition,
    };

    use tokio::time::Duration;

    #[tokio::test]
    async fn test_token_bucket_free() {
        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        for i in 0..10 {
            let pma_net1 = create_mock_peer_manager_for_foreign_network(&format!("net{}", i)).await;

            connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
            wait_for_condition(
                || async { pma_net1.list_routes().await.len() == 1 },
                Duration::from_secs(5),
            )
            .await;
            println!("net{}", i);
            println!(
                "buckets: {}",
                pm_center1.get_global_ctx().token_bucket_manager().len()
            );

            drop(pma_net1);
            wait_for_condition(
                || async {
                    pm_center1
                        .get_foreign_network_manager()
                        .list_foreign_network_infos(false)
                        .await
                        .is_empty()
                },
                Duration::from_secs(5),
            )
            .await;
        }

        // wait token bucket empty
        wait_for_condition(
            || async {
                pm_center1
                    .get_global_ctx()
                    .token_bucket_manager()
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }
}
