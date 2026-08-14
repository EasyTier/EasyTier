use crate::common::global_ctx::GlobalCtxEvent;

#[cfg(target_os = "linux")]
#[path = "public_ipv6_provider/linux.rs"]
mod platform;
#[cfg(not(target_os = "linux"))]
#[path = "public_ipv6_provider/unsupported.rs"]
mod platform;

pub(crate) use platform::runtime_public_ipv6_provider_platform;

fn should_reconcile_immediately(event: &GlobalCtxEvent) -> bool {
    match event {
        #[cfg(feature = "management")]
        GlobalCtxEvent::ConfigPatched(_) => true,
        GlobalCtxEvent::TunDeviceReady(_)
        | GlobalCtxEvent::TunDeviceError(_)
        | GlobalCtxEvent::PublicIpv6RoutesUpdated(_, _) => true,
        _ => false,
    }
}

pub(super) async fn wait_for_public_ipv6_provider_reconcile_event(
    event_receiver: &mut tokio::sync::broadcast::Receiver<GlobalCtxEvent>,
) -> bool {
    loop {
        match event_receiver.recv().await {
            Ok(event) if should_reconcile_immediately(&event) => return true,
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return false,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                *event_receiver = event_receiver.resubscribe();
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wait_for_reconcile_ignores_unrelated_events() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let trigger_tx = tx.clone();
        let spam_task = tokio::spawn(async move {
            loop {
                if tx.send(GlobalCtxEvent::PeerAdded(1)).is_err() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });
        let trigger_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = trigger_tx.send(GlobalCtxEvent::TunDeviceReady("et-test".to_owned()));
        });

        let reconciled = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            wait_for_public_ipv6_provider_reconcile_event(&mut rx),
        )
        .await
        .expect("a relevant event should wake the reconcile loop");

        spam_task.abort();
        trigger_task.await.unwrap();
        assert!(reconciled);
    }
}
