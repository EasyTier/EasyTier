use dashmap::DashMap;
use easytier::proto::{
    rpc::standalone::{runtime_udp_tunnel_dialer, runtime_udp_tunnel_listener},
    web::{GetFeatureRequest, WebServerServiceClientFactory},
};
use easytier_core::{
    connectivity::protocol::raw::TunnelDialer as _, tunnel::ring::create_ring_tunnel_pair,
};

use super::*;
use crate::{client_manager::ClientManager, db::Db, webhook::WebhookConfig};

async fn connect_udp(
    manager: &ClientManager,
    listener_url: url::Url,
) -> (BidirectRpcManager, Arc<Session>) {
    let tunnel = runtime_udp_tunnel_dialer(listener_url)
        .connect()
        .await
        .unwrap();
    let local_url: url::Url = tunnel.info().unwrap().local_addr.unwrap().into();
    let rpc = BidirectRpcManager::new();
    rpc.run_with_tunnel(tunnel);
    let client = rpc
        .rpc_client()
        .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, String::new());
    tokio::time::timeout(
        Duration::from_secs(5),
        client.get_feature(BaseController::default(), GetFeatureRequest {}),
    )
    .await
    .unwrap()
    .unwrap();
    let session = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(session) = manager
                .client_sessions
                .iter()
                .find(|entry| entry.key().port() == local_url.port())
                .map(|entry| entry.value().clone())
            {
                return session;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (rpc, session)
}

async fn heartbeat(rpc: &BidirectRpcManager, machine_id: uuid::Uuid) {
    let client = rpc
        .rpc_client()
        .scoped_client::<WebServerServiceClientFactory<BaseController>>(1, 1, String::new());
    client
        .heartbeat(
            BaseController::default(),
            HeartbeatRequest {
                machine_id: Some(machine_id.into()),
                user_token: "lifecycle-token".to_string(),
                report_time: chrono::Local::now().to_rfc3339(),
                support_heartbeat_policy: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

async fn ring_session(storage: &Storage, port: u16, epoch: u64) -> (Arc<Session>, Box<dyn Tunnel>) {
    let mut session = Session::new(
        storage.weak_ref(),
        format!("tcp://127.0.0.1:{port}").parse().unwrap(),
        None,
        HeartbeatPolicy::default(),
        Arc::new(FeatureFlags::default()),
        Arc::new(WebhookConfig::new(
            Some("http://127.0.0.1:1".to_string()),
            None,
            None,
            None,
            None,
        )),
        epoch,
    );
    let (server, peer) = create_ring_tunnel_pair();
    session.serve(server).await;
    session.mark_route_ready();
    (Arc::new(session), peer)
}

async fn bind_session(
    storage: &Storage,
    session: &Session,
    user_id: i32,
    machine_id: uuid::Uuid,
) -> StorageToken {
    let mut data = session.data.write().await;
    let token = StorageToken {
        token: format!("user-{user_id}"),
        client_url: data.client_url.clone(),
        machine_id,
        user_id,
    };
    data.managed_runtime =
        storage.bind_managed_runtime_state(user_id, machine_id, None, data.session_epoch);
    data.storage_token = Some(token.clone());
    data.auth_state = SessionAuthState::Authorized;
    storage.update_session_client(token.clone(), 1, true, data.session_epoch);
    token
}

#[tokio::test]
async fn pruning_retires_live_udp_duplicates_only_after_authentication() {
    let mut manager = ClientManager::new(
        Db::memory_db().await,
        None,
        HeartbeatPolicy::default(),
        Arc::new(FeatureFlags {
            allow_auto_create_user: true,
            ..Default::default()
        }),
        Arc::new(WebhookConfig::new(None, None, None, None, None)),
    );
    let listener_url = manager
        .add_listener(runtime_udp_tunnel_listener(
            "udp://127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await
        .unwrap();
    let machine_id = uuid::Uuid::new_v4();
    let (mut old_rpc, mut old) = connect_udp(&manager, listener_url.clone()).await;
    heartbeat(&old_rpc, machine_id).await;
    for _ in 0..3 {
        let (new_rpc, newest) = connect_udp(&manager, listener_url.clone()).await;
        assert_ne!(
            old.data.read().await.client_url,
            newest.data.read().await.client_url
        );
        assert!(newest.get_token().await.is_none());
        ClientManager::prune_sessions(&manager.client_sessions).await;
        assert_eq!(manager.client_sessions.len(), 2);
        assert!(old.is_running());

        heartbeat(&new_rpc, machine_id).await;
        heartbeat(&old_rpc, machine_id).await;
        let newest_token = newest.get_token().await.unwrap();
        ClientManager::prune_sessions(&manager.client_sessions).await;
        assert_eq!(manager.client_sessions.len(), 1);
        assert!(!old.is_running());
        assert!(Arc::ptr_eq(
            &manager
                .get_session_by_machine_id(newest_token.user_id, &machine_id)
                .unwrap(),
            &newest,
        ));
        heartbeat(&new_rpc, machine_id).await;
        old_rpc.stop().await;
        old_rpc = new_rpc;
        old = newest;
    }
    old.stop().await;
    old_rpc.stop().await;
}

#[tokio::test]
async fn pruning_remembers_disconnected_takeovers_and_isolates_identities() {
    let storage = Storage::new(Db::memory_db().await);
    let machine_id = uuid::Uuid::new_v4();
    let (old, _old_peer) = ring_session(&storage, 1001, 1).await;
    let (other_user, _user_peer) = ring_session(&storage, 1002, 2).await;
    let (other_machine, _machine_peer) = ring_session(&storage, 1003, 3).await;
    let (newest, _new_peer) = ring_session(&storage, 1004, 4).await;
    bind_session(&storage, &old, 1, machine_id).await;
    bind_session(&storage, &other_user, 2, machine_id).await;
    bind_session(&storage, &other_machine, 1, uuid::Uuid::new_v4()).await;
    let newest_token = bind_session(&storage, &newest, 1, machine_id).await;
    let sessions = DashMap::new();
    for session in [&old, &other_user, &other_machine, &newest] {
        sessions.insert(
            session.data.read().await.client_url.clone(),
            session.clone(),
        );
    }
    newest.stop().await;
    assert!(storage.remove_session_client(&newest_token, 4));
    assert!(
        storage
            .get_client_url_by_machine_id(1, &machine_id)
            .is_none()
    );
    ClientManager::prune_sessions(&sessions).await;
    assert_eq!(sessions.len(), 2);
    assert!(!old.is_running());
    assert!(other_user.is_running());
    assert!(other_machine.is_running());
    other_user.stop().await;
    other_machine.stop().await;
}

#[tokio::test]
async fn pruning_keeps_same_url_replacement_and_cancels_retained_session_workers() {
    let storage = Storage::new(Db::memory_db().await);
    let machine_id = uuid::Uuid::new_v4();
    let (old, _old_peer) = ring_session(&storage, 1001, 1).await;
    let (newest, _new_peer) = ring_session(&storage, 1001, 2).await;
    let token = bind_session(&storage, &old, 1, machine_id).await;
    bind_session(&storage, &newest, 1, machine_id).await;
    let sessions = DashMap::new();
    sessions.insert(token.client_url.clone(), old.clone());
    assert!(!old.webhook_validation_task.as_ref().unwrap().is_finished());
    assert!(!old.config_reconcile_task.as_ref().unwrap().is_finished());

    // Poll cleanup until its snapshot is blocked on this session's state lock.
    let state = old.data.write().await;
    let pruning = ClientManager::prune_sessions(&sessions);
    tokio::pin!(pruning);
    tokio::select! {
        biased;
        _ = &mut pruning => panic!("cleanup should wait for the session state lock"),
        _ = tokio::task::yield_now() => {}
    }
    sessions.insert(token.client_url.clone(), newest.clone());
    drop(state);
    pruning.await;
    assert!(Arc::ptr_eq(
        sessions.get(&token.client_url).unwrap().value(),
        &newest
    ));
    assert!(newest.is_running());
    assert!(!old.is_running());
    tokio::time::timeout(Duration::from_secs(5), async {
        while !old.webhook_validation_task.as_ref().unwrap().is_finished()
            || !old.config_reconcile_task.as_ref().unwrap().is_finished()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    newest.stop().await;
}
