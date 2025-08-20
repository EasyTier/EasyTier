use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;

use super::handlers::AppState;
use super::handlers::{
    admin_approve_node, admin_delete_node, admin_get_nodes, admin_login, admin_revoke_approval,
    admin_update_node, admin_verify_token, create_node, get_node, get_node_health,
    get_node_health_stats, get_nodes, health_check,
};
use crate::api::{get_node_connect_url, test_connection};
use crate::config::AppConfig;
use crate::db::Db;

pub fn create_routes() -> Router<AppState> {
    let config = AppConfig::default();

    let compression_layer = if config.security.enable_compression {
        Some(
            CompressionLayer::new()
                .br(true)
                .deflate(true)
                .gzip(true)
                .zstd(true),
        )
    } else {
        None
    };

    let cors_layer = if config.cors.enabled {
        Some(CorsLayer::very_permissive())
    } else {
        None
    };

    let mut router = Router::new()
        .route("/node/{id}", get(get_node_connect_url))
        .route("/health", get(health_check))
        .route("/api/nodes", get(get_nodes).post(create_node))
        .route("/api/test_connection", post(test_connection))
        .route("/api/nodes/{id}/health", get(get_node_health))
        .route("/api/nodes/{id}/health/stats", get(get_node_health_stats))
        // 管理员路由
        .route("/api/admin/login", post(admin_login))
        .route("/api/admin/verify", get(admin_verify_token))
        .route("/api/admin/nodes", get(admin_get_nodes))
        .route("/api/admin/nodes/{id}/approve", put(admin_approve_node))
        .route("/api/admin/nodes/{id}/revoke", put(admin_revoke_approval))
        .route(
            "/api/admin/nodes/{id}",
            put(admin_update_node).delete(admin_delete_node),
        );

    if let Some(layer) = compression_layer {
        router = router.layer(layer);
    }

    if let Some(layer) = cors_layer {
        router = router.layer(layer);
    }

    router
}
