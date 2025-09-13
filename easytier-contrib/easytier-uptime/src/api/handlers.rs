use std::ops::{Div, Mul};

use axum::extract::{Path, Query, State};
use axum::Json;
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, IntoActiveModel, ModelTrait, Order, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, Set, TryIntoModel,
};
use serde::Deserialize;
use validator::Validate;

use crate::api::{
    error::{ApiError, ApiResult},
    models::*,
};
use crate::db::entity::{self, health_records, shared_nodes};
use crate::db::{operations::*, Db};
use crate::health_checker_manager::HealthCheckerManager;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub health_checker_manager: Arc<HealthCheckerManager>,
}

pub async fn health_check() -> Json<ApiResponse<String>> {
    Json(ApiResponse::message("Service is healthy".to_string()))
}

pub async fn get_nodes(
    State(app_state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
    Query(filters): Query<NodeFilterParams>,
) -> ApiResult<Json<ApiResponse<PaginatedResponse<NodeResponse>>>> {
    let page = pagination.page.unwrap_or(1);
    let per_page = pagination.per_page.unwrap_or(20);

    let offset = (page - 1) * per_page;

    let mut query = entity::shared_nodes::Entity::find();

    // 普通用户只能看到已审核的节点
    query = query.filter(entity::shared_nodes::Column::IsApproved.eq(true));

    if let Some(is_active) = filters.is_active {
        query = query.filter(entity::shared_nodes::Column::IsActive.eq(is_active));
    }

    if let Some(protocol) = filters.protocol {
        query = query.filter(entity::shared_nodes::Column::Protocol.eq(protocol));
    }

    if let Some(search) = filters.search {
        query = query.filter(
            sea_orm::Condition::any()
                .add(entity::shared_nodes::Column::Name.contains(&search))
                .add(entity::shared_nodes::Column::Host.contains(&search))
                .add(entity::shared_nodes::Column::Description.contains(&search)),
        );
    }

    let total = query.clone().count(app_state.db.orm_db()).await?;
    let nodes = query
        .order_by_asc(entity::shared_nodes::Column::Id)
        .limit(Some(per_page as u64))
        .offset(Some(offset as u64))
        .all(app_state.db.orm_db())
        .await?;

    let mut node_responses: Vec<NodeResponse> = nodes.into_iter().map(NodeResponse::from).collect();
    let total_pages = total.div_ceil(per_page as u64);

    // 为每个节点添加健康状态信息
    for node_response in &mut node_responses {
        if let Some(mut health_record) = app_state
            .health_checker_manager
            .get_node_memory_record(node_response.id)
        {
            node_response.current_health_status =
                Some(health_record.get_current_health_status().to_string());
            node_response.last_check_time = Some(health_record.get_last_check_time());
            node_response.last_response_time = health_record.get_last_response_time();

            // 获取24小时健康统计
            if let Some(stats) = app_state
                .health_checker_manager
                .get_node_health_stats(node_response.id, 24)
            {
                node_response.health_percentage_24h = Some(stats.health_percentage);
            }

            let (total_ring, healthy_ring) = health_record.get_counter_ring();
            node_response.health_record_total_counter_ring = total_ring;
            node_response.health_record_healthy_counter_ring = healthy_ring;
            node_response.ring_granularity = health_record.get_ring_granularity();
        }
    }

    // remove sensitive information
    node_responses.iter_mut().for_each(|node| {
        tracing::info!("node: {:?}", node);
        node.network_name = None;
        node.network_secret = None;

        // make cur connection and max conn round to percentage
        if node.max_connections != 0 {
            node.current_connections = node.current_connections.mul(100).div(node.max_connections);
            node.max_connections = 100;
        } else {
            node.current_connections = 0;
            node.max_connections = 0;
        }

        node.wechat = None;
        node.qq_number = None;
        node.mail = None;
    });

    Ok(Json(ApiResponse::success(PaginatedResponse {
        items: node_responses,
        total,
        page,
        per_page,
        total_pages: total_pages as u32,
    })))
}

pub async fn create_node(
    State(app_state): State<AppState>,
    Json(request): Json<CreateNodeRequest>,
) -> ApiResult<Json<ApiResponse<NodeResponse>>> {
    request.validate()?;

    let node = NodeOperations::create_node(&app_state.db, request).await?;

    Ok(Json(ApiResponse::success(NodeResponse::from(node))))
}

pub async fn test_connection(
    State(app_state): State<AppState>,
    Json(request): Json<CreateNodeRequest>,
) -> ApiResult<Json<ApiResponse<NodeResponse>>> {
    let mut node = NodeOperations::create_node_model(request);
    node.id = Set(0);
    let node = node.try_into_model()?;
    app_state
        .health_checker_manager
        .test_connection(&node, std::time::Duration::from_secs(5))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(NodeResponse::from(node))))
}

pub async fn get_node(
    State(app_state): State<AppState>,
    Path(id): Path<i32>,
) -> ApiResult<Json<ApiResponse<NodeResponse>>> {
    let node = NodeOperations::get_node_by_id(&app_state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Node with id {} not found", id)))?;

    Ok(Json(ApiResponse::success(NodeResponse::from(node))))
}

pub async fn get_node_health(
    State(app_state): State<AppState>,
    Path(node_id): Path<i32>,
    Query(pagination): Query<PaginationParams>,
    Query(filters): Query<HealthFilterParams>,
) -> ApiResult<Json<ApiResponse<PaginatedResponse<HealthRecordResponse>>>> {
    let page = pagination.page.unwrap_or(1);
    let per_page = pagination.per_page.unwrap_or(20);
    let offset = (page - 1) * per_page;

    let mut query = entity::health_records::Entity::find()
        .filter(entity::health_records::Column::NodeId.eq(node_id));

    if let Some(status) = filters.status {
        query = query.filter(entity::health_records::Column::Status.eq(status));
    }

    if let Some(since) = filters.since {
        query = query.filter(entity::health_records::Column::CheckedAt.gte(since.naive_utc()));
    }

    let total = query.clone().count(app_state.db.orm_db()).await?;
    let records = query
        .order_by_desc(entity::health_records::Column::CheckedAt)
        .limit(Some(per_page as u64))
        .offset(Some(offset as u64))
        .all(app_state.db.orm_db())
        .await?;

    let record_responses: Vec<HealthRecordResponse> = records
        .into_iter()
        .map(HealthRecordResponse::from)
        .collect();
    let total_pages = total.div_ceil(per_page as u64);

    Ok(Json(ApiResponse::success(PaginatedResponse {
        items: record_responses,
        total,
        page,
        per_page,
        total_pages: total_pages as u32,
    })))
}

pub async fn get_node_health_stats(
    State(app_state): State<AppState>,
    Path(node_id): Path<i32>,
    Query(params): Query<HealthStatsParams>,
) -> ApiResult<Json<ApiResponse<HealthStatsResponse>>> {
    let hours = params.hours.unwrap_or(24);
    let stats = HealthOperations::get_health_stats(&app_state.db, node_id, hours).await?;

    Ok(Json(ApiResponse::success(HealthStatsResponse::from(stats))))
}

#[derive(Debug, Deserialize)]
pub struct HealthStatsParams {
    pub hours: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct InstanceFilterParams {
    pub node_id: Option<i32>,
    pub status: Option<String>,
}

// 管理员相关处理器
use crate::config::AppConfig;
use axum::http::{HeaderMap, StatusCode};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize)]
struct AdminClaims {
    sub: String,
    exp: usize,
    iat: usize,
}

pub async fn get_node_connect_url(
    State(app_state): State<AppState>,
    Path(id): Path<i32>,
) -> ApiResult<String> {
    let node = NodeOperations::get_node_by_id(&app_state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Node with id {} not found", id)))?;
    let connect_url = format!("{}://{}:{}", node.protocol, node.host, node.port);
    Ok(connect_url)
}

pub async fn admin_login(
    Json(request): Json<AdminLoginRequest>,
) -> ApiResult<Json<ApiResponse<AdminLoginResponse>>> {
    request
        .validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    let config = AppConfig::default();

    if request.password != config.security.admin_password {
        return Err(ApiError::Unauthorized("Invalid password".to_string()));
    }

    let now = Utc::now();
    let expires_at = now + Duration::hours(24);

    let claims = AdminClaims {
        sub: "admin".to_string(),
        exp: expires_at.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.security.jwt_secret.as_ref()),
    )
    .map_err(|e| ApiError::Internal(format!("Token generation failed: {}", e)))?;

    Ok(Json(ApiResponse::success(AdminLoginResponse {
        token,
        expires_at,
    })))
}

pub async fn admin_get_nodes(
    State(app_state): State<AppState>,
    Query(pagination): Query<PaginationParams>,
    Query(filters): Query<AdminNodeFilterParams>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiResponse<PaginatedResponse<NodeResponse>>>> {
    verify_admin_token(&headers)?;

    let page = pagination.page.unwrap_or(1);
    let per_page = pagination.per_page.unwrap_or(200);
    let offset = (page - 1) * per_page;

    let mut query = entity::shared_nodes::Entity::find();

    if let Some(is_active) = filters.is_active {
        query = query.filter(entity::shared_nodes::Column::IsActive.eq(is_active));
    }

    if let Some(is_approved) = filters.is_approved {
        query = query.filter(entity::shared_nodes::Column::IsApproved.eq(is_approved));
    }

    if let Some(protocol) = filters.protocol {
        query = query.filter(entity::shared_nodes::Column::Protocol.eq(protocol));
    }

    if let Some(search) = filters.search {
        query = query.filter(
            sea_orm::Condition::any()
                .add(entity::shared_nodes::Column::Name.contains(&search))
                .add(entity::shared_nodes::Column::Host.contains(&search))
                .add(entity::shared_nodes::Column::Description.contains(&search)),
        );
    }

    let total = query.clone().count(app_state.db.orm_db()).await?;

    let nodes = query
        .order_by(entity::shared_nodes::Column::CreatedAt, Order::Desc)
        .offset(offset as u64)
        .limit(per_page as u64)
        .all(app_state.db.orm_db())
        .await?;

    let node_responses: Vec<NodeResponse> = nodes.into_iter().map(NodeResponse::from).collect();

    let total_pages = (total as f64 / per_page as f64).ceil() as u32;

    Ok(Json(ApiResponse::success(PaginatedResponse {
        items: node_responses,
        total,
        page,
        per_page,
        total_pages,
    })))
}

pub async fn admin_approve_node(
    State(app_state): State<AppState>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiResponse<NodeResponse>>> {
    verify_admin_token(&headers)?;

    let node = entity::shared_nodes::Entity::find_by_id(id)
        .one(app_state.db.orm_db())
        .await?
        .ok_or_else(|| ApiError::NotFound("Node not found".to_string()))?;

    let mut active_model = node.into_active_model();
    active_model.is_approved = sea_orm::Set(true);

    let updated_node = entity::shared_nodes::Entity::update(active_model)
        .exec(app_state.db.orm_db())
        .await?;

    Ok(Json(ApiResponse::success(NodeResponse::from(updated_node))))
}

pub async fn admin_update_node(
    State(app_state): State<AppState>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Json(request): Json<UpdateNodeRequest>,
) -> ApiResult<Json<ApiResponse<NodeResponse>>> {
    verify_admin_token(&headers)?;
    request.validate()?;

    let mut node = NodeOperations::get_node_by_id(&app_state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Node with id {} not found", id)))?;

    let mut node = node.into_active_model();

    if let Some(name) = request.name {
        node.name = Set(name);
    }
    if let Some(host) = request.host {
        node.host = Set(host);
    }
    if let Some(port) = request.port {
        node.port = Set(port);
    }
    if let Some(protocol) = request.protocol {
        node.protocol = Set(protocol);
    }
    if let Some(description) = request.description {
        node.description = Set(description);
    }
    if let Some(max_connections) = request.max_connections {
        node.max_connections = Set(max_connections);
    }
    if let Some(is_active) = request.is_active {
        node.is_active = Set(is_active);
    }
    if let Some(allow_relay) = request.allow_relay {
        node.allow_relay = Set(allow_relay);
    }
    if let Some(network_name) = request.network_name {
        node.network_name = Set(network_name);
    }
    if let Some(network_secret) = request.network_secret {
        node.network_secret = Set(network_secret);
    }
    if let Some(wechat) = request.wechat {
        node.wechat = Set(wechat);
    }
    if let Some(mail) = request.mail {
        node.mail = Set(mail);
    }
    if let Some(qq_number) = request.qq_number {
        node.qq_number = Set(qq_number);
    }

    node.updated_at = Set(chrono::Utc::now().fixed_offset());

    tracing::info!("updated node: {:?}", node);

    let updated_node = entity::shared_nodes::Entity::update(node)
        .exec(app_state.db.orm_db())
        .await?;

    Ok(Json(ApiResponse::success(NodeResponse::from(updated_node))))
}

pub async fn admin_revoke_approval(
    State(app_state): State<AppState>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiResponse<NodeResponse>>> {
    verify_admin_token(&headers)?;

    let node = entity::shared_nodes::Entity::find_by_id(id)
        .one(app_state.db.orm_db())
        .await?
        .ok_or_else(|| ApiError::NotFound("Node not found".to_string()))?;

    let mut active_model = node.into_active_model();
    active_model.is_approved = sea_orm::Set(false);

    let updated_node = entity::shared_nodes::Entity::update(active_model)
        .exec(app_state.db.orm_db())
        .await?;

    Ok(Json(ApiResponse::success(NodeResponse::from(updated_node))))
}

pub async fn admin_delete_node(
    State(app_state): State<AppState>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiResponse<String>>> {
    verify_admin_token(&headers)?;

    let node = entity::shared_nodes::Entity::find_by_id(id)
        .one(app_state.db.orm_db())
        .await?
        .ok_or_else(|| ApiError::NotFound("Node not found".to_string()))?;

    node.delete(app_state.db.orm_db()).await?;

    Ok(Json(ApiResponse::message(
        "Node deleted successfully".to_string(),
    )))
}

pub async fn admin_verify_token(headers: HeaderMap) -> ApiResult<Json<ApiResponse<String>>> {
    verify_admin_token(&headers)?;
    Ok(Json(ApiResponse::message("Token is valid".to_string())))
}

fn verify_admin_token(headers: &HeaderMap) -> ApiResult<()> {
    let config = AppConfig::default();

    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| ApiError::Unauthorized("Missing authorization header".to_string()))?;

    let auth_str = auth_header
        .to_str()
        .map_err(|_| ApiError::Unauthorized("Invalid authorization header".to_string()))?;

    let token = auth_str
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("Invalid authorization format".to_string()))?;

    let _claims = decode::<AdminClaims>(
        token,
        &DecodingKey::from_secret(config.security.jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    Ok(())
}
