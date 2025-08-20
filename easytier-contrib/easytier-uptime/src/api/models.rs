use crate::db::entity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            message: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            message: None,
        }
    }

    pub fn message(message: String) -> Self {
        Self {
            success: true,
            data: None,
            error: None,
            message: Some(message),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
    pub total_pages: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Some(1),
            per_page: Some(20),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_contact_info", skip_on_field_errors = false))]
pub struct CreateNodeRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: String,

    #[validate(length(min = 1, max = 255))]
    pub host: String,

    #[validate(range(min = 1, max = 65535))]
    pub port: i32,

    #[validate(length(min = 1, max = 20))]
    pub protocol: String,

    #[validate(length(max = 500))]
    pub description: Option<String>,

    #[validate(range(min = 1, max = 10000))]
    pub max_connections: i32,

    pub allow_relay: bool,

    #[validate(length(min = 1, max = 100))]
    pub network_name: String,

    #[validate(length(max = 100))]
    pub network_secret: Option<String>,

    // 联系方式字段
    #[validate(length(max = 20))]
    pub qq_number: Option<String>,

    #[validate(length(max = 50))]
    pub wechat: Option<String>,

    #[validate(email)]
    pub mail: Option<String>,
}

// 自定义验证函数：确保至少填写一种联系方式
fn validate_contact_info(request: &CreateNodeRequest) -> Result<(), validator::ValidationError> {
    let has_qq = request
        .qq_number
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_wechat = request
        .wechat
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_mail = request.mail.as_ref().is_some_and(|s| !s.trim().is_empty());

    if !has_qq && !has_wechat && !has_mail {
        return Err(validator::ValidationError::new("contact_required"));
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UpdateNodeRequest {
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,

    #[validate(length(min = 1, max = 255))]
    pub host: Option<String>,

    #[validate(range(min = 1, max = 65535))]
    pub port: Option<i32>,

    #[validate(length(min = 1, max = 20))]
    pub protocol: Option<String>,

    #[validate(length(max = 500))]
    pub description: Option<String>,

    #[validate(range(min = 1, max = 10000))]
    pub max_connections: Option<i32>,

    pub is_active: Option<bool>,

    pub allow_relay: Option<bool>,

    #[validate(length(min = 1, max = 100))]
    pub network_name: Option<String>,

    #[validate(length(max = 100))]
    pub network_secret: Option<String>,

    // 联系方式字段
    #[validate(length(max = 20))]
    pub qq_number: Option<String>,

    #[validate(length(max = 50))]
    pub wechat: Option<String>,

    #[validate(email)]
    pub mail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeResponse {
    pub id: i32,
    pub name: String,
    pub host: String,
    pub port: i32,
    pub protocol: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub max_connections: i32,
    pub current_connections: i32,
    pub is_active: bool,
    pub is_approved: bool,
    pub allow_relay: bool,
    pub network_name: Option<String>,
    pub network_secret: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub address: String,
    pub usage_percentage: f64,
    // 健康状态相关字段
    pub current_health_status: Option<String>,
    pub last_check_time: Option<chrono::DateTime<chrono::Utc>>,
    pub last_response_time: Option<i32>,
    pub health_percentage_24h: Option<f64>,

    pub health_record_total_counter_ring: Vec<u64>,
    pub health_record_healthy_counter_ring: Vec<u64>,
    pub ring_granularity: u32,

    // 联系方式字段
    pub qq_number: Option<String>,
    pub wechat: Option<String>,
    pub mail: Option<String>,
}

impl From<entity::shared_nodes::Model> for NodeResponse {
    fn from(node: entity::shared_nodes::Model) -> Self {
        Self {
            id: node.id,
            name: node.name.clone(),
            host: node.host.clone(),
            port: node.port,
            protocol: node.protocol.clone(),
            version: Some(node.version.clone()),
            description: Some(node.description.clone()),
            max_connections: node.max_connections,
            current_connections: node.current_connections,
            is_active: node.is_active,
            is_approved: node.is_approved,
            allow_relay: node.allow_relay,
            network_name: Some(node.network_name.clone()),
            network_secret: Some(node.network_secret.clone()),
            created_at: node.created_at.into(),
            updated_at: node.updated_at.into(),
            address: format!("{}://{}:{}", node.protocol, node.host, node.port),
            usage_percentage: node.current_connections as f64 / node.max_connections as f64 * 100.0,
            // 健康状态字段初始化为 None，将在 handlers 中填充
            current_health_status: None,
            last_check_time: None,
            last_response_time: None,
            health_percentage_24h: None,

            health_record_healthy_counter_ring: Vec::new(),
            health_record_total_counter_ring: Vec::new(),
            ring_granularity: 0,

            // 联系方式字段
            qq_number: if node.qq_number.is_empty() {
                None
            } else {
                Some(node.qq_number)
            },
            wechat: if node.wechat.is_empty() {
                None
            } else {
                Some(node.wechat)
            },
            mail: if node.mail.is_empty() {
                None
            } else {
                Some(node.mail)
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthRecordResponse {
    pub id: i32,
    pub node_id: i32,
    pub status: String,
    pub response_time: Option<i32>,
    pub error_message: Option<String>,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

impl From<entity::health_records::Model> for HealthRecordResponse {
    fn from(record: entity::health_records::Model) -> Self {
        Self {
            id: record.id,
            node_id: record.node_id,
            status: record.status.to_string(),
            response_time: Some(record.response_time),
            error_message: Some(record.error_message),
            checked_at: record.checked_at.into(),
        }
    }
}

pub type HealthStatsResponse = crate::db::HealthStats;

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeFilterParams {
    pub is_active: Option<bool>,
    pub protocol: Option<String>,
    pub search: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthFilterParams {
    pub status: Option<String>,
    pub since: Option<DateTime<Utc>>,
}

// 管理员相关模型
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct AdminLoginRequest {
    #[validate(length(min = 1))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminLoginResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApproveNodeRequest {
    pub approved: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminNodeFilterParams {
    pub is_active: Option<bool>,
    pub is_approved: Option<bool>,
    pub protocol: Option<String>,
    pub search: Option<String>,
}
