//! 测试 HealthyStats 功能的示例代码

use easytier_uptime::db::entity::health_records::{HealthStatus, HealthStats, Model};
use sea_orm::prelude::*;

fn main() {
    // 创建一些模拟的健康记录
    let records = vec![
        Model {
            id: 1,
            node_id: 1,
            status: HealthStatus::Healthy.to_string(),
            response_time: 100,
            error_message: String::new(),
            checked_at: chrono::Utc::now().fixed_offset(),
        },
        Model {
            id: 2,
            node_id: 1,
            status: HealthStatus::Healthy.to_string(),
            response_time: 150,
            error_message: String::new(),
            checked_at: chrono::Utc::now().fixed_offset(),
        },
        Model {
            id: 3,
            node_id: 1,
            status: HealthStatus::Unhealthy.to_string(),
            response_time: 0,
            error_message: "Connection failed".to_string(),
            checked_at: chrono::Utc::now().fixed_offset(),
        },
    ];

    // 从记录创建统计信息
    let stats = HealthStats::from_records(&records);

    println!("健康统计信息:");
    println!("总检查次数: {}", stats.total_checks);
    println!("健康检查次数: {}", stats.healthy_count);
    println!("不健康检查次数: {}", stats.unhealthy_count);
    println!("健康百分比: {:.2}%", stats.health_percentage);
    println!("平均响应时间: {:?} ms", stats.average_response_time);
    println!("正常运行时间百分比: {:.2}%", stats.uptime_percentage);
    println!("最后检查时间: {:?}", stats.last_check_time);
    println!("最后状态: {:?}", stats.last_status);

    // 测试健康状态转换
    println!("\n健康状态测试:");
    let status_healthy = HealthStatus::from("healthy");
    let status_unhealthy = HealthStatus::from("unhealthy");
    let status_timeout = HealthStatus::from("timeout");
    let status_unknown = HealthStatus::from("invalid_status");

    println!("healthy -> {:?}", status_healthy);
    println!("unhealthy -> {:?}", status_unhealthy);
    println!("timeout -> {:?}", status_timeout);
    println!("invalid_status -> {:?}", status_unknown);

    // 测试记录的健康状态检查
    println!("\n记录健康状态检查:");
    for record in &records {
        println!("记录 {} 是否健康: {}", record.id, record.is_healthy());
        println!("记录 {} 状态: {:?}", record.id, record.get_status());
    }
}