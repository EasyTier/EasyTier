#![allow(unused)]

mod api;
mod config;
mod db;
mod health_checker;
mod health_checker_manager;
mod migrator;

use api::routes::create_routes;
use clap::Parser;
use config::AppConfig;
use db::{operations::NodeOperations, Db};
use easytier::common::log;
use health_checker::HealthChecker;
use health_checker_manager::HealthCheckerManager;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

use crate::db::cleanup::{CleanupConfig, CleanupManager};

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL_MIMALLOC: MiMalloc = MiMalloc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Admin password for management access
    #[arg(long, env = "ADMIN_PASSWORD")]
    admin_password: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    // 加载配置
    let config = AppConfig::default();

    // 初始化日志
    let _ = log::init(&config.logging, false);

    // 解析命令行参数
    let args = Args::parse();

    // 如果提供了管理员密码，设置环境变量
    if let Some(password) = args.admin_password {
        env::set_var("ADMIN_PASSWORD", password);
    }

    tracing::info!(
        "Admin password configured: {}",
        !config.security.admin_password.is_empty()
    );

    // 创建数据库连接
    let db = Db::new(&config.database.path.to_string_lossy()).await?;

    // 获取数据库统计信息
    let stats = db.get_database_stats().await?;
    tracing::info!("Database initialized successfully!");
    tracing::info!("Database stats: {:?}", stats);

    // 创建配置目录
    let config_dir = PathBuf::from("./configs");
    tokio::fs::create_dir_all(&config_dir).await?;

    // 创建健康检查器和管理器
    let health_checker = Arc::new(HealthChecker::new(db.clone()));
    let health_checker_manager = HealthCheckerManager::new(health_checker, db.clone())
        .with_monitor_interval(Duration::from_secs(1)); // 每30秒检查一次节点变化

    let cleanup_manager = CleanupManager::new(db.clone(), CleanupConfig::default());
    cleanup_manager.start_auto_cleanup().await?;

    // 启动节点监控
    health_checker_manager.start_monitoring().await?;
    tracing::info!("Health checker manager started successfully!");

    let monitored_count = health_checker_manager.get_monitored_node_count().await;
    tracing::info!("Currently monitoring {} nodes", monitored_count);

    // 创建应用状态
    let app_state = crate::api::handlers::AppState {
        db: db.clone(),
        health_checker_manager: Arc::new(health_checker_manager),
    };

    // 创建 API 路由
    let app = create_routes().with_state(app_state);

    // 配置服务器地址
    let addr = config.server.addr;

    tracing::info!("Starting server on http://{}", addr);
    tracing::info!("Available endpoints:");
    tracing::info!("  GET  /health - Health check");
    tracing::info!("  GET  /api/nodes - Get nodes (paginated, approved only)");
    tracing::info!("  POST /api/nodes - Create node (pending approval)");
    tracing::info!("  GET  /api/nodes/:id - Get node by ID");
    tracing::info!("  PUT  /api/nodes/:id - Update node");
    tracing::info!("  DELETE /api/nodes/:id - Delete node");
    tracing::info!("  GET  /api/nodes/:id/health - Get node health history");
    tracing::info!("  GET  /api/nodes/:id/health/stats - Get node health stats");
    tracing::info!("Admin endpoints:");
    tracing::info!("  POST /api/admin/login - Admin login");
    tracing::info!("  GET  /api/admin/nodes - Get all nodes (including pending)");
    tracing::info!("  PUT  /api/admin/nodes/:id/approve - Approve/reject node");
    tracing::info!("  DELETE /api/admin/nodes/:id - Delete node (admin only)");

    // 启动服务器
    let listener = tokio::net::TcpListener::bind(addr).await?;

    // 设置优雅关闭
    let shutdown_signal = Arc::new(tokio::sync::Notify::new());
    let server_shutdown_signal = shutdown_signal.clone();

    // 启动服务器任务
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                server_shutdown_signal.notified().await;
            })
            .await
            .unwrap();
    });

    // 等待 Ctrl+C 信号
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
        }
        _ = server_handle => {
            tracing::info!("Server task completed");
        }
    }

    // 优雅关闭
    tracing::info!("Shutting down gracefully...");
    shutdown_signal.notify_waiters();

    tracing::info!("Shutdown complete");
    Ok(())
}
