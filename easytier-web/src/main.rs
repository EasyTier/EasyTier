#![allow(dead_code)]

use std::sync::Arc;

use easytier::{
    common::config::{ConfigLoader, ConsoleLoggerConfig, TomlConfigLoader},
    tunnel::udp::UdpTunnelListener,
    utils::init_logger,
};

mod client_manager;
mod db;
mod migrator;
mod restful;

#[tokio::main]
async fn main() {
    let config = TomlConfigLoader::default();
    config.set_console_logger_config(ConsoleLoggerConfig {
        level: Some("trace".to_string()),
    });
    init_logger(config, false).unwrap();

    // let db = db::Db::new(":memory:").await.unwrap();
    let db = db::Db::new("et.db").await.unwrap();

    let listener = UdpTunnelListener::new("udp://0.0.0.0:22020".parse().unwrap());
    let mut mgr = client_manager::ClientManager::new();
    mgr.serve(listener).await.unwrap();
    let mgr = Arc::new(mgr);

    let mut restful_server =
        restful::RestfulServer::new("0.0.0.0:11211".parse().unwrap(), mgr.clone(), db)
            .await
            .unwrap();
    restful_server.start().await.unwrap();
    tokio::signal::ctrl_c().await.unwrap();
}
