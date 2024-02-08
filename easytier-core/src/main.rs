#![allow(dead_code)]

#[cfg(test)]
mod tests;

use clap::Parser;

mod arch;
mod common;
mod connector;
mod gateway;
mod instance;
mod peer_center;
mod peers;
mod tunnels;

use instance::instance::{Instance, InstanceConfigWriter};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// the instance name
    #[arg(short = 'n', long, default_value = "default")]
    instance_name: String,

    /// specify the network namespace, default is the root namespace
    #[arg(long)]
    net_ns: Option<String>,

    #[arg(short, long)]
    ipv4: Option<String>,

    #[arg(short, long)]
    peers: Vec<String>,
}

fn init_logger() {
    // logger to rolling file
    let file_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()
        .unwrap();
    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .max_log_files(5)
        .filename_prefix("core.log")
        .build("/var/log/easytier")
        .expect("failed to initialize rolling file appender");
    let mut file_layer = tracing_subscriber::fmt::layer();
    file_layer.set_ansi(false);
    let file_layer = file_layer
        .with_writer(file_appender)
        .with_timer(tracing_subscriber::fmt::time::OffsetTime::local_rfc_3339().unwrap())
        .with_filter(file_filter);

    // logger to console
    let console_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .from_env()
        .unwrap();
    let console_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_timer(tracing_subscriber::fmt::time::OffsetTime::local_rfc_3339().unwrap())
        .with_writer(std::io::stderr)
        .with_filter(console_filter);

    tracing_subscriber::Registry::default()
        .with(console_layer)
        .with(file_layer)
        .init();
}

#[tokio::main(flavor = "current_thread")]
#[tracing::instrument]
pub async fn main() {
    init_logger();

    let cli = Cli::parse();
    tracing::info!(cli = ?cli, "cli args parsed");

    let cfg = InstanceConfigWriter::new(cli.instance_name.as_str()).set_ns(cli.net_ns.clone());
    if let Some(ipv4) = &cli.ipv4 {
        cfg.set_addr(ipv4.clone());
    }

    let mut inst = Instance::new(cli.instance_name.as_str());

    let mut events = inst.get_global_ctx().subscribe();
    tokio::spawn(async move {
        while let Ok(e) = events.recv().await {
            log::warn!("event: {:?}", e);
        }
    });

    inst.run().await.unwrap();

    for peer in cli.peers {
        inst.get_conn_manager()
            .add_connector_by_url(peer.as_str())
            .await
            .unwrap();
    }

    inst.wait().await;
}
