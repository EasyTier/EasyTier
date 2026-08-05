use std::{ffi::OsString, path::PathBuf, sync::Arc};

use anyhow::Context as _;
use easytier::{
    common::config::{
        ConfigFileControl, ConfigLoader as _, EncryptionAlgorithm, TomlConfigLoader,
        load_toml_config_from_path, parse_encryption_algorithm,
    },
    instance::factory::native_instance_manager_with_runtime,
    rpc_service::ReadOnlyApiRpcServer,
};

enum Command {
    Run(PathBuf),
    Exit,
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> anyhow::Result<Command> {
    let Some(arg) = args.next() else {
        anyhow::bail!("usage: easytier-mini --config <FILE>");
    };
    if arg == "-h" || arg == "--help" {
        println!(
            "easytier-mini {}\n\nUsage: easytier-mini --config <FILE>",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(Command::Exit);
    }
    if arg == "-V" || arg == "--version" {
        println!("easytier-mini {}", env!("CARGO_PKG_VERSION"));
        return Ok(Command::Exit);
    }
    if arg != "-c" && arg != "--config" {
        anyhow::bail!("unknown argument {arg:?}; usage: easytier-mini --config <FILE>");
    }
    let path = args
        .next()
        .map(PathBuf::from)
        .context("--config requires a file path")?;
    if let Some(extra) = args.next() {
        anyhow::bail!("unexpected argument {extra:?}");
    }
    Ok(Command::Run(path))
}

fn require_tcp_or_udp(scheme: &str, source: &str) -> anyhow::Result<()> {
    match scheme {
        "tcp" | "udp" => Ok(()),
        scheme => anyhow::bail!(
            "{source} uses unsupported tunnel scheme {scheme:?}; easytier-mini supports only tcp:// and udp://"
        ),
    }
}

fn validate_and_constrain(config: &TomlConfigLoader) -> anyhow::Result<()> {
    for listener in config.get_listener_uris() {
        require_tcp_or_udp(listener.scheme(), "listener")?;
    }
    for listener in config.get_mapped_listeners() {
        require_tcp_or_udp(listener.scheme(), "mapped listener")?;
    }
    for peer in config.get_peers() {
        require_tcp_or_udp(peer.uri.scheme(), "peer")?;
    }

    if config.get_vpn_portal_config().is_some() {
        anyhow::bail!("vpn_portal is not supported by easytier-mini");
    }
    if config.get_socks5_portal().is_some() {
        anyhow::bail!("socks5_proxy is not supported by easytier-mini");
    }
    if !config.get_port_forwards().is_empty() {
        anyhow::bail!("port_forward is not supported by easytier-mini");
    }
    if !config.get_proxy_cidrs().is_empty() {
        anyhow::bail!("proxy_network is not supported by easytier-mini");
    }

    let mut flags = config.get_flags();
    let encryption_algorithm =
        parse_encryption_algorithm(&flags.encryption_algorithm).map_err(anyhow::Error::msg)?;
    if encryption_algorithm == EncryptionAlgorithm::ChaCha20 {
        anyhow::bail!("chacha20 encryption is not supported by easytier-mini");
    }
    if flags.socket_mark.is_some() {
        anyhow::bail!("socket_mark is not supported by easytier-mini");
    }
    if flags.use_smoltcp || flags.enable_exit_node {
        anyhow::bail!("gateway and smoltcp are not supported by easytier-mini");
    }
    if flags.accept_dns {
        anyhow::bail!("Magic DNS is not supported by easytier-mini");
    }
    if flags.enable_kcp_proxy || flags.enable_quic_proxy || flags.enable_udp_broadcast_relay {
        anyhow::bail!("the requested transport feature is not supported by easytier-mini");
    }

    // This binary is built without the port-mapping adapter. Keep the core policy
    // aligned with that build even when reading a full EasyTier configuration.
    flags.disable_upnp = true;
    flags.disable_tcp_hole_punching = true;
    flags.disable_kcp_input = true;
    flags.disable_relay_kcp = true;
    flags.enable_relay_foreign_network_kcp = false;
    flags.disable_quic_input = true;
    flags.disable_relay_quic = true;
    flags.enable_relay_foreign_network_quic = false;
    config.set_flags(flags);
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Command::Run(config_path) = parse_args(std::env::args_os().skip(1))? else {
        return Ok(());
    };
    let config = load_toml_config_from_path(&config_path)
        .with_context(|| format!("failed to load {}", config_path.display()))?;
    easytier::common::log::init_console()?;
    validate_and_constrain(&config)?;

    let instances = Arc::new(native_instance_manager_with_runtime(
        tokio::runtime::Handle::current(),
    ));
    let instance_id = instances.run_network_instance(config, ConfigFileControl::STATIC_CONFIG)?;
    let instance = instances
        .instance(instance_id)
        .context("new EasyTier instance is missing from the instance manager")?;
    let _rpc_server =
        ReadOnlyApiRpcServer::new(Some("127.0.0.1:15888".to_owned()), None, instances.clone())?
            .serve()
            .await?;
    eprintln!("easytier-mini started: {instance_id}; RPC: 127.0.0.1:15888");

    let stopped_unexpectedly = tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for Ctrl-C")?;
            false
        },
        _ = instances.wait() => true,
    };

    instance.stop().await;
    if stopped_unexpectedly {
        anyhow::bail!("EasyTier instance stopped unexpectedly");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config_argument() {
        let Command::Run(path) =
            parse_args([OsString::from("--config"), OsString::from("mini.toml")].into_iter())
                .unwrap()
        else {
            panic!("expected run command");
        };

        assert_eq!(path, PathBuf::from("mini.toml"));
    }

    #[test]
    fn rejects_extra_arguments() {
        let result = parse_args(
            [
                OsString::from("--config"),
                OsString::from("mini.toml"),
                OsString::from("extra"),
            ]
            .into_iter(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn accepts_native_tcp_udp_config_and_disables_upnp() {
        let config = TomlConfigLoader::new_from_str(
            r#"
listeners = ["tcp://127.0.0.1:11010", "udp://127.0.0.1:11010"]

[[peer]]
uri = "udp://127.0.0.1:11011"
"#,
        )
        .unwrap();

        validate_and_constrain(&config).unwrap();
        let flags = config.get_flags();
        assert!(flags.disable_upnp);
        assert!(flags.disable_tcp_hole_punching);
        assert!(flags.disable_kcp_input);
        assert!(flags.disable_relay_kcp);
        assert!(!flags.enable_relay_foreign_network_kcp);
        assert!(flags.disable_quic_input);
        assert!(flags.disable_relay_quic);
        assert!(!flags.enable_relay_foreign_network_quic);
    }

    #[test]
    fn rejects_excluded_tunnel_schemes() {
        let config =
            TomlConfigLoader::new_from_str("listeners = [\"quic://127.0.0.1:11010\"]").unwrap();

        assert!(validate_and_constrain(&config).is_err());
    }

    #[test]
    fn rejects_socket_mark_without_contextual_dns_support() {
        let config = TomlConfigLoader::new_from_str("[flags]\nsocket_mark = 7").unwrap();

        assert!(validate_and_constrain(&config).is_err());
    }

    #[test]
    fn rejects_encryption_algorithm_missing_from_the_mini_build() {
        let config =
            TomlConfigLoader::new_from_str("[flags]\nencryption_algorithm = \"chacha20\"").unwrap();

        assert!(validate_and_constrain(&config).is_err());
    }
}
