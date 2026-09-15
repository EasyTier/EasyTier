use std::{ffi::OsString, path::PathBuf, sync::Arc};

use anyhow::Context as _;
use easytier::common::MachineIdOptions;
use easytier::{
    common::config::{ConfigFileControl, load_toml_config_from_path},
    instance::factory::native_compact_instance_manager_with_runtime,
    rpc_service::ReadOnlyApiRpcServer,
    web_client::{WebClientHooks, parse_config_server_endpoint, run_web_client},
};

enum Command {
    Run(RunOptions),
    Exit,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RunOptions {
    config: Option<PathBuf>,
    config_server: Option<String>,
    machine_id: Option<String>,
    hostname: Option<String>,
    secure_mode: bool,
}

const USAGE: &str = "usage: easytier-mini [--config <FILE>] [--config-server <URL>] \
                     [--machine-id <ID>] [--hostname <NAME>] [--secure-mode]";

fn required_value(
    args: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> anyhow::Result<OsString> {
    args.next()
        .with_context(|| format!("{option} requires a value"))
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> anyhow::Result<Command> {
    let mut options = RunOptions::default();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            println!(
                "easytier-mini {}\n\nUsage: {USAGE}",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(Command::Exit);
        }
        if arg == "-V" || arg == "--version" {
            println!("easytier-mini {}", env!("CARGO_PKG_VERSION"));
            return Ok(Command::Exit);
        }
        if arg == "-c" || arg == "--config" {
            if options.config.is_some() {
                anyhow::bail!("--config may only be specified once");
            }
            options.config = Some(PathBuf::from(required_value(&mut args, "--config")?));
            continue;
        }
        if arg == "-w" || arg == "--config-server" {
            if options.config_server.is_some() {
                anyhow::bail!("--config-server may only be specified once");
            }
            options.config_server = Some(
                required_value(&mut args, "--config-server")?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("--config-server must be valid UTF-8"))?,
            );
            continue;
        }
        if arg == "--machine-id" {
            options.machine_id = Some(
                required_value(&mut args, "--machine-id")?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("--machine-id must be valid UTF-8"))?,
            );
            continue;
        }
        if arg == "--hostname" {
            options.hostname = Some(
                required_value(&mut args, "--hostname")?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("--hostname must be valid UTF-8"))?,
            );
            continue;
        }
        if arg == "--secure-mode" {
            options.secure_mode = true;
            continue;
        }
        anyhow::bail!("unknown argument {arg:?}; {USAGE}");
    }
    if options.config.is_none() && options.config_server.is_none() {
        anyhow::bail!("either --config or --config-server is required; {USAGE}");
    }
    Ok(Command::Run(options))
}

fn require_tcp_or_udp(scheme: &str, source: &str) -> anyhow::Result<()> {
    match scheme {
        "tcp" | "udp" => Ok(()),
        scheme => anyhow::bail!(
            "{source} uses unsupported tunnel scheme {scheme:?}; easytier-mini supports only tcp:// and udp://"
        ),
    }
}

fn validate_config_server(config_server: &str) -> anyhow::Result<()> {
    let endpoint = parse_config_server_endpoint(config_server)?;
    require_tcp_or_udp(endpoint.connect_url().scheme(), "config server")
}

struct MiniWebClientHooks;

impl WebClientHooks for MiniWebClientHooks {
    fn manages_remote_config_instances(&self) -> bool {
        true
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let Command::Run(options) = parse_args(std::env::args_os().skip(1))? else {
        return Ok(());
    };
    easytier::common::log::init_console()?;
    let local_config = options
        .config
        .as_ref()
        .map(|config_path| {
            load_toml_config_from_path(config_path)
                .with_context(|| format!("failed to load {}", config_path.display()))
        })
        .transpose()?;
    if let Some(config_server) = options.config_server.as_deref() {
        validate_config_server(config_server)?;
    }

    let instances = Arc::new(native_compact_instance_manager_with_runtime(
        tokio::runtime::Handle::current(),
    ));
    let local_instance_id = local_config
        .map(|config| instances.run_network_instance(config, ConfigFileControl::STATIC_CONFIG))
        .transpose()?;
    let _web_client = if let Some(config_server) = options.config_server.as_deref() {
        Some(
            run_web_client(
                config_server,
                MachineIdOptions {
                    explicit_machine_id: options.machine_id,
                    state_dir: None,
                },
                options.hostname,
                options.secure_mode,
                instances.clone(),
                Some(Arc::new(MiniWebClientHooks)),
            )
            .await?,
        )
    } else {
        None
    };
    let _rpc_server =
        ReadOnlyApiRpcServer::new(Some("127.0.0.1:15888".to_owned()), None, instances.clone())?
            .serve()
            .await?;
    eprintln!(
        "easytier-mini started: local={local_instance_id:?}, web={}; RPC: 127.0.0.1:15888",
        options.config_server.is_some()
    );

    let stopped_unexpectedly = tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for Ctrl-C")?;
            false
        },
        _ = instances.wait() => true,
    };

    for instance in instances.instances() {
        instance.stop().await;
    }
    if stopped_unexpectedly {
        anyhow::bail!("EasyTier instance stopped unexpectedly");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier::common::config::{ConfigLoader as _, TomlConfigLoader};

    #[test]
    fn parses_minimal_config_argument() {
        let Command::Run(options) =
            parse_args([OsString::from("--config"), OsString::from("mini.toml")].into_iter())
                .unwrap()
        else {
            panic!("expected run command");
        };

        assert_eq!(options.config, Some(PathBuf::from("mini.toml")));
    }

    #[test]
    fn parses_web_client_arguments_without_a_local_config() {
        let Command::Run(options) = parse_args(
            [
                OsString::from("--config-server"),
                OsString::from("token"),
                OsString::from("--machine-id"),
                OsString::from("machine"),
                OsString::from("--hostname"),
                OsString::from("mini"),
                OsString::from("--secure-mode"),
            ]
            .into_iter(),
        )
        .unwrap() else {
            panic!("expected run command");
        };

        assert_eq!(options.config_server.as_deref(), Some("token"));
        assert_eq!(options.machine_id.as_deref(), Some("machine"));
        assert_eq!(options.hostname.as_deref(), Some("mini"));
        assert!(options.secure_mode);
    }

    #[test]
    fn rejects_unknown_arguments() {
        let result = parse_args([OsString::from("extra")].into_iter());

        assert!(result.is_err());
    }

    #[test]
    fn accepts_tcp_udp_config_server() {
        assert!(validate_config_server("udp://127.0.0.1:22020/token").is_ok());
        assert!(validate_config_server("quic://127.0.0.1:22020/token").is_err());
    }

    #[tokio::test]
    async fn compact_factory_accepts_unsupported_config_without_changing_it() {
        let config = TomlConfigLoader::new_from_str(
            r#"
dhcp = true
listeners = ["quic://127.0.0.1:11010"]
proxy_network = [{ cidr = "10.20.0.0/16" }]

[flags]
encryption_algorithm = "chacha20"
data_compress_algo = "Zstd"
"#,
        )
        .unwrap();
        config.get_id();
        let before = config.dump();
        let manager =
            native_compact_instance_manager_with_runtime(tokio::runtime::Handle::current());

        let instance = manager.create(config, ()).unwrap();

        assert_eq!(instance.toml_config().unwrap().dump(), before);
    }
}
