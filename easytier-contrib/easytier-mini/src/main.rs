use std::{ffi::OsString, path::PathBuf, sync::Arc};

use anyhow::Context as _;
#[cfg(feature = "web-client")]
use easytier::common::MachineIdOptions;
#[cfg(feature = "rpc")]
use easytier::rpc_service::ReadOnlyApiRpcServer;
#[cfg(feature = "web-client")]
use easytier::web_client::{WebClientHooks, parse_config_server_endpoint, run_web_client};
use easytier::{
    common::config::{
        ConfigFileControl, ConfigLoader as _, TomlConfigLoader, load_toml_config_from_path,
    },
    instance::factory::native_compact_instance_manager_with_runtime,
};

enum Command {
    Run(RunOptions),
    Exit,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RunOptions {
    config: Option<PathBuf>,
    #[cfg(feature = "rpc")]
    rpc_portal: Option<String>,
    #[cfg(feature = "web-client")]
    config_server: Option<String>,
    #[cfg(feature = "web-client")]
    machine_id: Option<String>,
    #[cfg(feature = "web-client")]
    hostname: Option<String>,
    #[cfg(feature = "web-client")]
    secure_mode: bool,
}

#[cfg(feature = "web-client")]
const USAGE: &str = "usage: easytier-nano [--config <FILE>] [--config-server <URL>] \
                     [--machine-id <ID>] [--hostname <NAME>] [--secure-mode]";
#[cfg(not(feature = "web-client"))]
const USAGE: &str = "usage: easytier-nano --config <FILE>";
#[cfg(feature = "rpc")]
const DEFAULT_RPC_PORTAL: &str = "127.0.0.1:15888";

fn usage() -> String {
    #[cfg(feature = "rpc")]
    {
        format!("{USAGE} [--rpc-portal <ADDR>]")
    }
    #[cfg(not(feature = "rpc"))]
    {
        USAGE.to_owned()
    }
}

fn print_help() {
    println!(
        "easytier-nano {}\n\n{}\n\nOptions:\n  -c, --config <FILE>       Local TOML configuration\n  -h, --help                Show help\n  -V, --version             Show version",
        env!("CARGO_PKG_VERSION"),
        usage(),
    );
    #[cfg(feature = "web-client")]
    println!(
        "  -w, --config-server <URL>  EasyTier Web config-server URL\n      --machine-id <ID>     Web machine identity\n      --hostname <NAME>     Web hostname\n      --secure-mode         Secure Web transport"
    );
    #[cfg(feature = "rpc")]
    println!(
        "      --rpc-portal <ADDR>   Management RPC socket address (default: {DEFAULT_RPC_PORTAL})"
    );
}

fn required_value(
    args: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> anyhow::Result<OsString> {
    args.next()
        .with_context(|| format!("{option} requires a value"))
}

#[cfg(any(feature = "web-client", feature = "rpc"))]
fn required_utf8_value(
    args: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> anyhow::Result<String> {
    required_value(args, option)?
        .into_string()
        .map_err(|_| anyhow::anyhow!("{option} must be valid UTF-8"))
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> anyhow::Result<Command> {
    let mut options = RunOptions::default();
    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            print_help();
            return Ok(Command::Exit);
        }
        if arg == "-V" || arg == "--version" {
            println!("easytier-nano {}", env!("CARGO_PKG_VERSION"));
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
            #[cfg(feature = "web-client")]
            {
                if options.config_server.is_some() {
                    anyhow::bail!("--config-server may only be specified once");
                }
                options.config_server = Some(required_utf8_value(&mut args, "--config-server")?);
                continue;
            }
            #[cfg(not(feature = "web-client"))]
            anyhow::bail!(
                "--config-server requires the web-client feature; rebuild with --features web-client or --no-default-features --features official"
            );
        }
        if arg == "--machine-id" {
            #[cfg(feature = "web-client")]
            {
                options.machine_id = Some(required_utf8_value(&mut args, "--machine-id")?);
                continue;
            }
            #[cfg(not(feature = "web-client"))]
            anyhow::bail!(
                "--machine-id requires the web-client feature; rebuild with --features web-client"
            );
        }
        if arg == "--hostname" {
            #[cfg(feature = "web-client")]
            {
                options.hostname = Some(required_utf8_value(&mut args, "--hostname")?);
                continue;
            }
            #[cfg(not(feature = "web-client"))]
            anyhow::bail!(
                "--hostname requires the web-client feature; rebuild with --features web-client"
            );
        }
        if arg == "--secure-mode" {
            #[cfg(feature = "web-client")]
            {
                options.secure_mode = true;
                continue;
            }
            #[cfg(not(feature = "web-client"))]
            anyhow::bail!(
                "--secure-mode requires the web-client feature; rebuild with --features web-client"
            );
        }
        if arg == "--rpc-portal" {
            #[cfg(feature = "rpc")]
            {
                if options.rpc_portal.is_some() {
                    anyhow::bail!("--rpc-portal may only be specified once");
                }
                let portal = required_utf8_value(&mut args, "--rpc-portal")?;
                portal.parse::<std::net::SocketAddr>().context(
                    "--rpc-portal must be an IP address and port, such as 127.0.0.1:15889",
                )?;
                options.rpc_portal = Some(portal);
                continue;
            }
            #[cfg(not(feature = "rpc"))]
            anyhow::bail!("--rpc-portal requires the rpc feature; rebuild with --features rpc");
        }
        anyhow::bail!("unknown argument {}; {}", arg.to_string_lossy(), usage());
    }
    let has_config = options.config.is_some();
    #[cfg(feature = "web-client")]
    let has_config = has_config || options.config_server.is_some();
    if !has_config {
        #[cfg(feature = "web-client")]
        anyhow::bail!(
            "either --config or --config-server is required; {}",
            usage()
        );
        #[cfg(not(feature = "web-client"))]
        anyhow::bail!("--config is required in this build; {}", usage());
    }
    Ok(Command::Run(options))
}

fn validate_local_config(config: &TomlConfigLoader) -> anyhow::Result<()> {
    let flags = config.get_flags();
    let needs_virtual_ip =
        config.get_ipv4().is_some() || config.get_ipv6().is_some() || config.get_dhcp();
    if !cfg!(feature = "dhcp") && config.get_dhcp() {
        anyhow::bail!(
            "dhcp = true requires the dhcp feature; rebuild with --features dhcp or configure a static virtual IP"
        );
    }
    if !cfg!(feature = "smoltcp") && (flags.use_smoltcp || (flags.no_tun && needs_virtual_ip)) {
        anyhow::bail!(
            "no_tun = true with a virtual IP or use_smoltcp = true requires the smoltcp feature; rebuild with --features smoltcp"
        );
    }
    if !cfg!(feature = "tun") && !flags.no_tun && needs_virtual_ip {
        anyhow::bail!(
            "a virtual IP requires the tun feature; rebuild with --features tun, or enable smoltcp and set [flags] no_tun = true"
        );
    }
    Ok(())
}

#[cfg(feature = "web-client")]
fn require_tcp_or_udp(scheme: &str, source: &str) -> anyhow::Result<()> {
    match scheme {
        "tcp" | "udp" => Ok(()),
        scheme => anyhow::bail!(
            "{source} uses unsupported tunnel scheme {scheme}; easytier-nano supports only tcp:// and udp://"
        ),
    }
}

#[cfg(feature = "web-client")]
fn validate_config_server(config_server: &str) -> anyhow::Result<()> {
    let endpoint = parse_config_server_endpoint(config_server)?;
    require_tcp_or_udp(endpoint.connect_url().scheme(), "config server")
}

#[cfg(feature = "web-client")]
struct MiniWebClientHooks;

#[cfg(feature = "web-client")]
#[async_trait::async_trait]
impl WebClientHooks for MiniWebClientHooks {
    fn manages_remote_config_instances(&self) -> bool {
        true
    }

    async fn pre_run_network_instance(&self, config: &TomlConfigLoader) -> Result<(), String> {
        validate_local_config(config).map_err(|error| error.to_string())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let Command::Run(options) = parse_args(std::env::args_os().skip(1))? else {
        return Ok(());
    };
    #[cfg(feature = "logging")]
    easytier::common::log::init_console()?;
    let local_config = options
        .config
        .as_ref()
        .map(|config_path| {
            load_toml_config_from_path(config_path)
                .with_context(|| format!("failed to load {}", config_path.display()))
        })
        .transpose()?;
    if let Some(config) = local_config.as_ref() {
        validate_local_config(config)?;
    }
    #[cfg(feature = "web-client")]
    if let Some(config_server) = options.config_server.as_deref() {
        validate_config_server(config_server)?;
    }

    let instances = Arc::new(native_compact_instance_manager_with_runtime(
        tokio::runtime::Handle::current(),
    ));
    let _local_instance_id = local_config
        .map(|config| instances.run_network_instance(config, ConfigFileControl::STATIC_CONFIG))
        .transpose()?;
    #[cfg(feature = "web-client")]
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
    #[cfg(feature = "rpc")]
    let rpc_portal = options.rpc_portal.as_deref().unwrap_or(DEFAULT_RPC_PORTAL);
    #[cfg(feature = "rpc")]
    let _rpc_server =
        ReadOnlyApiRpcServer::new(Some(rpc_portal.to_owned()), None, instances.clone())?
            .serve()
            .await?;
    #[cfg(not(feature = "strip-logs"))]
    eprintln!("easytier-nano started: local={_local_instance_id:?}");
    #[cfg(all(feature = "web-client", not(feature = "strip-logs")))]
    eprintln!("Web: {}", options.config_server.is_some());
    #[cfg(all(feature = "rpc", not(feature = "strip-logs")))]
    eprintln!("RPC: {rpc_portal}");

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

    fn parse(args: &[&str]) -> anyhow::Result<Command> {
        parse_args(args.iter().map(|arg| OsString::from(*arg)))
    }

    fn parse_error(args: &[&str]) -> String {
        parse(args)
            .err()
            .expect("expected argument error")
            .to_string()
    }

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
    fn parses_short_config_argument() {
        let Command::Run(options) = parse(&["-c", "mini.toml"]).unwrap() else {
            panic!("expected run command");
        };

        assert_eq!(options.config, Some(PathBuf::from("mini.toml")));
    }

    #[test]
    fn requires_a_configuration_source() {
        let error = parse_error(&[]);
        assert!(error.contains("required"));
        assert!(error.contains("--config"));
    }

    #[test]
    fn rejects_missing_and_duplicate_config_arguments() {
        assert!(parse_error(&["--config"]).contains("requires a value"));
        assert!(
            parse_error(&["-c", "first.toml", "--config", "second.toml"])
                .contains("only be specified once")
        );
    }

    #[test]
    fn help_and_version_do_not_require_a_config() {
        for option in ["--help", "-h", "--version", "-V"] {
            assert!(matches!(parse(&[option]).unwrap(), Command::Exit));
        }
    }

    #[test]
    fn usage_matches_enabled_features() {
        assert_eq!(
            usage().contains("--config-server"),
            cfg!(feature = "web-client")
        );
        assert_eq!(usage().contains("--rpc-portal"), cfg!(feature = "rpc"));
    }

    #[cfg(feature = "web-client")]
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

    #[cfg(feature = "web-client")]
    #[test]
    fn accepts_local_and_web_config_together() {
        let Command::Run(options) = parse(&["-c", "mini.toml", "-w", "token"]).unwrap() else {
            panic!("expected run command");
        };

        assert_eq!(options.config, Some(PathBuf::from("mini.toml")));
        assert_eq!(options.config_server.as_deref(), Some("token"));
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn rejects_missing_and_duplicate_web_config_arguments() {
        assert!(parse_error(&["--config-server"]).contains("requires a value"));
        assert!(
            parse_error(&["-w", "first", "--config-server", "second"])
                .contains("only be specified once")
        );
    }

    #[cfg(not(feature = "web-client"))]
    #[test]
    fn disabled_web_options_explain_required_feature() {
        for option in [
            "--config-server",
            "-w",
            "--machine-id",
            "--hostname",
            "--secure-mode",
        ] {
            assert!(parse_error(&[option]).contains("--features web-client"));
        }
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn parses_custom_rpc_socket_address() {
        for portal in ["127.0.0.1:15889", "[::1]:15890"] {
            let Command::Run(options) =
                parse(&["-c", "mini.toml", "--rpc-portal", portal]).unwrap()
            else {
                panic!("expected run command");
            };

            assert_eq!(options.rpc_portal.as_deref(), Some(portal));
        }
    }

    #[cfg(feature = "rpc")]
    #[test]
    fn rejects_missing_invalid_and_duplicate_rpc_addresses() {
        assert!(parse_error(&["--rpc-portal"]).contains("requires a value"));
        assert!(
            parse_error(&["--rpc-portal", "localhost:15889"])
                .contains("must be an IP address and port")
        );
        assert!(
            parse_error(&[
                "-c",
                "mini.toml",
                "--rpc-portal",
                "127.0.0.1:15889",
                "--rpc-portal",
                "127.0.0.1:15890",
            ])
            .contains("only be specified once")
        );
    }

    #[cfg(not(feature = "rpc"))]
    #[test]
    fn disabled_rpc_option_explains_required_feature() {
        assert!(parse_error(&["--rpc-portal", "127.0.0.1:15889"]).contains("--features rpc"));
    }

    #[test]
    fn rejects_unknown_arguments() {
        let result = parse_args([OsString::from("extra")].into_iter());

        assert!(result.is_err());
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn accepts_tcp_udp_config_server() {
        assert!(validate_config_server("udp://127.0.0.1:22020/token").is_ok());
        assert!(validate_config_server("quic://127.0.0.1:22020/token").is_err());
    }

    #[test]
    fn relay_only_config_does_not_require_a_virtual_interface() {
        for config in ["listeners = []", "listeners = []\n[flags]\nno_tun = true"] {
            let config = TomlConfigLoader::new_from_str(config).unwrap();

            assert!(validate_local_config(&config).is_ok());
        }
    }

    #[test]
    fn static_virtual_addresses_require_tun() {
        for source in ["ipv4 = \"10.20.0.1/24\"", "ipv6 = \"fd00::1/64\""] {
            let config = TomlConfigLoader::new_from_str(source).unwrap();
            let result = validate_local_config(&config);

            assert_eq!(result.is_ok(), cfg!(feature = "tun"));
            if let Err(error) = result {
                assert!(error.to_string().contains("--features tun"));
            }
        }
    }

    #[test]
    fn userspace_virtual_ip_requires_smoltcp() {
        let config =
            TomlConfigLoader::new_from_str("ipv4 = \"10.20.0.1/24\"\n[flags]\nno_tun = true")
                .unwrap();
        let result = validate_local_config(&config);

        assert_eq!(result.is_ok(), cfg!(feature = "smoltcp"));
        if let Err(error) = result {
            assert!(error.to_string().contains("--features smoltcp"));
        }
    }

    #[test]
    fn explicit_userspace_stack_requires_smoltcp() {
        let config = TomlConfigLoader::new_from_str("[flags]\nuse_smoltcp = true").unwrap();

        assert_eq!(
            validate_local_config(&config).is_ok(),
            cfg!(feature = "smoltcp")
        );
    }

    #[cfg(not(feature = "dhcp"))]
    #[test]
    fn dynamic_virtual_ip_requires_dhcp() {
        let config = TomlConfigLoader::new_from_str("dhcp = true").unwrap();
        let error = validate_local_config(&config).unwrap_err().to_string();

        assert!(error.contains("--features dhcp"));
    }

    #[cfg(all(feature = "dhcp", feature = "tun"))]
    #[test]
    fn dynamic_virtual_ip_is_accepted_with_default_features() {
        let config = TomlConfigLoader::new_from_str("dhcp = true").unwrap();

        assert!(validate_local_config(&config).is_ok());
    }

    #[test]
    fn configuration_validation_preserves_secure_defaults() {
        let config = TomlConfigLoader::default();
        let before = config.get_flags();

        validate_local_config(&config).unwrap();

        assert_eq!(config.get_flags(), before);
        assert!(before.enable_encryption);
        assert_eq!(before.encryption_algorithm, "aes-gcm");
    }

    #[cfg(feature = "web-client")]
    #[tokio::test]
    async fn web_instance_validation_uses_the_same_feature_requirements() {
        let relay = TomlConfigLoader::new_from_str("listeners = []").unwrap();
        assert!(
            MiniWebClientHooks
                .pre_run_network_instance(&relay)
                .await
                .is_ok()
        );

        let userspace =
            TomlConfigLoader::new_from_str("ipv4 = \"10.20.0.1/24\"\n[flags]\nno_tun = true")
                .unwrap();
        assert_eq!(
            MiniWebClientHooks
                .pre_run_network_instance(&userspace)
                .await
                .is_ok(),
            cfg!(feature = "smoltcp")
        );
    }

    #[tokio::test]
    async fn compact_factory_accepts_unsupported_config_without_changing_it() {
        let config = TomlConfigLoader::new_from_str(
            r#"
listeners = ["quic://127.0.0.1:11010"]
proxy_network = [{ cidr = "10.20.0.0/16" }]

[flags]
encryption_algorithm = "chacha20"
data_compress_algo = "Zstd"
"#,
        )
        .unwrap();
        config.set_dhcp(cfg!(feature = "dhcp"));
        config.get_id();
        let authoritative_config = |config: &TomlConfigLoader| {
            (
                config.get_dhcp(),
                config.get_listener_uris(),
                config.get_proxy_cidrs(),
                config.get_flags(),
            )
        };
        let before = authoritative_config(&config);
        #[cfg(feature = "web-client")]
        let before_toml = config.dump();
        let manager =
            native_compact_instance_manager_with_runtime(tokio::runtime::Handle::current());

        let instance = manager.create(config.clone(), ()).unwrap();

        assert_eq!(instance.instance_id(), config.get_id());
        assert_eq!(authoritative_config(&config), before);
        #[cfg(feature = "web-client")]
        assert_eq!(instance.toml_config().unwrap().dump(), before_toml);
    }
}
