use std::{num::NonZeroU32, time::Duration};

use anyhow::{Context as _, ensure};
use easytier_core::instance::CoreInstanceConfig;
use reqwest::{Client, StatusCode};
use url::Url;
use uuid::Uuid;

use super::{
    ConfigFileControl, ConfigFileSource, ConfigLoader as _, NativeInstanceManager, NetworkOptions,
    TomlConfigLoader, load_toml_config_from_str_with_source, log,
};

pub(super) fn parse_url(input: &str) -> anyhow::Result<Url> {
    let url = Url::parse(input)?;
    ensure!(matches!(url.scheme(), "http" | "https"), "expected HTTP(S)");
    Ok(url)
}

fn parse(body: &str) -> anyhow::Result<TomlConfigLoader> {
    ensure!(!body.trim().is_empty(), "empty remote configuration");
    // TOML diagnostics may quote lines containing credentials.
    load_toml_config_from_str_with_source("remote config", body)
        .map_err(|_| anyhow::anyhow!("invalid remote TOML configuration"))
}

fn prepare(cfg: &TomlConfigLoader, overrides: Option<&NetworkOptions>) -> anyhow::Result<()> {
    if let Some(options) = overrides {
        options.merge_into(cfg)?;
    }
    CoreInstanceConfig::from_toml_with_host(
        cfg,
        &crate::instance::config::runtime_core_host_config(),
    )
    .map_err(|_| anyhow::anyhow!("invalid remote instance configuration"))?
    .validate_build_capabilities()
}

pub(super) struct RemoteConfig {
    url: Url,
    client: Client,
}

impl RemoteConfig {
    pub(super) fn new(url: Url) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .https_only(url.scheme() == "https")
            .referer(false)
            .build()?;
        Ok(Self { url, client })
    }

    pub(super) async fn load_initial<'a>(
        &self,
        options: &'a NetworkOptions,
        explicit_file_count: usize,
        dir_file_count: usize,
    ) -> anyhow::Result<(String, TomlConfigLoader, Option<&'a NetworkOptions>)> {
        let body = self.fetch().await?;
        let cfg = parse(&body)?;
        let overrides = options
            .can_merge(
                &cfg,
                ConfigFileSource::CliConfigFile,
                explicit_file_count,
                dir_file_count,
            )
            .then_some(options);
        prepare(&cfg, overrides)?;
        Ok((body, cfg, overrides))
    }

    async fn fetch(&self) -> anyhow::Result<String> {
        let mut response = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        ensure!(
            response.status() == StatusCode::OK,
            "config server returned {}",
            response.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            ensure!(
                body.len() + chunk.len() <= 1024 * 1024,
                "remote configuration exceeds 1 MiB"
            );
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).context("remote configuration is not UTF-8")
    }

    pub(super) async fn watch(
        self,
        manager: &NativeInstanceManager,
        interval: NonZeroU32,
        id: Uuid,
        mut applied: String,
        overrides: Option<&NetworkOptions>,
    ) -> anyhow::Result<()> {
        loop {
            tokio::time::sleep(Duration::from_secs(interval.get().into())).await;
            let candidate = async {
                let body = self.fetch().await?;
                if body == applied {
                    return Ok(None);
                }
                let cfg = parse(&body)?;
                ensure!(
                    cfg.configured_id().is_none_or(|new| new == id),
                    "remote instance_id changed"
                );
                cfg.set_id(id);
                prepare(&cfg, overrides)?;
                anyhow::Ok(Some((body, cfg)))
            }
            .await;
            let (body, cfg) = match candidate {
                Ok(Some(candidate)) => candidate,
                Ok(None) => continue,
                Err(error) => {
                    log::warn!(%error, "Remote config refresh failed; keeping current instance");
                    continue;
                }
            };

            let _mutation = manager.mutation_lock().lock_owned().await;
            // Keep manager.wait() from exiting between stop, start and possible rollback.
            let _daemon = manager.register_daemon();
            let previous = manager
                .config(id)
                .context("remote instance no longer exists")?;
            manager.delete_network_instances([id]).await?;
            let start = async |config| -> anyhow::Result<()> {
                let (_, started) =
                    manager.spawn_network_instance(config, ConfigFileControl::STATIC_CONFIG)?;
                started.await?
            };
            if start(cfg).await.is_err() {
                manager.delete_network_instances([id]).await?;
                start(previous)
                    .await
                    .context("failed to restore previous remote configuration")?;
                log::warn!(%id, "Remote config failed to start; restored previous instance");
            } else {
                log::info!(%id, "Applied remote config");
                applied = body;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::core::{Cli, cli_command, flags_from, run_with_manager, validate_config};
    use clap::FromArgMatches as _;
    use tokio::{
        io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
        net::{TcpListener, TcpStream},
    };

    async fn request(listener: &TcpListener) -> BufReader<TcpStream> {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut line = String::new();
        socket.read_line(&mut line).await.unwrap();
        assert_eq!(line, "GET /node.toml HTTP/1.1\r\n");
        loop {
            line.clear();
            assert!(socket.read_line(&mut line).await.unwrap() > 0);
            if line == "\r\n" {
                return socket;
            }
        }
    }

    async fn respond(mut socket: BufReader<TcpStream>, status: &str, body: &str) {
        socket
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn check_config_validates_remote_settings_after_cli_overrides() {
        crate::utils::init_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/node.toml", listener.local_addr().unwrap());
        for (extra, valid) in [(vec![], false), (vec!["--mtu", "1400"], true)] {
            let matches = cli_command()
                .try_get_matches_from(
                    ["easytier-core", "--check-config", "--config-url", &url]
                        .into_iter()
                        .chain(extra),
                )
                .unwrap();
            let mut cli = Cli::from_arg_matches(&matches).unwrap();
            cli.network_options.flags = flags_from(&matches).unwrap();
            let serve = async {
                respond(
                    request(&listener).await,
                    "200 OK",
                    "[flags]\nenable_udp_fec = true\nmtu = 1",
                )
                .await;
            };
            let (result, ()) = tokio::join!(validate_config(cli), serve);
            assert_eq!(result.is_ok(), valid, "{result:?}");
        }
    }

    #[test]
    fn refresh_requires_http_url_and_positive_interval() {
        for args in [
            vec!["--config-refresh-interval", "1"],
            vec!["--config-url", "file:///tmp/config.toml"],
            vec![
                "--config-url",
                "http://localhost/config",
                "--config-refresh-interval",
                "0",
            ],
        ] {
            assert!(
                cli_command()
                    .try_get_matches_from(std::iter::once("easytier-core").chain(args))
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn remote_refresh_keeps_good_instance_until_valid_change() {
        const FIRST: &str = "hostname = 'first'\nlisteners = []\nstun_servers = []\nstun_servers_v6 = []\ntcp_stun_servers = []\n[flags]\nno_tun = true\ndisable_upnp = true";
        let second = FIRST.replace("first", "second");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        #[cfg(any(feature = "socks5", not(feature = "smoltcp")))]
        let port_forward = format!(
            "{second}\n[[port_forward]]\nproto = 'tcp'\nbind_addr = '{}'\ndst_addr = '127.0.0.1:9'",
            listener.local_addr().unwrap()
        );
        let url = format!("http://{}/node.toml", listener.local_addr().unwrap());
        let args = [
            "easytier-core",
            "--config-url",
            &url,
            "--config-refresh-interval",
            "1",
        ];
        let cli =
            Cli::from_arg_matches(&cli_command().try_get_matches_from(args).unwrap()).unwrap();
        crate::utils::init_crypto_provider();
        let manager = Arc::new(crate::instance::factory::native_instance_manager());
        let stop = Arc::new(tokio::sync::Notify::new());
        let serve = async {
            let mut original = None;
            // Each request observes the result of the preceding response.
            for (status, body, before) in [
                ("200 OK", FIRST, None),
                ("200 OK", FIRST, Some(("first", true))),
                ("503 Service Unavailable", &second, Some(("first", true))),
                ("200 OK", "hostname = [", Some(("first", true))),
                #[cfg(not(feature = "smoltcp"))]
                ("200 OK", &port_forward, Some(("first", true))),
                ("200 OK", &second, Some(("first", true))),
                #[cfg(feature = "socks5")]
                ("200 OK", &port_forward, Some(("second", false))),
                ("200 OK", &second, Some(("second", false))),
            ] {
                let socket = request(&listener).await;
                if let Some((hostname, unchanged)) = before {
                    let instances = manager.instances();
                    assert_eq!(instances.len(), 1);
                    let current = &instances[0];
                    assert!(current.is_ready());
                    let first = original.get_or_insert_with(|| current.clone());
                    assert_eq!(first.instance_id(), current.instance_id());
                    assert_eq!(Arc::ptr_eq(first, current), unchanged);
                    assert!(
                        manager
                            .config(current.instance_id())
                            .unwrap()
                            .get_port_forwards()
                            .is_empty()
                    );
                    assert_eq!(
                        manager
                            .config(current.instance_id())
                            .unwrap()
                            .get_hostname(),
                        hostname
                    );
                }
                respond(socket, status, body).await;
            }
            let socket = request(&listener).await;
            let (other, started) = manager
                .spawn_network_instance(parse(FIRST).unwrap(), ConfigFileControl::STATIC_CONFIG)
                .unwrap();
            started.await.unwrap().unwrap();
            manager.retain_network_instances(&[other]).await.unwrap();
            respond(socket, "200 OK", FIRST).await;
            assert!(
                tokio::time::timeout(Duration::from_secs(2), listener.accept())
                    .await
                    .is_err(),
                "watcher continued polling after removal"
            );
            assert!(manager.instance(other).unwrap().is_ready());
        };
        let run = run_with_manager(cli, manager.clone(), Some(stop.clone()));
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::pin!(run);
            tokio::select! {
                result = &mut run => panic!("service stopped before shutdown: {result:?}"),
                () = serve => {}
            }
            stop.notify_one();
            run.await.unwrap();
        })
        .await
        .unwrap();
        manager.retain_network_instances(&[]).await.unwrap();
    }
}
