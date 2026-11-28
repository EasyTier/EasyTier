use std::{num::NonZeroU32, time::Duration};

use anyhow::{Context as _, ensure};
use easytier_core::instance::CoreInstanceConfig;
use reqwest::{Client, StatusCode};
use tokio_util::sync::CancellationToken;
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
    .and_then(|config| config.validate_before_replacement())
    .map_err(|_| anyhow::anyhow!("invalid remote instance configuration"))
}

pub(super) struct RemoteConfig {
    url: Url,
    client: Client,
}

pub(super) struct RemoteDocument {
    body: String,
    pub(super) cfg: TomlConfigLoader,
}

impl RemoteDocument {
    fn reuse_generated_key(&self, next: &TomlConfigLoader, overrides: Option<&NetworkOptions>) {
        if self.cfg.source_has_private_key()
            || next.source_has_private_key()
            || overrides.is_some_and(|opts| {
                opts.credential.is_some()
                    || (opts.secure_mode == Some(true)
                        && opts
                            .local_private_key
                            .as_ref()
                            .is_some_and(|key| !key.is_empty()))
            })
            || self.cfg.get_network_identity() != next.get_network_identity()
        {
            return;
        }
        if let (Some(previous), Some(mut mode)) =
            (self.cfg.get_secure_mode(), next.get_secure_mode())
            && previous.enabled
            && mode.enabled
        {
            mode.local_private_key = previous.local_private_key;
            mode.local_public_key = previous.local_public_key;
            next.set_secure_mode(Some(mode));
        }
    }
}

// Keep a handle until the stop is complete: deletion removes the manager entry
// before it joins the stop task.
async fn remove_instance(manager: &NativeInstanceManager, id: Uuid) -> anyhow::Result<bool> {
    let instance = manager.instance(id);
    if let Err(error) = manager.delete_network_instances([id]).await {
        log::warn!(%id, %error, "Could not delete remote instance");
        if manager.instance(id).is_none()
            && let Some(instance) = instance
        {
            tokio::spawn(async move { instance.stop().await })
                .await
                .context("failed to finish remote instance cleanup")?;
        }
        return Ok(false);
    }
    Ok(true)
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
    ) -> anyhow::Result<(RemoteDocument, Option<&'a NetworkOptions>)> {
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
        Ok((RemoteDocument { body, cfg }, overrides))
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
        mut applied: RemoteDocument,
        overrides: Option<&NetworkOptions>,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<()> {
        let id = applied.cfg.get_id();
        let mut failed = None;
        let start = async |config| -> anyhow::Result<()> {
            let (_, started) =
                manager.spawn_network_instance(config, ConfigFileControl::STATIC_CONFIG)?;
            started.await?
        };
        loop {
            let candidate = async {
                tokio::time::sleep(Duration::from_secs(interval.get().into())).await;
                let body = self.fetch().await?;
                if failed.as_ref() == Some(&body) {
                    return Ok(None);
                }
                failed = None;
                if body == applied.body {
                    return Ok(None);
                }
                let cfg = parse(&body)?;
                ensure!(
                    cfg.configured_id().is_none_or(|new| new == id),
                    "remote instance_id changed"
                );
                cfg.set_id(id);
                prepare(&cfg, overrides)?;
                applied.reuse_generated_key(&cfg, overrides);
                let guard = manager.mutation_lock().lock_owned().await;
                anyhow::Ok(Some((RemoteDocument { body, cfg }, guard)))
            };
            let candidate = tokio::select! {
                biased;
                _ = shutdown.cancelled() => return Ok(()),
                candidate = candidate => candidate,
            };
            let (next, _mutation) = match candidate {
                Ok(Some(candidate)) => candidate,
                Ok(None) => continue,
                Err(error) => {
                    log::warn!(%error, "Remote config refresh failed; keeping current instance");
                    continue;
                }
            };

            // Keep manager.wait() from exiting between stop, start and possible rollback.
            let _daemon = manager.register_daemon();
            ensure!(
                manager.instance(id).is_some(),
                "remote instance no longer exists"
            );
            if remove_instance(manager, id).await? {
                if shutdown.is_cancelled() {
                    return Ok(());
                }
                if start(next.cfg.clone()).await.is_ok() {
                    applied = next;
                    log::info!(%id, "Applied remote config");
                    continue;
                }
                failed = Some(next.body);
                remove_instance(manager, id).await?;
                ensure!(
                    manager.instance(id).is_none(),
                    "failed remote instance still registered"
                );
            } else if manager.instance(id).is_some() {
                continue;
            }
            if !shutdown.is_cancelled() {
                start(applied.cfg.clone())
                    .await
                    .context("failed to restore previous remote configuration")?;
                log::warn!(%id, "Restored previous remote instance");
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

    const FIRST: &str = "hostname = 'first'\nlisteners = []\nstun_servers = []\nstun_servers_v6 = []\ntcp_stun_servers = []\n[flags]\nno_tun = true\ndisable_upnp = true\nenable_encryption = false";

    fn refresh_cli(listener: &TcpListener) -> Cli {
        let rpc = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let matches = cli_command()
            .try_get_matches_from([
                "easytier-core",
                "--rpc-portal",
                &rpc.local_addr().unwrap().to_string(),
                "--config-url",
                &format!("http://{}/node.toml", listener.local_addr().unwrap()),
                "--config-refresh-interval",
                "1",
            ])
            .unwrap();
        Cli::from_arg_matches(&matches).unwrap()
    }

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
                    "[flags]\nenable_encryption = false\nenable_udp_fec = true\nmtu = 1",
                )
                .await;
            };
            let (result, ()) = tokio::join!(validate_config(cli), serve);
            assert_eq!(result.is_ok(), valid, "{result:?}");
        }
    }

    #[test]
    fn refresh_preserves_only_generated_keys_on_the_same_network() {
        let body = "[secure_mode]\nenabled = true";
        let previous = RemoteDocument {
            body: body.into(),
            cfg: parse(body).unwrap(),
        };
        let public_key =
            |cfg: &TomlConfigLoader| cfg.get_secure_mode().unwrap().local_public_key.unwrap();
        let old_key = public_key(&previous.cfg);

        let edited = parse(&format!("{body}\n# comment")).unwrap();
        previous.reuse_generated_key(&edited, None);
        assert_eq!(public_key(&edited), old_key);

        let other = parse(&format!(
            "{body}\n[network_identity]\nnetwork_name = 'other'"
        ))
        .unwrap();
        previous.reuse_generated_key(&other, None);
        assert_ne!(public_key(&other), old_key);

        let mode = parse(body).unwrap().get_secure_mode().unwrap();
        let explicit = parse(&format!(
            "{body}\nlocal_private_key = '{}'",
            mode.local_private_key.unwrap()
        ))
        .unwrap();
        previous.reuse_generated_key(&explicit, None);
        assert_eq!(public_key(&explicit), mode.local_public_key.unwrap());
        let explicit = RemoteDocument {
            body: String::new(),
            cfg: explicit,
        };
        let fresh = parse(body).unwrap();
        explicit.reuse_generated_key(&fresh, None);
        assert_ne!(public_key(&explicit.cfg), public_key(&fresh));
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
    async fn removed_instance_is_stopped_even_if_the_manager_cannot_join_its_stop_task() {
        crate::utils::init_crypto_provider();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let manager = crate::instance::factory::native_instance_manager_with_runtime(
            runtime.handle().clone(),
        );
        let instance = manager.create(parse(FIRST).unwrap(), ()).unwrap();
        instance.start().await.unwrap();
        runtime.shutdown_background();
        assert!(
            !remove_instance(&manager, instance.instance_id())
                .await
                .unwrap()
        );
        assert!(manager.instance(instance.instance_id()).is_none());
        assert_eq!(
            instance.state(),
            easytier_core::instance::CoreInstanceState::Stopped
        );
    }

    #[tokio::test]
    async fn shutdown_during_refresh_waits_for_removed_instance() {
        use std::{future::Future, task::Poll};
        crate::utils::init_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cli = refresh_cli(&listener);
        let manager = Arc::new(crate::instance::factory::native_instance_manager());
        let stop = Arc::new(tokio::sync::Notify::new());
        let run = run_with_manager(cli, manager.clone(), Some(stop.clone()));
        tokio::pin!(run);
        let serve = async {
            respond(request(&listener).await, "200 OK", FIRST).await;
            let socket = request(&listener).await;
            let old = manager.instances().pop().unwrap();
            respond(socket, "200 OK", &format!("{FIRST}\n# update")).await;
            old
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            let old = tokio::select! {
                result = &mut run => panic!("unexpected exit: {result:?}"),
                old = serve => old,
            };
            // On this current-thread runtime the spawned stop cannot run inside
            // this poll. Deliver shutdown exactly after removal, before cleanup.
            std::future::poll_fn(|cx| {
                assert!(run.as_mut().poll(cx).is_pending());
                if manager.instance(old.instance_id()).is_none() {
                    stop.notify_one();
                    assert!(run.as_mut().poll(cx).is_pending());
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            run.await.unwrap();
            assert_eq!(
                old.state(),
                easytier_core::instance::CoreInstanceState::Stopped
            );
            assert!(manager.instances().is_empty());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn remote_refresh_keeps_good_instance_until_valid_change() {
        let first = format!("{FIRST}\n[secure_mode]\nenabled = true");
        let second = first.replace("first", "second");
        let invalid_forward = format!(
            "{second}\n[[port_forward]]\nproto = 'invalid'\nbind_addr = '127.0.0.1:0'\ndst_addr = '127.0.0.1:9'"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        #[cfg(any(feature = "socks5", not(feature = "smoltcp")))]
        let port_forward = format!(
            "{second}\n[[port_forward]]\nproto = 'tcp'\nbind_addr = '{}'\ndst_addr = '127.0.0.1:9'",
            listener.local_addr().unwrap()
        );
        let cli = refresh_cli(&listener);
        crate::utils::init_crypto_provider();
        let manager = Arc::new(crate::instance::factory::native_instance_manager());
        let stop = Arc::new(tokio::sync::Notify::new());
        let serve = async {
            let mut previous = None;
            let mut public_key = None;
            // Each request observes the result of the preceding response.
            for (status, body, before) in [
                ("200 OK", first.as_str(), None),
                ("200 OK", &first, Some(("first", true))),
                ("503 Service Unavailable", &second, Some(("first", true))),
                ("200 OK", "hostname = [", Some(("first", true))),
                ("200 OK", &invalid_forward, Some(("first", true))),
                #[cfg(not(feature = "smoltcp"))]
                ("200 OK", &port_forward, Some(("first", true))),
                ("200 OK", &second, Some(("first", true))),
                #[cfg(feature = "socks5")]
                ("200 OK", &port_forward, Some(("second", false))),
                #[cfg(feature = "socks5")]
                ("200 OK", &port_forward, Some(("second", false))),
                #[cfg(feature = "socks5")]
                ("200 OK", &second, Some(("second", true))),
                #[cfg(not(feature = "socks5"))]
                ("200 OK", &second, Some(("second", false))),
                ("200 OK", &first, Some(("second", true))),
                ("200 OK", &first, Some(("first", false))),
            ] {
                let socket = request(&listener).await;
                if let Some((hostname, unchanged)) = before {
                    let instances = manager.instances();
                    assert_eq!(instances.len(), 1);
                    let current = &instances[0];
                    assert!(current.is_ready());
                    if let Some(last) = previous.replace(current.clone()) {
                        assert_eq!(last.instance_id(), current.instance_id());
                        assert_eq!(Arc::ptr_eq(&last, current), unchanged);
                    }
                    let cfg = manager.config(current.instance_id()).unwrap();
                    let key = cfg.get_secure_mode().unwrap().local_public_key.unwrap();
                    if let Some(old_key) = public_key.replace(key.clone()) {
                        assert_eq!(old_key, key);
                    }
                    assert!(cfg.get_port_forwards().is_empty());
                    assert_eq!(cfg.get_hostname(), hostname);
                }
                respond(socket, status, body).await;
            }
            let socket = request(&listener).await;
            let (other, started) = manager
                .spawn_network_instance(parse(FIRST).unwrap(), ConfigFileControl::STATIC_CONFIG)
                .unwrap();
            started.await.unwrap().unwrap();
            manager.retain_network_instances(&[other]).await.unwrap();
            respond(socket, "200 OK", &second).await;
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
