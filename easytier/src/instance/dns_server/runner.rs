use cidr::Ipv4Inet;
use tokio_util::sync::CancellationToken;

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use easytier_core::instance::CorePacketPlane;

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};

use super::{client_instance::MagicDnsClientInstance, server_instance::MagicDnsServerInstance};

#[derive(PartialEq, Eq)]
enum MagicDnsState {
    Ready(String),
    Error(String),
}

struct MagicDnsEventReporter {
    global_ctx: ArcGlobalCtx,
    last_state: Option<MagicDnsState>,
}

impl MagicDnsEventReporter {
    fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            last_state: None,
        }
    }

    fn report(&mut self, state: MagicDnsState) {
        if self.last_state.as_ref() == Some(&state) {
            return;
        }

        let event = match &state {
            MagicDnsState::Ready(endpoint) => GlobalCtxEvent::MagicDnsReady(endpoint.clone()),
            MagicDnsState::Error(error) => GlobalCtxEvent::MagicDnsError(error.clone()),
        };
        self.global_ctx.issue_event(event);
        self.last_state = Some(state);
    }

    fn ready(&mut self, endpoint: &url::Url) {
        self.report(MagicDnsState::Ready(endpoint.to_string()));
    }

    fn error(&mut self, error: &anyhow::Error) {
        self.report(MagicDnsState::Error(format!("{error:#}")));
    }
}

pub struct DnsRunner {
    client: Option<MagicDnsClientInstance>,
    server: Option<MagicDnsServerInstance>,
    packet_plane: Arc<CorePacketPlane>,
    global_ctx: ArcGlobalCtx,
    tun_dev: Option<String>,
    tun_inet: Ipv4Inet,
    fake_ip: Ipv4Addr,
    event_reporter: MagicDnsEventReporter,
}

impl DnsRunner {
    pub(crate) fn new(
        packet_plane: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Self {
        let event_reporter = MagicDnsEventReporter::new(global_ctx.clone());
        Self {
            client: None,
            server: None,
            packet_plane,
            global_ctx,
            tun_dev,
            tun_inet,
            fake_ip,
            event_reporter,
        }
    }

    async fn clean_env(&mut self) {
        if let Some(server) = self.server.take() {
            server.clean_env().await;
        }
        self.client.take();
    }

    async fn run_once(&mut self) -> anyhow::Result<()> {
        // try server first
        let server_error = match MagicDnsServerInstance::new(
            self.packet_plane.clone(),
            self.global_ctx.clone(),
            self.tun_dev.clone(),
            self.tun_inet,
            self.fake_ip,
        )
        .await
        {
            Ok(Some(server)) => {
                tracing::info!(
                    endpoint = %server.endpoint(),
                    "DnsRunner::run_once: server started"
                );
                self.server = Some(server);
                None
            }
            Ok(None) => {
                tracing::debug!("DnsRunner::run_once: another Magic DNS server is active");
                None
            }
            Err(e) => {
                tracing::error!("DnsRunner::run_once: {:?}", e);
                Some(e)
            }
        };

        // every runner must run a client
        let client = MagicDnsClientInstance::new(self.packet_plane.clone())
            .await
            .map_err(|client_error| match server_error {
                Some(server_error) => server_error.context(format!(
                    "Magic DNS server startup failed and client fallback also failed: {client_error:#}"
                )),
                None => client_error.context("failed to connect to the Magic DNS server"),
            })?;
        self.event_reporter.ready(client.endpoint());
        self.client = Some(client);
        self.client.as_mut().unwrap().run_and_wait().await
    }

    pub async fn run(&mut self, canel_token: CancellationToken) {
        loop {
            tracing::info!("DnsRunner::run: start");
            tokio::select! {
                _ = canel_token.cancelled() => {
                    self.clean_env().await;
                    tracing::info!("DnsRunner::run: cancelled");
                    return;
                }

                ret = self.run_once() => {
                    self.clean_env().await;
                    if let Err(e) = ret {
                        self.event_reporter.error(&e);
                        tracing::error!("DnsRunner::run: {:?}", e);
                    } else {
                        tracing::info!("DnsRunner::run: unexpected exit, server may be down");
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::broadcast::error::TryRecvError;

    use crate::common::global_ctx::{GlobalCtxEvent, tests::get_mock_global_ctx};

    use super::MagicDnsEventReporter;

    #[test]
    fn event_reporter_deduplicates_unchanged_magic_dns_state() {
        let global_ctx = get_mock_global_ctx();
        let mut events = global_ctx.subscribe();
        let mut reporter = MagicDnsEventReporter::new(global_ctx);
        let error = anyhow::anyhow!("endpoint registry unavailable");

        reporter.error(&error);
        reporter.error(&error);
        assert_eq!(
            events.try_recv().unwrap(),
            GlobalCtxEvent::MagicDnsError("endpoint registry unavailable".to_string())
        );
        assert_eq!(events.try_recv(), Err(TryRecvError::Empty));

        let endpoint = "tcp://127.0.0.1:54321".parse().unwrap();
        reporter.ready(&endpoint);
        reporter.ready(&endpoint);
        assert_eq!(
            events.try_recv().unwrap(),
            GlobalCtxEvent::MagicDnsReady("tcp://127.0.0.1:54321".to_string())
        );
        assert_eq!(events.try_recv(), Err(TryRecvError::Empty));
    }
}
