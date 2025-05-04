use anyhow::Context;
use hickory_proto::rr::LowerName;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{peers::peer_manager::PeerManager, proto::cli::Route};
use std::{ops::Deref, str::FromStr, sync::Arc, time::Duration};

use super::{
    config::{GeneralConfigBuilder, Record, RecordBuilder, RecordType, RunConfigBuilder},
    server::{build_authority, Server},
};

static DEFAULT_ET_DNS_ZONE: &str = "et.net.";

pub struct DnsRunner {
    et_zone: String,
    peer_mgr: Arc<PeerManager>,
    dns_server: Arc<Mutex<Server>>,
    tasks: Mutex<JoinSet<()>>,
}

impl DnsRunner {
    pub fn new(peer_mgr: Arc<PeerManager>, et_zone: Option<String>) -> Self {
        let et_zone = et_zone.unwrap_or_else(|| DEFAULT_ET_DNS_ZONE.to_string());

        let dns_config = RunConfigBuilder::default()
            .general(
                GeneralConfigBuilder::default()
                    .listen_udp("0.0.0.0:53")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let dns_server = Server::new(dns_config);

        Self {
            et_zone,
            peer_mgr,
            dns_server: Arc::new(Mutex::new(dns_server)),
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    async fn update_dns_records(
        dns_server: &Server,
        routes: &[Route],
        zone: &str,
    ) -> Result<(), anyhow::Error> {
        let mut records: Vec<Record> = vec![];
        for route in routes {
            if route.hostname.is_empty() {
                continue;
            }

            let Some(ipv4_addr) = route.ipv4_addr.unwrap_or_default().address else {
                continue;
            };

            let record = RecordBuilder::default()
                .rr_type(RecordType::A)
                .name(format!("{}.{}", route.hostname, zone))
                .value(ipv4_addr.to_string())
                .ttl(Duration::from_secs(1))
                .build()?;

            records.push(record);
        }

        let soa_record = RecordBuilder::default()
            .rr_type(RecordType::SOA)
            .name(zone.to_string())
            .value(format!(
                "ns.{} hostmaster.{} 2023101001 7200 3600 1209600 86400",
                zone, zone
            ))
            .ttl(Duration::from_secs(60))
            .build()?;
        records.push(soa_record);

        let authority = build_authority(zone, &records)?;

        dns_server
            .upsert(
                LowerName::from_str(zone)
                    .with_context(|| "Invalid zone name, expect fomat like \"et.net.\"")?,
                Arc::new(authority),
            )
            .await;

        tracing::trace!("Updated DNS records for zone {}: {:?}", zone, records);

        Ok(())
    }

    pub async fn run(&self) -> Result<(), anyhow::Error> {
        // Start the DNS server
        self.dns_server.lock().await.run().await?;

        // update with empty records, to generate the SOA record
        Self::update_dns_records(
            self.dns_server.lock().await.deref(),
            &vec![],
            self.et_zone.as_str(),
        )
        .await
        .context("Failed to update DNS records")?;

        let dns_server = self.dns_server.clone();
        let peer_mgr = self.peer_mgr.clone();
        let zone = self.et_zone.clone();
        self.tasks.lock().await.spawn(async move {
            let mut prev_last_update = peer_mgr.get_route_peer_info_last_update_time().await;
            loop {
                let last_update = peer_mgr.get_route_peer_info_last_update_time().await;
                if last_update == prev_last_update {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
                prev_last_update = last_update;
                let routes = peer_mgr.list_routes().await;
                let ret =
                    Self::update_dns_records(dns_server.lock().await.deref(), &routes, &zone).await;
                if let Err(e) = ret {
                    tracing::error!("Failed to update DNS records: {}", e);
                }
            }
        });

        Ok(())
    }
}
