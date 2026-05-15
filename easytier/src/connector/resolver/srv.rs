use dashmap::DashSet;
use rand::Rng;
use strum::VariantArray;

use crate::{
    common::dns::RESOLVER,
    common::error::Error,
    tunnel::IpScheme,
};

use super::{ConnectorResolver, ResolvedCandidate};

const SRV_REFRESH_SECS: u64 = 300;

fn weighted_choice(options: &[(url::Url, u64)]) -> Option<&url::Url> {
    let total_weight: u64 = options.iter().map(|(_, w)| *w).sum();
    let mut rng = rand::thread_rng();
    let rand_value = rng.gen_range(0..total_weight);
    let mut accumulated = 0u64;
    for (item, weight) in options {
        accumulated += *weight;
        if rand_value < accumulated {
            return Some(item);
        }
    }
    options.first().map(|(u, _)| u)
}

#[derive(Debug)]
pub struct SrvResolver {
    source_url: url::Url,
}

impl SrvResolver {
    pub fn new(source_url: url::Url) -> Self {
        Self { source_url }
    }
}

#[async_trait::async_trait]
impl ConnectorResolver for SrvResolver {
    async fn resolve(&self) -> Result<Vec<ResolvedCandidate>, Error> {
        let domain = self
            .source_url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("no host in SRV URL".to_string()))?;

        let srv_domains: Vec<(&IpScheme, String)> = IpScheme::iter()
            .map(|s| (s, format!("_easytier._{}.{}", s, domain)))
            .collect();

        let responses = Arc::new(DashSet::new());
        let tasks: Vec<_> = srv_domains
            .into_iter()
            .map(|(protocol, srv_domain)| {
                let responses = responses.clone();
                async move {
                    match RESOLVER.srv_lookup(&srv_domain).await {
                        Ok(lookup) => {
                            for record in lookup.iter() {
                                if record.port() == 0 {
                                    continue;
                                }
                                let url_str = format!(
                                    "{}://{}:{}",
                                    protocol,
                                    record.target().to_utf8(),
                                    record.port()
                                );
                                if let Ok(url) = url::Url::parse(&url_str) {
                                    responses.insert((url, record.priority() as u64));
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("SRV lookup failed for {}: {:?}", srv_domain, e);
                        }
                    }
                }
            })
            .collect();

        futures::future::join_all(tasks).await;

        let records: Vec<(url::Url, u64)> = responses.iter().map(|r| r.clone()).collect();

        if records.is_empty() {
            return Ok(vec![]);
        }

        let chosen = weighted_choice(&records)
            .ok_or_else(|| Error::InvalidUrl("SRV weighted choice failed".to_string()))?;

        Ok(vec![ResolvedCandidate { url: chosen.clone() }])
    }

    fn refresh_interval_secs(&self) -> u64 {
        SRV_REFRESH_SECS
    }

    fn source_url(&self) -> &url::Url {
        &self.source_url
    }
}
