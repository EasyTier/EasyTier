use crate::common::error::Error;
use rand::seq::SliceRandom;

use super::{ConnectorResolver, ResolvedCandidate};

const TXT_REFRESH_SECS: u64 = 300;

#[derive(Debug)]
pub struct TxtResolver {
    source_url: url::Url,
}

impl TxtResolver {
    pub fn new(source_url: url::Url) -> Self {
        Self { source_url }
    }
}

#[async_trait::async_trait]
impl ConnectorResolver for TxtResolver {
    async fn resolve(&self) -> Result<Vec<ResolvedCandidate>, Error> {
        let domain = self
            .source_url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl("no host in TXT URL".to_string()))?;

        let txt_data = crate::common::dns::resolve_txt_record(domain)
            .await
            .map_err(|e| Error::InvalidUrl(format!("TXT lookup failed: {:?}", e)))?;

        let mut urls: Vec<url::Url> = txt_data
            .split(" ")
            .filter_map(|s| url::Url::parse(s.trim()).ok())
            .collect();

        if urls.is_empty() {
            return Ok(vec![]);
        }

        urls.shuffle(&mut rand::thread_rng());

        Ok(urls.into_iter().map(|u| ResolvedCandidate { url: u }).collect())
    }

    fn refresh_interval_secs(&self) -> u64 {
        TXT_REFRESH_SECS
    }

    fn source_url(&self) -> &url::Url {
        &self.source_url
    }
}
