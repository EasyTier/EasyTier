use super::{ConnectorResolver, ResolvedCandidate};
use crate::common::error::Error;

#[derive(Debug)]
pub struct StaticResolver {
    source_url: url::Url,
}

impl StaticResolver {
    pub fn new(source_url: url::Url) -> Self {
        Self { source_url }
    }
}

#[async_trait::async_trait]
impl ConnectorResolver for StaticResolver {
    async fn resolve(&self) -> Result<Vec<ResolvedCandidate>, Error> {
        Ok(vec![ResolvedCandidate {
            url: self.source_url.clone(),
        }])
    }

    fn refresh_interval_secs(&self) -> u64 {
        u64::MAX
    }

    fn source_url(&self) -> &url::Url {
        &self.source_url
    }
}
