pub mod dns;
pub mod http;
pub mod r#static;
pub mod txt;
pub mod srv;

use std::fmt::Debug;

use crate::common::error::Error;

#[derive(Debug, Clone)]
pub struct ResolvedCandidate {
    pub url: url::Url,
}

#[async_trait::async_trait]
pub trait ConnectorResolver: Debug + Send + Sync {
    async fn resolve(&self) -> Result<Vec<ResolvedCandidate>, Error>;
    fn refresh_interval_secs(&self) -> u64;
    fn source_url(&self) -> &url::Url;
}
