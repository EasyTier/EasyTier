use std::sync::Arc;

use http_req::request::{RedirectPolicy, Request};
use rand::seq::SliceRandom;

use crate::{
    VERSION,
    common::{error::Error, global_ctx::ArcGlobalCtx},
};

use super::{ConnectorResolver, ResolvedCandidate};

const HTTP_REFRESH_SECS: u64 = 300;

#[derive(Debug)]
pub struct HttpResolver {
    source_url: url::Url,
    global_ctx: ArcGlobalCtx,
}

impl HttpResolver {
    pub fn new(source_url: url::Url, global_ctx: ArcGlobalCtx) -> Self {
        Self {
            source_url,
            global_ctx,
        }
    }
}

#[async_trait::async_trait]
impl ConnectorResolver for HttpResolver {
    async fn resolve(&self) -> Result<Vec<ResolvedCandidate>, Error> {
        let candidates =
            fetch_http_candidates(self.source_url.as_str(), &self.global_ctx).await?;
        Ok(candidates)
    }

    fn refresh_interval_secs(&self) -> u64 {
        HTTP_REFRESH_SECS
    }

    fn source_url(&self) -> &url::Url {
        &self.source_url
    }
}

async fn fetch_http_candidates(
    url_str: &str,
    global_ctx: &ArcGlobalCtx,
) -> Result<Vec<ResolvedCandidate>, Error> {
    let _url = url::Url::parse(url_str)
        .map_err(|e| Error::InvalidUrl(format!("parse url failed: {}", e)))?;
    let original_scheme = _url.scheme().to_string();

    let body = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let body_clone = body.clone();
    let url_clone = url_str.to_string();
    let network_name = global_ctx.network.network_name.clone();
    let user_agent = format!("easytier/{}", VERSION);

    let res = tokio::task::spawn_blocking(move || {
        let uri = http_req::uri::Uri::try_from(url_clone.as_str())
            .map_err(|e| format!("parse uri failed: {}", e))?;
        let res = Request::new(&uri)
            .header("User-Agent", &user_agent)
            .header("X-Network-Name", &network_name)
            .redirect_policy(RedirectPolicy::Limit(0))
            .timeout(std::time::Duration::from_secs(20))
            .send(&mut *body_clone.lock().unwrap())
            .map_err(|e| format!("HTTP request failed: {}", e))?;
        Ok::<_, String>(res)
    })
    .await
    .map_err(|e| Error::InvalidUrl(format!("task join error: {}", e)))?
    .map_err(|e| Error::InvalidUrl(e))?;

    let body_bytes = body.lock().unwrap().clone();
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    if res.status_code().is_redirect() {
        let location = res
            .headers()
            .get("Location")
            .ok_or_else(|| Error::InvalidUrl("no redirect address found".to_string()))?;
        handle_redirect(&original_scheme, location, url_str)
    } else if res.status_code().is_success() {
        Ok(parse_body_candidates(&body_str))
    } else {
        Err(Error::InvalidUrl(format!(
            "HTTP request failed with status: {:?}, body: {}",
            res.status_code(),
            body_str
        )))
    }
}

fn handle_redirect(
    original_scheme: &str,
    location: &str,
    original_url_str: &str,
) -> Result<Vec<ResolvedCandidate>, Error> {
    let new_url = url::Url::parse(location)
        .map_err(|e| Error::InvalidUrl(format!("parse redirect url failed: {}", e)))?;

    let ns = new_url.scheme();
    if ns == "http" || ns == "https" {
        let query_urls: Vec<url::Url> = new_url
            .query_pairs()
            .filter_map(|(_, v)| url::Url::parse(&v).ok())
            .collect();
        if !query_urls.is_empty() {
            return Ok(query_urls
                .into_iter()
                .map(|u| ResolvedCandidate { url: u })
                .collect());
        }
        if let Some(stripped) = original_url_str
            .strip_prefix(format!("{}://", original_scheme).as_str())
            .and_then(|rest| url::Url::parse(rest).ok())
        {
            return Ok(vec![ResolvedCandidate { url: stripped }]);
        }
        return Err(Error::InvalidUrl(format!(
            "no valid connector url found in redirect: {}",
            new_url
        )));
    }
    Ok(vec![ResolvedCandidate { url: new_url }])
}

fn parse_body_candidates(body: &str) -> Vec<ResolvedCandidate> {
    let mut lines: Vec<&str> = body
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    lines.shuffle(&mut rand::thread_rng());

    lines
        .into_iter()
        .filter_map(|l| {
            let url = url::Url::parse(l).ok()?;
            Some(ResolvedCandidate { url })
        })
        .collect()
}
