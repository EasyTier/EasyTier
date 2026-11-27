//! Latest-known EasyTier version, used to flag outdated devices in the
//! console. The version never gates anything - it is display-only, so a
//! failing source degrades to "no comparison" instead of an error.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Where the latest version comes from.
#[derive(Debug, Clone)]
pub enum VersionSource {
    /// GitHub releases API: `github:<owner>/<repo>`.
    Github { repo: String },
    /// Custom endpoint returning `{"tag_name": "v2.x.y"}` (the GitHub
    /// response shape), for mirrors and self-hosted environments.
    Url(url::Url),
    /// Pinned version, e.g. `static:2.7.0`; never touches the network.
    Static(String),
}

impl Default for VersionSource {
    fn default() -> Self {
        Self::Github {
            repo: "EasyTier/EasyTier".to_owned(),
        }
    }
}

impl VersionSource {
    /// Parses `github:<owner>/<repo>`, `url:<endpoint>`, `static:<version>`.
    /// A bare `owner/repo` is accepted as GitHub shorthand.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let value = value.trim();
        if let Some(repo) = value.strip_prefix("github:") {
            return Ok(Self::Github {
                repo: repo.to_owned(),
            });
        }
        if let Some(pinned) = value.strip_prefix("static:") {
            return Ok(Self::Static(pinned.to_owned()));
        }
        if let Some(url) = value.strip_prefix("url:") {
            return Ok(Self::Url(url.parse()?));
        }
        if !value.contains(' ') && value.matches('/').count() == 1 && !value.contains("://") {
            // `owner/repo` shorthand for GitHub.
            return Ok(Self::Github {
                repo: value.to_owned(),
            });
        }
        anyhow::bail!(
            "invalid version source: {value:?} (expected github:<owner>/<repo>, url:<endpoint>, or static:<version>)"
        );
    }

    fn describe(&self) -> String {
        match self {
            Self::Github { repo } => format!("github:{repo}"),
            Self::Url(url) => format!("url:{url}"),
            Self::Static(version) => format!("static:{version}"),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct VersionState {
    /// Normalized (no `v` prefix, no build suffix) latest version.
    latest: Option<String>,
    /// Raw tag as reported by the source, e.g. `v2.7.0`.
    raw_tag: Option<String>,
}

/// Shared cache refreshed by [`LatestVersion::spawn_refresh`].
#[derive(Debug, Default)]
pub struct LatestVersion {
    source: VersionSource,
    state: RwLock<VersionState>,
}

impl LatestVersion {
    pub fn new(source: VersionSource) -> Arc<Self> {
        Arc::new(Self {
            source,
            state: RwLock::new(VersionState::default()),
        })
    }

    /// Refreshes the cache immediately and then every hour. A static source
    /// fills the cache once and skips the loop entirely.
    pub fn spawn_refresh(self: &Arc<Self>) {
        if let VersionSource::Static(pinned) = &self.source {
            let latest = normalize_version(pinned);
            let state = VersionState {
                latest: Some(latest.to_owned()),
                raw_tag: Some(pinned.clone()),
            };
            tokio::spawn({
                let this = self.clone();
                async move {
                    *this.state.write().await = state;
                }
            });
            return;
        }
        tokio::spawn({
            let this = self.clone();
            async move {
                loop {
                    match this.fetch_once().await {
                        Ok(tag) => {
                            let latest = normalize_version(&tag).to_owned();
                            *this.state.write().await = VersionState {
                                latest: Some(latest),
                                raw_tag: Some(tag),
                            };
                        }
                        Err(error) => {
                            // Keep the previous cache; devices simply stop
                            // being flagged until the source recovers.
                            tracing::warn!(%error, source = %this.source.describe(), "failed to fetch latest version");
                        }
                    }
                    tokio::time::sleep(REFRESH_INTERVAL).await;
                }
            }
        });
    }

    pub fn source(&self) -> &VersionSource {
        &self.source
    }

    pub async fn latest(&self) -> Option<String> {
        self.state.read().await.latest.clone()
    }

    pub async fn snapshot(&self) -> VersionSnapshot {
        let state = self.state.read().await;
        VersionSnapshot {
            latest: state.latest.clone(),
            raw_tag: state.raw_tag.clone(),
            source: self.source.describe(),
        }
    }

    async fn fetch_once(&self) -> anyhow::Result<String> {
        let endpoint = match &self.source {
            VersionSource::Github { repo } => {
                format!("https://api.github.com/repos/{repo}/releases/latest")
            }
            VersionSource::Url(url) => url.to_string(),
            VersionSource::Static(_) => unreachable!("static source skips the loop"),
        };
        let client = reqwest::Client::builder()
            .user_agent("easytier-web")
            .timeout(Duration::from_secs(15))
            .build()?;
        #[derive(serde::Deserialize)]
        struct ReleaseTag {
            tag_name: String,
        }
        let release: ReleaseTag = client
            .get(endpoint)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let tag = release.tag_name.trim().to_owned();
        anyhow::ensure!(!tag.is_empty(), "source returned an empty tag");
        Ok(tag)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VersionSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_tag: Option<String>,
    pub source: String,
}

/// `v2.7.0-8b7f1f01` → `2.7.0`; `2.7.0` stays `2.7.0`.
pub fn normalize_version(version: &str) -> &str {
    let trimmed = version.trim();
    let without_prefix = trimmed.strip_prefix('v').unwrap_or(trimmed);
    without_prefix
        .split(['-', '+'])
        .next()
        .unwrap_or(without_prefix)
}

/// True when `reported` is an older release than `latest`. Versions that do
/// not parse (empty, custom builds) are never flagged to avoid false alarms.
pub fn is_outdated(reported: &str, latest: &str) -> bool {
    match (parse_release(reported), parse_release(latest)) {
        (Some(reported), Some(latest)) => reported < latest,
        _ => false,
    }
}

fn parse_release(version: &str) -> Option<Vec<u64>> {
    let normalized = normalize_version(version);
    if normalized.is_empty() {
        return None;
    }
    normalized
        .split('.')
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_prefix_and_build_suffix() {
        assert_eq!(normalize_version("v2.7.0"), "2.7.0");
        assert_eq!(normalize_version("2.7.0-8b7f1f01"), "2.7.0");
        assert_eq!(normalize_version("2.7.0+meta"), "2.7.0");
        assert_eq!(normalize_version("2.7"), "2.7");
        assert_eq!(normalize_version(""), "");
    }

    #[test]
    fn outdated_compares_release_segments() {
        assert!(is_outdated("2.6.4", "v2.7.0"));
        assert!(is_outdated("v2.7", "2.7.0"));
        assert!(!is_outdated("2.7.0-8b7f1f01", "v2.7.0"));
        assert!(!is_outdated("2.7.1", "v2.7.0"));
        assert!(!is_outdated("2.8.0-nightly", "2.7.0"));
        // Unparseable or missing reports are never flagged.
        assert!(!is_outdated("", "v2.7.0"));
        assert!(!is_outdated("custom", "v2.7.0"));
        assert!(!is_outdated("2.7.0", ""));
        assert!(!is_outdated("dev", "unknown"));
    }

    #[test]
    fn sources_parse_supported_forms() {
        assert!(matches!(
            VersionSource::parse("github:EasyTier/EasyTier").unwrap(),
            VersionSource::Github { .. }
        ));
        assert!(matches!(
            VersionSource::parse("EasyTier/EasyTier").unwrap(),
            VersionSource::Github { .. }
        ));
        assert!(matches!(
            VersionSource::parse("static:2.7.0").unwrap(),
            VersionSource::Static(_)
        ));
        assert!(matches!(
            VersionSource::parse("url:https://mirror.example/api").unwrap(),
            VersionSource::Url(_)
        ));
        assert!(VersionSource::parse("not a source").is_err());
    }

    #[tokio::test]
    async fn static_source_fills_cache_without_network() {
        let latest = LatestVersion::new(VersionSource::parse("static:2.7.0").unwrap());
        latest.spawn_refresh();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let snapshot = latest.snapshot().await;
        assert_eq!(snapshot.latest.as_deref(), Some("2.7.0"));
        assert_eq!(snapshot.raw_tag.as_deref(), Some("2.7.0"));
        assert_eq!(snapshot.source, "static:2.7.0");
    }
}
