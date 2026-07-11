use std::collections::HashSet;

use rand::{Rng as _, seq::SliceRandom};
use url::Url;

use crate::socket::{
    SocketContext,
    dns::{DnsQuery, DnsRecordResolver, DnsSrvRecord},
};

fn choose_weighted<T>(options: &[(T, u64)]) -> Option<&T> {
    let total_weight = options.iter().map(|(_, weight)| *weight).sum();
    let mut rng = rand::thread_rng();
    let selected = rng.gen_range(0..total_weight);
    let mut accumulated = 0;

    for (item, weight) in options {
        accumulated += *weight;
        if selected < accumulated {
            return Some(item);
        }
    }
    None
}

pub async fn resolve_txt_endpoint(
    resolver: &dyn DnsRecordResolver,
    domain_name: &str,
    context: SocketContext,
) -> anyhow::Result<Url> {
    let txt_data = resolver
        .resolve_txt(DnsQuery::new(domain_name, context))
        .await?;
    let candidates = txt_data
        .split(' ')
        .filter_map(|candidate| Url::parse(candidate).ok())
        .collect::<Vec<_>>();
    candidates
        .choose(&mut rand::thread_rng())
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no valid URL found in TXT data {txt_data:?}; expected a space-separated URL list"
            )
        })
}

fn srv_record_url(protocol: &str, record: DnsSrvRecord) -> anyhow::Result<(Url, u64)> {
    if record.port == 0 {
        anyhow::bail!("SRV port must be non-zero");
    }
    let url = format!("{protocol}://{}:{}", record.target, record.port);
    // Preserve the existing EasyTier selection rule, which treats SRV priority
    // as the candidate weight.
    Ok((Url::parse(&url)?, u64::from(record.priority)))
}

fn deduplicate_srv_candidates(candidates: Vec<(Url, u64)>) -> Vec<(Url, u64)> {
    candidates
        .into_iter()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

pub async fn resolve_srv_endpoint(
    resolver: &dyn DnsRecordResolver,
    domain_name: &str,
    supported_protocols: &[String],
    context: SocketContext,
) -> anyhow::Result<Url> {
    let lookups = supported_protocols.iter().map(|protocol| {
        let protocol = protocol.clone();
        let query = DnsQuery::new(
            format!("_easytier._{protocol}.{domain_name}"),
            context.clone(),
        );
        async move { (protocol, resolver.resolve_srv(query).await) }
    });

    let mut candidates = Vec::new();
    for (protocol, result) in futures::future::join_all(lookups).await {
        let Ok(records) = result else {
            continue;
        };
        candidates.extend(
            records
                .into_iter()
                .filter_map(|record| srv_record_url(&protocol, record).ok()),
        );
    }
    if candidates.is_empty() {
        anyhow::bail!("no SRV endpoint found for {domain_name}");
    }
    let candidates = deduplicate_srv_candidates(candidates);

    choose_weighted(&candidates)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("failed to choose an SRV endpoint for {domain_name}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;

    use super::*;

    struct TestResolver {
        txt: String,
        srv: Vec<DnsSrvRecord>,
        queries: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsRecordResolver for TestResolver {
        async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
            self.queries.lock().unwrap().push(query.host);
            Ok(self.txt.clone())
        }

        async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
            self.queries.lock().unwrap().push(query.host);
            Ok(self.srv.clone())
        }
    }

    #[tokio::test]
    async fn txt_discovery_parses_easy_tier_url_candidates() {
        let resolver = TestResolver {
            txt: "invalid tcp://127.0.0.1:11010".to_owned(),
            srv: Vec::new(),
            queries: Mutex::new(Vec::new()),
        };

        let endpoint =
            resolve_txt_endpoint(&resolver, "discovery.example", SocketContext::default())
                .await
                .unwrap();

        assert_eq!(endpoint.as_str(), "tcp://127.0.0.1:11010");
        assert_eq!(*resolver.queries.lock().unwrap(), ["discovery.example"]);
    }

    #[tokio::test]
    async fn srv_discovery_builds_protocol_specific_endpoint() {
        let resolver = TestResolver {
            txt: String::new(),
            srv: vec![DnsSrvRecord {
                priority: 1,
                weight: 10,
                port: 11012,
                target: "peer.example.com.".to_owned(),
            }],
            queries: Mutex::new(Vec::new()),
        };

        let endpoint = resolve_srv_endpoint(
            &resolver,
            "discovery.example",
            &["quic".to_owned()],
            SocketContext::default(),
        )
        .await
        .unwrap();

        assert_eq!(endpoint.as_str(), "quic://peer.example.com.:11012");
        assert_eq!(
            *resolver.queries.lock().unwrap(),
            ["_easytier._quic.discovery.example"]
        );
    }

    #[test]
    fn srv_discovery_deduplicates_url_and_priority() {
        let endpoint: Url = "tcp://peer.example.com:11010".parse().unwrap();
        let candidates = deduplicate_srv_candidates(vec![
            (endpoint.clone(), 10),
            (endpoint.clone(), 10),
            (endpoint.clone(), 20),
        ]);

        assert_eq!(candidates.len(), 2);
        assert!(candidates.contains(&(endpoint.clone(), 10)));
        assert!(candidates.contains(&(endpoint, 20)));
    }
}
