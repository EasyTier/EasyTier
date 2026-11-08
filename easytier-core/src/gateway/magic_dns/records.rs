use std::{collections::BTreeMap, net::Ipv4Addr, sync::Mutex, time::Duration};

use async_trait::async_trait;
use hickory_proto::rr::LowerName;
use quanta::Instant;

use crate::peers::peer_manager::PeerManagerCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRoute {
    pub hostname: String,
    pub ipv4_addr: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRouteSnapshot {
    pub revision: Instant,
    pub routes: Vec<MagicDnsRouteAdvertisement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRouteAdvertisement {
    pub hostname: String,
    pub ipv4_addr: Option<crate::proto::common::Ipv4Inet>,
}

#[async_trait]
pub trait MagicDnsRouteSource: Send + Sync {
    async fn snapshot(&self) -> MagicDnsRouteSnapshot;
    async fn revision(&self) -> Instant;
}

fn magic_dns_route_advertisement(
    route: crate::proto::core_peer::peer::Route,
) -> MagicDnsRouteAdvertisement {
    MagicDnsRouteAdvertisement {
        hostname: route.hostname,
        ipv4_addr: route.ipv4_addr,
    }
}

fn magic_dns_route_snapshot(
    revision: Instant,
    routes: Vec<crate::proto::core_peer::peer::Route>,
    local_identity: (String, Option<crate::proto::common::Ipv4Inet>),
) -> MagicDnsRouteSnapshot {
    let mut routes = routes
        .into_iter()
        .map(magic_dns_route_advertisement)
        .collect::<Vec<_>>();
    let (hostname, ipv4_addr) = local_identity;
    routes.push(MagicDnsRouteAdvertisement {
        hostname,
        ipv4_addr,
    });
    MagicDnsRouteSnapshot { revision, routes }
}

#[async_trait]
impl MagicDnsRouteSource for PeerManagerCore {
    async fn snapshot(&self) -> MagicDnsRouteSnapshot {
        let revision = self.get_route().get_peer_info_last_update_time().await;
        magic_dns_route_snapshot(
            revision,
            self.list_route_snapshots().await,
            self.dns_route_identity(),
        )
    }

    async fn revision(&self) -> Instant {
        self.get_route().get_peer_info_last_update_time().await
    }
}

#[async_trait]
pub trait MagicDnsRoutePublisher: Send {
    async fn handshake(&mut self) -> anyhow::Result<()>;
    async fn heartbeat(&mut self) -> anyhow::Result<()>;
    async fn publish(&mut self, snapshot: &MagicDnsRouteSnapshot) -> anyhow::Result<()>;
}

pub async fn run_magic_dns_route_publisher<S, P>(
    source: &S,
    publisher: &mut P,
    interval: Duration,
) -> anyhow::Result<()>
where
    S: MagicDnsRouteSource + ?Sized,
    P: MagicDnsRoutePublisher + ?Sized,
{
    publisher.handshake().await?;
    loop {
        publisher.heartbeat().await?;
        let snapshot = source.snapshot().await;
        publisher.publish(&snapshot).await?;
        crate::foundation::time::sleep(interval).await;
    }
}

/// One instance's contribution, owned by its long-lived publishing connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsClientRecord {
    pub source: Option<String>,
    pub zone: LowerName,
    pub routes: Vec<MagicDnsRoute>,
    pub configured: BTreeMap<LowerName, Vec<super::Zone>>,
}

#[derive(Debug, Clone, Default)]
pub struct MagicDnsRecordSnapshot {
    pub clients: BTreeMap<String, MagicDnsClientRecord>,
    pub zones: BTreeMap<LowerName, Vec<MagicDnsRoute>>,
}

impl MagicDnsRecordSnapshot {
    pub fn from_clients(clients: BTreeMap<String, MagicDnsClientRecord>) -> Self {
        let mut zones: BTreeMap<LowerName, Vec<MagicDnsRoute>> = BTreeMap::new();
        for client in clients.values() {
            zones
                .entry(client.zone.clone())
                .or_default()
                .extend(client.routes.clone());
        }
        Self { clients, zones }
    }

    pub fn configured_origins(&self) -> impl Iterator<Item = &LowerName> {
        self.clients
            .values()
            .flat_map(|client| client.configured.keys())
    }
}

#[derive(Debug, Default)]
pub struct MagicDnsRecordStore {
    clients: Mutex<BTreeMap<String, MagicDnsClientRecord>>,
}

impl MagicDnsRecordStore {
    /// Prepares a replacement without changing accepted state. The caller must
    /// serialize preparation and commit with its authority application lock.
    pub fn replacement(
        &self,
        instance_id: String,
        source: Option<String>,
        zone: LowerName,
        routes: Vec<MagicDnsRoute>,
        dns: crate::config::toml::DnsConfig,
    ) -> anyhow::Result<MagicDnsRecordSnapshot> {
        let instance_id = uuid::Uuid::parse_str(&instance_id)?.to_string();
        let mut clients = self.clients.lock().unwrap().clone();
        let previous = clients.get(&instance_id);
        if let Some(owner) = previous.and_then(|client| client.source.as_ref()) {
            anyhow::ensure!(
                Some(owner) == source.as_ref(),
                "DNS instance {instance_id} belongs to another active connection"
            );
        }
        if let Some(source) = source.as_ref() {
            anyhow::ensure!(
                !clients.iter().any(
                    |(id, client)| id != &instance_id && client.source.as_ref() == Some(source)
                ),
                "DNS connection already belongs to another instance"
            );
        }
        let configured = super::configured_zones(Some(&dns))?;
        clients.insert(
            instance_id,
            MagicDnsClientRecord {
                source,
                zone,
                routes,
                configured,
            },
        );
        Ok(MagicDnsRecordSnapshot::from_clients(clients))
    }

    pub fn without_source(&self, source: &str) -> MagicDnsRecordSnapshot {
        let mut clients = self.clients.lock().unwrap().clone();
        clients.retain(|_, client| client.source.as_deref() != Some(source));
        MagicDnsRecordSnapshot::from_clients(clients)
    }

    pub fn commit(&self, snapshot: MagicDnsRecordSnapshot) {
        *self.clients.lock().unwrap() = snapshot.clients;
    }

    pub fn snapshot(&self) -> MagicDnsRecordSnapshot {
        MagicDnsRecordSnapshot::from_clients(self.clients.lock().unwrap().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_advertisement_preserves_untrusted_prefix_without_parsing() {
        let ipv4_addr = crate::proto::common::Ipv4Inet {
            address: Some("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap().into()),
            network_length: 33,
        };

        let advertisement = magic_dns_route_advertisement(crate::proto::core_peer::peer::Route {
            hostname: "remote".to_owned(),
            ipv4_addr: Some(ipv4_addr),
            ..Default::default()
        });

        assert_eq!(advertisement.ipv4_addr, Some(ipv4_addr));
    }

    #[test]
    fn route_snapshot_appends_local_identity() {
        let ipv4_addr: crate::proto::common::Ipv4Inet =
            "10.20.0.91/16".parse::<cidr::Ipv4Inet>().unwrap().into();
        let snapshot = magic_dns_route_snapshot(
            Instant::now(),
            Vec::new(),
            ("portable-node".to_owned(), Some(ipv4_addr)),
        );

        assert_eq!(
            snapshot.routes,
            [MagicDnsRouteAdvertisement {
                hostname: "portable-node".to_owned(),
                ipv4_addr: Some(ipv4_addr),
            }]
        );
    }

    struct TestRouteSource {
        revision: Instant,
    }

    #[async_trait]
    impl MagicDnsRouteSource for TestRouteSource {
        async fn snapshot(&self) -> MagicDnsRouteSnapshot {
            MagicDnsRouteSnapshot {
                revision: self.revision,
                routes: vec![MagicDnsRouteAdvertisement {
                    hostname: "node-a".to_owned(),
                    ipv4_addr: Some("10.1.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                }],
            }
        }

        async fn revision(&self) -> Instant {
            self.revision
        }
    }

    struct TestRoutePublisher {
        heartbeat_calls: usize,
        fail_heartbeat_at: usize,
        handshake_calls: usize,
        snapshots: Vec<MagicDnsRouteSnapshot>,
    }

    #[async_trait]
    impl MagicDnsRoutePublisher for TestRoutePublisher {
        async fn handshake(&mut self) -> anyhow::Result<()> {
            self.handshake_calls += 1;
            Ok(())
        }

        async fn heartbeat(&mut self) -> anyhow::Result<()> {
            self.heartbeat_calls += 1;
            if self.heartbeat_calls == self.fail_heartbeat_at {
                anyhow::bail!("stop test publisher");
            }
            Ok(())
        }

        async fn publish(&mut self, snapshot: &MagicDnsRouteSnapshot) -> anyhow::Result<()> {
            self.snapshots.push(snapshot.clone());
            Ok(())
        }
    }

    fn test_publisher() -> TestRoutePublisher {
        TestRoutePublisher {
            heartbeat_calls: 0,
            fail_heartbeat_at: 3,
            handshake_calls: 0,
            snapshots: Vec::new(),
        }
    }

    #[tokio::test]
    async fn route_publisher_repeats_complete_unchanged_snapshot() {
        let source = TestRouteSource {
            revision: Instant::now(),
        };
        let mut publisher = test_publisher();

        let error =
            run_magic_dns_route_publisher(&source, &mut publisher, Duration::from_millis(1))
                .await
                .unwrap_err();

        assert!(error.to_string().contains("stop test publisher"));
        assert_eq!(publisher.handshake_calls, 1);
        assert_eq!(publisher.snapshots.len(), 2);
        assert_eq!(publisher.snapshots[0], publisher.snapshots[1]);
    }

    fn contribution(
        store: &MagicDnsRecordStore,
        id: &str,
        source: &str,
        dns: crate::config::toml::DnsConfig,
    ) -> anyhow::Result<MagicDnsRecordSnapshot> {
        store.replacement(
            id.to_owned(),
            Some(source.to_owned()),
            "et.net.".parse().unwrap(),
            vec![],
            dns,
        )
    }

    #[test]
    fn contribution_ownership_replacement_and_withdrawal() {
        let store = MagicDnsRecordStore::default();
        let id = uuid::Uuid::new_v4().to_string();
        let dns = crate::config::toml::DnsConfig {
            domain: Some("et.net.".to_owned()),
            zone: Some(vec![].into()),
        };
        store.commit(contribution(&store, &id, "client-a", dns.clone()).unwrap());
        assert_eq!(store.snapshot().clients.len(), 1);
        assert!(contribution(&store, &id, "client-b", dns.clone()).is_err());
        store.commit(contribution(&store, &id, "client-a", dns.clone()).unwrap());
        assert!(store.snapshot().clients[&id].configured.is_empty());
        store.commit(store.without_source("client-b"));
        assert_eq!(store.snapshot().clients.len(), 1);
        store.commit(store.without_source("client-a"));
        assert!(store.snapshot().clients.is_empty());
        assert!(contribution(&store, &id, "client-b", dns).is_ok());
    }
}
