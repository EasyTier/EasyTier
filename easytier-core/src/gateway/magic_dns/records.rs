use std::{collections::BTreeMap, net::Ipv4Addr, sync::Mutex, time::Duration};

use async_trait::async_trait;
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
    pub zone: String,
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
    local_identity: (String, Option<crate::proto::common::Ipv4Inet>, String),
) -> MagicDnsRouteSnapshot {
    let mut routes = routes
        .into_iter()
        .map(magic_dns_route_advertisement)
        .collect::<Vec<_>>();
    let (hostname, ipv4_addr, zone) = local_identity;
    routes.push(MagicDnsRouteAdvertisement {
        hostname,
        ipv4_addr,
    });
    MagicDnsRouteSnapshot {
        revision,
        routes,
        zone,
    }
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
    unchanged_interval: Duration,
) -> anyhow::Result<()>
where
    S: MagicDnsRouteSource + ?Sized,
    P: MagicDnsRoutePublisher + ?Sized,
{
    let mut published_revision = None;
    publisher.handshake().await?;
    loop {
        publisher.heartbeat().await?;

        let snapshot = source.snapshot().await;
        if published_revision == Some(snapshot.revision) {
            crate::foundation::time::sleep(unchanged_interval).await;
            continue;
        }

        publisher.publish(&snapshot).await?;
        if source.revision().await == snapshot.revision {
            published_revision = Some(snapshot.revision);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRecordSnapshot {
    pub zones: BTreeMap<String, Vec<MagicDnsRoute>>,
}

#[derive(Debug, Default)]
pub struct MagicDnsRecordStore {
    zones: Mutex<BTreeMap<String, BTreeMap<String, Vec<MagicDnsRoute>>>>,
}

impl MagicDnsRecordStore {
    /// Replaces one client's routes within a zone.
    ///
    /// Returns `true` when the update removed the final client from an
    /// existing zone. The host can use that signal to keep an empty zone
    /// authoritative.
    pub fn replace_client_routes(
        &self,
        zone: String,
        client: String,
        routes: Vec<MagicDnsRoute>,
    ) -> bool {
        let mut zones = self.zones.lock().unwrap();
        let Some(routes_by_client) = zones.get_mut(&zone) else {
            if !routes.is_empty() {
                zones.entry(zone).or_default().insert(client, routes);
            }
            return false;
        };

        routes_by_client.remove(&client);
        if !routes.is_empty() {
            routes_by_client.insert(client, routes);
        }
        if !routes_by_client.is_empty() {
            return false;
        }
        zones.remove(&zone);
        true
    }

    /// Removes a disconnected client from every zone and returns the zones
    /// that became empty.
    pub fn remove_client(&self, client: &str) -> Vec<String> {
        let mut zones = self.zones.lock().unwrap();
        let mut removed_zones = Vec::new();
        zones.retain(|zone, routes_by_client| {
            routes_by_client.remove(client);
            let retain = !routes_by_client.is_empty();
            if !retain {
                removed_zones.push(zone.clone());
            }
            retain
        });
        removed_zones
    }

    pub fn snapshot(&self) -> MagicDnsRecordSnapshot {
        let zones = self.zones.lock().unwrap();
        MagicDnsRecordSnapshot {
            zones: zones
                .iter()
                .map(|(zone, routes_by_client)| {
                    (
                        zone.clone(),
                        routes_by_client
                            .values()
                            .flat_map(|routes| routes.iter().cloned())
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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
            (
                "portable-node".to_owned(),
                Some(ipv4_addr),
                "et.net.".to_owned(),
            ),
        );

        assert_eq!(snapshot.zone, "et.net.");
        assert_eq!(
            snapshot.routes,
            [MagicDnsRouteAdvertisement {
                hostname: "portable-node".to_owned(),
                ipv4_addr: Some(ipv4_addr),
            }]
        );
    }

    struct TestRouteSource {
        revision: Mutex<Instant>,
    }

    #[async_trait]
    impl MagicDnsRouteSource for TestRouteSource {
        async fn snapshot(&self) -> MagicDnsRouteSnapshot {
            MagicDnsRouteSnapshot {
                revision: *self.revision.lock().unwrap(),
                routes: vec![MagicDnsRouteAdvertisement {
                    hostname: "node-a".to_owned(),
                    ipv4_addr: Some("10.1.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                }],
                zone: "et.net.".to_owned(),
            }
        }

        async fn revision(&self) -> Instant {
            *self.revision.lock().unwrap()
        }
    }

    struct TestRoutePublisher {
        source: Arc<TestRouteSource>,
        heartbeat_calls: usize,
        fail_heartbeat_at: usize,
        change_revision_on_first_publish: bool,
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
            if self.change_revision_on_first_publish && self.snapshots.len() == 1 {
                *self.source.revision.lock().unwrap() = snapshot.revision + Duration::from_secs(1);
            }
            Ok(())
        }
    }

    fn test_publisher(source: Arc<TestRouteSource>) -> TestRoutePublisher {
        TestRoutePublisher {
            source,
            heartbeat_calls: 0,
            fail_heartbeat_at: 3,
            change_revision_on_first_publish: false,
            handshake_calls: 0,
            snapshots: Vec::new(),
        }
    }

    #[tokio::test]
    async fn route_publisher_skips_unchanged_snapshot() {
        let source = Arc::new(TestRouteSource {
            revision: Mutex::new(Instant::now()),
        });
        let mut publisher = test_publisher(source.clone());

        let error = run_magic_dns_route_publisher(
            source.as_ref(),
            &mut publisher,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("stop test publisher"));
        assert_eq!(publisher.handshake_calls, 1);
        assert_eq!(publisher.snapshots.len(), 1);
    }

    #[tokio::test]
    async fn route_publisher_retries_change_during_publish() {
        let source = Arc::new(TestRouteSource {
            revision: Mutex::new(Instant::now()),
        });
        let mut publisher = test_publisher(source.clone());
        publisher.change_revision_on_first_publish = true;

        let error = run_magic_dns_route_publisher(
            source.as_ref(),
            &mut publisher,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("stop test publisher"));
        assert_eq!(publisher.snapshots.len(), 2);
        assert_ne!(
            publisher.snapshots[0].revision,
            publisher.snapshots[1].revision
        );
    }

    fn route(hostname: &str, addr: [u8; 4]) -> MagicDnsRoute {
        MagicDnsRoute {
            hostname: hostname.to_owned(),
            ipv4_addr: Some(addr.into()),
        }
    }

    #[test]
    fn replaces_routes_for_the_same_client_without_touching_other_clients() {
        let store = MagicDnsRecordStore::default();
        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            vec![route("old-a", [10, 0, 0, 1])],
        ));
        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        ));
        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            vec![route("new-a", [10, 0, 0, 3])],
        ));

        let routes = &store.snapshot().zones["et.net."];
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|route| route.hostname == "new-a"));
        assert!(routes.iter().any(|route| route.hostname == "peer-b"));
        assert!(!routes.iter().any(|route| route.hostname == "old-a"));
    }

    #[test]
    fn empty_update_removes_only_the_target_client_and_reports_empty_zone() {
        let store = MagicDnsRecordStore::default();
        store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            vec![route("peer-a", [10, 0, 0, 1])],
        );
        store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        );

        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            Vec::new(),
        ));
        assert!(store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            Vec::new(),
        ));
        assert!(store.snapshot().zones.is_empty());
    }

    #[test]
    fn disconnect_removes_client_from_all_zones() {
        let store = MagicDnsRecordStore::default();
        for zone in ["a.et.net.", "b.et.net."] {
            store.replace_client_routes(
                zone.to_owned(),
                "tcp://client-a".to_owned(),
                vec![route("peer-a", [10, 0, 0, 1])],
            );
        }
        store.replace_client_routes(
            "b.et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        );

        assert_eq!(
            store.remove_client("tcp://client-a"),
            vec!["a.et.net.".to_owned()]
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.zones.len(), 1);
        assert_eq!(snapshot.zones["b.et.net."][0].hostname, "peer-b");
    }
}
