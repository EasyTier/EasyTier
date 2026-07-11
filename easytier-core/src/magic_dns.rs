use std::{collections::BTreeMap, net::Ipv4Addr, sync::Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRoute {
    pub hostname: String,
    pub ipv4_addr: Option<Ipv4Addr>,
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
    use super::*;

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
