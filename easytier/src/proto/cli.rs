use url::Host;

include!(concat!(env!("OUT_DIR"), "/cli.rs"));

impl PeerRoutePair {
    pub fn get_latency_ms(&self) -> Option<f64> {
        let mut ret = u64::MAX;
        let p = self.peer.as_ref()?;
        let default_conn_id = p.default_conn_id.map(|id| id.to_string());
        for conn in p.conns.iter() {
            let Some(stats) = &conn.stats else {
                continue;
            };
            if default_conn_id == Some(conn.conn_id.to_string()) {
                return Some(f64::from(stats.latency_us as u32) / 1000.0);
            }
            ret = ret.min(stats.latency_us);
        }

        if ret == u64::MAX {
            None
        } else {
            Some(f64::from(ret as u32) / 1000.0)
        }
    }

    pub fn get_rx_bytes(&self) -> Option<u64> {
        let mut ret = 0;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(stats) = &conn.stats else {
                continue;
            };
            ret += stats.rx_bytes;
        }

        if ret == 0 {
            None
        } else {
            Some(ret)
        }
    }

    pub fn get_tx_bytes(&self) -> Option<u64> {
        let mut ret = 0;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(stats) = &conn.stats else {
                continue;
            };
            ret += stats.tx_bytes;
        }

        if ret == 0 {
            None
        } else {
            Some(ret)
        }
    }

    pub fn get_loss_rate(&self) -> Option<f64> {
        let mut ret = 0.0;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            ret += conn.loss_rate;
        }

        if ret == 0.0 {
            None
        } else {
            Some(ret as f64)
        }
    }

    fn is_tunnel_ipv6(tunnel_info: &super::common::TunnelInfo) -> bool {
        let Some(local_addr) = &tunnel_info.local_addr else {
            return false;
        };

        let u: url::Url = local_addr.clone().into();
        u.host()
            .map(|h| matches!(h, Host::Ipv6(_)))
            .unwrap_or(false)
    }

    fn get_tunnel_proto_str(tunnel_info: &super::common::TunnelInfo) -> String {
        if Self::is_tunnel_ipv6(tunnel_info) {
            format!("{}6", tunnel_info.tunnel_type)
        } else {
            tunnel_info.tunnel_type.clone()
        }
    }

    pub fn get_conn_protos(&self) -> Option<Vec<String>> {
        let mut ret = vec![];
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(tunnel_info) = &conn.tunnel else {
                continue;
            };
            // insert if not exists
            let tunnel_type = Self::get_tunnel_proto_str(tunnel_info);
            if !ret.contains(&tunnel_type) {
                ret.push(tunnel_type);
            }
        }

        if ret.is_empty() {
            None
        } else {
            Some(ret)
        }
    }

    pub fn get_udp_nat_type(&self) -> String {
        use crate::proto::common::NatType;
        let mut ret = NatType::Unknown;
        if let Some(r) = &self.route.clone().unwrap_or_default().stun_info {
            ret = NatType::try_from(r.udp_nat_type).unwrap();
        }
        format!("{:?}", ret)
    }
}

pub fn list_peer_route_pair(peers: Vec<PeerInfo>, routes: Vec<Route>) -> Vec<PeerRoutePair> {
    let mut pairs: Vec<PeerRoutePair> = vec![];

    for route in routes.iter() {
        let peer = peers.iter().find(|peer| peer.peer_id == route.peer_id);
        let pair = PeerRoutePair {
            route: Some(route.clone()),
            peer: peer.cloned(),
        };

        pairs.push(pair);
    }

    pairs.sort_by(|a, b| {
        let a_is_public_server = a
            .route
            .as_ref()
            .and_then(|r| r.feature_flag.as_ref())
            .is_some_and(|f| f.is_public_server);

        let b_is_public_server = b
            .route
            .as_ref()
            .and_then(|r| r.feature_flag.as_ref())
            .is_some_and(|f| f.is_public_server);

        if a_is_public_server != b_is_public_server {
            return if a_is_public_server {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }

        let a_ip = a
            .route
            .as_ref()
            .and_then(|r| r.ipv4_addr.as_ref())
            .and_then(|ipv4| ipv4.address.as_ref())
            .map_or(0, |addr| addr.addr);

        let b_ip = b
            .route
            .as_ref()
            .and_then(|r| r.ipv4_addr.as_ref())
            .and_then(|ipv4| ipv4.address.as_ref())
            .map_or(0, |addr| addr.addr);

        a_ip.cmp(&b_ip)
    });

    pairs
}
