use serde::{Deserialize, Serialize};

use crate::rpc::cli::{NatType, PeerInfo, Route};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRoutePair {
    pub route: Route,
    pub peer: Option<PeerInfo>,
}

impl PeerRoutePair {
    pub fn get_latency_ms(&self) -> Option<f64> {
        let mut ret = u64::MAX;
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(stats) = &conn.stats else {
                continue;
            };
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

    pub fn get_conn_protos(&self) -> Option<Vec<String>> {
        let mut ret = vec![];
        let p = self.peer.as_ref()?;
        for conn in p.conns.iter() {
            let Some(tunnel_info) = &conn.tunnel else {
                continue;
            };
            // insert if not exists
            if !ret.contains(&tunnel_info.tunnel_type) {
                ret.push(tunnel_info.tunnel_type.clone());
            }
        }

        if ret.is_empty() {
            None
        } else {
            Some(ret)
        }
    }

    pub fn get_udp_nat_type(self: &Self) -> String {
        let mut ret = NatType::Unknown;
        if let Some(r) = &self.route.stun_info {
            ret = NatType::try_from(r.udp_nat_type).unwrap();
        }
        format!("{:?}", ret)
    }
}

pub fn list_peer_route_pair(peers: Vec<PeerInfo>, routes: Vec<Route>) -> Vec<PeerRoutePair> {
    let mut pairs: Vec<PeerRoutePair> = vec![];

    for route in routes.iter() {
        let peer = peers.iter().find(|peer| peer.peer_id == route.peer_id);
        pairs.push(PeerRoutePair {
            route: route.clone(),
            peer: peer.cloned(),
        });
    }

    pairs
}

pub fn cost_to_str(cost: i32) -> String {
    if cost == 1 {
        "p2p".to_string()
    } else {
        format!("relay({})", cost)
    }
}

pub fn float_to_str(f: f64, precision: usize) -> String {
    format!("{:.1$}", f, precision)
}
