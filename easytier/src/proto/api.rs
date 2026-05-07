pub mod config {
    include!(concat!(env!("OUT_DIR"), "/api.config.rs"));
    pub struct Patchable<T> {
        pub action: Option<ConfigPatchAction>,
        pub value: Option<T>,
    }

    impl From<PortForwardPatch> for Patchable<crate::common::config::PortForwardConfig> {
        fn from(patch: PortForwardPatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(patch.action).ok(),
                value: patch.cfg.map(Into::into),
            }
        }
    }

    impl From<RoutePatch> for Patchable<cidr::Ipv4Cidr> {
        fn from(value: RoutePatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: value.cidr.map(Into::into),
            }
        }
    }

    impl From<ExitNodePatch> for Patchable<std::net::IpAddr> {
        fn from(value: ExitNodePatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: value.node.map(Into::into),
            }
        }
    }

    impl From<StringPatch> for Patchable<String> {
        fn from(value: StringPatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: Some(value.value),
            }
        }
    }

    impl From<UrlPatch> for Patchable<url::Url> {
        fn from(value: UrlPatch) -> Self {
            Patchable {
                action: ConfigPatchAction::try_from(value.action).ok(),
                value: value.url.map(Into::into),
            }
        }
    }

    pub fn patch_vec<T>(v: &mut Vec<T>, patches: Vec<Patchable<T>>)
    where
        T: PartialEq,
    {
        for patch in patches {
            match patch.action {
                Some(ConfigPatchAction::Add) => {
                    if let Some(value) = patch.value {
                        v.push(value);
                    }
                }
                Some(ConfigPatchAction::Remove) => {
                    if let Some(value) = patch.value {
                        v.retain(|x| x != &value);
                    }
                }
                Some(ConfigPatchAction::Clear) => {
                    v.clear();
                }
                None => {}
            }
        }
    }
}

pub mod instance {
    include!(concat!(env!("OUT_DIR"), "/api.instance.rs"));

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

            if ret == 0 { None } else { Some(ret) }
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

            if ret == 0 { None } else { Some(ret) }
        }

        pub fn get_loss_rate(&self) -> Option<f64> {
            let p = self.peer.as_ref()?;
            let default_conn_id = p.default_conn_id.map(|id| id.to_string());
            let mut ret = None;
            for conn in p.conns.iter() {
                if default_conn_id == Some(conn.conn_id.to_string()) {
                    return Some(conn.loss_rate as f64);
                }

                ret.get_or_insert(conn.loss_rate as f64);
            }

            ret
        }

        pub fn get_conn_priority(&self) -> Option<u32> {
            let p = self.peer.as_ref()?;
            let default_conn_id = p.default_conn_id.map(|id| id.to_string());
            let mut ret = None;
            for conn in p.conns.iter() {
                if default_conn_id == Some(conn.conn_id.to_string()) {
                    return Some(conn.priority);
                }

                ret.get_or_insert(conn.priority);
            }

            ret
        }

        fn get_tunnel_proto_str(tunnel_info: &super::super::common::TunnelInfo) -> String {
            tunnel_info.display_tunnel_type()
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

            if ret.is_empty() { None } else { Some(ret) }
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
}

pub mod logger {
    include!(concat!(env!("OUT_DIR"), "/api.logger.rs"));
}

pub mod manage {
    include!(concat!(env!("OUT_DIR"), "/api.manage.rs"));
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use prost::Message;

    use super::instance::{PeerConnInfo, PeerInfo, PeerRoutePair};
    use super::manage::{
        ListNetworkInstanceRequest, ListNetworkInstanceResponse, WebClientService,
        WebClientServiceClient, WebClientServiceDescriptor, WebClientServiceMethodDescriptor,
    };
    use crate::proto::common::Uuid;
    use crate::proto::rpc_types::controller::BaseController;
    use crate::proto::rpc_types::descriptor::ServiceDescriptor;
    use crate::proto::rpc_types::error::Error;
    use crate::proto::rpc_types::handler::Handler;

    #[derive(Clone, Default)]
    struct WebClientServiceJsonCallHandler;

    #[async_trait::async_trait]
    impl Handler for WebClientServiceJsonCallHandler {
        type Descriptor = WebClientServiceDescriptor;
        type Controller = BaseController;

        async fn call(
            &self,
            _ctrl: Self::Controller,
            method: <Self::Descriptor as ServiceDescriptor>::Method,
            input: Bytes,
        ) -> crate::proto::rpc_types::error::Result<Bytes> {
            match method {
                WebClientServiceMethodDescriptor::ListNetworkInstance => {
                    let _req = ListNetworkInstanceRequest::decode(input.as_ref()).unwrap();
                    let resp = ListNetworkInstanceResponse {
                        inst_ids: vec![Uuid {
                            part1: 1,
                            part2: 2,
                            part3: 3,
                            part4: 4,
                        }],
                    };
                    Ok(Bytes::from(resp.encode_to_vec()))
                }
                _ => Err(Error::ExecutionError(anyhow::anyhow!(
                    "unsupported method in test handler"
                ))),
            }
        }
    }

    #[tokio::test]
    async fn web_client_service_call_json_method_supports_snake_and_proto_method_name() {
        let client = WebClientServiceClient::new(WebClientServiceJsonCallHandler);

        let snake_result = client
            .json_call_method(
                BaseController::default(),
                "list_network_instance",
                serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(
            snake_result["inst_ids"][0],
            serde_json::json!({
                "part1": 1,
                "part2": 2,
                "part3": 3,
                "part4": 4
            })
        );

        let proto_result = client
            .json_call_method(
                BaseController::default(),
                "ListNetworkInstance",
                serde_json::json!({}),
            )
            .await
            .unwrap();
        assert_eq!(proto_result["inst_ids"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn web_client_service_call_json_method_rejects_unknown_method() {
        let client = WebClientServiceClient::new(WebClientServiceJsonCallHandler);
        let ret = client
            .json_call_method(
                BaseController::default(),
                "not_exist_method",
                serde_json::json!({}),
            )
            .await;
        assert!(ret.is_err());
    }

    #[test]
    fn peer_route_pair_loss_rate_uses_default_conn() {
        let default_conn_id = uuid::Uuid::new_v4();
        let pair = PeerRoutePair {
            peer: Some(PeerInfo {
                default_conn_id: Some(default_conn_id.into()),
                conns: vec![
                    PeerConnInfo {
                        conn_id: uuid::Uuid::new_v4().to_string(),
                        loss_rate: 0.8,
                        ..Default::default()
                    },
                    PeerConnInfo {
                        conn_id: default_conn_id.to_string(),
                        loss_rate: 0.4,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(
            pair.get_loss_rate()
                .is_some_and(|loss_rate| (loss_rate - 0.4).abs() < 1e-6)
        );
    }

    #[test]
    fn peer_route_pair_loss_rate_falls_back_to_first_conn() {
        let pair = PeerRoutePair {
            peer: Some(PeerInfo {
                conns: vec![
                    PeerConnInfo {
                        conn_id: uuid::Uuid::new_v4().to_string(),
                        loss_rate: 0.0,
                        ..Default::default()
                    },
                    PeerConnInfo {
                        conn_id: uuid::Uuid::new_v4().to_string(),
                        loss_rate: 0.7,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(pair.get_loss_rate(), Some(0.0));
    }
}
