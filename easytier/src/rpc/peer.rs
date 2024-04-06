use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize, Default)]
pub struct GetIpListResponse {
    pub public_ipv4: String,
    pub interface_ipv4s: Vec<String>,
    pub public_ipv6: String,
    pub interface_ipv6s: Vec<String>,
    pub listeners: Vec<url::Url>,
}

impl GetIpListResponse {
    pub fn new() -> Self {
        GetIpListResponse {
            public_ipv4: "".to_string(),
            interface_ipv4s: vec![],
            public_ipv6: "".to_string(),
            interface_ipv6s: vec![],
            listeners: vec![],
        }
    }
}
