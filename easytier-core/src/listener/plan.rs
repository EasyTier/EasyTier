use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    str::FromStr,
};

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::socket::{
    SocketContext,
    tcp::{TcpBindOptions, TcpListenOptions},
    udp::{UdpBindOptions, UdpSessionListenRequest},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerKind {
    Ring,
    TcpStream,
    UdpSession,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ListenerPlanSource {
    Ring,
    Configured,
    Ipv6Shadow { original: Url },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedListener {
    pub url: Url,
    pub kind: ListenerKind,
    pub must_succeed: bool,
    pub source: ListenerPlanSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListenerPlanFailure {
    pub url: Url,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ListenerPlan {
    pub listeners: Vec<PlannedListener>,
    pub failures: Vec<ListenerPlanFailure>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ListenerSchemeRegistry {
    schemes: BTreeMap<String, ListenerKind>,
    no_ipv6_shadow: BTreeSet<String>,
}

impl ListenerSchemeRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn support(mut self, scheme: impl Into<String>, kind: ListenerKind) -> Self {
        self.schemes.insert(normalize_scheme(scheme), kind);
        self
    }

    pub(crate) fn disable_ipv6_shadow(mut self, scheme: impl Into<String>) -> Self {
        self.no_ipv6_shadow.insert(normalize_scheme(scheme));
        self
    }

    pub(crate) fn classify(&self, url: &Url) -> Option<ListenerKind> {
        self.schemes.get(url.scheme()).copied()
    }

    fn allows_ipv6_shadow(&self, url: &Url) -> bool {
        !self.no_ipv6_shadow.contains(url.scheme())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListenerPlanRequest {
    pub self_id: uuid::Uuid,
    pub listeners: Vec<Url>,
    pub enable_ipv6: bool,
}

/// Normalized listener inputs owned and planned by one core instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerRuntimeConfig {
    pub urls: Vec<Url>,
    pub enable_ipv6: bool,
    pub socket_context: SocketContext,
}

impl ListenerRuntimeConfig {
    pub fn new(urls: Vec<Url>, enable_ipv6: bool, socket_context: SocketContext) -> Self {
        Self {
            urls,
            enable_ipv6,
            socket_context,
        }
    }

    pub(crate) fn request(&self, self_id: uuid::Uuid) -> ListenerPlanRequest {
        ListenerPlanRequest::new(self_id, self.urls.clone(), self.enable_ipv6)
    }
}

impl ListenerPlanRequest {
    pub(crate) fn new(self_id: uuid::Uuid, listeners: Vec<Url>, enable_ipv6: bool) -> Self {
        Self {
            self_id,
            listeners,
            enable_ipv6,
        }
    }
}

pub(crate) fn plan_listeners(
    request: ListenerPlanRequest,
    registry: &ListenerSchemeRegistry,
) -> ListenerPlan {
    let mut plan = ListenerPlan::default();
    plan.listeners.push(PlannedListener {
        url: ring_listener_url(request.self_id),
        kind: ListenerKind::Ring,
        must_succeed: true,
        source: ListenerPlanSource::Ring,
    });

    for url in request.listeners {
        let Some(kind) = registry.classify(&url) else {
            plan.failures.push(unsupported_listener(&url));
            continue;
        };

        plan.listeners.push(PlannedListener {
            url: url.clone(),
            kind,
            must_succeed: true,
            source: ListenerPlanSource::Configured,
        });

        if should_add_ipv6_shadow_listener(&url, request.enable_ipv6, registry) {
            match ipv6_shadow_listener(&url) {
                Ok(ipv6_url) => plan.listeners.push(PlannedListener {
                    url: ipv6_url,
                    kind,
                    must_succeed: false,
                    source: ListenerPlanSource::Ipv6Shadow { original: url },
                }),
                Err(message) => plan.failures.push(ListenerPlanFailure { url, message }),
            }
        }
    }

    plan
}

pub(crate) fn ring_listener_url(self_id: uuid::Uuid) -> Url {
    format!("ring://{self_id}")
        .parse()
        .expect("ring listener url should be valid")
}

pub(crate) fn listener_default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "tcp" | "udp" => Some(11010),
        "wg" => Some(11011),
        "quic" => Some(11012),
        "ws" => Some(80),
        "wss" => Some(443),
        "faketcp" => Some(11013),
        _ => None,
    }
}

pub(crate) fn listener_url_bind_device(url: &Url) -> Option<String> {
    url.path().strip_prefix('/').and_then(|path| {
        if path.is_empty() {
            None
        } else {
            Some(String::from_utf8(percent_decode_str(path).collect()).unwrap())
        }
    })
}

pub(crate) fn unresolved_udp_session_listen_request(
    url: &Url,
    context: SocketContext,
) -> UdpSessionListenRequest {
    UdpSessionListenRequest::new(
        UdpBindOptions::port_bound_listener("0.0.0.0:0".parse().unwrap())
            .with_local_addr(None)
            .with_context(context)
            .with_bind_device(listener_url_bind_device(url)),
    )
}

pub(crate) fn unresolved_tcp_listener_options(context: SocketContext) -> TcpListenOptions {
    TcpListenOptions::direct_connect("0.0.0.0:0".parse().unwrap())
        .with_bind(TcpBindOptions::default().with_context(context))
}

pub(crate) fn is_url_host_ipv6(url: &Url) -> bool {
    url.host_str().is_some_and(|h| h.contains(':'))
}

pub(crate) fn is_url_host_unspecified(url: &Url) -> bool {
    if let Ok(ip) = IpAddr::from_str(url.host_str().unwrap_or_default()) {
        ip.is_unspecified()
    } else {
        false
    }
}

fn should_add_ipv6_shadow_listener(
    url: &Url,
    enable_ipv6: bool,
    registry: &ListenerSchemeRegistry,
) -> bool {
    enable_ipv6
        && registry.allows_ipv6_shadow(url)
        && !is_url_host_ipv6(url)
        && is_url_host_unspecified(url)
}

fn ipv6_shadow_listener(url: &Url) -> Result<Url, String> {
    let mut ipv6_url = url.clone();
    ipv6_url
        .set_host(Some("[::]"))
        .map_err(|_| format!("failed to set ipv6 host for listener: {url}"))?;
    Ok(ipv6_url)
}

fn unsupported_listener(url: &Url) -> ListenerPlanFailure {
    ListenerPlanFailure {
        url: url.clone(),
        message: format!("failed to get listener by url: {url}, maybe not supported"),
    }
}

fn normalize_scheme(scheme: impl Into<String>) -> String {
    scheme.into().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ListenerSchemeRegistry {
        ListenerSchemeRegistry::new()
            .support("tcp", ListenerKind::TcpStream)
            .support("udp", ListenerKind::UdpSession)
            .support("quic", ListenerKind::External)
            .support("faketcp", ListenerKind::External)
            .disable_ipv6_shadow("quic")
            .disable_ipv6_shadow("faketcp")
    }

    #[test]
    fn listener_plan_adds_ring_and_configured_listener() {
        let self_id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let plan = plan_listeners(
            ListenerPlanRequest::new(
                self_id,
                vec!["udp://127.0.0.1:11010".parse().unwrap()],
                false,
            ),
            &registry(),
        );

        assert_eq!(plan.failures, Vec::new());
        assert_eq!(
            plan.listeners
                .iter()
                .map(|entry| (&entry.url, entry.kind, entry.must_succeed))
                .collect::<Vec<_>>(),
            vec![
                (
                    &"ring://00000000-0000-0000-0000-000000000001"
                        .parse()
                        .unwrap(),
                    ListenerKind::Ring,
                    true
                ),
                (
                    &"udp://127.0.0.1:11010".parse().unwrap(),
                    ListenerKind::UdpSession,
                    true
                ),
            ]
        );
    }

    #[test]
    fn listener_plan_adds_ipv6_shadow_for_unspecified_ip_listener() {
        let plan = plan_listeners(
            ListenerPlanRequest::new(
                uuid::Uuid::new_v4(),
                vec!["tcp://0.0.0.0:11010".parse().unwrap()],
                true,
            ),
            &registry(),
        );

        assert_eq!(plan.failures, Vec::new());
        assert_eq!(plan.listeners.len(), 3);
        assert_eq!(plan.listeners[2].url, "tcp://[::]:11010".parse().unwrap());
        assert!(!plan.listeners[2].must_succeed);
        assert!(matches!(
            plan.listeners[2].source,
            ListenerPlanSource::Ipv6Shadow { .. }
        ));
    }

    #[test]
    fn listener_plan_skips_ipv6_shadow_for_excluded_schemes() {
        for url in ["quic://0.0.0.0:11012", "faketcp://0.0.0.0:11013"] {
            let plan = plan_listeners(
                ListenerPlanRequest::new(uuid::Uuid::new_v4(), vec![url.parse().unwrap()], true),
                &registry(),
            );

            assert_eq!(plan.failures, Vec::new());
            assert_eq!(plan.listeners.len(), 2);
        }
    }

    #[test]
    fn listener_plan_reports_unsupported_scheme() {
        let url = "http://0.0.0.0:8080".parse().unwrap();
        let plan = plan_listeners(
            ListenerPlanRequest::new(uuid::Uuid::new_v4(), vec![url], true),
            &registry(),
        );

        assert_eq!(plan.listeners.len(), 1);
        assert_eq!(plan.failures.len(), 1);
        assert_eq!(
            plan.failures[0].message,
            "failed to get listener by url: http://0.0.0.0:8080/, maybe not supported"
        );
    }

    #[test]
    fn listener_url_bind_device_decodes_url_path() {
        let url = "udp://0.0.0.0:11010/eth%2Btest".parse().unwrap();

        assert_eq!(listener_url_bind_device(&url), Some("eth+test".to_owned()));
    }
}
