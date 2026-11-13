use super::get_config_server_listeners;

#[test]
fn tcp_and_udp_candidates_do_not_depend_on_default_routes() {
    for protocol in ["tcp", "udp"] {
        let listeners = get_config_server_listeners(protocol, 22020).unwrap();
        assert_eq!(listeners.len(), 2);
        assert_eq!(
            listeners[0].local_url().as_str(),
            format!("{protocol}://[::]:22020")
        );
        assert_eq!(
            listeners[1].local_url().as_str(),
            format!("{protocol}://0.0.0.0:22020")
        );
    }
}

#[test]
fn websocket_listener_remains_ipv4_only() {
    let listeners = get_config_server_listeners("ws", 22020).unwrap();
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].local_url().as_str(), "ws://0.0.0.0:22020/");
}

#[test]
fn invalid_protocol_is_rejected() {
    for protocol in ["invalid", "wss", "quic"] {
        assert!(get_config_server_listeners(protocol, 22020).is_err());
    }
}

#[tokio::test]
async fn ipv4_listeners_bind_even_when_ipv6_is_unavailable() {
    for protocol in ["tcp", "udp", "ws"] {
        let mut ipv4 = get_config_server_listeners(protocol, 0)
            .unwrap()
            .pop()
            .unwrap();
        // This also runs in an isolated IPv4-only network namespace without
        // default routes, so construction and binding must not probe the WAN.
        ipv4.listen().await.unwrap();
    }
}
