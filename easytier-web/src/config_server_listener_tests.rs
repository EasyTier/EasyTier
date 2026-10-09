use super::get_dual_stack_listener;

#[tokio::test]
async fn tcp_and_udp_candidates_do_not_depend_on_default_routes() {
    for protocol in ["tcp", "udp"] {
        let (ipv6, ipv4) = get_dual_stack_listener(protocol, 22020).await.unwrap();
        assert_eq!(
            ipv6.unwrap().local_url().as_str(),
            format!("{protocol}://[::]:22020")
        );
        assert_eq!(
            ipv4.unwrap().local_url().as_str(),
            format!("{protocol}://0.0.0.0:22020")
        );
    }
}

#[tokio::test]
async fn websocket_listener_remains_ipv4_only() {
    let (ipv6, ipv4) = get_dual_stack_listener("ws", 22020).await.unwrap();
    assert!(ipv6.is_none());
    assert_eq!(ipv4.unwrap().local_url().as_str(), "ws://0.0.0.0:22020/");
}

#[tokio::test]
async fn invalid_protocol_is_rejected() {
    assert!(get_dual_stack_listener("invalid", 22020).await.is_err());
}

#[tokio::test]
async fn ipv4_listeners_bind_even_when_ipv6_is_unavailable() {
    for protocol in ["tcp", "udp", "ws"] {
        let (_, ipv4) = get_dual_stack_listener(protocol, 0).await.unwrap();
        // This also runs in an isolated IPv4-only network namespace without
        // default routes, so construction and binding must not probe the WAN.
        ipv4.unwrap().listen().await.unwrap();
    }
}
