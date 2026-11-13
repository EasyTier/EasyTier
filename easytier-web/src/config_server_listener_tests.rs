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

#[test]
fn both_expands_to_tcp_and_udp_on_the_same_port() {
    let listeners = get_config_server_listeners("both", 22020).unwrap();
    let urls: Vec<_> = listeners
        .iter()
        .map(|listener| listener.local_url().to_string())
        .collect();
    assert_eq!(
        urls,
        vec![
            "udp://[::]:22020",
            "udp://0.0.0.0:22020",
            "tcp://[::]:22020",
            "tcp://0.0.0.0:22020"
        ]
    );
}

#[test]
fn both_rejects_independently_assigned_ephemeral_ports() {
    let error = get_config_server_listeners("both", 0).unwrap_err();
    assert!(error.to_string().contains("non-zero config server port"));
    // Preserve the existing ephemeral-port behavior for single protocols.
    for protocol in ["udp", "tcp", "ws"] {
        assert!(get_config_server_listeners(protocol, 0).is_ok());
    }
}

#[test]
fn cli_preserves_default_and_accepts_both() {
    use clap::Parser;
    assert_eq!(
        super::Cli::try_parse_from(["easytier-web"])
            .unwrap()
            .config_server_protocol,
        "udp"
    );
    for protocol in ["udp", "tcp", "ws", "both"] {
        assert_eq!(
            super::Cli::try_parse_from(["easytier-web", "--config-server-protocol", protocol])
                .unwrap()
                .config_server_protocol,
            protocol
        );
    }
    assert!(
        super::Cli::try_parse_from(["easytier-web", "--config-server-protocol", "invalid"])
            .is_err()
    );
}
