//! Tunnel module tests
//!
//! This module contains comprehensive tests for QUIC and WebSocket tunnels,
//! including pingpong, data transfer, and protocol tests.

use crate::tunnel::{
    common::tests::_tunnel_pingpong,
    TunnelConnector, TunnelListener,
};

// ==================== QUIC Tunnel Tests ====================

#[cfg(feature = "quic")]
mod quic_tests {
    use super::*;
    use crate::tunnel::quic::{QUICTunnelConnector, QUICTunnelListener};

    #[tokio::test]
    async fn quic_pingpong() {
        let listener = QUICTunnelListener::new("quic://0.0.0.0:31011".parse().unwrap());
        let connector = QUICTunnelConnector::new("quic://127.0.0.1:31011".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn quic_pingpong_v2() {
        let listener = QUICTunnelListener::new("quic://0.0.0.0:31017".parse().unwrap());
        let connector = QUICTunnelConnector::new("quic://127.0.0.1:31017".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn quic_alloc_port() {
        // Test v4 port allocation
        let mut listener = QUICTunnelListener::new("quic://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // Test v6 port allocation
        let mut listener = QUICTunnelListener::new("quic://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}

// ==================== WebSocket Tunnel Tests ====================

#[cfg(feature = "websocket")]
mod websocket_tests {
    use super::*;
    use crate::tunnel::websocket::{WSTunnelConnector, WSTunnelListener};

    #[tokio::test]
    #[serial_test::serial]
    async fn ws_pingpong() {
        let listener = WSTunnelListener::new("ws://0.0.0.0:35556".parse().unwrap());
        let connector = WSTunnelConnector::new("ws://127.0.0.1:35556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn wss_pingpong() {
        let listener = WSTunnelListener::new("wss://0.0.0.0:35557".parse().unwrap());
        let connector = WSTunnelConnector::new("wss://127.0.0.1:35557".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ws_pingpong_v2() {
        let listener = WSTunnelListener::new("ws://0.0.0.0:35565".parse().unwrap());
        let connector = WSTunnelConnector::new("ws://127.0.0.1:35565".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn wss_pingpong_v2() {
        let listener = WSTunnelListener::new("wss://0.0.0.0:35566".parse().unwrap());
        let connector = WSTunnelConnector::new("wss://127.0.0.1:35566".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ws_accept_wss_fails() {
        let mut listener = WSTunnelListener::new("wss://0.0.0.0:35558".parse().unwrap());
        listener.listen().await.unwrap();

        let j = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // ws client should fail to connect to wss server
        let mut connector = WSTunnelConnector::new("ws://127.0.0.1:35558".parse().unwrap());
        connector.connect().await.unwrap_err();

        // wss client should succeed
        let mut connector = WSTunnelConnector::new("wss://127.0.0.1:35558".parse().unwrap());
        connector.connect().await.unwrap();

        j.abort();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ws_pingpong_with_bind() {
        let listener = WSTunnelListener::new("ws://0.0.0.0:35562".parse().unwrap());
        let mut connector = WSTunnelConnector::new("ws://127.0.0.1:35562".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }
}
