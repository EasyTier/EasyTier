use std::sync::Arc;

use crate::{
    connectivity::{
        hole_punch::tcp::{TcpHolePunchConnector, TcpHolePunchHost},
        protocol::{CoreServerProtocolConfig, CoreServerProtocolUpgrader},
    },
    listener::transport::HostAcceptedTcpSocket,
    peers::peer_manager::PeerManagerCore,
};

use super::TcpHolePunchRuntimeInputs;

pub(in crate::instance) struct TcpHolePunchRuntime<H>
where
    H: TcpHolePunchHost,
{
    connector: TcpHolePunchConnector<H, PeerManagerCore>,
}

impl<H> TcpHolePunchRuntime<H>
where
    H: TcpHolePunchHost,
{
    pub(in crate::instance) fn new(inputs: TcpHolePunchRuntimeInputs<H>) -> Self {
        let TcpHolePunchRuntimeInputs {
            peer_manager,
            host,
            stun,
            socket_context,
            client_protocol,
        } = inputs;
        Self {
            connector: TcpHolePunchConnector::new(
                peer_manager,
                host,
                stun,
                socket_context,
                client_protocol,
                Arc::new(CoreServerProtocolUpgrader::<HostAcceptedTcpSocket<H>>::new(
                    CoreServerProtocolConfig::default(),
                )),
            ),
        }
    }

    pub(in crate::instance) fn run(&self) {
        self.connector.run();
    }

    pub(in crate::instance) async fn stop(&self) {
        self.connector.stop().await;
    }
}
