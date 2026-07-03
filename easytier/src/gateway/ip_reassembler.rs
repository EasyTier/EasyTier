use std::{net::Ipv4Addr, time::Duration};

use easytier_core::proxy::ip_reassembler as core_ip_reassembler;
use easytier_core::proxy::ip_reassembler::{IpProtocol, SmolIpv4Packet};
use pnet::packet::{
    Packet as _,
    ip::IpNextHeaderProtocol,
    ipv4::{Ipv4Flags, Ipv4Packet},
};

use crate::common::{error::Error, error::Result};

#[derive(Debug)]
pub(crate) struct IpReassembler {
    inner: core_ip_reassembler::IpReassembler,
}

impl IpReassembler {
    pub fn new(timeout: Duration) -> Self {
        Self {
            inner: core_ip_reassembler::IpReassembler::new(timeout),
        }
    }

    pub fn is_packet_fragmented(packet: &Ipv4Packet) -> bool {
        packet.get_fragment_offset() != 0 || packet.get_flags() & Ipv4Flags::MoreFragments != 0
    }

    pub fn is_last_fragment(packet: &Ipv4Packet) -> bool {
        packet.get_flags() & Ipv4Flags::MoreFragments == 0
    }

    pub fn add_fragment(
        &self,
        _source: Ipv4Addr,
        _destination: Ipv4Addr,
        packet: &Ipv4Packet,
    ) -> Option<Vec<u8>> {
        let packet = SmolIpv4Packet::new_checked(packet.packet()).ok()?;
        self.inner.add_fragment(&packet)
    }

    pub fn remove_expired_packets(&self) {
        self.inner.remove_expired_packets();
    }
}

pub struct ComposeIpv4PacketArgs<'a> {
    pub buf: &'a mut [u8],
    pub src_v4: &'a Ipv4Addr,
    pub dst_v4: &'a Ipv4Addr,
    pub next_protocol: IpNextHeaderProtocol,
    pub payload_len: usize,
    pub payload_mtu: usize,
    pub ip_id: u16,
}

pub fn compose_ipv4_packet<F>(args: ComposeIpv4PacketArgs, mut cb: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    core_ip_reassembler::compose_ipv4_packet(
        core_ip_reassembler::ComposeIpv4PacketArgs {
            buf: args.buf,
            src_v4: args.src_v4,
            dst_v4: args.dst_v4,
            next_protocol: IpProtocol::from(args.next_protocol.0),
            payload_len: args.payload_len,
            payload_mtu: args.payload_mtu,
            ip_id: args.ip_id,
        },
        |buf| cb(buf).map_err(anyhow::Error::new),
    )
    .map_err(Error::from)
}
