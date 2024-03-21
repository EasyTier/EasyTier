use std::fmt::Debug;

use rkyv::{Archive, Deserialize, Serialize};
use tokio_util::bytes::Bytes;

use crate::common::{
    global_ctx::NetworkIdentity,
    rkyv_util::{decode_from_bytes, encode_to_bytes, vec_to_string},
    PeerId,
};

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;

#[derive(Archive, Deserialize, Serialize, PartialEq, Clone)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub struct UUID(uuid::Bytes);

// impl Debug for UUID
impl std::fmt::Debug for UUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let uuid = uuid::Uuid::from_bytes(self.0);
        write!(f, "{}", uuid)
    }
}

impl From<uuid::Uuid> for UUID {
    fn from(uuid: uuid::Uuid) -> Self {
        UUID(*uuid.as_bytes())
    }
}

impl From<UUID> for uuid::Uuid {
    fn from(uuid: UUID) -> Self {
        uuid::Uuid::from_bytes(uuid.0)
    }
}

impl ArchivedUUID {
    pub fn to_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.0)
    }
}

impl From<&ArchivedUUID> for UUID {
    fn from(uuid: &ArchivedUUID) -> Self {
        UUID(uuid.0)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct HandShake {
    pub magic: u32,
    pub my_peer_id: PeerId,
    pub version: u32,
    pub features: Vec<String>,
    pub network_identity: NetworkIdentity,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct RoutePacket {
    pub route_id: u8,
    pub body: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum CtrlPacketPayload {
    HandShake(HandShake),
    RoutePacket(RoutePacket),
    Ping(u32),
    Pong(u32),
    TaRpc(u32, u32, bool, Vec<u8>), // u32: service_id, u32: transact_id, bool: is_req, Vec<u8>: rpc body
}

impl CtrlPacketPayload {
    pub fn from_packet(p: &ArchivedPacket) -> CtrlPacketPayload {
        assert_ne!(p.packet_type, PacketType::Data);
        postcard::from_bytes(p.payload.as_bytes()).unwrap()
    }

    pub fn from_packet2(p: &Packet) -> CtrlPacketPayload {
        postcard::from_bytes(p.payload.as_bytes()).unwrap()
    }
}

#[repr(u8)]
#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub enum PacketType {
    Data = 1,
    HandShake = 2,
    RoutePacket = 3,
    Ping = 4,
    Pong = 5,
    TaRpc = 6,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
pub struct Packet {
    pub from_peer: PeerId,
    pub to_peer: PeerId,
    pub packet_type: PacketType,
    pub payload: String,
}

impl std::fmt::Debug for ArchivedPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Packet {{ from_peer: {}, to_peer: {}, packet_type: {:?}, payload: {:?} }}",
            self.from_peer,
            self.to_peer,
            self.packet_type,
            &self.payload.as_bytes()
        )
    }
}

impl Packet {
    pub fn decode(v: &[u8]) -> &ArchivedPacket {
        decode_from_bytes::<Packet>(v).unwrap()
    }

    pub fn new(
        from_peer: PeerId,
        to_peer: PeerId,
        packet_type: PacketType,
        payload: Vec<u8>,
    ) -> Self {
        Packet {
            from_peer,
            to_peer,
            packet_type,
            payload: vec_to_string(payload),
        }
    }
}

impl From<Packet> for Bytes {
    fn from(val: Packet) -> Self {
        encode_to_bytes::<_, 4096>(&val)
    }
}

impl Packet {
    pub fn new_handshake(from_peer: PeerId, network: &NetworkIdentity) -> Self {
        let handshake = CtrlPacketPayload::HandShake(HandShake {
            magic: MAGIC,
            my_peer_id: from_peer,
            version: VERSION,
            features: Vec::new(),
            network_identity: network.clone().into(),
        });
        Packet::new(
            from_peer.into(),
            0,
            PacketType::HandShake,
            postcard::to_allocvec(&handshake).unwrap(),
        )
    }

    pub fn new_data_packet(from_peer: PeerId, to_peer: PeerId, data: &[u8]) -> Self {
        Packet::new(from_peer, to_peer, PacketType::Data, data.to_vec())
    }

    pub fn new_route_packet(from_peer: PeerId, to_peer: PeerId, route_id: u8, data: &[u8]) -> Self {
        let route = CtrlPacketPayload::RoutePacket(RoutePacket {
            route_id,
            body: data.to_vec(),
        });
        Packet::new(
            from_peer,
            to_peer,
            PacketType::RoutePacket,
            postcard::to_allocvec(&route).unwrap(),
        )
    }

    pub fn new_ping_packet(from_peer: PeerId, to_peer: PeerId, seq: u32) -> Self {
        let ping = CtrlPacketPayload::Ping(seq);
        Packet::new(
            from_peer,
            to_peer,
            PacketType::Ping,
            postcard::to_allocvec(&ping).unwrap(),
        )
    }

    pub fn new_pong_packet(from_peer: PeerId, to_peer: PeerId, seq: u32) -> Self {
        let pong = CtrlPacketPayload::Pong(seq);
        Packet::new(
            from_peer,
            to_peer,
            PacketType::Pong,
            postcard::to_allocvec(&pong).unwrap(),
        )
    }

    pub fn new_tarpc_packet(
        from_peer: PeerId,
        to_peer: PeerId,
        service_id: u32,
        transact_id: u32,
        is_req: bool,
        body: Vec<u8>,
    ) -> Self {
        let ta_rpc = CtrlPacketPayload::TaRpc(service_id, transact_id, is_req, body);
        Packet::new(
            from_peer,
            to_peer,
            PacketType::TaRpc,
            postcard::to_allocvec(&ta_rpc).unwrap(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::common::new_peer_id;

    use super::*;

    #[tokio::test]
    async fn serialize() {
        let a = "abcde";
        let out = Packet::new_data_packet(new_peer_id(), new_peer_id(), a.as_bytes());
        // let out = T::new(a.as_bytes());
        let out_bytes: Bytes = out.into();
        println!("out str: {:?}", a.as_bytes());
        println!("out bytes: {:?}", out_bytes);

        let archived = Packet::decode(&out_bytes[..]);
        println!("in packet: {:?}", archived);
    }
}
