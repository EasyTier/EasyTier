use std::fmt::Debug;

use rkyv::{Archive, Deserialize, Serialize};
use tokio_util::bytes::Bytes;

use crate::common::{
    global_ctx::NetworkIdentity,
    rkyv_util::{decode_from_bytes, encode_to_bytes},
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

#[derive(Archive, Deserialize, Serialize)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
pub struct NetworkIdentityForPacket(Vec<u8>);

impl From<NetworkIdentity> for NetworkIdentityForPacket {
    fn from(network: NetworkIdentity) -> Self {
        Self(bincode::serialize(&network).unwrap())
    }
}

impl From<NetworkIdentityForPacket> for NetworkIdentity {
    fn from(network: NetworkIdentityForPacket) -> Self {
        bincode::deserialize(&network.0).unwrap()
    }
}

impl From<&ArchivedNetworkIdentityForPacket> for NetworkIdentity {
    fn from(network: &ArchivedNetworkIdentityForPacket) -> Self {
        NetworkIdentityForPacket(network.0.to_vec()).into()
    }
}

impl Debug for NetworkIdentityForPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let network: NetworkIdentity = bincode::deserialize(&self.0).unwrap();
        write!(f, "{:?}", network)
    }
}

impl Debug for ArchivedNetworkIdentityForPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let network: NetworkIdentity = bincode::deserialize(&self.0).unwrap();
        write!(f, "{:?}", network)
    }
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub struct HandShake {
    pub magic: u32,
    pub my_peer_id: UUID,
    pub version: u32,
    pub features: Vec<String>,
    pub network_identity: NetworkIdentityForPacket,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
#[archive_attr(derive(Debug))]
pub struct RoutePacket {
    pub route_id: u8,
    pub body: Vec<u8>,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub enum CtrlPacketBody {
    HandShake(HandShake),
    RoutePacket(RoutePacket),
    Ping(u32),
    Pong(u32),
    TaRpc(u32, bool, Vec<u8>), // u32: service_id, bool: is_req, Vec<u8>: rpc body
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub struct DataPacketBody {
    pub data: Vec<u8>,
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub enum PacketBody {
    Ctrl(CtrlPacketBody),
    Data(DataPacketBody),
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
#[archive_attr(derive(Debug))]
pub struct Packet {
    pub from_peer: UUID,
    pub to_peer: Option<UUID>,
    pub body: PacketBody,
}

impl Packet {
    pub fn decode(v: &[u8]) -> &ArchivedPacket {
        decode_from_bytes::<Packet>(v).unwrap()
    }
}

impl From<Packet> for Bytes {
    fn from(val: Packet) -> Self {
        encode_to_bytes::<_, 4096>(&val)
    }
}

impl Packet {
    pub fn new_handshake(from_peer: uuid::Uuid, network: &NetworkIdentity) -> Self {
        Packet {
            from_peer: from_peer.into(),
            to_peer: None,
            body: PacketBody::Ctrl(CtrlPacketBody::HandShake(HandShake {
                magic: MAGIC,
                my_peer_id: from_peer.into(),
                version: VERSION,
                features: Vec::new(),
                network_identity: network.clone().into(),
            })),
        }
    }

    pub fn new_data_packet(from_peer: uuid::Uuid, to_peer: uuid::Uuid, data: &[u8]) -> Self {
        Packet {
            from_peer: from_peer.into(),
            to_peer: Some(to_peer.into()),
            body: PacketBody::Data(DataPacketBody {
                data: data.to_vec(),
            }),
        }
    }

    pub fn new_route_packet(
        from_peer: uuid::Uuid,
        to_peer: uuid::Uuid,
        route_id: u8,
        data: &[u8],
    ) -> Self {
        Packet {
            from_peer: from_peer.into(),
            to_peer: Some(to_peer.into()),
            body: PacketBody::Ctrl(CtrlPacketBody::RoutePacket(RoutePacket {
                route_id,
                body: data.to_vec(),
            })),
        }
    }

    pub fn new_ping_packet(from_peer: uuid::Uuid, to_peer: uuid::Uuid, seq: u32) -> Self {
        Packet {
            from_peer: from_peer.into(),
            to_peer: Some(to_peer.into()),
            body: PacketBody::Ctrl(CtrlPacketBody::Ping(seq)),
        }
    }

    pub fn new_pong_packet(from_peer: uuid::Uuid, to_peer: uuid::Uuid, seq: u32) -> Self {
        Packet {
            from_peer: from_peer.into(),
            to_peer: Some(to_peer.into()),
            body: PacketBody::Ctrl(CtrlPacketBody::Pong(seq)),
        }
    }

    pub fn new_tarpc_packet(
        from_peer: uuid::Uuid,
        to_peer: uuid::Uuid,
        service_id: u32,
        is_req: bool,
        body: Vec<u8>,
    ) -> Self {
        Packet {
            from_peer: from_peer.into(),
            to_peer: Some(to_peer.into()),
            body: PacketBody::Ctrl(CtrlPacketBody::TaRpc(service_id, is_req, body)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serialize() {
        let a = "abcde";
        let out = Packet::new_data_packet(uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), a.as_bytes());
        // let out = T::new(a.as_bytes());
        let out_bytes: Bytes = out.into();
        println!("out str: {:?}", a.as_bytes());
        println!("out bytes: {:?}", out_bytes);

        let archived = Packet::decode(&out_bytes[..]);
        println!("in packet: {:?}", archived);
    }
}
