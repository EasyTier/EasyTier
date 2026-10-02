use virtio_bindings::virtio_net::{
    VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_ECN, VIRTIO_NET_HDR_GSO_NONE,
    VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6, VIRTIO_NET_HDR_GSO_UDP_L4,
};
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[repr(C)]
#[derive(FromBytes, AsBytes, FromZeroes, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

pub const VNET_HDR_LEN: usize = std::mem::size_of::<VirtioNetHdr>();
pub const VNET_HDR_F_NEEDS_CSUM: u8 = VIRTIO_NET_HDR_F_NEEDS_CSUM as _;
pub const VNET_HDR_GSO_NONE: u8 = VIRTIO_NET_HDR_GSO_NONE as _;
pub const VNET_HDR_GSO_ECN: u8 = VIRTIO_NET_HDR_GSO_ECN as _;
pub const VNET_HDR_GSO_TCPV4: u8 = VIRTIO_NET_HDR_GSO_TCPV4 as _;
pub const VNET_HDR_GSO_TCPV6: u8 = VIRTIO_NET_HDR_GSO_TCPV6 as _;
pub const VNET_HDR_GSO_UDP_L4: u8 = VIRTIO_NET_HDR_GSO_UDP_L4 as _;
