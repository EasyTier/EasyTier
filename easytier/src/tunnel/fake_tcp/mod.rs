mod packet;
mod stack;

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use pnet::{
    datalink::{DataLinkReceiver, DataLinkSender},
    packet::{
        arp::{Arp, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EthernetPacket, MutableEthernetPacket},
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        Packet,
    },
    util::MacAddr,
};

fn construct_arp_response(new_packet: &mut MutableEthernetPacket, fake_mac_addr: MacAddr) {
    use pnet::packet::MutablePacket;
    new_packet.set_destination(new_packet.get_source());
    new_packet.set_source(fake_mac_addr.clone());
    new_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Arp);

    let mut arp_req = MutableArpPacket::new(new_packet.payload_mut()).unwrap();

    let old_sender_hw_addr = arp_req.get_sender_hw_addr();
    let old_sender_proto_addr = arp_req.get_sender_proto_addr();
    let old_target_proto_addr = arp_req.get_target_proto_addr();

    arp_req.set_operation(ArpOperations::Reply);

    arp_req.set_target_hw_addr(old_sender_hw_addr);
    arp_req.set_target_proto_addr(old_sender_proto_addr);

    arp_req.set_sender_hw_addr(fake_mac_addr.clone());
    arp_req.set_sender_proto_addr(old_target_proto_addr);
}

struct PnetTun {
    tx: Arc<parking_lot::Mutex<Box<dyn DataLinkSender>>>,
    rx: Arc<parking_lot::Mutex<Box<dyn DataLinkReceiver>>>,
}

#[async_trait::async_trait]
impl stack::Tun for PnetTun {
    async fn send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        let mut tx = self.tx.lock();
        tx.send_to(&packet, None)
    }

    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error> {
        let mut rx = self.rx.lock();
        rx.recv(packet).await.map_err(|e| e.into())
    }

    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        let mut tx = self.tx.lock();
        tx.try_send(packet).map_err(|e| e.into())
    }
}

#[tokio::test]
async fn test_pnet() {
    extern crate pnet;

    use pnet::datalink::Channel::Ethernet;
    use pnet::datalink::{self, NetworkInterface};
    use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
    use pnet::packet::{MutablePacket, Packet};

    use std::env;

    fn client() {
        let interface_name = "eth0";
        let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(interface_names_match)
            .next()
            .unwrap();
    }

    // Invoke as echo <interface name>
    fn main() {
        let interface_name = "eth0";
        let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

        // Find the network interface with the provided name
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(interface_names_match)
            .next()
            .unwrap();

        let interfaces = datalink::interfaces();
        let lo = interfaces
            .into_iter()
            .filter(|iface| iface.name == "lo")
            .next()
            .unwrap();

        let fake_mac_addr = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        // Create a new channel, dealing with layer 2 packets
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        let (mut tx_lo, mut rx_lo) = match datalink::channel(&lo, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet).unwrap();

                    // Constructs a single packet, the same length as the one received,
                    // using the provided closure. This allows the packet to be constructed
                    // directly in the write buffer, without copying. If copying is not a
                    // problem, you could also use send_to.
                    //
                    // The packet is sent once the closure has finished executing.
                    // tx.build_and_send(1, packet.packet().len(), &mut |mut new_packet| {
                    let mut payload = Vec::from(packet.packet());
                    let mut new_packet = MutableEthernetPacket::new(&mut payload).unwrap();

                    // if new packet is arp packet, just return a fake arp response with a fake mac address
                    if packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Arp {
                        let arp_req = ArpPacket::new(packet.payload()).unwrap();
                        if arp_req.get_operation() == ArpOperations::Request {
                            let fake_mac_addr = fake_mac_addr.clone();
                            // Create a clone of the original packet
                            new_packet.clone_from(&packet);
                            construct_arp_response(&mut new_packet, fake_mac_addr);
                        }
                    } else if packet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4
                        && new_packet.get_destination() == fake_mac_addr
                    {
                        new_packet.clone_from(&packet);
                        // Switch the source and destination
                        new_packet.set_source(packet.get_destination());
                        new_packet.set_destination(packet.get_source());

                        let ipv4_packet = Ipv4Packet::new(packet.payload()).unwrap();
                        let orig_dest = ipv4_packet.get_destination();
                        let orig_src = ipv4_packet.get_source();
                        drop(ipv4_packet);

                        let mut new_packet =
                            MutableIpv4Packet::new(new_packet.payload_mut()).unwrap();
                        new_packet.set_source(orig_dest);
                        new_packet.set_destination(orig_src);
                    }

                    tx_lo.send_to(new_packet.packet(), Some(lo.clone()));

                    println!("{:?}", packet);
                    println!("{:?}", new_packet);
                    // });
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }
    }

    main();
}
