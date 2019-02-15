extern crate pnet;

use std::str::FromStr;
use std::net::{Ipv4Addr};

use pnet::packet::MutablePacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::util;

const IPV4_HEADER_LENGTH: u8 = 5;
const ICMPV4_HEADER_LENGTH: u8 = 2;

fn main() {
	let ipAddress: Ipv4Addr = match Ipv4Addr::from_str("127.0.0.1") {
		Ok(address) => address,
		Err(err) => panic!(err)  
	};
	ping(ipAddress, 1);
}


fn ping(address: Ipv4Addr, ttl: u8) {
    //
    // ```text
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Version|  IHL  |   DSCP    |ECN|          Total length         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |        Identification	        |Flags|   Fragment Offset      |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |   TTL         |    Protocol   |      Header Checksum.         |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                       Source IP Address                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                       Target IP Address                       |
    // +-+-+-;+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Data ...
    // +-+-+-+-+-
    // ```
    // - IHL (Internet Header length)[4 Bit] - Number for 32 bit words. The minimum value is 5
    //     to a maximum of 15.
    // - DSCP (Differetiated Services Code Point)[RFC 2474] - specifies differentiated services
    // - ECN (Explicit Congestion Notification)[RFC 3168] - end-to-end notification about network congestion
    //     it is an optional feature and only used when both ends supoort it
    // - TTL (time to live) - maximum number of hops for a request
    // - Flags - set fragmentation control
    //     - bit 0: Reserved; must be zero
    //     - bit 1: Don't fragment (DF)
    //     - bit 2: More Fragments (MF)
    // - Fragment Offset - offset of the fragment compared tot the unfragmanted IP datagram
	let buffer_ip = & mut [0u8; 40];
    let mut ipv4_packet = MutableIpv4Packet::new(buffer_ip).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LENGTH);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(address);

    //
    // ```text
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |     Code      |          Checksum             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           Identifier          |        Sequence Number        |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Data ...
    // +-+-+-+-+-
    // ```
    const IMCP_BUFFER_SIZE: usize = 8;
    let buffer_icmp = & mut [0u8; IMCP_BUFFER_SIZE];
    let mut icmp_packet = MutableEchoRequestPacket::new(buffer_icmp).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = util::checksum(&icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);

    ipv4_packet.set_total_length((ipv4_packet.get_header_length() + ICMPV4_HEADER_LENGTH + (IMCP_BUFFER_SIZE/4) as u8 ) as u16);

    println!("{:?}", ipv4_packet);
    for buffer_element in buffer_ip.iter() {
    	print!(" {:}", buffer_element);
    }

    println!("");
    println!("############");

    println!("{:?}", icmp_packet);
    for buffer_element in buffer_icmp.iter() {
    	print!(" {:}", buffer_element);
    }
}
