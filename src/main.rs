extern crate pnet;

use std::str::FromStr;
use std::net::{Ipv4Addr,Ipv6Addr};

use pnet::packet::MutablePacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;

const IPV4_HEADER_LENGTH: u8 = 20;
const ICMPV4_HEADER_LENGTH: u8 = 8;

fn main() {
	let ipAddress: Ipv4Addr = match Ipv4Addr::from_str("127.0.0.1") {
		Ok(address) => address,
		Err(err) => panic!(err)  
	};
	ping(ipAddress);
}


fn ping(address: Ipv4Addr) {
	let buffer = & mut [0u8; 40];


    // abstraction for ICMP "echo reply" packets.
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
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Data ...
    // +-+-+-+-+-
    // ```
    // - IHL (Internet Header length)[4 Bit] - Number for 32 bit words. The minimum value is 4
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
    let mut ipv4_packet = MutableIpv4Packet::new(buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_ttl(1);
    ipv4_packet.set_destination(address);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    println!("{:?}", ipv4_packet);
    for buffer_element in buffer.iter() {
    	print!(" {:}", buffer_element);
    }
}
