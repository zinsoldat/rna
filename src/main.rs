extern crate pnet;

use std::str::FromStr;
use std::net::{Ipv4Addr};

use pnet::packet::MutablePacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::util;

const IPV4_HEADER_LENGTH: u8 = 5;

fn main() {
	let ip_address: Ipv4Addr = match Ipv4Addr::from_str("127.0.0.1") {
		Ok(address) => address,
		Err(err) => panic!(err)  
	};
	ping(ip_address, 1);
}


fn ping(address: Ipv4Addr, ttl: u8) {
	// create the icmp packet. This is the payload of the ip packet
    const ICMP_BUFFER_SIZE: usize = 8;
    let icmp_buffer = & mut [0u8; ICMP_BUFFER_SIZE];
    let mut icmp_packet = create_icmp_packet(icmp_buffer);

    // create the ip packet
    const IP_BUFFER_SIZE: usize = (IPV4_HEADER_LENGTH * 4) as usize + ICMP_BUFFER_SIZE;
	let ip_buffer = & mut [0u8; IP_BUFFER_SIZE];
    let mut ipv4_packet = create_ipv4_packet(ip_buffer, address, ttl);

    ipv4_packet.set_total_length((IP_BUFFER_SIZE) as u16);
    let icmp_mut_packet = icmp_packet.packet_mut();
    ipv4_packet.set_payload(icmp_mut_packet);

    println!("{:?}", ipv4_packet);
    print_buffer(ip_buffer);
    println!("");
    println!("############");
    println!("{:?}", icmp_packet);
    print_buffer(icmp_buffer);
}

fn print_buffer(buffer: &[u8]) {
    for buffer_element in buffer.iter() {
    	print!(" {:}", buffer_element);
    }
}

fn create_icmp_packet(icmp_buffer: & mut [u8]) -> MutableEchoRequestPacket {
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
    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    let checksum = util::checksum(&icmp_packet.packet_mut(), 2);
    icmp_packet.set_checksum(checksum);
    icmp_packet
}

fn create_ipv4_packet(ip_buffer: & mut [u8], address: Ipv4Addr, ttl: u8) -> MutableIpv4Packet {
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
    let mut ipv4_packet = MutableIpv4Packet::new(ip_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LENGTH);    
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_destination(address);
    ipv4_packet
}