extern crate pnet;

use std::time::{Duration, Instant};
use std::thread;
use std::sync::mpsc;
use std::net;
use std::io;

use pnet::packet::Packet;
use pnet::packet::MutablePacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType::Layer3};
use pnet::util;

const IPV4_HEADER_LENGTH: u8 = 5;

pub fn traceroute(address: net::Ipv4Addr) {
    let mut ttl = 1u8;
    loop {

    	let (sender, receiver) = mpsc::channel();
    	let thread_handle = thread::spawn(move || {
    		println!("{:?} - TTL: {}", address, ttl);
		    let result = match ping(address, ttl) {
	            Ok(result) => result,
	            Err(err) => {
	                println!("{:?}", err);
	                panic!(err)
	            }
	        };
	        println!("TTL: {} - {}ms - {:?}", ttl, (result.duration.subsec_nanos()/1000000) as f64, result.target_address);
	        if result.target_address == address {
	            return ();
	        }
	        sender.send(result).unwrap()
    	});
    	thread::sleep(std::time::Duration::from_millis(50));
		let _result = match receiver.try_recv() {
	        Ok(_) => (), // we have a connection
	        Err(mpsc::TryRecvError::Empty) => {
	            drop(receiver);
	            drop(thread_handle);
	        },
	        Err(mpsc::TryRecvError::Disconnected) => unreachable!(),
	    };
    	// let _result = receiver.recv().unwrap();
        ttl = ttl + 1;
        if ttl >= 64 {
        	()
        }
    }
}

pub struct PingResult {
	target_address: net::IpAddr,
	duration: Duration,
}

pub fn ping(address: net::Ipv4Addr, ttl: u8) -> io::Result<PingResult> {
	// create the icmp packet. This is the payload of the ip packet
    const ICMP_BUFFER_SIZE: usize = 8;
    let icmp_buffer = & mut [0u8; ICMP_BUFFER_SIZE];
    let icmp_packet = create_icmp_packet(icmp_buffer);

    // create the ip packet with icmp packet as payload
    const IP_BUFFER_SIZE: usize = (IPV4_HEADER_LENGTH * 4) as usize + ICMP_BUFFER_SIZE;
	let ip_buffer = & mut [0u8; IP_BUFFER_SIZE];
    let ipv4_packet = create_ipv4_packet(ip_buffer, address, ttl, icmp_packet.packet());

    let protocol = Layer3(IpNextHeaderProtocols::Icmp);
    let (mut sender, mut receiver) = match transport_channel(1024, protocol) {
    	Ok((sender, receiver)) => (sender, receiver),
    	Err(err) => {
    		println!("{:?}", err);
    		panic!(err)
    	}
    };

    let mut receiver = icmp_packet_iter(& mut receiver);
    let start_time = Instant::now();
    match sender.send_to(ipv4_packet, net::IpAddr::V4(address)) {
    	Ok(_) => (),
    	Err(err) => {
    		println!("{:?}", err);
    		panic!(err)
    	}
    }
    let (_result, ping_address ) = match receiver.next() {
    	Ok((result, address)) => (result, address),
    	Err(err) => {
    		println!("{:?}", err);
    		panic!(err)
    	}
    };
    let duration = start_time.elapsed();
    let result = PingResult{ 
    	target_address: ping_address, 
    	duration, 
    };
    Ok(result)
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

fn create_ipv4_packet<'a>(ip_buffer: &'a mut [u8], address: net::Ipv4Addr, ttl: u8, payload: &'a[u8]) -> MutableIpv4Packet<'a> {
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
    let packet_size = ip_buffer.len();
    let mut ipv4_packet = MutableIpv4Packet::new(ip_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LENGTH);  
    // ipv4_packet.set_header_length(5);  
    ipv4_packet.set_total_length(packet_size as u16);  
    // ipv4_packet.set_total_length(28u16);  
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_destination(address);
    ipv4_packet.set_payload(payload);
    ipv4_packet
}