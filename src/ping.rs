extern crate pnet;

use std::net::{Ipv4Addr,Ipv6Addr,IpAddr};

use pnet::packet::MutablePacket;
use pnet::packet::ipv4::MutableIpv4Packet;


fn ping_ipV4_address(ipAddress: Ipv4Addrr, ttl: u8) Result<()> {
  let ipv4_packet = MutableIpv4Packet::new;
} 