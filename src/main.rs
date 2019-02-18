use std::io::Error;
use std::str::FromStr;
use std::net;
use std::env;

mod network;

fn main() -> Result<(), Error> {
	let args: Vec<String> = env::args().collect();
	let address = &args[1];
	let ip_address: net::Ipv4Addr = match net::Ipv4Addr::from_str(address) {
		Ok(address) => address,
		Err(err) => {
    		println!("{:?}", err);
    		panic!(err)
    	}  
	};
	network::traceroute(ip_address);
	Ok(())
}