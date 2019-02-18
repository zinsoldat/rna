use std::io::Error;
use std::string::String;
use std::env;

mod network;

fn main() -> Result<(), Error> {

	let args: Vec<String> = env::args().collect();
	let address = &args[1];
	traceroute_bash(address);

	// let ip_address: net::Ipv4Addr = match net::Ipv4Addr::from_str(address) {
	// 	Ok(address) => address,
	// 	Err(err) => {
 //    		println!("{:?}", err);
 //    		panic!(err)
 //    	}  
	// };
	// network::traceroute(ip_address);
	Ok(())
}


use std::process::Command;

fn traceroute_bash(address:& String) {
    let output = Command::new("traceroute")
        .arg(address)
        .output()
        .expect("Failed to execute command");
    let result = match String::from_utf8(output.stdout) {
    	Ok(value) => value,
    	Err(err) => {
    		println!("{:?}", err);
    		String::new()
    	}
    };

    let lines = result.lines();
    println!("{:?}", result);
    println!("{:?}", lines);
}