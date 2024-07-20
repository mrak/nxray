mod args;

use args::*;
use std::env;
use std::process;

#[derive(Default, Debug)]
struct Settings {
    pcap: bool,
    tcp: bool,
    udp: bool,
    icmp: bool,
    ethernet: bool,
    interfaces: Vec<String>,
    filters: Vec<Filter>,
}

fn main() {
    let mut s = Settings {
        ..Default::default()
    };

    for argument in env::args().skip(1) {
        match parse_arg(argument.as_str()) {
            Ok(Argument::Pcap) => s.pcap = true,
            Ok(Argument::ProtocolFlag(Protocol::TCP)) => s.tcp = true,
            Ok(Argument::ProtocolFlag(Protocol::UDP)) => s.udp = true,
            Ok(Argument::ProtocolFlag(Protocol::ICMP)) => s.icmp = true,
            Ok(Argument::ProtocolFlag(Protocol::Ethernet)) => s.ethernet = true,
            Ok(Argument::Interface(i)) => s.interfaces.push(i.to_string()),
            Ok(Argument::FilterExpr(f)) => s.filters.push(f),
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1)
            }
        }
    }

    match (s.tcp, s.udp, s.icmp, s.ethernet) {
        (true, true, true, true) => {
            s.tcp = true;
            s.udp = true;
            s.icmp = true;
            s.ethernet = true;
        }
        _ => {}
    }

    println!("{s:?}");
}
