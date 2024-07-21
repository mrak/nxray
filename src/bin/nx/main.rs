mod args;

use args::*;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::arp::ArpOperations;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::env;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::process;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::thread;
use std::vec::Vec;

#[derive(Default, Debug)]
struct Settings {
    pcap: bool,
    tcp: bool,
    udp: bool,
    icmp: bool,
    arp: bool,
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
            Ok(Argument::ProtocolFlag(Protocol::ARP)) => s.arp = true,
            Ok(Argument::Interface(i)) => s.interfaces.push(i.to_string()),
            Ok(Argument::FilterExpr(f)) => s.filters.push(f),
            Err(e) => {
                eprintln!("{}", e);
                process::exit(1)
            }
        }
    }

    match (s.tcp, s.udp, s.icmp, s.arp) {
        (false, false, false, false) => {
            s.tcp = true;
            s.udp = true;
            s.icmp = false;
            s.arp = false;
        }
        _ => {}
    }

    let (snd, rcv): (Sender<(u32, Vec<u8>)>, Receiver<(u32, Vec<u8>)>) = mpsc::channel();

    capture_packets(&s, snd);
    print_packets(&s, rcv);
}

fn capture_packets(settings: &Settings, sender: Sender<(u32, Vec<u8>)>) {
    let interfaces = match &settings.interfaces {
        x if x.len() == 0 => datalink::interfaces(),
        x => {
            let interface_name_matcher = |interface: &NetworkInterface| x.contains(&interface.name);
            datalink::interfaces()
                .into_iter()
                .filter(interface_name_matcher)
                .collect()
        }
    };
    let mut children = Vec::new();

    for interface in interfaces {
        let child_snd = sender.clone();
        let child = thread::spawn(move || {
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("nx: unhandled channel type"),
                Err(e) => match e.kind() {
                    ErrorKind::PermissionDenied => {
                        eprintln!(
                            "nx: Permission Denied - Unable to open interface {}",
                            interface.name
                        );
                        process::exit(1)
                    }
                    _ => panic!("nx: unable to create channel: {}", e),
                },
            };
            loop {
                match rx.next() {
                    Ok(packet) => child_snd
                        .send((interface.index, packet.to_owned()))
                        .unwrap(),
                    Err(e) => panic!("nx: Unable to receive packet: {}", e),
                };
            }
        });
        children.push(child);
    }
}

fn print_packets(settings: &Settings, receiver: Receiver<(u32, Vec<u8>)>) {
    let interfaces = datalink::interfaces();
    loop {
        match receiver.recv() {
            Ok((interface_index, packet)) => {
                // OS interface indexes are 1 based, but Vectors are 0 based
                let index = (interface_index as usize) - 1;
                let ethernet_packet = EthernetPacket::new(packet.as_slice()).unwrap();
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        process_ipv4(settings, &interfaces[index].name[..], &ethernet_packet)
                    }
                    EtherTypes::Ipv6 => {
                        process_ipv6(settings, &interfaces[index].name[..], &ethernet_packet)
                    }
                    EtherTypes::Arp => {
                        process_arp(settings, &interfaces[index].name[..], &ethernet_packet)
                    }
                    _ => eprintln!("[{}] ? Unknown packet type", interfaces[index].name),
                }
            }
            Err(_) => panic!("All interfaces closed"),
        }
    }
}

fn process_ipv4(settings: &Settings, interface_name: &str, packet: &EthernetPacket) {
    match Ipv4Packet::new(packet.payload()) {
        Some(ipv4_packet) => {
            process_transport(
                settings,
                interface_name,
                &packet.get_source(),
                &IpAddr::V4(ipv4_packet.get_source()),
                &packet.get_destination(),
                &IpAddr::V4(ipv4_packet.get_destination()),
                ipv4_packet.get_next_level_protocol(),
                ipv4_packet.payload(),
            );
        }
        None => println!("[{}] Malformed IPv4 packet", interface_name),
    }
}

fn process_ipv6(settings: &Settings, interface_name: &str, packet: &EthernetPacket) {
    match Ipv6Packet::new(packet.payload()) {
        Some(ipv6_packet) => {
            process_transport(
                settings,
                interface_name,
                &packet.get_source(),
                &IpAddr::V6(ipv6_packet.get_source()),
                &packet.get_destination(),
                &IpAddr::V6(ipv6_packet.get_destination()),
                ipv6_packet.get_next_header(),
                ipv6_packet.payload(),
            );
        }
        None => println!("[{}] Malformed IPv6 packet", interface_name),
    }
}

fn process_arp(settings: &Settings, interface_name: &str, packet: &EthernetPacket) {
    if !settings.arp {
        return;
    }
    match ArpPacket::new(packet.payload()) {
        Some(arp_packet) => {
            if !filters_match_criteria(
                &settings.filters,
                &packet.get_source(),
                &IpAddr::V4(arp_packet.get_sender_proto_addr()),
                0,
                &packet.get_destination(),
                &IpAddr::V4(arp_packet.get_target_proto_addr()),
                0,
            ) {
                return;
            }
            println!(
                "[{}] A {}[{}] > {}[{}] ~ {}",
                interface_name,
                packet.get_source(),
                arp_packet.get_sender_proto_addr(),
                packet.get_destination(),
                arp_packet.get_target_proto_addr(),
                match arp_packet.get_operation() {
                    ArpOperations::Reply => "reply",
                    ArpOperations::Request => "request",
                    _ => "unknown",
                },
            )
        }
        None => println!("[{}] A Malformed packet", interface_name),
    }
}

fn process_transport(
    settings: &Settings,
    interface_name: &str,
    source_mac: &MacAddr,
    source: &IpAddr,
    destination_mac: &MacAddr,
    destination: &IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Tcp => process_tcp(
            settings,
            interface_name,
            source_mac,
            source,
            destination_mac,
            destination,
            packet,
        ),
        IpNextHeaderProtocols::Udp => process_udp(
            settings,
            interface_name,
            source_mac,
            source,
            destination_mac,
            destination,
            packet,
        ),
        IpNextHeaderProtocols::Icmp => process_icmp(
            settings,
            interface_name,
            source_mac,
            source,
            destination_mac,
            destination,
            packet,
        ),
        IpNextHeaderProtocols::Icmpv6 => process_icmpv6(
            settings,
            interface_name,
            source_mac,
            source,
            destination_mac,
            destination,
            packet,
        ),
        _ => println!("[{}] Unknown packet", interface_name),
    }
}

fn tcp_type_from_flags(flags: u8) -> String {
    if (flags & TcpFlags::RST) != 0 {
        String::from("RST")
    } else if (flags & TcpFlags::FIN) != 0 {
        String::from("FIN")
    } else if (flags & TcpFlags::SYN) != 0 {
        String::from("SYN")
    } else if (flags & TcpFlags::ACK) != 0 {
        String::from("ACK")
    } else {
        String::from("???")
    }
}

fn escape_payload(payload: &[u8]) -> String {
    String::from_utf8(
        payload
            .iter()
            .map(|&b| match b {
                b' '..=b'~' | b'\t' | b'\r' | b'\n' => b,
                _ => b'.',
            })
            .collect(),
    )
    .unwrap()
}

fn port_opt_match(port_opt: &PortOption, port: u16) -> bool {
    // POSIX.2024, port 0 is reserverd for "random port"
    // As that is senseless for matching ports, we use it here
    // as a wildcard match instead of a union type for the u16 field.
    if port == 0 {
        return true;
    }
    match port_opt {
        PortOption::Specific(p) => port == *p,
        PortOption::List(l) => l.contains(&port),
        PortOption::Range(l, r) => *l <= port && port <= *r,
        PortOption::Any => true,
    }
}

fn filters_match_criteria(
    filters: &Vec<Filter>,
    src_mac: &MacAddr,
    src_addr: &IpAddr,
    src_port: u16,
    dst_mac: &MacAddr,
    dst_addr: &IpAddr,
    dst_port: u16,
) -> bool {
    if filters.is_empty() {
        return true;
    }
    let address_match = |dir: &PacketDirection, addr: &Address| -> bool {
        match addr {
            Address::IP(ip, port_opt) => match dir {
                PacketDirection::Source => {
                    if ip.contains(*src_addr) && port_opt_match(&port_opt, src_port) {
                        return true;
                    }
                }
                PacketDirection::Destination => {
                    if ip.contains(*dst_addr) && port_opt_match(&port_opt, dst_port) {
                        return true;
                    }
                }
                PacketDirection::Either => {
                    if (ip.contains(*dst_addr) && port_opt_match(&port_opt, dst_port))
                        || (ip.contains(*src_addr) && port_opt_match(&port_opt, src_port))
                    {
                        return true;
                    }
                }
            },
            Address::PortOnly(port_opt) => match dir {
                PacketDirection::Source => {
                    if port_opt_match(&port_opt, src_port) {
                        return true;
                    }
                }
                PacketDirection::Destination => {
                    if port_opt_match(&port_opt, dst_port) {
                        return true;
                    }
                }
                PacketDirection::Either => {
                    if port_opt_match(&port_opt, dst_port) || port_opt_match(&port_opt, src_port) {
                        return true;
                    }
                }
            },
            Address::MAC(m) => match dir {
                PacketDirection::Source => {
                    if m == src_mac {
                        return true;
                    }
                }
                PacketDirection::Destination => {
                    if m == dst_mac {
                        return true;
                    }
                }
                PacketDirection::Either => {
                    if m == dst_mac || m == src_mac {
                        return true;
                    }
                }
            },
        }
        false
    };

    for filter in filters {
        match filter {
            Filter::AddressFilter(dir, addr) => {
                if address_match(dir, addr) {
                    return true;
                }
            }
            Filter::PacketFilter(dir1, addr1, dir2, addr2) => {
                if address_match(dir1, addr1) && address_match(dir2, addr2) {
                    return true;
                }
            }
        }
    }

    false
}

fn process_tcp(
    settings: &Settings,
    interface_name: &str,
    source_mac: &MacAddr,
    source: &IpAddr,
    destination_mac: &MacAddr,
    destination: &IpAddr,
    packet: &[u8],
) {
    if !settings.tcp {
        return;
    }
    match TcpPacket::new(packet) {
        Some(tcp_packet) => {
            if !filters_match_criteria(
                &settings.filters,
                source_mac,
                source,
                tcp_packet.get_source(),
                destination_mac,
                destination,
                tcp_packet.get_destination(),
            ) {
                return;
            }
            println!(
                "[{}] T {}:{} > {}:{} ~ {} #{} {}b",
                interface_name,
                source,
                tcp_packet.get_source(),
                destination,
                tcp_packet.get_destination(),
                tcp_type_from_flags(tcp_packet.get_flags()),
                tcp_packet.get_sequence(),
                tcp_packet.payload().len(),
            );
            if !tcp_packet.payload().is_empty() {
                println!("{}", escape_payload(tcp_packet.payload()))
            }
        }
        None => println!("[{}] T Malformed packet", interface_name),
    }
}

fn process_udp(
    settings: &Settings,
    interface_name: &str,
    source_mac: &MacAddr,
    source: &IpAddr,
    destination_mac: &MacAddr,
    destination: &IpAddr,
    packet: &[u8],
) {
    if !settings.udp {
        return;
    }
    match UdpPacket::new(packet) {
        Some(udp_packet) => {
            if !filters_match_criteria(
                &settings.filters,
                source_mac,
                source,
                udp_packet.get_source(),
                destination_mac,
                destination,
                udp_packet.get_destination(),
            ) {
                return;
            }
            println!(
                "[{}] U {}:{} > {}:{} ~ {}b",
                interface_name,
                source,
                udp_packet.get_source(),
                destination,
                udp_packet.get_destination(),
                udp_packet.get_length(),
            );
            if !udp_packet.payload().is_empty() {
                println!("{}", escape_payload(udp_packet.payload()))
            }
        }
        None => println!("[{}] U Malformed packet", interface_name),
    }
}

fn process_icmp(
    settings: &Settings,
    interface_name: &str,
    source_mac: &MacAddr,
    source: &IpAddr,
    destination_mac: &MacAddr,
    destination: &IpAddr,
    packet: &[u8],
) {
    if !settings.icmp {
        return;
    }
    if !filters_match_criteria(
        &settings.filters,
        source_mac,
        source,
        0,
        destination_mac,
        destination,
        0,
    ) {
        return;
    }
    match IcmpPacket::new(packet) {
        Some(icmp_packet) => match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {}
            _ => println!("[{}] I {} > {}", interface_name, source, destination,),
        },
        None => println!("[{}] I Malformed packet", interface_name),
    }
}

fn process_icmpv6(
    settings: &Settings,
    interface_name: &str,
    source_mac: &MacAddr,
    source: &IpAddr,
    destination_mac: &MacAddr,
    destination: &IpAddr,
    packet: &[u8],
) {
    if !settings.icmp {
        return;
    }
    if !filters_match_criteria(
        &settings.filters,
        source_mac,
        source,
        0,
        destination_mac,
        destination,
        0,
    ) {
        return;
    }
    match IcmpPacket::new(packet) {
        Some(icmp_packet) => match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {}
            _ => println!("[{}] I {} > {}", interface_name, source, destination,),
        },
        None => println!("[{}] I Malformed packet", interface_name),
    }
}
