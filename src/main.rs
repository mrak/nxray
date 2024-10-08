use anyhow::Context;
use colored::Colorize;
use nxray::args::Address;
use nxray::args::Argument;
use nxray::args::Filter;
use nxray::args::PacketDirection;
use nxray::args::PortOption;
use nxray::args::Protocol;
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
use pnet::packet::icmpv6::ndp::NdpOptionTypes;
use pnet::packet::icmpv6::ndp::NeighborAdvertPacket;
use pnet::packet::icmpv6::ndp::NeighborSolicitPacket;
use pnet::packet::icmpv6::ndp::RedirectPacket;
use pnet::packet::icmpv6::ndp::RouterAdvertPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashMap;
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
    short: bool,
    tcp: bool,
    udp: bool,
    icmp: bool,
    arp: bool,
    ipip: bool,
    interfaces: Vec<String>,
    filters: Vec<Filter>,
}

fn main() {
    let mut s = Settings {
        ..Default::default()
    };
    let mut args = env::args().skip(1);

    for argument in args.by_ref() {
        match nxray::args::parse_arg(argument.as_str())
            .context(format!("invalid argument '{}'", argument.as_str()))
        {
            Ok(Argument::Emdash) => break,
            Ok(Argument::Pcap) => s.pcap = true,
            Ok(Argument::Short) => s.short = true,
            Ok(Argument::Version) => {
                nxray::args::version();
                process::exit(0)
            }
            Ok(Argument::Help) => {
                nxray::args::usage();
                process::exit(0)
            }
            Ok(Argument::ProtocolFlag(Protocol::Tcp)) => s.tcp = true,
            Ok(Argument::ProtocolFlag(Protocol::Udp)) => s.udp = true,
            Ok(Argument::ProtocolFlag(Protocol::Icmp)) => s.icmp = true,
            Ok(Argument::ProtocolFlag(Protocol::Arp)) => s.arp = true,
            Ok(Argument::ProtocolFlag(Protocol::IpIp)) => s.ipip = true,
            Ok(Argument::Interface(i)) => s.interfaces.push(i),
            Ok(Argument::FilterExpr(f)) => s.filters.push(f),
            Err(e) => {
                eprintln!("nx: {:?}", e);
                process::exit(1)
            }
        }
    }

    for argument in args {
        s.interfaces.push(argument);
    }

    if let (false, false, false, false, false) = (s.tcp, s.udp, s.icmp, s.arp, s.ipip) {
        s.tcp = true;
        s.udp = true;
        s.icmp = true;
        s.arp = true;
        s.ipip = true;
    }

    let (snd, rcv) = mpsc::channel();

    capture_packets(&s, snd);
    print_packets(&s, rcv);
}

fn capture_packets(settings: &Settings, sender: Sender<(u32, Vec<u8>)>) {
    let interfaces = match &settings.interfaces {
        x if x.is_empty() => datalink::interfaces(),
        x => {
            let interface_name_matcher = |interface: &NetworkInterface| x.contains(&interface.name);
            datalink::interfaces()
                .into_iter()
                .filter(interface_name_matcher)
                .collect()
        }
    };

    for interface in interfaces {
        let child_snd = sender.clone();
        let _ = thread::Builder::new()
            .name(interface.name.clone())
            .spawn(move || {
                let mut rx = match datalink::channel(&interface, Default::default()) {
                    Ok(Ethernet(_, rx)) => rx,
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
                            .expect("packet should be able to be sent on channel"),
                        Err(e) => panic!("nx: Unable to receive packet: {}", e),
                    };
                }
            });
    }
}

fn print_packets(settings: &Settings, receiver: Receiver<(u32, Vec<u8>)>) {
    let inames: HashMap<u32, String> = datalink::interfaces()
        .iter()
        .map(|x| (x.index, x.name.clone()))
        .collect();
    for (index, packet) in receiver {
        if let Some(ethernet_packet) = EthernetPacket::new(packet.as_slice()) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => process_ipv4(settings, &inames[&index][..], &ethernet_packet),
                EtherTypes::Ipv6 => process_ipv6(settings, &inames[&index][..], &ethernet_packet),
                EtherTypes::Arp => process_arp(settings, &inames[&index][..], &ethernet_packet),
                _ => {}
            }
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
        None => eprintln!("[{}] Ipv4 Malformed packet", interface_name),
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
        None => eprintln!("[{}] IPv6 Malformed packet", interface_name),
    }
}

fn process_arp(settings: &Settings, interface_name: &str, packet: &EthernetPacket) {
    if !settings.arp {
        return;
    }
    let iname = interface_name.purple();
    let ptype = "ARP".bold().red();
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
            let src_mac = packet.get_source().to_string().green();
            let src_ip = format!("[{}]", arp_packet.get_sender_proto_addr())
                .dimmed()
                .green();
            let dst_mac = packet.get_destination().to_string().blue();
            let dst_ip = format!("[{}]", arp_packet.get_target_proto_addr())
                .dimmed()
                .blue();
            let op = match arp_packet.get_operation() {
                ArpOperations::Reply => "reply",
                ArpOperations::Request => "request",
                _ => "unknown",
            }
            .yellow();
            println!("{iname} {ptype} {src_mac}{src_ip} {dst_mac}{dst_ip} {op}")
        }
        None => eprintln!("{iname} {ptype} {}", "Malformed packet".red()),
    }
}

#[allow(clippy::too_many_arguments)]
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
        IpNextHeaderProtocols::Icmpv6 => process_icmpv6(
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
        IpNextHeaderProtocols::IpIp => process_ipip(
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
    let mut fs: Vec<String> = vec![];
    if (flags & TcpFlags::CWR) != 0 {
        fs.push(String::from("CWR"));
    }
    if (flags & TcpFlags::ECE) != 0 {
        fs.push(String::from("ECE"));
    }
    if (flags & TcpFlags::URG) != 0 {
        fs.push(String::from("URG"));
    }
    if (flags & TcpFlags::ACK) != 0 {
        fs.push(String::from("ACK"));
    }
    if (flags & TcpFlags::PSH) != 0 {
        fs.push(String::from("PSH"));
    }
    if (flags & TcpFlags::RST) != 0 {
        fs.push(String::from("RST"));
    }
    if (flags & TcpFlags::SYN) != 0 {
        fs.push(String::from("SYN"));
    }
    if (flags & TcpFlags::FIN) != 0 {
        fs.push(String::from("FIN"));
    }
    fs.join(" ")
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
    .expect("unable to escape packet payload")
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
                    if ip.contains(*src_addr) && port_opt_match(port_opt, src_port) {
                        return true;
                    }
                }
                PacketDirection::Destination => {
                    if ip.contains(*dst_addr) && port_opt_match(port_opt, dst_port) {
                        return true;
                    }
                }
                PacketDirection::Either => {
                    if (ip.contains(*dst_addr) && port_opt_match(port_opt, dst_port))
                        || (ip.contains(*src_addr) && port_opt_match(port_opt, src_port))
                    {
                        return true;
                    }
                }
            },
            Address::PortOnly(port_opt) => match dir {
                PacketDirection::Source => {
                    if port_opt_match(port_opt, src_port) {
                        return true;
                    }
                }
                PacketDirection::Destination => {
                    if port_opt_match(port_opt, dst_port) {
                        return true;
                    }
                }
                PacketDirection::Either => {
                    if port_opt_match(port_opt, dst_port) || port_opt_match(port_opt, src_port) {
                        return true;
                    }
                }
            },
            Address::Mac(m) => match dir {
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

fn process_ipip(
    settings: &Settings,
    interface_name: &str,
    source_mac: &MacAddr,
    source: &IpAddr,
    destination_mac: &MacAddr,
    destination: &IpAddr,
    packet: &[u8],
) {
    if !settings.ipip {
        return;
    }
    let iname = interface_name.purple();
    let ptype = "IPIP".bold().red();
    match Ipv4Packet::new(packet) {
        Some(ip_packet) => {
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
            if !filters_match_criteria(
                &settings.filters,
                source_mac,
                &IpAddr::V4(ip_packet.get_source()),
                0,
                destination_mac,
                &IpAddr::V4(ip_packet.get_destination()),
                0,
            ) {
                return;
            }
            let src_ip = source.to_string().green();
            let src_ipip = format!("[{}]", ip_packet.get_source()).dimmed().green();
            let dst_ip = destination.to_string().blue();
            let dst_ipip = format!("[{}]", ip_packet.get_destination()).dimmed().blue();
            let bytes = format!("{}b", ip_packet.payload().len()).cyan();
            println!("{iname} {ptype} {src_ip}{src_ipip} {dst_ip}{dst_ipip} {bytes}",);
        }
        None => eprintln!("{iname} {ptype} {}", "Malformed packet".red()),
    }
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
    let iname = interface_name.purple();
    let ptype = "TCP".bold().red();
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
            let src_ip = source.to_string().green();
            let src_port = format!(":{}", tcp_packet.get_source()).dimmed().green();
            let dst_ip = destination.to_string().blue();
            let dst_port = format!(":{}", tcp_packet.get_destination()).dimmed().blue();
            let flags = tcp_type_from_flags(tcp_packet.get_flags()).yellow();
            let seq = format!("#{}", tcp_packet.get_sequence()).dimmed().white();
            let bytes = format!("{}b", tcp_packet.payload().len()).cyan();
            println!("{iname} {ptype} {src_ip}{src_port} {dst_ip}{dst_port} {flags} {seq} {bytes}");
            if !settings.short && !tcp_packet.payload().is_empty() {
                println!("{}", escape_payload(tcp_packet.payload()))
            }
        }
        None => eprintln!("{iname} {ptype} Malformed packet"),
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
    let iname = interface_name.purple();
    let ptype = "UDP".bold().red();
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
            let src_ip = source.to_string().green();
            let src_port = format!(":{}", udp_packet.get_source()).dimmed().green();
            let dst_ip = destination.to_string().blue();
            let dst_port = format!(":{}", udp_packet.get_destination()).dimmed().blue();
            let bytes = format!("{}b", udp_packet.payload().len()).cyan();
            println!("{iname} {ptype} {src_ip}{src_port} {dst_ip}{dst_port} {bytes}");
            if !settings.short && !udp_packet.payload().is_empty() {
                println!("{}", escape_payload(udp_packet.payload()))
            }
        }
        None => eprintln!("{iname} {ptype} Malformed packet"),
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
    let iname = interface_name.purple();
    let ptype = "ICMP".bold().red();
    match Icmpv6Packet::new(packet) {
        Some(icmp_packet) => {
            let (i_type, i_desc, i_details) = match icmp_packet.get_icmpv6_type() {
                Icmpv6Types::EchoReply => (String::from("echo"), String::from("reply"), None),
                Icmpv6Types::EchoRequest => (String::from("echo"), String::from("request"), None),
                Icmpv6Types::ParameterProblem => (
                    String::from("parameter problem"),
                    match icmp_packet.get_icmpv6_code().0 {
                        0 => String::from("erroneous header"),
                        1 => String::from("next header"),
                        2 => String::from("option"),
                        x => format!("code {}", x),
                    },
                    None,
                ),
                Icmpv6Types::PacketTooBig => {
                    let mtu_bytes: [u8; 4] = icmp_packet.payload()[2..6].try_into().unwrap();
                    (
                        String::from("packet too big"),
                        format!("mtu {}", u32::from_be_bytes(mtu_bytes)),
                        None,
                    )
                }
                Icmpv6Types::Redirect => (
                    String::from("ndp"),
                    String::from("redirect"),
                    RedirectPacket::new(packet).map(|r| {
                        format!(
                            "{} {}\n{} {}",
                            "Target:      ".dimmed(),
                            r.get_target_addr(),
                            "Destination: ".dimmed(),
                            r.get_dest_addr(),
                        )
                    }),
                ),
                Icmpv6Types::TimeExceeded => {
                    (String::from("time exceeded"), String::from(""), None)
                }
                Icmpv6Types::DestinationUnreachable => (
                    String::from("unreachable"),
                    match icmp_packet.get_icmpv6_code().0 {
                        0 => String::from("route"),
                        1 => String::from("prohibited"),
                        2 => String::from("scope"),
                        3 => String::from("address"),
                        4 => String::from("port"),
                        5 => String::from("ingress/egress"),
                        6 => String::from("rejected"),
                        x => format!("code {}", x),
                    },
                    None,
                ),
                Icmpv6Types::RouterAdvert => {
                    let ra = RouterAdvertPacket::new(packet);
                    (
                        String::from("router"),
                        String::from("advertisement"),
                        ra.map(|r| {
                            fn router_options(ra: &RouterAdvertPacket) -> String {
                                let mut output = String::from("");
                                for o in ra.get_options_iter() {
                                    match o.get_option_type() {
                                        NdpOptionTypes::MTU => {
                                            let mtu_bytes: [u8; 4] =
                                                o.payload()[2..6].try_into().unwrap();
                                            output = format!(
                                                "{}\n{} {}",
                                                output,
                                                "MTU:                     ".dimmed(),
                                                u32::from_be_bytes(mtu_bytes),
                                            );
                                        }
                                        NdpOptionTypes::PrefixInformation => {
                                            let prefix_bytes: [u8; 16] =
                                                o.payload()[14..30].try_into().unwrap();
                                            let prefix_addr = IpAddr::from(prefix_bytes);
                                            let prefix_length = o.payload()[0];
                                            output = format!(
                                                "{}\n{} {}/{}",
                                                output,
                                                "Prefix:                  ".dimmed(),
                                                prefix_addr,
                                                prefix_length
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                                output
                            }
                            format!(
                                "{} {}\n{} {}s\n{} {}ms\n{} {}ms\n{} {}\n{} {}{}",
                                "Current Hop Limit:       ".dimmed(),
                                r.get_hop_limit(),
                                "Router Lifetime:         ".dimmed(),
                                r.get_lifetime(),
                                "Reachable Time:          ".dimmed(),
                                r.get_reachable_time(),
                                "Retrans Time:            ".dimmed(),
                                r.get_retrans_time(),
                                "Managed Address Flag     ".dimmed(),
                                r.get_flags() & 0b10000000 != 0,
                                "Other Configuraiton Flag ".dimmed(),
                                r.get_flags() & 0b11000000 != 0,
                                router_options(&r),
                            )
                        }),
                    )
                }
                Icmpv6Types::RouterSolicit => {
                    (String::from("router"), String::from("solicitation"), None)
                }
                Icmpv6Types::NeighborSolicit => {
                    let ns = NeighborSolicitPacket::new(packet);
                    (
                        String::from("ndp"),
                        String::from("neighbor solicitation"),
                        ns.map(|p| {
                            format!(
                                "{} {}",
                                String::from("Target:").dimmed(),
                                p.get_target_addr(),
                            )
                        }),
                    )
                }
                Icmpv6Types::NeighborAdvert => {
                    let na = NeighborAdvertPacket::new(packet);
                    (
                        String::from("ndp"),
                        String::from("neighbor advertisement"),
                        na.map(|p| {
                            format!(
                                "{} {}\n{} {}\n{} {}\n{} {} ",
                                String::from("Target:        ").dimmed(),
                                p.get_target_addr(),
                                String::from("Router flag:   ").dimmed(),
                                p.get_flags() & 0b10000000 == 0,
                                String::from("Solicited flag:").dimmed(),
                                p.get_flags() & 0b01000000 == 0,
                                String::from("Override flag: ").dimmed(),
                                p.get_flags() & 0b01000000 == 0,
                            )
                        }),
                    )
                }
                _ => (
                    format!("type {}", icmp_packet.get_icmpv6_type().0),
                    format!("code {}", icmp_packet.get_icmpv6_code().0),
                    None,
                ),
            };
            let src = source.to_string().green();
            let dst = destination.to_string().blue();
            let itype = i_type.yellow();
            let idesc = i_desc.dimmed().white();
            let bytes = format!("{}b", icmp_packet.payload().len()).cyan();
            println!("{iname} {ptype} {src} {dst} {itype} {idesc} {bytes}",);
            if !settings.short {
                if let Some(d) = i_details {
                    println!("{}", d)
                }
            }
        }
        None => eprintln!("{iname} {ptype} Malformed packet"),
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
    let iname = interface_name.purple();
    let ptype = "ICMP".bold().red();
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
        Some(icmp_packet) => {
            let (i_type, i_desc, i_details) = match icmp_packet.get_icmp_type() {
                IcmpTypes::EchoReply => (String::from("echo"), String::from("reply"), None),
                IcmpTypes::EchoRequest => (String::from("echo"), String::from("request"), None),
                IcmpTypes::RouterAdvertisement => {
                    (String::from("router"), String::from("advertisement"), None)
                }
                IcmpTypes::RouterSolicitation => {
                    (String::from("router"), String::from("solicitation"), None)
                }
                IcmpTypes::ParameterProblem => (
                    String::from("parameter problem"),
                    match icmp_packet.get_icmp_code().0 {
                        0 => String::from("pointer"),
                        1 => String::from("missing option"),
                        2 => String::from("bad length"),
                        x => format!("code {}", x),
                    },
                    None,
                ),
                IcmpTypes::Timestamp => (String::from("timestamp"), String::from("request"), None),
                IcmpTypes::TimestampReply => {
                    (String::from("timestamp"), String::from("reply"), None)
                }

                IcmpTypes::RedirectMessage => (
                    String::from("redirect"),
                    match icmp_packet.get_icmp_code().0 {
                        0 => String::from("network"),
                        1 => String::from("host"),
                        2 => String::from("tos network"),
                        3 => String::from("tos host"),
                        x => format!("code {}", x),
                    },
                    {
                        let ip_bytes: [u8; 4] = icmp_packet.payload()[4..8].try_into().unwrap();
                        Some(IpAddr::from(ip_bytes).to_string())
                    },
                ),
                IcmpTypes::AddressMaskRequest => {
                    (String::from("address mask"), String::from("request"), None)
                }
                IcmpTypes::AddressMaskReply => {
                    (String::from("address mask"), String::from("reply"), None)
                }
                IcmpTypes::InformationRequest => {
                    (String::from("information"), String::from("request"), None)
                }
                IcmpTypes::InformationReply => {
                    (String::from("information"), String::from("reply"), None)
                }
                IcmpTypes::Traceroute => (
                    String::from("traceroute"),
                    String::from("(deprecated)"),
                    None,
                ),
                IcmpTypes::DestinationUnreachable => (
                    String::from("unreachable"),
                    match icmp_packet.get_icmp_code().0 {
                        0 => String::from("network"),
                        1 => String::from("host"),
                        2 => String::from("protocol"),
                        3 => String::from("port"),
                        4 => String::from("fragmentation needed"),
                        5 => String::from("source route failed"),
                        x => format!("{}", x),
                    },
                    None,
                ),
                IcmpTypes::SourceQuench => (
                    String::from("source quench"),
                    String::from("(deprecated)"),
                    None,
                ),
                _ => (
                    format!("type {}", icmp_packet.get_icmp_type().0),
                    format!("code {}", icmp_packet.get_icmp_code().0),
                    None,
                ),
            };
            let src = source.to_string().green();
            let dst = destination.to_string().blue();
            let itype = i_type.yellow();
            let idesc = i_desc.dimmed().white();
            let bytes = format!("{}b", icmp_packet.payload().len()).cyan();
            println!("{iname} {ptype} {src} {dst} {itype} {idesc} {bytes}",);
            if !settings.short {
                if let Some(d) = i_details {
                    println!("{}", d)
                }
            }
        }
        None => eprintln!("{iname} {ptype} Malformed packet"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_to_filters(args: &[&str]) -> Vec<Filter> {
        args.iter()
            .map(|a| {
                let Argument::FilterExpr(f) = nxray::args::parse_arg(a).unwrap() else {
                    panic!()
                };
                f
            })
            .collect()
    }

    #[test]
    fn filters_match_criteria_tcp() {
        let ipv4_packet = |args: &[&str]| -> bool {
            let filters = args_to_filters(args);
            filters_match_criteria(
                &filters,
                &"aa:bb:cc:dd:ee:ff".parse().unwrap(),
                &"192.168.1.1".parse().unwrap(),
                22,
                &"ff:ee:dd:cc:bb:aa".parse().unwrap(),
                &"10.0.0.5".parse().unwrap(),
                22,
            )
        };

        let ipv6_packet = |args: &[&str]| -> bool {
            let filters = args_to_filters(args);
            filters_match_criteria(
                &filters,
                &"aa:bb:cc:dd:ee:ff".parse().unwrap(),
                &"2001:db8::4321:1313".parse().unwrap(),
                22,
                &"ff:ee:dd:cc:bb:aa".parse().unwrap(),
                &"2001:db8::1234:4444".parse().unwrap(),
                22,
            )
        };

        assert!(ipv4_packet(&[]));
        assert!(ipv6_packet(&[]));

        assert!(ipv6_packet(&["2001:db8::4321:1313"]));
        assert!(ipv6_packet(&["2001:db8::1234:4444"]));

        assert!(ipv4_packet(&["192.168.1.1"]));
        assert!(ipv4_packet(&["10.0.0.5"]));
        assert!(!ipv4_packet(&["192.168.100.100"]));
        assert!(ipv4_packet(&["10.0.0.0/8"]));
        assert!(ipv4_packet(&["192.168.0.0/16"]));
        assert!(!ipv4_packet(&["10.0.0.0:22"]));
        assert!(ipv4_packet(&["10.0.0.5:22"]));
        assert!(!ipv4_packet(&["192.168.0.0:22"]));
        assert!(ipv4_packet(&["192.168.1.1:22"]));
        assert!(ipv4_packet(&["192.168.1.1/16:22"]));
        assert!(ipv4_packet(&["10.0.0.0/8:22"]));
        assert!(ipv4_packet(&["10.0.0.0/8:22,2222"]));
        assert!(ipv4_packet(&["10.0.0.0/8:20-25"]));
        assert!(ipv4_packet(&["10.0.0.0/8:20-65535"]));
        assert!(ipv4_packet(&["10.0.0.0/8:-22"]));
        assert!(!ipv4_packet(&["192.168.100.1/24:-22"]));

        assert!(!ipv4_packet(&["@192.168.1.1"]));
        assert!(!ipv4_packet(&["^10.0.0.5"]));
        assert!(!ipv4_packet(&["@192.168.100.100"]));
        assert!(!ipv4_packet(&["^10.0.0.0/8"]));
        assert!(!ipv4_packet(&["@192.168.0.0/16"]));
        assert!(!ipv4_packet(&["^10.0.0.0:22"]));
        assert!(!ipv4_packet(&["^10.0.0.5:22"]));
        assert!(!ipv4_packet(&["@192.168.0.0:22"]));
        assert!(!ipv4_packet(&["@192.168.1.1:22"]));
        assert!(!ipv4_packet(&["@192.168.1.1/16:22"]));
        assert!(!ipv4_packet(&["^10.0.0.0/8:22"]));
        assert!(!ipv4_packet(&["^10.0.0.0/8:22,2222"]));
        assert!(!ipv4_packet(&["^10.0.0.0/8:20-25"]));
        assert!(!ipv4_packet(&["^10.0.0.0/8:20-65535"]));
        assert!(!ipv4_packet(&["^10.0.0.0/8:-22"]));
        assert!(!ipv4_packet(&["@192.168.100.1/24:-22"]));

        assert!(ipv4_packet(&["^192.168.1.1"]));
        assert!(ipv4_packet(&["@10.0.0.5"]));
        assert!(!ipv4_packet(&["^192.168.100.100"]));
        assert!(ipv4_packet(&["@10.0.0.0/8"]));
        assert!(ipv4_packet(&["^192.168.0.0/16"]));
        assert!(!ipv4_packet(&["@10.0.0.0:22"]));
        assert!(ipv4_packet(&["@10.0.0.5:22"]));
        assert!(!ipv4_packet(&["^192.168.0.0:22"]));
        assert!(ipv4_packet(&["^192.168.1.1:22"]));
        assert!(ipv4_packet(&["^192.168.1.1/16:22"]));
        assert!(ipv4_packet(&["@10.0.0.0/8:22"]));
        assert!(ipv4_packet(&["@10.0.0.0/8:22,2222"]));
        assert!(ipv4_packet(&["@10.0.0.0/8:20-25"]));
        assert!(ipv4_packet(&["@10.0.0.0/8:20-65535"]));
        assert!(ipv4_packet(&["@10.0.0.0/8:-22"]));
        assert!(!ipv4_packet(&["^192.168.100.1/24:-22"]));

        assert!(ipv4_packet(&["10.0.0.0/8:-22", "192.168.1.1:22"]));
        assert!(ipv4_packet(&["10.0.0.0/8:-22", "192.168.100.1/24"]));
        assert!(!ipv4_packet(&["172.16.0.0/12", "192.168.100.1/24"]));
        assert!(ipv4_packet(&["172.16.0.0/12", "10.0.0.0/8"]));

        assert!(!ipv4_packet(&["@172.16.0.0/12^10.0.0.0/8"]));
        assert!(!ipv4_packet(&["@192.168.0.0/12^10.0.0.0/8"]));
        assert!(ipv4_packet(&["^192.168.0.0/12@10.0.0.0/8"]));
        assert!(ipv4_packet(&["^192.168.1.1:22@10.0.0.5"]));

        assert!(ipv4_packet(&["192.168.1.1:22=10.0.0.5"]));
        assert!(ipv4_packet(&["10.0.0.5:22=192.168.1.1"]));
    }
}
