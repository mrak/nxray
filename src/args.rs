use pest::error::Error;
use pest::error::ErrorVariant;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use pnet::datalink::MacAddr;
use pnet::ipnetwork::IpNetwork;
use pnet::ipnetwork::Ipv4Network;
use pnet::ipnetwork::Ipv6Network;
use std::str::FromStr;

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn version() {
    println!("nx version {}", VERSION);
}

pub fn usage() {
    version();
    println!("Usage: nx [OPTION..] [FILTER_EXPRESSION..] [--] [INTERFACE_NAME..]");
    println!();
    println!("OPTIONS");
    println!();
    println!("pcap                   TODO: output in pcap format.");
    println!("                       Redirecting STDOUT to a file is assumed");
    println!();
    println!("protocol OPTIONS: if none are specificied, all are shown");
    println!("tcp                    show TCP packets");
    println!("udp                    show UDP packets");
    println!("icmp                   show ICMP packets");
    println!("arp                    show ARP packets");
    println!("ipip                   show Ip-in-Ip packets");
    println!();
    println!("FILTER_EXPRESSIONS");
    println!();
    println!("MAC Address match      MAC_ADDRESS");
    println!("Port match             :PORT");
    println!("Address match          IP_ADDRESS");
    println!("CIDR                   IP_ADDRESS/MASK");
    println!("CIDR with port         IP_ADDRESS/MASK:PORT");
    println!();
    println!("any of the above replaces ... below");
    println!();
    println!("Src match              ^...");
    println!("Dst match              @...");
    println!("Src AND Dst            @...^...");
    println!("Src <=> Dst            ...=...");
    println!();
    println!("INTERFACE_NAME");
    println!();
    println!("Any argument not matching the above is assumed to be an interface name.");
    println!("Arguments after -- are ONLY interpreted as interface names. This allows");
    println!("the use of interface names that conflict with an argument.");
}

#[derive(Parser)]
#[grammar = "args.pest"]
pub struct ARGParser;

#[derive(PartialEq, Debug)]
pub enum PortOption {
    Specific(u16),
    List(Vec<u16>),
    Range(u16, u16),
    Any,
}

#[derive(PartialEq, Debug)]
pub enum Address {
    Mac(MacAddr),
    IP(IpNetwork, PortOption),
    PortOnly(PortOption),
}

#[derive(PartialEq, Debug)]
pub enum PacketDirection {
    Source,
    Destination,
    Either,
}

#[derive(PartialEq, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Arp,
    IpIp,
}

impl FromStr for Protocol {
    type Err = ();
    fn from_str(input: &str) -> Result<Protocol, Self::Err> {
        match input {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "arp" => Ok(Protocol::Arp),
            "ipip" => Ok(Protocol::IpIp),
            _ => Err(()),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum Filter {
    AddressFilter(PacketDirection, Address),
    PacketFilter(PacketDirection, Address, PacketDirection, Address),
}

#[derive(PartialEq, Debug)]
pub enum Argument {
    Version,
    Emdash,
    Short,
    Help,
    Pcap,
    Interface(String),
    ProtocolFlag(Protocol),
    FilterExpr(Filter),
}

fn parse_port(arg: Pair<Rule>) -> Result<u16, Box<Error<Rule>>> {
    Ok(arg.as_str().parse::<u16>().map_err(|e| {
        Error::new_from_span(
            ErrorVariant::<Rule>::CustomError {
                message: e.to_string(),
            },
            arg.as_span(),
        )
    })?)
}

fn parse_port_opt(arg: Pair<Rule>) -> Result<PortOption, Box<Error<Rule>>> {
    let opt = arg.into_inner().next().unwrap();
    Ok(match opt.as_rule() {
        Rule::port => PortOption::Specific(opt.as_str().parse::<u16>().unwrap()),
        Rule::port_list => PortOption::List(
            opt.into_inner()
                .map(parse_port)
                .collect::<Result<Vec<u16>, Box<Error<Rule>>>>()?,
        ),
        Rule::port_range_lower => {
            PortOption::Range(0, opt.into_inner().as_str().parse::<u16>().unwrap())
        }
        Rule::port_range_upper => {
            PortOption::Range(opt.into_inner().as_str().parse::<u16>().unwrap(), u16::MAX)
        }
        Rule::port_range_bounded => {
            let mut inner = opt.into_inner();
            let lower = parse_port(inner.next().unwrap())?;
            let upper = parse_port(inner.next().unwrap())?;
            PortOption::Range(lower, upper)
        }
        _ => unreachable!(),
    })
}

fn parse_ip4_address(arg: Pair<Rule>) -> Result<Address, Box<Error<Rule>>> {
    let mut inner = arg.clone().into_inner();
    let mut port_opt = PortOption::Any;
    let ip_str = inner.next().unwrap().as_str();
    let ip = ip_str.parse::<Ipv4Network>().map_err(|e| {
        Error::new_from_span(
            ErrorVariant::<Rule>::CustomError {
                message: e.to_string(),
            },
            arg.as_span(),
        )
    })?;
    if let Some(n) = inner.next() {
        port_opt = parse_port_opt(n)?
    }
    Ok(Address::IP(IpNetwork::V4(ip), port_opt))
}

fn parse_ip6_address(arg: Pair<Rule>) -> Result<Address, Box<Error<Rule>>> {
    let mut inner = arg.clone().into_inner();
    let mut port_opt = PortOption::Any;
    let ip_str = inner.next().unwrap().as_str();
    let ip = ip_str.parse::<Ipv6Network>().map_err(|e| {
        Error::new_from_span(
            ErrorVariant::<Rule>::CustomError {
                message: e.to_string(),
            },
            arg.as_span(),
        )
    })?;
    if let Some(n) = inner.next() {
        port_opt = parse_port_opt(n)?
    }
    Ok(Address::IP(IpNetwork::V6(ip), port_opt))
}

fn parse_address(arg: Pair<Rule>) -> Result<Address, Box<Error<Rule>>> {
    let a = arg.into_inner().next().unwrap();
    match a.as_rule() {
        Rule::port_opt => Ok(Address::PortOnly(parse_port_opt(a)?)),
        Rule::ipv4_address => parse_ip4_address(a),
        Rule::ipv6_address => parse_ip6_address(a),
        Rule::mac_address => Ok(Address::Mac(a.as_str().parse::<MacAddr>().unwrap())),
        _ => unreachable!(),
    }
}

fn parse_anchor_address(arg: Pair<Rule>) -> Result<(PacketDirection, Address), Box<Error<Rule>>> {
    let mut inner = arg.into_inner();
    let direction = match inner.next().unwrap().into_inner().next().unwrap().as_rule() {
        Rule::source => PacketDirection::Source,
        Rule::destination => PacketDirection::Destination,
        _ => unreachable!(),
    };
    let address = parse_address(inner.next().unwrap())?;
    Ok((direction, address))
}

pub fn parse_arg(argstr: &str) -> Result<Argument, Box<Error<Rule>>> {
    let arg = ARGParser::parse(Rule::argument, argstr)?
        .next()
        .unwrap()
        .into_inner()
        .next()
        .unwrap();

    return Ok(match arg.as_rule() {
        Rule::pcap => Argument::Pcap,
        Rule::short => Argument::Short,
        Rule::version => Argument::Version,
        Rule::help => Argument::Help,
        Rule::protocol => Argument::ProtocolFlag(Protocol::from_str(arg.as_str()).unwrap()),
        Rule::address => Argument::FilterExpr(Filter::AddressFilter(
            PacketDirection::Either,
            parse_address(arg)?,
        )),
        Rule::anchor_address => {
            let (direction, address) = parse_anchor_address(arg)?;
            Argument::FilterExpr(Filter::AddressFilter(direction, address))
        }
        Rule::packet_anchored => {
            let mut inner = arg.into_inner();
            let (one_dir, one_addr) = parse_anchor_address(inner.next().unwrap())?;
            let (two_dir, two_addr) = parse_anchor_address(inner.next().unwrap())?;
            Argument::FilterExpr(Filter::PacketFilter(one_dir, one_addr, two_dir, two_addr))
        }
        Rule::packet_between => {
            let mut inner = arg.into_inner();
            let first = inner.next().unwrap();
            let second = inner.next().unwrap();
            Argument::FilterExpr(Filter::PacketFilter(
                PacketDirection::Either,
                parse_address(first)?,
                PacketDirection::Either,
                parse_address(second)?,
            ))
        }
        Rule::emdash => Argument::Emdash,
        Rule::interface => Argument::Interface(arg.as_str().to_owned()),
        _ => unreachable!(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn pcap() {
        let result = parse_arg("pcap");
        assert_eq!(result.unwrap(), Argument::Pcap);
    }

    #[test]
    fn protocol() {
        let result = parse_arg("tcp");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::Tcp));
        let result = parse_arg("udp");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::Udp));
        let result = parse_arg("icmp");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::Icmp));
        let result = parse_arg("arp");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::Arp));
        let result = parse_arg("ipip");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::IpIp));
    }

    #[test]
    fn port() {
        let result = parse_arg("^:8080");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Source,
                Address::PortOnly(PortOption::Specific(8080))
            ))
        );
        let result = parse_arg("@:8080");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Destination,
                Address::PortOnly(PortOption::Specific(8080))
            ))
        );
        let result = parse_arg(":8080");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Specific(8080))
            ))
        );
        let result = parse_arg(":80,443");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::List(vec!(80, 443)))
            ))
        );
        let result = parse_arg(":80,443,8080,8443");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::List(vec!(80, 443, 8080, 8443)))
            ))
        );
        let result = parse_arg(":1000-2000");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Range(1000, 2000))
            ))
        );
        let result = parse_arg(":-2000");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Range(0, 2000))
            ))
        );
        let result = parse_arg(":1000-");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Range(1000, u16::MAX))
            ))
        );
    }

    #[test]
    fn ipv4() {
        let result = parse_arg("192.168.1.1");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap()),
                    PortOption::Any,
                )
            ))
        );
        let result = parse_arg("192.168.1.1:8080");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap()),
                    PortOption::Specific(8080),
                )
            ))
        );
        let result = parse_arg("192.168.1.1/24:8080");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
                    PortOption::Specific(8080),
                )
            ))
        );
        let result = parse_arg("192.168.1.1/24");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
                    PortOption::Any,
                )
            ))
        );
    }

    #[test]
    fn ipv6() {
        let result = parse_arg("fe80::/10");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V6(
                        Ipv6Network::new(
                            Ipv6Addr::from(0xfe800000000000000000000000000000_u128),
                            10
                        )
                        .unwrap()
                    ),
                    PortOption::Any,
                )
            ))
        );
        let result = parse_arg("[fe80::/10]");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V6(
                        Ipv6Network::new(
                            Ipv6Addr::from(0xfe800000000000000000000000000000_u128),
                            10
                        )
                        .unwrap()
                    ),
                    PortOption::Any,
                )
            ))
        );
        let result = parse_arg("[fe80::]:944");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V6(
                        Ipv6Network::new(
                            Ipv6Addr::from(0xfe800000000000000000000000000000_u128),
                            128
                        )
                        .unwrap()
                    ),
                    PortOption::Specific(944),
                )
            ))
        );
        let result = parse_arg("[fe80::/64]:944");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V6(
                        Ipv6Network::new(
                            Ipv6Addr::from(0xfe800000000000000000000000000000_u128),
                            64
                        )
                        .unwrap()
                    ),
                    PortOption::Specific(944),
                )
            ))
        );
    }

    #[test]
    fn mac() {
        let result = parse_arg("^aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Source,
                Address::Mac(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            ))
        );
        let result = parse_arg("@aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Destination,
                Address::Mac(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            ))
        );
        let result = parse_arg("aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                PacketDirection::Either,
                Address::Mac(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            ))
        );
    }

    #[test]
    fn packet() {
        let result = parse_arg("192.168.1.1=192.168.1.100");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::PacketFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 32).unwrap()),
                    PortOption::Any,
                ),
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 100), 32).unwrap()),
                    PortOption::Any,
                ),
            ))
        );
        let result = parse_arg("192.168.1.1/24:53=192.168.100.100/24");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::PacketFilter(
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
                    PortOption::Specific(53),
                ),
                PacketDirection::Either,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 100, 100), 24).unwrap()),
                    PortOption::Any,
                ),
            ))
        );
        let result = parse_arg("^192.168.1.1/24:53@192.168.100.100/24");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::PacketFilter(
                PacketDirection::Source,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 1, 1), 24).unwrap()),
                    PortOption::Specific(53),
                ),
                PacketDirection::Destination,
                Address::IP(
                    IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 100, 100), 24).unwrap()),
                    PortOption::Any,
                ),
            ))
        );
    }

    #[test]
    fn version() {
        let result = parse_arg("version").unwrap();
        assert_eq!(Argument::Version, result);
        let result = parse_arg("-version").unwrap();
        assert_eq!(Argument::Version, result);
        let result = parse_arg("--version").unwrap();
        assert_eq!(Argument::Version, result);
        let result = parse_arg("-v").unwrap();
        assert_eq!(Argument::Version, result);
    }

    #[test]
    fn help() {
        let result = parse_arg("help").unwrap();
        assert_eq!(Argument::Help, result);
        let result = parse_arg("-help").unwrap();
        assert_eq!(Argument::Help, result);
        let result = parse_arg("--help").unwrap();
        assert_eq!(Argument::Help, result);
        let result = parse_arg("-h").unwrap();
        assert_eq!(Argument::Help, result);
    }

    #[test]
    fn interface() {
        let result = parse_arg("eth0");
        assert_eq!(result.unwrap(), Argument::Interface(String::from("eth0")));
        let result = parse_arg("docker0");
        assert_eq!(
            result.unwrap(),
            Argument::Interface(String::from("docker0"))
        );
    }
}
