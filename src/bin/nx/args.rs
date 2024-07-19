use pest::error::Error;
use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use pnet::datalink::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Parser)]
#[grammar = "bin/nx/args.pest"]
pub struct ARGParser;

#[derive(PartialEq, Debug)]
pub enum PortOption {
    Specific(u16),
    List(Vec<u16>),
    Range(u16, u16),
}

#[derive(PartialEq, Debug)]
pub enum Address {
    MAC(MacAddr),
    IP(IpAddr, IpAddr, PortOption),
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
    TCP,
    UDP,
    ICMP,
    Ethernet,
}

impl FromStr for Protocol {
    type Err = ();
    fn from_str(input: &str) -> Result<Protocol, Self::Err> {
        match input {
            "tcp" => Ok(Protocol::TCP),
            "udp" => Ok(Protocol::UDP),
            "icmp" => Ok(Protocol::ICMP),
            "ethernet" => Ok(Protocol::Ethernet),
            _ => Err(()),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum Argument<'a> {
    Pcap,
    Interface(&'a str),
    ProtocolOpt(Protocol, Option<bool>),
    AddressFilter(PacketDirection, Address),
    PacketFilter(PacketDirection, Address, PacketDirection, Address),
}

pub fn parse_arg(argstr: &str) -> Result<Argument, Error<Rule>> {
    fn parse_protocol_opt(arg: Pair<Rule>) -> Argument {
        let option = match arg.as_str().chars().nth(0) {
            Some('-') => Some(false),
            Some('+') => Some(true),
            _ => None,
        };
        let protocol = match option {
            Some(_) => Protocol::from_str(arg.as_str().get(1..).unwrap()).unwrap(),
            None => Protocol::from_str(arg.as_str()).unwrap(),
        };
        Argument::ProtocolOpt(protocol, option)
    }

    fn parse_port(arg: Pair<Rule>) -> u16 {
        arg.as_str().parse::<u16>().unwrap()
    }

    fn parse_port_opt(arg: Pair<Rule>) -> PortOption {
        let opt = arg.into_inner().next().unwrap();
        match opt.as_rule() {
            Rule::port => PortOption::Specific(opt.as_str().parse::<u16>().unwrap()),
            Rule::port_list => PortOption::List(opt.into_inner().map(parse_port).collect()),
            Rule::port_range_lower => {
                PortOption::Range(0, opt.into_inner().as_str().parse::<u16>().unwrap())
            }
            Rule::port_range_upper => {
                PortOption::Range(opt.into_inner().as_str().parse::<u16>().unwrap(), u16::MAX)
            }
            Rule::port_range_bounded => {
                let mut inner = opt.into_inner();
                let lower = parse_port(inner.next().unwrap());
                let upper = parse_port(inner.next().unwrap());
                PortOption::Range(lower, upper)
            }
            _ => unreachable!(),
        }
    }

    fn parse_ip6_mask(arg: Pair<Rule>) -> Ipv6Addr {
        let mut bitmask: u128 = u128::MAX;
        let mask_int = arg
            .as_str()
            .strip_prefix("/")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let count = 128 - mask_int;
        bitmask = bitmask << count;
        Ipv6Addr::from(bitmask)
    }

    fn parse_ip4_mask(arg: Pair<Rule>) -> Ipv4Addr {
        let mut bitmask: u32 = u32::MAX;
        let mask_int = arg
            .as_str()
            .strip_prefix("/")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let count = 32 - mask_int;
        bitmask = bitmask << count;
        Ipv4Addr::from(bitmask)
    }

    fn parse_ip4_address(arg: Pair<Rule>) -> Address {
        let mut inner = arg.into_inner();
        let mut port_opt = PortOption::Range(1, u16::MAX);
        let mut mask = Ipv4Addr::from(u32::MAX);
        let ip_str = inner.next().unwrap().as_str();
        let mut ip = ip_str.parse::<Ipv4Addr>().unwrap();
        while let Some(n) = inner.next() {
            match n.as_rule() {
                Rule::mask => {
                    mask = parse_ip4_mask(n);
                    ip = ip & mask;
                }
                Rule::port_opt => port_opt = parse_port_opt(n),
                _ => unreachable!(),
            }
        }
        Address::IP(IpAddr::V4(ip), IpAddr::V4(mask), port_opt)
    }

    fn parse_ip6_address(arg: Pair<Rule>) -> Address {
        let mut inner = arg.into_inner();
        let mut port_opt = PortOption::Range(1, u16::MAX);
        let mut mask = Ipv6Addr::from(u128::MAX);
        let ip_str = inner.next().unwrap().as_str();
        let mut ip = ip_str.parse::<Ipv6Addr>().unwrap();
        while let Some(n) = inner.next() {
            match n.as_rule() {
                Rule::mask => {
                    mask = parse_ip6_mask(n);
                    ip = ip & mask;
                }
                Rule::port_opt => port_opt = parse_port_opt(n),
                _ => unreachable!(),
            }
        }
        Address::IP(IpAddr::V6(ip), IpAddr::V6(mask), port_opt)
    }

    fn parse_address(arg: Pair<Rule>) -> Address {
        let a = arg.into_inner().next().unwrap();
        match a.as_rule() {
            Rule::port_opt => {
                let port_opt = parse_port_opt(a);
                Address::PortOnly(port_opt)
            }
            Rule::ipv4_address => parse_ip4_address(a),
            Rule::ipv6_address => parse_ip6_address(a),
            Rule::mac_address => Address::MAC(a.as_str().parse().unwrap()),
            _ => unreachable!(),
        }
    }

    fn parse_anchor_address(arg: Pair<Rule>) -> (PacketDirection, Address) {
        let mut inner = arg.into_inner();
        let direction = match inner.next().unwrap().into_inner().next().unwrap().as_rule() {
            Rule::source => PacketDirection::Source,
            Rule::destination => PacketDirection::Destination,
            _ => unreachable!(),
        };
        let address = parse_address(inner.next().unwrap());
        (direction, address)
    }

    let arg = ARGParser::parse(Rule::argument, argstr)?
        .next()
        .unwrap()
        .into_inner()
        .next()
        .unwrap();

    return Ok(match arg.as_rule() {
        Rule::pcap => Argument::Pcap,
        Rule::protocol_opt => parse_protocol_opt(arg),
        Rule::address => Argument::AddressFilter(PacketDirection::Either, parse_address(arg)),
        Rule::anchor_address => {
            let (direction, address) = parse_anchor_address(arg);
            Argument::AddressFilter(direction, address)
        }
        Rule::packet_anchored => {
            let mut inner = arg.into_inner();
            let (one_dir, one_addr) = parse_anchor_address(inner.next().unwrap());
            let (two_dir, two_addr) = parse_anchor_address(inner.next().unwrap());
            Argument::PacketFilter(one_dir, one_addr, two_dir, two_addr)
        }
        Rule::packet_between => {
            let mut inner = arg.into_inner();
            let first = inner.next().unwrap();
            let second = inner.next().unwrap();
            Argument::PacketFilter(
                PacketDirection::Either,
                parse_address(first),
                PacketDirection::Either,
                parse_address(second),
            )
        }
        Rule::interface => Argument::Interface(arg.as_str()),
        _ => unreachable!(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap() {
        let result = parse_arg("pcap");
        assert_eq!(result.unwrap(), Argument::Pcap);
    }

    #[test]
    fn protocol() {
        let result = parse_arg("tcp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::TCP, None));
        let result = parse_arg("-tcp");
        assert_eq!(
            result.unwrap(),
            Argument::ProtocolOpt(Protocol::TCP, Some(false))
        );
        let result = parse_arg("+tcp");
        assert_eq!(
            result.unwrap(),
            Argument::ProtocolOpt(Protocol::TCP, Some(true))
        );
        let result = parse_arg("udp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::UDP, None));
        let result = parse_arg("-udp");
        assert_eq!(
            result.unwrap(),
            Argument::ProtocolOpt(Protocol::UDP, Some(false))
        );
        let result = parse_arg("+udp");
        assert_eq!(
            result.unwrap(),
            Argument::ProtocolOpt(Protocol::UDP, Some(true))
        );
        let result = parse_arg("icmp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::ICMP, None));
        let result = parse_arg("-icmp");
        assert_eq!(
            result.unwrap(),
            Argument::ProtocolOpt(Protocol::ICMP, Some(false))
        );
        let result = parse_arg("+icmp");
        assert_eq!(
            result.unwrap(),
            Argument::ProtocolOpt(Protocol::ICMP, Some(true))
        );
        let result = parse_arg("ethernet");
        assert_eq!(
            result.unwrap(),
            Argument::ProtocolOpt(Protocol::Ethernet, None)
        );
    }

    #[test]
    fn port() {
        let result = parse_arg("^:8080");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Source,
                Address::PortOnly(PortOption::Specific(8080))
            )
        );
        let result = parse_arg("@:8080");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Destination,
                Address::PortOnly(PortOption::Specific(8080))
            )
        );
        let result = parse_arg(":8080");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Specific(8080))
            )
        );
        let result = parse_arg(":80,443");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::List(vec!(80, 443)))
            )
        );
        let result = parse_arg(":80,443,8080,8443");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::List(vec!(80, 443, 8080, 8443)))
            )
        );
        let result = parse_arg(":1000-2000");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Range(1000, 2000))
            )
        );
        let result = parse_arg(":-2000");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Range(0, 2000))
            )
        );
        let result = parse_arg(":1000-");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::PortOnly(PortOption::Range(1000, u16::MAX))
            )
        );
    }

    #[test]
    fn ipv4() {
        let result = parse_arg("192.168.1.1");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                    PortOption::Range(1, u16::MAX),
                )
            )
        );
        let result = parse_arg("192.168.1.1:8080");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                    PortOption::Specific(8080),
                )
            )
        );
        let result = parse_arg("192.168.1.1/24:8080");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    PortOption::Specific(8080),
                )
            )
        );
        let result = parse_arg("192.168.1.1/24");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    PortOption::Range(1, u16::MAX),
                )
            )
        );
    }

    #[test]
    fn ipv6() {
        let result = parse_arg("fe80::/10");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                    IpAddr::V6(Ipv6Addr::from(0xffc00000000000000000000000000000_u128)),
                    PortOption::Range(1, u16::MAX),
                )
            )
        );
        let result = parse_arg("[fe80::/10]");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                    IpAddr::V6(Ipv6Addr::from(0xffc00000000000000000000000000000_u128)),
                    PortOption::Range(1, u16::MAX),
                )
            )
        );
        let result = parse_arg("[fe80::]:944");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                    IpAddr::V6(Ipv6Addr::from(u128::MAX)),
                    PortOption::Specific(944),
                )
            )
        );
        let result = parse_arg("[fe80::/64]:944");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                    IpAddr::V6(Ipv6Addr::from(0xffffffffffffffff0000000000000000_u128)),
                    PortOption::Specific(944),
                )
            )
        );
    }

    #[test]
    fn mac() {
        let result = parse_arg("^aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Source,
                Address::MAC(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            )
        );
        let result = parse_arg("@aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Destination,
                Address::MAC(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            )
        );
        let result = parse_arg("aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::AddressFilter(
                PacketDirection::Either,
                Address::MAC(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            )
        );
    }

    #[test]
    fn packet() {
        let result = parse_arg("192.168.1.1=192.168.1.100");
        assert_eq!(
            result.unwrap(),
            Argument::PacketFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                    PortOption::Range(1, u16::MAX),
                ),
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                    PortOption::Range(1, u16::MAX),
                ),
            )
        );
        let result = parse_arg("192.168.1.1/24:53=192.168.100.100/24");
        assert_eq!(
            result.unwrap(),
            Argument::PacketFilter(
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    PortOption::Specific(53),
                ),
                PacketDirection::Either,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 100, 0)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    PortOption::Range(1, u16::MAX),
                ),
            )
        );
        let result = parse_arg("^192.168.1.1/24:53@192.168.100.100/24");
        assert_eq!(
            result.unwrap(),
            Argument::PacketFilter(
                PacketDirection::Source,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    PortOption::Specific(53),
                ),
                PacketDirection::Destination,
                Address::IP(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 100, 0)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    PortOption::Range(1, u16::MAX),
                ),
            )
        );
    }

    #[test]
    fn interface() {
        let result = parse_arg("eth0");
        assert_eq!(result.unwrap(), Argument::Interface("eth0"));
        let result = parse_arg("docker0");
        assert_eq!(result.unwrap(), Argument::Interface("docker0"));
    }
}
