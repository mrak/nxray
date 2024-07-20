use pest::error::Error;
use pest::error::ErrorVariant;
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
    ARP,
}

impl FromStr for Protocol {
    type Err = ();
    fn from_str(input: &str) -> Result<Protocol, Self::Err> {
        match input {
            "tcp" => Ok(Protocol::TCP),
            "udp" => Ok(Protocol::UDP),
            "icmp" => Ok(Protocol::ICMP),
            "arp" => Ok(Protocol::ARP),
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
pub enum Argument<'a> {
    Pcap,
    Interface(&'a str),
    ProtocolFlag(Protocol),
    FilterExpr(Filter),
}

pub fn parse_arg(argstr: &str) -> Result<Argument, Error<Rule>> {
    fn parse_port(arg: Pair<Rule>) -> Result<u16, Error<Rule>> {
        arg.as_str().parse::<u16>().or_else(|e| {
            Err(Error::new_from_span(ErrorVariant::<Rule>::CustomError {
                message : e.to_string()
            }, arg.as_span()))
        })
    }

    fn parse_port_opt(arg: Pair<Rule>) -> Result<PortOption, Error<Rule>> {
        let opt = arg.into_inner().next().unwrap();
        Ok(match opt.as_rule() {
            Rule::port => PortOption::Specific(opt.as_str().parse::<u16>().unwrap()),
            Rule::port_list => PortOption::List(opt.into_inner().map(parse_port).collect::<Result<Vec<u16>, Error<Rule>>>()?),
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

    fn parse_ip6_mask(arg: Pair<Rule>) -> Result<Ipv6Addr, Error<Rule>> {
        let mut bitmask: u128 = u128::MAX;
        let mask_int = arg
            .as_str()
            .strip_prefix("/")
            .unwrap()
            .parse::<usize>()
            .or_else(|e| {
                Err(Error::new_from_span(ErrorVariant::<Rule>::CustomError {
                    message : e.to_string()
                }, arg.as_span()))
            })?;
        if mask_int > 128 {
            return Err(Error::new_from_span(ErrorVariant::<Rule>::CustomError {
                message : format!("CIDR must between 0 and 128")
            }, arg.as_span()))
        }
        let count = 128 - mask_int;
        bitmask = bitmask << count;
        Ok(Ipv6Addr::from(bitmask))
    }

    fn parse_ip4_mask(arg: Pair<Rule>) -> Result<Ipv4Addr, Error<Rule>> {
        let mut bitmask: u32 = u32::MAX;
        let mask_int = arg
            .as_str()
            .strip_prefix("/")
            .unwrap()
            .parse::<usize>()
            .or_else(|e| {
                Err(Error::new_from_span(ErrorVariant::<Rule>::CustomError {
                    message : e.to_string()
                }, arg.as_span()))
            })?;
        if mask_int > 32 {
            return Err(Error::new_from_span(ErrorVariant::<Rule>::CustomError {
                message : format!("CIDR mask must between 0 and 32")
            }, arg.as_span()))
        }
        let count = 32 - mask_int;
        bitmask = bitmask << count;
        Ok(Ipv4Addr::from(bitmask))
    }

    fn parse_ip4_address(arg: Pair<Rule>) -> Result<Address, Error<Rule>> {
        let mut inner = arg.clone().into_inner();
        let mut port_opt = PortOption::Range(1, u16::MAX);
        let mut mask = Ipv4Addr::from(u32::MAX);
        let ip_str = inner.next().unwrap().as_str();
        let mut ip = ip_str.parse::<Ipv4Addr>().or_else(|e| {
            Err(Error::new_from_span(ErrorVariant::<Rule>::CustomError {
                message : e.to_string()
            }, arg.as_span()))
        })?;
        while let Some(n) = inner.next() {
            match n.as_rule() {
                Rule::mask => {
                    mask = parse_ip4_mask(n)?;
                    ip = ip & mask;
                }
                Rule::port_opt => port_opt = parse_port_opt(n)?,
                _ => unreachable!(),
            }
        }
        Ok(Address::IP(IpAddr::V4(ip), IpAddr::V4(mask), port_opt))
    }

    fn parse_ip6_address(arg: Pair<Rule>) -> Result<Address, Error<Rule>> {
        let mut inner = arg.clone().into_inner();
        let mut port_opt = PortOption::Range(1, u16::MAX);
        let mut mask = Ipv6Addr::from(u128::MAX);
        let ip_str = inner.next().unwrap().as_str();
        let mut ip = ip_str.parse::<Ipv6Addr>().or_else(|e| {
            Err(Error::new_from_span(ErrorVariant::<Rule>::CustomError {
                message : e.to_string()
            }, arg.as_span()))
        })?;
        while let Some(n) = inner.next() {
            match n.as_rule() {
                Rule::mask => {
                    mask = parse_ip6_mask(n)?;
                    ip = ip & mask;
                }
                Rule::port_opt => port_opt = parse_port_opt(n)?,
                _ => unreachable!(),
            }
        }
        Ok(Address::IP(IpAddr::V6(ip), IpAddr::V6(mask), port_opt))
    }

    fn parse_address(arg: Pair<Rule>) -> Result<Address, Error<Rule>> {
        let a = arg.into_inner().next().unwrap();
        match a.as_rule() {
            Rule::port_opt => Ok(Address::PortOnly(parse_port_opt(a)?)),
            Rule::ipv4_address => parse_ip4_address(a),
            Rule::ipv6_address => parse_ip6_address(a),
            Rule::mac_address => Ok(Address::MAC(a.as_str().parse::<MacAddr>().unwrap())),
            _ => unreachable!(),
        }
    }

    fn parse_anchor_address(arg: Pair<Rule>) -> Result<(PacketDirection, Address), Error<Rule>> {
        let mut inner = arg.into_inner();
        let direction = match inner.next().unwrap().into_inner().next().unwrap().as_rule() {
            Rule::source => PacketDirection::Source,
            Rule::destination => PacketDirection::Destination,
            _ => unreachable!(),
        };
        let address = parse_address(inner.next().unwrap())?;
        Ok((direction, address))
    }

    let arg = ARGParser::parse(Rule::argument, argstr)?
        .next()
        .unwrap()
        .into_inner()
        .next()
        .unwrap();

    return Ok(match arg.as_rule() {
        Rule::pcap => Argument::Pcap,
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
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::TCP));
        let result = parse_arg("udp");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::UDP));
        let result = parse_arg("icmp");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::ICMP));
        let result = parse_arg("arp");
        assert_eq!(result.unwrap(), Argument::ProtocolFlag(Protocol::ARP));
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
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                        PortOption::Range(1, u16::MAX),
                    )
            ))
        );
        let result = parse_arg("192.168.1.1:8080");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                    PacketDirection::Either,
                    Address::IP(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
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
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
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
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)),
                        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                        PortOption::Range(1, u16::MAX),
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
                        IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                        IpAddr::V6(Ipv6Addr::from(0xffc00000000000000000000000000000_u128)),
                        PortOption::Range(1, u16::MAX),
                    )
            ))
        );
        let result = parse_arg("[fe80::/10]");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                    PacketDirection::Either,
                    Address::IP(
                        IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                        IpAddr::V6(Ipv6Addr::from(0xffc00000000000000000000000000000_u128)),
                        PortOption::Range(1, u16::MAX),
                    )
            ))
        );
        let result = parse_arg("[fe80::]:944");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                    PacketDirection::Either,
                    Address::IP(
                        IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                        IpAddr::V6(Ipv6Addr::from(u128::MAX)),
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
                        IpAddr::V6(Ipv6Addr::from(0xfe800000000000000000000000000000_u128)),
                        IpAddr::V6(Ipv6Addr::from(0xffffffffffffffff0000000000000000_u128)),
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
                    Address::MAC(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            ))
        );
        let result = parse_arg("@aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                    PacketDirection::Destination,
                    Address::MAC(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
            ))
        );
        let result = parse_arg("aa:bb:cc:dd:ee:ff");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::AddressFilter(
                    PacketDirection::Either,
                    Address::MAC(MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff))
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
            ))
        );
        let result = parse_arg("192.168.1.1/24:53=192.168.100.100/24");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::PacketFilter(
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
            ))
        );
        let result = parse_arg("^192.168.1.1/24:53@192.168.100.100/24");
        assert_eq!(
            result.unwrap(),
            Argument::FilterExpr(Filter::PacketFilter(
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
            ))
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
