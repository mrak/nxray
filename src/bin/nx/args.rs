use std::str::FromStr;
use pest_derive::Parser;
use pest::error::Error;
use pest::Parser;
use pest::iterators::Pair;

#[derive(Parser)]
#[grammar = "bin/nx/args.pest"]
pub struct ARGParser;

type IPv4Addr = u32;
type IPv4Mask = u32;
type IPv6Addr = u128;
type IPv6Mask = u128;

#[derive(PartialEq,Debug)]
pub enum PortOption {
    Specific(u16),
    List(Vec<u16>),
    Range(u16, u16),
    Any,
}

#[derive(PartialEq,Debug)]
pub enum Address {
    MAC(u64), // 48 bit, really
    IPv4(IPv4Addr, IPv4Mask, PortOption),
    IPv6(IPv6Addr, IPv6Mask, PortOption),
    PortOnly(PortOption),
}

#[derive(PartialEq,Debug)]
pub enum PacketDirection {
    Source,
    Destination,
    Either,
}

#[derive(PartialEq,Debug)]
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
            _ => Err(())
        }
    }
}

#[derive(PartialEq,Debug)]
pub enum Argument<'a> {
    Pcap,
    Interface(&'a str),
    ProtocolOpt(Protocol, Option<bool>),
    AddressFilter(PacketDirection, Address),
    SrcDstFilter(Address, Address), // src, dest
    BetweenFilter(Address, Address), // src or dest, src or dest
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

    fn parse_address(direction: PacketDirection, arg: Pair<Rule>) -> Argument {
        let a = arg.into_inner().next().unwrap();
        match a.as_rule() {
            Rule::port_opt => {
                let opt = a.into_inner().next().unwrap();
                let port_opt = match opt.as_rule() {
                    Rule::port => PortOption::Specific(opt.as_str().parse::<u16>().unwrap()),
                    Rule::port_list => PortOption::List(opt.into_inner().map(parse_port).collect()),
                    Rule::port_range_lower => PortOption::Range(0, opt.into_inner().as_str().parse::<u16>().unwrap()),
                    Rule::port_range_upper => PortOption::Range(opt.into_inner().as_str().parse::<u16>().unwrap(), u16::MAX),
                    Rule::port_range_bounded => {
                        let mut inner = opt.into_inner();
                        let lower = parse_port(inner.next().unwrap());
                        let upper = parse_port(inner.next().unwrap());
                        PortOption::Range(lower, upper)
                    },
                    _ => unreachable!()
                };
                Argument::AddressFilter(direction, Address::PortOnly(port_opt))
            },
            Rule::ipv4_address => todo!(),
            Rule::ipv6_address => todo!(),
            Rule::mac_address => todo!(),
            _ => unreachable!()
        }
    }

    //let one = ARGParser::parse(Rule::argument, argstr)?.next();
    //let mut two = one.clone().unwrap().into_inner();
    //let three = two.next().unwrap();
    //println!("\none:{one:?}\ntwo:{two:?}\nthree:{three:?}");
    let arg = ARGParser::parse(Rule::argument, argstr)?.next().unwrap().into_inner().next().unwrap();

    return Ok(match arg.as_rule() {
        Rule::pcap => Argument::Pcap,
        Rule::protocol_opt => parse_protocol_opt(arg),
        Rule::address => parse_address(PacketDirection::Either, arg),
        Rule::anchor_address => {
            let mut inner = arg.into_inner();
            let dir_arg = inner.next().unwrap();
            let addr_arg = inner.next().unwrap();
            let direction = match dir_arg.into_inner().next().unwrap().as_rule() {
                Rule::source => PacketDirection::Source,
                Rule::destination => PacketDirection::Destination,
                _ => unreachable!()
            };
            parse_address(direction, addr_arg)
        },
        Rule::interface => Argument::Interface(arg.as_str()),
        _ => todo!(),
    })
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
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::TCP, Some(false)));
        let result = parse_arg("+tcp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::TCP, Some(true)));
        let result = parse_arg("udp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::UDP, None));
        let result = parse_arg("-udp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::UDP, Some(false)));
        let result = parse_arg("+udp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::UDP, Some(true)));
        let result = parse_arg("icmp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::ICMP, None));
        let result = parse_arg("-icmp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::ICMP, Some(false)));
        let result = parse_arg("+icmp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::ICMP, Some(true)));
        let result = parse_arg("ethernet");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::Ethernet, None));
    }

    #[test]
    fn port() {
        let result = parse_arg("^:8080");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Source, Address::PortOnly(PortOption::Specific(8080))));
        let result = parse_arg("@:8080");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Destination, Address::PortOnly(PortOption::Specific(8080))));
        let result = parse_arg(":8080");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Either, Address::PortOnly(PortOption::Specific(8080))));
        let result = parse_arg(":80,443");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Either, Address::PortOnly(PortOption::List(vec!(80,443)))));
        let result = parse_arg(":80,443,8080,8443");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Either, Address::PortOnly(PortOption::List(vec!(80,443,8080,8443)))));
        let result = parse_arg(":1000-2000");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Either, Address::PortOnly(PortOption::Range(1000,2000))));
        let result = parse_arg(":-2000");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Either, Address::PortOnly(PortOption::Range(0,2000))));
        let result = parse_arg(":1000-");
        assert_eq!(result.unwrap(), Argument::AddressFilter(PacketDirection::Either, Address::PortOnly(PortOption::Range(1000,u16::MAX))));
    }

    #[test]
    fn ipv4() {
    }

    #[test]
    fn interface() {
        let result = parse_arg("eth0");
        assert_eq!(result.unwrap(), Argument::Interface("eth0"));
        let result = parse_arg("docker0");
        assert_eq!(result.unwrap(), Argument::Interface("docker0"));
    }
}
