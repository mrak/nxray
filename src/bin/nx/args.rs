use std::str::FromStr;
use pest_derive::Parser;
use pest::error::Error;
use pest::Parser;

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
pub enum AddressType {
    MACAddress(u64), // 48 bit, really
    IPv4Address(IPv4Addr, IPv4Mask, PortOption),
    IPv6Address(IPv6Addr, IPv6Mask, PortOption),
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
    AddressFilter(Option<PacketDirection>, AddressType),
    SrcDstFilter(AddressType, AddressType), // src, dest
    BetweenFilter(AddressType, AddressType), // src or dest, src or dest
}

pub fn parse_arg(argstr: &str) -> Result<Argument, Error<Rule>> {
    let arg = ARGParser::parse(Rule::argument, argstr)?.next().unwrap().into_inner().next().unwrap();

    return Ok(match arg.as_rule() {
        Rule::pcap => Argument::Pcap,
        Rule::protocol_opt => {
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
        },
        Rule::interface => {
            Argument::Interface(arg.as_str())
        }
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
        let result = parse_arg("+tcp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::TCP, Some(true)));
        let result = parse_arg("-icmp");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::ICMP, Some(false)));
        let result = parse_arg("ethernet");
        assert_eq!(result.unwrap(), Argument::ProtocolOpt(Protocol::Ethernet, None));
    }

    #[test]
    fn interface() {
        let result = parse_arg("eth0");
        assert_eq!(result.unwrap(), Argument::Interface("eth0"));
    }
}
