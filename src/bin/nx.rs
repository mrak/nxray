use std::env;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "bin/nx.pest"]
pub struct ARGParser;

fn main() {
    for argument in env::args().skip(1) {
        println!("{argument}");
        let parse_result = ARGParser::parse(Rule::option, &argument);
        match parse_result {
            Ok(arg) => println!("{arg}"),
            Err(_) => println!(" Syntax error")
        }
        println!("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap() {
        let pair = ARGParser::parse(Rule::option, "pcap")
            .unwrap().next().unwrap();
        assert_eq!(pair.as_rule(), Rule::option);
        assert_eq!(pair.as_str(), "pcap");
        let mut inner = pair.into_inner();
        assert_eq!(inner.next().unwrap().as_rule(), Rule::pcap);
    }

    #[test]
    fn plus_icmp() {
        let pair = ARGParser::parse(Rule::option, "+icmp")
            .unwrap().next().unwrap();
        assert_eq!(pair.as_rule(), Rule::option);
        assert_eq!(pair.as_str(), "+icmp");

        let mut inner = pair.into_inner();
        let protocol_opt = inner.next().unwrap();
        assert_eq!(protocol_opt.as_rule(), Rule::protocol_opt);
        println!("{protocol_opt}");

        let mut inner = protocol_opt.into_inner();
        let on = inner.next().unwrap();
        assert_eq!(on.as_rule(), Rule::protocol_opt);
    }
}
