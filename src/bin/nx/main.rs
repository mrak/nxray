mod args;

use std::env;
use args::*;

fn main() {
    for argument in env::args().skip(1) {
        let parse_result = parse_arg(argument.as_str()).unwrap();
        println!("{parse_result:?}")
    }
}
