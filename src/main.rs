mod helpers;
use helpers::{read_from_stdin, parse_params};
fn main() {
    let x = parse_params();
    println!("{:?}", x);
    read_from_stdin();
}

