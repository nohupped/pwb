mod helpers;
use helpers::parse_params;
mod interactive;
mod crypt;
use interactive::shell;

#[macro_use]
extern crate serde_derive;

fn main() {
    let mut x = parse_params();
    if x.interactive {
        shell::shell(&mut x);
    }

}
