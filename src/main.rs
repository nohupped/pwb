mod helpers;
use helpers::parse_params;
mod interactive;
mod crypt;
use interactive::shell;
fn main() {
    let mut x = parse_params();
    if x.interactive {
        shell::shell(&mut x);
    }

}
