use clap::{App, Arg};
use dirs;
use std::io;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub fn read_from_stdin() {
    print!("{}", VERSION);
    loop {
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                println!("{:?}", input.trim());
            }
            Err(err) => {
                println!("{:?}", err);
            }
        }
        drop(input);
    }
}

pub fn parse_params() -> Config {
    let matches = App::new("The Encrypted Password Bank")
                            .version(VERSION)
                            .author("nohupped")
                            .about("Stores your passwords in an encrypted file that can be retrieved with a master password")
                            .arg(Arg::with_name("get")
                                .short("g")
                                .long("get")
                                .value_name("eg:  -g bank:bank_password")
                                .help("get a stored password from a section. Erases itself from clipbpard after 15 seconds unless delay is called."))
                            .arg(Arg::with_name("delay")
                                .short("d")
                                .long("delay")
                                .value_name("15")
                                .help("delay in seconds"))
                            .arg(Arg::with_name("interactive")
                                .short("i")
                                .long("interactive")
                                .help("starts an interactive shell. When in shell, /h for subcommands.")
                                .required(false))
                            .arg(Arg::with_name("confdir")
                                .short("c")
                                .long("confdir")
                                .value_name("/home/user/.pwb")
                                .help("The directory where this program needs to look for the configuration.")).get_matches();

    let home_dir = dirs::home_dir();
    let current_dir = std::env::current_dir().unwrap().into_os_string().into_string().unwrap();
    let config = Config {
        delay: matches
            .value_of("delay")
            .unwrap_or("15")
            .to_string()
            .parse::<i64>()
            .unwrap(),
        get: matches.value_of("get").unwrap_or("").to_string(),
        interactive: matches.is_present("interactive"),
        homedir: match home_dir {
            Some(x) => x.into_os_string().into_string().unwrap(),
            None => current_dir,
        },
    };

    config
}

pub fn generate_default_config(c: Config) {}

#[derive(Debug)]
pub struct Config {
    pub delay: i64,
    pub get: String,
    pub interactive: bool,
    pub homedir: String,
}
