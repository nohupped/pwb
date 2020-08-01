//! Contains a few helper functions that is used to read the command line arguments, init the program config
//! and to store the arguments everytime the program is run.

use crate::crypt;
use clap::{App, Arg};
use dirs;
use toml;

/// Read VERSION from Cargo Package Version
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

/// Parses the command line arguments, populates them in Config struct and if init is true, inits with the default configuration file.
pub fn parse_params() -> Config {
    let matches = App::new("The Encrypted Password Bank")
                            .version(VERSION)
                            .author("https://github.com/nohupped/pwb")
                            .about("Stores your passwords in an encrypted file that can be retrieved with a master password")
                            .arg(Arg::with_name("get")
                                .short("g")
                                .long("get")
                                .number_of_values(1)
                                .help("get a stored password associated with a key."))
                            .arg(Arg::with_name("allkeys")
                                .short("a")
                                .long("allkeys")
                                .required(false)
                                .help("forgot what the keyname was? Run this to get a clue on what keys you stored your passwords."))
                            .arg(Arg::with_name("put")
                                .short("p")
                                .long("put")
                                .value_name("server '!@355RRt'")
                                .number_of_values(2)
                                .help("Puts a password into the password db associated with a key."))
                            .arg(Arg::with_name("interactive")
                                .short("i")
                                .long("interactive")
                                .help("starts an interactive shell. When in shell, /h for subcommands.")
                                .required(false))
                            .arg(Arg::with_name("confdir")
                                .short("c")
                                .long("confdir")
                                .value_name("/home/user/.pwb")
                                .env("PWB_CONFDIR")
                                .help("The directory where this program needs to look for the configuration."))
                            .arg(Arg::with_name("init")
                                .long("init")
                                .required(false)
                                .help("Create default configuration."))
                            .arg(Arg::with_name("dump")
                                .long("dump_config")
                                .required(false)
                                .help("Dump the current config paths. This is no-op.")).get_matches();

    // Read Home directory from the env
    let home_dir = dirs::home_dir();
    // Read the current working directory. This will be used if the Home Directory returns None.
    let current_dir = std::env::current_dir()
        .unwrap()
        .into_os_string()
        .into_string()
        .unwrap();

    // Create an instance of the Config struct and populate the fields
    let mut config = Config {
        interactive: matches.is_present("interactive"),
        init: matches.is_present("init"),

        dump: matches.is_present("dump"),

        confdir: if matches.is_present("confdir") {
            format!(r#"{}"#, matches.value_of("confdir").unwrap().to_string())
        } else {
            match home_dir {
                Some(x) => format!(r#"{}/.pwb"#, x.into_os_string().into_string().unwrap()),
                None => format!(r#"{}/.pwb"#, current_dir),
            }
        },

        conffile: "".to_string(),
        datafile: "".to_string(),
    };
    config.datafile = format!(r#"{}/data/data.pwb"#, &config.confdir);
    config.conffile = format!(r#"{}/config.toml"#, &config.confdir);
    // Args parsing and action for get
    if matches.is_present("get") {
        let mut params_iter = match matches.values_of("get") {
            Some(a) => a,
            None => {
                println!("Received None value from parsing parameters. Check --help for usage.");
                std::process::exit(1)
            },
        };
        let mut creds = crate::crypt::Creds::ask_username_and_password(false);
        creds.generate_pbkdf2();
        let key = match crate::crypt::Data::get_key(
            params_iter.next().unwrap().to_string(),
            &creds.pbkdf2_hash.to_vec(),
            &creds.aes_iv.to_vec(),
            &config,
        ) {
            Ok(a) => a,
            Err(e) => {
                println!("Get encountered error. Error is: {:?}", e);
                std::process::exit(1)
            }
        };
        println!("{}", key);
        std::process::exit(0)
    }
    // Arg parsing for action get ends here

    // Args parsing and action for put 
    if matches.is_present("put") {
        let mut params_iter = match matches.values_of("put") {
            Some(a) => a,
            None => {
                println!("Received None value from parsing parameters. Check --help for usage.");
                std::process::exit(1)
            },
        };
        let mut creds = crate::crypt::Creds::ask_username_and_password(false);
        creds.generate_pbkdf2();
        match crate::crypt::Data::put_key(params_iter.next().unwrap().to_string(), params_iter.next().unwrap().to_string(), &creds.pbkdf2_hash, &creds.aes_iv, &config) {
            Ok(a) => {
                println!("{}", a);
                std::process::exit(0)
            },
            Err(e) => {
                println!("Error putting data into the datastore, {:?}", e);
                std::process::exit(1)
            },
        };
    }
    // Arg parsing for put ends here

    // Arg parsing for allkeys
    if matches.is_present("allkeys") {
        let mut creds = crate::crypt::Creds::ask_username_and_password(false);
        creds.generate_pbkdf2();
        let key = match crate::crypt::Data::get_all_keys(
            &creds.pbkdf2_hash.to_vec(),
            &creds.aes_iv.to_vec(),
            &config,
        ) {
            Ok(a) => a,
            Err(e) => {
                println!("Get encountered error. Error is: {:?}", e);
                std::process::exit(1)
            }
        };
        println!("{}", key);
        std::process::exit(0)
    }

    if config.init {
        generate_default_config(&mut config);
    }
    if config.dump {
        println!("{:?}", config)
    }
    config
}

pub fn generate_default_config(c: &mut Config) {
    // If the conf directory doesn't exist:
    if !std::path::Path::new(&c.confdir).exists() || !std::path::Path::new(&c.conffile).exists() {
        // Creates the data directory
        std::fs::create_dir_all(format!(r#"{}/data"#, c.confdir)).unwrap();
        println!("Created {:?}", &c.confdir);
        let mut toml_config = toml::map::Map::new();
        toml_config.insert("version".into(), VERSION.into());
        toml_config.insert("default_cryptfile".into(), c.datafile.clone().into());
        let mut section = toml::map::Map::new();
        section.insert("pwb".into(), toml::Value::Table(toml_config));
        println!(
            "Writing the following to {:?}\n{}",
            &c.conffile,
            toml::to_string(&toml::Value::Table(section.clone())).unwrap()
        );
        std::fs::write(
            &c.conffile,
            toml::to_string(&toml::Value::Table(section)).unwrap(),
        )
        .unwrap();
        println!("Created {:?}", &c.conffile);

        // Gets username and password
        let mut creds = crypt::Creds::ask_username_and_password(true);
        creds.generate_pbkdf2();
        let mut data = crypt::Data::new();
        match data.encrypt_with_pbkdf2_and_write(&creds.pbkdf2_hash, &creds.aes_iv, c) {
            Ok(a) => a,
            Err(e) => {
                println!("Error: {:?}", e);
                std::fs::remove_dir_all(&c.confdir).expect(&format!(
                    "Cannot clean {}. Remove it manually..",
                    &c.confdir
                ));
            }
        };

        println!("Created encrypted {:?}. This can be populated in the interactive mode. Check /h when in interactive mode.", &c.datafile);
        println!("Checking decryption test on file...");
        if match data.check_decryption_file(&creds.pbkdf2_hash, &creds.aes_iv, c) {
            Ok(a) => a,
            Err(e) => {
                println!("{:?}", e);
                false
            }
        } {
            println!("decryption succeeded")
        } else {
            println!("decryption failed...cleaning up");
            std::fs::remove_dir_all(&c.confdir).expect(&format!(
                "Cannot clean {}. Remove it manually..",
                &c.confdir
            ));
        }

        return;
    }
    // Else, do nothing
    println!("{:?} exists, remove it to re-init.", c.confdir);
}

/// Config struct holds the runtime configuration for this program, including the command line args.
/// This will be dumped as is, when the --dump command line flag is provided.
#[derive(Debug)]
pub struct Config {
    /// interactive is only a flag, which opens the program's own minimal shell, so we just needs to see if it is mentioned
    pub interactive: bool,
    /// init is a flag. This is used to initialise the program with the default config.toml file.
    /// If the directory already exists, it will not re-initiate. You have to manually delete
    /// the file to re-initiate. This is to prevent the program from accidentally deleting the
    /// encrypted password bank file.
    pub init: bool,
    /// dump is a flag. This just prints the current config this program is using.
    pub dump: bool,
    /// confdir is the path where the program tries to read the config.toml from.
    /// It tries to read if the confdir is explicitly specified as a commandline arg,
    /// and if not, reads the home directory environment, and if it is None, use the
    /// current working directory. Unless over-ridden, this defaults to $HOME/.pwb
    pub confdir: String,
    /// confFile is the path to the config file that this program reads upon execution.
    pub conffile: String,
    /// datafile is the encrypted file that this program stores the passwords into.
    pub datafile: String,
}
