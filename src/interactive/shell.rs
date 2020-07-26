//! shell contains the minimal interactive shell that the user gets, to interact with
//! this program. From an end user, use /h to view all subcommands.
//! Commands supported:

// TODO: 


use crate::{helpers, interactive::{prompt, commands::{ALLCOMMANDS, build_all_commands}}};

use prompt::{print_banner, prompt_builder};

// Todo: Add a toml reference to the config for updating the recently used data file and to change the default one
#[derive(Debug)]
pub(crate) struct InteractiveMeta <'a> {
    pub(crate) command: Option<&'a str>,
    pub(crate) params: Option<&'a [&'a str]>,
}

pub fn shell(mut c: &mut helpers::Config) {
    print_banner();
    std::fs::OpenOptions::new()
        .create_new(false)
        .write(true)
        .open(&c.conffile)
        .unwrap();

    let mut detailed_prompt = prompt_builder(&c);

    build_all_commands();

    loop {
        print!("{}", detailed_prompt);
        std::io::Write::flush(&mut std::io::stdout()).expect("flush failed!");
        println!("{}", input( &mut c));
        detailed_prompt = prompt_builder(&c);
    }
}

fn input( mut config: &mut helpers::Config) -> String {
    let mut ret = String::new();
    // Read user input to ret
    std::io::stdin()
        .read_line(&mut ret)
        .expect("Failed to read from stdin");
    // Split command and parameters
    let command_vector = ret.split(" ").collect::<Vec<&str>>();
    let mut metadata;
    // let (command, params);
    if command_vector.len() > 1 {
        metadata = InteractiveMeta{
            command: Some(command_vector[0]),
            params: Some(&command_vector[1..]),
        };
    } else {
        metadata = InteractiveMeta{
            command: Some(command_vector[0]),
            params: None,
        };

    }
    
    match ALLCOMMANDS.read().unwrap().iter().find(|cmd| cmd.name == metadata.command.unwrap().trim()) {
        Some(a) => {
            let x = a.action;
            match x(&mut config, &mut metadata) {
                Some(val) => val,
                None => {
                    println!("Quitting on the command {:?}. If you think this is a bug, file an issue at https://github.com/nohupped/pwb/issues", ret.trim());
                    std::process::exit(1)
                }
            }
            
        },
        None => {
            "Command not found.".to_string()},
    }

}
