//! shell contains the minimal interactive shell that the user gets, to interact with
//! this program. From an end user, use /h to view all subcommands.

use crate::{
    helpers,
    interactive::{
        commands::{build_all_commands, ALLCOMMANDS},
        prompt,
    },
};

use prompt::{print_banner, prompt_builder};

// Todo: Add a toml reference to the config for updating the recently used data file and to change the default one
#[derive(Debug)]
pub(crate) struct InteractiveMeta<'a> {
    pub(crate) command: Option<&'a str>,
    pub(crate) params: Option<&'a [&'a str]>,
    // pub(crate) data_needs_initialization: bool,
}

/// runs the shell.
pub fn shell(mut c: &mut helpers::Config) {
    print_banner();

    let mut detailed_prompt = prompt_builder(&c);

    build_all_commands();

    loop {
        print!("{}", detailed_prompt);
        std::io::Write::flush(&mut std::io::stdout()).expect("flush failed!");
        println!("{}", input(&mut c));
        detailed_prompt = prompt_builder(&c);
    }
}

fn input(mut config: &mut helpers::Config) -> String {
    let mut ret = String::new();
    // Read user input to ret
    let mut meta = InteractiveMeta {
        command: None,
        params: None,
    };
    std::io::stdin()
        .read_line(&mut ret)
        .expect("Failed to read from stdin");
    // Split command and parameters
    let command_vector = ret.split(" ").collect::<Vec<&str>>();

    // populate command and parameters into the struct
    if command_vector.len() > 1 {
        meta.command = Some(command_vector[0]);
        meta.params = Some(&command_vector[1..]);
    } else {
        meta.command = Some(command_vector[0]);
        meta.params = None;
    }

    match ALLCOMMANDS
        .read()
        .unwrap()
        .iter()
        .find(|cmd| cmd.name == meta.command.unwrap().trim())
    {
        Some(a) => {
            let x = a.action;
            match x(&mut config, &mut meta) {
                Some(val) => val,
                None => {
                    "".to_string()       
                }
            }
        }
        None => "Command not found.".to_string(),
    }
}
