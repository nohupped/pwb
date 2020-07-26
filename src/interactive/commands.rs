//! commands crate builds all the commands and pushes it into a lazy_static global vector.
//! This vector holds struct Command that contains the name of the command, which is evaluated
//! by the shell crate against the user input to match the userinput, and if it matches, the
//! function pointer as a part of the Command struct is called.
//! Run the build_all_commands() function to initiate the global lazy_static vector.

use crate::helpers::Config;
use crate::interactive::shell;
use lazy_static;
use std::fs::metadata;
use std::sync::RwLock;

lazy_static::lazy_static! {

    /// This is a lazy_static global vector that is used to store
    /// all the commands that this interactive shell supports. This is initiated using the
    /// build_all_commands() function.
    #[derive(Debug, Copy, Clone)]
    pub(crate) static ref ALLCOMMANDS: RwLock<Vec<Command>> =  RwLock::new(Vec::new());

}

/// This is the basic structure for a command in this interactive shell.
pub(crate) struct Command {
    /// This field is evaluated against the user input to validate if it is a command that this shell supports.
    pub(crate) name: &'static str,
    /// A description of this command. This field is for displaying help about a command.
    pub(crate) description: &'static str,
    /// A function pointer that defines the action when this command is invoked.
    pub(crate) action: fn(config: &mut Config, meta: &mut shell::InteractiveMeta) -> Option<String>,
}

/// A Debug implementation for Command struct.
impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Debug:: {}, {}\n", self.name, self.description)
    }
}

impl Command {
    /// Generate the help command that acts upon /h userinput. This is called inside build_all_commands.
    pub fn help_command() -> Self {
        Command {
            name: "/h",
            description: "List all commands available in this shell",
            action: |_, _| {
                let tmp_rlock = &ALLCOMMANDS.read().unwrap();
                let mut help_s = String::new();
                for i in tmp_rlock.iter() {
                    help_s.push_str(&format!(
                        "Command: {}\nDescription: {}\n",
                        i.name, i.description
                    ));
                }
                Some(help_s)
            },
        }
    }
    /// Invoked upon /q userinput. This is called inside build_all_commands.
    pub(crate) fn quit_command() -> Self {
        Command {
            name: "/q",
            description: "Quit this shell",
            action: |_, meta| {
                println!(r#"Quitting on {:?}"#, meta.command.unwrap().trim());
                std::process::exit(1)
            },
        }
    }

    // Used to change to a different password db. The file (at least an empty one) and path must exist.
    pub(crate) fn change_db_command() -> Self {
        Command {
            name: "/changedb",
            description: "Change to another pwb encrypted file. Usage: /changedb /tmp/newdb.pwb",
            action: |c, meta| {
                if let Some(p) = meta.params {
                    let file_metadata = metadata(p[0].trim());
                    if file_metadata.is_ok() && file_metadata.unwrap().is_file() {
                        c.datafile = p[0].trim().to_string();
                        Some(format!(
                            "changed datafile to {:?}",
                            p[0].trim()
                        ))
                    } else {
                        Some(format!(
                            "ERROR:: {:?} is not a valid pwb file to use. Verify the path.",
                            p[0].trim()
                        ))
                    }
                } else {
                    Some(format!("Empty path. check /h for help"))
                }
            },
        }
    }
}

pub(crate) fn build_all_commands() {
    let mut tmp_rwlock = ALLCOMMANDS.write().unwrap();
    tmp_rwlock.push(Command::quit_command());
    tmp_rwlock.push(Command::change_db_command());
    tmp_rwlock.push(Command::help_command());

    std::mem::drop(tmp_rwlock);
}
