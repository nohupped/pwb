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
    pub(crate) static ref PBKDF2_HASH: RwLock<Vec<u8>> =  RwLock::new(Vec::new());


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
    pub(crate) fn select_command() -> Self {
        Command {
            name: "/select",
            description: "Selects an existing pwb encrypted file. Usage: /changedb /tmp/newdb.pwb. Note: This will not unlock the DB, just selects it",
            action: |c, meta| {
                if let Some(p) = meta.params {
                    let file_metadata = metadata(p[0].trim());
                    if file_metadata.is_ok() && file_metadata.unwrap().is_file() {
                        PBKDF2_HASH.write().unwrap().clear();
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

    pub(crate) fn unlock_command() -> Self {
        Command {
            name: "/unlock",
            description:
                "Unlocks the currently selected encrypted password db with a username and password",
            action: |c, _| {
                _unlock(c);
                return Some("".to_string());
            },
        }
    }

    pub(crate) fn get_command() -> Self{
        Command {
            name: "/get",
            description: "Gets the specified key from the encrypted database. Eg: /get server_password. Displays a key error if the key is not present",
            action: |c, m| {
                if let Some(p) =  m.params {
                    if PBKDF2_HASH.read().unwrap().len() == 0 {
                        return Some(format!("DB {:?} is not unlocked. Use /unlock command to unlock the selected db. Check /h for more.", c.datafile))
                    }
                    let mut data = crate::crypt::Data::new();
                    match data.get_key(p[0].to_string(), &PBKDF2_HASH.read().unwrap().to_vec(), c) {
                        Ok(a) => return {
                            println!("Value is {:?}", a);
                            Some(a)
                        },
                        Err(_) => return Some(format!("Key not found...")),
                    };

                } else {
                    Some(format!("You didn't give a key name. Check /h for usage."))
                }
            },
        }
    }

    pub(crate) fn put_command() -> Self{
        Command {
            name: "/put",
            description: "Put a specified password into encrypted database. Eg: /put server_password 98hy54@1!55. WARNING: This will overwrite the password if it already exists under that key",
            action: |c, m| {
                println!("{:?}", &m.params.unwrap().len());
                if let Some(p) =  m.params {
                    if p.len() != 2 {
                        return Some("You didn't give a key an value. Check /h for usage".to_string());
                    }
                    if PBKDF2_HASH.read().unwrap().len() == 0 {
                        return Some(format!("DB {:?} is not unlocked. Use /unlock command to unlock the selected db. Check /h for more.", c.datafile))
                    }
                    let mut data = crate::crypt::Data::new();
                    match data.put_key(p[0].to_string(), p[1].to_string(), &PBKDF2_HASH.read().unwrap().to_vec(), c) {
                        Ok(a) => {
                            return Some(a)
                        },
                        Err(_) => return Some(format!("Key not found.")),
                    };

                }else {
                    Some(format!("You didn't give a key name. Check /h for usage."))
                }
                
                // return Some(format!("You didn't give a key name. Check /h for usage."))
            },
        }
    }
}

fn _unlock(c: &Config) {
    PBKDF2_HASH.write().unwrap().clear();
    let mut creds: crate::crypt::Creds;

    creds = crate::crypt::Creds::ask_username_and_password(false);
    creds.generate_pbkdf2();
    let mut tmp_rwlock = PBKDF2_HASH.write().unwrap();
    tmp_rwlock.append(&mut creds.pbkdf2_hash);
    std::mem::drop(tmp_rwlock);
    let mut data = crate::crypt::Data::new();
    let hash = &PBKDF2_HASH.read().unwrap().to_vec();
    if match data.check_decryption_file(&hash, c) {
        Ok(a) => a,
        Err(err) => {
            println!("Unlocking and deserialising failed with error:\n{:?}. 
This indicates one of the following reasons.
1. your username/password is incorrect
2. your data file is corrupt
3. your pwb version is different from the one that created the data file. 
The technical difficulty makes it impossible for pwb to find which version 
of the program was used to encrypt this file. If the config file is not replaced by you, 
check the {:?} file to see the version, and download that release. Check help to see the github page to
find the releases.", err, &c.conffile);
            return;
        }
    } {
        println!("Unlocking {:?} succeeded", &c.datafile);
    } else {
        println!(
            "Unlocking {:?} failed. Check your username and password.",
            c.datafile
        );
    }
}

/// Unlock error when the db unlock fails
#[derive(Debug)]
struct CommandError {
    details: String,
}
impl CommandError {
    fn new(msg: &str) -> Self {
        Self {
            details: msg.to_string(),
        }
    }
}
impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.details)
    }
}
impl std::error::Error for CommandError {
    fn description(&self) -> &str {
        &self.details
    }
}

pub(crate) fn build_all_commands() {
    let mut tmp_rwlock = ALLCOMMANDS.write().unwrap();
    tmp_rwlock.push(Command::quit_command());
    tmp_rwlock.push(Command::select_command());
    tmp_rwlock.push(Command::unlock_command());
    tmp_rwlock.push(Command::get_command());
    tmp_rwlock.push(Command::put_command());

    // use this only at the last so that the commands are populated into the lazy_static.
    tmp_rwlock.push(Command::help_command());

    std::mem::drop(tmp_rwlock);
}
