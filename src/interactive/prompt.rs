use crate::helpers;
pub(crate) static PROMPT: &str = "pwb://";
pub(crate) static BANNER: &str = r#"_____                                   _  ______             _    
| ___ \                                 | | | ___ \           | |   
| |_/ __ _ ___ _____      _____  _ __ __| | | |_/ / __ _ _ __ | | __
|  __/ _` / __/ __\ \ /\ / / _ \| '__/ _` | | ___ \/ _` | '_ \| |/ /
| | | (_| \__ \__ \\ V  V | (_) | | | (_| | | |_/ | (_| | | | |   < 
\_|  \__,_|___|___/ \_/\_/ \___/|_|  \__,_| \____/ \__,_|_| |_|_|\_\


Press /h for all commands.
"#;

pub(crate) fn print_banner() {
    print!("{}[2J", 27 as char);
    print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
    println!("{}\n",BANNER);
}

pub(crate) fn prompt_builder(c: &helpers::Config) -> String {
    if crate::interactive::commands::PBKDF2_HASH.read().unwrap().len() == 0 {
    format!("(Locked) {}{} > ", PROMPT, c.datafile)
    } else {
        format!("(Unlocked) {}{} > ", PROMPT, c.datafile)
    }
}