# A rust password bank to store passwords with a master key/password

## Features

- [x] Generate a default config at $HOME/.pwb/config.toml which stores path to the encrypted password bank
- [ ] open/close command to an encrypted password file
- [x] `/h` command to list all supported commands
- [ ] Support multi encryption with more than one password to make brute force harder
- [ ] Create new sections for passwords
- [ ] Save new passwords
- [ ] Erase clipboard after delay (Display with a fancy spinner)
- [ ] Interactive mode should have option to change to new pwb db (A command that modifies the toml like update_db_path or something)
