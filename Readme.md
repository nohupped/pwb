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

Encryption:

This is all wrong.
Use a username and password.
Use username as the salt
password as the key
use PBKDF2-HMAC algorithm with a digest function to convert it into an aes256 key
Use that key to encrypt the string

Crates to be used: https://docs.rs/openssl/0.9.24/openssl/aes/index.html, https://docs.rs/openssl/0.9.24/openssl/pkcs5/index.html

// use ring instead 


Bibliography: 
https://en.wikipedia.org/wiki/AES_key_schedule
https://en.wikipedia.org/wiki/Key_schedule
https://en.wikipedia.org/wiki/PBKDF2
    // aes128 = 16 byte key, aes192 = 24, aes256 = 32 byte key
    // Block size always remain 128 bit (16 byte)