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

## How encryption is implemented

- User will be asked to input a username and password.
- A PBKDF2_HMAC_SHA256 is used to compute a 16 bytes long PBKDF2 key with username as salt and password as key.
- Use this key to encrypt the userinput to AES-128 encrypted byte array and store it in a struct.
- Use serde to serialise this and store into disk.

## Decryption

- User will be asked to input a username and password.
- A PBKDF2_HMAC_SHA256 is used to compute a 16 byte long PBKDF2 key with username as salt and password as key.
- Use this key to decrypt the struct and read the struct

Crates used: ring = "0.16.15"

Bibliography:

[AES Key schedule](https://en.wikipedia.org/wiki/AES_key_schedule)
[Key schedule](https://en.wikipedia.org/wiki/Key_schedule)
[PBKDF2 Hashing](https://en.wikipedia.org/wiki/PBKDF2)

Todo: Support aes128 = 16 byte key, aes192 = 24, aes256 = 32 byte keys
Note: Block size always remain 128 bits (16 bytes), so the encryption has to be done in chunks if the password is > 16 bytes.
