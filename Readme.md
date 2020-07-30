# A rust password bank to store passwords with a master key/password

## Features

- [x] Generate a default config at $HOME/.pwb/config.toml which stores path to the encrypted password bank
- [ ] open/close command to an encrypted password file
- [x] `/h` command to list all supported commands
- [x] Take username and password to generate key and salt.
- [ ] Create new sections for passwords
- [ ] Save new passwords
- [ ] Erase clipboard after delay (Display with a fancy spinner)
- [ ] Interactive mode should have option to change to new pwb db (A command that modifies the toml like update_db_path or something)
- [ ] Support aes128 = 16 byte key, aes192 = 24, aes256 = 32 byte keys implementations.

## How encryption is implemented

- User will be asked to input a username and password.
- A PBKDF2_HMAC_SHA256 is used to compute a 16 bytes long PBKDF2 key with username as salt and password as key.
- Use this key to encrypt the userinput to AES ECB standard encrypted byte array and store it in a struct. (ECB is used because this will be a personal password bank and the password is not stored anywhere, )
- Since the max block size is 16 bytes, split the strings into chunks and store the size of the initial password as well (Use a struct for that)
- Use serde to serialise this and store into disk.

## Decryption

- User will be asked to input a username and password.
- A PBKDF2_HMAC_SHA256 is used to compute a 16 byte long PBKDF2 key using the username as salt and password as key.
- Use this key to decrypt the struct and read the struct

Crates used: openssl

Crates considered:

[bincode_aes](https://docs.rs/bincode_aes/1.0.1/bincode_aes/)
[aes_gcm](https://docs.rs/aes-gcm/0.6.0/aes_gcm/)

Openssl was used just for the fun of using it.

Bibliography:

1. [AES Key schedule](https://en.wikipedia.org/wiki/AES_key_schedule)
2. [Key schedule](https://en.wikipedia.org/wiki/Key_schedule)
3. [PBKDF2 Hashing](https://en.wikipedia.org/wiki/PBKDF2)
4. [Ref on how AesKey is used](https://durch.github.io/rust-jwt/openssl/symm/index.html)
5. [List of AES implementation that doesn't need a salt](https://crypto.stackexchange.com/questions/66856/in-which-cases-aes-doesnt-need-iv)

Note:

- Block size always remain 128 bits (16 bytes), so the encryption has to be done in chunks if the password is > 16 bytes.
