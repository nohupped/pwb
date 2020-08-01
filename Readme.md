# A rust personal password bank to store passwords, locked with a username/password

## Features

- [x] Generate a default config at $HOME/.pwb/config.toml which stores path to the encrypted password bank
- [x] An interactive shell
- [x] `/unlock` command to unlock an encrypted password file
- [x] `/h` command to list all supported commands
- [x] Take username and password to generate key and salt.
- [x] Each password associated with a key, eg: ssh, bank, etc.
- [x] Save new passwords
- [x] Use `PBKDF2_HMAC` to generate a Hash using Username and Password
- [x] Use aes256 to encrypt the data.
- [ ] Commandline parameters to get and put passwords to the password store
- [ ] Capture password to clipbpard when not in interactive mode (controlled via the config file or env var).
- [ ] Erase clipboard after delay (If a clipboard manager is being used, it is out of scope)
- [ ] Interactive mode should have option to change to new pwb db (A command that modifies the toml like update_db_path or something)
- [ ] Support aes128 = 16 byte key, aes192 = 24, aes256 = 32 byte keys implementations.

## How encryption is implemented

- User will be asked to input a username and password.
- A PBKDF2_HMAC_SHA256 is used to compute a 256 byte PBKDF2 key. The first 32 bytes is used as the aes key and the last 16 bytes as the AES IV.
- Use this key and IV to encrypt the data into an AES CBC standard
- Use serde to serialise this and store into disk.

### Crates used

openssl

### Crates considered

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

- ~Block size always remain 128 bits (16 bytes), so the encryption has to be done in chunks if the password is > 16 bytes.~ This is not required, as `openssl::symm::{encrypt, Cipher, decrypt}` will take care of chunks for us.
