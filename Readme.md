# pwb

A password bank written in RUST to store all your passwords, locked with one username and password. One tool to store it all.. One tool to lose it too..

This is a personal tool written as a part of a personal project to learn and explore Rust. There are many places that can definitely be improved or can use some good Rust practices.

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
- [x] Commandline parameters to get and put passwords to the password store
- [x] Interactive mode to support option to change to another pwb db without quitting
- [ ] Write test cases

## How encryption is implemented

- User will be asked to input a username and password.
- PBKDF2_HMAC_SHA256 algorithm in the [Openssl](https://docs.rs/openssl/0.10.30/openssl/) crate is used to produce a digest of 256 bytes of which the first 32 bytes is used as the AES key and the last 16 bytes as the AES IV.
- Use this key and IV to encrypt the data into an AES CBC standard
- Use serde to serialise this and store into disk.

## Usage

- use `--init` to initialize the config and encrypted password store. It will prompt you to enter a username / password twice that will not be echoed.

### Interactive shell

- use `--help` to see how to invoke the interactive shell.
- Once in shell, it automatically `select` the db based on environment variable or the config file.
- run `/unlock` to unlock the encrypted DB. This will prompt you to enter a username and password.
- A 32 byte long hash and a 16 byte long IV is generated, and will be stored in a `lazy_static` global.
- This will be used to try to decrypt the db, deserialize it and evaluate a pre-coded string. (This may not be required because de-serialising at the next step will return an error if it wasn't able to.)
- Each operation on the DB during that session will use the global Hash and IV to decrypt and deserialize and viceversa.
- `/select` to another DB will clear these globals.

### Dependencies

- C compiler
- perl
- make

~~because the `vendored` cargo feature in the dependent [openssl](https://docs.rs/openssl/0.10.30/openssl/) crate is enabled.~~

No more using vendored because of security vulnerability. 

Quoting from the crate documentation:

If the vendored Cargo feature is enabled, the openssl-src crate will be used to compile and statically link to a copy of OpenSSL. The build process requires a C compiler, perl, and make. The OpenSSL version will generally track the newest OpenSSL release, and changes to the version are not considered breaking changes.

```toml
[dependencies]
openssl = { version = "0.10", features = ["vendored"] }
```

Bibliography:

1. [AES Key schedule](https://en.wikipedia.org/wiki/AES_key_schedule)
2. [Key schedule](https://en.wikipedia.org/wiki/Key_schedule)
3. [PBKDF2 Hashing](https://en.wikipedia.org/wiki/PBKDF2)
4. [Ref on how AesKey is used](https://docs.rs/openssl/0.10.30/openssl/symm/index.html)

Note:

- ~Block size always remain 128 bits (16 bytes), so the encryption has to be done in chunks if the password is > 16 bytes.~ This is not required, as `openssl::symm::{encrypt, Cipher, decrypt}` will take care of the chunks.
