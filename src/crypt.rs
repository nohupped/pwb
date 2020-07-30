//! Crypt crate has the cryptographic implementation of the struct that we encrypt and store.
use chrono::prelude::*;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{encrypt, Cipher, decrypt};

use rpassword::read_password;
// Length of credential. Using 16 here to use it for the AES128
const PBKDF2_CREDENTIAL_LEN: usize = 16;
const PBKDF2_ITERATIONS: usize = 100;
type Credential = [u8; PBKDF2_CREDENTIAL_LEN];

/// Creds store the credentials in byte array and in hashed byte array (pbkdf2) format
#[derive(Debug)]
pub struct Creds {
    username_salt: Vec<u8>,
    password_key: Vec<u8>,
    pbkdf2_hash: Vec<u8>,
}

impl Creds {
    pub fn ask_username_and_password(ask_multi: bool) -> Creds {
        println!("You will be asked to enter a username and password twice that will not be echoed to the terminal.");
        let username = _confirm_user_input("username".to_string(), ask_multi).unwrap();
        let password = _confirm_user_input("password".to_string(), ask_multi).unwrap();
        Creds {
            username_salt: username.as_bytes().to_vec(),
            password_key: password.as_bytes().to_vec(),
            pbkdf2_hash: Vec::new(),
        }
    }
    /// Run this function to populate the member pbkdf2_hash with the PBKDF2 Hash
    pub fn generate_pbkdf2(&mut self) {
        let mut to_store: Credential = [0u8; PBKDF2_CREDENTIAL_LEN];
        match pbkdf2_hmac(
            self.password_key.as_ref(),
            self.username_salt.as_ref(),
            PBKDF2_ITERATIONS,
            openssl::hash::MessageDigest::sha256(),
            &mut to_store,
        ) {
            Ok(_) => {
                self.pbkdf2_hash = to_store.to_vec();
                println!("Hash generated");
            }
            Err(err) => {
                println!("Error when generating hash; Error: {:?}", err);
                std::process::exit(1);
            }
        };
    }
}

pub struct Data {
    Meta: CryptMeta,
}

pub struct CryptMeta {
    created_utc: DateTime<Utc>,
    last_modified: DateTime<Utc>,
    encrypted_string: Vec<u8>,
    decrypted_string: String,
}

impl Data {
    pub fn new() -> Self {
        let meta: CryptMeta = CryptMeta {
            created_utc: Utc::now(),
            last_modified: Utc::now(),
            encrypted_string: Vec::new(),
            decrypted_string: "decrypted_string".to_string(),
        };
        Self { Meta: meta }
    }

    pub fn encrypt_with_pbkdf2(&mut self, creds: Creds) {
        let cipher = Cipher::aes_128_ecb();
        let ciphertext = encrypt(
            cipher,
            &creds.pbkdf2_hash,
            None,
            self.Meta.decrypted_string.as_bytes(),
        ).unwrap();
        println!("{:?}", ciphertext);
        let uncipher= Cipher::aes_128_ecb();
        let unciphertext = decrypt(uncipher,&creds.pbkdf2_hash, None, &ciphertext).unwrap();
        println!("{:?}", unciphertext.iter().map(|&c| c as char).collect::<String>());
    }
}

fn _confirm_user_input(prompt: String, multi: bool) -> Option<String> {
    if multi {
        println!("Enter {:?} followed by an enter :", prompt);
        let input = read_password().unwrap();
        println!("Enter {:?} again by an enter :", prompt);
        if read_password().unwrap() == input {
            return Some(input.trim().to_string());
        }
        println!("{} doesn't match, exiting...", prompt);
        std::process::exit(1);
    } else {
        println!("Enter {:?} followed by an enter :", prompt);
        let input = read_password().unwrap();
        Some(input.trim().to_string())
    }
}
