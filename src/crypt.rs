//! Crypt crate has the cryptographic implementation of the struct that we encrypt and store.
use chrono::prelude::*;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{encrypt, Cipher, decrypt};

use std::io::Write;
use std::io::Read;
use std::collections::HashMap;

use rpassword::read_password;
// Length of credential. Using 16 here to use it for the AES128
const PBKDF2_CREDENTIAL_LEN: usize = 32;
const PBKDF2_ITERATIONS: usize = 100;

const CIPHER_256_FUNCTION: fn () -> Cipher = Cipher::aes_256_ecb;

type Credential = [u8; PBKDF2_CREDENTIAL_LEN];

/// Creds store the credentials in byte array and in hashed byte array (pbkdf2) format
#[derive(Debug)]
pub struct Creds {
    pub username_salt: Vec<u8>,
    pub password_key: Vec<u8>,
    pub pbkdf2_hash: Vec<u8>,
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
                println!("Hash of length {} generated", self.pbkdf2_hash.len());
            }
            Err(err) => {
                println!("Error when generating hash; Error: {:?}", err);
                std::process::exit(1);
            }
        };
    }
}

/// Stores the actual data that will be encrypted and stored.
/// Warning:: Changing this will break compatibility with older
/// versions when deserialising.
#[derive(Debug, Serialize, Deserialize)]
pub struct Data {
    meta: CryptMeta,
    data: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
        Self { 
            meta,
            data: HashMap::new(),
         }
    }

    pub fn encrypt_with_pbkdf2_and_write(&mut self, pbkdf2_hash: &Vec<u8>, c: &crate::helpers::Config) {
        println!("Serializing and encrypting the struct using aes_256_ecb" );
        let encoded: Vec<u8> = bincode::serialize(&self).unwrap();
        let cipher = CIPHER_256_FUNCTION();
        let ciphertext = encrypt(
            cipher,
            &pbkdf2_hash,
            None,
            &encoded,
        ).unwrap();
        let mut fd = std::fs::File::create(&c.datafile).unwrap();
        fd.write_all(&ciphertext).unwrap();
        // println!("{:?}", ciphertext.iter().map(|&c| c as char).collect::<String>());
        // let decipher= CIPHER_256_FUNCTION();
        // let deciphertext = decrypt(decipher,&creds.pbkdf2_hash, None, &ciphertext).unwrap();
        // println!("{:?}", deciphertext.iter().map(|&c| c as char).collect::<String>());
    }
    
    pub fn check_decryption_file(&mut self, pbkdf2_hash: &Vec<u8>, c: &crate::helpers::Config) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Deserializing from file {:?}...", &c.datafile);
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, None, &data)?;
   
        let decoded: Self = bincode::deserialize(&deciphertext[..])?;
        println!("Trying to read metadata from decrypted file, {:?}", decoded.meta.decrypted_string);

        if decoded.meta.decrypted_string == "decrypted_string".to_string() {
            return Ok(true);
        }
        Ok(false)
    }
    pub fn get_key(key: String, pbkdf2_hash: &Vec<u8>, c: &crate::helpers::Config) -> Result<String, Box<dyn std::error::Error>> {
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, None, &data)?;
        let decoded: Self = bincode::deserialize(&deciphertext[..])?;
        return match decoded.data.get(&key) {
            Some(a) => return Ok(a.to_string()),
            
            None => {Ok("".to_string())}
        }

    }

    pub fn put_key(key: String, val: String, pbkdf2_hash: &Vec<u8>, c: &crate::helpers::Config) -> Result<String, Box<dyn std::error::Error>> {
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, None, &data)?;
        let mut decoded: Self = bincode::deserialize(&deciphertext[..])?;
        decoded.meta.last_modified = Utc::now();
        let d = &decoded.data.insert(key, val);
        decoded.encrypt_with_pbkdf2_and_write(pbkdf2_hash, c);
        match d {
            Some(x) => {
                Ok(format!("Old password: {:?}\nThis has been over-written and is lost forever", x.to_string()))
            }
            None => {
                Ok(format!("written to vault"))
            }
        }
    }

    pub fn get_all(pbkdf2_hash: &Vec<u8>, c: &crate::helpers::Config) -> Result<String, Box<dyn std::error::Error>> {
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, None, &data)?;
        let decoded: Self = bincode::deserialize(&deciphertext[..])?;
        return Ok(format!("{:?}",decoded));

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
