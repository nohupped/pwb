//! Crypt crate has the cryptographic implementation of the struct that we encrypt and store.
use chrono::prelude::*;
use openssl::pkcs5::pbkdf2_hmac;
use openssl::symm::{encrypt, Cipher, decrypt};

use std::io::Write;
use std::io::Read;
use std::collections::HashMap;

use rpassword::read_password;
/// Length of credential. Using 32 here for AES 256 standards that require the key length to be 32 bytes
const USED_PBKDF2_HASH_LEN: usize = 32;
/// AES IV specification is 16 bytes
const AES_IV_SIZE: usize = 16;
/// Total length of the PBKDF2 hash length that we store in bytes. We use the first 32 bytes as the pbkdf2 hash and the last 16 bytes as the aes IV
const TOTAL_PBKDF2_CREDENTIAL_LEN: usize = 256;
/// The number of iterations to generate the pbkdf2 hash
const PBKDF2_ITERATIONS: usize = 100;

// We use cbc (as opposed to ecb for making use of the AES IV);
const CIPHER_256_FUNCTION: fn () -> Cipher = Cipher::aes_256_cbc;


/// Creds store the pbkdf2 hash ad the aes IV.
#[derive(Debug)]
pub struct Creds {
    pub username_salt: Vec<u8>,
    pub password_key: Vec<u8>,
    pub pbkdf2_hash: Vec<u8>,
    pub aes_iv: Vec<u8>,
}

impl Creds {

    /// prompts for a userinput for username and password. If ask_multi is true, will ask twice to confirm.
    pub fn ask_username_and_password(ask_multi: bool) -> Creds {
        println!("You will be asked to enter a username and password twice that will not be echoed to the terminal.");
        let username = _confirm_user_input("username".to_string(), ask_multi).unwrap();
        let password = _confirm_user_input("password".to_string(), ask_multi).unwrap();
        Creds {
            username_salt: username.as_bytes().to_vec(),
            password_key: password.as_bytes().to_vec(),
            pbkdf2_hash: Vec::new(),
            aes_iv: Vec::new(),
        }
    }
    /// Generates a 32 byte pbkdf2 hash and a 16 byte aes iv. Use these to pass on to the methods and functions 
    /// that encrypts the Data with aes256 cbc encryption.
    pub fn generate_pbkdf2(&mut self) {
        let mut to_store  = [0u8; TOTAL_PBKDF2_CREDENTIAL_LEN];
        match pbkdf2_hmac(
            self.password_key.as_ref(),
            self.username_salt.as_ref(),
            PBKDF2_ITERATIONS,
            openssl::hash::MessageDigest::sha256(),
            &mut to_store,
        ) {
            Ok(_) => {
                self.pbkdf2_hash = to_store[0..USED_PBKDF2_HASH_LEN].to_vec();
                self.aes_iv = to_store[TOTAL_PBKDF2_CREDENTIAL_LEN - AES_IV_SIZE..].to_vec();
                println!("Hash of length {} generated", self.pbkdf2_hash.len());
                println!("AES IV of length {} generated", self.aes_iv.len());
                println!()
            }
            Err(err) => {
                println!("Error when generating hash; Error: {:?}", err);
                std::process::exit(1);
            }
        };
    }
}

/// Stores the actual data that will be serialised, encrypted using aes 256 cbc and stored.
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

    pub fn encrypt_with_pbkdf2_and_write(&mut self, pbkdf2_hash: &Vec<u8>, iv: &Vec<u8>, c: &crate::helpers::Config) -> Result<(), Box<dyn std::error::Error>> {
        println!("Serializing and encrypting the struct using aes_256_ecb" );
        let encoded: Vec<u8> = bincode::serialize(&self).unwrap();
        let cipher = CIPHER_256_FUNCTION();
        let ciphertext = encrypt(
            cipher,
            &pbkdf2_hash,
            Some(iv),
            &encoded,
        ).unwrap();
        let mut fd = std::fs::File::create(&c.datafile)?;
        fd.write_all(&ciphertext)?;
        Ok(())
    }
    
    pub fn check_decryption_file(&mut self, pbkdf2_hash: &Vec<u8>, aes_iv: &Vec<u8>, c: &crate::helpers::Config) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Deserializing from file {:?}...", &c.datafile);
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, Some(aes_iv), &data)?;
   
        let decoded: Self = bincode::deserialize(&deciphertext[..])?;
        println!("Trying to read metadata from decrypted file, {:?}", decoded.meta.decrypted_string);

        if decoded.meta.decrypted_string == "decrypted_string".to_string() {
            return Ok(true);
        }
        Ok(false)
    }
    pub fn get_key(key: String, pbkdf2_hash: &Vec<u8>, aes_iv: &Vec<u8>, c: &crate::helpers::Config) -> Result<String, Box<dyn std::error::Error>> {
        let mut fd = std::fs::File::open(&c.datafile)?;
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, Some(aes_iv), &data)?;
        let decoded: Self = bincode::deserialize(&deciphertext[..])?;
        return match decoded.data.get(&key) {
            Some(a) => return Ok(a.to_string()),
            
            None => {Ok("".to_string())}
        }

    }

    pub fn put_key(key: String, val: String, pbkdf2_hash: &Vec<u8>, iv: &Vec<u8>, c: &crate::helpers::Config) -> Result<String, Box<dyn std::error::Error>> {
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, Some(iv), &data)?;
        let mut decoded: Self = bincode::deserialize(&deciphertext[..])?;
        decoded.meta.last_modified = Utc::now();
        let d = &decoded.data.insert(key, val);
        decoded.encrypt_with_pbkdf2_and_write(pbkdf2_hash, &iv, c)?;
        match d {
            Some(x) => {
                Ok(format!("Old password: {:?}\nThis has been over-written and is lost forever", x.to_string()))
            }
            None => {
                Ok(format!("written to vault"))
            }
        }
    }

    pub fn get_all(pbkdf2_hash: &Vec<u8>, aes_iv: &Vec<u8>, c: &crate::helpers::Config) -> Result<String, Box<dyn std::error::Error>> {
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, Some(aes_iv), &data)?;
        let decoded: Self = bincode::deserialize(&deciphertext[..])?;
        return Ok(format!("{:?}",decoded));

    }

    pub fn get_all_keys(pbkdf2_hash: &Vec<u8>, aes_iv: &Vec<u8>, c: &crate::helpers::Config) -> Result<String, Box<dyn std::error::Error>> {
        let mut fd = std::fs::File::open(&c.datafile).unwrap();
        let mut data = Vec::new();
        fd.read_to_end(&mut data).unwrap();
        let decipher= CIPHER_256_FUNCTION();
        let deciphertext =  decrypt(decipher,&pbkdf2_hash, Some(aes_iv), &data)?;
        let decoded: Self = bincode::deserialize(&deciphertext[..])?;
        let mut keys: Vec<String> = Vec::new();
        for key in decoded.data.keys() {
            keys.push(key.to_owned())
        }
        return Ok(format!("{}",keys.join(", ")));

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
