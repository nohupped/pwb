//! Crypt crate has the cryptographic implementation of the struct that we encrypt and store.
use ring::pbkdf2;
use rpassword::read_password;
use std::num::NonZeroU32;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
// Length of credential. Using 16 here to use it for the AES128
const PBKDF2_CREDENTIAL_LEN: usize = 16;
const PBKDF2_ITERATIONS: u32 = 100;
type Credential = [u8; PBKDF2_CREDENTIAL_LEN];

/// Creds store the credentials in byte array and in hashed byte array (pbkdf2) format
#[derive(Debug)]
pub struct Creds {
    username_salt: Vec<u8>,
    password_key: Vec<u8>,
    pbkdf2_hash: Vec<u8>,
}

pub struct Crypt {
    Meta: CryptMeta,
}

pub struct CryptMeta {
    created: String,
    last_modified: String,
    decrypted: Vec<u8>,
}

impl Creds {
    pub fn ask_username_and_password(ask_multi: bool) -> Creds {
        println!("You will be asked to enter a username and password twice that will not be echoed to the terminal.");
        let username = _confirm_user_input("username".to_string(), ask_multi).unwrap();
        let password = _confirm_user_input("password".to_string(), ask_multi).unwrap();
        Creds {
            username_salt: username.as_bytes().to_vec(),
            password_key: password.as_bytes().to_vec(),
            pbkdf2_hash: Vec::new()
        }
    }

    pub fn pbkdf2_hash_and_validate(&mut self) {
        // Define a storage to store the credential.
        let mut to_store: Credential = [0u8; PBKDF2_CREDENTIAL_LEN];
        
        pbkdf2::derive(
            PBKDF2_ALG,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            &self.username_salt.as_mut(),
            &self.password_key.as_mut(),
            to_store.as_mut(),
        );
        self.pbkdf2_hash = to_store.to_vec();
        println!("{:?}", self.pbkdf2_hash);
        match pbkdf2::verify(
            PBKDF2_ALG,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            &self.username_salt.as_mut(),
            &self.password_key.as_mut(),
            &self.pbkdf2_hash,
        ) {
            Ok(_) => {
                println!("Hash created and verified..{:?}", &mut self.pbkdf2_hash.to_ascii_lowercase());
            },
            Err(e) => {
                println!("pbkdf2 hash computed, but verification of the hash against the username and password failed with error: {:?}.. Exiting.. ", e);
                std::process::exit(1);
            }
        };
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
