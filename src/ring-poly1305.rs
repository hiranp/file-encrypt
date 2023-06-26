use aead::{Aead, KeyInit};
//use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::num::NonZeroU32;

const CREDENTIAL_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const ITERATIONS: u32 = 100_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "my_passphrase";
    let data = fs::read("my_file.txt").expect("Failed to read file");
    let salt = [0u8; CREDENTIAL_LEN];
    let mut key = [0u8; KEY_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(ITERATIONS).unwrap(),
        &salt,
        password.as_bytes(),
        &mut key,
    );

    let cipher = ChaCha20Poly1305::new(&key.into());
    // let cipher = Aes256Gcm::new(&key.into());
    let mut nonce = [0u8; NONCE_LEN];
    
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("Failed to generate random nonce");
    let encrypted_data = cipher.encrypt(&nonce.into(), data.as_ref()).unwrap();

    fs::write("my_file.enc", &encrypted_data).expect("Failed to write file");

    let decrypted_data = cipher.decrypt(&nonce.into(), encrypted_data.as_ref()).unwrap();

    fs::write("my_file.dec", &decrypted_data).expect("Failed to write file");

     Ok(())
}