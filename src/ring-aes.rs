use ring::aead::{Aad, Algorithm, Nonce, OpeningKey, SealingKey};
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::num::NonZeroU32;

const CREDENTIAL_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = Algorithm::AES_256_GCM.key_len();
const TAG_LEN: usize = Algorithm::AES_256_GCM.tag_len();
const ITERATIONS: u32 = 100_000;

/// This code uses the SealingKey and OpeningKey types from the ring::aead module to encrypt and decrypt data using the AES-256-GCM algorithm. 
/// It also uses the pbkdf2::derive and SystemRandom::fill functions from the ring crate to derive an encryption key from a password and generate a random nonce.
///
fn main() {
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

    let sealing_key = SealingKey::new(&Algorithm::AES_256_GCM, &key).unwrap();
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("Failed to generate random nonce");
    let nonce = Nonce::assume_unique_for_key(nonce);
    let mut encrypted_data = data.to_vec();
    encrypted_data.extend_from_slice(&[0u8; TAG_LEN]);
    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted_data)
        .unwrap();

    fs::write("my_file.enc", &encrypted_data).expect("Failed to write file");

    let opening_key = OpeningKey::new(&Algorithm::AES_256_GCM, &key).unwrap();
    let decrypted_data = opening_key
        .open_in_place(nonce, Aad::empty(), &mut encrypted_data)
        .unwrap();

    fs::write("my_file.dec", decrypted_data).expect("Failed to write file");
}