use std::fs::File;
use std::io::{Read, Write};
use aes::Aes256;
use getrandom::getrandom;
use ring::{pbkdf2};
use block_modes::{BlockMode, Cbc};  // Deprecated 
use block_modes::block_padding::Pkcs7;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const PBKDF2_ITERATIONS: u32 = 100_000;

struct EncryptionParameters {
    file_path: String,
    operation: String,
    passphrase: String,
}

impl EncryptionParameters {
    fn new(file_path: String, operation: String, passphrase: String) -> Self {
        Self {
            file_path,
            operation,
            passphrase,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parameters = EncryptionParameters::new(
        "my_file.txt".to_string(),
        "encrypt".to_string(),
        "my_passphrase".to_string(),
    );

    // Generate a random IV using the getrandom crate
    let mut iv = [0u8; 16];
    getrandom(&mut iv)?;

    // Derive the encryption key from the passphrase using PBKDF2
    let key = [0u8; 32];
    let mut salt = [0u8; 16];
    getrandom(&mut salt)?;
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        &[0; 16],
        parameters.passphrase.as_ref(),
        &mut [0; 32],
    );

    if parameters.operation == "encrypt" {
        let mut file_to_encrypt = File::open(parameters.file_path.clone())?;
        let mut encrypted_file = File::create(format!("{}.enc", parameters.file_path))?;   
    
        let mut buffer = Vec::new();
        file_to_encrypt.read_to_end(&mut buffer)?;
    
        let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
        let ciphertext = cipher.encrypt_vec(&buffer);
    
        encrypted_file.write_all(&ciphertext)?;
    } else if parameters.operation == "decrypt" {
        let mut file_to_decrypt = File::open(parameters.file_path.clone())?;
        let mut decrypted_file = File::create(format!("{}.dec", parameters.file_path))?;
    
        let mut buffer = Vec::new();
        file_to_decrypt.read_to_end(&mut buffer)?;
    
        let cipher = Aes256Cbc::new_from_slices(&key, &iv)?;
        let decrypted_data = cipher.decrypt_vec(&buffer)?;
    
        decrypted_file.write_all(&decrypted_data)?;
    } else {
        println!("Invalid operation. Please choose either 'encrypt' or 'decrypt'.");
    }

    Ok(())
}