use aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
//use chacha20poly1305::ChaCha20Poly1305;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::num::NonZeroU32;
use clap::{Parser, ValueEnum};
use std::{error, fmt};

#[derive(Debug)]
struct AeadError(aead::Error);

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aead error: {:?}", self.0)
    }
}

#[derive(Parser)]
#[command(author = "HSP", version = "0.1.0")]
struct Cli {
    #[arg(short, long)]
    operation: Mode,
    #[arg(short, long)]
    passphrase: String,
    #[arg(short, long)]
    file_path: String,
}
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Mode {
    Encrypt,
    Decrypt,
}

const CREDENTIAL_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    impl error::Error for AeadError {}

    let args = Cli::parse();
    println!("passphrase: {}", args.passphrase);
    println!("file_path: {}", args.file_path);

    let password = args.passphrase;
    
    // Generate pdbkdf2 derived key
    let mut salt = [0u8; CREDENTIAL_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .expect("Failed to generate random salt");
    let mut key = [0u8; KEY_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
        &mut salt,
        password.as_bytes(),
        &mut key,
    );

    //let cipher = ChaCha20Poly1305::new(&key.into());
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .expect("Failed to generate random nonce");

    match args.operation {
        Mode::Encrypt => {
            let data = fs::read(args.file_path.clone()).expect("Failed to read file");
            let encrypted_data = cipher.encrypt(&nonce.into(), data.as_ref()).unwrap();
            // Write encrypted data to file, adding .enc extension
            let mut file_path = args.file_path.clone();
            file_path.push_str(".enc");
            fs::write(file_path, &encrypted_data).expect("Failed to write file");
        }
        Mode::Decrypt => {
            
            // Use the same key and nonce for decryption
            let mut file_path = args.file_path.clone();
            if !file_path.ends_with(".enc") {
                panic!("File does not have .enc required extension. Please add .enc");
            }
            file_path.pop();
            file_path.pop();
            let encrypted_data = fs::read(args.file_path.clone()).expect("Failed to read file");
            let decrypted_data = match cipher.decrypt(&nonce.into(), &*encrypted_data) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Error: {:?}", e);
                    return Err(AeadError(e).into());
                }
            };
            fs::write(file_path, &decrypted_data).expect("Failed to write file");
        }
    }

    Ok(())
}
