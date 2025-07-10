//! A cryptographic library providing matrix-based encryption and decryption.
//!
//! This library implements a custom encryption scheme using:
//! - Matrix transformations with configurable size
//! - Key-derived shuffling operations
//! - Random padding and mixing operations
//! - URL-safe base64 encoding for text operations
//!
//! # Features
//! - Configurable matrix size for transformation blocks
//! - Both raw byte and text-friendly operations
//! - Key-based encryption/decryption
//! - Randomized padding for better security
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```
//! use crypt_ro::Cryptor;
//!
//! let cryptor = Cryptor::new();
//! let secret = "my secret message";
//! let key = "strong password";
//!
//! // Encrypt and decrypt text
//! let encrypted = cryptor.encrypt_text(secret, key).unwrap();
//! let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();
//!
//! assert_eq!(decrypted, secret);
//!
//! // Using custom matrix size
//! let mut cryptor = Cryptor::new();
//! cryptor.set_matrix(64);  // Use larger blocks
//! let encrypted = cryptor.encrypt_text(secret, key).unwrap();
//! let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();
//!
//! assert_eq!(decrypted, secret);
//! ```
//!
//! Working with raw bytes:
//!
//! ```
//! use crypt_ro::Cryptor;
//!
//! let cryptor = Cryptor::new();
//! let data = b"binary data \x01\x02\x03";
//! let key = "encryption key";
//!
//! let encrypted = cryptor.encrypt(data, key).unwrap();
//! let decrypted = cryptor.decrypt(&encrypted, key).unwrap();
//!
//! assert_eq!(decrypted.as_bytes(), data);
//! ```

mod util;
mod rand;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use std::error::Error;
use std::iter::repeat;
use crate::rand::SimpleRng;
use crate::util::{generate_password, mix, shuffle, unmix, unshuffle};

/// A cryptographic utility for encrypting and decrypting text using a matrix-based transformation.
///
/// The `Cryptor` uses a combination of shuffling, mixing, and matrix operations to obscure the
/// original text. It supports configurable matrix sizes for the transformation process.
///
/// # Examples
///
/// ```
/// use crypt_ro::Cryptor;
///
/// let cryptor = Cryptor::new();
/// let encrypted = cryptor.encrypt_text("secret message", "password").unwrap();
/// let decrypted = cryptor.decrypt_text(&encrypted, "password").unwrap();
/// assert_eq!(decrypted, "secret message");
/// ```
pub struct Cryptor {
    matrix: usize,
}
const RANDOM_LEN: usize = 3;
impl Cryptor {
    /// Creates a new `Cryptor` instance with default matrix size (32).
    pub fn new() -> Self {
        Self { matrix: 32 }
    }

    /// Encrypts raw bytes using the provided key.
    ///
    /// # Arguments
    /// * `data` - The bytes to encrypt
    /// * `key` - The encryption key
    ///
    /// # Returns
    /// A `Result` containing the encrypted bytes or an error if encryption fails.
    ///
    /// # Example
    /// ```
    /// use crypt_ro::Cryptor;
    ///
    /// let cryptor = Cryptor::new();
    /// let encrypted = cryptor.encrypt(b"secret data", "key123").unwrap();
    /// assert!(!encrypted.is_empty());
    /// ```
    pub fn encrypt(&self, data: &[u8], key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let matrix_size=self.matrix;
        let pad = (matrix_size - ((10 + data.len()) % matrix_size)) % matrix_size;
        let key_bytes = generate_password(matrix_size,key.as_bytes());
        let data_len = data.len();
        if data_len>u32::MAX as usize {
            return Err("Data too Big".into());
        }
        let data_size = (data_len as u32).to_be_bytes();
        let random_prefix = SimpleRng::new_with_time_seed().get_random_bytes(6);
        let seed_random = random_prefix.iter().map(|&b| b as u16).sum::<u16>() as u64;
        let mut padded_text = Vec::with_capacity(10 + data.len()+pad);
        padded_text.extend_from_slice(&data_size);
        padded_text.extend_from_slice(&random_prefix);
        padded_text.extend_from_slice(data);
        padded_text.extend(repeat(1).take(pad));
        let seed_sum: u64 = key_bytes.iter().map(|&b| b as u64).sum();
        shuffle(&mut padded_text,seed_sum.wrapping_add(seed_random),5);

        let mut matrix = padded_text.chunks_exact_mut(matrix_size).collect::<Vec<_>>();
        let matrix_len=matrix.len();
        if matrix_len==0 {
            return Err("Invalid Padding Length".into());
        }
        for i in 0..matrix_len {
            let seed = matrix.get(i+1)
                .map(|b| b[0] as u64)
                .unwrap_or(key_bytes[0] as u64);
            shuffle(&mut matrix[i], seed.wrapping_add(seed_random),2);
        }

        mix(matrix_size,&mut padded_text, &key_bytes);
        let seed_random=(seed_random as u16).to_be_bytes();
        padded_text.push(seed_random[0]);
        padded_text.push(seed_random[1]);
        Ok(padded_text)
    }


    /// Encrypts raw bytes using the provided key.
    ///
    /// # Arguments
    /// * `text` - The plaintext to encrypt
    /// * `key` - The encryption key
    ///
    /// # Returns
    /// A `Result` URL-safe base64 string without padding or an error if encryption fails.
    ///
    /// # Example
    /// ```
    /// use crypt_ro::Cryptor;
    ///
    /// let cryptor = Cryptor::new();
    /// let encrypted = cryptor.encrypt_text("secret message", "password").unwrap();
    /// assert!(!encrypted.contains('/'));  // URL-safe
    pub fn encrypt_text(&self, text: &str, key: &str) -> Result<String, Box<dyn Error>> {
        Ok(URL_SAFE.encode(self.encrypt(text.as_bytes(), key)?).trim_end_matches('=').to_string())
    }

    /// Decrypts bytes using the provided key.
    ///
    /// # Arguments
    /// * `encoded` - The encrypted bytes to decrypt
    /// * `key` - The decryption key
    ///
    /// # Returns
    /// A `Result` containing the decrypted bytes or an error if decryption fails.
    ///
    /// # Example
    /// ```
    /// use crypt_ro::Cryptor;
    ///
    /// let cryptor = Cryptor::new();
    /// let encrypted = cryptor.encrypt(b"data", "key").unwrap();
    /// let decrypted = cryptor.decrypt(&encrypted, "key").unwrap();
    /// assert_eq!(decrypted, b"data");
    /// ```
    pub fn decrypt(&self, encoded: &Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let len=encoded.len();
        if len < 6 {
            return Err("Invalid Token Matrix Length".into());
        }

        let seed_random=u16::from_be_bytes([encoded[len - 2],encoded[len - 1]]) as u64;
        let mut decoded = encoded[..len-2].to_vec();
        let len=len-2;
        let matrix_size=self.matrix;

        let key_bytes = generate_password(matrix_size,key.as_bytes());
        unmix(matrix_size,&mut decoded, &key_bytes);
        let mut matrix = decoded.chunks_exact_mut(matrix_size).collect::<Vec<_>>();
        let matrix_len=matrix.len();
        for i in (0..matrix_len).rev() {
            let seed = matrix.get(i+1)
                .map(|b| b[0] as u64)
                .unwrap_or(key_bytes[0] as u64);
            unshuffle(&mut matrix[i], seed.wrapping_add(seed_random),2);
        }

        let seed_sum: u64 = key_bytes.iter().map(|&b| b as u64).sum();
        unshuffle(&mut decoded, seed_sum.wrapping_add(seed_random),5);

        let data_size = u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]) as usize;
        if len < data_size+10 {
            return Err("Invalid Token Matrix Length".into());
        }
        let result_bytes = &decoded[10..data_size+10];
        Ok(result_bytes.to_vec())
    }

    /// Decrypts a URL-safe base64 encoded string using the provided key.
    ///
    /// # Arguments
    /// * `encoded` - A URL-safe base64 encoded string to decrypt
    /// * `key` - The decryption key
    ///
    /// # Returns
    /// A `Result` containing the decrypted string or an error if decryption fails.
    ///
    /// # Example
    /// ```
    /// use crypt_ro::Cryptor;
    ///
    /// let cryptor = Cryptor::new();
    /// let encrypted = cryptor.encrypt_text("message", "pass").unwrap();
    /// let decrypted = cryptor.decrypt_text(&encrypted, "pass").unwrap();
    /// assert_eq!(decrypted, "message");
    /// ```
    pub fn decrypt_text(&self, encoded: &str, key: &str) -> Result<String, Box<dyn Error>> {
        let mut input = encoded.to_string();
        let padding = input.len() % 4;
        if padding != 0 {
            input.push_str(&"=".repeat(4 - padding));
        }

        let data = URL_SAFE.decode(&input)?;
        let result = String::from_utf8(self.decrypt(&data, &key)?)?
            .to_string();
        Ok(result)
    }

    /// Sets the matrix size used for cryptographic operations.
    ///
    /// The matrix size determines how data is chunked and processed during encryption/decryption.
    /// Must be a positive non-zero value.
    ///
    /// # Example
    /// ```
    /// use crypt_ro::Cryptor;
    ///
    /// let mut cryptor = Cryptor::new();
    /// cryptor.set_matrix(64);  // Use larger blocks
    /// ```
    pub fn set_matrix(&mut self, size: usize) {
        if size>0{
            self.matrix = size;
        }
    }
}