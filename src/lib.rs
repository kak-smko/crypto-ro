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
//! let encrypted = cryptor.encrypt(std::str::from_utf8(data).unwrap(), key).unwrap();
//! let decrypted = cryptor.decrypt(&encrypted, key).unwrap();
//!
//! assert_eq!(decrypted.as_bytes(), data);
//! ```

mod util;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use std::error::Error;
use crate::util::{generate_password, get_random_bytes, mix, shuffle, unmix, unshuffle};

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

impl Cryptor {
    /// Creates a new `Cryptor` instance with default matrix size (32).
    pub fn new() -> Self {
        Self { matrix: 32 }
    }

    /// Encrypts raw bytes using the provided key.
    ///
    /// # Arguments
    /// * `text` - The plaintext to encrypt
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
    /// let encrypted = cryptor.encrypt("secret data", "key123").unwrap();
    /// assert!(!encrypted.is_empty());
    /// ```
    pub fn encrypt(&self, text: &str, key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let matrix_size=self.matrix;
        let key_bytes = generate_password(matrix_size,key.as_bytes());

        let random_prefix = get_random_bytes(6);

        let mut padded_text = Vec::with_capacity(random_prefix.len() + text.len());
        padded_text.extend_from_slice(&random_prefix);
        padded_text.extend_from_slice(text.as_bytes());

        let pad_len = (matrix_size - (padded_text.len() % matrix_size)) % matrix_size;
        padded_text.resize(padded_text.len() + pad_len, 0);

        let seed_sum: u64 = key_bytes.iter().map(|&b| b as u64).sum();
        shuffle(&mut padded_text,seed_sum,5);

        let mut matrix = padded_text.chunks_exact_mut(matrix_size).collect::<Vec<_>>();
        let matrix_len=matrix.len();

        for i in 0..matrix_len {
            let seed = match matrix.get(i+1) {
                None => {
                    key_bytes[0] as u64}
                Some(a) => {
                        a[0] as u64
                }
            };
            shuffle(&mut matrix[i], seed,2);
        }

        mix(matrix_size,&mut padded_text, &key_bytes);

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
        Ok(URL_SAFE.encode(self.encrypt(text, key)?).trim_end_matches('=').to_string())
    }

    /// Decrypts bytes using the provided key.
    ///
    /// # Arguments
    /// * `encoded` - The encrypted bytes to decrypt
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
    /// let encrypted = cryptor.encrypt("data", "key").unwrap();
    /// let decrypted = cryptor.decrypt(&encrypted, "key").unwrap();
    /// assert_eq!(decrypted, "data");
    /// ```
    pub fn decrypt(&self, encoded: &Vec<u8>, key: &str) -> Result<String, Box<dyn Error>> {
        let mut decoded = encoded.clone();
        let matrix_size=self.matrix;
        if decoded.len() % matrix_size != 0 {
            return Err("Invalid Token Matrix Length".into());
        }

        let key_bytes = generate_password(matrix_size,key.as_bytes());
        unmix(matrix_size,&mut decoded, &key_bytes);
        let mut matrix = decoded.chunks_exact_mut(matrix_size).collect::<Vec<_>>();
        let matrix_len=matrix.len();
        for i in (0..matrix_len).rev() {
            let seed = match matrix.get(i + 1) {
                None => {key_bytes[0] as u64}
                Some(a) => {a[0] as u64}
            };
            unshuffle(&mut matrix[i], seed,2);
        }


        let seed_sum: u64 = key_bytes.iter().map(|&b| b as u64).sum();
        unshuffle(&mut decoded, seed_sum,5);

        if decoded.len() < matrix_size {
            return Err("Invalid Token Matrix Length".into());
        }
        let result_bytes = &decoded[6..];
        let result = String::from_utf8(result_bytes.to_vec())?
            .trim_end_matches('\0')
            .to_string();

        Ok(result)
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

        Ok(self.decrypt(&data, &key)?)
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