use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypt_ro::Cryptor;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1v15::Pkcs1v15Encrypt};
use rand_core::OsRng;

use aes_gcm::{aead::{Aead, AeadCore}, Aes256Gcm, KeyInit};

const SIZE:usize=50;
fn setup_cryptor() -> Cryptor {
    let mut a=Cryptor::new();
    a.set_matrix(32);
    a
}


fn bench_cryptor_encrypt(c: &mut Criterion) {
    let mut cryptor = setup_cryptor();
    let text = "a".repeat(SIZE);
    let text = text.as_bytes();
    let key = "strong-password-123";

    c.bench_function(&format!("Cryptor Encrypt {SIZE}B"), |b| {
        b.iter(|| cryptor.encrypt(black_box(text), black_box(key)).unwrap())
    });
}

fn bench_cryptor_decrypt(c: &mut Criterion) {
    let mut cryptor = setup_cryptor();
    let text = "a".repeat(SIZE);
    let text = text.as_bytes();
    let key = "strong-password-123";
    let encrypted = cryptor.encrypt(text, key).unwrap();

    c.bench_function(&format!("Cryptor Decrypt {SIZE}B"), |b| {
        b.iter(|| cryptor.decrypt(black_box(&encrypted), black_box(key)).unwrap())
    });
}



fn setup_aes_gcm() -> (Aes256Gcm, Vec<u8>) {
    let key = Aes256Gcm::generate_key(OsRng);

    let cipher = Aes256Gcm::new(&key);

    // Pre-encrypted test data
    let plaintext = vec![0u8; SIZE];
    (cipher, plaintext)
}

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let (cipher, plaintext) = setup_aes_gcm();
    c.bench_function(&format!("AES-256-GCM Encrypt {SIZE}B"), |b| {
        b.iter(|| {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            cipher.encrypt(&nonce, black_box(plaintext.as_ref()))
                .expect("AES-GCM encryption failed")
        })
    });
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let (cipher, plaintext) = setup_aes_gcm();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

    c.bench_function(&format!("AES-256-GCM Decrypt {SIZE}B"), |b| {
        b.iter(|| {
            let _ = Aes256Gcm::generate_nonce(&mut OsRng);
            cipher.decrypt(&nonce, black_box(ciphertext.as_ref()))
                .expect("AES-GCM decryption failed")
        })
    });
}

fn setup_rsa() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

fn bench_rsa_encrypt(c: &mut Criterion) {
    let (_, pub_key) = setup_rsa();
    let text = "a".repeat(SIZE);
    let padding = Pkcs1v15Encrypt;

    c.bench_function(&format!("RSA-2048 Encrypt {SIZE}B"), |b| {
        b.iter(|| {
            pub_key.encrypt(&mut OsRng, padding, black_box(text.as_bytes()))
                .expect("RSA encryption failed")
        })
    });
}




fn bench_rsa_decrypt(c: &mut Criterion) {
    let (priv_key, pub_key) = setup_rsa();
    let text ="a".repeat(SIZE);
    let padding = Pkcs1v15Encrypt;
    let encrypted = pub_key.encrypt(&mut OsRng, padding, text.as_bytes()).unwrap();

    c.bench_function(&format!("RSA-2048 Decrypt {SIZE}B"), |b| {
        b.iter(|| priv_key.decrypt(padding, black_box(&encrypted)).unwrap())
    });
}


criterion_group!(
    benches,
    bench_cryptor_encrypt,
    bench_cryptor_decrypt,
    bench_aes_gcm_encrypt,
    bench_aes_gcm_decrypt,
    bench_rsa_encrypt,
    bench_rsa_decrypt,
);
criterion_main!(benches);