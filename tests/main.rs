use crypt_ro::Cryptor;

#[test]
fn test_decrypt_python() {
    let cryptor = Cryptor::new(); // Default 32-byte matrix
    let secret = "my secret message";
    let key = "strong password";
    let decrypted = cryptor.decrypt_text("B2VzbxcUAgMTFh7eT8JlA3U9Cg0KRQNhElMQCnNkcqgDFg", key).unwrap();

    assert_eq!(decrypted, secret);
}
#[test]
fn test_decrypt_js() {
    let cryptor = Cryptor::new(); // Default 32-byte matrix
    let secret = "my secret message";
    let key = "strong password";
    let decrypted = cryptor.decrypt_text("q2Vyb2MUUm8MFAoSHAoBFhE-G38KIANBchBXbnMFcnUB2Q==", key).unwrap();
    assert_eq!(decrypted, secret);
}
#[test]
fn test_encrypt_decrypt_roundtrip() {
    let cryptor = Cryptor::new(); // Default 32-byte matrix
    let text = "abc".repeat(1000);
    let text = text.as_bytes();
    let key = "strong-password-123";

    let encrypted = cryptor.encrypt(text, key).unwrap();
    let decrypted = cryptor.decrypt(&encrypted, key).unwrap();
    assert_eq!(decrypted, text);
}

#[test]
fn test_encrypt_decrypt_with_different_lengths() {
    let mut cryptor = Cryptor::new();
    cryptor.set_matrix(16);
    let texts = [
        "Short",
        "Medium length message",
        "Very long message that should test the padding and multiple blocks functionality of the encryption",
    ];
    let key = "another_password";

    for text in texts {
        let encrypted = cryptor.encrypt_text(text, key).unwrap();
        let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();
        assert_eq!(decrypted, text);
    }
}

#[test]
fn test_decrypt_invalid_token() {
    let cryptor = Cryptor::new();
    // Invalid base64
    assert!(cryptor.decrypt_text("invalid_base64!", "key").is_err());
    // Wrong length
    assert!(cryptor.decrypt_text("YWJj", "key").is_err()); // "abc" encoded
    // Wrong key
    let encrypted = cryptor.encrypt_text("message", "right_key").unwrap();
    assert!(cryptor.decrypt_text(&encrypted, "wrong_key").is_err());
}

#[test]
fn test_empty_input() {
    let cryptor = Cryptor::new();
    let encrypted = cryptor.encrypt_text("", "key").unwrap();
    let decrypted = cryptor.decrypt_text(&encrypted, "key").unwrap();
    assert_eq!(decrypted, "");
}

fn count_char_differences(text1: &str, text2: &str) -> usize {
    let mut differences = 0;

    // Compare characters up to the length of the shorter string
    let mut chars1 = text1.chars();
    let mut chars2 = text2.chars();

    loop {
        match (chars1.next(), chars2.next()) {
            (Some(c1), Some(c2)) if c1 != c2 => differences += 1,
            (Some(_), None) | (None, Some(_)) => differences += 1, // One string is longer
            (None, None) => break,                                 // Both strings ended
            _ => continue,                                         // Characters are equal
        }
    }

    differences
}

#[test]
fn test_special_characters() {
    let cryptor = Cryptor::new();
    let text = "Special chars: !@#$%^&*()_+{}|:\"<>?~`\n\t";
    let key = "key_with_special_chars!@#";

    let encrypted = cryptor.encrypt_text(text, key).unwrap();
    let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();

    assert_eq!(decrypted, text);
}

#[test]
fn test_encrypt_decrypt_text_roundtrip() {
    let cryptor = Cryptor::new();
    let text = "Hello, world! こんにちは! 😊";
    let key = "secure password 123";

    let encrypted = cryptor.encrypt_text(text, key).unwrap();
    let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();

    assert_eq!(decrypted, text);
}

#[test]
fn test_encrypt_decrypt_binary_data() {
    let cryptor = Cryptor::new();
    let data: &[u8] = &[0x01, 0x02, 0x03, 0xff, 0x00, 0x7f];
    let key = "binary key";

    let encrypted = cryptor.encrypt(data, key).unwrap();
    let decrypted = cryptor.decrypt(&encrypted, key).unwrap();

    assert_eq!(decrypted, data);
}

#[test]
fn test_different_matrix_sizes() {
    let sizes = [16, 32, 64, 128];
    let text = "The quick brown fox jumps over the lazy dog";
    let key = "matrix size test";

    for size in sizes {
        let mut cryptor = Cryptor::new();
        cryptor.set_matrix(size);

        let encrypted = cryptor.encrypt_text(text, key).unwrap();
        let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();

        assert_eq!(decrypted, text);
    }
}

#[test]
fn test_wrong_key_fails() {
    let cryptor = Cryptor::new();
    let text = "secret message";
    let key = "correct key";
    let wrong_key = "wrong key";

    let encrypted = cryptor.encrypt_text(text, key).unwrap();
    let decrypted = cryptor.decrypt_text(&encrypted, wrong_key);
    assert!(decrypted.is_err());
}

#[test]
fn test_encrypt_decrypt_long_text() {
    let cryptor = Cryptor::new();
    let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100);
    let key = "long text key";

    let encrypted = cryptor.encrypt_text(&text, key).unwrap();
    let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();

    assert_eq!(decrypted, text);
}

#[test]
fn test_decrypt_invalid_length_fails() {
    let cryptor = Cryptor::new();
    let invalid_data = vec![1u8; 31];

    let result = cryptor.decrypt(&invalid_data, "any key");
    assert!(result.is_err());
}

#[test]
fn test_url_safe_base64() {
    let cryptor = Cryptor::new();
    let text = "test";
    let key = "key";

    let encrypted = cryptor.encrypt_text(text, key).unwrap();
    assert!(!encrypted.contains('+'));
    assert!(!encrypted.contains('/'));
    assert!(!encrypted.ends_with('='));
}