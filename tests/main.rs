use crypt_ro::Cryptor;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let cryptor = Cryptor::new(); // Default 32-byte matrix
    let text = "a".repeat(64);
    let key = "strong-password-123";

    let encrypted = cryptor.encrypt(&text, key).unwrap();
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

#[test]
fn test_special_characters() {
    let cryptor = Cryptor::new();
    let text = "Special chars: !@#$%^&*()_+{}|:\"<>?~`\n\t";
    let key = "key_with_special_chars!@#";

    let encrypted = cryptor.encrypt_text(text, key).unwrap();
    let decrypted = cryptor.decrypt_text(&encrypted, key).unwrap();

    assert_eq!(decrypted, text);
}
