// src/modes/gcm_siv.rs

use {
    crate::{
        config::AesKeySize,
        types::{Aes128GcmSivMode, Aes256GcmSivMode}
    },
    eax::aead::{
        generic_array::GenericArray, Aead, KeyInit, Payload // For Nonce/IV handling
    },
    classified::classified_data::ClassifiedData
};

/// Encrypts plaintext using AES-128-GCM-SIV mode.
///
/// Returns `(ciphertext, tag)`.
/// GCM-SIV typically expects a 12-byte nonce (96 bits).
pub fn encrypt_aes_gcm_siv(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let cipher = Aes128GcmSivMode::new_from_slice(key).map_err(|_| "Invalid key length")?;
    let nonce_ga = GenericArray::from_slice(nonce); // Nonce must be 12 bytes

    let payload = Payload { msg: plaintext, aad };

    let encrypted_data = cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?;
    // The `aead` trait's `encrypt` method returns `ciphertext || tag`.
    // GCM-SIV tag length is fixed at 16 bytes.
    let tag = encrypted_data[encrypted_data.len() - 16..].to_vec();
    let ciphertext = encrypted_data[..encrypted_data.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Encrypts plaintext using AES-128-GCM-SIV mode with a sensitive key.
///
/// Returns `(ciphertext, tag)`.
/// GCM-SIV typically expects a 12-byte nonce (96 bits).
pub fn encrypt_aes_gcm_siv_safe(
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let cipher = Aes128GcmSivMode::new_from_slice(key.expose()).map_err(|_| "Invalid key length")?;
    let nonce_ga = GenericArray::from_slice(nonce);

    let payload = Payload { msg: plaintext, aad };

    let encrypted_data = cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?;
    let tag = encrypted_data[encrypted_data.len() - 16..].to_vec();
    let ciphertext = encrypted_data[..encrypted_data.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Decrypts ciphertext using AES-128-GCM-SIV mode.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// GCM-SIV typically expects a 12-byte nonce (96 bits).
pub fn decrypt_aes_gcm_siv(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes128GcmSivMode::new_from_slice(key).map_err(|_| "Invalid key length")?;
    let nonce_ga = GenericArray::from_slice(nonce);

    let mut data_with_tag = ciphertext.to_vec();
    data_with_tag.extend_from_slice(tag); // Decrypt expects `ciphertext || tag`

    let payload = Payload { msg: &data_with_tag, aad };

    cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")
}

/// Decrypts ciphertext using AES-128-GCM-SIV mode with a sensitive key.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// GCM-SIV typically expects a 12-byte nonce (96 bits).
pub fn decrypt_aes_gcm_siv_safe(
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes128GcmSivMode::new_from_slice(key.expose()).map_err(|_| "Invalid key length")?;
    let nonce_ga = GenericArray::from_slice(nonce);

    let mut data_with_tag = ciphertext.to_vec();
    data_with_tag.extend_from_slice(tag); // Decrypt expects `ciphertext || tag`

    let payload = Payload { msg: &data_with_tag, aad };

    cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")
}

/// Encrypts plaintext using AES-GCM-SIV mode with a specified key size.
///
/// Returns `(ciphertext, tag)`.
/// GCM-SIV expects a 12-byte nonce regardless of AES key size.
pub fn encrypt_aes_gcm_siv_with_size(
    key_size: AesKeySize,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let nonce_ga = GenericArray::from_slice(nonce); // Nonce must be 12 bytes
    let payload = Payload { msg: plaintext, aad };

    let encrypted_data = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128GcmSivMode::new_from_slice(key).map_err(|_| "Invalid key length")?;
            cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256GcmSivMode::new_from_slice(key).map_err(|_| "Invalid key length")?;
            cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?
        }
    };

    let tag = encrypted_data[encrypted_data.len() - 16..].to_vec();
    let ciphertext = encrypted_data[..encrypted_data.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Encrypts plaintext using AES-GCM-SIV mode with a specified key size and sensitive key.
///
/// Returns `(ciphertext, tag)`.
/// GCM-SIV expects a 12-byte nonce regardless of AES key size.
pub fn encrypt_aes_gcm_siv_safe_with_size(
    key_size: AesKeySize,
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let nonce_ga = GenericArray::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };

    let encrypted_data = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128GcmSivMode::new_from_slice(key.expose()).map_err(|_| "Invalid key length")?;
            cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256GcmSivMode::new_from_slice(key.expose()).map_err(|_| "Invalid key length")?;
            cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?
        }
    };

    let tag = encrypted_data[encrypted_data.len() - 16..].to_vec();
    let ciphertext = encrypted_data[..encrypted_data.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Decrypts ciphertext using AES-GCM-SIV mode with a specified key size.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// GCM-SIV expects a 12-byte nonce regardless of AES key size.
pub fn decrypt_aes_gcm_siv_with_size(
    key_size: AesKeySize,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let nonce_ga = GenericArray::from_slice(nonce);
    let mut data_with_tag = ciphertext.to_vec();
    data_with_tag.extend_from_slice(tag);
    let payload = Payload { msg: &data_with_tag, aad };

    let decrypted_data = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128GcmSivMode::new_from_slice(key).map_err(|_| "Invalid key length")?;
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256GcmSivMode::new_from_slice(key).map_err(|_| "Invalid key length")?;
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
    };
    Ok(decrypted_data)
}

/// Decrypts ciphertext using AES-GCM-SIV mode with a specified key size and sensitive key.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// GCM-SIV expects a 12-byte nonce regardless of AES key size.
pub fn decrypt_aes_gcm_siv_safe_with_size(
    key_size: AesKeySize,
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let nonce_ga = GenericArray::from_slice(nonce);
    let mut data_with_tag = ciphertext.to_vec();
    data_with_tag.extend_from_slice(tag);
    let payload = Payload { msg: &data_with_tag, aad };

    let decrypted_data = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128GcmSivMode::new_from_slice(key.expose()).map_err(|_| "Invalid key length")?;
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256GcmSivMode::new_from_slice(key.expose()).map_err(|_| "Invalid key length")?;
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
    };
    Ok(decrypted_data)
}

// tests/gcm_siv_tests.rs

#[cfg(test)]
mod tests {
    #![allow(unused, unused_must_use)]
    
    use super::*; // Import functions from the parent module
    use hex::FromHex; // For easier key/nonce/AAD/plaintext creation from hex strings
    use rand::{rngs::OsRng, Rng, TryRngCore}; // For generating random data
    use classified::classified_data::ClassifiedData; // Import ClassifiedData

    // --- Helper function for generating random bytes ---
    fn generate_random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        OsRng.try_fill_bytes(&mut bytes);
        bytes
    }

    // --- Tests for `encrypt_aes_gcm_siv` and `decrypt_aes_gcm_siv` ---

    #[test]
    fn test_aes128_gcm_siv_encryption_decryption_basic() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(); // 16 bytes for AES128
        let nonce = hex::decode("0102030405060708090a0b0c").unwrap(); // 12 bytes for GCM-SIV nonce (recommended)
        let aad = b"additional authenticated data for GCM-SIV";
        let plaintext = b"Hello, GCM-SIV misuse-resistant world!";

        let (ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16); // GCM-SIV tag is always 16 bytes
        assert_eq!(ciphertext.len(), plaintext.len()); // Ciphertext length == plaintext length
    }

    #[test]
    fn test_aes128_gcm_siv_encryption_decryption_empty_aad() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b""; // Empty AAD
        let plaintext = b"Message with no AAD in GCM-SIV.";

        let (ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_gcm_siv_encryption_decryption_empty_plaintext() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b"some AAD for empty plaintext";
        let plaintext = b""; // Empty plaintext

        let (ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_gcm_siv_encryption_decryption_random_data() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = generate_random_bytes(64);
        let plaintext = generate_random_bytes(2048); // Random 2KB message

        let (ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, &aad, &plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv(&key, &nonce, &aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_gcm_siv_decryption_invalid_key() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM-SIV world!";

        let (ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();

        let wrong_key = generate_random_bytes(16); // Different key
        let result = decrypt_aes_gcm_siv(&wrong_key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_gcm_siv_decryption_invalid_nonce() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM-SIV world!";

        let (ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();

        let wrong_nonce = generate_random_bytes(12); // Different nonce
        let result = decrypt_aes_gcm_siv(&key, &wrong_nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_gcm_siv_decryption_tampered_aad() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b"original AAD";
        let plaintext = b"Hello, GCM-SIV world!";

        let (ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();

        let tampered_aad = b"tampered AAD"; // Modified AAD
        let result = decrypt_aes_gcm_siv(&key, &nonce, tampered_aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_gcm_siv_decryption_tampered_ciphertext() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM-SIV world!";

        let (mut ciphertext, tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();

        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        } else {
            assert!(!plaintext.is_empty(), "Test requires non-empty plaintext for ciphertext tampering.");
        }

        let result = decrypt_aes_gcm_siv(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_gcm_siv_decryption_tampered_tag() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM-SIV world!";

        let (ciphertext, mut tag) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext).unwrap();

        if !tag.is_empty() {
            tag[0] ^= 0x01;
        } else {
            panic!("Tag should not be empty for tampering test.");
        }

        let result = decrypt_aes_gcm_siv(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_gcm_siv_nonce_reuse() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12); // Reused nonce
        let aad = b"reused AAD";
        let plaintext1 = b"First message with reused nonce.";
        let plaintext2 = b"Second message with reused nonce."; // Different plaintext

        let (ciphertext1, tag1) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext1).unwrap();
        let (ciphertext2, tag2) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext2).unwrap();

        // Ciphertexts and tags should be different because plaintexts are different
        assert_ne!(ciphertext1, ciphertext2);
        assert_ne!(tag1, tag2);

        // Decryption should still work for both
        let decrypted1 = decrypt_aes_gcm_siv(&key, &nonce, aad, &ciphertext1, &tag1).unwrap();
        let decrypted2 = decrypt_aes_gcm_siv(&key, &nonce, aad, &ciphertext2, &tag2).unwrap();

        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);

        // If plaintext and AAD were identical, ciphertext and tag would also be identical
        let plaintext_same = b"Same message for reuse test.";
        let (c1, t1) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext_same).unwrap();
        let (c2, t2) = encrypt_aes_gcm_siv(&key, &nonce, aad, plaintext_same).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_aes128_gcm_siv_encrypt_invalid_key_length() {
        let short_key = b"short_key"; // 9 bytes, not 16
        let nonce = generate_random_bytes(12);
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_gcm_siv(short_key, &nonce, aad, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key length");
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_aes128_gcm_siv_encrypt_invalid_nonce_length_panic() {
        let key = generate_random_bytes(16);
        let short_nonce = b"short"; // 5 bytes, not 12
        let aad = b"";
        let plaintext = b"test";

        let _ = encrypt_aes_gcm_siv(&key, short_nonce, aad, plaintext);
    }

    // --- Tests for _safe functions ---

    #[test]
    fn test_aes128_gcm_siv_safe_encryption_decryption_basic() {
        let key = ClassifiedData::new(hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let nonce = hex::decode("0102030405060708090a0b0c").unwrap();
        let aad = b"sensitive data for GCM-SIV";
        let plaintext = b"Hello, secure GCM-SIV world!";

        let (ciphertext, tag) = encrypt_aes_gcm_siv_safe(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv_safe(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    // --- Tests for _with_size functions ---

    #[test]
    fn test_aes128_gcm_siv_with_size_success() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(12);
        let aad = b"AAD for 128-bit GCM-SIV";
        let plaintext = b"Data for AES128 GCM-SIV with size control.";

        let (ciphertext, tag) = encrypt_aes_gcm_siv_with_size(AesKeySize::Bits128, &key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv_with_size(AesKeySize::Bits128, &key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes256_gcm_siv_with_size_success() {
        let key = generate_random_bytes(32);
        let nonce = generate_random_bytes(12);
        let aad = b"AAD for 256-bit GCM-SIV";
        let plaintext = b"Data for AES256 GCM-SIV with size control, a bit longer.";

        let (ciphertext, tag) = encrypt_aes_gcm_siv_with_size(AesKeySize::Bits256, &key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv_with_size(AesKeySize::Bits256, &key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_gcm_siv_with_size_invalid_key_length() {
        let key = generate_random_bytes(32); // Wrong size for AES128
        let nonce = generate_random_bytes(12);
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_gcm_siv_with_size(AesKeySize::Bits128, &key, &nonce, aad, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key length");
    }

    #[test]
    fn test_aes256_gcm_siv_with_size_invalid_key_length() {
        let key = generate_random_bytes(16); // Wrong size for AES256
        let nonce = generate_random_bytes(12);
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_gcm_siv_with_size(AesKeySize::Bits256, &key, &nonce, aad, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key length");
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_aes_gcm_siv_with_size_invalid_nonce_length_panic() {
        let key_128 = generate_random_bytes(16);
        let short_nonce = generate_random_bytes(8); // Must be 12 bytes for GCM-SIV
        let aad = b"";
        let plaintext = b"test";

        // This will panic due to GenericArray::from_slice
        let _ = encrypt_aes_gcm_siv_with_size(AesKeySize::Bits128, &key_128, &short_nonce, aad, plaintext);
    }

    #[test]
    fn test_aes128_gcm_siv_safe_with_size_success() {
        let key = ClassifiedData::new(generate_random_bytes(16));
        let nonce = generate_random_bytes(12);
        let aad = b"Safe AAD for 128-bit GCM-SIV";
        let plaintext = b"Secure data for AES128 GCM-SIV with size control.";

        let (ciphertext, tag) = encrypt_aes_gcm_siv_safe_with_size(AesKeySize::Bits128, &key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm_siv_safe_with_size(AesKeySize::Bits128, &key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }
}