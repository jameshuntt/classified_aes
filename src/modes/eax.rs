// src/modes/eax.rs

use {
    crate::{
        config::AesKeySize,
        types::{Aes128Eax, Aes256Eax}
    },
    eax::aead::{
        generic_array::GenericArray,
        Aead,
        KeyInit,
        Payload // For Nonce/IV handling
    },
    classified::classified_data::ClassifiedData
};

/// Encrypts plaintext using AES-128-EAX mode.
///
/// Returns `(ciphertext, tag)`.
/// EAX expects a 16-byte nonce.
pub fn encrypt_aes_eax(
    key: &[u8],
    nonce: &[u8], // Renamed to nonce for AEAD modes
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let cipher = Aes128Eax::new_from_slice(key).map_err(|_| "Invalid key")?;
    // EAX nonce for Aes128Eax should be 16 bytes
    let nonce_ga = GenericArray::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };

    let encrypted = cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?;
    // The `eax` crate's `encrypt` method outputs `ciphertext || tag`.
    // The tag length is fixed at 16 bytes by default for EAX.
    let tag = encrypted[encrypted.len() - 16..].to_vec();
    let ciphertext = encrypted[..encrypted.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Encrypts plaintext using AES-128-EAX mode with a sensitive key.
///
/// Returns `(ciphertext, tag)`.
/// EAX expects a 16-byte nonce.
pub fn encrypt_aes_eax_safe(
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let cipher = Aes128Eax::new_from_slice(key.expose()).map_err(|_| "Invalid key")?;
    let nonce_ga = GenericArray::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };

    let encrypted = cipher.encrypt(nonce_ga, payload).map_err(|_| "Encryption failed")?;
    let tag = encrypted[encrypted.len() - 16..].to_vec();
    let ciphertext = encrypted[..encrypted.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Decrypts ciphertext using AES-128-EAX mode.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// EAX expects a 16-byte nonce.
pub fn decrypt_aes_eax(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes128Eax::new_from_slice(key).map_err(|_| "Invalid key")?;
    let nonce_ga = GenericArray::from_slice(nonce);

    let mut data = ciphertext.to_vec();
    data.extend_from_slice(tag); // Decrypt expects ciphertext || tag

    let payload = Payload { msg: &data, aad };

    cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")
}

/// Decrypts ciphertext using AES-128-EAX mode with a sensitive key.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// EAX expects a 16-byte nonce.
pub fn decrypt_aes_eax_safe(
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes128Eax::new_from_slice(key.expose()).map_err(|_| "Invalid key")?;
    let nonce_ga = GenericArray::from_slice(nonce);

    let mut data = ciphertext.to_vec();
    data.extend_from_slice(tag); // Decrypt expects ciphertext || tag

    let payload = Payload { msg: &data, aad };

    cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")
}

/// Encrypts plaintext using AES-EAX mode with a specified key size.
///
/// Returns `(ciphertext, tag)`.
/// EAX expects a 16-byte nonce regardless of AES key size.
pub fn encrypt_aes_eax_with_size(
    key_size: AesKeySize,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let encrypted = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128Eax::new_from_slice(key).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce); // Fixed 16-byte nonce
            cipher.encrypt(nonce_ga, Payload { msg: plaintext, aad }).map_err(|_| "Encryption failed")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256Eax::new_from_slice(key).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce); // Fixed 16-byte nonce
            cipher.encrypt(nonce_ga, Payload { msg: plaintext, aad }).map_err(|_| "Encryption failed")?
        }
    };

    let tag = encrypted[encrypted.len() - 16..].to_vec();
    let ciphertext = encrypted[..encrypted.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Encrypts plaintext using AES-EAX mode with a specified key size and sensitive key.
///
/// Returns `(ciphertext, tag)`.
/// EAX expects a 16-byte nonce regardless of AES key size.
pub fn encrypt_aes_eax_safe_with_size(
    key_size: AesKeySize,
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let encrypted = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128Eax::new_from_slice(key.expose()).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce);
            cipher.encrypt(nonce_ga, Payload { msg: plaintext, aad }).map_err(|_| "Encryption failed")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256Eax::new_from_slice(key.expose()).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce);
            cipher.encrypt(nonce_ga, Payload { msg: plaintext, aad }).map_err(|_| "Encryption failed")?
        }
    };

    let tag = encrypted[encrypted.len() - 16..].to_vec();
    let ciphertext = encrypted[..encrypted.len() - 16].to_vec();

    Ok((ciphertext, tag))
}

/// Decrypts ciphertext using AES-EAX mode with a specified key size.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// EAX expects a 16-byte nonce regardless of AES key size.
pub fn decrypt_aes_eax_with_size(
    key_size: AesKeySize,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut data = ciphertext.to_vec();
    data.extend_from_slice(tag); // Decrypt expects ciphertext || tag
    let payload = Payload { msg: &data, aad };

    let decrypted = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128Eax::new_from_slice(key).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce);
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256Eax::new_from_slice(key).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce);
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
    };
    Ok(decrypted)
}

/// Decrypts ciphertext using AES-EAX mode with a specified key size and sensitive key.
///
/// Returns `plaintext`. Fails if tag is invalid or data is tampered.
/// EAX expects a 16-byte nonce regardless of AES key size.
pub fn decrypt_aes_eax_safe_with_size(
    key_size: AesKeySize,
    key: &ClassifiedData<Vec<u8>>,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut data = ciphertext.to_vec();
    data.extend_from_slice(tag); // Decrypt expects ciphertext || tag
    let payload = Payload { msg: &data, aad };

    let decrypted = match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128Eax::new_from_slice(key.expose()).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce);
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256Eax::new_from_slice(key.expose()).map_err(|_| "Invalid key")?;
            let nonce_ga = GenericArray::from_slice(nonce);
            cipher.decrypt(nonce_ga, payload).map_err(|_| "Decryption failed (tag mismatch or data corruption)")?
        }
    };
    Ok(decrypted)
}

// tests/eax_tests.rs (or in a `#[cfg(test)]` module in `src/lib.rs`)

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

    // --- Tests for `encrypt_aes_eax` and `decrypt_aes_eax` ---

    #[test]
    fn test_aes128_eax_encryption_decryption_basic() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(); // 16 bytes for AES128
        let nonce = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap(); // 16 bytes for EAX nonce (typical)
        let aad = b"additional authenticated data for EAX";
        let plaintext = b"Hello, EAX authenticated world!";

        let (ciphertext, tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_eax(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16); // EAX tag is 16 bytes by default
        assert_eq!(ciphertext.len(), plaintext.len()); // In EAX, ciphertext length == plaintext length
    }

    #[test]
    fn test_aes128_eax_encryption_decryption_empty_aad() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b""; // Empty AAD
        let plaintext = b"Message with no AAD in EAX.";

        let (ciphertext, tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_eax(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_eax_encryption_decryption_empty_plaintext() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b"some AAD for empty plaintext";
        let plaintext = b""; // Empty plaintext

        let (ciphertext, tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_eax(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_eax_encryption_decryption_random_data() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = generate_random_bytes(64);
        let plaintext = generate_random_bytes(1024); // Random 1KB message

        let (ciphertext, tag) = encrypt_aes_eax(&key, &nonce, &aad, &plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_eax(&key, &nonce, &aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_eax_decryption_invalid_key() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, EAX world!";

        let (ciphertext, tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();

        let wrong_key = generate_random_bytes(16); // Different key
        let result = decrypt_aes_eax(&wrong_key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_eax_decryption_invalid_nonce() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, EAX world!";

        let (ciphertext, tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();

        let wrong_nonce = generate_random_bytes(16); // Different nonce
        let result = decrypt_aes_eax(&key, &wrong_nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_eax_decryption_tampered_aad() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b"original AAD";
        let plaintext = b"Hello, EAX world!";

        let (ciphertext, tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();

        let tampered_aad = b"tampered AAD"; // Modified AAD
        let result = decrypt_aes_eax(&key, &nonce, tampered_aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

    #[test]
    fn test_aes128_eax_decryption_tampered_ciphertext() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, EAX world!";

        let (mut ciphertext, tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();

        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01;
        } else {
            assert!(!plaintext.is_empty(), "Test requires non-empty plaintext for ciphertext tampering.");
        }

        let result = decrypt_aes_eax(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }



    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_aes128_eax_encrypt_invalid_nonce_length_panic() {
        let key = generate_random_bytes(16);
        let short_nonce = b"short"; // 5 bytes, not 16
        let aad = b"";
        let plaintext = b"test";

        let _ = encrypt_aes_eax(&key, short_nonce, aad, plaintext);
    }

    #[test]
    fn test_aes128_eax_decrypt_invalid_key_length() {
        let short_key = b"short_key"; // 9 bytes, not 16
        let nonce = generate_random_bytes(16);
        let aad = b"";
        let ciphertext = b"dummy_ciphertext";
        let tag = generate_random_bytes(16);

        let result = decrypt_aes_eax(short_key, &nonce, aad, ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key");
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_aes128_eax_decrypt_invalid_nonce_length_panic() {
        let key = generate_random_bytes(16);
        let short_nonce = b"short"; // 5 bytes, not 16
        let aad = b"";
        let ciphertext = b"dummy_ciphertext";
        let tag = generate_random_bytes(16);

        let _ = decrypt_aes_eax(&key, short_nonce, aad, ciphertext, &tag);
    }
    
    // --- Tests for _safe functions ---

    #[test]
    fn test_aes128_eax_safe_encryption_decryption_basic() {
        let key = ClassifiedData::new(hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let nonce = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let aad = b"sensitive data for EAX";
        let plaintext = b"Hello, secure EAX world!";

        let (ciphertext, tag) = encrypt_aes_eax_safe(&key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_eax_safe(&key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    // --- Tests for _with_size functions ---

    #[test]
    #[should_panic(expected = "slice length must be equal to array length")]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_aes_eax_with_size_invalid_nonce_length_panic() {
        let key_128 = generate_random_bytes(16);
        let short_nonce = generate_random_bytes(8); // Must be 16 bytes for EAX
        let aad = b"";
        let plaintext = b"test";

        // This will panic due to GenericArray::from_slice
        let _ = encrypt_aes_eax_with_size(AesKeySize::Bits128, &key_128, &short_nonce, aad, plaintext);
    }

    #[test]
    fn test_aes128_eax_decryption_tampered_tag() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, EAX world!";

        let (ciphertext, mut tag) = encrypt_aes_eax(&key, &nonce, aad, plaintext).unwrap();

        if !tag.is_empty() {
            tag[0] ^= 0x01;
        } else {
            panic!("Tag should not be empty for tampering test.");
        }

        let result = decrypt_aes_eax(&key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed (tag mismatch or data corruption)");
    }

        #[test]
    fn test_aes128_eax_encrypt_invalid_key_length() {
        let short_key = b"short_key"; // 9 bytes, not 16
        let nonce = generate_random_bytes(16);
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_eax(short_key, &nonce, aad, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key");
    }




    // --- Tests for _with_size functions ---

    #[test]
    fn test_aes128_eax_with_size_success() {
        let key = generate_random_bytes(16);
        let nonce = generate_random_bytes(16);
        let aad = b"AAD for 128-bit EAX";
        let plaintext = b"Data for AES128 EAX with size control.";

        let (ciphertext, tag) = encrypt_aes_eax_with_size(AesKeySize::Bits128, &key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_eax_with_size(AesKeySize::Bits128, &key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes256_eax_with_size_success() {
        let key = generate_random_bytes(32);
        let nonce = generate_random_bytes(16);
        let aad = b"AAD for 256-bit EAX";
        let plaintext = b"Data for AES256 EAX with size control, a bit longer.";

        let (ciphertext, tag) = encrypt_aes_eax_with_size(AesKeySize::Bits256, &key, &nonce, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_eax_with_size(AesKeySize::Bits256, &key, &nonce, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_eax_with_size_invalid_key_length() {
        let key = generate_random_bytes(32); // Wrong size for AES128
        let nonce = generate_random_bytes(16);
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_eax_with_size(AesKeySize::Bits128, &key, &nonce, aad, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key");
    }

    #[test]
    fn test_aes256_eax_with_size_invalid_key_length() {
        let key = generate_random_bytes(16); // Wrong size for AES256
        let nonce = generate_random_bytes(16);
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_eax_with_size(AesKeySize::Bits256, &key, &nonce, aad, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key");
    }
}
