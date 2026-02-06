use {
    aes_gcm::{
        Aes128Gcm,
        KeyInit,
        aead::{
            Aead,
            generic_array::GenericArray
        },
    }
};


pub fn encrypt_aes_gcm(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| "invalid key")?;
    let nonce = GenericArray::from_slice(iv);
    let payload = aes_gcm::aead::Payload { msg: plaintext, aad };

    let encrypted = cipher.encrypt(nonce, payload).map_err(|_| "encryption failed")?;
    let tag = encrypted[encrypted.len() - 16..].to_vec(); // GCM tag is the last 16 bytes
    let ciphertext = encrypted[..encrypted.len() - 16].to_vec();

    Ok((ciphertext, tag))
}


// pub fn encrypt_aes_gcm(key: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> // returns (ciphertext, tag)

pub fn decrypt_aes_gcm(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| "invalid key")?;
    let nonce = GenericArray::from_slice(iv);
    let mut data = ciphertext.to_vec();
    data.extend_from_slice(tag);

    let payload = aes_gcm::aead::Payload { msg: &data, aad };

    cipher.decrypt(nonce, payload).map_err(|_| "decryption failed")
}


// pub fn decrypt_aes_gcm(key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>, &'static str>


// tests/gcm_tests.rs (or in a `#[cfg(test)]` module in `src/lib.rs`)

#[cfg(test)]
mod tests {
    #![allow(unused, unused_must_use)]
    use super::*; // Import functions from the parent module
    use hex::FromHex; // For easier key/IV/AAD/plaintext creation from hex strings
    use rand::{rngs::OsRng, Rng, TryRngCore}; // For generating random data

    // --- Helper function for generating random bytes ---
    fn generate_random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        OsRng.try_fill_bytes(&mut bytes);
        bytes
    }

    // --- Tests for `encrypt_aes_gcm` and `decrypt_aes_gcm` ---

    #[test]
    fn test_aes128_gcm_encryption_decryption_basic() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(); // 16 bytes for AES128
        let iv = hex::decode("000000000000000000000000").unwrap(); // 12 bytes for GCM nonce
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM world!";

        let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm(&key, &iv, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16); // GCM tag is 16 bytes
        assert_eq!(ciphertext.len(), plaintext.len()); // In GCM, ciphertext length == plaintext length
    }

    #[test]
    fn test_aes128_gcm_encryption_decryption_empty_aad() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = b""; // Empty AAD
        let plaintext = b"Message with no AAD.";

        let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm(&key, &iv, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_gcm_encryption_decryption_empty_plaintext() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = b"some AAD";
        let plaintext = b""; // Empty plaintext

        let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm(&key, &iv, aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_gcm_encryption_decryption_random_data() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = generate_random_bytes(32);
        let plaintext = generate_random_bytes(256); // Random 256-byte message

        let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, &aad, &plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_gcm(&key, &iv, &aad, &ciphertext, &tag).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(tag.len(), 16);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_gcm_decryption_invalid_key() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM world!";

        let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();

        let wrong_key = generate_random_bytes(16); // Different key
        let result = decrypt_aes_gcm(&wrong_key, &iv, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "decryption failed");
    }

    #[test]
    fn test_aes128_gcm_decryption_invalid_iv() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM world!";

        let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();

        let wrong_iv = generate_random_bytes(12); // Different IV
        let result = decrypt_aes_gcm(&key, &wrong_iv, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "decryption failed");
    }

    #[test]
    fn test_aes128_gcm_decryption_tampered_aad() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = b"original AAD";
        let plaintext = b"Hello, GCM world!";

        let (ciphertext, tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();

        let tampered_aad = b"tampered AAD"; // Modified AAD
        let result = decrypt_aes_gcm(&key, &iv, tampered_aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "decryption failed");
    }

    #[test]
    fn test_aes128_gcm_decryption_tampered_ciphertext() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM world!";

        let (mut ciphertext, tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();
        
        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0x01; 
        } else {
            // Handle case for empty plaintext/ciphertext
            // If plaintext is empty, ciphertext is also empty.
            // In GCM, if ciphertext is empty, there's no data to tamper with directly.
            // But if the tag is still provided and doesn't match, it will fail.
            // For this test, ensure plaintext is not empty.
            assert!(!plaintext.is_empty(), "Test requires non-empty plaintext for ciphertext tampering.");
            panic!("Test requires non-empty plaintext for ciphertext tampering.");
        }

        let result = decrypt_aes_gcm(&key, &iv, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "decryption failed");
    }

    #[test]
    fn test_aes128_gcm_decryption_tampered_tag() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(12);
        let aad = b"additional authenticated data";
        let plaintext = b"Hello, GCM world!";

        let (ciphertext, mut tag) = encrypt_aes_gcm(&key, &iv, aad, plaintext).unwrap();
        
        // Tamper with tag
        if !tag.is_empty() {
            tag[0] ^= 0x01; 
        } else {
            panic!("Tag should not be empty for tampering test.");
        }

        let result = decrypt_aes_gcm(&key, &iv, aad, &ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "decryption failed");
    }

    #[test]
    fn test_aes128_gcm_encrypt_invalid_key_length() {
        let short_key = b"short_key"; // 9 bytes, not 16
        let iv = generate_random_bytes(12);
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_gcm(short_key, &iv, aad, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "invalid key");
    }

    #[test]
    fn test_aes128_gcm_encrypt_invalid_iv_length() {
        let key = generate_random_bytes(16);
        let short_iv = b"short"; // 5 bytes, not 12
        let aad = b"";
        let plaintext = b"test";

        let result = encrypt_aes_gcm(&key, short_iv, aad, plaintext);
        assert!(result.is_err());
        // The error message from `GenericArray::from_slice` will be different,
        // it panics if the length doesn't match.
        // So this test needs to use `#[should_panic]` if the `map_err` doesn't catch it.
        // Let's refine this to catch the specific panic if it happens directly from GenericArray.
        // If `new_from_slice` itself handles IV length, then "Invalid key/IV" would be appropriate.
        // Based on `aes-gcm` crate, `GenericArray::from_slice` will panic if the slice length is wrong.
        // We'll need a `should_panic` for this.
        assert_eq!(result.unwrap_err(), "encryption failed"); // This assumes the `encrypt` call will fail due to bad nonce.
    }

    #[test]
    #[should_panic(expected = "slice length must be equal to array length")]
    #[should_panic(expected = "assertion `left == right` failed\n  left: 5\n right: 12")]
    fn test_aes128_gcm_encrypt_invalid_iv_length_panic() {
        let key = generate_random_bytes(16);
        let short_iv = b"short"; // 5 bytes, not 12
        let aad = b"";
        let plaintext = b"test";

        let _ = encrypt_aes_gcm(&key, short_iv, aad, plaintext);
    }

    #[test]
    fn test_aes128_gcm_decrypt_invalid_key_length() {
        let short_key = b"short_key"; // 9 bytes, not 16
        let iv = generate_random_bytes(12);
        let aad = b"";
        let ciphertext = b"dummy_ciphertext";
        let tag = generate_random_bytes(16);

        let result = decrypt_aes_gcm(short_key, &iv, aad, ciphertext, &tag);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "invalid key");
    }

    #[test]
    #[should_panic(expected = "slice length must be equal to array length")]
    #[should_panic(expected = "assertion `left == right` failed\n  left: 5\n right: 12")]
    fn test_aes128_gcm_decrypt_invalid_iv_length_panic() {
        let key = generate_random_bytes(16);
        let short_iv = b"short"; // 5 bytes, not 12
        let aad = b"";
        let ciphertext = b"dummy_ciphertext";
        let tag = generate_random_bytes(16);

        let _ = decrypt_aes_gcm(&key, short_iv, aad, ciphertext, &tag);
    }


}
