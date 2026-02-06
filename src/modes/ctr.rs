use {
    crate::{
        config::AesKeySize,
        types::{Aes128Ctr, Aes256Ctr}
    },
    cipher::{KeyIvInit, StreamCipher},
    classified::classified_data::ClassifiedData
};




// pub fn encrypt_aes_ctr(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>
pub fn encrypt_aes_ctr(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new_from_slices(key, iv).unwrap();
    let mut buffer = plaintext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

pub fn encrypt_aes_ctr_safe(
    key: &ClassifiedData<Vec<u8>>,
    iv: &[u8],
    plaintext: &[u8]
) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new_from_slices(
        key.expose(), iv
    ).unwrap();

    let mut buffer = plaintext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

// pub fn decrypt_aes_ctr(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8>
pub fn decrypt_aes_ctr(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new_from_slices(key, iv).unwrap();
    let mut buffer = ciphertext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

pub fn decrypt_aes_ctr_safe(
    key: &ClassifiedData<Vec<u8>>,
    iv: &[u8],
    ciphertext: &[u8]
) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new_from_slices(
        key.expose(), iv
    ).unwrap();
    
    let mut buffer = ciphertext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}




/// Encrypt with AES-CTR using key size
pub fn encrypt_aes_ctr_with_size(
    key_size: AesKeySize,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut buffer = plaintext.to_vec();

    match key_size {
        AesKeySize::Bits128 => {
            let mut cipher = Aes128Ctr::new_from_slices(key, iv)
                .map_err(|_| "Invalid key/IV")?;

            cipher.apply_keystream(&mut buffer);
        }
        AesKeySize::Bits256 => {
            let mut cipher = Aes256Ctr::new_from_slices(key, iv)
                .map_err(|_| "Invalid key/IV")?;
            
            cipher.apply_keystream(&mut buffer);
        }
    }

    Ok(buffer)
}

pub fn encrypt_aes_ctr_safe_with_size(
    key_size: AesKeySize,
    key: &ClassifiedData<Vec<u8>>,
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut buffer = plaintext.to_vec();

    match key_size {
        AesKeySize::Bits128 => {
            let mut cipher = Aes128Ctr::new_from_slices(
                key.expose(), iv
            ).map_err(|_| "Invalid key/IV")?;
            cipher.apply_keystream(&mut buffer);
        }
        AesKeySize::Bits256 => {
            let mut cipher = Aes256Ctr::new_from_slices(
                key.expose(), iv
            ).map_err(|_| "Invalid key/IV")?;
            cipher.apply_keystream(&mut buffer);
        }
    }

    Ok(buffer)
}

/// Decrypt with AES-CTR using key size (identical to encrypt in CTR mode)
pub fn decrypt_aes_ctr_with_size(
    key_size: AesKeySize,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    encrypt_aes_ctr_with_size(key_size, key, iv, ciphertext)
}

pub fn decrypt_aes_ctr_safe_with_size(
    key_size: AesKeySize,
    key: &ClassifiedData<Vec<u8>>,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    encrypt_aes_ctr_with_size(key_size, key.expose(), iv, ciphertext)
}

// tests/ctr_tests.rs (or in a `#[cfg(test)]` module in `src/lib.rs`)

#[cfg(test)]
mod tests {
    #![allow(unused, unused_must_use)]
    use super::*; // Import functions from the parent module
    use hex::FromHex; // For easier key/IV/plaintext creation from hex strings
    use rand::{rngs::OsRng, Rng, TryRngCore}; // For generating random data
    use classified::classified_data::ClassifiedData; // Import ClassifiedData

    // --- Helper function for generating random bytes ---
    fn generate_random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        OsRng.try_fill_bytes(&mut bytes);
        bytes
    }

    // --- Tests for `encrypt_aes_ctr` and `decrypt_aes_ctr` ---

    #[test]
    fn test_aes128_ctr_encryption_decryption_basic() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(); // 16 bytes
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap(); // 16 bytes (nonce + counter)
        let plaintext = b"Short message for CTR test.";

        let ciphertext = encrypt_aes_ctr(&key, &iv, plaintext);
        let decrypted_plaintext = decrypt_aes_ctr(&key, &iv, &ciphertext);

        assert_eq!(decrypted_plaintext, plaintext);
        // In CTR, ciphertext length is always equal to plaintext length
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_ctr_encryption_decryption_long_data() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(16);
        let plaintext = generate_random_bytes(1024 * 5); // 5KB of random data

        let ciphertext = encrypt_aes_ctr(&key, &iv, &plaintext);
        let decrypted_plaintext = decrypt_aes_ctr(&key, &iv, &ciphertext);

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidLength")]
    fn test_aes128_ctr_invalid_key_length_encrypt() {
        let short_key = b"short_key"; // Must be 16 bytes for AES128
        let iv = generate_random_bytes(16);
        let plaintext = b"test";
        let _ = encrypt_aes_ctr(short_key, &iv, plaintext);
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidLength")]
    fn test_aes128_ctr_invalid_iv_length_encrypt() {
        let key = generate_random_bytes(16);
        let short_iv = b"short_iv"; // Must be 16 bytes for CTR (nonce + counter)
        let plaintext = b"test";
        let _ = encrypt_aes_ctr(&key, short_iv, plaintext);
    }

    // --- Tests for `encrypt_aes_ctr_safe` and `decrypt_aes_ctr_safe` ---

    #[test]
    fn test_aes128_ctr_safe_encryption_decryption_basic() {
        let key_data = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let key = ClassifiedData::new(key_data);
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = b"Secret message via safe CTR.";

        let ciphertext = encrypt_aes_ctr_safe(&key, &iv, plaintext);
        let decrypted_plaintext = decrypt_aes_ctr_safe(&key, &iv, &ciphertext);

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidLength")]
    fn test_aes128_ctr_safe_invalid_key_length_encrypt() {
        let key_data = b"short_key".to_vec(); // Wrong length
        let key = ClassifiedData::new(key_data);
        let iv = generate_random_bytes(16);
        let plaintext = b"test";
        let _ = encrypt_aes_ctr_safe(&key, &iv, plaintext);
    }

    // --- Tests for `encrypt_aes_ctr_with_size` and `decrypt_aes_ctr_with_size` ---

    #[test]
    fn test_aes128_ctr_with_size_success() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(16);
        let plaintext = b"Data for AES128 CTR with size control.";

        let ciphertext = encrypt_aes_ctr_with_size(AesKeySize::Bits128, &key, &iv, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_ctr_with_size(AesKeySize::Bits128, &key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes256_ctr_with_size_success() {
        let key = generate_random_bytes(32);
        let iv = generate_random_bytes(16);
        let plaintext = b"Data for AES256 CTR with size control, a bit longer.";

        let ciphertext = encrypt_aes_ctr_with_size(AesKeySize::Bits256, &key, &iv, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_ctr_with_size(AesKeySize::Bits256, &key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_ctr_with_size_invalid_key_length() {
        let key = generate_random_bytes(32); // Wrong size for AES128
        let iv = generate_random_bytes(16);
        let plaintext = b"test";

        let result = encrypt_aes_ctr_with_size(AesKeySize::Bits128, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_with_size(AesKeySize::Bits128, &key, &iv, plaintext); // Plaintext as dummy ciphertext
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_aes256_ctr_with_size_invalid_key_length() {
        let key = generate_random_bytes(16); // Wrong size for AES256
        let iv = generate_random_bytes(16);
        let plaintext = b"test";

        let result = encrypt_aes_ctr_with_size(AesKeySize::Bits256, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_with_size(AesKeySize::Bits256, &key, &iv, plaintext); // Plaintext as dummy ciphertext
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_aes_ctr_with_size_invalid_iv_length() {
        let key_128 = generate_random_bytes(16);
        let key_256 = generate_random_bytes(32);
        let short_iv = generate_random_bytes(8); // Must be 16 bytes for CTR
        let plaintext = b"test";

        let result = encrypt_aes_ctr_with_size(AesKeySize::Bits128, &key_128, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = encrypt_aes_ctr_with_size(AesKeySize::Bits256, &key_256, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_with_size(AesKeySize::Bits128, &key_128, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_with_size(AesKeySize::Bits256, &key_256, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    // --- Tests for `encrypt_aes_ctr_safe_with_size` and `decrypt_aes_ctr_safe_with_size` ---

    #[test]
    fn test_aes128_ctr_safe_with_size_success() {
        let key = ClassifiedData::new(generate_random_bytes(16));
        let iv = generate_random_bytes(16);
        let plaintext = b"Safe data for AES128 CTR with size control.";

        let ciphertext = encrypt_aes_ctr_safe_with_size(AesKeySize::Bits128, &key, &iv, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_ctr_safe_with_size(AesKeySize::Bits128, &key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes256_ctr_safe_with_size_success() {
        let key = ClassifiedData::new(generate_random_bytes(32));
        let iv = generate_random_bytes(16);
        let plaintext = b"Safe data for AES256 CTR with size control, longer message.";

        let ciphertext = encrypt_aes_ctr_safe_with_size(AesKeySize::Bits256, &key, &iv, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_ctr_safe_with_size(AesKeySize::Bits256, &key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_aes128_ctr_safe_with_size_invalid_key_length() {
        let key = ClassifiedData::new(generate_random_bytes(32)); // Wrong size for AES128
        let iv = generate_random_bytes(16);
        let plaintext = b"test";

        let result = encrypt_aes_ctr_safe_with_size(AesKeySize::Bits128, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_safe_with_size(AesKeySize::Bits128, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_aes256_ctr_safe_with_size_invalid_key_length() {
        let key = ClassifiedData::new(generate_random_bytes(16)); // Wrong size for AES256
        let iv = generate_random_bytes(16);
        let plaintext = b"test";

        let result = encrypt_aes_ctr_safe_with_size(AesKeySize::Bits256, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_safe_with_size(AesKeySize::Bits256, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_aes_ctr_safe_with_size_invalid_iv_length() {
        let key_128 = ClassifiedData::new(generate_random_bytes(16));
        let key_256 = ClassifiedData::new(generate_random_bytes(32));
        let short_iv = generate_random_bytes(8); // Wrong size for CTR
        let plaintext = b"test";

        let result = encrypt_aes_ctr_safe_with_size(AesKeySize::Bits128, &key_128, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = encrypt_aes_ctr_safe_with_size(AesKeySize::Bits256, &key_256, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_safe_with_size(AesKeySize::Bits128, &key_128, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let result = decrypt_aes_ctr_safe_with_size(AesKeySize::Bits256, &key_256, &short_iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }
}