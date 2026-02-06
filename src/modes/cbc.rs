use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};


use crate::config::AesKeySize;
use crate::types::{Aes128CbcDec, Aes128CbcEnc, Aes256CbcDec, Aes256CbcEnc};



// pub fn encrypt_aes_cbc(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8>
pub fn encrypt_aes_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128CbcEnc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_padded_vec_mut::<Pkcs7>(ciphertext)
}

// pub fn decrypt_aes_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8>
pub fn decrypt_aes_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128CbcDec::new_from_slices(key, iv).unwrap();
    cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).unwrap()
}






pub fn decrypt_aes_cbc_with_context(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes128CbcDec::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
    cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).map_err(|_| "Decryption failed")
}

// pub fn encrypt_aes_cbc_with_context(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
//     let cipher = Aes128CbcEnc::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
//     cipher.encrypt_padded_vec_mut::<Pkcs7>(ciphertext).map_err(|_| "Encryption failed")
// }





pub fn encrypt_aes_cbc_with_size(
    key_size: AesKeySize,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128CbcEnc::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
            Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
            Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
        }
    }
}

pub fn decrypt_aes_cbc_with_size(
    key_size: AesKeySize,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    match key_size {
        AesKeySize::Bits128 => {
            let cipher = Aes128CbcDec::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
            cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).map_err(|_| "Decryption failed")
        }
        AesKeySize::Bits256 => {
            let cipher = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
            cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).map_err(|_| "Decryption failed")
        }
    }
}
// pub fn decrypt_aes_cbc_with_size(
//     key_size: AesKeySize,
//     key: &[u8],
//     iv: &[u8],
//     plaintext: &[u8],
// ) -> Result<Vec<u8>, &'static str> {
//     match key_size {
//         AesKeySize::Bits128 => {
//             let cipher = Aes128CbcDec::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
//             Ok(cipher.decrypt_padded_vec_mut::<Pkcs7>(plaintext))
//         }
//         AesKeySize::Bits256 => {
//             let cipher = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| "Invalid key/IV")?;
//             Ok(cipher.decrypt_block_mut::<Pkcs7>(plaintext))
//         }
//     }
// }


// tests/crypto_tests.rs (or in a `#[cfg(test)]` module in `src/lib.rs`)

#[cfg(test)]
mod tests {
    #![allow(unused, unused_must_use)]
    use super::*; // Import functions from the parent module
    use hex::FromHex; // For easier key/IV/plaintext creation from hex strings
    use rand::{rngs::OsRng, RngCore, TryRngCore}; // For generating random data

    // --- Helper function for generating random data ---
    fn generate_random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        OsRng.try_fill_bytes(&mut bytes);
        bytes
    }

    // --- Tests for `encrypt_aes_cbc` and `decrypt_aes_cbc` ---

    #[test]
    fn test_aes128_cbc_encryption_decryption_short_plaintext() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = b"Hello, world!"; // 13 bytes, needs padding

        let ciphertext = encrypt_aes_cbc(&key, &iv, plaintext);
        let decrypted_plaintext = decrypt_aes_cbc(&key, &iv, &ciphertext);

        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    fn test_aes128_cbc_encryption_decryption_long_plaintext() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = "This is a much longer plaintext that should span multiple blocks to test the CBC mode thoroughly.".as_bytes();

        let ciphertext = encrypt_aes_cbc(&key, &iv, plaintext);
        let decrypted_plaintext = decrypt_aes_cbc(&key, &iv, &ciphertext);

        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    fn test_aes128_cbc_encryption_decryption_exact_block_size() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = b"0123456789ABCDEF"; // 16 bytes, exact block size

        let ciphertext = encrypt_aes_cbc(&key, &iv, plaintext);
        let decrypted_plaintext = decrypt_aes_cbc(&key, &iv, &ciphertext);

        assert_eq!(decrypted_plaintext, plaintext);
        // Ciphertext should be 32 bytes (16 for original + 16 for padding block)
        assert_eq!(ciphertext.len(), 32);
    }

    // #[test]
    // #[should_panic(expected = "unwrap() on an `Err` value: InvalidLength")]
    // fn test_aes128_cbc_invalid_key_length_encrypt() {
    //     let short_key = b"short_key"; // Must be 16 bytes for AES128
    //     let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
    //     let plaintext = b"test";
    //     let _ = encrypt_aes_cbc(short_key, &iv, plaintext);
    // }

    // #[test]
    // #[should_panic(expected = "unwrap() on an `Err` value: InvalidLength")]
    // fn test_aes128_cbc_invalid_iv_length_encrypt() {
    //     let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    //     let short_iv = b"short_iv"; // Must be 16 bytes for CBC
    //     let plaintext = b"test";
    //     let _ = encrypt_aes_cbc(&key, short_iv, plaintext);
    // }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidLength")]
    fn test_aes128_cbc_invalid_key_length_encrypt() {
        let short_key = b"short_key"; // Must be 16 bytes for AES128
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = b"test";
        let _ = encrypt_aes_cbc(short_key, &iv, plaintext);
    }

    #[test]
    #[should_panic(expected = "called `Result::unwrap()` on an `Err` value: InvalidLength")]
    fn test_aes128_cbc_invalid_iv_length_encrypt() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let short_iv = b"short_iv"; // Must be 16 bytes for CBC
        let plaintext = b"test";
        let _ = encrypt_aes_cbc(&key, short_iv, plaintext);
    }

    // --- Tests for `decrypt_aes_cbc_with_context` ---

    #[test]
    fn test_decrypt_aes_cbc_with_context_success() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = b"Secret message.";
        let ciphertext = encrypt_aes_cbc(&key, &iv, plaintext); // Use the existing encrypt func

        let result = decrypt_aes_cbc_with_context(&key, &iv, &ciphertext);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_aes_cbc_with_context_invalid_key_length() {
        let short_key = b"short_key";
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let ciphertext = vec![0u8; 32]; // Dummy ciphertext

        let result = decrypt_aes_cbc_with_context(short_key, &iv, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_decrypt_aes_cbc_with_context_invalid_iv_length() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let short_iv = b"short_iv";
        let ciphertext = vec![0u8; 32]; // Dummy ciphertext

        let result = decrypt_aes_cbc_with_context(&key, short_iv, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_decrypt_aes_cbc_with_context_invalid_padding() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        // Create a ciphertext that is likely to have invalid padding
        let mut invalid_ciphertext = vec![0u8; 32]; // 2 blocks of zeros
        invalid_ciphertext[31] = 0xFF; // Corrupt the padding byte

        let result = decrypt_aes_cbc_with_context(&key, &iv, &invalid_ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed");
    }

    #[test]
    fn test_decrypt_aes_cbc_with_context_truncated_ciphertext() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let iv = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
        let plaintext = b"short";
        let ciphertext = encrypt_aes_cbc(&key, &iv, plaintext);

        // Truncate the ciphertext
        let truncated_ciphertext = &ciphertext[0..ciphertext.len() - 5];
        let result = decrypt_aes_cbc_with_context(&key, &iv, truncated_ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed");
    }


    // --- Tests for `encrypt_aes_cbc_with_size` and `decrypt_aes_cbc_with_size` ---

    #[test]
    fn test_aes128_cbc_with_size_success() {
        let key = generate_random_bytes(16); // 16 bytes for AES128
        let iv = generate_random_bytes(16);
        let plaintext = b"Hello from AES128 with size!";

        let ciphertext = encrypt_aes_cbc_with_size(AesKeySize::Bits128, &key, &iv, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_cbc_with_size(AesKeySize::Bits128, &key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    fn test_aes256_cbc_with_size_success() {
        let key = generate_random_bytes(32); // 32 bytes for AES256
        let iv = generate_random_bytes(16);
        let plaintext = b"Hello from AES256 with size, this is a longer message for good measure.";

        let ciphertext = encrypt_aes_cbc_with_size(AesKeySize::Bits256, &key, &iv, plaintext).unwrap();
        let decrypted_plaintext = decrypt_aes_cbc_with_size(AesKeySize::Bits256, &key, &iv, &ciphertext).unwrap();

        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    fn test_aes128_cbc_with_size_invalid_key_length() {
        let key = generate_random_bytes(32); // Wrong size for AES128
        let iv = generate_random_bytes(16);
        let plaintext = b"test";

        let result = encrypt_aes_cbc_with_size(AesKeySize::Bits128, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let ciphertext = vec![0u8; 32];
        let result = decrypt_aes_cbc_with_size(AesKeySize::Bits128, &key, &iv, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_aes256_cbc_with_size_invalid_key_length() {
        let key = generate_random_bytes(16); // Wrong size for AES256
        let iv = generate_random_bytes(16);
        let plaintext = b"test";

        let result = encrypt_aes_cbc_with_size(AesKeySize::Bits256, &key, &iv, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");

        let ciphertext = vec![0u8; 32];
        let result = decrypt_aes_cbc_with_size(AesKeySize::Bits256, &key, &iv, &ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_aes_cbc_with_size_invalid_iv_length() {
        let key_128 = generate_random_bytes(16);
        let key_256 = generate_random_bytes(32);
        let short_iv = generate_random_bytes(8); // Wrong size for CBC
        let plaintext = b"test";

        let result_enc128 = encrypt_aes_cbc_with_size(AesKeySize::Bits128, &key_128, &short_iv, plaintext);
        assert!(result_enc128.is_err());
        assert_eq!(result_enc128.unwrap_err(), "Invalid key/IV");

        let result_enc256 = encrypt_aes_cbc_with_size(AesKeySize::Bits256, &key_256, &short_iv, plaintext);
        assert!(result_enc256.is_err());
        assert_eq!(result_enc256.unwrap_err(), "Invalid key/IV");

        let ciphertext = vec![0u8; 32];
        let result_dec128 = decrypt_aes_cbc_with_size(AesKeySize::Bits128, &key_128, &short_iv, &ciphertext);
        assert!(result_dec128.is_err());
        assert_eq!(result_dec128.unwrap_err(), "Invalid key/IV");

        let result_dec256 = decrypt_aes_cbc_with_size(AesKeySize::Bits256, &key_256, &short_iv, &ciphertext);
        assert!(result_dec256.is_err());
        assert_eq!(result_dec256.unwrap_err(), "Invalid key/IV");
    }

    #[test]
    fn test_aes_cbc_with_size_decryption_failed_invalid_padding() {
        let key_128 = generate_random_bytes(16);
        let iv = generate_random_bytes(16);
        let mut invalid_ciphertext = vec![0u8; 32]; // Simulate a corrupted ciphertext
        invalid_ciphertext[31] = 0x01; // Invalid padding byte

        let result = decrypt_aes_cbc_with_size(AesKeySize::Bits128, &key_128, &iv, &invalid_ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed");
    }

    #[test]
    fn test_aes_cbc_with_size_decryption_failed_truncated_ciphertext() {
        let key = generate_random_bytes(16);
        let iv = generate_random_bytes(16);
        let plaintext = b"Some data";
        let ciphertext = encrypt_aes_cbc_with_size(AesKeySize::Bits128, &key, &iv, plaintext).unwrap();

        // Truncate the ciphertext, making it un-decryptable
        let truncated_ciphertext = &ciphertext[0..ciphertext.len() - 5];
        let result = decrypt_aes_cbc_with_size(AesKeySize::Bits128, &key, &iv, truncated_ciphertext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Decryption failed");
    }
}