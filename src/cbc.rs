//! Cipher block chaining with PKCS#7 over classified plaintexts.
//!
//! Confidentiality only, and the padding error on decryption is an oracle
//! if an attacker can observe it. Prefer [`gcm`](crate::gcm); this is for
//! formats that require CBC.

use classified::ClassifiedBuffer;
use honest_aes::{cbc, BLOCK};

use crate::{Cipher, Error};

/// Pad and encrypt the buffer under `iv`.
pub fn encrypt(cipher: &Cipher, iv: &[u8; BLOCK], plaintext: &ClassifiedBuffer) -> Vec<u8> {
    plaintext.expose(|view| cbc::encrypt(cipher.aes(), iv, view.as_bytes()))
}

/// Decrypt and unpad into a buffer bounded to the plaintext's length.
pub fn decrypt(cipher: &Cipher, iv: &[u8; BLOCK], ciphertext: &[u8]) -> Result<ClassifiedBuffer, Error> {
    let plaintext = cbc::decrypt(cipher.aes(), iv, ciphertext)?;
    let len = plaintext.len();
    Ok(ClassifiedBuffer::try_from_vec(plaintext, len)?)
}
