//! Counter mode over classified plaintexts. No authentication: a flipped
//! ciphertext bit flips the plaintext bit. Prefer [`gcm`](crate::gcm).

use classified::ClassifiedBuffer;
use honest_aes::{ctr, BLOCK};

use crate::{Cipher, Error};

/// Encrypt the buffer with the keystream starting at `counter`.
pub fn encrypt(cipher: &Cipher, counter: &[u8; BLOCK], plaintext: &ClassifiedBuffer) -> Vec<u8> {
    plaintext.expose(|view| {
        let mut data = view.as_bytes().to_vec();
        ctr::apply(cipher.aes(), counter, &mut data);
        data
    })
}

/// Decrypt into a buffer bounded to the plaintext's length.
pub fn decrypt(cipher: &Cipher, counter: &[u8; BLOCK], ciphertext: &[u8]) -> Result<ClassifiedBuffer, Error> {
    let mut data = ciphertext.to_vec();
    ctr::apply(cipher.aes(), counter, &mut data);
    let len = data.len();
    Ok(ClassifiedBuffer::try_from_vec(data, len)?)
}
