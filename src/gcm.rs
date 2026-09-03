//! AES-GCM over classified plaintexts: seal a container into public bytes,
//! open public bytes back into a container.

use classified::{ClassifiedBuffer, ClassifiedBytes};
use honest_aes::gcm;

use crate::{Cipher, Error, Nonce};

/// Encrypt and tag the buffer. The result is the ciphertext followed by
/// the 16-byte tag over `aad` and the ciphertext; it is public.
///
/// The plaintext is copied out of the container once and encrypted in
/// place, so the copy is ciphertext by the time the call returns.
pub fn seal(cipher: &Cipher, nonce: &Nonce, aad: &[u8], plaintext: &ClassifiedBuffer) -> Vec<u8> {
    plaintext.expose(|view| seal_bytes(cipher, nonce, aad, view.as_bytes()))
}

/// [`seal`] for a fixed-size secret such as a key.
pub fn seal_fixed<const N: usize>(cipher: &Cipher, nonce: &Nonce, aad: &[u8], plaintext: &ClassifiedBytes<N>) -> Vec<u8> {
    plaintext.expose(|view| seal_bytes(cipher, nonce, aad, view.as_bytes()))
}

/// Check the tag and decrypt into a buffer bounded to the plaintext's
/// length. A mismatch returns [`AesError::TagMismatch`](honest_aes::AesError::TagMismatch)
/// and nothing else; an empty plaintext is refused by the container.
pub fn open(cipher: &Cipher, nonce: &Nonce, aad: &[u8], sealed: &[u8]) -> Result<ClassifiedBuffer, Error> {
    let plaintext = gcm::decrypt(cipher.aes(), nonce.as_bytes(), aad, sealed)?;
    let len = plaintext.len();
    Ok(ClassifiedBuffer::try_from_vec(plaintext, len)?)
}

/// [`open`] into a fixed-size container. Refused with
/// [`ClassifiedError::LengthMismatch`](classified::ClassifiedError::LengthMismatch)
/// when the plaintext is not `N` bytes.
pub fn open_fixed<const N: usize>(cipher: &Cipher, nonce: &Nonce, aad: &[u8], sealed: &[u8]) -> Result<ClassifiedBytes<N>, Error> {
    let buffer = open(cipher, nonce, aad, sealed)?;
    Ok(buffer.expose(|view| ClassifiedBytes::try_from_slice(view.as_bytes()))?)
}

fn seal_bytes(cipher: &Cipher, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    gcm::encrypt(cipher.aes(), nonce.as_bytes(), aad, plaintext).expect("a 96-bit nonce and a bounded buffer are always accepted")
}
