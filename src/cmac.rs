//! CMAC with a classified key: tag public data, verify in constant time.

use honest_aes::cmac;

use crate::{Cipher, BLOCK};

/// The 16-byte tag of `message`.
pub fn tag(cipher: &Cipher, message: &[u8]) -> [u8; BLOCK] {
    cmac::tag(cipher.aes(), message)
}

/// Whether `tag` is the tag of `message`, compared in constant time.
pub fn verify(cipher: &Cipher, message: &[u8], tag: &[u8; BLOCK]) -> bool {
    cmac::verify(cipher.aes(), message, tag)
}
