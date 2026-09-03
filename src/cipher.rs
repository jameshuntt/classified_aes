use core::fmt;

use classified::ClassifiedBytes;
use honest_aes::Aes;

use crate::Error;

/// An expanded key built from a classified one.
///
/// The key bytes are exposed once, inside the constructor, to run the key
/// schedule; from then on only the round keys exist, inside
/// [`honest_aes::Aes`], zeroized on drop. `Debug` shows the key size only.
pub struct Cipher {
    aes: Aes,
}

impl Cipher {
    /// Expand a classified key of 16, 24 or 32 bytes.
    pub fn new<const N: usize>(key: &ClassifiedBytes<N>) -> Result<Self, Error> {
        let aes = key.expose(|view| Aes::new(view.as_bytes()))?;
        Ok(Self { aes })
    }

    /// AES-128.
    pub fn aes128(key: &ClassifiedBytes<16>) -> Self {
        Self::new(key).expect("16 bytes is a valid key length")
    }

    /// AES-192.
    pub fn aes192(key: &ClassifiedBytes<24>) -> Self {
        Self::new(key).expect("24 bytes is a valid key length")
    }

    /// AES-256.
    pub fn aes256(key: &ClassifiedBytes<32>) -> Self {
        Self::new(key).expect("32 bytes is a valid key length")
    }

    /// The key size in bits: 128, 192 or 256.
    pub fn key_bits(&self) -> usize {
        self.aes.key_bits()
    }

    /// The expanded key, for modes and uses this crate does not wrap. It
    /// holds round keys, not the key bytes, and gives neither out.
    pub fn aes(&self) -> &Aes {
        &self.aes
    }
}

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cipher({:?})", self.aes)
    }
}
