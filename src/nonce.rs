use core::fmt;

/// A 96-bit GCM nonce.
///
/// A nonce is not secret, but it must never repeat under one key: two
/// messages sealed with the same key and nonce give away their XOR and
/// the authentication key. Either count (and never restart the count) or
/// draw one at random per message with [`Nonce::random`], which is safe
/// for well under 2^32 messages per key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Wrap twelve bytes.
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Wrap a slice, if it is twelve bytes long.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    /// A fresh random nonce from the operating system's generator.
    #[cfg(feature = "os-rng")]
    pub fn random() -> Self {
        use rand_core::TryRngCore;
        let mut bytes = [0u8; 12];
        rand_core::OsRng.try_fill_bytes(&mut bytes).expect("the OS random source is available");
        Self(bytes)
    }

    /// The bytes, to store beside the ciphertext.
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl From<[u8; 12]> for Nonce {
    fn from(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}
