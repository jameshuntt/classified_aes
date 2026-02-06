
#[derive(Debug)]
pub enum CryptoError {
    MissingIv,
    MissingTag,
    InvalidKey,
    InvalidSignature,
    UnsupportedAlgorithm,
    SaltLengthRequired,
    DigestFailure,
    InvalidInput(&'static str),

    // ...
}

impl From<&'static str> for CryptoError {
    fn from(err: &'static str) -> Self {
        CryptoError::InvalidInput(err)
    }
}

impl From<std::array::TryFromSliceError> for CryptoError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        CryptoError::InvalidInput("Failed to convert slice")
    }
}

// impl From<ed25519_dalek::SignatureError> for CryptoError {
//     fn from(err: ed25519_dalek::SignatureError) -> Self {
//         CryptoError::InvalidInput("Signature parse error")
//     }
// }
