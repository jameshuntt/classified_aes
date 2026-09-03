use core::fmt;

use classified::ClassifiedError;
use honest_aes::AesError;

/// Why an operation was refused: the cipher refused (key length, tag,
/// padding, alignment) or a container refused the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// From `honest_aes`: a bad key length, a tag mismatch, bad padding, a
    /// nonce or alignment problem.
    Aes(AesError),
    /// From `classified`: an opened secret that is empty, or does not fit
    /// the fixed-size type asked for.
    Classified(ClassifiedError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aes(e) => e.fmt(f),
            Self::Classified(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Aes(e) => Some(e),
            Self::Classified(e) => Some(e),
        }
    }
}

impl From<AesError> for Error {
    fn from(e: AesError) -> Self {
        Self::Aes(e)
    }
}

impl From<ClassifiedError> for Error {
    fn from(e: ClassifiedError) -> Self {
        Self::Classified(e)
    }
}
