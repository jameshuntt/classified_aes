use crate::errors::CryptoError;
use cmac::{Cmac, Mac};
use aes::{Aes256}; // Import both AES key sizes
use classified::{classified_data::ClassifiedData}; // Assuming ClassifiedData is here

/// Computes AES-256 CMAC
pub fn compute_cmac_initial(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut mac = Cmac::<Aes256>::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Computes AES-256 CMAC for the given data using a raw key slice.
///
/// Returns the CMAC tag as a `Vec<u8>`.
///
/// # Errors
/// Returns `CryptoError::InvalidKey` if the key length is not 32 bytes (for AES-256).
pub fn compute_cmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut mac = Cmac::<Aes256>::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Computes AES-256 CMAC for the given data using a `ClassifiedData` wrapped key.
///
/// Returns the CMAC tag as a `Vec<u8>`.
///
/// # Errors
/// Returns `CryptoError::InvalidKey` if the key length is not 32 bytes (for AES-256).
pub fn compute_cmac_safe(key: &ClassifiedData<Vec<u8>>, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // The key is exposed only for the duration of the CMAC initialization.
    let mut mac = Cmac::<Aes256>::new_from_slice(key.expose())
        .map_err(|_| CryptoError::InvalidKey)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
