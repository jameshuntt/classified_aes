//! AES with classified keys and plaintexts.
//!
//! [`honest_aes`] is AES without lookup tables, on plain bytes. This crate
//! drives it from [`classified`] containers: the key is a
//! [`ClassifiedBytes`] of 16, 24 or 32 bytes, plaintext goes in and comes
//! out as a [`ClassifiedBuffer`] or [`ClassifiedBytes`], and only the
//! ciphertext, the tag and the nonce are ever plain. The key bytes are
//! exposed once, to expand the round keys, which [`honest_aes::Aes`]
//! zeroizes on drop.
//!
//! ```
//! use classified::{ClassifiedBuffer, ClassifiedBytes};
//! use classified_aes::{gcm, Cipher, Nonce};
//!
//! let key = ClassifiedBytes::<32>::new([0x42; 32]).unwrap();
//! let cipher = Cipher::aes256(&key);
//! let nonce = Nonce::new([7; 12]);            // never reused under one key
//!
//! let secret = ClassifiedBuffer::try_from_slice(b"wrap this data key", 64).unwrap();
//! let sealed: Vec<u8> = gcm::seal(&cipher, &nonce, b"header", &secret);
//!
//! let opened = gcm::open(&cipher, &nonce, b"header", &sealed).unwrap();
//! assert!(opened.ct_eq(&secret));
//! assert_eq!(format!("{cipher:?}"), "Cipher(Aes-256([REDACTED]))");
//! ```
//!
//! [`gcm`] is the mode to reach for: it authenticates. [`cmac`] tags
//! public data with a classified key. [`ctr`] and [`cbc`] are here for
//! formats that require them and carry the same caveats as in
//! `honest_aes`. For anything else, [`Cipher::aes`] hands out the expanded
//! key for use with `honest_aes` directly.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cbc;
mod cipher;
pub mod cmac;
pub mod ctr;
mod error;
pub mod gcm;
mod nonce;

pub use cipher::Cipher;
pub use error::Error;
pub use honest_aes::{AesError, BLOCK};
pub use nonce::Nonce;

#[doc(no_inline)]
pub use classified::{ClassifiedBuffer, ClassifiedBytes};

#[cfg(all(doctest, feature = "os-rng"))]
#[doc = include_str!("../README.md")]
mod readme_doctests {}
