//! Containers in, public bytes out, containers back: what the wrapping adds
//! to honest_aes, and proof that the bytes on the wire are plain AES-GCM.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use classified::{ClassifiedBuffer, ClassifiedBytes, ClassifiedError};
use classified_aes::{cbc, cmac, ctr, gcm, AesError, Cipher, Error, Nonce};

fn key256() -> ClassifiedBytes<32> {
    ClassifiedBytes::new(core::array::from_fn(|i| i as u8)).unwrap()
}

fn secret(bytes: &[u8]) -> ClassifiedBuffer {
    ClassifiedBuffer::try_from_slice(bytes, 256).unwrap()
}

#[test]
fn gcm_seals_a_buffer_and_opens_it_again_for_every_key_size() {
    let nonce = Nonce::new([9; 12]);
    let plaintext = secret(b"the data key, wrapped");

    let ciphers = [
        Cipher::aes128(&ClassifiedBytes::new([1; 16]).unwrap()),
        Cipher::aes192(&ClassifiedBytes::new([2; 24]).unwrap()),
        Cipher::aes256(&key256()),
    ];
    for (cipher, bits) in ciphers.iter().zip([128, 192, 256]) {
        assert_eq!(cipher.key_bits(), bits);
        let sealed = gcm::seal(cipher, &nonce, b"aad", &plaintext);
        assert_eq!(sealed.len(), plaintext.len() + 16);
        let opened = gcm::open(cipher, &nonce, b"aad", &sealed).unwrap();
        assert!(opened.ct_eq(&plaintext));
        assert_eq!(opened.capacity_limit(), plaintext.len(), "bounded to its own length");
    }
}

#[test]
fn the_sealed_bytes_are_plain_aes_gcm() {
    // the same key and nonce through RustCrypto give the same bytes
    let cipher = Cipher::aes256(&key256());
    let nonce = Nonce::new([3; 12]);
    let sealed = gcm::seal(&cipher, &nonce, b"header", &secret(b"interop"));

    let raw_key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let theirs = aes_gcm::Aes256Gcm::new_from_slice(&raw_key)
        .unwrap()
        .encrypt(aes_gcm::Nonce::from_slice(nonce.as_bytes()), Payload { msg: b"interop", aad: b"header" })
        .unwrap();
    assert_eq!(sealed, theirs);
}

#[test]
fn a_fixed_size_key_comes_back_as_the_same_type() {
    let wrapping = Cipher::aes256(&key256());
    let nonce = Nonce::new([1; 12]);
    let data_key = ClassifiedBytes::<32>::new([0xd4; 32]).unwrap();

    let sealed = gcm::seal_fixed(&wrapping, &nonce, b"data-key", &data_key);
    let opened: ClassifiedBytes<32> = gcm::open_fixed(&wrapping, &nonce, b"data-key", &sealed).unwrap();
    assert_eq!(opened, data_key);

    let wrong_size = gcm::open_fixed::<16>(&wrapping, &nonce, b"data-key", &sealed).unwrap_err();
    assert_eq!(wrong_size, Error::Classified(ClassifiedError::LengthMismatch { expected: 16, actual: 32 }));
}

#[test]
fn opening_refuses_tampering_wrong_aad_and_wrong_nonce() {
    let cipher = Cipher::aes128(&ClassifiedBytes::new([5; 16]).unwrap());
    let nonce = Nonce::new([2; 12]);
    let sealed = gcm::seal(&cipher, &nonce, b"aad", &secret(b"guarded"));

    let mut tampered = sealed.clone();
    tampered[0] ^= 1;
    assert_eq!(gcm::open(&cipher, &nonce, b"aad", &tampered).unwrap_err(), Error::Aes(AesError::TagMismatch));
    assert_eq!(gcm::open(&cipher, &nonce, b"other", &sealed).unwrap_err(), Error::Aes(AesError::TagMismatch));
    assert!(gcm::open(&cipher, &Nonce::new([0; 12]), b"aad", &sealed).is_err());
    assert_eq!(gcm::open(&cipher, &nonce, b"aad", &sealed[..10]).unwrap_err().to_string(), "GCM tag mismatch");
    assert!(std::error::Error::source(&Error::Aes(AesError::TagMismatch)).is_some());
}

#[test]
fn keys_of_the_wrong_length_are_refused_and_the_cipher_is_redacted() {
    let odd = ClassifiedBytes::<20>::new([0; 20]).unwrap();
    assert_eq!(Cipher::new(&odd).unwrap_err(), Error::Aes(AesError::InvalidKeyLength(20)));
    let cipher = Cipher::aes192(&ClassifiedBytes::new([0; 24]).unwrap());
    assert_eq!(format!("{cipher:?}"), "Cipher(Aes-192([REDACTED]))");
    assert_eq!(cipher.aes().rounds(), 12);
}

#[test]
fn nonces_are_public_values() {
    let n = Nonce::new([0xab; 12]);
    assert_eq!(format!("{n:?}"), "Nonce(abababababababababababab)");
    assert_eq!(Nonce::from_slice(&[0xab; 12]), Some(n));
    assert_eq!(Nonce::from_slice(&[0xab; 11]), None);
    assert_eq!(Nonce::from([1; 12]).as_bytes(), &[1; 12]);
}

#[cfg(feature = "os-rng")]
#[test]
fn random_nonces_differ() {
    let a = Nonce::random();
    let b = Nonce::random();
    assert_ne!(a, b);
}

#[test]
fn cmac_tags_public_data_with_a_classified_key() {
    let cipher = Cipher::aes128(&ClassifiedBytes::new([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]).unwrap());
    let tag = cmac::tag(&cipher, b"");
    // RFC 4493 example 1
    assert_eq!(tag[..4], [0xbb, 0x1d, 0x69, 0x29]);
    assert!(cmac::verify(&cipher, b"", &tag));
    assert!(!cmac::verify(&cipher, b"x", &tag));
}

#[test]
fn ctr_and_cbc_round_trip_through_containers() {
    let cipher = Cipher::aes256(&key256());
    let plaintext = secret(b"seventeen bytes!!");

    let counter = [0u8; 16];
    let ct = ctr::encrypt(&cipher, &counter, &plaintext);
    assert_eq!(ct.len(), 17);
    assert!(ctr::decrypt(&cipher, &counter, &ct).unwrap().ct_eq(&plaintext));

    let iv = [4u8; 16];
    let ct = cbc::encrypt(&cipher, &iv, &plaintext);
    assert_eq!(ct.len(), 32);
    assert!(cbc::decrypt(&cipher, &iv, &ct).unwrap().ct_eq(&plaintext));
    assert_eq!(cbc::decrypt(&cipher, &iv, &ct[..17]).unwrap_err(), Error::Aes(AesError::NotBlockAligned(17)));
}
