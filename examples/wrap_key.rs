//! Wrap a data key under a classified wrapping key with AES-256-GCM, store
//! the public parts, and unwrap it back into a fixed-size container.
//!
//! cargo run --example wrap_key

use classified::ClassifiedBytes;
use classified_aes::{gcm, Cipher, Nonce};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let wrapping_key = ClassifiedBytes::<32>::new([0x4b; 32]).expect("32 bytes");
    let cipher = Cipher::aes256(&wrapping_key);
    let data_key = ClassifiedBytes::<32>::new([0xd4; 32]).expect("32 bytes");

    // the nonce and the sealed bytes are public and go into storage together
    let nonce = Nonce::random();
    let sealed = gcm::seal_fixed(&cipher, &nonce, b"data-key:v1", &data_key);
    println!("nonce  {nonce:?}");
    println!("sealed {}", hex(&sealed));
    println!("cipher {cipher:?}, key {data_key:?}");

    let unwrapped: ClassifiedBytes<32> = gcm::open_fixed(&cipher, &nonce, b"data-key:v1", &sealed).expect("tag matches");
    println!("unwrapped matches: {}", unwrapped.ct_eq(&data_key));
}
