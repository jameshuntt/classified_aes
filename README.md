# classified_aes

AES with classified keys and plaintexts.

[`honest_aes`](https://crates.io/crates/honest_aes) is AES without lookup
tables, on plain bytes. This crate drives it from
[`classified`](https://crates.io/crates/classified) containers: the key is
a `ClassifiedBytes` of 16, 24 or 32 bytes, plaintext goes in and comes out
as a `ClassifiedBuffer` or `ClassifiedBytes`, and only the ciphertext, the
tag and the nonce are ever plain. The key bytes are exposed once, to expand
the round keys, which are zeroized on drop.

```rust
use classified::{ClassifiedBuffer, ClassifiedBytes};
use classified_aes::{gcm, Cipher, Nonce};

let key = ClassifiedBytes::<32>::new([0x42; 32]).unwrap();
let cipher = Cipher::aes256(&key);
let nonce = Nonce::random();                       // one per message, stored beside it

let secret = ClassifiedBuffer::try_from_slice(b"wrap this data key", 64).unwrap();
let sealed: Vec<u8> = gcm::seal(&cipher, &nonce, b"header", &secret);

let opened = gcm::open(&cipher, &nonce, b"header", &sealed).unwrap();
assert!(opened.ct_eq(&secret));

// a changed header or a flipped bit is refused and nothing comes back
assert!(gcm::open(&cipher, &nonce, b"other", &sealed).is_err());

// nothing here prints a secret
assert_eq!(format!("{cipher:?}"), "Cipher(Aes-256([REDACTED]))");
```

A key wrapped for storage comes back as the same fixed-size type:

```rust
use classified::ClassifiedBytes;
use classified_aes::{gcm, Cipher, Nonce};

let wrapping = Cipher::aes256(&ClassifiedBytes::new([1; 32]).unwrap());
let data_key = ClassifiedBytes::<32>::new([0xd4; 32]).unwrap();
let nonce = Nonce::new([7; 12]);

let sealed = gcm::seal_fixed(&wrapping, &nonce, b"data-key", &data_key);
let unwrapped: ClassifiedBytes<32> = gcm::open_fixed(&wrapping, &nonce, b"data-key", &sealed).unwrap();
assert_eq!(unwrapped, data_key);
```

## What is here

| module | does |
|---|---|
| `Cipher` | an expanded key from a `ClassifiedBytes<16 / 24 / 32>`; `aes()` hands the expanded key to `honest_aes` for anything not wrapped here |
| `Nonce` | a 96-bit GCM nonce, public, `random()` with the `os-rng` feature (default) |
| `gcm` | `seal` / `open` for buffers, `seal_fixed` / `open_fixed` for fixed-size secrets |
| `cmac` | tag public data with a classified key, verify in constant time |
| `ctr`, `cbc` | the unauthenticated modes, for formats that require them |

The bytes on the wire are plain AES-GCM, AES-CTR, AES-CBC and CMAC: the
tests check them against the RustCrypto crates. A nonce must never repeat
under one key.

`Error` is `Error::Aes(AesError)` from the cipher or
`Error::Classified(ClassifiedError)` from a container.

## Releasing

Bump `version` in Cargo.toml, add a dated `## <version> (YYYY-MM-DD)` entry to CHANGELOG.md, and push to
`main`. CI (.github/workflows/ci.yml) runs the tests and clippy, then publishes that version to crates.io.

## License

MIT OR Apache-2.0.
