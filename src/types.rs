// pkcs/utils/operations/aes_operations/src/types.rs

use {
    aes::{Aes128, Aes256},
    cbc::{Decryptor, Encryptor},
    ctr::Ctr128BE
};


/// CBC block mode types
pub type Aes128CbcEnc = Encryptor<Aes128>;
pub type Aes128CbcDec = Decryptor<Aes128>;

pub type Aes256CbcEnc = Encryptor<Aes256>;
pub type Aes256CbcDec = Decryptor<Aes256>;


/// CTR block mode types
pub type Aes128Ctr = Ctr128BE<Aes128>;
pub type Aes256Ctr = Ctr128BE<Aes256>;



// src/config.rs
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AesKeySize {
    Bits128,
    Bits256,
}

// src/types.rs
// use cfb::{Encryptor as CfbEnc, Decryptor as CfbDec}; // Assuming `cfb` crate is used for CFB mode
// 
// pub type Aes128CfbEnc = CfbEnc<Aes128>;
// pub type Aes128CfbDec = CfbDec<Aes128>;
// pub type Aes256CfbEnc = CfbEnc<Aes256>;
// pub type Aes256CfbDec = CfbDec<Aes256>;
// 


// src/types.rs


use eax::Eax; // <-- New import for EAX

// Define the EAX modes for AES-128 and AES-256
pub type Aes128Eax = Eax<Aes128>;
pub type Aes256Eax = Eax<Aes256>;

// Keep your other types if they exist, e.g.:
// pub type Aes128Cbc = block_modes::Cbc<Aes128, Pkcs7>;
// pub type Aes128Ctr = ctr::Ctr32BE<Aes128>;
// pub type Aes128Gcm = aes_gcm::Aes128Gcm;
// ...

// src/types.rs

use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv}; // <-- New import for GCM-SIV

// Define the GCM-SIV modes for AES-128 and AES-256
pub type Aes128GcmSivMode = Aes128GcmSiv;
pub type Aes256GcmSivMode = Aes256GcmSiv;

// Keep your other types if they exist, e.g.:
// pub type Aes128Cbc = block_modes::Cbc<Aes128, Pkcs7>;
// pub type Aes128Ctr = ctr::Ctr32BE<Aes128>;
// pub type Aes128Gcm = aes_gcm::Aes128Gcm;
// pub type Aes128Eax = eax::Eax<aes::Aes128>;
// ...