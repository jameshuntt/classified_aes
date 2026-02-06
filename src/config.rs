pub const AES128_KEY_SIZE:  usize = 16;
pub const AES256_KEY_SIZE:  usize = 32;
pub const AES_BLOCK_SIZE:   usize = 16;
pub const GCM_TAG_SIZE:     usize = 16;


impl TryFrom<usize> for AesKeySize {
    type Error = &'static str;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            16 => Ok(Self::Bits128),
            32 => Ok(Self::Bits256),
            _ => Err("Unsupported AES key size"),
        }
    }
}


pub enum AesKeySize {
    Bits128,
    Bits256,
}
