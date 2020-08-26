use serde::{Deserialize, Serialize};

/// Header used for encrypted DMGs
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EncryptedDmgHeader {
    signature: [char; 8],
    pub version: u32,
    pub enc_iv_size: u32,
    unk1: u32,
    unk2: u32,
    pub data_enc_key_bits: u32,
    unk4: u32,
    pub hmac_key_bits: u32,
    pub uuid: [u8; 16],
    pub blocksize: u32,
    pub datasize: u64,
    pub dataoffset: u64,
    unk6: [u8; 24],
    pub kdf_algorithm: u32,
    pub kdf_prng_algorithm: u32,
    pub kdf_iteration_count: u32,
    pub kdf_salt_len: u32,
    pub kdf_salt: [u8; 32],
    pub blob_enc_iv_size: u32,
    pub blob_enc_iv: [u8; 32],
    pub blob_enc_key_bits: u32,
    pub blob_enc_algorithm: u32,
    pub blob_enc_padding: u32,
    pub blob_enc_mode: u32,
    pub encrypted_keyblob_size: u32,
    pub encrypted_keyblob1: [u8; 32],
    pub encrypted_keyblob2: [u8; 32],
}

impl EncryptedDmgHeader {
    pub fn get_signature(&self) -> String {
        self.signature.iter().collect::<String>()
    }
}
