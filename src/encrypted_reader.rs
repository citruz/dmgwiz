use std::cmp;
use std::convert::TryInto;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::num::NonZeroU32;

use bincode::config as bincode_config;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{decrypt as openssl_decrypt, Cipher, Crypter, Mode};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA1;

use super::{Error, Result, Verbosity};

// how can i use macro from super?
macro_rules! printDebug {
    ($self:ident, $($arg:tt)*) => ({
        if $self.verbosity == Verbosity::Debug {
            println!($($arg)*);
        }
    })
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EncryptedDmgHeader {
    signature: [char; 8],
    version: u32,
    enc_iv_size: u32,
    unk1: u32,
    unk2: u32,
    data_enc_key_bits: u32,
    unk4: u32,
    hmac_key_bits: u32,
    uuid: [u8; 16],
    blocksize: u32,
    datasize: u64,
    dataoffset: u64,
    unk6: [u8; 24],
    kdf_algorithm: u32,
    kdf_prng_algorithm: u32,
    kdf_iteration_count: u32,
    kdf_salt_len: u32,
    kdf_salt: [u8; 32],
    blob_enc_iv_size: u32,
    blob_enc_iv: [u8; 32],
    blob_enc_key_bits: u32,
    blob_enc_algorithm: u32,
    blob_enc_padding: u32,
    blob_enc_mode: u32,
    encrypted_keyblob_size: u32,
    encrypted_keyblob1: [u8; 32],
    encrypted_keyblob2: [u8; 32],
}

impl EncryptedDmgHeader {
    pub fn get_signature(&self) -> String {
        self.signature.iter().collect::<String>()
    }
}

pub struct EncryptedDmgReader<R> {
    header: EncryptedDmgHeader,
    aes_key: Vec<u8>,
    hmacsha1_key: Vec<u8>,
    reader: R,
    block_cipher: Cipher,
    chunk_size: usize,
    data_size: usize,
    cur_pos: usize,
    pub verbosity: Verbosity,
}

impl<R> EncryptedDmgReader<R>
where
    R: Read + Seek,
{
    pub fn from_reader(
        mut reader: R,
        password: &str,
        verbosity: Verbosity,
    ) -> Result<EncryptedDmgReader<R>> {
        let header: EncryptedDmgHeader = bincode_config()
            .big_endian()
            .deserialize_from(&mut reader)
            .map_err(|err| Error::Parse(err))?;

        if verbosity == Verbosity::Debug {
            println!("header: {:#?}", header);
        }

        if header.get_signature() != "encrcdsa" {
            return Err(Error::InvalidInput("could not parse header".to_string()));
        }

        if header.version != 2 {
            return Err(Error::UnsupportedEncryption(format!(
                "unsupported header version {}",
                header.version
            )));
        }

        if header.blob_enc_algorithm != 17
            || header.blob_enc_mode != 6
            || header.blob_enc_padding != 7
        {
            return Err(Error::UnsupportedEncryption(format!(
                "unsupported blob encryption parameters algorithm={} mode={} padding={}",
                header.blob_enc_algorithm, header.blob_enc_mode, header.blob_enc_padding
            )));
        }

        // generate 3des key from password
        let derived_key = Self::derive_key(&header, password)?;
        let keyblob = Self::decrypt_keyblob(&header, &derived_key)?;

        // extract aes and hmac keys
        let aes_key_size: usize = header.data_enc_key_bits as usize / 8;
        let hmac_key_size: usize = header.hmac_key_bits as usize / 8;

        let aes_key = &keyblob[..aes_key_size];
        let hmacsha1_key = &keyblob[aes_key_size..aes_key_size + hmac_key_size];

        if verbosity == Verbosity::Debug {
            println!("aes_key: {:x?}", aes_key);
            println!("hmacsha1_key: {:x?}", hmacsha1_key);
        }

        let cipher = match header.data_enc_key_bits {
            128 => Cipher::aes_128_cbc(),
            256 => Cipher::aes_256_cbc(),
            val => {
                return Err(Error::UnsupportedEncryption(format!(
                    "unsupported AES key size {}",
                    val
                )))
            }
        };

        Ok(EncryptedDmgReader {
            aes_key: aes_key.to_vec(),
            hmacsha1_key: hmacsha1_key.to_vec(),
            reader: reader,
            block_cipher: cipher,
            data_size: header.datasize as usize,
            chunk_size: header.blocksize as usize,
            header: header,
            cur_pos: 0,
            verbosity: verbosity,
        })
    }

    pub fn read_all<W>(&mut self, mut output: W) -> Result<usize>
    where
        W: Write,
    {
        self.reader.seek(SeekFrom::Start(self.header.dataoffset))?;

        let mut buffer: Vec<u8> = vec![0; self.chunk_size];
        let mut chunk_no = 0;
        let mut bytes_written: usize = 0;
        loop {
            match self.reader.read(&mut buffer) {
                Err(err) => return Err(err.into()),
                Ok(0) => break,
                Ok(val) => val,
            };
            let mut data = self.decrypt_chunk(&buffer, chunk_no)?;
            if (self.data_size - bytes_written) < self.chunk_size {
                data.truncate(self.data_size - bytes_written);
            }
            bytes_written += output.write(&data)?;
            chunk_no += 1;
        }
        Ok(bytes_written)
    }

    fn derive_key(header: &EncryptedDmgHeader, password: &str) -> Result<Vec<u8>> {
        if header.kdf_algorithm != 103
            || header.kdf_prng_algorithm != 0
            || header.kdf_salt_len != 20
        {
            return Err(Error::UnsupportedEncryption(format!(
                "unsupported key-derivation parameters: algorithm={} prng_algorithm={} salt_len={} ",
                header.kdf_algorithm,
                header.kdf_prng_algorithm,
                header.kdf_salt_len)));
        }

        let iterations = NonZeroU32::new(header.kdf_iteration_count).ok_or(
            Error::UnsupportedEncryption("iterations cannot be zero".to_string()),
        )?;

        let mut derived_key = [0u8; 24];
        pbkdf2::derive(
            PBKDF2_ALG,
            iterations,
            &header.kdf_salt[..20],
            password.as_bytes(),
            &mut derived_key,
        );

        Ok(derived_key.to_vec())
    }

    fn decrypt_keyblob(header: &EncryptedDmgHeader, key: &[u8]) -> Result<Vec<u8>> {
        let cipher = Cipher::des_ede3_cbc();
        let mut iv = header.blob_enc_iv.to_vec();
        iv.truncate(header.blob_enc_iv_size.try_into().unwrap());

        // rust does not support static array of > 32 elements
        let mut encrypted_keyblob = [
            header.encrypted_keyblob1.to_vec(),
            header.encrypted_keyblob2.to_vec(),
        ]
        .concat();
        encrypted_keyblob.truncate(header.encrypted_keyblob_size as usize);

        // do decryption
        let keyblob = openssl_decrypt(cipher, key, Some(&iv), &encrypted_keyblob)
            .map_err(|_| Error::InvalidPassword)?;

        Ok(keyblob)
    }

    fn decrypt_chunk(&self, data: &[u8], chunk_no: u32) -> Result<Vec<u8>> {
        let iv: Vec<u8> = self.compute_iv(chunk_no)?;

        let mut decrypter =
            Crypter::new(self.block_cipher, Mode::Decrypt, &self.aes_key, Some(&iv))?;
        decrypter.pad(false);

        let block_size = self.block_cipher.block_size();
        let mut plaintext = vec![0; data.len() + block_size];

        let mut count = decrypter.update(data, &mut plaintext)?;
        count += decrypter.finalize(&mut plaintext[count..])?;
        plaintext.truncate(count);
        Ok(plaintext)
    }

    fn compute_iv(&self, chunk_no: u32) -> Result<Vec<u8>> {
        let key = PKey::hmac(&self.hmacsha1_key)?;
        let mut signer = Signer::new(MessageDigest::sha1(), &key)?;
        signer.update(&bincode_config().big_endian().serialize(&chunk_no).unwrap())?;

        match signer.sign_to_vec() {
            Err(err) => Err(err.into()),
            // TODO check if we can/should hardcode this
            // TODO check vector length befpre taking slice
            Ok(val) => Ok(val[..16].to_vec()),
        }
    }
}

impl<R: Read + Seek> std::io::Read for EncryptedDmgReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        printDebug!(
            self,
            "EncryptedDmgReader: got read with len={} cur_pos={} data_size={}",
            buf.len(),
            self.cur_pos,
            self.data_size
        );

        if self.cur_pos >= self.data_size || buf.len() == 0 {
            // EOF
            return Ok(0);
        }

        // starting chunk
        let mut chunk_no = self.cur_pos / self.chunk_size;
        // offset in starting chunk
        let mut chunk_offset = self.cur_pos % self.chunk_size;
        // total bytes to read
        let mut bytes_to_read = cmp::min(buf.len(), self.data_size - self.cur_pos);
        // bytes written to buffer
        let mut bytes_written = 0;
        let mut buffer: Vec<u8> = vec![0; self.chunk_size];

        if let Err(err) = self.reader.seek(SeekFrom::Start(
            self.header.dataoffset + (self.chunk_size as u64) * (chunk_no as u64),
        )) {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, err));
        };

        while bytes_to_read > 0 {
            printDebug!(
                self,
                "chunk_no={} chunk_offset={} bytes_to_read={}",
                chunk_no,
                chunk_offset,
                bytes_to_read
            );

            if self.reader.read(&mut buffer)? == 0 {
                // reached eof of underlying reader
                return Ok(bytes_written);
            }

            let mut data = match self.decrypt_chunk(&buffer, chunk_no as u32) {
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "could not decrypt",
                    ))
                }
                Ok(val) => val,
            };
            if chunk_offset + bytes_to_read < self.chunk_size {
                data.truncate(chunk_offset + bytes_to_read);
            }

            let new_bytes = data.len() - chunk_offset;
            buf[bytes_written..bytes_written + new_bytes].copy_from_slice(&data[chunk_offset..]);
            bytes_to_read -= new_bytes;
            bytes_written += new_bytes;

            chunk_no += 1;
            chunk_offset = 0;
        }

        self.cur_pos += bytes_written;
        Ok(bytes_written)
    }
}

impl<R> std::io::Seek for EncryptedDmgReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos: i64 = match pos {
            SeekFrom::Start(val) => val as i64,
            SeekFrom::End(val) => self.data_size as i64 + val,
            SeekFrom::Current(val) => self.cur_pos as i64 + val,
        };

        if new_pos < 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seeking to negative position",
            ))
        } else {
            // according to docs seeking beyond the end should not be an error hence we allow it
            printDebug!(self, "EncryptedDmgReader: seeking to {}", new_pos);
            self.cur_pos = new_pos as usize;
            Ok(self.cur_pos as u64)
        }
    }
}
