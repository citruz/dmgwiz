use std::convert::TryInto;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::SeekFrom;
use std::num::NonZeroU32;
use std::path::Path;

use bincode::config;
use clap::{App, Arg, SubCommand};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{decrypt as openssl_decrypt, Cipher, Crypter, Mode};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA1;

/*
impl From<ErrorStack> for String {
    fn from(item: ErrorStack) -> Self {
        format!("{}", item)
    }
}*/

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Header {
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

fn main() {
    let matches = App::new("dmgwiz")
        .version("0.1")
        .author("Felix Seele <fseele@gmail.com>")
        .about("Tool to work with DMG images")
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("decrpyt dmg")
                .arg(
                    Arg::with_name("password")
                        .takes_value(true)
                        .short("p")
                        .required(true)
                        .help("password"),
                )
                .arg(
                    Arg::with_name("output")
                        .takes_value(true)
                        .short("o")
                        .required(true)
                        .help("file to write into"),
                ),
        )
        .get_matches();

    let in_file = matches.value_of("INPUT").unwrap();
    println!("Using input file: {}", in_file);

    // Vary the output based on how many times the user used the "verbose" flag
    // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
    match matches.occurrences_of("v") {
        0 => println!("No verbose info"),
        1 => println!("Some verbose info"),
        2 => println!("Tons of verbose info"),
        3 | _ => println!("Don't be crazy"),
    }

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    if let Some(matches) = matches.subcommand_matches("decrypt") {
        let password = matches.value_of("password").unwrap();
        let out_file = matches.value_of("output").unwrap();

        println!("Decrypting {:?} using password {:?}", in_file, password);
        let in_path = Path::new(in_file);
        let input = match File::open(&in_path) {
            Err(why) => panic!("couldn't open {}: {}", in_path.display(), why.description()),
            Ok(file) => file,
        };
        let out_path = Path::new(out_file);
        let output = match File::create(&out_path) {
            Err(why) => panic!(
                "couldn't open {}: {}",
                out_path.display(),
                why.description()
            ),
            Ok(file) => file,
        };
        if let Err(err) = decrypt(
            &mut BufReader::new(input),
            &mut BufWriter::new(output),
            password,
        ) {
            println!("Error while decrypting: {}", err);
        }
    }
    // more program logic goes here...
}

fn decrypt<R, W>(mut input: R, mut output: W, password: &str) -> Result<usize, String>
where
    R: Read + Seek,
    W: Write,
{
    let header: Header = match config().big_endian().deserialize_from(&mut input) {
        Err(err) => panic!("couldn't read: {:?}", err),
        Ok(header) => header,
    };

    println!("{:?}", header);
    if header.signature.iter().collect::<String>() != "encrcdsa" {
        return Err(format!(
            "Invalid header signature: {:?}",
            header.signature.iter().collect::<String>()
        ));
    }

    if header.version != 2 {
        return Err(format!("Invalid version: {:?}", header.version));
    }

    // generate 3des key from password
    let derived_key = derive_key(&header, password)?;
    let keyblob = decrypt_keyblob(&header, &derived_key)?;

    // extract aes and hmac keys
    let aes_key_size: usize = (header.data_enc_key_bits / 8).try_into().unwrap();
    let hmac_key_size: usize = (header.hmac_key_bits / 8).try_into().unwrap();

    let aes_key = &keyblob[..aes_key_size];
    let hmacsha1_key = &keyblob[aes_key_size..aes_key_size + hmac_key_size];

    println!("aes_key: {:x?}", aes_key);
    println!("hmacsha1_key: {:x?}", hmacsha1_key);

    let cipher = match header.data_enc_key_bits {
        128 => Cipher::aes_128_cbc(),
        256 => Cipher::aes_256_cbc(),
        val => return Err(format!("Invalid key size: {}", val))
    };

    if let Err(err) = input.seek(SeekFrom::Start(header.dataoffset)) {
        return Err(format!(
            "could not seek to data offset {:?}: {:?}",
            header.dataoffset, err
        ));
    };

    let chunk_size: usize = header.blocksize.try_into().unwrap();
    let data_size: usize = header.datasize.try_into().unwrap();
    let mut buffer: Vec<u8> = vec![0; chunk_size];
    let mut chunk_no = 0;
    let mut bytes_written: usize = 0;
    loop {
        let bytes_read = match input.read(&mut buffer) {
            Err(err) => return Err(format!("failed to read from file: {}", err)),
            Ok(val) => val,
        };
        if bytes_read == 0 {
            break;
        }
        let mut data = decrypt_chunk(cipher, &buffer, chunk_no, &aes_key, &hmacsha1_key)?;
        if (data_size - bytes_written) < chunk_size {
            data.truncate(data_size - bytes_written);
        }
        bytes_written += match output.write(&data) {
            Err(err) => return Err(format!("could not write: {}", err)),
            Ok(val) => val,
        };
        chunk_no += 1;
    }
    Ok(bytes_written)
}

fn derive_key(header: &Header, password: &str) -> Result<Vec<u8>, String> {
    if header.kdf_algorithm != 103 || header.kdf_prng_algorithm != 0 || header.kdf_salt_len != 20 {
        return Err(format!(
            "Invalid kdf parameters: kdf_algorithm={} kdf_prng_algorithm={} kdf_salt_len={} kdf_iteration_count={}",
            header.kdf_algorithm,
            header.kdf_prng_algorithm,
            header.kdf_salt_len,
            header.kdf_iteration_count));
    }

    let iterations = match NonZeroU32::new(header.kdf_iteration_count) {
        Some(val) => val,
        None => return Err("Iterations can't be zero".to_string()),
    };
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

fn decrypt_keyblob(header: &Header, key: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Cipher::des_ede3_cbc();
    let mut iv = header.blob_enc_iv.to_vec();
    iv.truncate(header.blob_enc_iv_size.try_into().unwrap());

    let mut encrypted_keyblob = [
        header.encrypted_keyblob1.to_vec(),
        header.encrypted_keyblob2.to_vec(),
    ]
    .concat();
    encrypted_keyblob.truncate(header.encrypted_keyblob_size.try_into().unwrap());
    let keyblob = match openssl_decrypt(cipher, key, Some(&iv), &encrypted_keyblob) {
        Ok(val) => val,
        Err(err) => return Err(format!("error while decrypting keyblob: {:?}", err)),
    };
    Ok(keyblob)
}

fn decrypt_chunk(cipher: Cipher, data: &[u8], chunk_no: u32, aes_key: &[u8], hmacsha1_key: &[u8]) -> Result<Vec<u8>, String> {
    let iv = compute_iv(chunk_no, hmacsha1_key);

    let mut decrypter = match Crypter::new(cipher, Mode::Decrypt, aes_key, Some(&iv)) {
        Err(err) => return Err(format!("{}", err)),
        Ok(val) => val,
    };
    decrypter.pad(false);
    let block_size = cipher.block_size();
    let mut plaintext = vec![0; data.len() + block_size];

    let mut count = match decrypter.update(data, &mut plaintext) {
        Err(err) => return Err(format!("{}", err)),
        Ok(val) => val,
    };
    count += match decrypter.finalize(&mut plaintext[count..]) {
        Err(err) => return Err(format!("{}", err)),
        Ok(val) => val,
    };
    plaintext.truncate(count);
    Ok(plaintext)
}

fn compute_iv(chunk_no: u32, hmacsha1_key: &[u8]) -> Vec<u8> {
    let key = PKey::hmac(hmacsha1_key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha1(), &key).unwrap();
    signer
        .update(&config().big_endian().serialize(&chunk_no).unwrap())
        .unwrap();
    signer.sign_to_vec().unwrap()[..16].to_vec()
}
