use std::fs::File;

use dmgwiz::{DmgWiz, EncryptedDmgReader, Verbosity};

#[test]
fn test_reader() {
    let input = File::open("tests/input.dmg").unwrap();
    DmgWiz::from_reader(input, Verbosity::None).unwrap();

    // TODO test for specific attributes and return value
}

#[test]
fn test_extract_all() {
    let input = File::open("tests/input.dmg").unwrap();
    let output = File::create("tests/output.bin").unwrap();
    let mut wiz = DmgWiz::from_reader(input, Verbosity::None).unwrap();
    match wiz.extract_all(output) {
        Err(err) => panic!(format!("error while extracting: {}", err)),
        Ok(bytes) => println!("done. {} bytes written", bytes),
    }
}

#[test]
fn test_extract_partition() {
    let input = File::open("tests/input.dmg").unwrap();
    let output = File::create("tests/output.bin").unwrap();
    let mut wiz = DmgWiz::from_reader(input, Verbosity::None).unwrap();
    match wiz.extract_partition(output, 0) {
        Err(err) => panic!(format!("error while extracting: {}", err)),
        Ok(bytes) => println!("done. {} bytes written", bytes),
    }
}

#[test]
fn test_encrypted_reader() {
    let input = File::open("tests/input_aes256.dmg").unwrap();
    EncryptedDmgReader::from_reader(input, "test123", Verbosity::None).unwrap();
}

#[test]
fn test_encrypted_reader_read_all() {
    let input = File::open("tests/input_aes256.dmg").unwrap();
    let output = File::create("tests/output.dmg").unwrap();
    let mut reader = EncryptedDmgReader::from_reader(input, "test123", Verbosity::None).unwrap();
    match reader.read_all(output) {
        Err(err) => panic!(format!("error while decrypting: {}", err)),
        Ok(bytes) => println!("done. {} bytes written", bytes),
    }
}
