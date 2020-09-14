use file_diff::diff_files;
use std::fs::File;
use std::io::BufWriter;

#[cfg(feature = "crypto")]
use dmgwiz::EncryptedDmgReader;
use dmgwiz::{DmgWiz, Verbosity};

#[test]
fn test_reader() {
    let input = File::open("tests/input_zlib.dmg").unwrap();
    DmgWiz::from_reader(input, Verbosity::None).unwrap();

    // TODO test for specific attributes and return value
}

fn extract_all_test(inpath: &str, outpath: &str) {
    let input = File::open(inpath).unwrap();
    let outfile = File::create(outpath).unwrap();
    let output = BufWriter::new(outfile);

    let mut wiz = DmgWiz::from_reader(input, Verbosity::None).unwrap();
    let bytes_written = wiz.extract_all(output).unwrap();
    assert_eq!(bytes_written, 10510336);

    assert!(diff_files(
        &mut File::open(outpath).unwrap(),
        &mut File::open("tests/output_all.bin").unwrap()
    ));
}

#[test]
fn test_extract_all_zlib() {
    extract_all_test("tests/input_zlib.dmg", "tests/output_zlib.bin")
}

#[test]
fn test_extract_all_adc() {
    extract_all_test("tests/input_adc.dmg", "tests/output_adc.bin")
}
#[test]
fn test_extract_all_bzip2() {
    extract_all_test("tests/input_bzip2.dmg", "tests/output_bzip2.bin")
}

#[test]
fn test_extract_all_lzfse() {
    extract_all_test("tests/input_lzfse.dmg", "tests/output_lzfse.bin")
}

#[test]
#[should_panic(expected = "unknown chunk type 0x80000008")]
// lzma support is not implemented yet
fn test_extract_all_lzma() {
    extract_all_test("tests/input_lzma.dmg", "tests/output_lzma.bin")
}

#[test]
fn test_extract_partition() {
    let input = File::open("tests/input_zlib.dmg").unwrap();
    let outfile = File::create("tests/output_zlib_p4.bin").unwrap();
    let output = BufWriter::new(outfile);

    let mut wiz = DmgWiz::from_reader(input, Verbosity::None).unwrap();
    let bytes_written = wiz.extract_partition(output, 4).unwrap();

    assert_eq!(bytes_written, 10469376);
    assert!(diff_files(
        &mut File::open("tests/output_zlib_p4.bin").unwrap(),
        &mut File::open("tests/output_p4.bin").unwrap()
    ));
}

#[cfg(feature = "crypto")]
#[test]
fn test_encrypted_reader() {
    let input = File::open("tests/input_aes256.dmg").unwrap();
    EncryptedDmgReader::from_reader(input, "test123", Verbosity::None).unwrap();
}

#[cfg(feature = "crypto")]
#[test]
fn test_encrypted_reader_read_all() {
    let input = File::open("tests/input_aes256.dmg").unwrap();
    let outfile = File::create("tests/output_aes256.dmg").unwrap();
    let output = BufWriter::new(outfile);

    let mut reader = EncryptedDmgReader::from_reader(input, "test123", Verbosity::None).unwrap();
    let bytes_written = reader.read_all(output).unwrap();

    assert_eq!(bytes_written, 13654);

    // extract decrypted dmg
    extract_all_test("tests/output_aes256.dmg", "tests/output_aes256.bin")
}
