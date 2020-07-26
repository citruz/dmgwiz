use std::fmt;

use super::ChunkType;

pub type Result<T> = std::result::Result<T, Error>;

/// This type represents all possible errors that can occur when working with DMGs.
#[derive(Debug)]
pub enum Error {
    /// The was an IO error while reading or writing.
    Io(std::io::Error),
    /// There was an error parsing the DMG header or partition table. The file is most likely not a valid DMG.
    Parse(Box<dyn std::error::Error>),
    /// The DMG is encrypted. Use EncryptedDmgReader to read encrypted DMGs.
    Encrypted,
    /// The input is not a valid DMG file.
    InvalidInput(String),
    /// The partition number supplied is not valid.
    InvalidPartition(usize),
    /// There was an error while decompressing a data chunk.
    Decompress {
        partition_num: usize,
        chunk_num: usize,
        chunk_type: ChunkType,
    },
    /// The DMG uses an unsupported header version, encryption algorithm or key-derivation fucntion.
    UnsupportedEncryption(String),
    /// The DMG could not be decrypted using the given password.
    InvalidPassword,
    /// There was an OpenSSL error during decryption.
    Decryption(openssl::error::ErrorStack),
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            Error::Io(ref err) => Some(err),
            Error::Decryption(ref err) => Some(err),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Encrypted => write!(f, "DMG seems to encrypted"),
            Error::InvalidInput(ref str) => write!(f, "{}", str),
            Error::InvalidPartition(num_partition) => {
                write!(f, "partition {} does not exist", num_partition)
            }
            Error::UnsupportedEncryption(ref str) => {
                write!(f, "unsupported encryption parameters: {}", str)
            }
            Error::InvalidPassword => write!(f, "invalid password given"),
            Error::Decryption(_) => write!(f, "error during decryption"),
            Error::Decompress {
                partition_num,
                chunk_num,
                ref chunk_type,
            } => write!(
                f,
                "there was an error during decompression (partition={} chunk={} type={:?}",
                partition_num, chunk_num, chunk_type
            ),
            Error::Io(ref e) => e.fmt(f),
            Error::Parse(ref e) => write!(f, "parse error ({})", e),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(err: Box<bincode::ErrorKind>) -> Error {
        match *err {
            bincode::ErrorKind::Io(err) => Error::Io(err),
            err => Error::Parse(Box::new(err)),
        }
    }
}

impl From<plist::Error> for Error {
    fn from(err: plist::Error) -> Error {
        match err.into_io() {
            Ok(io_err) => Error::Io(io_err),
            Err(err) => Error::Parse(Box::new(err)),
        }
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Error {
        Error::Decryption(err)
    }
}
