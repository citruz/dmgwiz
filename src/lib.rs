use adc::AdcDecoder;
use bincode::config as bincode_config;
use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use itertools::Itertools;
use lzfse::decode_buffer as lzfse_decode_buffer;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::cmp;
use std::error;
use std::fmt;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;

mod encrypted_reader;
use encrypted_reader::EncryptedDmgHeader;
pub use encrypted_reader::EncryptedDmgReader;

const SECTOR_SIZE: usize = 512;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct KolyHeader {
    signature: [char; 4],
    version: u32,
    header_size: u32,
    flags: u32,
    running_data_fork_offset: u64,
    data_fork_offset: u64,
    data_fork_length: u64,
    rsrc_fork_offset: u64,
    rsrc_fork_length: u64,
    segment_number: u32,
    segment_count: u32,
    segment_id: [u32; 4],
    data_fork_checksum_type: u32,
    data_fork_checksum_size: u32,
    data_fork_checksum: [u32; 32],
    xml_offset: u64,
    xml_length: u64,
    reserved4: [u64; 15],
    master_checksum_type: u32,
    master_checksum_size: u32,
    master_checksum: [u32; 32],
    image_variant: u32,
    sector_count: u64,
}

impl KolyHeader {
    fn get_signature(&self) -> String {
        self.signature.iter().collect::<String>()
    }
}

#[derive(Debug)]
struct Partition {
    name: String,
    id: i64,
    attributes: String,
    blkx_table: BLKXTable,
}

impl fmt::Display for Partition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Partition:\n\
             \tName:       {}\n\
             \tAttributes: {}\n\
             \tBlkx Table:\n\
             {}\n",
            self.name, self.attributes, self.blkx_table
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct UDIFChecksum {
    r#type: u32,
    size: u32,
    data: [u32; 0x20],
}

#[repr(u32)]
#[derive(FromPrimitive, Debug, PartialEq)]
pub enum ChunkType {
    Zero = 0x00000000,
    Raw = 0x00000001,
    Ignore = 0x00000002,
    //Comment = 0x7ffffffe,
    ADC = 0x80000004,
    ZLIB = 0x80000005,
    BZLIB = 0x80000006,
    LZFSE = 0x80000007,

    Term = 0xffffffff,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct BLKXChunk {
    r#type: u32,
    comment: u32,
    sector_number: u64,
    sector_count: u64,
    compressed_offset: u64,
    compressed_length: u64,
}

impl fmt::Display for BLKXChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let type_str = match ChunkType::from_u32(self.r#type) {
            Some(val) => format!("{:?}", val),
            None => "??".to_string(),
        };
        write!(
            f,
            "\t\t\tType:       {:#010x} ({})\n\
             \t\t\tComment:    {}\n\
             \t\t\tsector num: {}\n\
             \t\t\t# sectors:  {}\n\
             \t\t\tOffset:     {:#010x}\n\
             \t\t\tLength:     {:#010x}",
            self.r#type,
            type_str,
            self.comment,
            self.sector_number,
            self.sector_count,
            self.compressed_offset,
            self.compressed_length
        )
    }
}

#[derive(Debug)]
struct BLKXTable {
    signature: [char; 4],
    version: u32,
    sector_number: u64,
    sector_count: u64,
    data_offset: u64,
    buffers_needed: u32,
    block_descriptors: u32,
    reserved: [u32; 6],
    checksum: UDIFChecksum,
    num_chunks: u32,
    chunks: Vec<BLKXChunk>,
}

impl std::convert::From<Vec<u8>> for BLKXTable {
    fn from(data: Vec<u8>) -> Self {
        let mut c = Cursor::new(data);
        let mut decoder = bincode::config();
        decoder.big_endian();
        let mut table = BLKXTable {
            signature: decoder.deserialize_from(&mut c).unwrap(),
            version: decoder.deserialize_from(&mut c).unwrap(),
            sector_number: decoder.deserialize_from(&mut c).unwrap(),
            sector_count: decoder.deserialize_from(&mut c).unwrap(),
            data_offset: decoder.deserialize_from(&mut c).unwrap(),
            buffers_needed: decoder.deserialize_from(&mut c).unwrap(),
            block_descriptors: decoder.deserialize_from(&mut c).unwrap(),
            reserved: decoder.deserialize_from(&mut c).unwrap(),
            checksum: decoder.deserialize_from(&mut c).unwrap(),
            num_chunks: decoder.deserialize_from(&mut c).unwrap(),
            chunks: vec![],
        };
        let chunks: Vec<BLKXChunk> = (0..table.num_chunks)
            .map(|_| decoder.deserialize_from(&mut c).unwrap())
            .collect();
        table.chunks = chunks;
        table
    }
}

impl fmt::Display for BLKXTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\t\tSector count:  {}\n\
             \t\tData offset:   {}\n\
             \t\tNumber chunks: {}\n\
             \t\tChunks:\n\
             {}\n",
            self.sector_count,
            self.data_offset,
            self.num_chunks,
            self.chunks.iter().format("\n\t\t\t----\n")
        )
    }
}

pub enum Error {
    /// The was an IO error while reading or writing.
    Io(std::io::Error),
    /// There was an error parsing the DMG header or partition table. The file is most likely not a valid DMG.
    Parse(Box<dyn error::Error>),
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Encrypted => write!(f, "DMG seems to encrypted"),
            Error::InvalidInput(ref str) => write!(f, "invalid input: {}", str),
            Error::InvalidPartition(num_partition) => {
                write!(f, "partition {} does not exist", num_partition)
            }
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
            Error::Parse(ref e) => e.fmt(f),
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

type Result<T> = std::result::Result<T, Error>;

#[derive(PartialEq, Debug)]
pub enum Verbosity {
    None,
    Info,
    Debug,
}

macro_rules! printInfo {
    ($self:ident, $($arg:tt)*) => ({
        if $self.verbosity == Verbosity::Info || $self.verbosity == Verbosity::Debug {
            println!($($arg)*);
        }
    })
}

macro_rules! printDebug {
    ($self:ident, $($arg:tt)*) => ({
        if $self.verbosity == Verbosity::Debug {
            println!($($arg)*);
        }
    })
}

pub struct DmgWiz<R> {
    input: R,
    partitions: Vec<Partition>,
    pub verbosity: Verbosity,
}

impl<R> DmgWiz<R>
where
    R: Read + Seek,
{
    fn check_encrypted_or(mut input: R, err: Error) -> Error {
        if let Err(err) = input.seek(SeekFrom::Start(0)) {
            return err.into();
        }
        match bincode_config()
            .big_endian()
            .deserialize_from::<&mut R, EncryptedDmgHeader>(&mut input)
        {
            Ok(ref hdr) if hdr.get_signature() == "encrcdsa" => Error::Encrypted,
            _ => err,
        }
    }
    pub fn from_reader(mut input: R) -> Result<DmgWiz<R>> {
        // seek to end of file to read koly header
        input.seek(SeekFrom::End(-0x200))?;

        // try to read header
        let header: KolyHeader = match bincode_config().big_endian().deserialize_from(&mut input) {
            Err(err) => return Err(DmgWiz::check_encrypted_or(input, err.into())),
            Ok(val) => val,
        };
        if header.get_signature() != "koly" {
            // check if DMG is encrypted
            return Err(DmgWiz::check_encrypted_or(
                input,
                Error::InvalidInput("could not parse koly header".to_string()),
            ));
        }
        //println!("{:?}", header);

        // read plist
        input.seek(SeekFrom::Start(header.xml_offset))?;
        let mut plist = plist::Value::from_reader_xml(&mut input)?;

        // get partitions from dict
        let partitions_arr = plist
            .as_dictionary_mut()
            .and_then(|dict| dict.get("resource-fork"))
            .and_then(|rsfk| rsfk.as_dictionary())
            .and_then(|rsfk| rsfk.get("blkx"))
            .and_then(|blkx| blkx.as_array())
            .ok_or(Error::InvalidInput("invalid plist structure".to_string()))?;

        // convert partition dicts to Partiton objects
        let partitions: Vec<Partition> = partitions_arr
            .iter()
            .map(|part| part.as_dictionary())
            .map(|part| Partition {
                name: part
                    .and_then(|p| p.get("Name"))
                    .and_then(|n| n.as_string())
                    .unwrap_or_default()
                    .to_string(),
                attributes: part
                    .and_then(|p| p.get("Attributes"))
                    .and_then(|n| n.as_string())
                    .unwrap_or_default()
                    .to_string(),
                blkx_table: part
                    .and_then(|p| p.get("Data"))
                    .and_then(|n| n.as_data())
                    .unwrap_or_default()
                    .to_vec()
                    .into(),
                id: part
                    .and_then(|p| p.get("Name"))
                    .and_then(|n| n.as_signed_integer())
                    .unwrap_or_default(),
            })
            .collect();

        let verbosity = Verbosity::None;
        Ok(DmgWiz {
            input,
            partitions,
            verbosity,
        })
    }

    pub fn info(&self) {
        for (i, partition) in self.partitions.iter().enumerate() {
            println!("partition {}: {}", i, partition.name);
        }
    }

    pub fn extract_all<W>(&mut self, mut output: W) -> Result<usize>
    where
        W: Write + Seek,
    {
        let mut bytes_written = 0;

        for i in 0..self.partitions.len() {
            bytes_written += self.extract_partition(&mut output, i)?;
        }
        Ok(bytes_written)
    }

    pub fn extract_partition<W>(&mut self, mut output: W, partition_num: usize) -> Result<usize>
    where
        W: Write,
    {
        let partition = self
            .partitions
            .get(partition_num)
            .ok_or(Error::InvalidPartition(partition_num))?;

        printInfo!(
            self,
            "extracting partition {} \"{}\"",
            partition_num,
            partition.name
        );

        println!("{}", partition);

        if partition.blkx_table.data_offset != 0 {
            // data_offset always seems to be 0, let's just be sure
            return Err(Error::InvalidInput(format!(
                "invalid data offset of partition {}: {}",
                partition_num, partition.blkx_table.data_offset
            )));
        }

        // allocate buffers for in and output
        let max_compressed_length = partition
            .blkx_table
            .chunks
            .iter()
            .fold(0, |max, c| cmp::max(max, c.compressed_length))
            as usize;
        let max_sector_count = partition
            .blkx_table
            .chunks
            .iter()
            .fold(0, |max, c| cmp::max(max, c.sector_count))
            as usize;

        let mut inbuf = vec![0; max_compressed_length];
        // need to add one additional byte for lzfse decompression
        let mut outbuf = vec![0; (max_sector_count * SECTOR_SIZE) + 1];

        let mut sectors_written = 0;

        for (chunk_num, chunk) in partition.blkx_table.chunks.iter().enumerate() {
            let chunk_type = ChunkType::from_u32(chunk.r#type).ok_or(Error::InvalidInput(
                format!("unknown chunk type {:#010x}", chunk.r#type),
            ))?;

            printDebug!(self,
                "chunk {}: type={:?} comment={} sector_number={} sector_count={} compressed_offset={} compressed_length={}",
                chunk_num,
                chunk_type,
                chunk.comment,
                chunk.sector_number,
                chunk.sector_count,
                chunk.compressed_offset,
                chunk.compressed_length
            );

            if chunk_type == ChunkType::Term {
                printInfo!(self, "done");
                return Ok(sectors_written as usize * SECTOR_SIZE);
            }

            // position input at start of chunk
            self.input.seek(SeekFrom::Start(chunk.compressed_offset))?;

            let in_len = chunk.compressed_length as usize;
            let out_len = chunk.sector_count as usize * SECTOR_SIZE;

            // read compressed chunk
            self.input.read_exact(&mut inbuf[0..in_len])?;

            // usually sectors are consecutive, but let's check to be sure.
            // if chunk.sector_number is less than what we have alreay written we have a problem.
            // otherwise just write NULL sectors.
            if chunk.sector_number < sectors_written {
                return Err(Error::InvalidInput(format!(
                    "invalid sector number: {} (partition={} chunk={})",
                    chunk.sector_number, partition_num, chunk_num
                )));
            } else if chunk.sector_number > sectors_written {
                let padding_sectors = chunk.sector_number - sectors_written;
                let padding = vec![0; SECTOR_SIZE];
                for _ in 0..padding_sectors {
                    output.write_all(&padding)?;
                }
            }

            // decompress
            let bytes_read = match chunk_type {
                ChunkType::Ignore | ChunkType::Zero => fill_zero(&mut outbuf[0..out_len]),
                ChunkType::Raw => copy(&inbuf[0..in_len], &mut outbuf[0..out_len]),
                ChunkType::ADC => decode_adc(&inbuf[0..in_len], &mut outbuf[0..out_len]),
                ChunkType::ZLIB => decode_zlib(&inbuf[0..in_len], &mut outbuf[0..out_len]),
                ChunkType::BZLIB => decode_bzlib(&inbuf[0..in_len], &mut outbuf[0..out_len]),
                // lzfse buffer needs to be one byte larger to tell if the buffer was large enough
                ChunkType::LZFSE => decode_lzfse(&inbuf[0..in_len], &mut outbuf[0..(out_len + 1)]),
                ChunkType::Term => panic!(), // cannot happen
            };

            match bytes_read {
                Some(val) if val == out_len => printDebug!(self, "decompressed {} bytes", val),
                _ => {
                    return Err(Error::Decompress {
                        partition_num,
                        chunk_num,
                        chunk_type,
                    })
                }
            };

            // write to ouput
            output.write_all(&outbuf[0..out_len])?;
            sectors_written += chunk.sector_count;
        }

        Ok(sectors_written as usize * SECTOR_SIZE)
    }
}

fn decode_zlib(inbuf: &[u8], outbuf: &mut [u8]) -> Option<usize> {
    let mut z = ZlibDecoder::new(&inbuf[..]);
    match z.read_exact(outbuf) {
        Err(_) => return None,
        Ok(_) => Some(outbuf.len()),
    }
}

fn decode_bzlib(inbuf: &[u8], outbuf: &mut [u8]) -> Option<usize> {
    let mut z = BzDecoder::new(&inbuf[..]);
    match z.read_exact(outbuf) {
        Err(_) => None,
        Ok(_) => Some(outbuf.len()),
    }
}

fn decode_lzfse(inbuf: &[u8], outbuf: &mut [u8]) -> Option<usize> {
    match lzfse_decode_buffer(inbuf, outbuf) {
        Err(_) => None,
        Ok(val) => Some(val),
    }
}

fn decode_adc(inbuf: &[u8], outbuf: &mut [u8]) -> Option<usize> {
    let mut z = AdcDecoder::new(&inbuf[..]);
    match z.decompress_into(outbuf) {
        Ok(val) => Some(val),
        Err(_) => None,
    }
}

fn fill_zero(outbuf: &mut [u8]) -> Option<usize> {
    for i in &mut outbuf[..] {
        *i = 0
    }
    Some(outbuf.len())
}

fn copy(inbuf: &[u8], outbuf: &mut [u8]) -> Option<usize> {
    outbuf.copy_from_slice(inbuf);
    Some(outbuf.len())
}
