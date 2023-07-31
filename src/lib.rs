use adc::AdcDecoder;
use bincode::Options;
use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;
use itertools::Itertools;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use std::cmp;
use std::cmp::Ordering;
use std::fmt;
use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use std::io::SeekFrom;

mod crypto;
mod error;

use crypto::header::EncryptedDmgHeader;

#[cfg(feature = "crypto")]
pub use crypto::reader::EncryptedDmgReader;
pub use error::{Error, Result};

const SECTOR_SIZE: usize = 512;

/// Structure representing the "koly" header (actually it is a trailer)
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct KolyHeader {
    /// "koly"
    signature: [char; 4],
    /// we only support 4 which is the current one
    version: u32,
    /// size of this header, always 512
    header_size: u32,
    flags: u32,
    running_data_fork_offset: u64,
    /// file offset where the data starts
    data_fork_offset: u64,
    /// size of data
    data_fork_length: u64,
    rsrc_fork_offset: u64,
    rsrc_fork_length: u64,
    segment_number: u32,
    segment_count: u32,
    segment_id: [u32; 4],
    data_fork_checksum_type: u32,
    data_fork_checksum_size: u32,
    data_fork_checksum: [u32; 32],
    /// file offset where the plist starts
    xml_offset: u64,
    xml_length: u64,
    reserved4: [u64; 15],
    master_checksum_type: u32,
    master_checksum_size: u32,
    master_checksum: [u32; 32],
    image_variant: u32,
    /// total number of sectors
    sector_count: u64,
}

impl KolyHeader {
    fn get_signature(&self) -> String {
        self.signature.iter().collect::<String>()
    }
}

/// Structure representing a partition of the DMG
///
/// Attributes are extracted from the plist.
#[derive(Debug)]
pub struct Partition {
    pub name: String,
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

/// Possible compression types of the BLXChunk
#[repr(u32)]
#[derive(FromPrimitive, Debug, PartialEq)]
pub enum ChunkType {
    Zero = 0x00000000,
    Raw = 0x00000001,
    Ignore = 0x00000002,
    Comment = 0x7ffffffe,
    ADC = 0x80000004,
    ZLIB = 0x80000005,
    BZLIB = 0x80000006,
    LZFSE = 0x80000007,

    Term = 0xffffffff,
}

/// each chunk describes a number of consecutive sectors
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct BLKXChunk {
    /// compression type used for this chunk
    r#type: u32,
    /// ascii, only set if type is Comment
    comment: u32,
    /// start sector
    sector_number: u64,
    /// number of sectors represented by this chunk
    sector_count: u64,
    /// offset of the compressed data
    compressed_offset: u64,
    /// length of compressed data
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

/// header of the BLXTable
#[derive(Debug)]
struct BLKXTable {
    /// "mish"
    signature: [char; 4],
    /// currently 1
    version: u32,
    /// starting sector
    sector_number: u64,
    /// number of sectors
    sector_count: u64,
    /// seems to be always 0
    data_offset: u64,
    buffers_needed: u32,
    block_descriptors: u32,
    reserved: [u32; 6],
    /// checksum
    checksum: UDIFChecksum,
    /// number of chunks in the following table
    num_chunks: u32,
    /// chunks
    chunks: Vec<BLKXChunk>,
}

impl std::convert::From<Vec<u8>> for BLKXTable {
    /// parse a BLKXTable struct from binary input
    fn from(data: Vec<u8>) -> Self {
        let mut c = Cursor::new(data);
        let decoder = bincode::DefaultOptions::new().with_big_endian();
        let mut table = BLKXTable {
            signature: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            version: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            sector_number: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            sector_count: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            data_offset: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            buffers_needed: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            block_descriptors: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            reserved: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            checksum: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            num_chunks: decoder
                .with_fixint_encoding()
                .deserialize_from(&mut c)
                .unwrap(),
            chunks: vec![],
        };
        let chunks: Vec<BLKXChunk> = (0..table.num_chunks)
            .map(|_| {
                decoder
                    .with_fixint_encoding()
                    .deserialize_from(&mut c)
                    .unwrap()
            })
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

/// Defines how much information should be printed
#[derive(PartialEq, Debug, Copy, Clone)]
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

/// Main type representing a DMG
///
/// Use the `from_reader` method to parse a DMG from any input stream. Afterwards, partition
/// information will be available through the `partitions` attribute. Either `extract_all` or
/// `extract` can be used to retrieve partition data from the image.
///
/// See `main.rs` for a real-world example.
pub struct DmgWiz<R> {
    input: R,
    /// Array of partitions
    pub partitions: Vec<Partition>,
    data_offset: u64,
    pub verbosity: Verbosity,
}

impl<R> DmgWiz<R>
where
    R: Read + Seek,
{
    /// Create a `DmgWiz` instance from a seekable byte stream
    ///
    /// # Arguments
    ///
    /// * `input` - A seekable reader
    /// * `verbosity` - Verbosity for debugging
    ///
    /// # Example
    ///
    /// ```
    /// use std::fs::File;
    /// use dmgwiz::{DmgWiz, Verbosity};
    ///
    /// let input = File::open("tests/input_zlib.dmg").unwrap();
    /// let mut wiz = match DmgWiz::from_reader(input, Verbosity::None) {
    ///     Err(err) => panic!(format!("could not read input file - {}", err)),
    ///     Ok(val) => val,
    /// };
    /// ```
    pub fn from_reader(mut input: R, verbosity: Verbosity) -> Result<DmgWiz<R>> {
        // seek to end of file to read koly header
        input.seek(SeekFrom::End(-0x200))?;

        // try to read header
        let header: KolyHeader = match bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .deserialize_from(&mut input)
        {
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
        if verbosity == Verbosity::Debug {
            println!("{:#?}", header);
        }

        // sanity check
        if header.data_fork_length == 0 {
            return Err(Error::InvalidInput("data fork length is 0".to_string()));
        }
        let data_offset = header.data_fork_offset;

        // read plist
        input.seek(SeekFrom::Start(header.xml_offset))?;
        let partial_reader = input.by_ref().take(header.xml_length);
        let mut plist = plist::Value::from_reader_xml(partial_reader)?;

        // get partitions from dict
        let partitions_arr = plist
            .as_dictionary_mut()
            .and_then(|dict| dict.get("resource-fork"))
            .and_then(|rsfk| rsfk.as_dictionary())
            .and_then(|rsfk| rsfk.get("blkx"))
            .and_then(|blkx| blkx.as_array())
            .ok_or_else(|| Error::InvalidInput("invalid plist structure".to_string()))?;

        fn get_string<'a>(dict: &'a plist::Dictionary, name: &str) -> Option<&'a str> {
            dict.get(name).and_then(|v| v.as_string())
        }

        // convert partition dicts to Partition objects
        let partitions: Vec<Partition> = partitions_arr
            .iter()
            .map(|part| part.as_dictionary())
            .map(|part| Partition {
                name: part
                    .and_then(|p| {
                        get_string(p, "Name")
                            .filter(|n| !n.is_empty())
                            .or_else(|| get_string(p, "CFName"))
                    })
                    .unwrap_or_default()
                    .to_string(),
                attributes: part
                    .and_then(|p| get_string(p, "Attributes"))
                    .unwrap_or_default()
                    .to_string(),
                blkx_table: part
                    .and_then(|p| p.get("Data"))
                    .and_then(|n| n.as_data())
                    .unwrap_or_default()
                    .to_vec()
                    .into(),
                id: part
                    .and_then(|p| p.get("ID"))
                    .and_then(|n| n.as_signed_integer())
                    .unwrap_or_default(),
            })
            .collect();

        Ok(DmgWiz {
            input,
            partitions,
            data_offset,
            verbosity,
        })
    }

    /// Decompress all partitions and write to output
    ///
    /// # Arguments
    ///
    /// * `output` - A seekable writer
    ///
    /// # Example
    ///
    /// ```
    /// use std::{fs::File, io::BufWriter};
    /// use dmgwiz::{DmgWiz, Verbosity};
    ///
    /// let input = File::open("tests/input_zlib.dmg").unwrap();
    /// let outfile = File::create("tests/tmp_output_zlib.bin").unwrap();
    /// let output = BufWriter::new(outfile);
    ///
    /// let mut wiz = DmgWiz::from_reader(input, Verbosity::None).unwrap();
    /// match wiz.extract_all(output) {
    ///     Err(err) => panic!(format!("error while extracting: {}", err)),
    ///     Ok(bytes) => println!("done. {} bytes written", bytes),
    /// }
    /// ```
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

    /// Decompress a specific partition and write to output
    ///
    /// Partition information can be retrieved using the `partitions` attribute of `DmzWiz`.
    /// Returns the number of written bytes.
    ///
    /// # Arguments
    ///
    /// * `output` - A writer
    /// * `partition_num` - Index of the partition
    ///
    /// # Example
    ///
    /// ```
    /// use std::{fs::File, io::BufWriter};
    /// use dmgwiz::{DmgWiz, Verbosity};
    ///
    /// let input = File::open("tests/input_zlib.dmg").unwrap();
    /// let outfile = File::create("tests/tmp_output_zlib.bin").unwrap();
    /// let output = BufWriter::new(outfile);
    ///
    /// let mut wiz = DmgWiz::from_reader(input, Verbosity::None).unwrap();
    /// match wiz.extract_partition(output, 0) {
    ///     Err(err) => panic!(format!("error while extracting: {}", err)),
    ///     Ok(bytes) => println!("done. {} bytes written", bytes),
    /// }
    /// ```
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

        printDebug!(self, "{}", partition);

        let mut sectors_written = 0;

        for (chunk_num, chunk) in partition.blkx_table.chunks.iter().enumerate() {
            let chunk_type = ChunkType::from_u32(chunk.r#type).ok_or_else(|| {
                Error::InvalidInput(format!("unknown chunk type {:#010x}", chunk.r#type))
            })?;

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

            // usually sectors are consecutive, but let's check to be sure.
            // if chunk.sector_number is less than what we have already written we have a problem.
            // otherwise just write NULL sectors.
            match chunk.sector_number.cmp(&sectors_written) {
                Ordering::Less => {
                    return Err(Error::InvalidInput(format!(
                        "invalid sector number: {} (partition={} chunk={})",
                        chunk.sector_number, partition_num, chunk_num
                    )))
                }
                Ordering::Greater => {
                    let padding_sectors = chunk.sector_number - sectors_written;
                    let padding = vec![0; SECTOR_SIZE];
                    for _ in 0..padding_sectors {
                        output.write_all(&padding)?;
                    }
                }
                Ordering::Equal => (),
            }

            let in_len = chunk.compressed_length as usize;
            let out_len = chunk.sector_count as usize * SECTOR_SIZE;

            let chunk_offset =
                self.data_offset + partition.blkx_table.data_offset + chunk.compressed_offset;
            self.input.seek(SeekFrom::Start(chunk_offset))?;
            let mut chunk_input = BoundedReader {
                inner: &mut self.input,
                len: in_len,
            };

            // decompress
            let bytes_read = match chunk_type {
                ChunkType::Ignore | ChunkType::Zero | ChunkType::Comment => {
                    write_zero(&mut output, out_len)
                }
                ChunkType::Raw => copy(&mut chunk_input, &mut output),
                ChunkType::ADC => decode_adc(&mut chunk_input, &mut output),
                ChunkType::ZLIB => decode_zlib(&mut chunk_input, &mut output),
                ChunkType::BZLIB => decode_bzlib(&mut chunk_input, &mut output),
                ChunkType::LZFSE => decode_lzfse(&mut chunk_input, &mut output, out_len),
                ChunkType::Term => unreachable!(),
            };

            match bytes_read {
                Ok(val) if val == out_len => printDebug!(self, "decompressed {} bytes", val),
                _ => {
                    return Err(Error::Decompress {
                        partition_num,
                        chunk_num,
                        chunk_type,
                    })
                }
            };

            sectors_written += chunk.sector_count;
        }

        Ok(sectors_written as usize * SECTOR_SIZE)
    }

    fn check_encrypted_or(mut input: R, err: Error) -> Error {
        if let Err(err) = input.seek(SeekFrom::Start(0)) {
            return err.into();
        }
        match bincode::DefaultOptions::new()
            .with_big_endian()
            .with_fixint_encoding()
            .deserialize_from::<&mut R, EncryptedDmgHeader>(&mut input)
        {
            Ok(ref hdr) if hdr.get_signature() == "encrcdsa" => Error::Encrypted,
            _ => err,
        }
    }
}

struct BoundedReader<R> {
    inner: R,
    len: usize,
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let max_len = cmp::min(self.len, buf.len());
        let read_len = self.inner.read(&mut buf[..max_len])?;
        self.len -= read_len;
        Ok(read_len)
    }
}

fn decode_zlib<R: Read, W: Write>(src: &mut R, dest: &mut W) -> Result<usize> {
    let mut z = ZlibDecoder::new(src);
    let len = io::copy(&mut z, dest)?;
    Ok(len as usize)
}

fn decode_bzlib<R: Read, W: Write>(src: &mut R, dest: &mut W) -> Result<usize> {
    let mut bz = BzDecoder::new(src);
    let len = io::copy(&mut bz, dest)?;
    Ok(len as usize)
}

fn decode_lzfse<R: Read, W: Write>(src: &mut R, dest: &mut W, dest_size: usize) -> Result<usize> {
    let input = src.bytes().collect::<io::Result<Vec<_>>>()?;
    // We need to allocate one byte more because the lzfse library internally
    // uses `buf.len()` to signal a too-small output buffer.
    let mut out_buf = vec![0; dest_size + 1];

    let len = lzfse::decode_buffer(&input, &mut out_buf)
        .map_err(|_| Error::InvalidInput("lzfse decompression failed".into()))?;

    dest.write_all(&out_buf[..dest_size])?;
    Ok(len)
}

fn decode_adc<R: Read, W: Write>(src: &mut R, dest: &mut W) -> Result<usize> {
    let mut adc = AdcDecoder::new(src);
    let len = io::copy(&mut adc, dest)?;
    Ok(len as usize)
}

fn write_zero<W: Write>(w: &mut W, len: usize) -> Result<usize> {
    let mut zeros = io::repeat(0).take(len as u64);
    io::copy(&mut zeros, w)?;
    Ok(len)
}

fn copy<R: Read, W: Write>(src: &mut R, dest: &mut W) -> Result<usize> {
    let len = io::copy(src, dest)?;
    Ok(len as usize)
}
