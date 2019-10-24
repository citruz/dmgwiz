use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Cursor;
use std::io::SeekFrom;
use std::path::Path;

use itertools::Itertools;
use flate2::read::ZlibDecoder;
use bincode::config as bincode_config;
use clap::{App, Arg, SubCommand};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use plist::Value;
use serde::{Deserialize, Serialize};
mod decrypt;
use decrypt::EncryptedDmgReader;

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
             \tName:      {}\n\
             \tAttibutes: {}\n\
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
#[derive(FromPrimitive, Debug)]
enum ChunkType {
    //Zero = 0x00000000,
    //Raw = 0x00000001,
    //Ignore = 0x00000002,
    //Comment = 0x7ffffffe,

    //ADV = 0x80000004,
    ZLIB = 0x80000005,
    //BZLIB = 0x80000006,
    //LZFSE = 0x80000007,

    //Term = 0xffffffff,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct BLKXChunk {
    r#type: u32,
    comment: u32,
    sector_number: u64,
    sector_count: u64,
    offset: u64,
    length: u64,
}

impl fmt::Display for BLKXChunk {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let type_str = match ChunkType::from_u32(self.r#type) {
            Some(val) => format!("{:?}", val),
            None => "??".to_string(),
        };
        write!(
            f,
            "\t\t\tType:      {:#010x} ({})\n\
             \t\t\tComment:   {}\n\
             \t\t\t# sectors: {}\n\
             \t\t\tOffset:    {:#010x}\n\
             \t\t\tLength:    {:#010x}",
            self.r#type, type_str, self.comment, self.sector_count, self.offset, self.length
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

struct DmgWiz<R> {
    input: R,
    partitions: Vec<Partition>,
}

impl<R> DmgWiz<R>
where
    R: Read + Seek,
{
    pub fn from_reader(mut input: R) -> Result<DmgWiz<R>, String> {
        if let Err(err) = input.seek(SeekFrom::End(-0x200)) {
            return Err(format!("Invalid input file: {}", err));
        };

        let header: KolyHeader = match bincode_config().big_endian().deserialize_from(&mut input) {
            Err(err) => return Err(format!("couldn't read: {}", err)),
            Ok(header) => header,
        };

        //println!("{:?}", header);
        if header.signature.iter().collect::<String>() != "koly" {
            return Err(format!(
                "Invalid header signature: {:?}",
                header.signature.iter().collect::<String>()
            ));
        }

        // read plist
        if let Err(err) = input.seek(SeekFrom::Start(header.xml_offset)) {
            return Err(format!("Invalid xml offset: {}", err));
        };
        let mut plist = match Value::from_reader_xml(&mut input) {
            Err(err) => return Err(format!("could not parse plist: {}", err)),
            Ok(val) => val,
        };

        // get partitions from dict
        let partitions_arr = match plist
            .as_dictionary_mut()
            .and_then(|dict| dict.get("resource-fork"))
            .and_then(|rsfk| rsfk.as_dictionary())
            .and_then(|rsfk| rsfk.get("blkx"))
            .and_then(|blkx| blkx.as_array())
        {
            None => return Err("invalid plist structure".to_string()),
            Some(val) => val,
        };

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

        Ok(DmgWiz { input, partitions })
    }

    pub fn info(&self) {
        for (i, partition) in self.partitions.iter().enumerate() {
            println!("partition {}: {}", i, partition.name);
        }
    }

    pub fn extract_all(&mut self) -> Result<(), String> {
        println!("extracting all partitions");

        for i in 0..self.partitions.len() {
            self.extract_partition(i)?
        }
        Ok(())
    }

    pub fn extract_partition(&mut self, partition_num: usize) -> Result<(), String> {
        let partition = match self.partitions.get(partition_num) {
            Some(val) => val,
            None => {
                return Err(format!(
                    "invalid partition number: {} (see info command)",
                    partition_num
                ))
            }
        };
        println!(
            "extracting partition {} \"{}\"",
            partition_num, partition.name
        );

        println!("{}", partition);

        for (chunk_num, chunk) in partition.blkx_table.chunks.iter().enumerate() {
            let chunk_type = match ChunkType::from_u32(chunk.r#type) {
                Some(val) => val,
                None => return Err(format!("unknown chunk type: {:#010x}", chunk.r#type)),
            };

            println!(
                "chunk {}: type={:?} comment={} sector_number={} sector_count={} offset={} length={}",
                chunk_num,
                chunk_type,
                chunk.comment,
                chunk.sector_number,
                chunk.sector_count,
                chunk.offset,
                chunk.length
            );

            match chunk_type {
                ChunkType::ZLIB => self.decode_zlib(chunk)?
            }
        }

        Ok(())
    }

    fn decode_zlib(&mut self, chunk: &BLKXChunk) -> Result<(), String> {
        if let Err(_) = self.input.seek(SeekFrom::Start(chunk.offset)) {
            return Err(format!("invalid offset: {}", chunk.offset));
        }
        // allocate buffer for chunk
        let mut buf: Vec<u8> = vec![0; chunk.length.try_into().unwrap()];
        // read compressed chunk
        if let Err(_) = self.input.read_exact(&mut buf) {
            return Err(format!("could not read {} bytes from input", chunk.length));
        }
        let mut z = ZlibDecoder::new(&buf[..]);
        Ok(())
    }
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
        .subcommand(SubCommand::with_name("info").about("show dmg properties"))
        .subcommand(
            SubCommand::with_name("extract")
                .about("single or all partitions")
                .arg(
                    Arg::with_name("partition")
                        .takes_value(true)
                        .short("p")
                        .required(false)
                        .help("partition number (see info command)"),
                ),
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
    let in_path = Path::new(in_file);
    let input = match File::open(&in_path) {
        Err(why) => panic!("couldn't open {}: {}", in_path.display(), why.description()),
        Ok(file) => file,
    };
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

        let out_path = Path::new(out_file);
        let output = match File::create(&out_path) {
            Err(why) => panic!(
                "couldn't open {}: {}",
                out_path.display(),
                why.description()
            ),
            Ok(file) => file,
        };
        let buf_reader = &mut BufReader::new(input);
        let mut reader = match EncryptedDmgReader::from_reader(buf_reader, password) {
            Err(err) => panic!("Error while decrypting: {}", err),
            Ok(val) => val,
        };

        let buf_writer = &mut BufWriter::new(output);
        match reader.read_all(buf_writer) {
            Err(err) => panic!("Error while decrypting: {}", err),
            Ok(bytes_written) => println!("written {} bytes", bytes_written),
        };
    } else {
        let buf_reader = &mut BufReader::new(input);
        let mut wiz = match DmgWiz::from_reader(buf_reader) {
            Err(err) => panic!("Error while reading dmg: {}", err),
            Ok(val) => val,
        };
        if let Some(_) = matches.subcommand_matches("info") {
            wiz.info();
        } else if let Some(matches) = matches.subcommand_matches("extract") {
            let res;
            if let Some(partition_str) = matches.value_of("partition") {
                let partition_num: usize = match partition_str.parse() {
                    Ok(val) => val,
                    Err(_) => panic!(format!("invalid partition number: {}", partition_str)),
                };
                res = wiz.extract_partition(partition_num)
            } else {
                res = wiz.extract_all();
            }

            if let Err(err) = res {
                panic!("Error while extracting: {}", err);
            }
        }
    }
}
