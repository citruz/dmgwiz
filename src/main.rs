use std::error::Error;
use std::io::SeekFrom;
use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::path::Path;
use std::process;

use clap::{App, Arg, SubCommand};
use serde::{Deserialize, Serialize};
use bincode::config as bincode_config;

mod decrypt;
use decrypt::EncryptedDmgReader;

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
    segment_ids: [u32; 4],
    data_fork_checksum_type: u32,
    reserved1: u32,
    data_fork_checksum: u32,
    reserved2: u32,
    reserved3: [u64; 15],
    xml_offset: u64,
    xml_length: u64,
    reserved4: [u64; 15],
    master_checksum_type: u32,
    reserved5: u32,
    master_checksum: u32,
    reserved6: u32,
    reserved7: [u64; 15],
    image_variant: u32,
    sector_count: u64,
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
            SubCommand::with_name("info")
                .about("show dmg properties")
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
    if let Some(_) = matches.subcommand_matches("info") {
        if let Err(err) = info(input) {
            eprintln!("Error while retrieving info: {}", err);
            process::exit(1);
        }
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
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
    }
}

fn info<R>(mut input: R) -> Result<(), String>
where
    R: Read + Seek
 {
    if let Err(err) = input.seek(SeekFrom::End(-0x200)) {
        return Err(format!("Invalid input file: {}", err));
    };

    let header: KolyHeader =
        match bincode_config().big_endian().deserialize_from(&mut input) {
            Err(err) => return Err(format!("couldn't read: {}", err)),
            Ok(header) => header,
        };

    println!("{:?}", header);
    if header.signature.iter().collect::<String>() != "koly" {
        return Err(format!(
            "Invalid header signature: {:?}",
            header.signature.iter().collect::<String>()
        ));
    }

    Ok(())
}