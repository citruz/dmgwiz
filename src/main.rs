use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::path::Path;

use clap::{App, Arg, SubCommand};

use dmgwiz::{DmgWiz, EncryptedDmgReader, Verbosity};

trait ReadNSeek: Read + Seek {}
impl<T: Read + Seek> ReadNSeek for T {}

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
        .arg(
            Arg::with_name("password")
                .short("p")
                .takes_value(true)
                .help("Password for encrypted DMGs"),
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
                )
                .arg(
                    Arg::with_name("output")
                        .takes_value(true)
                        .short("o")
                        .required(true)
                        .help("output file"),
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

    let verbosity = match matches.occurrences_of("v") {
        0 => Verbosity::Info,
        1 | _ => Verbosity::Debug,
    };

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
        let input_real: Box<dyn ReadNSeek> = match matches.value_of("password") {
            None => Box::new(input),
            Some(password) => Box::new(EncryptedDmgReader::from_reader(input, password).unwrap()),
        };
        let buf_reader = &mut BufReader::new(input_real);
        let mut wiz = match DmgWiz::from_reader(buf_reader, verbosity) {
            Err(err) => panic!("Error while reading dmg: {}", err),
            Ok(val) => val,
        };
        if let Some(_) = matches.subcommand_matches("info") {
            wiz.info();
        } else if let Some(matches) = matches.subcommand_matches("extract") {
            let out_file = matches.value_of("output").unwrap();
            let out_path = Path::new(out_file);
            let output = match File::create(&out_path) {
                Err(why) => panic!(
                    "couldn't open {}: {}",
                    out_path.display(),
                    why.description()
                ),
                Ok(file) => file,
            };
            let buf_writer = &mut BufWriter::new(output);

            let res;
            if let Some(partition_str) = matches.value_of("partition") {
                let partition_num: usize = match partition_str.parse() {
                    Ok(val) => val,
                    Err(_) => panic!(format!("invalid partition number: {}", partition_str)),
                };
                res = wiz.extract_partition(buf_writer, partition_num)
            } else {
                res = wiz.extract_all(buf_writer);
            }

            if let Err(err) = res {
                panic!("Error while extracting: {}", err);
            }
        }
    }
}
