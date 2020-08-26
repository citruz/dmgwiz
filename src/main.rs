use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::path::Path;
use std::process;

use clap::{App, Arg, SubCommand};

use dmgwiz::{DmgWiz, EncryptedDmgReader, Verbosity};

trait ReadNSeek: Read + Seek {}
impl<T: Read + Seek> ReadNSeek for T {}

fn error(msg: String) -> ! {
    eprintln!("error: {}", msg);
    process::exit(1);
}

fn main() {
    let matches = App::new("dmgwiz")
        .version("0.2")
        .author("Felix Seele <fseele@gmail.com>")
        .about("Extract filesystem data from DMG files")
        .arg(
            Arg::with_name("INPUT")
                .help("Sets the input file to use")
                .required(true)
                .index(1),
        )
        .arg(Arg::with_name("quiet").short("q").help("Only print errors"))
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity (multiple allowed)"),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .takes_value(true)
                .help("Password for encrypted DMGs"),
        )
        .subcommand(SubCommand::with_name("info").about("Print DMG partitions"))
        .subcommand(
            SubCommand::with_name("extract")
                .about("Extract single or all partitions")
                .arg(
                    Arg::with_name("partition")
                        .takes_value(true)
                        .short("n")
                        .required(false)
                        .help("partition number (see info command)"),
                )
                .arg(
                    Arg::with_name("output")
                        .takes_value(true)
                        .short("o")
                        .required(true)
                        .help("Output file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt").about("Decrypt DMG").arg(
                Arg::with_name("output")
                    .takes_value(true)
                    .short("o")
                    .required(true)
                    .help("Path to write output"),
            ),
        )
        .get_matches();

    // open input file
    let in_file = matches.value_of("INPUT").unwrap();
    let in_path = Path::new(in_file);
    let input = match File::open(&in_path) {
        Err(why) => error(format!("could not open input file - {}", why)),
        Ok(file) => file,
    };

    let verbosity = match matches.is_present("quiet") {
        true => Verbosity::None,
        false => match matches.occurrences_of("v") {
            0 => Verbosity::Info,
            _ => Verbosity::Debug,
        },
    };

    if let Some(decrypt_args) = matches.subcommand_matches("decrypt") {
        let password = match matches.value_of("password") {
            Some(val) => val,
            None => error("no password supplied".to_string()),
        };
        let out_file = decrypt_args.value_of("output").unwrap();

        decrypt(verbosity, input, out_file, password);
    } else {
        // if a password is supplied, use it do create an EncryptedDmgReader
        let input_real: Box<dyn ReadNSeek> = match matches.value_of("password") {
            None => Box::new(input),
            Some(password) => match EncryptedDmgReader::from_reader(input, password, verbosity) {
                Ok(reader) => Box::new(reader),
                Err(err) => error(format!("{}", err)),
            },
        };
        // read dmg
        let buf_reader = &mut BufReader::new(input_real);
        let mut wiz = match DmgWiz::from_reader(buf_reader, verbosity) {
            Err(err) => match err {
                dmgwiz::Error::Encrypted => error(
                    "dmg is encrypted, please use the -p option and provide a password".to_string(),
                ),
                _ => error(format!("could not read input file - {}", err)),
            },
            Ok(val) => val,
        };
        if matches.subcommand_matches("info").is_some() {
            info(wiz, verbosity);
        } else if let Some(matches) = matches.subcommand_matches("extract") {
            let out_file = matches.value_of("output").unwrap();
            extract(&mut wiz, out_file, matches.value_of("partition"));
        }
    }
}

fn decrypt(verbosity: Verbosity, input: File, out_file: &str, password: &str) {
    // open output file
    let out_path = Path::new(out_file);
    let output = match File::create(&out_path) {
        Err(why) => error(format!("could not open output file - {}", why)),
        Ok(file) => file,
    };

    // read input file
    let buf_reader = &mut BufReader::new(input);
    let mut reader = match EncryptedDmgReader::from_reader(buf_reader, password, verbosity) {
        Err(err) => match err {
            dmgwiz::Error::Parse(ref _e) => {
                error("could not parse input file - are you sure it is encrypted?".to_string())
            }
            dmgwiz::Error::InvalidPassword => error("invalid password".to_string()),
            _ => error(format!("could not read encrypted dmg - {}", err)),
        },
        Ok(val) => val,
    };

    // write output file
    let buf_writer = &mut BufWriter::new(output);
    match reader.read_all(buf_writer) {
        Err(err) => error(format!("could not read encrypted dmg - {}", err)),
        Ok(bytes_written) => println!("{} bytes written", bytes_written),
    };
}

fn info(wiz: DmgWiz<&mut BufReader<Box<dyn ReadNSeek>>>, verbosity: Verbosity) {
    for (i, partition) in wiz.partitions.iter().enumerate() {
        if verbosity == Verbosity::Debug {
            println!("{}", partition);
        } else {
            println!("partition {}: {}", i, partition.name);
        }
    }
}

fn extract(
    wiz: &mut DmgWiz<&mut BufReader<Box<dyn ReadNSeek>>>,
    out_file: &str,
    partition: Option<&str>,
) {
    // open output file
    let out_path = Path::new(out_file);
    let output = match File::create(&out_path) {
        Err(why) => error(format!("could not open ouput file - {}", why)),
        Ok(file) => file,
    };
    let buf_writer = &mut BufWriter::new(output);

    // extract partition(s)
    let result = match partition {
        Some(partition_str) => {
            let partition_num = match partition_str.parse() {
                Ok(val) => val,
                Err(_) => error(format!("invalid partition number: {}", partition_str)),
            };
            wiz.extract_partition(buf_writer, partition_num)
        }
        None => wiz.extract_all(buf_writer),
    };

    if let Err(err) = result {
        error(format!("Error while extracting: {}", err));
    }
}
