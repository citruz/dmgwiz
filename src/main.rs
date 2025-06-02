use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::path::Path;
use std::process;

use clap::{arg, Command};

use dmgwiz::{DmgWiz, EncryptedDmgReader, Verbosity};

trait ReadNSeek: Read + Seek {}
impl<T: Read + Seek> ReadNSeek for T {}

fn error(msg: String) -> ! {
    eprintln!("error: {}", msg);
    process::exit(1);
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Action {
    Info,
    Extract,
    Decrypt,
}

fn common_args(password_req: bool) -> Vec<clap::Arg> {
    let mut password_help = "Password for encrypted DMGs".to_owned();
    if password_req {
        password_help.push_str(" (required)");
    }
    vec![
        arg!(<INPUT> "Input file to read"),
        arg!(-p --password <PASSWORD>)
            .required(password_req)
            .help(password_help),
    ]
}

fn main() {
    let matches = Command::new("dmgwiz")
        .version("1.1.0")
        .author("Felix Seele <fseele@gmail.com>")
        .about("Extract filesystem data from DMG files")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(arg!(-q --quiet "Only print errors"))
        .arg(arg!(-v --verbose ... "Level of verbosity (multiple allowed)"))
        .subcommand(
            Command::new("info")
                .about("Print DMG partitions")
                .args(common_args(false))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("extract")
                .about("Extract single or all partitions")
                .arg_required_else_help(true)
                .args(common_args(false))
                .arg(arg!(<OUTPUT> "Output file"))
                .arg(arg!(-n --partition <PARTITION> "Partition number (see info command). By default all partitions will be extracted."))
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt DMG")
                .arg_required_else_help(true)
                .args(common_args(true))
                .arg(arg!(<OUTPUT> "Output file"))
        )
        .get_matches();

    let verbosity = match matches.get_flag("quiet") {
        true => Verbosity::None,
        false => match matches.get_count("verbose") {
            0 => Verbosity::Info,
            _ => Verbosity::Debug,
        },
    };

    let (action, sub_matches) = match matches.subcommand() {
        Some(("info", sub_matches)) => (Action::Info, sub_matches),
        Some(("extract", sub_matches)) => (Action::Extract, sub_matches),
        Some(("decrypt", sub_matches)) => (Action::Decrypt, sub_matches),
        _ => unreachable!(),
    };

    // open input file
    let in_file = sub_matches.get_one::<String>("INPUT").unwrap();
    let in_path = Path::new(in_file);
    let input = match File::open(in_path) {
        Err(why) => error(format!("could not open input file - {}", why)),
        Ok(file) => file,
    };

    if action == Action::Decrypt {
        let password = sub_matches.get_one::<String>("password").unwrap();
        let out_file = sub_matches.get_one::<String>("OUTPUT").unwrap();

        decrypt(verbosity, input, out_file, password);
    } else {
        // if a password is supplied, use it do create an EncryptedDmgReader
        let input_real: Box<dyn ReadNSeek> = match sub_matches.get_one::<String>("password") {
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
                    "dmg is encrypted, please use the -p option to provide a password".to_string(),
                ),
                _ => error(format!("could not read input file - {}", err)),
            },
            Ok(val) => val,
        };
        if action == Action::Info {
            info(wiz, verbosity);
        } else if action == Action::Extract {
            let out_file = sub_matches.get_one::<String>("OUTPUT").unwrap();
            let partition = sub_matches.get_one::<String>("partition");
            extract(&mut wiz, out_file, partition.map(|s| s.as_str()));
        } else {
            panic!("should not be reached")
        }
    }
}

fn decrypt(verbosity: Verbosity, input: File, out_file: &str, password: &str) {
    // open output file
    let out_path = Path::new(out_file);
    let output = match File::create(out_path) {
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
    let output = match File::create(out_path) {
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
