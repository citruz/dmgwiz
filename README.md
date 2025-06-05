DmgWiz
======
[![CI](https://github.com/citruz/dmgwiz/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/citruz/dmgwiz/actions/workflows/main.yml)
[![crates.io](https://img.shields.io/crates/v/dmgwiz)](https://crates.io/crates/dmgwiz)

DmgWiz lets you extract raw filesystem data from compressed and encrypted DMG files. It started as a [dmg2img](http://vu1tur.eu.org/tools/) clone but has more features and is more secure due to the Rust programming language.

- Support for adc, zlib, bzip2 and lzfse compression
- Support for encrypted DMGs (AES-128 and AES-256)
- Runs on Windows, Linux, macOS

DmgWiz is both a CLI tool and a Rust crate so it can be integrated into other projects.

**[🚀 &nbsp;&nbsp;Download](https://github.com/citruz/dmgwiz/releases)**

CLI Usage
---------

    dmgwiz [OPTIONS] <COMMAND>

    Commands:
      info     Print DMG partitions
      extract  Extract single or all partitions
      decrypt  Decrypt DMG
      help     Print this message or the help of the given subcommand(s)

    Global options (must be placed before subcommand):
      -q, --quiet       Only print errors
      -v, --verbose...  Level of verbosity (multiple allowed)
      -h, --help        Print help
      -V, --version     Print version

**info**

    dmgwiz info [OPTIONS] <INPUT>

    Arguments:
      <INPUT>  Input file to read

    Options:
      -p, --password <PASSWORD>  Password for encrypted DMGs
      -h, --help                 Print help

**decrypt**

    dmgwiz decrypt --password <PASSWORD> <INPUT> <OUTPUT>

    Arguments:
      <INPUT>   Input file to read
      <OUTPUT>  Output file

    Options:
      -p, --password <PASSWORD>  Password for encrypted DMGs (required)
      -h, --help                 Print help

**extract**

    dmgwiz extract [OPTIONS] <INPUT> <OUTPUT>

    Arguments:
      <INPUT>   Input file to read
      <OUTPUT>  Output file

    Options:
      -p, --password <PASSWORD>    Password for encrypted DMGs
      -n, --partition <PARTITION>  Partition number (see info command). By default all partitions will be extracted.
      -h, --help                   Print help


Crate Usage
-----------

DmgWiz can also be used as a crate in other Rust projects. Please see the [API Documentation](https://docs.rs/dmgwiz) and `main.rs` for examples how to use it.

Support for encrypted DMGs can be disabled to reduce the compilation time and amount of C code. To do this, add the `default-features = false` option in your `Cargo.toml`:&nbsp;
```TOML
[dependencies]
dmgwiz = {version = "0.2", default-features = false}
```

Changelog
---------

1.1.0
- Made XML parsing more robust by ignoring trailing garbage data.

1.0.0
- Refactored CLI so that the argument order or more intuitive: First global options (verbose, quiet), then subcommand, then options.

0.2.4
- Fixed parsing of XML with plist 1.5

0.2.3
- Fixed handling of DMGs with a non-null value in blkx_table.data_offset

0.2.2
- Reverted to buffer-based decoding for LZFSE

0.2.1
- Removed temporary buffers for decompression

0.2.0
- Added support for comment chunks
- Added `CFName` as fallback in case the `Name` attribute is not set
- Separated crypto support in a feature (enabled by default)

0.1.0
- Initial release

References
----------
- [dmg2img](http://vu1tur.eu.org/tools/)
- [Demystifying the DMG File Format - Jonathan Levin](http://newosxbook.com/DMG.html)

TODO
----
- verify checksums in DMG
- add support for LZMA ("ULMO")
