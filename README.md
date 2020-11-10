DmgWiz
======
![Build and Test](https://github.com/citruz/dmgwiz/workflows/Build%20and%20Test/badge.svg?branch=main)
[![crates.io](https://img.shields.io/crates/v/dmgwiz)](https://crates.io/crates/dmgwiz)

DmgWiz lets you extract raw filesystem data from compressed and encrypted DMG files. It started as a [dmg2img](http://vu1tur.eu.org/tools/) clone but has more features and is more secure due to the Rust programming language.

- Support for adc, zlib, bzip2 and lzfse compression
- Support for encrypted DMGs (AES-128 and AES-256)
- Runs on Windows, Linux, macOS

DmgWiz is both a CLI tool and a Rust crate so it can be integrated into other projects.


CLI Usage
---------

    dmgwiz [OPTIONS] <INPUT> [SUBCOMMAND]

    OPTIONS:
    -q               Only print errors
    -v               Sets the level of verbosity (multiple allowed)
    -p <password>    Password for encrypted DMGs

**info**

    dmgwiz <INPUT> info

**decrypt**

    dmgwiz <INPUT> decrypt -o <output> -p <password>

**extract**

    dmgwiz <INPUT> extract [-n <partition number>] -o <output>
    

Crate Usage
-----------

DmgWiz can also be used as a crate in other Rust projects. Please see the [API Documentation](https://docs.rs/dmgwiz) and `main.rs` for examples how to use it.

Support for encrypted DMGs can be disabled to reduce the compilation time and amount of C code. To do this, add the `default-features = false` option in your `Cargo.toml`:
```TOML
[dependencies]
dmgwiz = {version = "0.2", default-features = false}
```

Changelog
---------

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