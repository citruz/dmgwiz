dmgwiz
======
dmgwiz lets you extract raw filesystem data from compressed and encrypted DMG files. It started as a [dmg2img](http://vu1tur.eu.org/tools/) clone but has more features and is more secure due to the Rust programming language.

- Support for adc, zlib, bzip2 and lzfse compression
- Support for encrypted DMGs (AES-128 and AES-256)
- Runs on Windows, Linux, macOS

dmgwiz is both a CLI tool and a Rust crate so it can be integrated into other projects.

Usage
-----

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

    dmgwiz <INPUT> extract [-p <partition number>] -o <output>
    


References
----------
- [dmg2img](http://vu1tur.eu.org/tools/)
- [Demystifying the DMG File Format - Jonathan Levin](http://newosxbook.com/DMG.html)

TODO
----
- verify checksums in DMG