extern crate cc;

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let mut cfg = cc::Build::new();
    cfg.warnings(false);

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    cfg.include("lzfse/src")
        .file("lzfse/src/lzfse_encode.c")
        .file("lzfse/src/lzfse_decode.c")
        .file("lzfse/src/lzfse_encode_base.c")
        .file("lzfse/src/lzfse_decode_base.c")
        .file("lzfse/src/lzvn_encode_base.c")
        .file("lzfse/src/lzvn_decode_base.c")
        .file("lzfse/src/lzfse_fse.c")
        .out_dir(dst.join("lib"))
        .compile("libbz2.a");

    let src = env::current_dir().unwrap().join("lzfse").join("src");
    let include = dst.join("include");
    fs::create_dir_all(&include).unwrap();
    fs::copy(src.join("lzfse.h"), include.join("lzfse.h")).unwrap();
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", dst.join("include").display());
}
