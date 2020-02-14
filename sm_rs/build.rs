extern crate bindgen;

use std::env;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    //let cc = env::var("CC")
    //    .expect("could not find compiler!");
    let cc = "riscv64-unknown-elf-gcc";

    let cc_child = Command::new(cc)
        .arg("-print-sysroot")
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start cc process");

    let output = cc_child.wait_with_output()
        .expect("Failed to wait on cc");
    let sysroot_bytes = output.stdout.split(|b| *b == b'\n')
        .next()
        .expect("Found no output for $(CC) -print-sysroot!"); 

    let sysroot = OsStr::from_bytes(sysroot_bytes);
    let sysroot_include = Path::new(sysroot)
        .join("include")
        .canonicalize()
        .expect("Failure to canonicalize sysroot include directory!");

    let cflags = env::var("CFLAGS")
        .unwrap_or("".into());
    let cflags_iter = cflags
        .split_whitespace();

    let bindings = bindgen::Builder::default()
        .header("bindings.h")
        .clang_arg("--target=riscv64")
        .clang_arg("-I.")
        .clang_arg("-I../machine/")
        .clang_arg(format!("-I{}", sysroot_include.to_str().unwrap()))
        .clang_args(cflags_iter)
        .ctypes_prefix("::util")
        .use_core()
        .rustfmt_bindings(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
