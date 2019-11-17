#![feature(lang_items)]
#![no_std]

use core::fmt::Write;

use util::{println, print, LogWriter};
use util::ctypes::*;

#[lang = "start"]
pub fn start<T>(main: fn() -> T, _argc: isize, _argv: *const *const u8) -> isize
where
    T: Termination,
{
    main();
    0
}

#[lang = "termination"]
pub trait Termination {
    fn report(self) -> i32;
}

impl Termination for () {
    fn report(self) -> i32 {
        0
    }
}


//#[cfg(test)]
pub fn test_runner(tests: &[&dyn Fn()]) {
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
}

#[no_mangle]
pub fn __test_start(ntests: usize) {
    println!("running {} tests", ntests)
}

#[no_mangle]
pub fn __test_ignored(name: &str) {
    println!("test {} ... ignored", name);
}

#[no_mangle]
pub fn __test_before_run(name: &str) {
    print!("test {} ... ", name);
}

#[no_mangle]
pub fn __test_panic_fmt(args: ::core::fmt::Arguments,
                        file: &'static str,
                        line: u32) {
    print!("\npanicked at '");
    let _ = LogWriter.write_fmt(args);
    println!("', {}:{}", file, line);
}

#[no_mangle]
pub fn __test_failed(_name: &str) {
    println!("FAILED");
}

#[no_mangle]
pub fn __test_success(_name: &str) {
    println!("OK");
}

#[no_mangle]
pub fn __test_summary(passed: usize, failed: usize, ignored: usize) {
    println!("\ntest result: {}. {} passed; {} failed; {} ignored",
              if failed == 0 { "OK" } else { "FAILED" },
              passed,
              failed,
              ignored);

    if failed != 0 {
    }
}


#[no_mangle]
pub static mut disabled_hart_mask: c_long = 0;


const MDSIZE: usize = 64;
const SIGNATURE_SIZE: usize = 64;
const PRIVATE_KEY_SIZE: usize = 64; // includes public key
const PUBLIC_KEY_SIZE: usize = 32;

#[no_mangle]
pub static mut sanctum_sm_hash: [u8; MDSIZE] = [0u8; MDSIZE];
#[no_mangle]
pub static mut sanctum_sm_signature: [u8; SIGNATURE_SIZE] = [0u8; SIGNATURE_SIZE];
#[no_mangle]
pub static mut sanctum_sm_public_key: [u8; PRIVATE_KEY_SIZE] = [0u8; PRIVATE_KEY_SIZE];
#[no_mangle]
pub static mut sanctum_sm_secret_key: [u8; PUBLIC_KEY_SIZE] = [0u8; PUBLIC_KEY_SIZE];
#[no_mangle]
pub static mut sanctum_dev_public_key: [u8; PUBLIC_KEY_SIZE] = [0u8; PUBLIC_KEY_SIZE];

#[no_mangle]
pub extern fn boot_loader(_dtb: usize) {
    unreachable!();
}

#[no_mangle]
pub extern fn boot_other_hart(_dtb: usize) {
    unreachable!();
}
