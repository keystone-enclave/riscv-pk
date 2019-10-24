#![no_std]

#[cfg(test)]
extern crate mock;

pub mod attest;
pub mod cpu;
pub mod sm;
pub mod enclave;
mod crypto;
mod pmp;

#[allow(warnings)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}


#[cfg(test)]
#[macro_use]
extern crate utest_macros;

#[cfg(test)]
macro_rules! panic {
    ($($tt:tt)*) => {
        upanic!($($tt)*);
    };
}
