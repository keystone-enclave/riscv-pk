#![no_std]
#[deny(warnings)]

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
extern crate utest_macros;

#[cfg(test)]
#[allow(unused_macros)]
macro_rules! panic {
    ($($tt:tt)*) => {
        utest_macros::upanic!($($tt)*);
    };
}
