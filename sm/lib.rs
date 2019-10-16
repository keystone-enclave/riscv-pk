#![no_std]
#![feature(const_transmute)]

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
