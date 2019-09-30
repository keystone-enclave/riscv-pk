#![no_std]

pub mod cpu;
pub mod sm;
pub mod enclave;

#[allow(warnings)]
pub mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
