//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

use riscv::register as csr;

type enclave_id = i32;

/* hart state for regulating SBI */
#[derive(Copy, Clone)]
struct CpuState 
{
  is_enclave: i32,
  eid: enclave_id,
}

const MAX_HARTS: usize = 8;
static mut CPUS: [CpuState; MAX_HARTS]
  = [CpuState { is_enclave: 0, eid: 0 }; MAX_HARTS];

#[no_mangle]
pub extern fn cpu_is_enclave_context() -> i32
{
  unsafe {
    return (CPUS[csr::mhartid::read()].is_enclave != 0) as i32;
  }
}

#[no_mangle]
pub extern fn cpu_get_enclave_id() -> i32
{
  unsafe {
    return CPUS[csr::mhartid::read()].eid;
  }
}

#[no_mangle]
pub extern fn cpu_enter_enclave_context(eid: enclave_id)
{
  unsafe {
    CPUS[csr::mhartid::read()].is_enclave = 1;
    CPUS[csr::mhartid::read()].eid = eid;
  }
}

#[no_mangle]
pub extern fn cpu_exit_enclave_context()
{
  unsafe {
    CPUS[csr::mhartid::read()].is_enclave = 0;
  }
}
