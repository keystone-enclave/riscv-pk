use core::mem::size_of;
use core::slice;

use util::ctypes::*;
use crate::bindings::*;
use crate::sm;


fn enclave_exists(eid: enclave_id) -> bool {
  unsafe {
    enclaves[eid as usize].state >= enclave_state_FRESH
  }
}

#[no_mangle]
pub extern fn get_enclave_region_index(eid: enclave_id, ty: enclave_region_type) -> c_int
{
  let eid = eid as usize;

  for i in 0..ENCLAVE_REGIONS_MAX {
    if unsafe { enclaves[eid] }.regions[i as usize].type_ == ty {
      return i as c_int;
    }
  }
  // No such region for this enclave
  -1
}

#[no_mangle]
pub extern fn get_enclave_region_size(eid: enclave_id, memid: c_int) -> usize
{
  let eid = eid as usize;

  if 0 <= memid && memid < ENCLAVE_REGIONS_MAX as c_int {
    let size = unsafe {
        pmp_region_get_size(enclaves[eid].regions[memid as usize].pmp_rid)
    };
    // TODO: u64<->usize mismatch
    return size as usize;
  }

  0
}

#[no_mangle]
pub unsafe extern fn get_enclave_region_base(eid: enclave_id, memid: c_int) -> usize
{
  let eid = eid as usize;

  if 0 <= memid && memid < ENCLAVE_REGIONS_MAX as c_int {
    let addr = pmp_region_get_addr(enclaves[eid].regions[memid as usize].pmp_rid);
    // TODO: u64<->usize mismatch
    return addr as usize;
  }

  0
}



#[no_mangle]
pub extern fn attest_enclave(report_ptr: usize, data: usize, size: usize, eid: enclave_id) -> enclave_ret_code 
{
  let eid = eid as usize;

  let mut report = report {
    dev_public_key: [0u8; PUBLIC_KEY_SIZE as usize],
    enclave: enclave_report {
      data: [0u8; 1024],
      data_len: 0,
      hash: [0u8; MDSIZE as usize],
      signature: [0u8; SIGNATURE_SIZE as usize],
    },
    sm: sm_report {
      hash: [0u8; MDSIZE as usize],
      public_key: [0u8; PUBLIC_KEY_SIZE as usize],
      signature: [0u8; SIGNATURE_SIZE as usize],
    },
  };

  if size > ATTEST_DATA_MAXLEN as usize {
    return ENCLAVE_ILLEGAL_ARGUMENT as enclave_ret_code;
  }

  let attestable = unsafe {
    enclave_lock();
    let attestable = enclaves[eid].state >= enclave_state_INITIALIZED;
    enclave_unlock();
    attestable
  };

  if !attestable {
    return ENCLAVE_NOT_INITIALIZED as enclave_ret_code;
  }

  /* copy data to be signed */
  let dst_data_ptr = report.enclave.data.as_mut_ptr() as *mut c_void;
  let src_data_ptr = data as *mut c_void;

  let ret = unsafe {
    copy_from_enclave(&mut enclaves[eid],
      dst_data_ptr,
      src_data_ptr,
      size)
  };
  report.enclave.data_len = size as u64;

  if ret != 0 {
    return ret;
  }

  unsafe {
    report.dev_public_key = sm::dev_public_key;
    report.sm.hash = sm::sm_hash;
    report.sm.public_key = sm::sm_public_key;
    report.sm.signature = sm::sm_signature;
    report.enclave.hash = enclaves[eid].hash;
    //memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  }

  unsafe {
    let enclave = &report.enclave as *const enclave_report as *const u8;
    let enclave_slice = slice::from_raw_parts(enclave, size_of::<enclave_report>());
    let enclave_slice = &enclave_slice[..enclave_slice.len() - SIGNATURE_SIZE as usize];
    let enclave_slice = &enclave_slice[..enclave_slice.len() - (ATTEST_DATA_MAXLEN as usize) + size];

    sm::sm_sign(&mut report.enclave.signature, enclave_slice);
  }

  /* copy report to the enclave */
  let dst_report_ptr = report_ptr as *mut c_void;
  let src_report_ptr = &mut report as *mut report as *mut c_void;

  let ret = unsafe {
    copy_to_enclave(&mut enclaves[eid],
      dst_report_ptr,
      src_report_ptr,
      size_of::<report>())
  };

  if ret != 0 {
    return ret;
  }

  return ENCLAVE_SUCCESS as enclave_ret_code;
}


#[no_mangle]
pub extern fn run_enclave(host_regs: *mut usize, eid: enclave_id) -> enclave_ret_code 
{
  let runnable = unsafe {
      enclave_lock();
      
      enclave_exists(eid)
          && enclaves[eid as usize].n_thread < MAX_ENCL_THREADS
  };

  unsafe {
      if runnable {
        enclaves[eid as usize].state = enclave_state_RUNNING;
        enclaves[eid as usize].n_thread += 1;
      }
      enclave_unlock();
  }

  if !runnable {
    return ENCLAVE_NOT_RUNNABLE as enclave_ret_code;
  }

  // Enclave is OK to run, context switch to it
  unsafe {
      context_switch_to_enclave(host_regs, eid as u32, 1)
  }
}

#[no_mangle]
pub extern fn exit_enclave(encl_regs: *mut usize, retval: c_ulong, eid: enclave_id) -> enclave_ret_code
{
  let eid = eid as usize;

  let exitable = unsafe {
    enclave_lock();
    let out = enclaves[eid].state == enclave_state_RUNNING;
    enclave_unlock();
    out
  };

  if !exitable {
    return ENCLAVE_NOT_RUNNING as enclave_ret_code;
  }

  unsafe {
    context_switch_to_host(encl_regs, eid as u32);
  }

  // update enclave state
  unsafe {
      enclave_lock();
      enclaves[eid].n_thread -= 1;
      if enclaves[eid].n_thread == 0 {
        enclaves[eid].state = enclave_state_INITIALIZED;
      }
      enclave_unlock();
  }

  return ENCLAVE_SUCCESS as enclave_ret_code;
}

#[no_mangle]
pub extern fn stop_enclave(encl_regs: *mut usize, request: u64, eid: enclave_id) -> enclave_ret_code
{
  let eid = eid as usize;

  let stoppable = unsafe {
      enclave_lock();
      let out = enclaves[eid].state == enclave_state_RUNNING;
      enclave_unlock();
      out
  };

  if !stoppable {
    return ENCLAVE_NOT_RUNNING as enclave_ret_code;
  }

  unsafe {
    context_switch_to_host(encl_regs, eid as u32);
  }

  match request {
      n if n == STOP_TIMER_INTERRUPT as u64 =>
          ENCLAVE_INTERRUPTED as enclave_ret_code,
      n if n == STOP_EDGE_CALL_HOST as u64 =>
          ENCLAVE_EDGE_CALL_HOST as enclave_ret_code,
      _ =>
          ENCLAVE_UNKNOWN_ERROR as enclave_ret_code
  }
}

#[no_mangle]
pub extern fn resume_enclave(host_regs: *mut usize, eid: enclave_id) -> enclave_ret_code
{
  let eid = eid as usize;

  let resumable = unsafe {
      enclave_lock();
      let out = enclaves[eid].state == enclave_state_RUNNING // not necessary?
               && enclaves[eid].n_thread > 0; // not necessary
      enclave_unlock();
      out
  };

  if !resumable {
    return ENCLAVE_NOT_RESUMABLE as enclave_ret_code;
  }

  // Enclave is OK to resume, context switch to it
  return unsafe {
      context_switch_to_enclave(host_regs, eid as u32, 0)
  }
}

