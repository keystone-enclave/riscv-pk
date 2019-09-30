use core::mem::size_of;
use core::slice;

use util::ctypes::*;
use crate::bindings::*;
use crate::sm;



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
