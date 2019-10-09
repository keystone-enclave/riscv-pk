use core::mem::{forget, size_of, zeroed};
use core::slice;

use riscv::register as csr;

use util::ctypes::*;
use util::insert_field;
use crate::bindings::*;
use crate::cpu;
use crate::sm;

const SATP_MODE_CHOICE: usize = insert_field!(0, SATP64_MODE as usize, SATP_MODE_SV39 as usize);


/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/


/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
#[no_mangle]
pub unsafe extern fn context_switch_to_enclave(regs: *mut [usize; 32],
                                               eid: enclave_id,
                                               load_parameters: c_int) -> enclave_ret_code
{
  let enclave = unsafe { &mut enclaves[eid as usize] };
  let regs = &mut (*regs)[..]; 

  /* save host context */
  swap_prev_state(&mut enclave.threads[0], regs.as_mut_ptr());
  swap_prev_mepc(&mut enclave.threads[0], csr::mepc::read());

  if load_parameters != 0 {
    // passing parameters for a first run
    // $mepc: (VA) kernel entry
    csr::mepc::write(enclave.params.runtime_entry);
    // $sepc: (VA) user entry
    csr::sepc::write(enclave.params.user_entry);
    // $a1: (PA) DRAM base,
    regs[11] = enclave.pa_params.dram_base;
    // $a2: (PA) DRAM size,
    regs[12] = enclave.pa_params.dram_size;
    // $a3: (PA) kernel location,
    regs[13] = enclave.pa_params.runtime_base;
    // $a4: (PA) user location,
    regs[14] = enclave.pa_params.user_base;
    // $a5: (PA) freemem location,
    regs[15] = enclave.pa_params.free_base;
    // $a6: (VA) utm base,
    regs[16] = enclave.params.untrusted_ptr;
    // $a7: (size_t) utm size
    regs[17] = enclave.params.untrusted_size;

    // switch to the initial enclave page table
    csr::satp::write(enclave.encl_satp);
  }

  // disable timer set by the OS
  csr::mie::clear_mtimer();

  // Clear pending interrupts
  csr::mip::clear_mtimer();
  csr::mip::clear_stimer();
  csr::mip::clear_ssoft();
  csr::mip::clear_sext();

  // set PMP
  osm_pmp_set(PMP_NO_PERM as u8);
  for region in enclave.regions.iter() {
    if region.type_ != enclave_region_type_REGION_INVALID {
      pmp_set(region.pmp_rid, PMP_ALL_PERM as u8);
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(enclave);
  cpu::cpu_enter_enclave_context(eid as i32);
  return ENCLAVE_SUCCESS as enclave_ret_code;
}


#[no_mangle]
pub unsafe extern fn context_switch_to_host(encl_regs: *mut usize,
    eid: enclave_id)
{
  let enclave = unsafe { &mut enclaves[eid as usize] };
  // set PMP
  for region in enclave.regions.iter() {
    if region.type_ != enclave_region_type_REGION_INVALID {
      pmp_set(region.pmp_rid, PMP_NO_PERM as u8);
    }
  }
  osm_pmp_set(PMP_ALL_PERM as u8);

  /* restore host context */
  swap_prev_state(&mut enclave.threads[0], encl_regs);
  swap_prev_mepc(&mut enclave.threads[0], csr::mepc::read());

  // enable timer interrupt
  csr::mie::set_mtimer();

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(enclave);

  cpu::exit_enclave_context();
  return;
}





fn enclave_exists(eid: enclave_id) -> bool {
  unsafe {
    enclaves[eid as usize].state >= enclave_state_FRESH
  }
}


unsafe fn clean_enclave_memory(utbase: usize, utsize: usize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  (utbase as *mut c_void).write_bytes(0, utsize);
}


/* Ensures that dest ptr is in host, not in enclave regions
 */
unsafe fn copy_word_to_host(dest_ptr: *mut usize, value: usize) -> enclave_ret_code 
{
  enclave_lock();
  let region_overlap = pmp_detect_region_overlap_atomic(dest_ptr as usize,
                                                        size_of::<usize>());
  if region_overlap == 0 {
    *dest_ptr = value;
  }
  enclave_unlock();

  if region_overlap != 0 {
    ENCLAVE_REGION_OVERLAPS as enclave_ret_code
  } else {
    ENCLAVE_SUCCESS as enclave_ret_code
  }
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
#[no_mangle]
pub unsafe extern fn copy_from_host(source: *mut c_void, dest: *mut c_void, size: usize) -> enclave_ret_code
{
  enclave_lock();
  let region_overlap = pmp_detect_region_overlap_atomic(source as usize, size);
  // TODO: Validate that dest is inside the SM.
  if region_overlap == 0 {
    dest.copy_from_nonoverlapping(source, size);
  }
  enclave_unlock();

  if region_overlap != 0 {
    ENCLAVE_REGION_OVERLAPS as enclave_ret_code
  } else {
    ENCLAVE_SUCCESS as enclave_ret_code
  }
}

/* copies data from enclave, source must be inside EPM */
unsafe fn copy_from_enclave(enclave: &enclave, dest: *mut c_void, source: *const c_void, size: usize) -> enclave_ret_code
{
  enclave_lock();
  let legal = buffer_in_enclave_region(&*enclave, source, size);

  if legal {
    dest.copy_from_nonoverlapping(source, size);
  }
  enclave_unlock();

  if !legal {
    ENCLAVE_ILLEGAL_ARGUMENT as enclave_ret_code
  } else {
    ENCLAVE_SUCCESS as enclave_ret_code
  }
}

/* copies data into enclave, destination must be inside EPM */
unsafe fn copy_to_enclave(enclave: &enclave, dest: *mut c_void, source: *const c_void, size: usize) -> enclave_ret_code
{
  enclave_lock();
  let legal = buffer_in_enclave_region(enclave, dest, size);

  if legal {
    dest.copy_from_nonoverlapping(source, size);
  }
  enclave_unlock();

  if !legal {
    ENCLAVE_ILLEGAL_ARGUMENT as enclave_ret_code
  } else {
    ENCLAVE_SUCCESS as enclave_ret_code
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


fn is_create_args_valid(args: &keystone_sbi_create) -> bool
{
  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if args.epm_region.size <= 0 {
    return false;
  }

  // check if overflow
  if args.epm_region.paddr >=
      args.epm_region.paddr + args.epm_region.size {
    return false;
  }
  if args.utm_region.paddr >=
      args.utm_region.paddr + args.utm_region.size {
    return false;
  }

  let epm_start = args.epm_region.paddr;
  let epm_end = args.epm_region.paddr + args.epm_region.size;

  // check if physical addresses are in the range
  if args.runtime_paddr < epm_start ||
      args.runtime_paddr >= epm_end {
    return false;
  }
  if args.user_paddr < epm_start ||
      args.user_paddr >= epm_end {
    return false;
  }
  if args.free_paddr < epm_start ||
      args.free_paddr > epm_end {
      // note: free_paddr == epm_end if there's no free memory
    return false;
  }

  // check the order of physical addresses
  if args.runtime_paddr > args.user_paddr {
    return false;
  }
  if args.user_paddr > args.free_paddr {
    return false;
  }

  true
}



fn buffer_in_enclave_region(enclave: &enclave, start: *const c_void, size: usize) -> bool
{
  let start = start as usize;
  let end = start + size;

  let mut regions_iter = enclave.regions.iter()
      .filter(|r| r.type_ != enclave_region_type_REGION_INVALID)
      .filter(|r| r.type_ != enclave_region_type_REGION_UTM);

  /* Check if the source is in a valid region */
  for region in regions_iter {
    let region_start = unsafe { pmp_region_get_addr(region.pmp_rid) };
    let region_size = unsafe { pmp_region_get_size(region.pmp_rid) } as usize;
    let region_end = region_start + region_size;

    if start >= region_start && end <= region_end {
      return true
    }
  }
  false
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

// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
#[no_mangle]
pub unsafe extern fn enclave_init_metadata()
{
  /* Assumes eids are incrementing values, which they are for now */
  for enclave in unsafe { enclaves.iter_mut() } {
    enclave.state = enclave_state_INVALID;

    // Clear out regions
    for region in enclave.regions.iter_mut() {
      region.type_ = enclave_region_type_REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(enclave);
  }

}



/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


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



struct PmpRegion {
    region: c_int 
}

impl PmpRegion {
    fn reserve(base: usize, size: usize, prio: pmp_priority) -> Result<Self, c_int> {
        let region = unsafe {
            let mut region = 0;
            let err = pmp_region_init_atomic(base, size as u64, prio, &mut region, 0);
            if err != 0 {
                return Err(err);
            }
            region
        };

        Ok(Self {
            region
        })
    }

    fn leak(self) -> c_int {
        let out = self.region;
        forget(self);
        out
    }

    fn set_global(&mut self, prop: u8) -> Result<(), c_int> {
        let err = unsafe {
            pmp_set_global(self.region, prop)
        };
        if err == 0 { Ok(()) }
        else { Err(err) }
    }
}

impl Drop for PmpRegion {
    fn drop(&mut self) {
      unsafe {
          pmp_region_free_atomic(self.region);
      }
    }
}


fn encl_alloc_eid() -> Result<enclave_id, enclave_ret_code>
{
  unsafe {
      enclave_lock();

      let found = enclaves.iter_mut()
          .enumerate()
          .find(|(_, enc)| enc.state < 0);

      let ret = if let Some((eid, enclave)) = found {
        enclave.state = enclave_state_ALLOCATED;
        Ok(eid as enclave_id)
      } else {
        Err(ENCLAVE_NO_FREE_RESOURCE as enclave_ret_code)
      };

      enclave_unlock();
      ret
  }
}

fn encl_free_eid(eid: enclave_id) -> enclave_ret_code
{
  unsafe {
    enclave_lock();
    enclaves[eid as usize].state = enclave_state_DESTROYED;
    enclave_unlock();
  }
  ENCLAVE_SUCCESS as enclave_ret_code
}

struct Eid {
    eid: enclave_id
}

impl Eid {
    fn reserve() -> Result<Eid, usize> {
        Ok(Self {
            eid: encl_alloc_eid()?
        })
    }

    fn leak(self) -> enclave_id {
        let out = self.eid;
        forget(self);
        out
    }
}

impl Drop for Eid {
    fn drop(&mut self) {
        encl_free_eid(self.eid);
    }
}

/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
#[no_mangle]
pub unsafe extern fn create_enclave(create_args: keystone_sbi_create) -> enclave_ret_code
{
  /* EPM and UTM parameters */
  let base = create_args.epm_region.paddr;
  let size = create_args.epm_region.size;
  let utbase = create_args.utm_region.paddr;
  let utsize = create_args.utm_region.size;
  let eidptr = create_args.eid_pptr as *mut usize;

  /* Runtime parameters */
  if !is_create_args_valid(&create_args) {
    return ENCLAVE_ILLEGAL_ARGUMENT as enclave_ret_code;
  }

  /* set va params */
  let params = create_args.params;
  let pa_params = runtime_pa_params {
    dram_base: base,
    dram_size: size,
    runtime_base: create_args.runtime_paddr,
    user_base: create_args.user_paddr,
    free_base: create_args.free_paddr,
  };


  // allocate eid
  let eid_reservation = Eid::reserve();
  let eid_reservation = if let Ok(e) = eid_reservation { e }
                        else { return ENCLAVE_NO_FREE_RESOURCE as enclave_ret_code };
  let eid = eid_reservation.eid as usize;

  // create a PMP region bound to the enclave
  let ret = ENCLAVE_PMP_FAILURE as enclave_ret_code;
  let region = PmpRegion::reserve(base, size, pmp_priority_PMP_PRI_ANY);
  let mut region = if let Ok(r) = region { r }
                   else { return ret };

  // create PMP region for shared memory
  let shared_region = PmpRegion::reserve(utbase, utsize, pmp_priority_PMP_PRI_BOTTOM);
  let shared_region = if let Ok(r) = shared_region { r }
                      else { return ret };

  // set pmp registers for private region (not shared)
  if let Err(_) = region.set_global(PMP_NO_PERM as u8) {
    return ret
  }

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);

  // initialize enclave metadata
  let mut enc = enclave {
      eid: eid as u32,

      regions: [
        enclave_region {
          pmp_rid: zeroed(),
          type_: 0
        };
        ENCLAVE_REGIONS_MAX as usize
      ],

      hash: zeroed(),
      ped: zeroed(),
      threads: zeroed(),
      sign: zeroed(),
      state: enclave_state_INVALID,

      encl_satp: ((base >> RISCV_PGSHIFT) | SATP_MODE_CHOICE),
      n_thread: 0,
      params: params,
      pa_params: pa_params,
  };

  enc.regions[0].pmp_rid = region.leak();
  enc.regions[0].type_ = enclave_region_type_REGION_EPM;
  enc.regions[1].pmp_rid = shared_region.leak();
  enc.regions[1].type_ = enclave_region_type_REGION_UTM;

  /* Init enclave state (regs etc) */
  clean_state(&mut enc.threads[0]);

  unsafe {
    enclaves[eid] = enc;
  }

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  let ret = platform_create_enclave(&mut enclaves[eid]);
  if ret != ENCLAVE_SUCCESS as usize {
    return ret;
  }

  /* Validate memory, prepare hash and signature for attestation */
  enclave_lock();
  enclaves[eid].state = enclave_state_FRESH;
  let ret = validate_and_hash_enclave(&mut enclaves[eid]);
  enclave_unlock();

  if ret != ENCLAVE_SUCCESS as usize {
      platform_destroy_enclave(&mut enclaves[eid]);
  }

  /* EIDs are unsigned int in size, copy via simple copy */
  copy_word_to_host(eidptr, eid);

  eid_reservation.leak();
  return ENCLAVE_SUCCESS as enclave_ret_code;
}



#[no_mangle]
pub extern fn run_enclave(host_regs: *mut [usize; 32], eid: enclave_id) -> enclave_ret_code 
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
pub extern fn resume_enclave(host_regs: *mut [usize; 32], eid: enclave_id) -> enclave_ret_code
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


/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
#[no_mangle]
pub unsafe extern fn destroy_enclave(eid: enclave_id) -> enclave_ret_code
{
  let enclave = unsafe {
    &mut enclaves[eid as usize]
  };

  enclave_lock();
  let destroyable = enclave_exists(eid)
                 && enclave.state != enclave_state_ALLOCATED;
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if destroyable {
    enclave.state = enclave_state_DESTROYED;
  }
  enclave_unlock();

  if !destroyable {
    return ENCLAVE_NOT_DESTROYABLE as enclave_ret_code;
  }


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(enclave);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  let mut regions_iter = enclave.regions.iter()
      /* Check if the source is in a valid region */
      .filter(|r| r.type_ != enclave_region_type_REGION_INVALID)
      .filter(|r| r.type_ != enclave_region_type_REGION_UTM);

  for region in regions_iter {
    //1.a Clear all pages
    let rid = region.pmp_rid;
    let base = pmp_region_get_addr(rid);
    let size = pmp_region_get_size(rid) as usize;
    clean_enclave_memory(base, size);

    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  let rid = get_enclave_region_index(eid, enclave_region_type_REGION_UTM);
  if rid != -1 {
    pmp_region_free_atomic(enclave.regions[rid as usize].pmp_rid);
  }

  enclave.encl_satp = 0;
  enclave.n_thread = 0;
  enclave.params = zeroed();
  enclave.pa_params = zeroed();
  for region in enclave.regions.iter_mut() {
    region.type_ = enclave_region_type_REGION_INVALID;
  }

  // 3. release eid
  encl_free_eid(eid);

  ENCLAVE_SUCCESS as enclave_ret_code
}

