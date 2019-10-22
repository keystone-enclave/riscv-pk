use core::mem::{forget, size_of, zeroed};
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};

use riscv::register as csr;
use spin::Mutex;

use crate::attest;
use crate::bindings::*;
use crate::cpu;
use crate::pmp;
use crate::sm;
use util::ctypes::*;
use util::insert_field;

macro_rules! encl_unwrap_opt {
    ($what:expr, $ret:expr) => {
        if let Some(val) = $what {
            val
        } else {
            return $ret as enclave_ret_code;
        }
    };
}

// TODO: This really shouldn't be here
const SATP_MODE_CHOICE: usize = insert_field!(0, SATP64_MODE as usize, SATP_MODE_SV39 as usize);

const NUM_ENCL: usize = 16;
static enclaves: Mutex<[Option<Enclave>; NUM_ENCL]> = Mutex::new([
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
]);

static EID_BITMAP: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct EnclaveRegion {
    pub(crate) pmp: pmp::PmpRegion,
    pub(crate) type_: enclave_region_type,
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
enum EnclaveState {
    Fresh,
    Initialized,
    Running,
}

/* enclave metadata */
pub struct Enclave {
    //spinlock_t lock; //local enclave lock. we don't need this until we have multithreaded enclave
    eid: Eid,                      //enclave id
    pub(crate) encl_satp: c_ulong, // enclave's page table base
    state: EnclaveState,           // global state of the enclave

    /* Physical memory regions associate with this enclave */
    pub(crate) regions: [Option<EnclaveRegion>; ENCLAVE_REGIONS_MAX as usize],

    /* measurement */
    pub(crate) hash: [u8; MDSIZE as usize],
    sign: [u8; SIGNATURE_SIZE as usize],

    /* parameters */
    pub(crate) params: runtime_va_params_t,
    pub(crate) pa_params: runtime_pa_params,

    /* enclave execution context */
    n_thread: u32,
    threads: [thread_state; MAX_ENCL_THREADS as usize],

    ped: platform_enclave_data,
}

impl Enclave {
    pub(crate) fn to_ffi(&self) -> *const enclave {
        self as *const Self as *const enclave
    }
    pub(crate) fn to_ffi_mut(&mut self) -> *mut enclave {
        self as *mut Self as *mut enclave
    }
    pub(crate) unsafe fn from_ffi<'a>(enc: *const enclave) -> &'a Self {
        &*(enc as *const Self)
    }
    pub(crate) unsafe fn from_ffi_mut<'a>(enc: *mut enclave) -> &'a mut Self {
        &mut *(enc as *mut Self)
    }

    pub fn region_id_bytype(&self, ty: enclave_region_type) -> Option<usize> {
        self.regions
            .iter()
            .flatten()
            .enumerate()
            .find(|(_, r)| r.type_ == ty)
            .map(|(i, _)| i)
    }

    pub(crate) fn region_bytype(&mut self, ty: enclave_region_type) -> Option<&mut EnclaveRegion> {
        let i = self.region_id_bytype(ty)?;
        self.regions[i].as_mut()
    }
}

/* attestation reports */
#[repr(C)]
struct EnclaveReport {
    hash: [u8; MDSIZE as usize],
    data_len: u64,
    data: [u8; ATTEST_DATA_MAXLEN as usize],
    signature: [u8; SIGNATURE_SIZE as usize],
}

#[repr(C)]
struct SmReport {
    hash: [u8; MDSIZE as usize],
    public_key: [u8; PUBLIC_KEY_SIZE as usize],
    signature: [u8; SIGNATURE_SIZE as usize],
}

#[repr(C)]
struct Report {
    enclave: EnclaveReport,
    sm: SmReport,
    dev_public_key: [u8; PUBLIC_KEY_SIZE as usize],
}

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
pub unsafe extern "C" fn context_switch_to_enclave(
    enclave: &mut Enclave,
    regs: *mut [usize; 32],
    load_parameters: c_int,
) -> enclave_ret_code {
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

    for region in enclave.regions.iter_mut().filter_map(|r| r.as_mut()) {
        region.pmp.set_perm(PMP_ALL_PERM as u8);
    }

    // Setup any platform specific defenses
    platform_switch_to_enclave(enclave.to_ffi_mut());
    cpu::cpu_enter_enclave_context(enclave.eid.eid);
    ENCLAVE_SUCCESS as enclave_ret_code
}

unsafe fn context_switch_to_host(enclave: &mut Enclave, encl_regs: *mut usize) {
    // set PMP
    for region in enclave.regions.iter_mut().filter_map(|r| r.as_mut()) {
        region.pmp.set_perm(PMP_NO_PERM as u8);
    }
    osm_pmp_set(PMP_ALL_PERM as u8);

    /* restore host context */
    swap_prev_state(&mut enclave.threads[0], encl_regs);
    swap_prev_mepc(&mut enclave.threads[0], csr::mepc::read());

    // enable timer interrupt
    csr::mie::set_mtimer();

    // Reconfigure platform specific defenses
    platform_switch_from_enclave(enclave.to_ffi_mut());
    cpu::exit_enclave_context();
}

unsafe fn clean_enclave_memory(utbase: usize, utsize: usize) {
    // This function is quite temporary. See issue #38

    // Zero out the untrusted memory region, since it may be in
    // indeterminate state.
    (utbase as *mut c_void).write_bytes(0, utsize);
}

/* Ensures that dest ptr is in host, not in enclave regions
 */
unsafe fn copy_word_to_host(
    _enclave: &mut Enclave,
    dest_ptr: *mut usize,
    value: usize,
) -> Result<(), enclave_ret_code> {
    // lock here for functional safety
    let region_overlap = pmp::detect_region_overlap(dest_ptr as usize, size_of::<usize>());
    if region_overlap {
        return Err(ENCLAVE_REGION_OVERLAPS as enclave_ret_code);
    }

    *dest_ptr = value;
    Ok(())
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
#[no_mangle]
pub unsafe extern "C" fn copy_from_host(
    source: *mut c_void,
    dest: *mut c_void,
    size: usize,
) -> enclave_ret_code {
    // lock here for functional safety
    let _ = enclaves.lock();

    let region_overlap = pmp::detect_region_overlap(source as usize, size);
    if region_overlap {
        return ENCLAVE_REGION_OVERLAPS as enclave_ret_code;
    }

    // TODO: Validate that dest is inside the SM.
    dest.copy_from_nonoverlapping(source, size);
    ENCLAVE_SUCCESS as enclave_ret_code
}

/* copies data from enclave, source must be inside EPM */
unsafe fn copy_from_enclave(
    enclave: &Enclave,
    dest: *mut c_void,
    source: *const c_void,
    size: usize,
) -> enclave_ret_code {
    let legal = buffer_in_enclave_region(&*enclave, source, size);
    if !legal {
        return ENCLAVE_ILLEGAL_ARGUMENT as enclave_ret_code;
    }

    dest.copy_from_nonoverlapping(source, size);
    ENCLAVE_SUCCESS as enclave_ret_code
}

/* copies data into enclave, destination must be inside EPM */
unsafe fn copy_to_enclave(
    enclave: &Enclave,
    dest: *mut c_void,
    source: *const c_void,
    size: usize,
) -> enclave_ret_code {
    let legal = buffer_in_enclave_region(enclave, dest, size);
    if !legal {
        return ENCLAVE_ILLEGAL_ARGUMENT as enclave_ret_code;
    }

    dest.copy_from_nonoverlapping(source, size);
    ENCLAVE_SUCCESS as enclave_ret_code
}

#[no_mangle]
pub extern "C" fn get_enclave_region_index(
    enclave: *const enclave,
    ty: enclave_region_type,
) -> c_int {
    let enclave = unsafe { Enclave::from_ffi(enclave) };
    enclave.region_id_bytype(ty).unwrap_or(!0) as c_int
}

fn is_create_args_valid(args: &keystone_sbi_create) -> bool {
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
    if args.epm_region.paddr >= args.epm_region.paddr + args.epm_region.size {
        return false;
    }
    if args.utm_region.paddr >= args.utm_region.paddr + args.utm_region.size {
        return false;
    }

    let epm_start = args.epm_region.paddr;
    let epm_end = args.epm_region.paddr + args.epm_region.size;

    // check if physical addresses are in the range
    if args.runtime_paddr < epm_start || args.runtime_paddr >= epm_end {
        return false;
    }
    if args.user_paddr < epm_start || args.user_paddr >= epm_end {
        return false;
    }
    if args.free_paddr < epm_start || args.free_paddr > epm_end {
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

fn buffer_in_enclave_region(enclave: &Enclave, start: *const c_void, size: usize) -> bool {
    let start = start as usize;
    let end = start + size;

    let regions_iter = enclave
        .regions
        .iter()
        .flatten()
        .filter(|r| r.type_ != enclave_region_type_REGION_UTM);

    /* Check if the source is in a valid region */
    for region in regions_iter {
        let region_start = region.pmp.addr();
        let region_size = region.pmp.size();
        let region_end = region_start + region_size;

        if start >= region_start && end <= region_end {
            return true;
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn get_enclave_region_size(eid: enclave_id, memid: c_int) -> usize {
    enclaves.lock()[eid as usize]
        .as_mut()
        .and_then(|e| e.regions.get(memid as usize))
        .and_then(|e| e.as_ref())
        .map(|r| r.pmp.size())
        .unwrap_or(0)
}

#[no_mangle]
pub unsafe extern "C" fn get_enclave_region_base(eid: enclave_id, memid: c_int) -> usize {
    enclaves.lock()[eid as usize]
        .as_mut()
        .and_then(|e| e.regions.get(memid as usize))
        .and_then(|e| e.as_ref())
        .map(|r| r.pmp.addr())
        .unwrap_or(0)
}

/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
// TODO: There's nothing for platform_init_enclave to do with an enclave that hasn't been created yet... refactoring needed
#[no_mangle]
pub extern "C" fn enclave_init_metadata() {
    /*let mut enclave_arr = enclaves.lock();

    /* Assumes eids are incrementing values, which they are for now */
    for enclave in enclave_arr.iter_mut().filter_map(|x|x.as_mut()) {
        /* Fire all platform specific init for each enclave */
        unsafe {
            platform_init_enclave(enclave.to_ffi_mut());
        }
    }*/
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/

#[no_mangle]
pub extern "C" fn attest_enclave(
    report_ptr: usize,
    data: usize,
    size: usize,
    eid: enclave_id,
) -> enclave_ret_code {
    let e_idx = eid as usize;

    let mut report = Report {
        dev_public_key: [0u8; PUBLIC_KEY_SIZE as usize],
        enclave: EnclaveReport {
            data: [0u8; 1024],
            data_len: 0,
            hash: [0u8; MDSIZE as usize],
            signature: [0u8; SIGNATURE_SIZE as usize],
        },
        sm: SmReport {
            hash: [0u8; MDSIZE as usize],
            public_key: [0u8; PUBLIC_KEY_SIZE as usize],
            signature: [0u8; SIGNATURE_SIZE as usize],
        },
    };

    if size > ATTEST_DATA_MAXLEN as usize {
        return ENCLAVE_ILLEGAL_ARGUMENT as enclave_ret_code;
    }

    {
        let mut enclave_arr = enclaves.lock();
        let enclave = encl_unwrap_opt!(enclave_arr[e_idx].as_ref(), ENCLAVE_NOT_INITIALIZED);

        let attestable = enclave.state >= EnclaveState::Initialized;
        if !attestable {
            return ENCLAVE_NOT_INITIALIZED as enclave_ret_code;
        }

        /* copy data to be signed */
        let dst_data_ptr = report.enclave.data.as_mut_ptr() as *mut c_void;
        let src_data_ptr = data as *mut c_void;

        report.enclave.data_len = size as u64;
        report.enclave.hash = enclave.hash;

        unsafe {
            let ret = copy_from_enclave(enclave, dst_data_ptr, src_data_ptr, size);
            if ret != 0 {
                return ret;
            }

            report.dev_public_key = sm::dev_public_key;
            report.sm.hash = sm::sm_hash;
            report.sm.public_key = sm::sm_public_key;
            report.sm.signature = sm::sm_signature;
        };
    }

    unsafe {
        let enclave = &report.enclave as *const EnclaveReport as *const u8;
        let enclave_slice = slice::from_raw_parts(enclave, size_of::<EnclaveReport>());
        let enclave_slice = &enclave_slice[..enclave_slice.len() - SIGNATURE_SIZE as usize];
        let enclave_slice =
            &enclave_slice[..enclave_slice.len() - (ATTEST_DATA_MAXLEN as usize) + size];

        sm::sign(&mut report.enclave.signature, enclave_slice);
    }

    /* copy report to the enclave */
    let dst_report_ptr = report_ptr as *mut c_void;
    let src_report_ptr = &mut report as *mut Report as *mut c_void;

    if let Some(ref mut enclave) = enclaves.lock()[e_idx] {
        let ret = unsafe {
            copy_to_enclave(enclave, dst_report_ptr, src_report_ptr, size_of::<Report>())
        };

        if ret != 0 {
            return ret;
        }
    };

    return ENCLAVE_SUCCESS as enclave_ret_code;
}

fn encl_alloc_eid() -> Result<enclave_id, enclave_ret_code> {
    for i in 0..NUM_ENCL {
        let prev = EID_BITMAP.fetch_or(1 << i, Ordering::SeqCst);
        if prev & (1 << i) == 0 {
            // we succeeded!
            return Ok(i as enclave_id);
        }
    }

    Err(ENCLAVE_NO_FREE_RESOURCE as enclave_ret_code)
}

fn encl_free_eid(eid: enclave_id) {
    EID_BITMAP.fetch_and(!(1 << eid), Ordering::SeqCst);
}

struct Eid {
    eid: enclave_id,
}

impl Eid {
    fn reserve() -> Result<Eid, usize> {
        Ok(Self {
            eid: encl_alloc_eid()?,
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
pub extern "C" fn create_enclave(create_args: keystone_sbi_create) -> enclave_ret_code {
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
    let eid_reservation = if let Ok(e) = eid_reservation {
        e
    } else {
        return ENCLAVE_NO_FREE_RESOURCE as enclave_ret_code;
    };
    let eid = eid_reservation.eid as usize;

    // create a PMP region bound to the enclave
    let ret = ENCLAVE_PMP_FAILURE as enclave_ret_code;
    let region = pmp::PmpRegion::reserve(base, size, pmp::Priority::Any);
    let mut region = if let Ok(r) = region { r } else { return ret };

    // create PMP region for shared memory
    let shared_region = pmp::PmpRegion::reserve(utbase, utsize, pmp::Priority::Bottom);
    let shared_region = if let Ok(r) = shared_region {
        r
    } else {
        return ret;
    };

    // set pmp registers for private region (not shared)
    if let Err(_) = region.set_global(PMP_NO_PERM as u8) {
        return ret;
    }

    // cleanup some memory regions for sanity See issue #38
    unsafe {
        clean_enclave_memory(utbase, utsize);
    }

    // initialize enclave metadata
    let mut enc = Enclave {
        eid: eid_reservation,

        regions: Default::default(),

        hash: [0u8; MDSIZE as usize],
        ped: unsafe { zeroed() },
        threads: unsafe { zeroed() },
        sign: [0u8; SIGNATURE_SIZE as usize],
        state: EnclaveState::Fresh,

        encl_satp: ((base >> RISCV_PGSHIFT) | SATP_MODE_CHOICE),
        n_thread: 0,
        params: params,
        pa_params: pa_params,
    };

    enc.regions[0] = Some(EnclaveRegion {
        pmp: region,
        type_: enclave_region_type_REGION_EPM,
    });
    enc.regions[1] = Some(EnclaveRegion {
        pmp: shared_region,
        type_: enclave_region_type_REGION_UTM,
    });

    unsafe {
        /* Init enclave state (regs etc) */
        clean_state(&mut enc.threads[0]);

        /* Platform create happens as the last thing before hashing/etc since
        it may modify the enclave struct */
        let ret = platform_create_enclave(enc.to_ffi_mut());
        if ret != ENCLAVE_SUCCESS as usize {
            return ret;
        }
    }

    /* Validate memory, prepare hash and signature for attestation */
    let ret = attest::validate_and_hash_enclave(&mut enc);

    if ret != ENCLAVE_SUCCESS as usize {
        unsafe {
            platform_destroy_enclave(enc.to_ffi_mut());
        }
        return ret;
    }

    /* EIDs are unsigned int in size, copy via simple copy */
    unsafe {
        let ret = copy_word_to_host(&mut enc, eidptr, eid);
        if let Err(ret) = ret {
            return ret as enclave_ret_code;
        }
    }

    let mut enclave_arr = enclaves.lock();
    enclave_arr[eid] = Some(enc);

    ENCLAVE_SUCCESS as enclave_ret_code
}

#[no_mangle]
pub extern "C" fn run_enclave(host_regs: *mut [usize; 32], eid: enclave_id) -> enclave_ret_code {
    let mut enclave_arr = enclaves.lock();
    let enclave = encl_unwrap_opt!(enclave_arr[eid as usize].as_mut(), ENCLAVE_NOT_RUNNING);

    let runnable = enclave.n_thread < MAX_ENCL_THREADS;
    if !runnable {
        return ENCLAVE_NOT_RUNNABLE as enclave_ret_code;
    }

    enclave.state = EnclaveState::Running;
    enclave.n_thread += 1;

    // Enclave is OK to run, context switch to it
    unsafe { context_switch_to_enclave(enclave, host_regs, 1) }
}

#[no_mangle]
pub extern "C" fn exit_enclave(
    encl_regs: *mut usize,
    retval: c_ulong,
    eid: enclave_id,
) -> enclave_ret_code {
    let mut enclave_arr = enclaves.lock();
    let enclave = encl_unwrap_opt!(enclave_arr[eid as usize].as_mut(), ENCLAVE_NOT_RUNNING);

    let exitable = enclave.state == EnclaveState::Running;
    if !exitable {
        return ENCLAVE_NOT_RUNNING as enclave_ret_code;
    }

    unsafe {
        context_switch_to_host(enclave, encl_regs);
    }

    // update enclave state
    enclave.n_thread -= 1;
    if enclave.n_thread == 0 {
        enclave.state = EnclaveState::Initialized;
    }

    return ENCLAVE_SUCCESS as enclave_ret_code;
}

#[no_mangle]
pub extern "C" fn stop_enclave(
    encl_regs: *mut usize,
    request: u64,
    eid: enclave_id,
) -> enclave_ret_code {
    let mut enclave_arr = enclaves.lock();
    let enclave = encl_unwrap_opt!(enclave_arr[eid as usize].as_mut(), ENCLAVE_NOT_RUNNING);

    let stoppable = enclave.state == EnclaveState::Running;
    if !stoppable {
        return ENCLAVE_NOT_RUNNING as enclave_ret_code;
    }

    unsafe {
        context_switch_to_host(enclave, encl_regs);
    }

    match request {
        n if n == STOP_TIMER_INTERRUPT as u64 => ENCLAVE_INTERRUPTED as enclave_ret_code,
        n if n == STOP_EDGE_CALL_HOST as u64 => ENCLAVE_EDGE_CALL_HOST as enclave_ret_code,
        _ => ENCLAVE_UNKNOWN_ERROR as enclave_ret_code,
    }
}

#[no_mangle]
pub extern "C" fn resume_enclave(host_regs: *mut [usize; 32], eid: enclave_id) -> enclave_ret_code {
    enclaves
        .lock()
        .get_mut(eid as usize)
        .and_then(|e| e.as_mut())
        .filter(|enc| enc.state == EnclaveState::Running && enc.n_thread > 0)
        .map(|enc| unsafe { context_switch_to_enclave(enc, host_regs, 0) })
        .unwrap_or(ENCLAVE_NOT_RESUMABLE as enclave_ret_code)
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
#[no_mangle]
pub extern "C" fn destroy_enclave(eid: enclave_id) -> enclave_ret_code {
    let mut enclave_arr = enclaves.lock();
    let mut enclave = encl_unwrap_opt!(enclave_arr[eid as usize].take(), ENCLAVE_NOT_DESTROYABLE);

    // 0. Let the platform specifics do cleanup/modifications
    unsafe {
        platform_destroy_enclave(enclave.to_ffi_mut());
    }

    // 1. clear all the data in the enclave pages
    for region in enclave.regions.iter_mut().flatten() {
        if region.type_ == enclave_region_type_REGION_UTM {
            continue;
        }

        //1.a Clear all pages
        let base = region.pmp.addr();
        let size = region.pmp.size();
        unsafe {
            clean_enclave_memory(base, size);
        }

        //1.b free pmp region
        region.pmp.unset_global();
    }

    ENCLAVE_SUCCESS as enclave_ret_code
}
