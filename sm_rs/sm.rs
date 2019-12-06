//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

use crate::bindings::*;
use spin::RwLock;
use util::ctypes::*;

use crate::crypto;
use crate::pmp;

struct InitData {
    sm_region: pmp::PmpRegion,
    os_region: pmp::PmpRegion,
}

static INIT_DATA: RwLock<Option<InitData>> = RwLock::new(None);

/* from Sanctum BootROM */
extern "C" {
    static mut sanctum_sm_hash: [u8; MDSIZE as usize];
    static mut sanctum_sm_signature: [u8; SIGNATURE_SIZE as usize];
    static mut sanctum_sm_secret_key: [u8; PRIVATE_KEY_SIZE as usize];
    static mut sanctum_sm_public_key: [u8; PUBLIC_KEY_SIZE as usize];
    static mut sanctum_dev_public_key: [u8; PUBLIC_KEY_SIZE as usize];
}

#[no_mangle]
pub static mut sm_hash: [u8; MDSIZE as usize] = [0; MDSIZE as usize];
#[no_mangle]
pub static mut sm_signature: [u8; SIGNATURE_SIZE as usize] = [0; SIGNATURE_SIZE as usize];
#[no_mangle]
pub static mut sm_public_key: [u8; PUBLIC_KEY_SIZE as usize] = [0; PUBLIC_KEY_SIZE as usize];
#[no_mangle]
pub static mut sm_private_key: [u8; PRIVATE_KEY_SIZE as usize] = [0; PRIVATE_KEY_SIZE as usize];
#[no_mangle]
pub static mut dev_public_key: [u8; PUBLIC_KEY_SIZE as usize] = [0; PUBLIC_KEY_SIZE as usize];

#[no_mangle]
pub extern "C" fn osm_pmp_set(perm: u8) -> c_int {
    /* in case of OSM, PMP cfg is exactly the opposite.*/
    let mut init_data = INIT_DATA.write();
    let init_data = init_data
        .as_mut()
        .expect("[SM] Tried to set OSM PMP permission before initialization!");

    init_data.os_region.set_perm(perm).err().unwrap_or(0)
}

fn smm_init() -> Result<pmp::PmpRegion, c_int> {
    pmp::PmpRegion::reserve(
        SMM_BASE as usize,
        SMM_SIZE as usize,
        pmp::Priority::Top,
        false,
    )
}

fn osm_init() -> Result<pmp::PmpRegion, c_int> {
    pmp::PmpRegion::reserve(0, !0, pmp::Priority::Bottom, true)
}

pub type Signature = [u8; SIGNATURE_SIZE as usize];

pub fn sign(signature: &mut Signature, data: &[u8]) {
    unsafe {
        crypto::sign_bytes(signature, data, &sm_public_key, &sm_private_key);
    }
}

fn sm_copy_key() {
    unsafe {
        sm_hash = sanctum_sm_hash;
        sm_signature = sanctum_sm_signature;
        sm_public_key = sanctum_sm_public_key;
        sm_private_key = sanctum_sm_secret_key;
        dev_public_key = sanctum_dev_public_key;
    }
}

/*
void sm_print_cert()
{
    int i;

    printm("Booting from Security Monitor\n");
    printm("Size: %d\n", sanctum_sm_size[0]);

    printm("============ PUBKEY =============\n");
    for(i=0; i<8; i+=1)
    {
        printm("%x",*((int*)sanctum_dev_public_key+i));
        if(i%4==3) printm("\n");
    }
    printm("=================================\n");

    printm("=========== SIGNATURE ===========\n");
    for(i=0; i<16; i+=1)
    {
        printm("%x",*((int*)sanctum_sm_signature+i));
        if(i%4==3) printm("\n");
    }
    printm("=================================\n");
}
*/

#[no_mangle]
pub extern "C" fn sm_init() {
    // initialize SMM

    let mut init_data = INIT_DATA.write();

    let init_inner = init_data.get_or_insert_with(|| {
        let sm_region =
            smm_init().expect("[SM] intolerable error - failed to initialize SM memory");

        let os_region =
            osm_init().expect("[SM] intolerable error - failed to initialize OS memory");

        if unsafe { platform_init_global_once() } != ENCLAVE_SUCCESS as usize {
            panic!("[SM] platform global init fatal error");
        }

        InitData {
            sm_region,
            os_region,
        }
    });

    init_inner
        .sm_region
        .set_perm(PMP_NO_PERM as u8)
        .expect("[SM] PMP set permission failed for SM region");
    init_inner
        .os_region
        .set_perm(PMP_ALL_PERM as u8)
        .expect("[SM] PMP set permission failed for OS region");

    /* Fire platform specific global init */
    if unsafe { platform_init_global() } != ENCLAVE_SUCCESS as usize {
        panic!("[SM] platform global init fatal error");
    }

    unsafe {
        // Copy the keypair from the root of trust
        sm_copy_key();

        // Init the enclave metadata
        enclave_init_metadata();
    }

    // for debug
    // sm_print_cert();
}
