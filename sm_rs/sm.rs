//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

use crate::bindings::*;
use spin::RwLock;
use util::ctypes::*;

use crate::crypto;
use crate::enclave;
use crate::pmp;

pub(crate) struct InitData {
    sm_region: pmp::PmpRegion,
    os_region: pmp::PmpRegion,

    pub(crate) sm_hash: [u8; crypto::HASH_SIZE],
    pub(crate) sm_signature: [u8; crypto::SIGNATURE_SIZE],
    pub(crate) sm_public_key: [u8; crypto::PUBKEY_SIZE],
    pub(crate) dev_public_key: [u8; crypto::PUBKEY_SIZE],
    sm_private_key: [u8; crypto::PRIVKEY_SIZE],
}

pub(crate) static INIT_DATA: RwLock<Option<InitData>> = RwLock::new(None);

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

pub type Signature = [u8; crypto::SIGNATURE_SIZE];

pub fn sign(signature: &mut Signature, data: &[u8]) {
    let init_data = INIT_DATA.read();
    let init_data = init_data.as_ref()
        .expect("[SM] Tried to sign before initialization!");

    crypto::sign_bytes(signature, data, &init_data.sm_public_key, &init_data.sm_private_key);
}

fn copy_keys(init_data: &mut InitData) {
    /* from Sanctum BootROM */
    extern "C" {
        static mut sanctum_sm_hash: [u8; crypto::HASH_SIZE];
        static mut sanctum_sm_signature: [u8; crypto::SIGNATURE_SIZE];
        static mut sanctum_sm_secret_key: [u8; crypto::PRIVKEY_SIZE];
        static mut sanctum_sm_public_key: [u8; crypto::PUBKEY_SIZE];
        static mut sanctum_dev_public_key: [u8; crypto::PUBKEY_SIZE];
    }

    unsafe {
        init_data.sm_hash = sanctum_sm_hash;
        init_data.sm_signature = sanctum_sm_signature;
        init_data.sm_public_key = sanctum_sm_public_key;
        init_data.sm_private_key = sanctum_sm_secret_key;
        init_data.dev_public_key = sanctum_dev_public_key;
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
            dev_public_key: [0; crypto::PUBKEY_SIZE],
            sm_public_key: [0; crypto::PUBKEY_SIZE],
            sm_private_key: [0; crypto::PRIVKEY_SIZE],
            sm_signature: [0; crypto::SIGNATURE_SIZE],
            sm_hash: [0; crypto::HASH_SIZE],
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

    // Copy the keypair from the root of trust
    copy_keys(init_inner);

    // for debug
    // sm_print_cert();
}
