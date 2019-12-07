//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------

use spin::RwLock;
use util::ctypes::*;
use crate::bindings::*;

use crate::crypto;
use crate::pmp;

struct InitData {
  init_done: bool,
  sm_region_id: region_id,
  os_region_id: region_id,
}

impl InitData {
  const fn new() -> Self {
    Self {
      init_done: false,
      sm_region_id: 0,
      os_region_id: 0
    }
  }
}

static INIT_DATA: RwLock<InitData> = RwLock::new(InitData::new());

/* from Sanctum BootROM */
extern {
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
pub extern fn osm_pmp_set(perm: u8) -> c_int
{
  /* in case of OSM, PMP cfg is exactly the opposite.*/
  let init_data = INIT_DATA.read();
  return unsafe {
      pmp_set(init_data.os_region_id, perm)
  };
}

pub fn smm_init() -> c_int
{
  let region = pmp::PmpRegion::reserve(SMM_BASE as usize, SMM_SIZE as usize, pmp::Priority::Top); 
  if let Ok(region) = region {
      region.leak()
  } else {
      return -1
  }
}

#[no_mangle]
pub extern fn osm_init() -> c_int
{
  let mut region = -1;
  let ret = unsafe {
      pmp_region_init_atomic(0, !0, pmp_priority_PMP_PRI_BOTTOM, &mut region, 1)
  };
  if ret != 0 {
    return -1;
  }

  return region;
}

pub type Signature = [u8; SIGNATURE_SIZE as usize];

pub fn sign(signature: &mut Signature, data: &[u8])
{
  unsafe {
    crypto::sign_bytes(signature, data, &sm_public_key, &sm_private_key);
  }
}

fn sm_copy_key()
{
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
pub extern fn sm_init()
{
	// initialize SMM

  let mut init_data = INIT_DATA.write();

  if !init_data.init_done {
    init_data.sm_region_id = smm_init();
    if init_data.sm_region_id < 0 {
      panic!("[SM] intolerable error - failed to initialize SM memory");
    }

    init_data.os_region_id = osm_init();
    if init_data.os_region_id < 0 {
      panic!("[SM] intolerable error - failed to initialize OS memory");
    }

    init_data.init_done = true;


    if unsafe { platform_init_global_once() } != ENCLAVE_SUCCESS as usize {
      panic!("[SM] platform global init fatal error");
    }
  }

  unsafe {
    pmp_set(init_data.sm_region_id, PMP_NO_PERM as u8);
    pmp_set(init_data.os_region_id, PMP_ALL_PERM as u8);
  }

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
