//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include <string.h>
#include "atomic.h"
#include "platform.h"

struct enclave enclaves[ENCL_MAX];
#define ENCLAVE_EXISTS(eid) (enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPINLOCK_INIT;
void enclave_lock(void) {
    spinlock_lock(&encl_lock);
}
void enclave_unlock(void) {
    spinlock_unlock(&encl_lock);
}

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

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
enclave_ret_code context_switch_to_enclave(uintptr_t* regs,
                                                enclave_id eid,
                                                int load_parameters){

  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs);
  swap_prev_mepc(&enclaves[eid].threads[0], read_csr(mepc));

  if(load_parameters){
    // passing parameters for a first run
    // $mepc: (VA) kernel entry
    write_csr(mepc, (uintptr_t) enclaves[eid].params.runtime_entry);
    // $sepc: (VA) user entry
    write_csr(sepc, (uintptr_t) enclaves[eid].params.user_entry);
    // $a1: (PA) DRAM base,
    regs[11] = (uintptr_t) enclaves[eid].pa_params.dram_base;
    // $a2: (PA) DRAM size,
    regs[12] = (uintptr_t) enclaves[eid].pa_params.dram_size;
    // $a3: (PA) kernel location,
    regs[13] = (uintptr_t) enclaves[eid].pa_params.runtime_base;
    // $a4: (PA) user location,
    regs[14] = (uintptr_t) enclaves[eid].pa_params.user_base;
    // $a5: (PA) freemem location,
    regs[15] = (uintptr_t) enclaves[eid].pa_params.free_base;
    // $a6: (VA) utm base,
    regs[16] = (uintptr_t) enclaves[eid].params.untrusted_ptr;
    // $a7: (size_t) utm size
    regs[17] = (uintptr_t) enclaves[eid].params.untrusted_size;

    // switch to the initial enclave page table
    write_csr(satp, enclaves[eid].encl_satp);
  }

  // disable timer set by the OS
  clear_csr(mie, MIP_MTIP);

  // Clear pending interrupts
  clear_csr(mip, MIP_MTIP);
  clear_csr(mip, MIP_STIP);
  clear_csr(mip, MIP_SSIP);
  clear_csr(mip, MIP_SEIP);

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid);
  return ENCLAVE_SUCCESS;
}

void context_switch_to_host(uintptr_t* encl_regs,
    enclave_id eid){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], encl_regs);
  swap_prev_mepc(&enclaves[eid].threads[0], read_csr(mepc));

  // enable timer interrupt
  set_csr(mie, MIP_MTIP);

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();
  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}



int is_create_args_valid(const struct keystone_sbi_create* args)
{
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;

  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
enclave_ret_code destroy_enclave(enclave_id eid)
{
  int destroyable;

  spinlock_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state != ALLOCATED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYED;
  spinlock_unlock(&encl_lock);

  if(!destroyable)
    return ENCLAVE_NOT_DESTROYABLE;


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    memset((void*) base, 0, size);

    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = (struct runtime_va_params_t) {0};
  enclaves[eid].pa_params = (struct runtime_pa_params) {0};
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }

  // 3. release eid
  encl_free_eid(eid);

  return ENCLAVE_SUCCESS;
}

