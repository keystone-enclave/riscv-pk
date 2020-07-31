#include "fu540.h"
#include "encoding.h"
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include <errno.h>
#include "page.h"
#include <string.h>
#include "platform.h"
#include "sm.h"

enclave_ret_code scratch_init(){
  if(scratchpad_allocated_ways != 0){
    return ENCLAVE_SUCCESS;
  }

  /* TODO TMP way to try and get the scratchpad allocated */
  waymask_allocate_scratchpad();

  /* Clear scratchpad for use */
  unsigned int core = read_csr(mhartid);
  waymask_apply_allocated_mask(scratchpad_allocated_ways, core);

  waymask_t invert_mask = WM_FLIP_MASK(scratchpad_allocated_ways);
  _wm_assign_mask(invert_mask, core*2+1);

  /* This section is quite delicate, and may need to be re-written in
     assembly. Fundamentally, we are going to create a scratchpad
     region in the L2 based on the given mask (assuming that the mask
     is contiguous bits.
  */

  /* Choose a start/stop physical address to use for the
     scratchpad. As long as we choose contiguous addresses in the L2
     Zero Device that total the size of the allocated ways, they don't
     really matter */
  uintptr_t scratch_start = L2_SCRATCH_START;
  uintptr_t scratch_stop = L2_SCRATCH_START + (8 *  L2_WAY_SIZE);
  waymask_t tmp_mask;
  uintptr_t addr;

  addr = scratch_start;
  /* We will be directly setting the controller d$ mask to avoid any cache
     pollution issues */
  waymask_t* controller_mask = WM_REG_ADDR(core*2);
  /* Go through the mask one way at a time to control the allocations */
  for(tmp_mask=0x80;
      tmp_mask <= scratchpad_allocated_ways;
      tmp_mask = tmp_mask << 1){
    uintptr_t way_end  = addr + L2_WAY_SIZE;
    /* Assign a temporary mask of 1 way to the d$ */
    *controller_mask = tmp_mask;
    /* Write a known value to every L2_LINE_SIZE offset */
    for(;
        addr < way_end;
        addr+= L2_LINE_SIZE){
      *(uintptr_t*)addr = 64;
    }
    /* Disable as soon as possible */
    *controller_mask = invert_mask;
  }

  /* At this point, no controller has waymasks for the scratchpad ways,
     and all scratchpad addresses have L2 lines */

  /* We try and check it now, any error SHOULD be immediately detectable. */
  /* If there was a mistake, the scratchpad will never be safe to use
     again... */
  for(addr = scratch_start; addr < scratch_stop; addr += L2_LINE_SIZE){
    if(*(uintptr_t*)addr != 64){
      printm("FATAL: Found a bad line %x\r\n", addr);
      return ENCLAVE_UNKNOWN_ERROR;
    }
  }

  return ENCLAVE_SUCCESS;
}

enclave_ret_code platform_init_global_once(){

  waymask_init();
  scratchpad_allocated_ways = 0;

  /* PMP Lock the entire L2 controller */
  if(pmp_region_init_atomic(CACHE_CONTROLLER_ADDR_START,
                            CACHE_CONTROLLER_ADDR_END - CACHE_CONTROLLER_ADDR_START,
                            PMP_PRI_ANY, &l2_controller_rid, 1)){
    printm("FATAL CANNOT CREATE PMP FOR CONTROLLER\r\n");
    return ENCLAVE_NO_FREE_RESOURCE;
  }
  /* Create PMP region for scratchpad */
  if(pmp_region_init_atomic(L2_SCRATCH_START,
                            L2_SCRATCH_STOP - L2_SCRATCH_START,
                            PMP_PRI_ANY, &scratch_rid, 1)){
    printm("FATAL CANNOT CREATE SCRATCH PMP\r\n");
    return ENCLAVE_NO_FREE_RESOURCE;
  }
  return ENCLAVE_SUCCESS;
}


enclave_ret_code platform_init_global(){
  pmp_set(l2_controller_rid, PMP_NO_PERM);
  pmp_set(scratch_rid, PMP_NO_PERM);

  return ENCLAVE_SUCCESS;
}

void platform_init_enclave(struct enclave* enclave){
  enclave->ped.num_ways = 0; // DISABLE waymasking
  //ped->num_ways = WM_NUM_WAYS/2;
  enclave->ped.saved_mask = 0;
  enclave->ped.use_scratch = 0;

}

enclave_ret_code platform_create_enclave(struct enclave* enclave){
  enclave->ped.use_scratch = 0;
  int i;
  if(enclave->ped.use_scratch){

    if(scratch_init() != ENCLAVE_SUCCESS){
      return ENCLAVE_UNKNOWN_ERROR;
    }

    /* Swap regions */
    int old_epm_idx = get_enclave_region_index(enclave->eid, REGION_EPM);
    int new_idx = get_enclave_region_index(enclave->eid, REGION_INVALID);
    if(old_epm_idx < 0 || new_idx < 0){
      return ENCLAVE_NO_FREE_RESOURCE;
    }

    enclave->regions[new_idx].pmp_rid = scratch_rid;
    enclave->regions[new_idx].type = REGION_EPM;
    enclave->regions[old_epm_idx].type = REGION_OTHER;

    /* Copy the enclave over */
    uintptr_t old_epm_start = pmp_region_get_addr(enclave->regions[old_epm_idx].pmp_rid);
    uintptr_t scratch_epm_start = pmp_region_get_addr(scratch_rid);
    size_t size = enclave->pa_params.free_base - old_epm_start;
    size_t scratch_size = 8*L2_WAY_SIZE;

    if(size > scratch_size){
      printm("FATAL: Enclave too big for scratchpad!\r\n");
      return ENCLAVE_NO_FREE_RESOURCE;
    }
    memcpy((enclave_ret_code*)scratch_epm_start,
           (enclave_ret_code*)old_epm_start,
           size);
    printm("Performing copy from %llx to %llx\r\n", old_epm_start, scratch_epm_start);
    /* Change pa params to the new region */
    enclave->pa_params.dram_base = scratch_epm_start;
    enclave->pa_params.dram_size = scratch_size;
    enclave->pa_params.runtime_base = (scratch_epm_start +
                                       (enclave->pa_params.runtime_base -
                                        old_epm_start));
    enclave->pa_params.user_base = (scratch_epm_start +
                                    (enclave->pa_params.user_base -
                                     old_epm_start));
    enclave->pa_params.free_base = (scratch_epm_start +
                                       size);
    enclave->encl_satp =((scratch_epm_start >> RISCV_PGSHIFT) | SATP_MODE_CHOICE);

  /* printm("[new pa_params]: \r\n\tbase_addr: %llx\r\n\tbasesize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        enclave->pa_params.dram_base, */
  /*        enclave->pa_params.dram_size, */
  /*        enclave->pa_params.runtime_base, */
  /*        enclave->pa_params.user_base, */
  /*        enclave->pa_params.free_base); */

  }

  return ENCLAVE_SUCCESS;

}

void platform_destroy_enclave(struct enclave* enclave){
  if(enclave->ped.use_scratch){
    int scratch_epm_idx = get_enclave_region_index(enclave->eid, REGION_EPM);
    /* Clean out the region ourselves */

    /* Should be safe to just write to the memory addresses we used to
       initialize */
    uintptr_t addr;
    uintptr_t scratch_start = pmp_region_get_addr(enclave->regions[scratch_epm_idx].pmp_rid);
    uintptr_t scratch_stop = scratch_start + pmp_region_get_size(enclave->regions[scratch_epm_idx].pmp_rid);
    for( addr = scratch_start;
         addr < scratch_stop;
         addr += sizeof(uintptr_t)){
      *(uintptr_t*)addr = 0;
    }

    /* Fix the enclave region info to no longer know about
       scratchpad */

    enclave->regions[scratch_epm_idx].type = REGION_INVALID;

    /* Free the scratchpad */
    waymask_free_scratchpad();
  }
  enclave->ped.use_scratch = 0;
}

void platform_switch_to_enclave(struct enclave* enclave){

  if(enclave->ped.num_ways > 0){
    // Each hart gets special access to some
    unsigned int core = read_csr(mhartid);

    //Allocate ways, fresh every time we enter
    size_t remaining = waymask_allocate_ways(enclave->ped.num_ways,
                                             core,
                                             &enclave->ped.saved_mask);

    //printm("Chose ways: 0x%x, core 0x%x\r\n",enclave->ped.saved_mask, core);
    /* Assign the ways to all cores */
    waymask_apply_allocated_mask(enclave->ped.saved_mask, core);

    /* Clear out these ways MUST first apply mask to other controllers */
    waymask_clear_ways(enclave->ped.saved_mask, core);
  }

  /* Setup PMP region for scratchpad */
  if(enclave->ped.use_scratch != 0){
    pmp_set(scratch_rid, PMP_ALL_PERM);
    //printm("Switching to an enclave with scratchpad access\r\n");
  }
}

void platform_switch_from_enclave(struct enclave* enclave){
  if(enclave->ped.num_ways > 0){
    /* Free all our ways */
    waymask_free_ways(enclave->ped.saved_mask);
    /* We don't need to clean them, see docs */
  }
  if(enclave->ped.use_scratch != 0){
    pmp_set(scratch_rid, PMP_NO_PERM);
  }

}
