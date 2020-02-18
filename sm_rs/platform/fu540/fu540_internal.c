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
  /* We will be directly setting the master d$ mask to avoid any cache
     pollution issues */
  waymask_t* master_mask = WM_REG_ADDR(core*2);
  /* Go through the mask one way at a time to control the allocations */
  for(tmp_mask=0x80;
      tmp_mask <= scratchpad_allocated_ways;
      tmp_mask = tmp_mask << 1){
    uintptr_t way_end  = addr + L2_WAY_SIZE;
    /* Assign a temporary mask of 1 way to the d$ */
    *master_mask = tmp_mask;
    /* Write a known value to every L2_LINE_SIZE offset */
    for(;
        addr < way_end;
        addr+= L2_LINE_SIZE){
      *(uintptr_t*)addr = 64;
    }
    /* Disable as soon as possible */
    *master_mask = invert_mask;
  }

  /* At this point, no master has waymasks for the scratchpad ways,
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
  struct platform_enclave_data *ped = get_enclave_ped(enclave);

  ped->num_ways = 0; // DISABLE waymasking
  //ped->num_ways = WM_NUM_WAYS/2;
  ped->saved_mask = 0;
  ped->use_scratch = 0;
}

enclave_ret_code platform_create_enclave(struct enclave* enclave){
  struct platform_enclave_data *ped = get_enclave_ped(enclave);
  struct runtime_pa_params *pa_params = get_enclave_pa_params(enclave);

  ped->use_scratch = 0;
  int i;
  if(ped->use_scratch){

    if(scratch_init() != ENCLAVE_SUCCESS){
      return ENCLAVE_UNKNOWN_ERROR;
    }

    int err = 0;
    err |= enclave_region_retype(enclave, REGION_EPM, REGION_OTHER);
    err |= enclave_region_make(enclave, REGION_EPM, scratch_rid);

    /* Swap regions */
    if(err){
      return ENCLAVE_NO_FREE_RESOURCE;
    }
    
    /* Copy the enclave over */
    uintptr_t old_epm_start = enclave_region_get_base(enclave, REGION_OTHER);
    uintptr_t scratch_epm_start = enclave_region_get_base(enclave, REGION_EPM);
    size_t size = pa_params->free_base - old_epm_start;
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
    pa_params->dram_base = scratch_epm_start;
    pa_params->dram_size = scratch_size;
    pa_params->runtime_base = (scratch_epm_start +
                                       (pa_params->runtime_base -
                                        old_epm_start));
    pa_params->user_base = (scratch_epm_start +
                                    (pa_params->user_base -
                                     old_epm_start));
    pa_params->free_base = (scratch_epm_start +
                                       size);
    enclave_set_satp(enclave, (scratch_epm_start >> RISCV_PGSHIFT) | SATP_MODE_CHOICE);

  /* printm("[new pa_params]: \r\n\tbase_addr: %llx\r\n\tbasesize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        pa_params->dram_base, */
  /*        pa_params->dram_size, */
  /*        pa_params->runtime_base, */
  /*        pa_params->user_base, */
  /*        pa_params->free_base); */

  }

  return ENCLAVE_SUCCESS;

}

void platform_destroy_enclave(struct enclave* enclave){
  struct platform_enclave_data *ped = get_enclave_ped(enclave);

  if(ped->use_scratch){
    /* Free the scratchpad */
    waymask_free_scratchpad();
  }
  ped->use_scratch = 0;
}

void platform_switch_to_enclave(struct enclave* enclave){
  struct platform_enclave_data *ped = get_enclave_ped(enclave);

  if(ped->num_ways > 0){
    // Each hart gets special access to some
    unsigned int core = read_csr(mhartid);

    //Allocate ways, fresh every time we enter
    size_t remaining = waymask_allocate_ways(ped->num_ways,
                                             core,
                                             &ped->saved_mask);

    //printm("Chose ways: 0x%x, core 0x%x\r\n",ped->saved_mask, core);
    /* Assign the ways to all cores */
    waymask_apply_allocated_mask(ped->saved_mask, core);

    /* Clear out these ways MUST first apply mask to other masters */
    waymask_clear_ways(ped->saved_mask, core);
  }

  /* Setup PMP region for scratchpad */
  if(ped->use_scratch != 0){
    pmp_set(scratch_rid, PMP_ALL_PERM);
    //printm("Switching to an enclave with scratchpad access\r\n");
  }
}

void platform_switch_from_enclave(struct enclave* enclave){
  struct platform_enclave_data *ped = get_enclave_ped(enclave);

  if(ped->num_ways > 0){
    /* Free all our ways */
    waymask_free_ways(ped->saved_mask);
    /* We don't need to clean them, see docs */
  }
  if(ped->use_scratch != 0){
    pmp_set(scratch_rid, PMP_NO_PERM);
  }

}
