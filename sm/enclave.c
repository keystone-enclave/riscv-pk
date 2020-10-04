//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include <string.h>
#include "atomic.h"
#include "platform.h"

#define ENCL_MAX  16
#define ENCL_TIME_SLICE 100000

struct enclave enclaves[ENCL_MAX];
#define ENCLAVE_EXISTS(eid) (eid >= 0 && eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPINLOCK_INIT;
static spinlock_t uid_lock = SPINLOCK_INIT; 
static size_t uid = 0;

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
static inline enclave_ret_code context_switch_to_enclave(uintptr_t* regs,
                                                enclave_id eid,
                                                int load_parameters){

  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, 1);
  swap_prev_mepc(&enclaves[eid].threads[0], read_csr(mepc));

  uintptr_t interrupts = 0;
  write_csr(mideleg, interrupts);

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

  switch_vector_enclave();

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
  swap_prev_mpp(&enclaves[eid].threads[0], regs);
  return ENCLAVE_SUCCESS;
}

static inline void context_switch_to_host(uintptr_t* encl_regs,
    enclave_id eid,
    int return_on_resume){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  write_csr(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], encl_regs, return_on_resume);
  swap_prev_mepc(&enclaves[eid].threads[0], read_csr(mepc));

  switch_vector_host();

  uintptr_t pending = read_csr(mip);

  if (pending & MIP_MTIP) {
    clear_csr(mip, MIP_MTIP);
    set_csr(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    clear_csr(mip, MIP_MSIP);
    set_csr(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    clear_csr(mip, MIP_MEIP);
    set_csr(mip, MIP_SEIP);
  }


  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();
  swap_prev_mpp(&enclaves[eid].threads[0], encl_regs);
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

static enclave_ret_code clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  memset((void*)utbase, 0, utsize);

  return ENCLAVE_SUCCESS;
}

static int enc_alloc_uid(){
   int ret_uid; 

   spinlock_lock(&uid_lock);
   ret_uid = uid++; 
   spinlock_unlock(&uid_lock);

   return ret_uid; 
}

static enclave_ret_code encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spinlock_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spinlock_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return ENCLAVE_SUCCESS;
  }
  else{
    return ENCLAVE_NO_FREE_RESOURCE;
  }
}

static enclave_ret_code encl_free_eid(enclave_id eid)
{
  spinlock_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spinlock_unlock(&encl_lock);
  return ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

/* Ensures that dest ptr is in host, not in enclave regions
 */
static enclave_ret_code copy_word_to_host(uintptr_t dest_ptr, uintptr_t value)
{
  enclave_ret_code ret = ENCLAVE_REGION_OVERLAPS;

  int err = copy_word_from_sm(dest_ptr, (uintptr_t *)&value);
  if (!err) {
    ret = ENCLAVE_SUCCESS;
  }

  return ret;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
enclave_ret_code copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create));

  if (region_overlap)
    return ENCLAVE_REGION_OVERLAPS;
  else
    return ENCLAVE_SUCCESS;
}

static int buffer_in_enclave_region(struct enclave* enclave,
                                    void* start, size_t size){
  int legal = 0;

  int i;
  /* Check if the source is in a valid region */
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclave->regions[i].type == REGION_INVALID ||
       enclave->regions[i].type == REGION_UTM)
      continue;
    uintptr_t region_start = pmp_region_get_addr(enclave->regions[i].pmp_rid);
    size_t region_size = pmp_region_get_size(enclave->regions[i].pmp_rid);
    if(start >= (void*)region_start
       && start + size <= (void*)(region_start + region_size)){
      return 1;
    }
  }
  return 0;
}

/* copies data from enclave, source must be inside EPM */
static enclave_ret_code copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static enclave_ret_code copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create* args)
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


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
enclave_ret_code create_enclave(struct keystone_sbi_create create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;
  enclave_id* eidptr = create_args.eid_pptr;

  uint8_t perm = 0;
  enclave_id eid;
  enclave_ret_code ret;
  int region, shared_region;
  int i;
  int region_overlap = 0;

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return ENCLAVE_ILLEGAL_ARGUMENT;

  /* set va params */
  struct runtime_va_params_t params = create_args.params;
  struct runtime_pa_params pa_params;
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  pa_params.runtime_base = create_args.runtime_paddr;
  pa_params.user_base = create_args.user_paddr;
  pa_params.free_base = create_args.free_paddr;


  // allocate eid
  ret = ENCLAVE_NO_FREE_RESOURCE;
  if(encl_alloc_eid(&eid) != ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
  enclaves[eid].eid = eid;
  enclaves[eid].uid = enc_alloc_uid(); 

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;

  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | SATP_MODE_CHOICE);
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;
  enclaves[eid].pa_params = pa_params;

  init_mailbox(&enclaves[eid].mailbox); 

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if(ret != ENCLAVE_SUCCESS)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
  spinlock_lock(&encl_lock); // FIXME This should error for second enter.
  ret = validate_and_hash_enclave(&enclaves[eid]);
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if(ret != ENCLAVE_SUCCESS)
    goto unlock;

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */

  ret = copy_word_to_host((uintptr_t)eidptr, (uintptr_t)eid);
  if (ret) {
    ret = ENCLAVE_ILLEGAL_ARGUMENT;
    goto unlock;
  }

  spinlock_unlock(&encl_lock);
  return ENCLAVE_SUCCESS;

unlock:
  spinlock_unlock(&encl_lock);
free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

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
                 && enclaves[eid].state <= STOPPED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
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


enclave_ret_code run_enclave(uintptr_t* host_regs, enclave_id eid)
{
  int runable;

  spinlock_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spinlock_unlock(&encl_lock);

  if(!runable) {
    return ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  return context_switch_to_enclave(host_regs, eid, 1);
}

enclave_ret_code exit_enclave(uintptr_t* encl_regs, unsigned long retval, enclave_id eid)
{
  int exitable;

  spinlock_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spinlock_unlock(&encl_lock);

  if(!exitable)
    return ENCLAVE_NOT_RUNNING;

  context_switch_to_host(encl_regs, eid, 0);

  return ENCLAVE_SUCCESS;
}

enclave_ret_code stop_enclave(uintptr_t* encl_regs, uint64_t request, enclave_id eid)
{
  int stoppable;

  spinlock_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spinlock_unlock(&encl_lock);

  if(!stoppable)
    return ENCLAVE_NOT_RUNNING;

  context_switch_to_host(encl_regs, eid, request == STOP_EDGE_CALL_HOST);

  switch(request) {
  case(STOP_TIMER_INTERRUPT):
    return ENCLAVE_INTERRUPTED;
  case(STOP_EDGE_CALL_HOST):
    return ENCLAVE_EDGE_CALL_HOST;
  default:
    return ENCLAVE_UNKNOWN_ERROR;
  }
}

enclave_ret_code resume_enclave(uintptr_t* host_regs, enclave_id eid)
{
  int resumable;

  spinlock_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS);
  if(!resumable) {
    spinlock_unlock(&encl_lock);
    return ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spinlock_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  return context_switch_to_enclave(host_regs, eid, 0);
}

enclave_ret_code attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return ENCLAVE_ILLEGAL_ARGUMENT;

  spinlock_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spinlock_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  memcpy(report.sm.hash, sm_hash, MDSIZE);
  memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spinlock_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);
      
  if (ret) {
    ret = ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = ENCLAVE_SUCCESS;

err_unlock:
  spinlock_unlock(&encl_lock);
  return ret;
}

enclave_ret_code get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return ENCLAVE_SUCCESS;
}

/* Initializes enclave mailbox */
void init_mailbox(struct mailbox* mailbox){
   mailbox->capacity = MAILBOX_SIZE;
   mailbox->size = 0;
   mailbox->lock.lock = 0;
   memset(mailbox->data, 0, MAILBOX_SIZE);
}

enclave_ret_code recv_msg(enclave_id eid, size_t uid, void *buf, size_t msg_size) {
	struct mailbox* mailbox = &enclaves[eid].mailbox;
	uint8_t *ptr = (uint8_t *) &enclaves[eid].mailbox.data;
  	struct mailbox_header *hdr = (struct mailbox_header *) ptr;  
  	size_t size = 0; 
  	size_t hdr_size = 0; 

	spinlock_lock(&(mailbox->lock));

	while (size < mailbox->size){

		hdr_size = hdr->size; 

     	if(hdr->send_uid == uid){
        	//Check if the message is bigger than the buffer. 
        	if(hdr->size > msg_size){
            		spinlock_unlock(&(mailbox->lock));
            		return 1; 
		}

        	memcpy(buf, hdr->data, msg_size); 

        	//Clear the message from the mailbox
        	memset(hdr->data, 0, hdr->size);
        	memset(hdr, 0, sizeof(struct mailbox_header));
        	memcpy(hdr, ptr + hdr_size + sizeof(struct mailbox_header), mailbox->size - (size + sizeof(struct mailbox_header) + hdr_size)); 

        	mailbox->size -= hdr_size + sizeof(struct mailbox_header); 
        	spinlock_unlock(&(mailbox->lock));
		return 0; 
     	}
  		size += sizeof(struct mailbox_header) + hdr_size;
    		ptr += sizeof(struct mailbox_header) + hdr_size;    
    		hdr = (struct mailbox_header *) ptr;
	}
	//Release lock on mailbox 
  	spinlock_unlock(&(mailbox->lock));
	return 1;

}


enclave_ret_code send_msg(enclave_id eid, size_t uid, void *buf, size_t msg_size){
   struct mailbox *mbox = (void *) 0; 

   for(int eid=0; eid<ENCL_MAX; eid++)
  {
    if(ENCLAVE_EXISTS(eid) && enclaves[eid].uid == uid){
      mbox = &enclaves[eid].mailbox;
      break; 
    }
  }

   //Check if the mailbox is registered
   if(!mbox){
      return 1;  
   }

   spinlock_lock(&(mbox->lock));
 
   //Check if the message + header can fit in the mailbox. 
   if(mbox->capacity - mbox->size < msg_size + sizeof(struct mailbox_header)){
      spinlock_unlock(&(mbox->lock));
      return 0; 
   }

   struct mailbox_header hdr;
   hdr.send_uid = enclaves[eid].uid; 
   hdr.size = msg_size;
 
   memcpy(mbox->data + mbox->size, &hdr, sizeof(hdr));
   memcpy(mbox->data + mbox->size + sizeof(hdr), buf, msg_size);  
   mbox->size += msg_size + sizeof(hdr);  

   spinlock_unlock(&(mbox->lock));
   
   return 0;
}

enclave_ret_code mem_share(enclave_id eid, size_t uid, uintptr_t *enclave_addr, uintptr_t *enclave_size){
   struct enclave *grantee = (void *) 0; 
   int grantee_eid; 
   //return ENCLAVE_SUCCESS; 
   //Find the enclave with the corresponding uid
   for(int eid=0; eid<ENCL_MAX; eid++)
  {
    if(ENCLAVE_EXISTS(eid) && enclaves[eid].uid == uid){
      grantee = &enclaves[eid];
      grantee_eid = eid; 
      break;
    }
  }   	

  if(!grantee){
      return 1; 
  }

  //Set PMP of the granter enclave with grantee
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type == REGION_EPM) {
      /* Find empty memory region slot in grantee */
      for(int grantee_memid = 0; grantee_memid < ENCLAVE_REGIONS_MAX; grantee_memid++){
	if(grantee->regions[grantee_memid].type == REGION_INVALID){
		grantee->regions[grantee_memid].pmp_rid = enclaves[eid].regions[memid].pmp_rid;
		grantee->regions[grantee_memid].type = enclaves[eid].regions[memid].type;
		break;
	}
      }
    }
  }

  if(enclave_addr)
     *enclave_addr = enclaves[eid].pa_params.dram_base;

  if(enclave_size)
     *enclave_size = enclaves[eid].pa_params.dram_size;

  return 0; 
}

enclave_ret_code get_uid(enclave_id eid, size_t *uid){
  
  if(uid)
      *uid = enclaves[eid].uid;

  return ENCLAVE_SUCCESS; 
}

enclave_ret_code mem_stop(enclave_id eid, size_t uid){
   struct enclave *granter = (void *) 0;

   //Find the enclave with the corresponding uid
   for(int eid=0; eid<ENCL_MAX; eid++)
  {
    if(ENCLAVE_EXISTS(eid) && enclaves[eid].uid == uid){
      granter = &enclaves[eid];
      break;
    }
  }

  if(!granter){
      return 1;
  }

  //Set PMP of the granter enclave turned off
  int granter_memid;

  for(granter_memid=0; granter_memid < ENCLAVE_REGIONS_MAX; granter_memid++) {
    if(granter->regions[granter_memid].type == REGION_EPM) {
      for(int memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++){
	  if(enclaves[eid].regions[memid].pmp_rid == granter->regions[granter_memid].pmp_rid){
	     pmp_unset(granter->regions[granter_memid].pmp_rid);
	     enclaves[eid].regions[memid].pmp_rid = 0; 
	     enclaves[eid].regions[memid].type = REGION_INVALID;
	     break; 
	}
      }
    }
  }


  return 0; 
}
