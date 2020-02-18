//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

#include "sm.h"
#include "bits.h"
#include "vm.h"
#include "pmp.h"
#include "thread.h"
#include "crypto.h"

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

#define ATTEST_DATA_MAXLEN  1024
#define ENCLAVE_REGIONS_MAX 8
/* TODO: does not support multithreaded enclave yet */
#define MAX_ENCL_THREADS 1

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2

/* For now, eid's are a simple unsigned int */
typedef unsigned int enclave_id;

/* Metadata around memory regions associate with this enclave
 * EPM is the 'home' for the enclave, contains runtime code/etc
 * UTM is the untrusted shared pages
 * OTHER is managed by some other component (e.g. platform_)
 * INVALID is an unused index
 */
enum enclave_region_type {
  REGION_EPM,
  REGION_UTM,
  REGION_OTHER,
};

struct enclave;

/*** SBI functions & external functions ***/
// callables from the host
enclave_ret_code create_enclave(struct keystone_sbi_create create_args);
enclave_ret_code destroy_enclave(enclave_id eid);
enclave_ret_code run_enclave(uintptr_t* host_regs, enclave_id eid);
enclave_ret_code resume_enclave(uintptr_t* regs, enclave_id eid);
// callables from the enclave
enclave_ret_code exit_enclave(uintptr_t* regs, unsigned long retval, enclave_id eid);
enclave_ret_code stop_enclave(uintptr_t* regs, uint64_t request, enclave_id eid);
enclave_ret_code attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size, enclave_id eid);

// TODO: These functions are supposed to be internal functions.
void enclave_init_metadata();

// Changes the type of a given enclave region.
int enclave_region_retype(struct enclave *enclave, enum enclave_region_type old, enum enclave_region_type new);

// Creates a new memory region of the given type with the given PMP ID. Takes ownership of the PMP region belonging to `pmp_id`.
int enclave_region_make(struct enclave *enclave, enum enclave_region_type ty, int pmp_id);

// Borrows the PMP region id belonging to the given memory region.
int enclave_region_get_pmpid(struct enclave *enclave, enum enclave_region_type ty, int *pmp_id);

uintptr_t enclave_region_get_base(struct enclave *enclave, enum enclave_region_type ty);
uintptr_t enclave_region_get_size(struct enclave *enclave, enum enclave_region_type ty);

enclave_ret_code copy_from_host(void* source, void* dest, size_t size);
struct platform_enclave_data *get_enclave_ped(struct enclave *enclave);
struct runtime_pa_params *get_enclave_pa_params(struct enclave *enclave);
void enclave_set_satp(struct enclave *enclave, uintptr_t satp);

#endif
