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
enclave_ret_code get_sealing_key(uintptr_t seal_key, uintptr_t key_ident,
                                 size_t key_ident_size, uintptr_t info_buffer,
                                 size_t info_buffer_size, enclave_id eid);
// TODO: These functions are supposed to be internal functions.
void enclave_init_metadata();
int get_enclave_region_index(const struct enclave *enclave, enum enclave_region_type type);
int get_eid_region_index(enclave_id eid, enum enclave_region_type type);

enclave_ret_code copy_from_host(void* source, void* dest, size_t size);
uintptr_t get_enclave_region_base(enclave_id eid, int memid);
uintptr_t get_enclave_region_size(enclave_id eid, int memid);
struct platform_enclave_data *get_enclave_ped(struct enclave *enclave);

#endif
