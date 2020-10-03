//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef sm_h
#define sm_h

#include <stdint.h>
#include "pmp.h"
#include "sm-sbi.h"
#include "encoding.h"

#define SMM_BASE  0x80000000
#define SMM_SIZE  0x200000

#define SBI_SM_CREATE_ENCLAVE    101
#define SBI_SM_DESTROY_ENCLAVE   102
#define SBI_SM_ATTEST_ENCLAVE    103
#define SBI_SM_GET_SEALING_KEY   104
#define SBI_SM_RUN_ENCLAVE       105
#define SBI_SM_STOP_ENCLAVE      106
#define SBI_SM_RESUME_ENCLAVE    107
#define SBI_SM_RANDOM            108
#define SBI_SM_EXIT_ENCLAVE     1101
#define SBI_SM_CALL_PLUGIN      1000
#define SBI_SM_NOT_IMPLEMENTED  1111

/* error codes */
#define ENCLAVE_NOT_IMPLEMENTED             -2U
#define ENCLAVE_UNKNOWN_ERROR               -1U
#define ENCLAVE_SUCCESS                     0
#define ENCLAVE_INVALID_ID                  1
#define ENCLAVE_INTERRUPTED                 2
#define ENCLAVE_PMP_FAILURE                 3
#define ENCLAVE_NOT_RUNNABLE                4
#define ENCLAVE_NOT_DESTROYABLE             5
#define ENCLAVE_REGION_OVERLAPS             6
#define ENCLAVE_NOT_ACCESSIBLE              7
#define ENCLAVE_ILLEGAL_ARGUMENT            8
#define ENCLAVE_NOT_RUNNING                 9
#define ENCLAVE_NOT_RESUMABLE               10
#define ENCLAVE_EDGE_CALL_HOST              11
#define ENCLAVE_NOT_INITIALIZED             12
#define ENCLAVE_NO_FREE_RESOURCE            13
#define ENCLAVE_SBI_PROHIBITED              14
#define ENCLAVE_ILLEGAL_PTE                 15
#define ENCLAVE_SM_NOT_READY                16

#define PMP_UNKNOWN_ERROR                   -1U
#define PMP_SUCCESS                         0
#define PMP_REGION_SIZE_INVALID             20
#define PMP_REGION_NOT_PAGE_GRANULARITY     21
#define PMP_REGION_NOT_ALIGNED              22
#define PMP_REGION_MAX_REACHED              23
#define PMP_REGION_INVALID                  24
#define PMP_REGION_OVERLAP                  25
#define PMP_REGION_IMPOSSIBLE_TOR           26

void sm_init(void);

/* platform specific functions */
#define ATTESTATION_KEY_LENGTH  64
void sm_retrieve_pubkey(void* dest);

/* creation parameters */
struct keystone_sbi_pregion
{
  uintptr_t paddr;
  size_t size;
};
struct runtime_va_params_t
{
  uintptr_t runtime_entry;
  uintptr_t user_entry;
  uintptr_t untrusted_ptr;
  uintptr_t untrusted_size;
};

struct runtime_pa_params
{
  uintptr_t dram_base;
  uintptr_t dram_size;
  uintptr_t runtime_base;
  uintptr_t user_base;
  uintptr_t free_base;
};

struct keystone_sbi_create
{
  struct keystone_sbi_pregion epm_region;
  struct keystone_sbi_pregion utm_region;

  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;

  struct runtime_va_params_t params;
  uint64_t* eid_vptr;
};

int osm_pmp_set(uint8_t perm);
#endif
