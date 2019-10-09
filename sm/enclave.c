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





/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/

