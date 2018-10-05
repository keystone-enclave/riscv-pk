#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "atomic.h"
#include <errno.h>

static spinlock_t sm_lock = SPINLOCK_INIT;

int mcall_sm_create_enclave(unsigned long base, unsigned long size)
{
  int ret;
  spinlock_lock(&sm_lock);
  ret = create_enclave((uintptr_t) base, (uintptr_t) size);
  spinlock_unlock(&sm_lock);
  return ret;
}

int mcall_sm_destroy_enclave(unsigned long eid)
{
  int ret;
  if(get_host_satp(eid) != read_csr(satp))
    return -EFAULT;
  
  spinlock_lock(&sm_lock);
  ret = destroy_enclave((int)eid);
  spinlock_unlock(&sm_lock);
  return ret;
}

int mcall_sm_copy_from_enclave(unsigned long eid, unsigned long ptr, unsigned long size)
{
  int ret;
  if(get_host_satp(eid) != read_csr(satp))
    return -EFAULT;
  ret = copy_from_enclave(eid, (void*) ptr, (size_t) size);
  return ret;
}

int mcall_sm_copy_to_enclave(unsigned long eid, unsigned long addr, unsigned long ptr, unsigned long size)
{
  int ret;
  if(get_host_satp(eid) != read_csr(satp))
    return -EFAULT;

  ret = copy_to_enclave(eid, (uintptr_t) addr,(uintptr_t) ptr, (size_t) size);
  return ret;
}

int mcall_sm_run_enclave(unsigned long eid, unsigned long ptr)
{
  if(get_host_satp(eid) != read_csr(satp))
    return -EPERM;
  return run_enclave((unsigned int) eid, (uintptr_t) ptr);
}

int mcall_sm_exit_enclave(unsigned long retval)
{
  return exit_enclave((uint64_t)retval);
}

int mcall_sm_not_implemented(unsigned long cause)
{
  printm("sm ecall is not implemented for %ld\n", cause);
  return exit_enclave((uint64_t)-1UL);
}
