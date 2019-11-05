//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "sm-sbi.h"
#include "pmp.h"
#include "enclave.h"
#include "page.h"
#include "cpu.h"
#include <errno.h>
#include "platform.h"
#include "plugins/plugins.h"

uintptr_t mcall_sm_create_enclave(uintptr_t create_args)
{
  // printm("[%d] sm_create_enclave\r\n", read_csr(mhartid));
  struct keystone_sbi_create create_args_local;
  enclave_ret_code ret;

  /* an enclave cannot call this SBI */
  if (cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  ret = copy_from_host((struct keystone_sbi_create*)create_args,
                       &create_args_local,
                       sizeof(struct keystone_sbi_create));

  if( ret != ENCLAVE_SUCCESS )
    return ret;

  ret = create_enclave(create_args_local);
  return ret;
}

uintptr_t mcall_sm_destroy_enclave(unsigned long eid)
{
  // printm("[%d][%d] sm_destroy_enclave\r\n", read_csr(mhartid), eid);
  enclave_ret_code ret;

  /* an enclave cannot call this SBI */
  if (cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  ret = destroy_enclave((unsigned int)eid);
  // printm("[%d][%d] sm_destroy_enclave_done\r\n", read_csr(mhartid), eid);
  return ret;
}
uintptr_t mcall_sm_run_enclave(uintptr_t* regs, unsigned long eid)
{
  // printm("[%d][%d] sm_run_enclave\r\n", read_csr(mhartid), eid);
  enclave_ret_code ret;

  /* an enclave cannot call this SBI */
  if (cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  ret = run_enclave(regs, (unsigned int) eid);

  return ret;
}

uintptr_t mcall_sm_resume_enclave(uintptr_t* host_regs, unsigned long eid)
{
  // printm("[%d][%d] sm_resume_enclave\r\n", read_csr(mhartid), eid);
  enclave_ret_code ret;

  /* an enclave cannot call this SBI */
  if (cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  ret = resume_enclave(host_regs, (unsigned int) eid);
  return ret;
}

uintptr_t mcall_sm_exit_enclave(uintptr_t* encl_regs, unsigned long retval)
{
  // printm("[%d][%d] sm_exit_enclave\r\n", read_csr(mhartid), cpu_get_enclave_id());
  enclave_ret_code ret;
  /* only an enclave itself can call this SBI */
  if (!cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  ret = exit_enclave(encl_regs, (unsigned long) retval, cpu_get_enclave_id());
  // printm("[%d][%d] sm_exit_enclave_done\r\n", read_csr(mhartid), cpu_get_enclave_id());
  return ret;
}

uintptr_t mcall_sm_stop_enclave(uintptr_t* encl_regs, unsigned long request)
{
  // printm("[%d][%d] sm_stop_enclave\r\n", read_csr(mhartid), cpu_get_enclave_id());
  enclave_ret_code ret;
  /* only an enclave itself can call this SBI */
  if (!cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  ret = stop_enclave(encl_regs, (uint64_t)request, cpu_get_enclave_id());
  return ret;
}

uintptr_t mcall_sm_attest_enclave(uintptr_t report, uintptr_t data, uintptr_t size)
{
  // printm("[%d][%d] sm_attest_enclave\r\n", read_csr(mhartid), cpu_get_enclave_id());
  enclave_ret_code ret;
  /* only an enclave itself can call this SBI */
  if (!cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  ret = attest_enclave(report, data, size, cpu_get_enclave_id());
  return ret;
}

uintptr_t mcall_sm_random()
{
  /* Anyone may call this interface. */
// printm("[%d] mcall_sm_random\r\n", read_csr(mhartid));
  return platform_random();
}

uintptr_t mcall_sm_call_plugin(uintptr_t plugin_id, uintptr_t call_id, uintptr_t arg0, uintptr_t arg1)
{
  // printm("[%d][%d] sm_call_plugin\r\n", read_csr(mhartid), cpu_get_enclave_id());
  if(!cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  return call_plugin(cpu_get_enclave_id(), plugin_id, call_id, arg0, arg1);
}

/* TODO: this should be removed in the future. */
uintptr_t mcall_sm_not_implemented(uintptr_t* encl_regs, unsigned long cause)
{
  // printm("[%d][%d] sm_not_implemented\r\n", read_csr(mhartid), cpu_get_enclave_id());
  /* only an enclave itself can call this SBI */
  if (!cpu_is_enclave_context()) {
    return ENCLAVE_SBI_PROHIBITED;
  }

  if((long)cause < 0)
  {
    // discard MSB
    cause = cause << 1;
    cause = cause >> 1;
    printm("the runtime could not handle interrupt %ld\r\n", cause );
    printm("mideleg: 0x%lx\r\n");

  }
  else
  {
    printm("the runtime could not handle exception %ld\r\n", cause);
    printm("medeleg: 0x%lx (expected? %ld)\r\n", read_csr(medeleg), read_csr(medeleg) & (1<<cause));
  }

  return exit_enclave(encl_regs, (uint64_t)-1UL, cpu_get_enclave_id());
}
