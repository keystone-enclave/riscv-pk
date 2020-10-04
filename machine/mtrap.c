#include "mtrap.h"
#include "mcall.h"
#include "htif.h"
#include "atomic.h"
#include "bits.h"
#include "vm.h"
#include "uart.h"
#include "uart16550.h"
#include "finisher.h"
#include "fdt.h"
#include "unprivileged_memory.h"
#include "disabled_hart_mask.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef SM_ENABLED
#include "sm.h"
#endif

hls_t *get_hls()
{
  return HLS();
}

void __attribute__((noreturn)) bad_trap(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  die("machine mode: unhandlable trap %d @ %p", read_csr(mcause), mepc);
}

uintptr_t mcall_console_putchar(uint8_t ch)
{
  if (uart) {
    uart_putchar(ch);
  } else if (uart16550) {
    uart16550_putchar(ch);
  } else if (htif) {
    htif_console_putchar(ch);
  }
  return 0;
}

void putstring(const char* s)
{
  while (*s)
    mcall_console_putchar(*s++);
}

void vprintm(const char* s, va_list vl)
{
  char buf[256];
  vsnprintf(buf, sizeof buf, s, vl);
  putstring(buf);
}

void printm(const char* s, ...)
{
  va_list vl;

  va_start(vl, s);
  vprintm(s, vl);
  va_end(vl);
}

static void send_ipi(uintptr_t recipient, int event)
{
  if (((disabled_hart_mask >> recipient) & 1)) return;
  atomic_or(&OTHER_HLS(recipient)->mipi_pending, event);
  mb();
  *OTHER_HLS(recipient)->ipi = 1;
}

static uintptr_t mcall_console_getchar()
{
  if (uart) {
    return uart_getchar();
  } else if (uart16550) {
    return uart16550_getchar();
  } else if (htif) {
    return htif_console_getchar();
  } else {
    return '\0';
  }
}

static uintptr_t mcall_clear_ipi()
{
  return clear_csr(mip, MIP_SSIP) & MIP_SSIP;
}

static uintptr_t mcall_shutdown()
{
  poweroff(0);
}

static uintptr_t mcall_set_timer(uint64_t when)
{
  *HLS()->timecmp = when;
  clear_csr(mip, MIP_STIP);
  set_csr(mie, MIP_MTIP);
  return 0;
}
static void send_ipi_many(uintptr_t* pmask, int event)
{
  _Static_assert(MAX_HARTS <= 8 * sizeof(*pmask), "# harts > uintptr_t bits");
  uintptr_t mask = hart_mask;
  if (pmask)
    mask &= load_uintptr_t(pmask, read_csr(mepc));

  // send IPIs to everyone
  for (uintptr_t i = 0, m = mask; m; i++, m >>= 1)
    if (m & 1)
      send_ipi(i, event);

  if (event == IPI_SOFT)
    return;

  // wait until all events have been handled.
  // prevent deadlock by consuming incoming IPIs.
  uint32_t incoming_ipi = 0;
  for (uintptr_t i = 0, m = mask; m; i++, m >>= 1)
    if (m & 1)
      while (*OTHER_HLS(i)->ipi)
        incoming_ipi |= atomic_swap(HLS()->ipi, 0);

  // if we got an IPI, restore it; it will be taken after returning
  if (incoming_ipi) {
    *HLS()->ipi = incoming_ipi;
    mb();
  }
}


void mcall_trap_enclave(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  uintptr_t n = regs[17], arg0 = regs[10], arg1 = regs[11], arg2 = regs[12], arg3 = regs[13], retval, ipi_type;

  switch (n)
  {
    case SBI_CONSOLE_PUTCHAR:
      retval = mcall_console_putchar(arg0);
      break;
    case SBI_CONSOLE_GETCHAR:
      retval = mcall_console_getchar();
      break;
    case SBI_SEND_IPI:
      ipi_type = IPI_SOFT;
      goto send_ipi;
    case SBI_REMOTE_SFENCE_VMA:
    case SBI_REMOTE_SFENCE_VMA_ASID:
      ipi_type = IPI_SFENCE_VMA;
      goto send_ipi;
    case SBI_REMOTE_FENCE_I:
      ipi_type = IPI_FENCE_I;
send_ipi:
      send_ipi_many((uintptr_t*)arg0, ipi_type);
      retval = 0;
      break;
    case SBI_CLEAR_IPI:
      retval = mcall_clear_ipi();
      break;
    case SBI_SHUTDOWN:
      retval = mcall_shutdown();
      break;
    case SBI_SET_TIMER:
#if __riscv_xlen == 32
      retval = mcall_set_timer(arg0 + ((uint64_t)arg1 << 32));
#else
      retval = mcall_set_timer(arg0);
#endif
      break;
#ifdef SM_ENABLED
    case SBI_SM_CREATE_ENCLAVE:
      retval = mcall_sm_create_enclave(arg0);
      break;
    case SBI_SM_DESTROY_ENCLAVE:
      retval = mcall_sm_destroy_enclave(arg0);
      break;
    case SBI_SM_RUN_ENCLAVE:
      retval = mcall_sm_run_enclave(regs, arg0);
      break;
    case SBI_SM_EXIT_ENCLAVE:
      retval = mcall_sm_exit_enclave(regs, arg0);
      break;
    case SBI_SM_STOP_ENCLAVE:
      retval = mcall_sm_stop_enclave(regs, arg0);
      break;
    case SBI_SM_RESUME_ENCLAVE:
      retval = mcall_sm_resume_enclave(regs, arg0);
      break;
    case SBI_SM_ATTEST_ENCLAVE:
      retval = mcall_sm_attest_enclave(arg0, arg1, arg2);
      break;
    case SBI_SM_GET_SEALING_KEY:
      retval = mcall_sm_get_sealing_key(arg0, arg1, arg2);
      break;
    case SBI_SM_RANDOM:
      retval = mcall_sm_random();
      break;
    case SBI_SM_MAILBOX_RECV:
      retval = mcall_sm_recv_msg(arg0, arg1, arg2);
      break;
    case SBI_SM_MAILBOX_SEND:
      retval = mcall_sm_recv_msg(arg0, arg1, arg2);
      break; 
    case SBI_SM_UID:
      retval = mcall_sm_uid(arg0);
      break; 
    case SBI_SM_MEM_SHARE:
      retval = mcall_sm_mem_share(arg0, arg1, arg2); 
      break;
    case SBI_SM_MEM_STOP:
      retval = mcall_sm_mem_stop(arg0);
      break;
    case SBI_SM_NOT_IMPLEMENTED:
      retval = mcall_sm_not_implemented(regs, arg0);
      break;
#endif
    default:
      retval = -ENOSYS;
      break;
  }
  regs[10] = retval;
}



void mcall_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  write_csr(mepc, mepc + 4);

  uintptr_t n = regs[17], arg0 = regs[10], arg1 = regs[11], arg2 = regs[12], arg3 = regs[13], retval, ipi_type;

  switch (n)
  {
    case SBI_CONSOLE_PUTCHAR:
      retval = mcall_console_putchar(arg0);
      break;
    case SBI_CONSOLE_GETCHAR:
      retval = mcall_console_getchar();
      break;
    case SBI_SEND_IPI:
      ipi_type = IPI_SOFT;
      goto send_ipi;
    case SBI_REMOTE_SFENCE_VMA:
    case SBI_REMOTE_SFENCE_VMA_ASID:
      ipi_type = IPI_SFENCE_VMA;
      goto send_ipi;
    case SBI_REMOTE_FENCE_I:
      ipi_type = IPI_FENCE_I;
send_ipi:
      send_ipi_many((uintptr_t*)arg0, ipi_type);
      retval = 0;
      break;
    case SBI_CLEAR_IPI:
      retval = mcall_clear_ipi();
      break;
    case SBI_SHUTDOWN:
      retval = mcall_shutdown();
      break;
    case SBI_SET_TIMER:
#if __riscv_xlen == 32
      retval = mcall_set_timer(arg0 + ((uint64_t)arg1 << 32));
#else
      retval = mcall_set_timer(arg0);
#endif
      break;
#ifdef SM_ENABLED
    case SBI_SM_CREATE_ENCLAVE:
      retval = mcall_sm_create_enclave(arg0);
      break;
    case SBI_SM_DESTROY_ENCLAVE:
      retval = mcall_sm_destroy_enclave(arg0);
      break;
    case SBI_SM_RUN_ENCLAVE:
      retval = mcall_sm_run_enclave(regs, arg0);
      break;
    case SBI_SM_EXIT_ENCLAVE:
      retval = mcall_sm_exit_enclave(regs, arg0);
      break;
    case SBI_SM_STOP_ENCLAVE:
      retval = mcall_sm_stop_enclave(regs, arg0);
      break;
    case SBI_SM_RESUME_ENCLAVE:
      retval = mcall_sm_resume_enclave(regs, arg0);
      if (regs[0]) /* preserve a0 */
        return;
      break;
    case SBI_SM_ATTEST_ENCLAVE:
      retval = mcall_sm_attest_enclave(arg0, arg1, arg2);
      break;
    case SBI_SM_GET_SEALING_KEY:
      retval = mcall_sm_get_sealing_key(arg0, arg1, arg2);
      break;
    case SBI_SM_RANDOM:
      retval = mcall_sm_random();
      break;
    case SBI_SM_CALL_PLUGIN:
      retval = mcall_sm_call_plugin(arg0, arg1, arg2, arg3);
      break;
    case SBI_SM_MAILBOX_SEND:
      retval = mcall_sm_send_msg(arg0, arg1, arg2);
      break;  
    case SBI_SM_MAILBOX_RECV:
      retval = mcall_sm_recv_msg(arg0, arg1, arg2);
      break;
    case SBI_SM_MEM_SHARE: 
      retval = mcall_sm_mem_share(arg0, arg1, arg2);
      break;
    case SBI_SM_MEM_STOP:
      retval = mcall_sm_mem_stop(arg0); 
      break; 
    case SBI_SM_UID:
      retval = mcall_sm_uid(arg0);
      break; 
    case SBI_SM_NOT_IMPLEMENTED:
      retval = mcall_sm_not_implemented(regs, arg0);
      break;
#endif
    default:
      retval = -ENOSYS;
      break;
  }
  regs[10] = retval;
}

void redirect_trap(uintptr_t epc, uintptr_t mstatus, uintptr_t badaddr)
{
  write_csr(sbadaddr, badaddr);
  write_csr(sepc, epc);
  write_csr(scause, read_csr(mcause));
  write_csr(mepc, read_csr(stvec));

  uintptr_t new_mstatus = mstatus & ~(MSTATUS_SPP | MSTATUS_SPIE | MSTATUS_SIE);
  uintptr_t mpp_s = MSTATUS_MPP & (MSTATUS_MPP >> 1);
  new_mstatus |= (mstatus * (MSTATUS_SPIE / MSTATUS_SIE)) & MSTATUS_SPIE;
  new_mstatus |= (mstatus / (mpp_s / MSTATUS_SPP)) & MSTATUS_SPP;
  new_mstatus |= mpp_s;
  write_csr(mstatus, new_mstatus);

  extern void __redirect_trap();
  return __redirect_trap();
}

void pmp_trap(uintptr_t* regs, uintptr_t mcause, uintptr_t mepc)
{
  redirect_trap(mepc, read_csr(mstatus), read_csr(mbadaddr));
}

static void machine_page_fault(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  // MPRV=1 iff this trap occurred while emulating an instruction on behalf
  // of a lower privilege level. In that case, a2=epc and a3=mstatus.
  if (read_csr(mstatus) & MSTATUS_MPRV) {
    return redirect_trap(regs[12], regs[13], read_csr(mbadaddr));
  }
  bad_trap(regs, dummy, mepc);
}

void trap_from_machine_mode(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  uintptr_t mcause = read_csr(mcause);

  switch (mcause)
  {
    case CAUSE_LOAD_PAGE_FAULT:
    case CAUSE_STORE_PAGE_FAULT:
    case CAUSE_FETCH_ACCESS:
    case CAUSE_LOAD_ACCESS:
    case CAUSE_STORE_ACCESS:
      return machine_page_fault(regs, dummy, mepc);
    default:
      bad_trap(regs, dummy, mepc);
  }
}

void poweroff(uint16_t code)
{
  printm("Power off\r\n");
  finisher_exit(code);
  if (htif) {
    htif_poweroff();
  } else {
    send_ipi_many(0, IPI_HALT);
    while (1) { asm volatile ("wfi\n"); }
  }
}
