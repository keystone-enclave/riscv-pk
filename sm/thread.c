//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "thread.h"
#include "mtrap.h"


 void switch_vector_enclave(){
  extern void trap_vector_enclave(); 
  write_csr(mtvec, &trap_vector_enclave);
}

void switch_vector_host(){
  extern void trap_vector();
  write_csr(mtvec, &trap_vector);
}

uint64_t getRTC(){
	return *mtime;
}

void swap_prev_mpp(struct thread_state* thread, uintptr_t* regs){
  //Time interrupts can occur in either user mode or supervisor mode

  int curr_mstatus = read_csr(mstatus);
  int old_mpp = thread->prev_mpp;
  if(old_mpp < 0){
   //Old MPP bit isn't initialized!
   old_mpp = curr_mstatus & 0x800;
  }
  thread->prev_mpp = curr_mstatus & 0x800;
  int new_mstatus = (curr_mstatus & ~0x800) | old_mpp;
  write_csr(mstatus, new_mstatus);
}

/* Swaps the entire s-mode visible state, general registers and then csrs */
inline void swap_prev_state(struct thread_state* thread, uintptr_t* regs, int return_on_resume)
{
  int i;

  uintptr_t* prev = (uintptr_t*) &thread->prev_state;
  // for(i=0; i<32; i++)
  // {
  //   /* swap state */
  //   uintptr_t tmp = prev[i];
  //   prev[i] = regs[i];
  //   regs[i] = tmp;
  // }

  uintptr_t tmp;

  /* swap state */
  tmp = prev[0];
  prev[0] = regs[0];
  regs[0] = tmp;
  tmp = prev[1];
  prev[1] = regs[1];
  regs[1] = tmp;
  tmp = prev[2];
  prev[2] = regs[2];
  regs[2] = tmp;
  tmp = prev[3];
  prev[3] = regs[3];
  regs[3] = tmp;
  tmp = prev[4];
  prev[4] = regs[4];
  regs[4] = tmp;
  tmp = prev[5];
  prev[5] = regs[5];
  regs[5] = tmp;
  tmp = prev[6];
  prev[6] = regs[6];
  regs[6] = tmp;
  tmp = prev[7];
  prev[7] = regs[7];
  regs[7] = tmp;
  tmp = prev[8];
  prev[8] = regs[8];
  regs[8] = tmp;
  tmp = prev[9];
  prev[9] = regs[9];
  regs[9] = tmp;
  tmp = prev[10];
  prev[10] = regs[10];
  regs[10] = tmp;
  tmp = prev[11];
  prev[11] = regs[11];
  regs[11] = tmp;
  tmp = prev[12];
  prev[12] = regs[12];
  regs[12] = tmp;
  tmp = prev[13];
  prev[13] = regs[13];
  regs[13] = tmp;
  tmp = prev[14];
  prev[14] = regs[14];
  regs[14] = tmp;
  tmp = prev[15];
  prev[15] = regs[15];
  regs[15] = tmp;
  tmp = prev[16];
  prev[16] = regs[16];
  regs[16] = tmp;
  tmp = prev[17];
  prev[17] = regs[17];
  regs[17] = tmp;
  tmp = prev[18];
  prev[18] = regs[18];
  regs[18] = tmp;
  tmp = prev[19];
  prev[19] = regs[19];
  regs[19] = tmp;
  tmp = prev[20];
  prev[20] = regs[20];
  regs[20] = tmp;
  tmp = prev[21];
  prev[21] = regs[21];
  regs[21] = tmp;
  tmp = prev[22];
  prev[22] = regs[22];
  regs[22] = tmp;
  tmp = prev[23];
  prev[23] = regs[23];
  regs[23] = tmp;
  tmp = prev[24];
  prev[24] = regs[24];
  regs[24] = tmp;
  tmp = prev[25];
  prev[25] = regs[25];
  regs[25] = tmp;
  tmp = prev[26];
  prev[26] = regs[26];
  regs[26] = tmp;
  tmp = prev[27];
  prev[27] = regs[27];
  regs[27] = tmp;
  tmp = prev[28];
  prev[28] = regs[28];
  regs[28] = tmp;
  tmp = prev[29];
  prev[29] = regs[29];
  regs[29] = tmp;
  tmp = prev[30];
  prev[30] = regs[30];
  regs[30] = tmp;
  tmp = prev[31];
  prev[31] = regs[31];
  regs[31] = tmp;

  prev[0] = !return_on_resume;

  swap_prev_smode_csrs(thread);

  return;
}

/* Swaps all s-mode csrs defined in 1.10 standard */
/* TODO: Right now we are only handling the ones that our test
   platforms support. Realistically we should have these behind
   defines for extensions (ex: N extension)*/
void swap_prev_smode_csrs(struct thread_state*
thread){

  uintptr_t tmp;

#define LOCAL_SWAP_CSR(csrname) \
  tmp = thread->prev_csrs.csrname;                 \
  thread->prev_csrs.csrname = read_csr(csrname);   \
  write_csr(csrname, tmp);

  LOCAL_SWAP_CSR(sstatus);
  // These only exist with N extension.
  //LOCAL_SWAP_CSR(sedeleg);
  //LOCAL_SWAP_CSR(sideleg);
  LOCAL_SWAP_CSR(sie);
  LOCAL_SWAP_CSR(stvec);
  LOCAL_SWAP_CSR(scounteren);
  LOCAL_SWAP_CSR(sscratch);
  LOCAL_SWAP_CSR(sepc);
  LOCAL_SWAP_CSR(scause);
  LOCAL_SWAP_CSR(sbadaddr);
  LOCAL_SWAP_CSR(sip);
  LOCAL_SWAP_CSR(satp);

#undef LOCAL_SWAP_CSR
}

void swap_prev_mepc(struct thread_state* thread, uintptr_t current_mepc)
{
  uintptr_t tmp = thread->prev_mepc;
  thread->prev_mepc = current_mepc;
  write_csr(mepc, tmp);
}


void clean_state(struct thread_state* state){
  int i;
  uintptr_t* prev = (uintptr_t*) &state->prev_state;
  // for(i=1; i<32; i++)
  // {
  //   prev[i] = 0;
  // }
  prev[1] = 0; prev[2] = 0; prev[3] = 0; prev[4] = 0; prev[5] = 0;
  prev[6] = 0; prev[7] = 0; prev[8] = 0; prev[9] = 0; prev[10] = 0;
  prev[11] = 0; prev[12] = 0; prev[13] = 0; prev[14] = 0; prev[15] = 0;
  prev[16] = 0; prev[17] = 0; prev[18] = 0; prev[19] = 0; prev[20] = 0;
  prev[21] = 0; prev[22] = 0; prev[23] = 0; prev[24] = 0; prev[25] = 0;
  prev[26] = 0; prev[27] = 0; prev[28] = 0; prev[29] = 0; prev[30] = 0;
  prev[31] = 0;

  state->prev_mpp = -1; // 0x800;
  clean_smode_csrs(state);
}

void clean_smode_csrs(struct thread_state* state){

  state->prev_csrs.sstatus = 0;

  // We can't read these or set these from M-mode?
  state->prev_csrs.sedeleg = 0;
  state->prev_csrs.sideleg = 0;

  state->prev_csrs.sie = 0;
  state->prev_csrs.stvec = 0;
  // For now we take whatever the OS was doing
  state->prev_csrs.scounteren = read_csr(scounteren);
  state->prev_csrs.sscratch = 0;
  state->prev_csrs.sepc = 0;
  state->prev_csrs.scause = 0;
  state->prev_csrs.sbadaddr = 0;
  state->prev_csrs.sip = 0;
  state->prev_csrs.satp = 0;

}
