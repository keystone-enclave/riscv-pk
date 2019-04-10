//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __THREAD_H__
#define __THREAD_H__

#include <stdint.h>
struct ctx_t
{
  uintptr_t slot;
  uintptr_t ra;
  uintptr_t sp;
  uintptr_t gp;
  uintptr_t tp;
  uintptr_t t0;
  uintptr_t t1;
  uintptr_t t2;
  uintptr_t s0;
  uintptr_t s1;
  uintptr_t a0;
  uintptr_t a1;
  uintptr_t a2;
  uintptr_t a3;
  uintptr_t a4;
  uintptr_t a5;
  uintptr_t a6;
  uintptr_t a7;
  uintptr_t s2;
  uintptr_t s3;
  uintptr_t s4;
  uintptr_t s5;
  uintptr_t s6;
  uintptr_t s7;
  uintptr_t s8;
  uintptr_t s9;
  uintptr_t s10;
  uintptr_t s11;
  uintptr_t t3;
  uintptr_t t4;
  uintptr_t t5;
  uintptr_t t6;
};

struct csrs_t
{
  uintptr_t sstatus;    //Supervisor status register.
  uintptr_t sedeleg;    //Supervisor exception delegation register.
  uintptr_t sideleg;    //Supervisor interrupt delegation register.
  uintptr_t sie;        //Supervisor interrupt-enable register.
  uintptr_t stvec;      //Supervisor trap handler base address.
  uintptr_t scounteren; //Supervisor counter enable

  /*  Supervisor Trap Handling */
  uintptr_t sscratch;   //Scratch register for supervisor trap handlers.
  uintptr_t sepc;       //Supervisor exception program counter.
  uintptr_t scause;     //Supervisor trap cause.
  //NOTE: This should be stval, toolchain issue?
  uintptr_t sbadaddr;   //Supervisor bad address.
  uintptr_t sip;        //Supervisor interrupt pending.

  /*  Supervisor Protection and Translation */
  uintptr_t satp;     //Page-table base register.

};

/* enclave thread state */
struct thread_state_t
{
  uintptr_t prev_mepc;
  struct csrs_t prev_csrs;
  struct ctx_t prev_state;
};

/* swap previous and current thread states */
void swap_prev_state(struct thread_state_t* state, uintptr_t* regs);
void swap_prev_mepc(struct thread_state_t* state, uintptr_t mepc);
void swap_prev_smode_csrs(struct thread_state_t* thread);

/* Clean state generation */
void clean_state(struct thread_state_t* state);
void clean_smode_csrs(struct thread_state_t* state);
#endif /* thread */
