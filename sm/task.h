#ifndef _TASK_H_
#define _TASK_H_

#include "sm.h"
#include "bits.h"
#include "vm.h"
#include "pmp.h"
#include "thread.h"
#include "crypto.h"

#define SCHEDULER_TID 0

#define RTOS_ENABLED 1
#define MAX_TASKS_NUM 32 
#define TASK_VALID 1
#define TASK_INVALID 0

#define SBI_ENABLE_INTERRUPT     200
#define SBI_SWITCH_TASK          201
#define SBI_REGISTER_TASK        202

#define RET_EXIT 0 
#define RET_YIELD 1
#define RET_TIMER 2

#define ERROR_TASK_INVALID 10
#define ERROR_RET_INVALID 11

#define DEFAULT_CLOCK_DELAY 10000

struct switch_sbi_arg {
    uintptr_t mepc;
	uintptr_t task_id; 
}; 

struct register_sbi_arg {
    uintptr_t mepc;
	uintptr_t sp; 
}; 


struct regs {
	uintptr_t pc; // Interrupted PC 
	uintptr_t ra; // x1
    uintptr_t sp; // x2
	uintptr_t t0; // x5
	uintptr_t t1; // x6
	uintptr_t t2; // x7 
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


struct task {
    uintptr_t regs[32];  
	uintptr_t mepc; 
	uintptr_t task_id; 
    uintptr_t valid; 
}; 


uintptr_t mcall_switch_task(uintptr_t* regs, uintptr_t next_task_id, uintptr_t ret_type);
uintptr_t mcall_register_task(uintptr_t args);
uintptr_t handle_time_interrupt(uintptr_t* regs); 


typedef unsigned long cycles_t;

static inline cycles_t get_cycles_inline(void)
{
	cycles_t n;

	__asm__ __volatile__ (
		"rdtime %0"
		: "=r" (n));
	return n;
}
#define get_cycles get_cycles_inline

static inline uint64_t get_cycles64(void)
{
        return get_cycles();
}

#define ARCH_HAS_READ_CURRENT_TIMER

static inline int read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_cycles();
	return 0;
}


#endif
