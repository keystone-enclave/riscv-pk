#ifndef _TASK_H_
#define _TASK_H_

#include "sm.h"
#include "bits.h"
#include "vm.h"
#include "pmp.h"
#include "thread.h"
#include "crypto.h"
#include "enclave.h"

#define SCHEDULER_TID 0

#define RTOS_ENABLED 1
#define MAX_TASKS_NUM 32 
#define TASK_VALID 1
#define TASK_INVALID 0

#define SBI_ENABLE_INTERRUPT     200
#define SBI_SWITCH_TASK          201
#define SBI_REGISTER_TASK        202
#define SBI_ATTEST_TASK          203
#define SBI_SEND_TASK        	 204
#define SBI_RECV_TASK            205

#define RET_EXIT 0 
#define RET_YIELD 1
#define RET_TIMER 2
#define RET_RECV_WAIT 3 

#define ERROR_TASK_INVALID 10
#define ERROR_RET_INVALID 11

#define DEFAULT_CLOCK_DELAY 10000

#define RTOS_START 0x80400000
#define RTOS_SIZE 0x16000

typedef enum {
	TASK_DESTROYING,
	TASK_FRESH,
	TASK_RUNNING,
} task_state;

struct register_sbi_arg {
    uintptr_t pc;
	uintptr_t sp; 
	uintptr_t arg; 
	uintptr_t stack_size; 
	uintptr_t base;
	uintptr_t size;  
	uintptr_t enclave; 
}; 

struct task {
    uintptr_t regs[32];  

	uintptr_t enclave; 
	
	uintptr_t base;
	uintptr_t size; 

	//PMP region of the task. 
	struct enclave_region region; 

	// global state of the task
	task_state state; 

	/* Unique identifier for task ID */
	uintptr_t task_id; 

	uintptr_t ret_task_id; 
	uintptr_t destroyed; 

	/* measurement */
	byte hash[MDSIZE];
	byte sign[SIGNATURE_SIZE];

	struct mailbox mailbox; 

	/* Whether task slot is valid */
    uintptr_t valid; 
	
	/* Whether task is waiting on msg */
	uintptr_t wait_recv; 
	uintptr_t wait_done; 
	uintptr_t recv_buf; 
}; 


uintptr_t mcall_switch_task(uintptr_t* regs, uintptr_t next_task_id, uintptr_t ret_type);
uintptr_t mcall_register_task(uintptr_t args);
uintptr_t mcall_enable_interrupt(); 
uintptr_t handle_time_interrupt(uintptr_t* regs); 

uintptr_t validate_and_hash_task(struct task *task, struct register_sbi_arg *register_args);

int task_recv_msg(uintptr_t* regs, int tid, void *buf, size_t msg_size);
int task_send_msg(uintptr_t* regs, int tid, void *buf, size_t msg_size, uintptr_t yield);
enclave_ret_code mcall_attest_task(uintptr_t report_ptr, uintptr_t data, uintptr_t size);

struct task *find_task(int task_id); 


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
