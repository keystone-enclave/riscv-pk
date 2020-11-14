#include "enclave.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include <string.h>
#include "atomic.h"
#include "platform.h"
#include "task.h"
#include "cpu.h"
#include "crypto.h"
#include "page.h"

struct task tasks[MAX_TASKS_NUM]; 
static spinlock_t task_lock = SPINLOCK_INIT;

/* 
    Task ID is a monotonic counter 
    Assigns unique ID to each task.
    Begins 1 after SCHEDULER_TID  
*/

static size_t task_id = SCHEDULER_TID + 1; 


uintptr_t validate_and_hash_task(struct task *task, struct register_sbi_arg *register_args){

    hash_ctx hash_ctx;
    hash_init(&hash_ctx);

   // hash the init register arguments
  hash_extend(&hash_ctx, register_args, sizeof(struct register_sbi_arg));

  for(uintptr_t ptr = 0; ptr < register_args->size; ptr += 4096){
      hash_extend(&hash_ctx, (char *) register_args->base + ptr, 4096);
  }

  hash_finalize(task->hash, &hash_ctx);
  return 0; 
}

/* Registers task with the SM and returns task ID to identify task. */
uintptr_t mcall_register_task(uintptr_t args){

    uintptr_t ret = -1; 

    if(cpu_get_task_id() != SCHEDULER_TID){
      /* Can only call this SBI call in a scheduler context. */
      return ret; 
  }
   spinlock_lock(&task_lock);

   struct register_sbi_arg *register_args = (struct register_sbi_arg *)args;

   for (int i = 1; i < MAX_TASKS_NUM; i++)
   {
       if (tasks[i].valid == TASK_INVALID)
       {

           tasks[i].valid = TASK_VALID;
           tasks[i].task_id = task_id++;
           tasks[i].regs[0] = register_args->pc;
           tasks[i].enclave = register_args->enclave;

           if (register_args->enclave)
           {
               //Stack pointer will always be the highest address of the EPM
               tasks[i].regs[2] = (uintptr_t)((char *)register_args->sp + register_args->stack_size);

               if (pmp_region_init_atomic(register_args->base, register_args->size, PMP_PRI_ANY, &tasks[i].region.pmp_rid, 0))
               {
                   printm("Task failed to allocate PMP region");
                   ret = -1;
                   goto unlock;
               }

                validate_and_hash_task(&tasks[i], register_args); 

           } else {
                tasks[i].regs[2] = register_args->sp; 
           }
           
           ret = tasks[i].task_id;
           break;
       }
   }

unlock:
    spinlock_unlock(&task_lock);

    return ret; 
}

uintptr_t handle_time_interrupt(uintptr_t* regs){

    /* Set next timer interrupt */
    unsigned long next_cycle = get_cycles64() + DEFAULT_CLOCK_DELAY;
    *HLS()->timecmp = next_cycle;
    clear_csr(mip, MIP_STIP);
    set_csr(mie, MIP_MTIP);

    return mcall_switch_task(regs, 0, RET_TIMER);
}

uintptr_t mcall_switch_task(uintptr_t* regs, uintptr_t next_task_id, uintptr_t ret_type){

    struct task *next_task = NULL; 
    struct task *curr_task = NULL; 

    uintptr_t ret; 

    spinlock_lock(&task_lock);
    /* Get next task */
    for(int i = SCHEDULER_TID; i < MAX_TASKS_NUM; i++){
        if(tasks[i].task_id == next_task_id){
            next_task = &tasks[i]; 
            break; 
        }
    }

    /* Get current task */
    for(int i = SCHEDULER_TID; i < MAX_TASKS_NUM; i++){
        if(tasks[i].task_id == cpu_get_task_id()){
            curr_task = &tasks[i]; 
            break; 
        }
    }

    /* Check if task to switch into is found or if the task switching into is the scheduler. */
    if(!next_task && next_task_id != SCHEDULER_TID){
        ret = ERROR_TASK_INVALID;
        return ret; 
    }

    ret = ret_type;

    if(cpu_get_task_id() == SCHEDULER_TID){
        /* If ARGS is not NULL, that means the scheduler is switching into a task */
        memcpy(tasks[SCHEDULER_TID].regs, regs, 32 * sizeof(uintptr_t));
        tasks[SCHEDULER_TID].regs[0] = read_csr(mepc); 

        //Copy the next task to current registers 
        memcpy(regs, next_task->regs, 32 * sizeof(uintptr_t));
        write_csr(mepc, next_task->regs[0]); 
        cpu_enter_task_context(next_task->task_id);


        if(next_task->enclave){
            /* Flip PMP registers ONLY if the next task is an enclave 
                Not necessary if the next task is unprotected and runs in the scheduler space. 
            */
    
            pmp_set(tasks[SCHEDULER_TID].region.pmp_rid, PMP_NO_PERM);
            pmp_set(next_task->region.pmp_rid, PMP_ALL_PERM);
        }
        
    } else {


        if(curr_task->enclave){
            /* If the task is an enclave, flip the PMP registers */
            pmp_set(tasks[SCHEDULER_TID].region.pmp_rid, PMP_ALL_PERM);
            pmp_set(curr_task->region.pmp_rid, PMP_NO_PERM);
        }

        switch(ret_type){
            /* If the return type is EXIT, scrub the current task */
            case RET_EXIT:
                memset(curr_task, 0, sizeof(struct task)); 
                break;
            /* If the return type is YIELD, save the old registers */
            case RET_YIELD:
                memcpy(curr_task->regs, regs, 32 * sizeof(uintptr_t));
                curr_task->regs[0] = read_csr(mepc) + 4;
                break;
            /* If the return type is an interrupt, restart the instruction */
            case RET_TIMER:
                memcpy(curr_task->regs, regs, 32 * sizeof(uintptr_t));
                curr_task->regs[0] = read_csr(mepc);
                break;
            default:
                ret = ERROR_RET_INVALID;
                return ret; 
        }

        /* All tasks that call switch yields control back to the scheduler */
        memcpy(regs, tasks[SCHEDULER_TID].regs, 32 * sizeof(uintptr_t));
        write_csr(mepc, tasks[SCHEDULER_TID].regs[0]);
        cpu_enter_task_context(SCHEDULER_TID);

    }

    spinlock_unlock(&task_lock);

    return ret; 
}

uintptr_t mcall_enable_interrupt(uintptr_t enable){

  if(cpu_get_task_id() != SCHEDULER_TID){
      /* Can only call this SBI call in a scheduler context. */
      return -1; 
  }

  uintptr_t old_enable = read_csr(mstatus) & MSTATUS_MIE;

  if(enable){
    set_csr(mstatus, MSTATUS_MIE);
  } else {
    clear_csr(mstatus, MSTATUS_MIE);
  }

  return old_enable;

}