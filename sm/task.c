#include "enclave.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include <string.h>
#include "atomic.h"
#include "platform.h"
#include "task.h"
#include "cpu.h"

struct task tasks[MAX_TASKS_NUM]; 

/* 
    Task ID is a monotonic counter 
    Assigns unique ID to each task.
    Begins 1 after SCHEDULER_TID  
*/

static size_t task_id = SCHEDULER_TID + 1; 


/* Registers task with the SM and returns task ID to identify task. */
uintptr_t mcall_register_task(uintptr_t args){

    uintptr_t ret = -1; 

    struct register_sbi_arg *register_args = (struct register_sbi_arg *) args; 

    for(int i = 1; i < MAX_TASKS_NUM; i++){
        if(tasks[i].valid == TASK_INVALID){
            tasks[i].valid = TASK_VALID; 
            tasks[i].task_id = task_id++;
            tasks[i].mepc = register_args->mepc;
            tasks[i].regs[2] = register_args->sp; 

            ret = tasks[i].task_id; 
            break; 
        }
    }

    return ret; 
}

uintptr_t mcall_switch_task(uintptr_t* regs, uintptr_t next_task_id, uintptr_t ret_type){

    // struct switch_sbi_arg *switch_args = (struct switch_sbi_arg *) args;

    struct task *next_task = NULL; 
    uintptr_t ret; 

    for(int i = SCHEDULER_TID + 1; i < MAX_TASKS_NUM; i++){
        if(tasks[i].task_id == next_task_id){
            next_task = &tasks[i]; 
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
        tasks[SCHEDULER_TID].mepc = read_csr(mepc);
        memcpy(tasks[SCHEDULER_TID].regs, regs, 32 * sizeof(uintptr_t));

        write_csr(mepc, next_task->mepc); 
        cpu_enter_task_context(next_task->task_id);
    } else {
        /* All tasks that call switch yields control back to the scheduler */
        memcpy(regs, tasks[SCHEDULER_TID].regs, 32 * sizeof(uintptr_t));
        write_csr(mepc, tasks[SCHEDULER_TID].mepc);
        cpu_enter_task_context(SCHEDULER_TID);
    }
    
    return ret; 
}