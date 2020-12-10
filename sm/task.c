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

extern byte dev_public_key[PUBLIC_KEY_SIZE];

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
           tasks[i].regs[10] = register_args->arg; 
           tasks[i].enclave = register_args->enclave;
           init_mailbox(&tasks[i].mailbox);

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

struct task *find_task(int task_id){
    struct task *ptr = NULL; 

    for(int i = SCHEDULER_TID; i < MAX_TASKS_NUM; i++){
        if(tasks[i].task_id == task_id){
            ptr = &tasks[i];
            goto find_task_done;
        }
    }

find_task_done:
    return ptr; 
}


void switch_into_task(uintptr_t* regs, struct task *next_task){
    //Copy the next task to current registers 
    memcpy(regs, next_task->regs, 32 * sizeof(uintptr_t));
    write_csr(mepc, next_task->regs[0]); 
    cpu_enter_task_context(next_task->task_id);
}

uintptr_t mcall_switch_task(uintptr_t* regs, uintptr_t next_task_id, uintptr_t ret_type){

    struct task *next_task = NULL; 
    struct task *curr_task = NULL; 

    uintptr_t ret; 

    spinlock_lock(&task_lock);

    /* Get next task */
    next_task = find_task(next_task_id);
    /* Get current task */
    curr_task = find_task(cpu_get_task_id()); 

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

        switch_into_task(regs, next_task);
        ret = regs[10]; 

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
            case RET_RECV_WAIT:
                memcpy(curr_task->regs, regs, 32 * sizeof(uintptr_t));
                curr_task->regs[0] = read_csr(mepc);
                break;
            default:
                ret = ERROR_RET_INVALID;
                return ret; 
        }

        /* All tasks that call switch yields control back to the scheduler */
        switch_into_task(regs, next_task); 
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



enclave_ret_code mcall_attest_task(uintptr_t report_ptr, uintptr_t data, uintptr_t size)
{
    uintptr_t task_id = cpu_get_task_id(); 
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return -1;

  spinlock_lock(&task_lock);
  
  attestable = ((task_id < 32|| task_id >= 0)
                && tasks[task_id].valid == TASK_VALID);

  if(!attestable) {
    ret = ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  memcpy(report.enclave.data,
      (void *) data, size);
  report.enclave.data_len = size;


  spinlock_unlock(&task_lock); // Don't need to wait while signing, which might take some time

  memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  memcpy(report.sm.hash, sm_hash, MDSIZE);
  memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  memcpy(report.enclave.hash, tasks[task_id].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spinlock_lock(&task_lock);

  /* copy report to the enclave */
  memcpy((void *) report_ptr, &report, sizeof(struct report));
      
  ret = ENCLAVE_SUCCESS;

err_unlock:
  spinlock_unlock(&task_lock);
  return ret;
}

int task_recv_msg(uintptr_t* regs, int tid, void *buf, size_t msg_size)
{

    struct task *task = find_task(cpu_get_task_id());

    struct mailbox *mailbox = &task->mailbox;
    uint8_t *ptr = (uint8_t *)mailbox->data;
    struct mailbox_header *hdr = (struct mailbox_header *)ptr;
    size_t size = 0;
    size_t hdr_size = 0;

    spinlock_lock(&(mailbox->lock));

    while (size < mailbox->size)
    {

        hdr_size = hdr->size;

        if (hdr->send_uid == tid)
        {
            //Check if the message is bigger than the buffer.
            if (hdr->size > msg_size)
            {
                spinlock_unlock(&(mailbox->lock));
                return 1;
            }

            memcpy(buf, hdr->data, msg_size);

            //Clear the message from the mailbox
            memset(hdr->data, 0, hdr->size);
            memset(hdr, 0, sizeof(struct mailbox_header));
            memcpy(hdr, ptr + hdr_size + sizeof(struct mailbox_header), mailbox->size - (size + sizeof(struct mailbox_header) + hdr_size));

            mailbox->size -= hdr_size + sizeof(struct mailbox_header);
            spinlock_unlock(&(mailbox->lock));
            return 0;
        }
        size += sizeof(struct mailbox_header) + hdr_size;
        ptr += sizeof(struct mailbox_header) + hdr_size;
        hdr = (struct mailbox_header *)ptr;
    }
    //Release lock on mailbox
    spinlock_unlock(&(mailbox->lock));

    //Message doesn't exist!

    return mcall_switch_task(regs, 0, RET_RECV_WAIT);
}

int task_send_msg(int tid, void *buf, size_t msg_size)
{

    struct task *task = find_task(tid);

    struct mailbox *mbox = &task->mailbox;

    spinlock_lock(&(mbox->lock));

    //Check if the message + header can fit in the mailbox.
    if (mbox->capacity - mbox->size < msg_size + sizeof(struct mailbox_header))
    {
        spinlock_unlock(&(mbox->lock));
        return 0;
    }

    struct mailbox_header hdr;
    hdr.send_uid = cpu_get_task_id();
    hdr.size = msg_size;

    memcpy(mbox->data + mbox->size, &hdr, sizeof(hdr));
    memcpy(mbox->data + mbox->size + sizeof(hdr), buf, msg_size);
    mbox->size += msg_size + sizeof(hdr);

    spinlock_unlock(&(mbox->lock));

    return 0;
}
