#include "waymasks.h"

void waymask_debug_printstatus(){
  unsigned int hartid = read_csr(mhartid);
  printm("mhartid: %x, corecontrollers: %x & %x\r\n",hartid, (hartid)*2, (hartid)*2 + 1);

  unsigned int controller;
  for(controller=0;controller<WM_NUM_CONTROLLERS;controller++){
    waymask_t* controller_mask = WM_REG_ADDR(controller);
    printm("Controller %x : %0.8x\r\n",controller, *controller_mask);
  }
}

size_t waymask_allocate_ways(size_t n_ways, unsigned int target_hart,
                             waymask_t* mask){

  *mask = 0;
  size_t remaining = _wm_choose_ways_for_hart(n_ways, mask, target_hart);

  if(remaining  == n_ways){
    //fatal, should never happen
    return -1;
  }

  // TODO intelligently handle having remaining > 0

  // Mark these ways as used by an enclave
  enclave_allocated_ways |= *mask;
  allocated_ways |= *mask;

  return remaining;
}

int controller_is_for_hart(unsigned int controller, unsigned int hart){
  return(controller == hart*2 || controller == hart*2 + 1);
}

void waymask_apply_allocated_mask(waymask_t mask, unsigned int target_hart){

  // Lockout/assign controllers from these ways
  unsigned int controller;
  for(controller=0;controller<WM_NUM_CONTROLLERS;controller++){

    // Hard assign if the controller is ours, otherwise lockout
    // If its our controller, we want it ONLY using this mask
    if(controller_is_for_hart(controller, target_hart)){
      _wm_assign_mask(mask, controller);
    }
    else{
      _wm_lockout_ways(mask, controller);
    }
  }
}

void waymask_free_ways(waymask_t _mask){
  unsigned int controller;
  for(controller=0; controller < WM_NUM_CONTROLLERS; controller++){
    if(IS_CONTROLLER_RUNNING_UNTRUSTED( controller )){
      // Grant it
      _wm_grant_ways(_mask, controller);
    }
    // We don't enable new free ways on harts running trusted code
  }

  // Re-enable those ways as free to be allocated
  enclave_allocated_ways &= WM_FLIP_MASK(_mask);
  allocated_ways &= WM_FLIP_MASK(_mask);
}

// Simplest possible way choosing, with reserved way for each hart
// Returns number of ways it couldn't allocate
int _wm_choose_ways_for_hart(size_t n_ways, waymask_t* mask, unsigned int target_hart){

  *mask = 0;
  // Best effort, we may not be able to allocate n_ways
  if(n_ways == 0)
    return 0;

  // Always allocate our 'reserved' way if available
  if(! IS_WAY_ALLOCATED( GET_HART_WAY(target_hart) )){
    *mask |= (0x1 << GET_HART_WAY(target_hart));
    n_ways--;
  }

  // Find ways to allocate as available, ignoring reserved hart ways
  int way = WM_MIN_FREE_WAY;
  while(n_ways > 0 && way <= WM_MAX_FREE_WAY){
    if( !IS_WAY_ALLOCATED(way) ){
      *mask |= (0x1 << way);
      n_ways--;
    }
    way++;
  }

  // Return number of UNallocated ways
  return n_ways;
}

// This will DISABLE the given ways
int _wm_lockout_ways(waymask_t mask, unsigned int controller){

  if(controller > WM_NUM_CONTROLLERS){
    return  -1;
  }

  //Note that we DO allow entirely locking out a controller
  // Supposedly this isn't allowed, we'll see what happens.
  // "At least one cache way must be enabled. "
  waymask_t* controller_mask = WM_REG_ADDR(controller);
  waymask_t current_mask = *controller_mask;
  *controller_mask = current_mask & WM_FLIP_MASK(mask);
  return 0;
}

// This will GRANT ACCESS to the given ways
int _wm_grant_ways(waymask_t mask, unsigned int controller){

  if(controller > WM_NUM_CONTROLLERS){
    return  -1;
  }

  waymask_t* controller_mask = WM_REG_ADDR(controller);

  *controller_mask |= mask;
  return 0;
}

// Just hard set ways for a controller
int _wm_assign_mask(waymask_t mask, unsigned int controller){

  if(controller > WM_NUM_CONTROLLERS){
    return  -1;
  }

  waymask_t* controller_mask = WM_REG_ADDR(controller);

  *controller_mask = mask;
  return 0;
}

void waymask_init(){
  allocated_ways = 0;
  enclave_allocated_ways = 0;
  scratchpad_allocated_ways = 0;
}

void waymask_allocate_scratchpad(){

  /* Avoid the 'special' ways we reserve for cores */
  waymask_t mask = 0xF00 | 0x80 | 0x1000 | 0x2000 | 0x4000;

  /* tmp sanity check */
  if( (allocated_ways & mask) != 0){
    printm("Cannot allocate ways for scratchpad, in use!\r\n");
    return;
  }

  scratchpad_allocated_ways = mask;
  allocated_ways |= scratchpad_allocated_ways;
}

void waymask_free_scratchpad(){

  allocated_ways &= WM_FLIP_MASK(scratchpad_allocated_ways);
  scratchpad_allocated_ways = 0;

}


/* TODO check this is the right way to clear */
void waymask_clear_ways(waymask_t mask, unsigned int core){

  /* L2 Scratchpad (L2 Zero Device) allows us to write to non-memory
     backed locations. We'll do one way at a time, writing once to
     each cache set */

  int cur_mask = 0;
  int i,j = 0;
  for(i=0; i < WM_NUM_WAYS; i++){
    cur_mask = 1<<i;

    /* Only clear the way if we need to */
    if( cur_mask & mask ){

      /* Only set the data cache waymask. */
      _wm_assign_mask(cur_mask, GET_CORE_DWAY(core));

      /* We iterate by line size, one for each set */
      uintptr_t next = L2_SCRATCH_START;
      for(j=0; j < L2_NUM_SETS; next+=L2_LINE_SIZE, j++){
        *(uintptr_t*)next = 0;
      }
    }
  }

  /* Reset the mask ways, only d$ again */
  _wm_assign_mask(mask, GET_CORE_DWAY(core));

}
