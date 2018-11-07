#include "pmp.h"
#include "mtrap.h"
#include "atomic.h"
#include "fdt.h"
#include "disabled_hart_mask.h"

static uint32_t reg_bitmap = 0;
static uint32_t region_def_bitmap = 0;
static struct pmp_region regions[PMP_MAX_N_REGION];

/* PMP IPI mailbox */
typedef struct {
  uint8_t pending;
  uint8_t perm;
} ipi_msg_t;

static ipi_msg_t ipi_mailbox[MAX_HARTS] = {0,};
static int ipi_region_idx = -1;
static enum ipi_type {IPI_PMP_INVALID=-1, 
                      IPI_PMP_SET, 
                      IPI_PMP_UNSET} ipi_type = IPI_PMP_INVALID;

/* PMP IPI global lock */
static spinlock_t pmp_ipi_global_lock = SPINLOCK_INIT;

static spinlock_t pmp_lock = SPINLOCK_INIT;

static int is_pmp_region_valid(int region_idx) {
  return TEST_BIT(region_def_bitmap, region_idx);
}

int search_rightmost_unset(uint32_t bitmap, int max) {
  int i;
  uint32_t mask = 0x1;
  for(i=0; i<max; i++) {
    if( ~bitmap & mask )
      return i;
    mask = mask << 1;
  }
  return -1;
}

int get_free_region_idx() {
  return search_rightmost_unset(region_def_bitmap, PMP_MAX_N_REGION);
}

int get_free_reg_idx() {
  return search_rightmost_unset(reg_bitmap, PMP_N_REG);
}

void handle_pmp_ipi(uintptr_t* regs, uintptr_t dummy, uintptr_t mepc)
{
  if(ipi_type == IPI_PMP_SET) 
  {
    uint8_t perm = ipi_mailbox[read_csr(mhartid)].perm;
    pmp_set(ipi_region_idx, perm);
  }
  else 
  {
    pmp_unset(ipi_region_idx);
  }

  ipi_mailbox[read_csr(mhartid)].pending = 0;
  return;
}

static int detect_region_overlap(uintptr_t addr, uintptr_t size)
{
  void* epm_base;
  size_t epm_size;
  int region_overlap = 0, i;

  /* CAUTION: the caller should use pmp_lock to synchronize */

  for(i=0; i<PMP_MAX_N_REGION; i++)
  {
    if(!is_pmp_region_valid(i))
      continue;

    struct pmp_region region = regions[i];
    if(region.allow_overlap) {
      continue;
    }
    
    epm_base = (void*) region.addr;
    epm_size = region.size;

    region_overlap |= ((uintptr_t) epm_base < addr + size) &&
                      ((uintptr_t) epm_base + epm_size > addr);
  }
  
  return region_overlap;
}

int detect_region_overlap_atomic(uintptr_t addr, uintptr_t size)
{
  int region_overlap = 0;
  spinlock_lock(&pmp_lock);
  region_overlap = detect_region_overlap(addr, size);
  spinlock_unlock(&pmp_lock);
  return region_overlap;
}

static void send_pmp_ipi(uintptr_t recipient, uint8_t perm)
{
  if (((disabled_hart_mask >> recipient) & 1)) return;
  /* never send IPI to my self; it will result in a deadlock */
  if (recipient == read_csr(mhartid)) return;
  atomic_or(&OTHER_HLS(recipient)->mipi_pending, IPI_PMP);
  mb();
  ipi_mailbox[recipient].pending = 1;
  ipi_mailbox[recipient].perm = perm & PMP_ALL_PERM;
  *OTHER_HLS(recipient)->ipi = 1;
}

static void send_and_sync_pmp_ipi(int region_idx, enum ipi_type type, uint8_t perm)
{
  uintptr_t mask = hart_mask;
  ipi_region_idx = region_idx;
  ipi_type = type;

  for(uintptr_t i=0, m=mask; m; i++, m>>=1)
  {
    if(m & 1) {
      send_pmp_ipi(i, perm);
    }
  }

  /* wait until every other hart sets PMP */
  for(uintptr_t i=0, m=mask; m; i++, m>>=1) {
    if(m & 1) {
      while( atomic_read(&ipi_mailbox[i].pending) ) {
        continue;
      }
    }
  }
}

int pmp_unset_global(int region_idx)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");

  /* We avoid any complex PMP-related IPI management
   * by ensuring only one hart can enter this region at a time */
#ifdef __riscv_atomic
  spinlock_lock(&pmp_ipi_global_lock);
  send_and_sync_pmp_ipi(region_idx, IPI_PMP_UNSET, PMP_NO_PERM);
  spinlock_unlock(&pmp_ipi_global_lock);
#endif
  /* unset PMP of itself */
  pmp_unset(region_idx);
  
  return PMP_SUCCESS;
}

/* populate pmp set command to every other hart */
int pmp_set_global(int region_idx, uint8_t perm)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");

  /* We avoid any complex PMP-related IPI management
   * by ensuring only one hart can enter this region at a time */
#ifdef __riscv_atomic
  spinlock_lock(&pmp_ipi_global_lock);
  send_and_sync_pmp_ipi(region_idx, IPI_PMP_SET, perm);
  spinlock_unlock(&pmp_ipi_global_lock);
#endif
  /* set PMP of itself */
  pmp_set(region_idx, perm);
  return PMP_SUCCESS;
}

int pmp_set(int region_idx, uint8_t perm)
{ 
  if(!is_pmp_region_valid(region_idx)) 
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");
 
  uint8_t perm_bits = perm & PMP_ALL_PERM;
  int reg_idx = regions[region_idx].reg_idx;
  uintptr_t pmpcfg = (uintptr_t) (regions[region_idx].addrmode | perm_bits) << (8*(reg_idx%PMP_PER_GROUP));
  uintptr_t pmpaddr = regions[region_idx].addr;

  /*spinlock_lock(&pmp_lock);
  printm("pmp_set() [hart %d]: pmpreg %d, address:%lx, size:%lx, perm: 0x%x\n", 
      read_csr(mhartid), reg_idx, regions[region_idx].addr<<2, regions[region_idx].size, perm);
  spinlock_unlock(&pmp_lock);
  */
  int n=reg_idx;
  switch(n) {
#define X(n,g) case n: { PMP_SET(n, g, pmpaddr, pmpcfg); break; }
  LIST_OF_PMP_REGS
#undef X
    default:  
      die("pmp_set failed: this must not be tolerated\n");
  } 

  return PMP_SUCCESS;
}

int pmp_unset(int region_idx)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID,"Invalid PMP region index");

  int reg_idx = regions[region_idx].reg_idx;
  int n=reg_idx;
  switch(n) {
#define X(n,g) case n: { PMP_UNSET(n, g); break;}
  LIST_OF_PMP_REGS
#undef X
    default:
      die("pmp_unset failed: this must not be tolerated\n");
  }
  
  /* spinlock_lock(&pmp_lock);
  printm("pmp_unset() [hart %d]: pmpreg %d, address:%lx, size:%lx\n", 
      read_csr(mhartid), reg_idx, regions[region_idx].addr<<2, regions[region_idx].size);
  spinlock_unlock(&pmp_lock);
  */
  return PMP_SUCCESS;
}

int pmp_region_debug_print(int region_idx)
{
  if(!is_pmp_region_valid(region_idx))
    PMP_ERROR(PMP_REGION_INVALID,"Invalid PMP region index");
 
  uintptr_t start = regions[region_idx].start;
  uint64_t size = regions[region_idx].size;
  uint8_t addrmode = regions[region_idx].addrmode;
  uintptr_t addr = regions[region_idx].addr;
  int reg_idx = regions[region_idx].reg_idx;

  printm("start: 0x%llx\n"
    "size: 0x%llx (%d)\n"
    "addrmode: 0x%x\n"
    "addr<<3: 0x%llx\n"
    "reg_idx: %d\n"
   , start, size, size, addrmode, addr<<3, reg_idx ); 

  return PMP_SUCCESS;  
}


int pmp_region_init_atomic(uintptr_t start, uint64_t size, enum pmp_priority priority, int* rid, int allow_overlap)
{
  int ret;
  spinlock_lock(&pmp_lock);
  ret = pmp_region_init(start, size, priority, rid, allow_overlap);
  spinlock_unlock(&pmp_lock);
  return ret;
}

int pmp_region_init(uintptr_t start, uint64_t size, enum pmp_priority priority, int* rid, int allow_overlap)
{
  uintptr_t pmp_address;
  int reg_idx = -1;
  int region_idx = -1;
  int region_overlap = 0, i = 0;

  /* if region covers the entire RAM */
  if(size == -1UL && start == 0)
  {
    pmp_address = -1UL;
  }
  else
  {
    // size should be power of 2
    if(!(size && !(size&(size-1))))
      PMP_ERROR(PMP_REGION_SIZE_INVALID, "PMP size should be power of 2");

    // size should be page granularity
    if(size & (RISCV_PGSIZE - 1))
      PMP_ERROR(PMP_REGION_NOT_PAGE_GRANULARITY, "PMP granularity is RISCV_PGSIZE");

    // the starting address must be naturally aligned
    if(start & (size-1))
      PMP_ERROR(PMP_REGION_NOT_ALIGNED, "PMP region should be naturally aligned");

    pmp_address = (start | (size/2-1)) >> 2;
  }

  /* overlap detection */
  if (!allow_overlap) {
    if (detect_region_overlap(start, size)) {
      return PMP_REGION_OVERLAP;
    }
  }

  //find avaiable pmp region idx
  region_idx = get_free_region_idx();
  if(region_idx < 0 || region_idx > PMP_MAX_N_REGION)
    PMP_ERROR(PMP_REGION_MAX_REACHED, "Reached the maximum number of PMP regions");
  
  *rid = region_idx;

  switch(priority)
  {
    case(PMP_PRI_ANY): {
      reg_idx = get_free_reg_idx();
      if(reg_idx < 0)
        PMP_ERROR(PMP_REGION_MAX_REACHED, "No available PMP register");
      if(TEST_BIT(reg_bitmap, reg_idx) || reg_idx >= PMP_N_REG)
        PMP_ERROR(PMP_REGION_MAX_REACHED, "PMP register unavailable");
      break;
    }
    case(PMP_PRI_TOP): {
      reg_idx = 0;
      if(TEST_BIT(reg_bitmap, reg_idx))
        PMP_ERROR(PMP_REGION_MAX_REACHED, "PMP register unavailable");
      break;
    }
    case(PMP_PRI_BOTTOM): {
      /* the bottom register can be used by multiple regions, 
       * so we don't check its availability */
      reg_idx = PMP_N_REG - 1;
      break;
    }
    default: {
      PMP_ERROR(PMP_UNKNOWN_ERROR, "Invalid priority");
    }
  }

  // initialize the region (only supports NAPOT)
  regions[region_idx].start = start;
  regions[region_idx].size = size;
  regions[region_idx].addrmode = PMP_NAPOT;
  regions[region_idx].addr = pmp_address;
  regions[region_idx].reg_idx = reg_idx;
  regions[region_idx].allow_overlap = allow_overlap;
  SET_BIT(region_def_bitmap, region_idx);
  SET_BIT(reg_bitmap, reg_idx);
 
  return PMP_SUCCESS;
}

int pmp_region_free_atomic(int region_idx)
{

  spinlock_lock(&pmp_lock);
  
  if(!is_pmp_region_valid(region_idx))
  {
    spinlock_unlock(&pmp_lock);
    PMP_ERROR(PMP_REGION_INVALID, "Invalid PMP region index");
  }
  /*
  if(is_pmp_region_set(region_idx)) {
    int ret = pmp_unset(region_idx);
    if(ret) {
      return ret;
    }
  }*/
  
  int reg_idx = regions[region_idx].reg_idx;
  UNSET_BIT(region_def_bitmap, region_idx);
  UNSET_BIT(reg_bitmap, reg_idx);
  regions[region_idx].start = 0;
  regions[region_idx].size = 0;
  regions[region_idx].addrmode = 0;
  regions[region_idx].addr = 0;
  regions[region_idx].reg_idx = -1;
  
  spinlock_unlock(&pmp_lock);
  
  return PMP_SUCCESS;
}

void* pmp_get_addr(int region_idx)
{
  if(!TEST_BIT(region_def_bitmap, region_idx))
  {
    printm("pmp_get_addr(): Invalid PMP region index\n");
    return NULL;
  }
  
  return (void*)regions[region_idx].start;
}

uint64_t pmp_get_size(int region_idx)
{
  if(!TEST_BIT(region_def_bitmap, region_idx))
  {
    printm("pmp_get_size(): Invalid PMP region index\n");
    return 0;
  }

  return regions[region_idx].size;
}
