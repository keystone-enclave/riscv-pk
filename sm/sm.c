#include "sm.h"
#include "mtrap.h"
#include "pmp.h"

typedef unsigned char byte;

extern byte sanctum_sm_signature[64];
extern byte sanctum_dev_public_key[32];
extern unsigned int sanctum_sm_size[1];

int smm_init(uintptr_t start, uint64_t size, uint8_t perm)
{
  int region = pmp_region_init(start, size, perm);
  if(region < 0)
  {
    printm("sm: failed to initialize a PMP region\n");
    return -1;
  }

  int reg = pmp_set(region);
  if(reg < 0)
  {
    pmp_region_debug_print(region);
    return -1;
  }

  return 0;
}

void sm_print_cert()
{
	int i;

	printm("Booting from Security Monitor\n");
	printm("Size: %d\n", sanctum_sm_size[0]);

	printm("============ PUBKEY =============\n");
	for(i=0; i<8; i+=1)
	{
		printm("%x",*((int*)sanctum_dev_public_key+i));
		if(i%4==3) printm("\n");
	}	
	printm("=================================\n");
	
	printm("=========== SIGNATURE ===========\n");
	for(i=0; i<16; i+=1)
	{
		printm("%x",*((int*)sanctum_sm_signature+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");
}

void sm_init(void)
{
	// initialize SMM
	int ret;
  ret = smm_init(SMM_BASE, SMM_SIZE, 0);
  if(ret < 0)
    die("[SM] intolerable error - failed to initialize SM memory");
  // reserve the last PMP register for the OS
  ret = set_os_pmp_region();
  if(ret < 0)
    die("[SM] intolerable error - failed to initialize OS memory");
  
  // for debug
  // sm_print_cert();
}
