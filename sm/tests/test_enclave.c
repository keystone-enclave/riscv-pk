#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../enclave.c"

static void test_context_switch_to_enclave()
{

}

static void test_get_enclave_region_after_init()
{
  enclave_id eid;
  int memid;
  enum enclave_region_type type;

  enclave_init_metadata();

  for (eid=0; eid < ENCL_MAX; eid++)
  {
    // testing get_enclave_region_index
    assert_int_equal( get_enclave_region_index(eid, REGION_EPM), -1 );
    assert_int_equal( get_enclave_region_index(eid, REGION_UTM), -1 );
    assert_int_equal( get_enclave_region_index(eid, REGION_OTHER), -1 );
    assert_int_equal( get_enclave_region_index(eid, REGION_INVALID), 0 );

    // testing get_enclave_region_size
    assert_int_equal( get_enclave_region_size(eid, REGION_EPM), 0 );
    assert_int_equal( get_enclave_region_size(eid, REGION_UTM), 0 );
    assert_int_equal( get_enclave_region_size(eid, REGION_OTHER), 0 );
    assert_int_equal( get_enclave_region_size(eid, REGION_INVALID), 0 );

    // testing get_enclave_region_base
    assert_int_equal( get_enclave_region_base(eid, REGION_EPM), 0 );
    assert_int_equal( get_enclave_region_base(eid, REGION_UTM), 0 );
    assert_int_equal( get_enclave_region_base(eid, REGION_OTHER), 0 );
    assert_int_equal( get_enclave_region_base(eid, REGION_INVALID), 0 );

  }
}

static void test_get_enclave_region_index()
{
  enclave_id eid;
  int memid;
  enum enclave_region_type type;

  enclave_init_metadata();

  enclaves[0].regions[2].type = REGION_OTHER;
  enclaves[0].regions[2].pmp_rid = 4;

  assert_int_equal( get_enclave_region_index(0, REGION_OTHER), 2 );
}

int main()
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_is_create_args_valid),
    cmocka_unit_test(test_context_switch_to_enclave),
    cmocka_unit_test(test_get_enclave_region_after_init),
    cmocka_unit_test(test_get_enclave_region_index),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
