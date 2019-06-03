#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_create_enclave()
{

}

int main()
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_create_enclave),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
