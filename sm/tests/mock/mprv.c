#include <stdint.h>

int __wrap_copy8_from_sm(uint8_t *dst, uint8_t *src)
{
    *dst = *src;
    return 0;
}
