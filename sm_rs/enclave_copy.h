#include <stdint.h>

void copy64_to_sm(void *dst, const void *src);
void copy8_to_sm(uint64_t *dst, const uint64_t *src);
void copy1_to_sm(uint8_t *dst, const uint8_t *src);

void copy64_from_sm(void *dst, const void *src);
void copy8_from_sm(uint64_t *dst, const uint64_t *src);
void copy1_from_sm(uint8_t *dst, const uint8_t *src);
