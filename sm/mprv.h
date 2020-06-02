#pragma once
#include <stdint.h>
#include <stdbool.h>

int copy1_from_sm(uintptr_t dst, const uint8_t *src);
int copy_word_from_sm(uintptr_t dst, const uint64_t *src);
int copy_block_from_sm(uintptr_t dst, const uint64_t *src);

int copy1_to_sm(uint8_t *dst, uintptr_t src);
int copy_word_to_sm(uint64_t *dst, uintptr_t src);
int copy_block_to_sm(uint64_t *dst, uintptr_t src);

#if __riscv_xlen == 64
#define MPRV_BLOCK 64
#define MPRV_WORD 8
#elif __riscv_xlen == 32
#define MPRV_BLOCK 32
#define MPRV_WORD 4
#endif

int copy_from_sm(uintptr_t dst, void *src_buf, size_t len)
{
    uintptr_t src = (uintptr_t)src_buf;

    if (src % MPRV_WORD == 0 && dst % MPRV_WORD == 0) {
        while (len >= MPRV_BLOCK) {
            int res = copy_block_from_sm(dst, (uint64_t *)src);
            if (res)
                return res;
            
            src += MPRV_BLOCK;
            dst += MPRV_BLOCK;
            len -= MPRV_BLOCK;
        }

        while (len >= MPRV_WORD) {
            int res = copy_word_from_sm(dst, (uint64_t *)src);
            if (res)
                return res;

            src += MPRV_WORD;
            dst += MPRV_WORD;
            len -= MPRV_WORD;
        }
    }

    while (len > 0) {
        int res = copy1_from_sm(dst, (uint8_t *)src);
        if (res)
            return res;

        src++;
        dst++;
        len--;
    }

    return 0;
}

int copy_to_sm(void *dst_buf, uintptr_t src, size_t len)
{
    uintptr_t dst = (uintptr_t)dst_buf;

    if (src % MPRV_WORD == 0 && dst % MPRV_WORD == 0) {
        while (len >= MPRV_BLOCK) {
            int res = copy_block_to_sm((uint64_t *)dst, src);
            if (res)
                return res;
            
            src += MPRV_BLOCK;
            dst += MPRV_BLOCK;
            len -= MPRV_BLOCK;
        }

        while (len >= MPRV_WORD) {
            int res = copy_word_to_sm((uint64_t *)dst, src);
            if (res)
                return res;

            src += MPRV_WORD;
            dst += MPRV_WORD;
            len -= MPRV_WORD;
        }
    }

    while (len > 0) {
        int res = copy1_to_sm((uint8_t *)dst, src);
        if (res)
            return res;

        src++;
        dst++;
        len--;
    }

    return 0;
}
