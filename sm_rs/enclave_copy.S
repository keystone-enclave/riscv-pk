.text

set_mprv:
    # NOTE: CLOBBERS a3
    li a3, 1
    slli a3, a3, 17
    csrs mstatus, a3
    jr ra

unset_mprv:
    # NOTE: CLOBBERS a3
    li a3, 1
    slli a3, a3, 17
    csrc mstatus, a3
    jr ra

.global copy64_to_sm
copy64_to_sm:
    # a0: dst
    # a1: src
    addi sp, sp, -8
    sd ra, 0(sp)
    jal set_mprv
    ld t0, 0x00(a0)
    ld t1, 0x08(a0)
    ld t2, 0x10(a0)
    ld t3, 0x18(a0)
    ld t4, 0x20(a0)
    ld t5, 0x28(a0)
    ld t6, 0x30(a0)
    ld a6, 0x38(a0)
    jal unset_mprv
    sd t0, 0x00(a1)
    sd t1, 0x08(a1)
    sd t2, 0x10(a1)
    sd t3, 0x18(a1)
    sd t4, 0x20(a1)
    sd t5, 0x28(a1)
    sd t6, 0x30(a1)
    sd a6, 0x38(a1)
    ld ra, 0(sp)
    addi sp, sp, 8
    jr ra

.global copy8_to_sm
copy8_to_sm:
    # a0: dst
    # a1: src
    addi sp, sp, -8
    sd ra, 0(sp)
    jal set_mprv
    ld t0, 0x00(a0)
    jal unset_mprv
    sd t0, 0x00(a1)
    ld ra, 0(sp)
    addi sp, sp, 8
    jr ra

.global copy1_to_sm
copy1_to_sm:
    # a0: dst
    # a1: src
    addi sp, sp, -8
    sd ra, 0(sp)
    jal set_mprv
    lb t0, 0x00(a0)
    jal unset_mprv
    sb t0, 0x00(a1)
    ld ra, 0(sp)
    addi sp, sp, 8
    jr ra

.global copy64_from_sm
copy64_from_sm:
    # a0: dst
    # a1: src
    addi sp, sp, -8
    sd ra, 0(sp)
    ld t0, 0x00(a0)
    ld t1, 0x08(a0)
    ld t2, 0x10(a0)
    ld t3, 0x18(a0)
    ld t4, 0x20(a0)
    ld t5, 0x28(a0)
    ld t6, 0x30(a0)
    ld a6, 0x38(a0)
    jal set_mprv
    sd t0, 0x00(a1)
    sd t1, 0x08(a1)
    sd t2, 0x10(a1)
    sd t3, 0x18(a1)
    sd t4, 0x20(a1)
    sd t5, 0x28(a1)
    sd t6, 0x30(a1)
    sd a6, 0x38(a1)
    jal unset_mprv
    ld ra, 0(sp)
    addi sp, sp, 8
    jr ra

.global copy8_from_sm
copy8_from_sm:
    # a0: dst
    # a1: src
    addi sp, sp, -8
    sd ra, 0(sp)
    ld t0, 0x00(a0)
    jal set_mprv
    sd t0, 0x00(a1)
    jal unset_mprv
    ld ra, 0(sp)
    addi sp, sp, 8
    jr ra

.global copy1_from_sm
copy1_from_sm:
    # a0: dst
    # a1: src
    addi sp, sp, -8
    sd ra, 0(sp)
    lb t0, 0x00(a0)
    jal set_mprv
    sb t0, 0x00(a1)
    jal unset_mprv
    ld ra, 0(sp)
    addi sp, sp, 8
    jr ra
