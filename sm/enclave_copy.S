.text

#define TRY(tryname, r_mtvec, r_mepc, r_mcause) \
    la r_mtvec, tryname##_err     ;\
    csrrw r_mtvec, mtvec, r_mtvec ;\
    csrr r_mepc, mepc             ;\
    csrr r_mcause, mcause

#define CATCH_ERR(tryname, r_mepc) \
        j tryname##_ok    ;\
        .align 4          ;\
    tryname##_err :       ;\
        la r_mepc, tryname##_err_real ;\
        csrw mepc, r_mepc ;\
        mret              ;\
        .align 4          ;\
    tryname##_err_real :

#define TRY_END(tryname, r_mtvec, r_mepc, r_mcause) \
    tryname##_ok :             ;\
        csrw mtvec, r_mtvec    ;\
        csrw mepc, r_mepc      ;\
        csrw mcause, r_mcause


#define SET_MPRV(reg)  \
    li reg, 1         ;\
    slli reg, reg, 17 ;\
    csrs mstatus, reg

#define UNSET_MPRV(reg) \
    li reg, 1          ;\
    slli reg, reg, 17  ;\
    csrc mstatus, reg



.global copy8_from_sm
copy8_from_sm:
    # a0: dst
    # a1: src
TRY(copy8_check, t1, t2, t3)
    ld t0, 0x00(a1)
    SET_MPRV(t5)
    sd t0, 0x00(a0)
    li a0, 0
CATCH_ERR(copy8_check, t4)
    li a0, -1
TRY_END(copy8_check, t1, t2, t3)

    UNSET_MPRV(t5)
    ret
