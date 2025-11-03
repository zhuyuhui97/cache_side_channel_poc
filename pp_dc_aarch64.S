#define RPAR_DPTR       x0
#define RPAR_LEN        x1
#define RPAR_REPEAT     x2
#define RLOC_DPTR       x9
#define RLOC_LEN        x10
#define RLOC_VAL_BAK    x11
#define RLOC_PRE_CCNTR  x12
#define RLOC_POST_CCNTR x13
#define RLOC_PRE_EVCNT  x14
#define RLOC_POST_EVCNT x15

.align 6
.global walk_dc_prime
walk_dc_prime:
    mov RLOC_DPTR, RPAR_DPTR
    mov RLOC_LEN, RPAR_LEN
    dsb sy
    isb
    mrs RLOC_PRE_EVCNT, pmevcntr0_el0
    cmp RPAR_REPEAT, #0
    b.eq return

step:
    mov RLOC_VAL_BAK, RLOC_DPTR
    // measure
    dsb sy
    isb
    mrs RLOC_PRE_CCNTR, pmccntr_el0
    ldr RLOC_DPTR, [RLOC_DPTR]
    dsb sy
    isb
    mrs RLOC_POST_CCNTR, pmccntr_el0

    sub RLOC_POST_CCNTR, RLOC_POST_CCNTR, RLOC_PRE_CCNTR
    add RLOC_VAL_BAK, RLOC_VAL_BAK, #8
    str RLOC_POST_CCNTR, [RLOC_VAL_BAK]

    sub RLOC_LEN, RLOC_LEN, #1
    cmp RLOC_LEN, #0
    b.ne step

    sub RPAR_REPEAT, RPAR_REPEAT, #1
    cmp RPAR_REPEAT, #0
    b.ne walk_dc_prime

return:
    mrs RLOC_POST_EVCNT, pmevcntr0_el0
    sub RLOC_POST_EVCNT, RLOC_POST_EVCNT, RLOC_PRE_EVCNT
    mov RPAR_DPTR, RLOC_POST_EVCNT
    ret
.align 6
.global walk_dc_prime_end
walk_dc_prime_end: