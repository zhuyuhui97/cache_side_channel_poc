#define RPAR_DATA       x0
#define RLOC_PRE_CCNTR  x9
#define RLOC_POST_CCNTR x10
#define RLOC_BR         x11
#define RLOC_IDX        x12
#define RLOC_PRE_EVCNTR  x13
#define RLOC_POST_L2REF x14

.global probe_wrapper_head
probe_wrapper_head:
    eor RLOC_IDX, RLOC_IDX, RLOC_IDX
    ldr RLOC_BR, [RPAR_DATA, RLOC_IDX, lsl #3]
    dsb sy
    isb
    nop
    nop
    nop
    nop
    mrs RLOC_PRE_EVCNTR, pmevcntr0_el0
    mrs RLOC_PRE_CCNTR, pmccntr_el0
    br RLOC_BR
.global probe_wrapper_tail
probe_wrapper_tail:
    mrs RLOC_POST_L2REF, pmevcntr0_el0
    sub RLOC_POST_L2REF, RLOC_POST_L2REF, RLOC_PRE_EVCNTR
    str RLOC_POST_L2REF, [RPAR_DATA, RLOC_IDX, lsl #3]
    ret
.global probe_wrapper_end
probe_wrapper_end:

.align 6
.global prime_snippet
prime_snippet:
    dsb sy
    isb
    nop
    nop
    mrs RLOC_POST_CCNTR, pmccntr_el0
    // store ccntr
    sub RLOC_POST_CCNTR, RLOC_POST_CCNTR, RLOC_PRE_CCNTR
    str RLOC_POST_CCNTR, [RPAR_DATA, RLOC_IDX, lsl #3]
    // inc index
    add RLOC_IDX, RLOC_IDX, 1
    // load next addr
    ldr RLOC_BR, [RPAR_DATA, RLOC_IDX, lsl #3]
    dsb sy
    isb
    nop
    nop
    mrs RLOC_PRE_CCNTR, pmccntr_el0
    br RLOC_BR
.align 6
.global prime_snippet_end
prime_snippet_end: