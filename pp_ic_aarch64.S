#define RPAR_DATA       x0
#define RPAR_REPEAT     x1
#define RLOC_PRE_CCNTR  x9
#define RLOC_POST_CCNTR x10
#define RLOC_BR         x11
#define RLOC_IDX        x12
#define RLOC_PRE_EVCNTR x13
#define RLOC_POST_L2REF x14

.global walk_wrapper_head
walk_wrapper_head:
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
.global walk_wrapper_tail
walk_wrapper_tail:
    mrs RLOC_POST_L2REF, pmevcntr0_el0
    sub RLOC_POST_L2REF, RLOC_POST_L2REF, RLOC_PRE_EVCNTR
    add RLOC_IDX, RLOC_IDX, 1 // walk_step_t[x].o_cycle
    str RLOC_POST_L2REF, [RPAR_DATA, RLOC_IDX, lsl #3]
    sub RPAR_REPEAT, RPAR_REPEAT, #1
    cmp RPAR_REPEAT, #0
    b.ne walk_wrapper_head
return:
    ret
.global walk_wrapper_end
walk_wrapper_end:

.align 6
.global prime_snippet
prime_snippet:
    dsb sy
    isb
    nop
    nop
    add RLOC_IDX, RLOC_IDX, 1 // walk_step_t[x].o_cycle
    mrs RLOC_POST_CCNTR, pmccntr_el0
    // store ccntr
    sub RLOC_POST_CCNTR, RLOC_POST_CCNTR, RLOC_PRE_CCNTR
    str RLOC_POST_CCNTR, [RPAR_DATA, RLOC_IDX, lsl #3]
    // inc index
    add RLOC_IDX, RLOC_IDX, 1 // walk_step_t[x+1].i_target
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

.align 6
.global speculative_br
speculative_br:
speculative_br_arg0:
    .quad 0
speculative_br_arg1:
    .quad 0
speculative_br_arg2:
    .quad 0
speculative_br_arg3:
    .quad 0
.global speculative_br_x
speculative_br_x:
    ldr  x0, speculative_br_arg0
    ldr  x1, speculative_br_arg1
    ldr  x0, [x0]
    cbz  x0, speculative_br_ret
    br   x1
speculative_br_ret:
    ret
.global speculative_br_end
speculative_br_end:
