/**
 * d$ prime+probe
 */

#include <argp.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "physmap.h"
#include "env.h"
#include "walk.h"

#define LEN_PRIME_SNIPPET (sizeof(walk_step_t))

/* uarch-dependent definitions */
#if defined(__x86_64__)
#error Not ready for amd64 processors!
#define OPS_BARRIER(x)                                                         \
    asm volatile("mfence");                                                    \
    NOP(x);
#define FLUSH_ICACHE(p) asm volatile("clflush (%0)" ::"r"(p));
#define OPCODE_RET (0xC3C3C3C3UL)
#define NR_OPCODE_ALIGN 0
#elif defined(__aarch64__)
#define OPS_BARRIER(x)                                                         \
    asm volatile("dsb sy");                                                    \
    asm volatile("isb");                                                       \
    NOP(x);
#define FLUSH_ICACHE(p) asm volatile("ic ivau, %0\n dc civac, %0" ::"r"(p));
#define OPCODE_RET (0xD65F03C0UL)
#define NR_OPCODE_ALIGN 2
#define PMEVTYPERm(x) "PMEVTYPER" MACRO_TO_STR(x) "_EL0"
#define PMEVCNTRm(x) "PMEVCNTR" MACRO_TO_STR(x) "_EL0"
#define INIT_PMU(cntr, mask)                                                   \
    {                                                                          \
        register uint64_t xt;                                                  \
        /* enable event */                                                     \
        __asm__ volatile("MRS %0, " PMEVTYPERm(cntr) : "=r"(xt));              \
        xt &= ~0xFFFF;                                                         \
        xt |= mask;                                                            \
        __asm__ volatile("MSR " PMEVTYPERm(cntr) ", %0" ::"r"(xt));            \
        /* reset counter */                                                    \
        __asm__ volatile("MSR " PMEVCNTRm(cntr) ", %0" ::"r"(0));              \
        /* enable counter */                                                   \
        __asm__ volatile("MRS %0, PMCNTENSET_EL0" : "=r"(xt));                 \
        xt |= 1 << cntr;                                                       \
        __asm__ volatile("MSR PMCNTENSET_EL0, %0" ::"r"(xt));                  \
    }
#endif

args_t args = {.tramp_base = NULL,
               .tramp_bits = TRAMP_BITS_DEFAULT,
               .tramp_size = (1 << TRAMP_BITS_DEFAULT),
               .cache_ways = 16,
               .cache_idx_bits = 20,
               .cache_offset_bits = 6,
               .offset_dbg_probe = OFFSET_PROBE_INPAGE,
               .pmu_event_id = -1,
               .threshold_ns = 0,
               .do_eviction = false,
               .verbose = false,
               .peek_phys_map = false,
               .prime_sweep = 16,
               .prime_repeat = 16,
               .nr_repeat = 100,
               .evict_repeat = 4};

void *test_ptr = NULL;

pagemap_t pmap_tramp = {
    .p = NULL,
    .size = 0,
};
pagemap_t pmap_pr = {
    .p = NULL,
    .size = 0,
};

uint64_t walk_dc_prime(walk_step_t *buf, uint64_t len, uint64_t repeat);
extern uint8_t walk_dc_prime_end;

static inline __attribute__((always_inline)) uint64_t read_cycles();
static inline void
init_probe_descriptor(void **evset, walk_descriptor_t *o_walk_probe, ctx_t ctx);
static inline void init_prime_descriptor(walk_descriptor_t *walk_probe,
                                         walk_descriptor_t *o_walk_prime,
                                         ctx_t ctx);
static inline void
init_pp_descriptors(void **evset, pp_descriptors_t *o_descriptor, ctx_t ctx);

void test_dcache_latency(void *probe, pagemap_t pmap, uint64_t *o_fast,
                         uint64_t *o_slow) {
    void *tramp = pmap.p;
    uint64_t tramp_size = pmap.size;
    // test branch latency when target in icache
    probe = (void *)((uint64_t)probe & ~((1 << args.cache_offset_bits) -
                                         1)); // align to cache line
    assert((probe < tramp) ||
           (probe >= (tramp + tramp_size))); // not in the same region

    printf("Test addr: %p\n", probe);

#define WALK_LEN 4
    uint64_t addr[WALK_LEN] = {
        (uint64_t)tramp + SIZE_CACHE_LINE + (0 * sizeof(uint64_t)),
        (uint64_t)tramp + SIZE_CACHE_LINE + (2 * sizeof(uint64_t)),
        (uint64_t)tramp + SIZE_CACHE_LINE + (4 * sizeof(uint64_t)),
        (uint64_t)probe};
    walk_step_t walkbuf[4];
    for (int i = 0; i < WALK_LEN - 1; i++) {
        walk_step_t *ptr = (walk_step_t *)addr[i];
        ptr->i_target = addr[i+1];
    }
#undef WALK_LEN

    // test branch latency when target in dcache
    walk_dc_prime((walk_step_t*)addr[0], 4, 4);
    OPS_BARRIER(8);
    *o_fast = ((walk_step_t*)addr[2])->o_cycle;

    // test branch latency when target not in dcache
    // BUG: we change the chain here to avoid BPU-guided prefetch
    FLUSH_ICACHE(probe);
    OPS_BARRIER(0x20);
    walk_dc_prime((walk_step_t*)addr[0], 4, 1);
    *o_slow = ((walk_step_t*)addr[3])->o_cycle;

}

void init_dc_probe_descriptor(void **evset, walk_descriptor_t *o_walk_probe,
                                  ctx_t ctx) {
    uint64_t nr_prime = args.cache_ways;
    uint64_t len = nr_prime + 1;
    // create probe chain
    walk_step_t *walkbuf = evset[0];
    for (int i = 0; i < (nr_prime - 1); i++) {
        walk_step_t *ptr = (walk_step_t *)evset[i];
        ptr->i_target = (uint64_t)evset[i+1];
    }
    o_walk_probe->walk_buffer = walkbuf;
    // TODO: use a different type to mark partition of pagemap_t!
}

void init_dc_pp_descriptors(void **evset, pp_descriptors_t *o_descriptor,
                                ctx_t ctx) {
    uint64_t nr_prime = args.cache_ways;
    walk_descriptor_t *walk_probe = &(o_descriptor->walk_probe);
    walk_descriptor_t *walk_prime = &(o_descriptor->walk_prime);
    // initialize descriptors
    init_dc_probe_descriptor(evset, walk_probe, ctx);
    // init_dc_prime_descriptor(walk_probe, walk_prime, ctx);
}



void print_res_test_primeprobe(void *evict_line, void **evset,
                               walk_step_t *walkbuf, uint64_t ret) {
    uint64_t nr_prime = args.cache_ways;
    assert(pid != -1);
    {
        uintptr_t paddr;
        virt_to_phys_user(&paddr, pid, (uintptr_t)evict_line);
        printf("!\tv=%p\tp=%p\n", evict_line, (void *)paddr);
    }
    for (int i = 0; i < nr_prime; i++) {
        uintptr_t paddr;
        virt_to_phys_user(&paddr, pid, (uintptr_t)evset[i]);
        uint p_idx = IDX_IN_CACHE_WAY(paddr) >> args.cache_offset_bits;
        uint64_t val = ((walk_step_t*)evset[i])->o_cycle;
        printf("%d\tv=%p\tp=%p\tp_idx=%6x\t%" PRIu64, i, evset[i],
               (void *)paddr, p_idx, val);
        printf((val > args.threshold_ns) ? " *EVICTED*\n"
                                                        : "\n");
    }
#if defined(__aarch64__)
    if (args.pmu_event_id != (uint16_t)-1)
        printf("PMU ev_0x%x=%d\n", args.pmu_event_id,
               ret);
#endif
}

void print_primeprobe_desciptor(pp_descriptors_t *pp_desc) {
    walk_step_t *probe_walkbuf = pp_desc->walk_probe.walk_buffer;
    void *probe_walkbuf_end = probe_walkbuf + pp_desc->walk_probe.len;
    walk_step_t *prime_walkbuf = pp_desc->walk_prime.walk_buffer;
    void *prime_walkbuf_end = prime_walkbuf + pp_desc->walk_prime.len;

    printf("walk_probe.walkbuf= %p - %p\n", probe_walkbuf, probe_walkbuf_end);
    // for (uint64_t i = 0; i < pp_desc->walk_probe.len; i++)
    //     printf("  --[%" PRIu64 "]=%p\n", i,
    //            (void *)(probe_walkbuf[i].i_target));
    printf("walk_prime.walkbuf= %p - %p\n", prime_walkbuf, prime_walkbuf_end);
    // for (uint64_t i = 0; i < pp_desc->walk_prime.len; i++)
    //     printf("  --[%" PRIu64 "]=%p\n", i,
    //            (void *)(prime_walkbuf[i].i_target));
}

uint64_t prime_probe_launcher(pagemap_t pr, ctx_t *ctx) {
    void *ev = ctx->ev;
    void *pr_base = pr.p;
    uint64_t pr_size = pr.size;
    uint64_t nr_prime = args.cache_ways;
    uint64_t evict_cntr = 0;

    get_prime_set(pr, ctx);
    void **prset = ctx->prime_set->list;
    uint64_t nr_available_ev = ctx->prime_set->available;
    assert((ctx->prime_set) && (prset) && (nr_available_ev >= nr_prime));

    pp_descriptors_t pp_desc;
    init_dc_pp_descriptors(prset, &pp_desc, *ctx);
    walk_step_t *walkbuf_probe = pp_desc.walk_probe.walk_buffer;
    int64_t repeat_prime = ctx->prime_repeat;
    uint64_t repeat_evict = ctx->evict_repeat;

    if (ctx->dbg_print_res)
        print_primeprobe_desciptor(&pp_desc);

    OPS_BARRIER(8);
    // Prime the cache set
    walk_dc_prime(walkbuf_probe, nr_prime, ctx->prime_repeat);
    OPS_BARRIER(8);

    if (args.do_eviction) { // do evict on demand!
        OPS_BARRIER(8);
        walk_dc_prime((walk_step_t *)ev, 1, repeat_evict);
        OPS_BARRIER(8);
    }

#if defined(DBG_FLUSH_EVSET)
    for (int i = 0; i < nr_prime; i++) {
        FLUSH_ICACHE((void*)prset[i]);
    }
#endif

    // let's detect who has been evicted by *test_cursor
    OPS_BARRIER(8);
    uint64_t ret;
    ret = walk_dc_prime(walkbuf_probe, nr_prime, 1);
    OPS_BARRIER(8);
    for (int i = 0; i < nr_prime; i++) {
        uint64_t val = ((walk_step_t*)prset[i])->o_cycle;
        evict_cntr += (val > args.threshold_ns);
    }
    if (ctx->dbg_print_res)
        print_res_test_primeprobe(ev, prset, walkbuf_probe, ret);

    ctx_t_free_prime_set(ctx);
    pp_descriptors_t_free(&pp_desc);
    return evict_cntr;
}

void print_env() {
    printf("=== ENV VALUES ===\n");
    printf("PID: %" PRIu64 "\n", pid);
    printf("Page size: %" PRIu64 "\n", os_page_size);
    printf("=== USER VALUES ===\n");
    printf("Cache ways: %" PRIu64 "\n", args.cache_ways);
    printf("Cache index bits: %" PRIu64 " (cover %llu bytes)\n",
           args.cache_idx_bits, SIZE_CACHE_WAY);
    printf("Cache offset bits: %" PRIu64 "\n", args.cache_offset_bits);
    printf("Trampoline size: %" PRIu64 " bytes\n", args.tramp_size);
    printf("Test probe address: %p\n", test_ptr);
    printf("Threshold (ns): %" PRIu64 "\n", args.threshold_ns);
    printf("\n");
}

void init_shared_tramp() {
    void *tramp = create_exec_tramp(args.tramp_size, args.tramp_base);
    assert(tramp);
    pmap_tramp.p = tramp;
    pmap_tramp.size = args.tramp_size;
    // TODO: use a different type to mark partition of pagemap_t!
    pmap_pr.p = pmap_tramp.p + (args.tramp_size >> 1);
    pmap_pr.size = args.tramp_size >> 1;
}

void init_test_ptr() {
    // TODO: remove magic number
    // TODO: only do this on a sub partition
    // TODO: check the border carefully
    // TODO: check conflict with other prime entries
    assert(pmap_pr.p);
    test_ptr = pmap_pr.p + IDX_IN_CACHE_WAY(args.offset_dbg_probe) -
               (0 << args.cache_idx_bits);
}

void test_latency() {
    // TODO: BROKEN!!!
    uint64_t cache_fast, cache_slow;
    void *pr_base = pmap_tramp.p + (args.tramp_size >> 1);
    pagemap_t pmap_pr = {
        .p = pr_base,
        .size = args.tramp_size >> 1,
    };
    test_dcache_latency(pmap_tramp.p + 0x6c0, pmap_pr, &cache_fast,
                        &cache_slow);
    printf("FAST=%"PRIu64", SLOW=%"PRIu64"\n", cache_fast, cache_slow);
    args.threshold_ns = (cache_fast + cache_slow) / 2;
}

void init(int argc, char **argv) {
    init_args(argc, argv);
    assert(args.offset_dbg_probe < args.tramp_size);
    init_paging_info();
    pid = getpid();
    init_shared_tramp();
    // init_rw_buffer_shared();
    init_test_ptr();
    if (args.threshold_ns == 0)
        test_latency();
    print_env();
#if defined(__aarch64__)
    if (args.pmu_event_id != (uint16_t)-1)
        INIT_PMU(0, args.pmu_event_id);
#endif
    if (args.peek_phys_map)
        peek_physmap(pmap_tramp, pid);
}

void finish() { pagemap_t_free(&pmap_tramp); }

int main(int argc, char **argv) {
    init(argc, argv);

    for (uint64_t i = 0; i < (1 << 16); i += (1 << 6)) {
        uint64_t ptr = (uint64_t)pmap_tramp.p + i;
        ctx_t ctx = {
            .ev = (void *)ptr,
            .prime_sweep = args.prime_sweep,
            .prime_repeat = args.prime_repeat,
            .evict_repeat = args.evict_repeat,
            .dbg_print_res = args.verbose,
            .cache_entry_size = sizeof(walk_step_t),
            .args = &args
        };
        uint64_t cntr_evicted = 0;
        for (int j = 0; j < args.nr_repeat; j++) {
            ctx.dbg_print_res = (j==0) & args.verbose;
            cntr_evicted += prime_probe_launcher(pmap_pr, &ctx);
        }
        printf("PTR=%p, PRIME_ROUNDS=%" PRIu64 ", PRIME_ROUNDS_REPEATS=%" PRIu64
               " => EVICTED=%" PRIu64 "\n",
               ptr, ctx.prime_sweep, ctx.prime_repeat, cntr_evicted);
    }

    finish();
}