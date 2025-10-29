/**
 * Probing executable addresses based on i$ prime+probe side channel.
 * Based on paper: *Speculative Probing: Hacking Blind in the Spectre Era*
 */

#include <argp.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include "physmap.h"
#include "env.h"
#include "walk.h"

#define NR_BPU_ACTV 4
#define NR_BPU_TRAIN 32
#define FILL_BHB_LEN 600

#define LEN_PRIME_SNIPPET (&prime_snippet_end - &prime_snippet)

/* uarch-dependent definitions */
#if defined(__x86_64__)
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

const bool dont_br = false, do_br = true;

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
               .verbose = false};

uint64_t os_page_size = 0;
uint64_t pid = -1;
void *test_ptr = NULL;

pagemap_t rw_buffer_shared = {
    .p = NULL,
    .size = 0,
};
pagemap_t pmap_tramp = {
    .p = NULL,
    .size = 0,
};
pagemap_t pmap_pr = {
    .p = NULL,
    .size = 0,
};

extern uint8_t prime_snippet, prime_snippet_end;
void walk_wrapper_head(walk_step_t *buf, uint64_t repeat);
extern uint8_t walk_wrapper_tail, walk_wrapper_end;

static inline __attribute__((always_inline)) uint64_t read_cycles();
static inline void
init_ic_probe_descriptor(void **evset, walk_descriptor_t *o_walk_probe, ctx_t ctx);
static inline void
init_ic_prime_descriptor(walk_descriptor_t *walk_probe,
                      walk_descriptor_t *o_walk_prime,
                      ctx_t ctx);
static inline void
init_ic_pp_descriptors(void **evset, pp_descriptors_t *o_descriptor, ctx_t ctx);

typedef uint64_t do_evict_t();
void speculative_br(uint64_t flag, register void* ptr);
extern uint8_t speculative_br_end;

#define DO_EVICT_T_NR_PARAMS 4
typedef struct {
    uint64_t args[DO_EVICT_T_NR_PARAMS];
    uint8_t snippet;
} evict_stub_t;

void test_icache_latency(void *probe, pagemap_t pmap, uint64_t *o_fast,
                         uint64_t *o_slow) {
    void *tramp = pmap.p;
    uint64_t tramp_size = pmap.size;
    // test branch latency when target in icache
    probe = (void *)((uint64_t)probe & ~((1 << args.cache_offset_bits) -
                                         1)); // align to cache line
    assert((probe < tramp) ||
           (probe >= (tramp + tramp_size))); // not in the same region

    printf("Test addr: %p\n", probe);
    fflush(stdout);
    // put a bridging prime snippet at the beginning of trampoline
    memcpy(tramp, &prime_snippet, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)tramp, (char *)tramp + LEN_PRIME_SNIPPET);
    // put a victim prime snippet at the probe address
    memcpy(probe, &prime_snippet, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)probe, (char *)probe + LEN_PRIME_SNIPPET);
    // make a jumping chain: head -> bridging snippet *->* probe snippet -> tail

    // TODO: move to walk_descriptor_t_map_buffer to avoid cache pollution?
    walk_step_t walkbuf[3] = {
        {(uint64_t)tramp, 0},
        {(uint64_t)tramp, 0},
        {(uint64_t)&walk_wrapper_tail, 0},
    };

    // test branch latency when target in icache

    walk_wrapper_head(walkbuf, 4);
    OPS_BARRIER(8);
    *o_fast = walkbuf[1].o_cycle;

    // test branch latency when target not in icache
    // BUG: we change the chain here to avoid BPU-guided prefetch
    walkbuf[1].i_target = (uint64_t)probe;
    FLUSH_ICACHE(probe);
    OPS_BARRIER(0x20);
    walk_wrapper_head(walkbuf, 1);
    *o_slow = walkbuf[1].o_cycle;
    // clear the snippets
    memset(tramp, 0, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)tramp, (char *)tramp + LEN_PRIME_SNIPPET);
    memset(probe, 0, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)probe, (char *)probe + LEN_PRIME_SNIPPET);
}

walk_step_t *walk_descriptor_t_map_buffer(uint64_t len,
                                          walk_descriptor_t *walk_d,
                                          ctx_t ctx) {
    uint64_t size = len * sizeof(walk_step_t);
    if (size > (os_page_size - SIZE_CACHE_LINE)) {
        fprintf(stderr,
                "E: RW buffer bigger than trampoline! Requested %" PRIu64 "\n",
                size);
        exit(-1);
    }
    // TODO: WARN when the buffer span may cover the in-page offset of p+p set, in case of cache pollution.
    uint64_t ev = (uint64_t)ctx.ev;
    uint64_t in_page_offset = OFFSET_IN_PAGE(ev);
    // here let's avoid cache pollusion using non-overlapping in-page offsets
    // start from next cache line
    in_page_offset = ALIGN_CACHE_LINE(in_page_offset + 4 * SIZE_CACHE_LINE);
    void *map = mmap(NULL, 2 * os_page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(map);
    walk_d->map.size = 2 * os_page_size;
    walk_d->map.p = map;
    walk_d->walk_buffer = map + in_page_offset;
    walk_d->len = len;
    return (map + in_page_offset);
}

inline void init_ic_probe_descriptor(void **evset, walk_descriptor_t *o_walk_probe,
                                  ctx_t ctx) {
    uint64_t nr_prime = args.cache_ways;
    uint64_t len = nr_prime + 1;
    // create probe chain
    walk_step_t *walkbuf = walk_descriptor_t_map_buffer(len, o_walk_probe, ctx);
    for (int i = 0; i < nr_prime; i++) {
        walkbuf[i].i_target = (uint64_t)evset[nr_prime - i - 1];
    }
    // last jump to the tail
    walkbuf[nr_prime].i_target = (uint64_t)&walk_wrapper_tail;
}

inline void init_ic_prime_descriptor(walk_descriptor_t *walk_probe,
                                  walk_descriptor_t *o_walk_prime, ctx_t ctx) {
    // walk the prime set back and forth
    uint64_t nr_rept = ctx.prime_rounds;
    walk_step_t *walkbuf_probe = walk_probe->walk_buffer;
    uint64_t nr_probe = (walk_probe->len) - 1; // exclude the tail
    uint64_t len = ((nr_rept * (nr_probe - 1)) + 1);
    walk_step_t *walkbuf = walk_descriptor_t_map_buffer(len, o_walk_prime, ctx);
    for (int i = 0; i < nr_rept; i++) {
        if (i % 2 == 0) {
            for (int j = 0; j < nr_probe - 1; j++)
                walkbuf[i * (nr_probe - 1) + j].i_target =
                    walkbuf_probe[nr_probe - j - 1].i_target;
        } else {
            for (int j = 0; j < nr_probe - 1; j++)
                walkbuf[i * (nr_probe - 1) + j].i_target =
                    walkbuf_probe[j].i_target;
        }
    }
    walkbuf[len - 1].i_target = (uint64_t)&walk_wrapper_tail;
}

inline void init_ic_pp_descriptors(void **evset, pp_descriptors_t *o_descriptor,
                                ctx_t ctx) {
    uint64_t nr_prime = args.cache_ways;
    walk_descriptor_t *walk_probe = &(o_descriptor->walk_probe);
    walk_descriptor_t *walk_prime = &(o_descriptor->walk_prime);
    // copy prime snippet to all evset entries
    for (int i = 0; i < nr_prime; i++) {
        memcpy((void *)evset[i], &prime_snippet, LEN_PRIME_SNIPPET);
        __builtin___clear_cache((char *)evset[i],
                                (char *)evset[i] + LEN_PRIME_SNIPPET);
    }
    // initialize descriptors
    init_ic_probe_descriptor(evset, walk_probe, ctx);
    init_ic_prime_descriptor(walk_probe, walk_prime, ctx);
}

inline evict_stub_t *init_ic_ev_stub(void **evset, walk_descriptor_t *o_descriptor,
                                ctx_t ctx, walk_descriptor_t *i_ev_flag) {
    uint64_t size_x = (uint64_t)(&speculative_br_end) - (uint64_t)(&speculative_br);
    uint64_t size_rwx = 0;
    size_rwx += sizeof(uint64_t) * DO_EVICT_T_NR_PARAMS;
    size_rwx += size_x;
    evict_stub_t *evd = (evict_stub_t *) walk_descriptor_t_map_buffer(size_rwx, o_descriptor, ctx);
    evd->args[0] = (uint64_t) i_ev_flag->walk_buffer;
    evd->args[1] = (uint64_t) ctx.ev;
    evd->args[2] = 0xdeadbeef;
    evd->args[3] = 0xbeefdead;
    memcpy(&(evd->snippet), &speculative_br, size_x);
    __builtin___clear_cache((char *)&(evd->snippet), (char *)&(evd->snippet) + size_x);
    return evd;
}

inline void init_ic_ev_flag(void **evset, walk_descriptor_t *o_descriptor, ctx_t ctx) {
    walk_descriptor_t_map_buffer(sizeof(uint64_t), o_descriptor, ctx);
}

inline void init_ic_ev_descriptors(void **evset, ev_descriptors_t *o_descriptor,
                                ctx_t ctx) {
    walk_descriptor_t *ev_stub = &(o_descriptor->ev_stub);
    walk_descriptor_t *ev_flag = &(o_descriptor->ev_flag);
    // initialize descriptors
    init_ic_ev_flag(evset, ev_flag, ctx);
    evict_stub_t *evd = init_ic_ev_stub(evset, ev_stub, ctx, ev_flag);
}

void ev_descriptors_t_free(ev_descriptors_t *desc) {
    walk_descriptor_t_free(&(desc->ev_flag));
    walk_descriptor_t_free(&(desc->ev_stub));
}

// TODO: rework logging
void print_res_test_primeprobe(void *evict_line, void **evset,
                               walk_step_t *walkbuf) {
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
        uint p_idx = ((paddr & ((1 << args.cache_idx_bits) - 1)) >>
                      args.cache_offset_bits);
        printf("%d\tv=%p\tp=%p\tp_idx=%6x\t%" PRIu64, i, evset[i],
               (void *)paddr, p_idx, walkbuf[i].o_cycle);
        printf((walkbuf[i].o_cycle > args.threshold_ns) ? " *EVICTED*\n"
                                                        : "\n");
    }
#if defined(__aarch64__)
    if (args.pmu_event_id != (uint16_t)-1)
        printf("PMU ev_0x%x=%d\n", args.pmu_event_id,
               walkbuf[nr_prime].o_cycle);
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

uint64_t prime_probe_ic(register walk_step_t *walkbuf_prime,
                        register uint64_t repeat_prime,
                        register walk_step_t *walkbuf_evict,
                        register uint64_t repeat_evict,
                        register walk_step_t *walkbuf_probe,
                        register uint64_t nr_prime,
                        register uint64_t threshold,
                        register evict_stub_t *do_evict) {
    register uint64_t evict_cntr = 0;
    do_evict_t *do_evict_entry = ((void *)do_evict) + (DO_EVICT_T_NR_PARAMS * sizeof(uint64_t));
    OPS_BARRIER(8);
    // Prime the cache set
    walk_wrapper_head(walkbuf_prime, repeat_prime);
    OPS_BARRIER(8);

    // do evict on demand!
    OPS_BARRIER(8);
    do_evict_entry();
    OPS_BARRIER(8);

#if defined(DBG_FLUSH_EVSET)
    for (int i = 0; i < nr_prime; i++) {
        FLUSH_ICACHE(evset[i]);
    }
#endif

    // let's detect who has been evicted by *test_cursor
    OPS_BARRIER(8);
    walk_wrapper_head(walkbuf_probe, 1);
    OPS_BARRIER(128);
    for (register int i = 0; i < nr_prime; i++) {
        evict_cntr += (walkbuf_probe[i].o_cycle > threshold);
    }
    return evict_cntr;
}

uint64_t prime_probe_launcher(pagemap_t pr, ctx_t *ctx, register uint64_t repeat) {
    void *ev = ctx->ev;
    void *pr_base = pr.p;
    uint64_t pr_size = pr.size;
    uint64_t nr_prime = args.cache_ways;
    register uint64_t evict_cntr = 0;
    register uint64_t threshold = args.threshold_ns;

    get_prime_set(pr, ctx);
    void **prset = ctx->prime_set->list;
    uint64_t nr_available_ev = ctx->prime_set->available;
    assert((ctx->prime_set) && (prset) && (nr_available_ev >= nr_prime));

    memcpy((void *)ev, &prime_snippet, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)ev, (char *)ev + LEN_PRIME_SNIPPET);

    pp_descriptors_t pp_desc;
    // walk_descriptor_t ev_desc;
    ev_descriptors_t ev_desc;
    init_ic_pp_descriptors(prset, &pp_desc, *ctx);
    init_ic_ev_descriptors(prset, &ev_desc, *ctx);
    evict_stub_t *ev_stub = (evict_stub_t *) ev_desc.ev_stub.walk_buffer;
    // ev_stub = init_ic_ev_stub(prset, &ev_desc, *ctx);
    register walk_step_t *walkbuf_probe = pp_desc.walk_probe.walk_buffer;
    register uint64_t repeat_prime = ctx->prime_rounds_repeats;
    register walk_step_t *walkbuf_prime = pp_desc.walk_prime.walk_buffer;
    // TODO: move to walk_descriptor_t_map_buffer to avoid cache pollution
    walk_step_t walkbuf_evict[4] = {
        // if we don't want eviction, create a shortcut to the tail.
        {args.do_eviction ? (uint64_t)ev : (uint64_t)&walk_wrapper_tail, 0},
        {(uint64_t)ev, 0},
        {(uint64_t)ev, 0},
        {(uint64_t)&walk_wrapper_tail, 0}};
    register uint64_t repeat_evict = ctx->evict_repeats;

    if (ctx->dbg_print_res)
        print_primeprobe_desciptor(&pp_desc);

    for (register int _repeat = 0; _repeat < repeat; _repeat++) {
        evict_cntr +=
            prime_probe_ic(walkbuf_prime, repeat_prime, walkbuf_evict,
                           repeat_evict, walkbuf_probe, nr_prime, threshold, ev_stub);
    }

    if (ctx->dbg_print_res)
        print_res_test_primeprobe(ev, prset, walkbuf_probe);

    ctx_t_free_prime_set(ctx);
    pp_descriptors_t_free(&pp_desc);
    ev_descriptors_t_free(&ev_desc);
    // walk_descriptor_t_free(&ev_desc);
    return evict_cntr;
}

void print_env() {
    printf("=== ENV VALUES ===\n");
    printf("PID: %" PRIu64 "\n", pid);
    printf("Page size: %" PRIu64 "\n", os_page_size);
    printf("=== USER VALUES ===\n");
    printf("Cache ways: %" PRIu64 "\n", args.cache_ways);
    printf("Cache index bits: %" PRIu64 " (cover %llu bytes)\n",
           args.cache_idx_bits, (1ULL << args.cache_idx_bits));
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

void init_rw_buffer_shared() {
    uint64_t size = (2 << args.cache_idx_bits);
    void *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(buf != MAP_FAILED);
    rw_buffer_shared.p = buf;
    rw_buffer_shared.size = size;
}

void init_test_ptr() {
    // TODO: remove magic number
    // TODO: only do this on a sub partition
    // TODO: check the border carefully
    // TODO: check overlapping with other prime entries
    assert(pmap_pr.p);
    test_ptr = pmap_pr.p +
               (args.offset_dbg_probe & ((1 << args.cache_idx_bits) - 1)) -
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
    test_icache_latency(pmap_tramp.p + 0x6c0, pmap_pr, &cache_fast,
                        &cache_slow);
    args.threshold_ns = (cache_fast + cache_slow) / 2;
}

void init(int argc, char **argv) {
    // TODO: handle different cache line size
    assert(LEN_PRIME_SNIPPET == 64);
    init_args(argc, argv);
    assert(args.offset_dbg_probe < args.tramp_size);
    os_page_size = getpagesize();
    pid = getpid();
    init_shared_tramp();
    init_rw_buffer_shared();
    init_test_ptr();
    if (args.threshold_ns == 0)
        test_latency();
    print_env();
#if defined(__aarch64__)
    if (args.pmu_event_id != (uint16_t)-1)
        INIT_PMU(0, args.pmu_event_id);
#endif
}

void finish() { pagemap_t_free(&pmap_tramp); }

int main(int argc, char **argv) {
    init(argc, argv);

    for (uint64_t i = 0; i < (1 << 16); i += (1 << 6)) {
        uint64_t ptr = (uint64_t)pmap_tramp.p + i;
        ctx_t ctx = {
            .ev = (void *)ptr,
            .prime_rounds = 2,
            .prime_rounds_repeats = 4,
            .evict_repeats = 128,
            .dbg_print_res = args.verbose,
            .cache_entry_size = LEN_PRIME_SNIPPET,
            .args = &args
        };
        uint64_t cntr_evicted = prime_probe_launcher(pmap_pr, &ctx, 1000);
        printf("PTR=%p, PRIME_ROUNDS=%" PRIu64 ", PRIME_ROUNDS_REPEATS=%" PRIu64
               " => EVICTED=%" PRIu64 "\n",
               ptr, ctx.prime_rounds, ctx.prime_rounds_repeats, cntr_evicted);
        fflush(stdout);
        fflush(stderr);
        sched_yield();
    }

    // ctx_t ctx = {
    //         .ev = test_cursor,
    //         .prime_rounds = 256,
    //         .prime_rounds_repeats = 256,
    //         .evict_repeats = 128,
    //         .dbg_print_res = false,
    //         .cache_entry_size = LEN_PRIME_SNIPPET
    //         .args = &args
    //     };
    // test_primeprobe(pmap_pr, ctx);
    finish();
}