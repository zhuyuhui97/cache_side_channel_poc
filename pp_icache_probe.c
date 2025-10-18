/**
 * Probing executable addresses based on i$ prime+probe side channel.
 * Based on paper: *Speculative Probing: Hacking Blind in the Spectre Era*
 */

#include <argp.h>
#include <assert.h>
#include <fcntl.h> /* open */
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
#include <unistd.h> /* pread, sysconf */

#define NR_BPU_ACTV 4
#define NR_BPU_TRAIN 32
#define OFFSET_PROBE_INPAGE 0x2ca0
#define FILL_BHB_LEN 600
#define TRAMP_BITS_DEFAULT 26 // 64MB
#define __NOP(x, rsh)                                                          \
    asm volatile(".rept " MACRO_TO_STR(x >> rsh) "\n nop\n .endr")
#define NOP(x) __NOP(x, 0)

#define CALL_ADDR(x) ((void (*)(void))(x))()
#define MEM_ACCESS(p) *(volatile unsigned char *)p
#define MACRO_TO_STR(x) #x

#define LEN_PRIME_SNIPPET (&prime_snippet_end - &prime_snippet)

#define SIZE_PRIME_GAP (1 << args.cache_idx_bits)
#define SIZE_CACHE_LINE (1 << args.cache_offset_bits)
#define CACHE_LINE_ALIGN(addr)                                                 \
    ((void *)((uint64_t)addr & ~(SIZE_CACHE_LINE - 1)))

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

typedef struct {
    uint64_t *ro_chain;
    uint64_t *rw_buffer;
    uint64_t len;
} walk_descriptor_t;

typedef struct {
    walk_descriptor_t walk_prime;
    walk_descriptor_t walk_probe;
} pp_descriptors_t;

typedef struct {
    void *p;
    uint64_t size;
} pagemap_t;

typedef struct {
    void *tramp_base;
    uint64_t tramp_bits;
    uint64_t tramp_size;
    uint64_t cache_ways;
    uint64_t cache_idx_bits;
    uint64_t cache_offset_bits;
    uint64_t offset_dbg_probe;
    uint16_t pmu_event_id;
    uint64_t threshold_ns;
    bool do_eviction;
    bool verbose;
} args_t;

typedef struct {
    void **list;
    uint64_t available;
} prime_set_t;

typedef struct {
    void *ev;
    uint64_t prime_rounds;
    uint64_t prime_rounds_repeats;
    uint64_t evict_repeats;
    prime_set_t *prime_set;
    bool dbg_print_res;
} ctx_t;

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
void walk_wrapper_head(uint64_t *buf);
extern uint8_t walk_wrapper_tail, walk_wrapper_end;

static struct argp_option options[] = {
    {"tramp", 't', "TRAMPOLINE_BASE", 0, "Base address of trampoline."},
    {"ways", 'w', "CACHE_WAYS", 0, "Number of ways."},
    {"bits", 'b', "CACHE_IDX_BITS", 0, "Number of index bits."},
    {"offset", 'o', "CACHE_OFFSET_BITS", 0, "Size of cache line, default 64b."},
    {"size", 's', "TRAMPOLINE_BITS", 0,
     "Bits of address span of the RET trampoline, size=(1<<TRAMPOLINE_BITS)."},
    {"probe", 'p', "OFFSET", 0, "DEBUG: test offset of P+P probe"},
    {"evict", 'e', NULL, 0, "DEBUG: do eviction"},
    {"pmu-ev", 'm', "PMU_EVENT_ID", 0,
     "DEBUG: PMU event to monitor (ARM only)."},
    {"ns", 'n', "NANOSEC", 0, "Threshold in nanoseconds."},
    {"verbose", 'v', NULL, 0, "Print debug information."},
    {0}};

static inline __attribute__((always_inline)) uint64_t read_cycles();

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    switch (key) {
    case 't':
        args.tramp_base = (void *)strtoull(arg, NULL, 0);
        break;
    case 'w':
        args.cache_ways = strtoull(arg, NULL, 0);
        break;
    case 'b':
        args.cache_idx_bits = strtoull(arg, NULL, 0);
        if (args.cache_idx_bits < 6) {
            fprintf(stderr, "error: cache_idx_bits must be >= 6\n");
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case 'o':
        args.cache_offset_bits = strtoull(arg, NULL, 0);
        break;
    case 's':
        args.tramp_bits = strtoull(arg, NULL, 0);
        args.tramp_size = 1 << args.tramp_bits;
        break;
    case 'p':
        args.offset_dbg_probe = strtoull(arg, NULL, 0);
        break;
    case 'e':
        args.do_eviction = true;
        break;
    case 'm':
        args.pmu_event_id = strtoull(arg, NULL, 0);
        break;
    case 'n':
        args.threshold_ns = strtoull(arg, NULL, 0);
        break;
    case 'v':
        args.verbose = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, NULL, NULL, NULL};

/**
 * create a trampoline which matches the LLC size and fill with
 * ret opcodes
 */
void *create_exec_tramp(uint32_t size, void *base) {
    // size != 0
    assert(size);
    // create an anonymous, executable mapping
    void *buf = mmap(base, (size_t)size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(buf != MAP_FAILED);
    return buf;
}

void pagemap_t_free(pagemap_t *pmap) {
    if (pmap->p)
        munmap(pmap->p, pmap->size);
}

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
    uint64_t chain[3] = {(uint64_t)tramp, (uint64_t)tramp,
                         (uint64_t)&walk_wrapper_tail};
    uint64_t iobuf[3];

    // test branch latency when target in icache
    for (int i = 0; i < 4; i++) {
        for (int i = 0; i < 3; i++)
            iobuf[i] = chain[i];
        OPS_BARRIER(8);
        walk_wrapper_head(iobuf);
        OPS_BARRIER(8);
    }
    *o_fast = iobuf[1];

    // test branch latency when target not in icache
    // BUG: we change the chain here to avoid BPU-guided prefetch
    chain[1] = (uint64_t)probe;
    for (int i = 0; i < 3; i++)
        iobuf[i] = chain[i];
    FLUSH_ICACHE(probe);
    OPS_BARRIER(0x20);
    walk_wrapper_head(iobuf);
    *o_slow = iobuf[1];
    // clear the snippets
    memset(tramp, 0, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)tramp, (char *)tramp + LEN_PRIME_SNIPPET);
    memset(probe, 0, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)probe, (char *)probe + LEN_PRIME_SNIPPET);
}

void get_prime_set(pagemap_t pmap, ctx_t *ctx) {
    void *i_target = ctx->ev;
    uint64_t *o_n;
    void *pr_base = pmap.p;
    uint64_t pr_len = pmap.size;
    uint64_t idx_bits = args.cache_idx_bits;
    uint64_t stride = 1 << idx_bits;
    uint64_t mask = stride - 1;
    uint64_t index = (uint64_t)i_target & mask;
    uint64_t base_unaligned =
        -(((uint64_t)pr_base & mask) != 0); // -1 when unaligned
    uint64_t cursor =
        (((uint64_t)pr_base & ~mask) | index) + (base_unaligned & stride);
    uint64_t end = (uint64_t)pr_base + pr_len;
    assert(((uint64_t)i_target < cursor) || (uint64_t)i_target > end);
    uint64_t n = (1 & base_unaligned) + ((end - cursor) >> idx_bits);
    void **o_evset = malloc(n * sizeof(void *));
    for (int i = 0; i < n; i++) {
        assert(cursor < end);
        o_evset[i] = (void *)cursor;
        cursor += stride;
    }
    ctx->prime_set = malloc(sizeof(prime_set_t));
    ctx->prime_set->list = o_evset;
    ctx->prime_set->available = n;
}

inline void prime_set_t_free(prime_set_t *pr_set) {
    if (pr_set->list) {
        free(pr_set->list);
        pr_set->list = NULL;
    }
}
inline void ctx_t_free_prime_set(ctx_t *ctx) {
    if (ctx->prime_set) {
        prime_set_t_free(ctx->prime_set);
        free(ctx->prime_set);
        ctx->prime_set = NULL;
    }
}

typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

/*
 * https://github.com/cirosantilli/linux-kernel-module-cheat/blob/25f9913e0c1c5b4a3d350ad14d1de9ac06bfd4be/kernel_module/user/common.h
 */

/* Parse the pagemap entry for the given virtual address.
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr) {
    size_t nread;
    ssize_t ret;
    uint64_t data;

    nread = 0;
    while (nread < sizeof(data)) {
        ret =
            pread(pagemap_fd, ((uint8_t *)&data) + nread, sizeof(data) - nread,
                  (vaddr / sysconf(_SC_PAGE_SIZE)) * sizeof(data) + nread);
        nread += ret;
        if (ret <= 0) {
            return 1;
        }
    }
    entry->pfn = data & (((uint64_t)1 << 54) - 1);
    entry->soft_dirty = (data >> 54) & 1;
    entry->file_page = (data >> 61) & 1;
    entry->swapped = (data >> 62) & 1;
    entry->present = (data >> 63) & 1;
    return 0;
}

/* Convert the given virtual address to physical using /proc/PID/pagemap.
 *
 * @param[out] paddr physical address
 * @param[in]  pid   process to convert for
 * @param[in]  vaddr virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr) {
    char pagemap_file[BUFSIZ];
    int pagemap_fd;

    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap",
             (uintmax_t)pid);
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        return 1;
    }
    PagemapEntry entry;
    if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
        return 1;
    }
    close(pagemap_fd);
    *paddr =
        (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    return 0;
}

void *get_rw_buffer_in_tramp(uint64_t size, pagemap_t tramp, ctx_t ctx) {
    // TODO: an additinal margin to prevent consecutive line prefetching
    uint64_t prefetch_margin = 0;
    uint64_t allowed_size = (SIZE_PRIME_GAP - SIZE_CACHE_LINE);
    if (size >= (args.tramp_size - SIZE_CACHE_LINE)) {
        fprintf(stderr,
                "E: RW buffer bigger than trampoline! Requested %" PRIu64 "\n",
                size);
        exit(-1);
    }
    if (size >= allowed_size) { // WARNING: requested buffer is larger than a
                                // gap between prime lines!
        fprintf(stderr,
                "W: RW buffer oversized. Allow %" PRIu64 ", requested %" PRIu64
                "\n",
                allowed_size, size);
    }

    void **prset = ctx.prime_set->list;
    uint64_t nr_prime = args.cache_ways;
    void *min = (void *)-1ULL, *max = NULL;
    for (uint64_t i = 0; i < nr_prime; i++) {
        if (prset[i] > max)
            max = prset[i];
        if (prset[i] < min)
            min = prset[i];
    }
    min = (CACHE_LINE_ALIGN(min) - prefetch_margin);
    max = (CACHE_LINE_ALIGN(max) + SIZE_CACHE_LINE + prefetch_margin);
    uint64_t min_margin = min - tramp.p;
    uint64_t max_margin = (tramp.p + tramp.size) - max;

    uint64_t scan_grow = 0;
    void *scan_start = NULL;
    if (max_margin >= size) {
        scan_grow = 0;
        scan_start = max;
    } else if (min_margin >= size) {
        scan_grow = -1;
        scan_start = min;
    } else {
        if (size >= allowed_size) {
            fprintf(stderr, "E: No enough spaces between prime lines!\n");
            exit(-1);
        }
        scan_grow = 0;
        scan_start = prset[0];
    }

    void *o = CACHE_LINE_ALIGN(scan_start + scan_grow * size);
    return o;
}

inline void init_probe_descriptor(void **evset, walk_descriptor_t *o_walk_probe,
                                  ctx_t ctx) {
    uint64_t nr_prime = args.cache_ways;
    uint64_t len = nr_prime + 1;
    // create probe chain
    uint64_t *chain_probe = malloc(sizeof(uint64_t) * len);
    uint64_t *iobuf_probe =
        get_rw_buffer_in_tramp(sizeof(uint64_t) * len, pmap_tramp, ctx);
    for (int i = 0; i < nr_prime; i++) {
        chain_probe[i] = (uint64_t)evset[nr_prime - i - 1];
    }
    // last jump to the tail
    chain_probe[nr_prime] = (uint64_t)&walk_wrapper_tail;

    o_walk_probe->ro_chain = chain_probe;
    o_walk_probe->rw_buffer = iobuf_probe;
    o_walk_probe->len = len;
}

inline void init_prime_descriptor(walk_descriptor_t *walk_probe,
                                  walk_descriptor_t *o_walk_prime, ctx_t ctx) {
    // walk the prime set back and forth
    uint64_t nr_rept = ctx.prime_rounds;
    uint64_t *chain_probe = walk_probe->ro_chain;
    uint64_t nr_probe = (walk_probe->len) - 1; // exclude the tail
    uint64_t len_chain_prime = ((nr_rept * (nr_probe - 1)) + 1);
    uint64_t *chain_prime = malloc(sizeof(uint64_t) * len_chain_prime);
    uint64_t *iobuf_prime = get_rw_buffer_in_tramp(
        sizeof(uint64_t) * len_chain_prime, pmap_tramp, ctx);
    for (int i = 0; i < nr_rept; i++) {
        if (i % 2 == 0) {
            for (int j = 0; j < nr_probe - 1; j++)
                chain_prime[i * (nr_probe - 1) + j] =
                    chain_probe[nr_probe - j - 1];
        } else {
            for (int j = 0; j < nr_probe - 1; j++)
                chain_prime[i * (nr_probe - 1) + j] = chain_probe[j];
        }
    }
    chain_prime[len_chain_prime - 1] = (uint64_t)&walk_wrapper_tail;

    o_walk_prime->ro_chain = chain_prime;
    o_walk_prime->rw_buffer = iobuf_prime;
    o_walk_prime->len = len_chain_prime;
}

inline void init_pp_descriptors(void **evset, pp_descriptors_t *o_descriptor,
                                ctx_t ctx) {
    uint64_t nr_prime = args.cache_ways;
    uint64_t snippet_size = LEN_PRIME_SNIPPET;
    walk_descriptor_t *walk_probe = &(o_descriptor->walk_probe);
    walk_descriptor_t *walk_prime = &(o_descriptor->walk_prime);
    // copy prime snippet to all evset entries
    for (int i = 0; i < nr_prime; i++) {
        memcpy((void *)evset[i], &prime_snippet, LEN_PRIME_SNIPPET);
        __builtin___clear_cache((char *)evset[i],
                                (char *)evset[i] + LEN_PRIME_SNIPPET);
    }
    // initialize descriptors
    init_probe_descriptor(evset, walk_probe, ctx);
    init_prime_descriptor(walk_probe, walk_prime, ctx);
}

void walk_descriptor_t_copy_to_iobuf(walk_descriptor_t *desc) {
    for (uint64_t i = 0; i < desc->len; i++) {
        desc->rw_buffer[i] = desc->ro_chain[i];
    }
}

void walk_descriptor_t_free(walk_descriptor_t *desc) {
    if (desc->ro_chain)
        free(desc->ro_chain);
}

void pp_descriptors_t_free(pp_descriptors_t *desc) {
    walk_descriptor_t_free(&(desc->walk_prime));
    walk_descriptor_t_free(&(desc->walk_probe));
}

void print_res_test_primeprobe(void *evict_line, void **evset,
                               uint64_t *rw_buffer_probe) {
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
               (void *)paddr, p_idx, rw_buffer_probe[i]);
        printf((rw_buffer_probe[i] > args.threshold_ns) ? " *EVICTED*\n"
                                                        : "\n");
    }
#if defined(__aarch64__)
    if (args.pmu_event_id != (uint16_t)-1)
        printf("PMU ev_0x%x=%d\n", args.pmu_event_id,
               rw_buffer_probe[nr_prime]);
#endif
}

void print_primeprobe_desciptor(pp_descriptors_t *pp_desc) {
    printf("walk_probe.rw_buffer=%p-%p\n", pp_desc->walk_probe.rw_buffer,
           pp_desc->walk_probe.rw_buffer +
               pp_desc->walk_probe.len * sizeof(uint64_t));
    printf("walk_probe.ro_chain=%p\n", pp_desc->walk_probe.ro_chain);
    for (uint64_t i = 0; i < pp_desc->walk_probe.len; i++)
        printf("--[%" PRIu64 "]=%p\n", i,
               (void *)(pp_desc->walk_probe.ro_chain[i]));
    printf("walk_prime.rw_buffer=%p\n", pp_desc->walk_prime.rw_buffer);
    printf("walk_prime.ro_chain=%p\n", pp_desc->walk_prime.ro_chain);
    for (uint64_t i = 0; i < pp_desc->walk_prime.len; i++)
        printf("--[%" PRIu64 "]=%p\n", i,
               (void *)(pp_desc->walk_prime.ro_chain[i]));
}

uint64_t test_primeprobe(pagemap_t pr, ctx_t *ctx) {
    void *ev = ctx->ev;
    void *pr_base = pr.p;
    uint64_t pr_size = pr.size;
    uint64_t nr_prime = args.cache_ways;
    uint64_t evict_cntr = 0;

    get_prime_set(pr, ctx);
    void **prset = ctx->prime_set->list;
    uint64_t nr_available_ev = ctx->prime_set->available;
    assert((ctx->prime_set) && (prset) && (nr_available_ev >= nr_prime));

    uint64_t chain_evict[4] = {(uint64_t)ev, (uint64_t)ev, (uint64_t)ev,
                               (uint64_t)&walk_wrapper_tail};

    memcpy((void *)ev, &prime_snippet, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)ev, (char *)ev + LEN_PRIME_SNIPPET);

    pp_descriptors_t pp_desc;
    init_pp_descriptors(prset, &pp_desc, *ctx);
    uint64_t *rw_buffer_probe = pp_desc.walk_probe.rw_buffer;
    uint64_t *rw_buffer_prime = pp_desc.walk_prime.rw_buffer;

    if (args.verbose)
        print_primeprobe_desciptor(&pp_desc);

    // Prime the cache set
    for (int _prime = 0; _prime < ctx->prime_rounds_repeats; _prime++) {
        walk_descriptor_t_copy_to_iobuf(&(pp_desc.walk_prime));
        OPS_BARRIER(8);
        walk_wrapper_head(rw_buffer_prime);
        OPS_BARRIER(8);
    }

    { // do evict on demand!
        uint64_t iobuf_evict[4];
        for (int i = 0; i < ctx->evict_repeats; i++) {
            // If we don't want eviction, create a shortcut to the tail.
            iobuf_evict[0] = args.do_eviction ? chain_evict[0] : chain_evict[3];
            iobuf_evict[1] = chain_evict[1];
            iobuf_evict[2] = chain_evict[2];
            iobuf_evict[3] = chain_evict[3];
            // for (int j = 0; j < 4; j++)
            //     printf("EVICT CHAIN[%d]=%p\n", j, (void *)iobuf_evict[j]);
            OPS_BARRIER(8);
            walk_wrapper_head(iobuf_evict);
            OPS_BARRIER(8);
        }
    }
    OPS_BARRIER(8);

#if defined(DBG_FLUSH_EVSET)
    for (int i = 0; i < nr_prime; i++) {
        FLUSH_ICACHE(evset[i]);
    }
#endif

    walk_descriptor_t_copy_to_iobuf(&(pp_desc.walk_probe));
    // let's detect who has been evicted by *test_cursor
    OPS_BARRIER(8);
    walk_wrapper_head(rw_buffer_probe);
    OPS_BARRIER(8);
    for (int i = 0; i < nr_prime; i++) {
        evict_cntr += (rw_buffer_probe[i] > args.threshold_ns);
    }
    if (ctx->dbg_print_res)
        print_res_test_primeprobe(ev, prset, rw_buffer_probe);

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
    // TODO: check conflict with other prime entries
    assert(pmap_pr.p);
    test_ptr = pmap_pr.p +
               (args.offset_dbg_probe & ((1 << args.cache_idx_bits) - 1)) -
               (12 << args.cache_idx_bits);
}

void test_latency() {
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
    argp_parse(&argp, argc, argv, 0, 0, NULL);
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
            .prime_rounds = 16,
            .prime_rounds_repeats = 16,
            .evict_repeats = 4,
            .dbg_print_res = args.verbose,
        };
        uint64_t cntr_evicted = 0;
        for (int j = 0; j < 100; j++) {
            cntr_evicted += test_primeprobe(pmap_pr, &ctx);
        }
        printf("PTR=%p, PRIME_ROUNDS=%" PRIu64 ", PRIME_ROUNDS_REPEATS=%" PRIu64
               " => EVICTED=%" PRIu64 "\n",
               ptr, ctx.prime_rounds, ctx.prime_rounds_repeats, cntr_evicted);
    }

    // ctx_t ctx = {
    //         .ev = test_cursor,
    //         .prime_rounds = 256,
    //         .prime_rounds_repeats = 256,
    //         .evict_repeats = 128,
    //         .dbg_print_res = false,
    //     };
    // test_primeprobe(pmap_pr, ctx);
    finish();
}