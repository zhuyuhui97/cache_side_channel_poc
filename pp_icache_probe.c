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
} args_t;

args_t args = {.tramp_base = NULL,
               .tramp_bits = TRAMP_BITS_DEFAULT,
               .tramp_size = (1 << TRAMP_BITS_DEFAULT),
               .cache_ways = 16,
               .cache_idx_bits = 20,
               .cache_offset_bits = 6,
               .offset_dbg_probe = OFFSET_PROBE_INPAGE,
               .pmu_event_id = -1,
               .threshold_ns = 0,
               .do_eviction = false};

uint64_t os_page_size = 0;
uint64_t pid = -1;
void *tramp = NULL;
pagemap_t rw_buffer_shared = {
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

void *create_ret_tramp(uint32_t size, void *base) {
    void *buf = create_exec_tramp(size, base);
    for (void *_cursor = buf; _cursor < (buf + size); _cursor += 4)
        *(uint32_t *)(_cursor) = OPCODE_RET;
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    return buf;
}

void fill_bhb(void) {
    void *_cursor = tramp + 0x9200;
    uintptr_t end = (uintptr_t)tramp + args.tramp_size;
    for (int i = 0; i < FILL_BHB_LEN; i++) {
        _cursor += (1 << NR_OPCODE_ALIGN);
        { // _cursor = (_cursor>=(ret_tramp+tramp_size)) ? ret_tramp : _cursor;
            uintptr_t cur = (uintptr_t)_cursor;
            // all-ones if cur >= end, else 0
            uintptr_t mask = -(uintptr_t)(cur >= end);
            cur = (cur & ~mask) | ((uintptr_t)tramp & mask);
            _cursor = (void *)cur;
        }
        CALL_ADDR(_cursor);
    }
}

static inline __attribute__((always_inline)) uint64_t read_cycles() {
#if !defined(DBG_TIMER_HW)
#define NANOSECONDS_PER_SECOND 1000000000L
    struct timespec tp;
    clockid_t clk_id = CLOCK_REALTIME;
    clock_gettime(clk_id, &tp);
    return (uint64_t)((tp.tv_sec * NANOSECONDS_PER_SECOND) + tp.tv_nsec);
#else
#if defined(__x86_64__)
    register uint64_t cnt_new_lo, cnt_new_hi;
    asm volatile("rdtsc\n" : "=a"(cnt_new_lo), "=d"(cnt_new_hi)::);
    return ((cnt_new_hi << 32) | cnt_new_lo);
#elif defined(__aarch64__)
    register uint64_t cntr;
    asm volatile("mrs %0, pmccntr_el0" : "=r"(cntr));
    return cntr;
#endif
#endif
}

/**
 * Jump to requested address and measure the jump latency.
 * Remember record the timer after loading the target and a memory barrier.
 */
uint64_t measure_br_latency(bool *br_cond, register void *target) {
    register uint64_t t = 0;
    // fill_bhb();
    if (*br_cond) {
        OPS_BARRIER(0);
        t = read_cycles();
        CALL_ADDR(target);
        OPS_BARRIER(0);
        t = read_cycles() - t;
    }
    return t;
}

void train_bcond(void *valid_target) {
    for (int i = 0; i < NR_BPU_ACTV; i++) {
        measure_br_latency((bool *)&dont_br, valid_target);
        measure_br_latency((bool *)&do_br, valid_target);
    }
    for (int i = 0; i < NR_BPU_TRAIN; i++) {
        measure_br_latency((bool *)&do_br, valid_target);
    }
}

void test_icache_latency(void *probe, void *tramp, uint64_t tramp_size,
                         uint64_t *o_fast, uint64_t *o_slow) {
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

void **get_evset(void *i_target, void *i_base, uint64_t i_len,
                 uint64_t i_addr_bits, uint64_t *o_n) {
    uint64_t stride = 1 << i_addr_bits;
    uint64_t mask = stride - 1;
    uint64_t index = (uint64_t)i_target & mask;
    uint64_t base_unaligned =
        -(((uint64_t)i_base & mask) != 0); // -1 when unaligned
    uint64_t cursor =
        (((uint64_t)i_base & ~mask) | index) + (base_unaligned & stride);
    uint64_t end = (uint64_t)i_base + i_len;
    assert(((uint64_t)i_target < cursor) || (uint64_t)i_target > end);
    uint64_t n = (1 & base_unaligned) + ((end - cursor) >> i_addr_bits);
    *o_n = n;
    void **o_evset = malloc(n * sizeof(void *));
    for (int i = 0; i < n; i++) {
        assert(cursor < end);
        o_evset[i] = (void *)cursor;
        cursor += stride;
    }
    return o_evset;
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

inline void init_probe_descriptor(uint64_t nr_ev, void **evset,
                                  walk_descriptor_t *o_walk_probe) {
    uint64_t len = nr_ev + 1;
    // create probe chain
    uint64_t *chain_probe = malloc(sizeof(uint64_t) * len);
    uint64_t *iobuf_probe = malloc(sizeof(uint64_t) * len);
    printf("iobuf_probe=%p - %p\n", iobuf_probe,
           (void *)((char *)iobuf_probe + len));
    for (int i = 0; i < nr_ev; i++) {
        chain_probe[i] = (uint64_t)evset[nr_ev - i - 1];
    }
    // last jump to the tail
    chain_probe[nr_ev] = (uint64_t)&walk_wrapper_tail;

    o_walk_probe->ro_chain = chain_probe;
    o_walk_probe->rw_buffer = iobuf_probe;
    o_walk_probe->len = len;
}

inline void init_prime_descriptor(uint64_t nr_rept,
                                  walk_descriptor_t *walk_probe,
                                  walk_descriptor_t *o_walk_prime) {
    uint64_t *chain_probe = walk_probe->ro_chain;
    uint64_t nr_probe = (walk_probe->len) - 1; // exclude the tail
    uint64_t len_chain_prime = ((nr_rept * (nr_probe - 1)) + 1);
    printf("Prime descriptor: nr_rept=%" PRIu64 ", nr_probe=%" PRIu64
           ", len_chain_prime=%" PRIu64 "\n",
           nr_rept, nr_probe, len_chain_prime);
    uint64_t *chain_prime = malloc(sizeof(uint64_t) * len_chain_prime);
    uint64_t *iobuf_prime = malloc(sizeof(uint64_t) * len_chain_prime);
    printf("iobuf_prime=%p - %p\n", iobuf_prime,
           (void *)((char *)iobuf_prime + len_chain_prime));
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

inline void init_pp_descriptors(uint64_t nr_ev, void **evset,
                                pp_descriptors_t *o_descriptor) {
    uint64_t snippet_size = LEN_PRIME_SNIPPET;
    walk_descriptor_t *walk_probe = &(o_descriptor->walk_probe);
    walk_descriptor_t *walk_prime = &(o_descriptor->walk_prime);
    // copy prime snippet to all evset entries
    for (int i = 0; i < nr_ev; i++) {
        memcpy((void *)evset[i], &prime_snippet, LEN_PRIME_SNIPPET);
        __builtin___clear_cache((char *)evset[i],
                                (char *)evset[i] + LEN_PRIME_SNIPPET);
    }
    // initialize descriptors
    init_probe_descriptor(nr_ev, evset, walk_probe);
#define NR_PRIME_REPT 256
    init_prime_descriptor(NR_PRIME_REPT, walk_probe, walk_prime);
#undef NR_PRIME_REPT
}

inline void walk_descriptor_t_copy_to_iobuf(walk_descriptor_t *desc) {
    for (uint64_t i = 0; i < desc->len; i++) {
        desc->rw_buffer[i] = desc->ro_chain[i];
    }
}

void walk_descriptor_t_free(walk_descriptor_t *desc) {
    if (desc->ro_chain)
        free(desc->ro_chain);
    if (desc->rw_buffer)
        free(desc->rw_buffer);
}

void pp_descriptors_t_free(pp_descriptors_t *desc) {
    walk_descriptor_t_free(&(desc->walk_prime));
    walk_descriptor_t_free(&(desc->walk_probe));
}

void print_res_test_primeprobe(uint64_t nr_ev, void *evict_line, void **evset,
                               uint64_t *rw_buffer_probe) {
    assert(pid != -1);
    {
        uintptr_t paddr;
        virt_to_phys_user(&paddr, pid, (uintptr_t)evict_line);
        printf("!\tv=%p\tp=%p\n", evict_line, (void *)paddr);
    }
    for (int i = 0; i < nr_ev; i++) {
        uintptr_t paddr;
        virt_to_phys_user(&paddr, pid, (uintptr_t)evset[i]);
        uint p_idx = ((paddr & ((1 << args.cache_idx_bits) - 1)) >>
                      args.cache_offset_bits);
        printf("%d\tv=%p\tp=%p\tp_idx=%6x\t%" PRIu64, i, evset[i],
               (void *)paddr, p_idx, rw_buffer_probe[i]);
        printf((rw_buffer_probe[i] > args.threshold_ns) ? " *EVICTED*\n"
                                                        : "\n");
    }
}

uint64_t test_primeprobe(void *evict_line, void *ev_base, uint64_t ev_size,
                         uint64_t nr_ev) {
    uint64_t evict_cntr = 0;
    uint64_t nr_available_ev;
    void **evset = get_evset(evict_line, ev_base, ev_size, args.cache_idx_bits,
                             &nr_available_ev);
    assert(nr_available_ev >= nr_ev);

    uint64_t chain_evict[4] = {(uint64_t)evict_line, (uint64_t)evict_line,
                               (uint64_t)evict_line,
                               (uint64_t)&walk_wrapper_tail};

    memcpy((void *)evict_line, &prime_snippet, LEN_PRIME_SNIPPET);
    __builtin___clear_cache((char *)evict_line,
                            (char *)evict_line + LEN_PRIME_SNIPPET);

    pp_descriptors_t pp_desc;
    init_pp_descriptors(nr_ev, evset, &pp_desc);
    uint64_t *rw_buffer_probe = pp_desc.walk_probe.rw_buffer;
    uint64_t *rw_buffer_prime = pp_desc.walk_prime.rw_buffer;

    // Prime the cache set
    for (int _prime = 0; _prime < 256; _prime++) {
        walk_descriptor_t_copy_to_iobuf(&(pp_desc.walk_prime));
        OPS_BARRIER(8);
        walk_wrapper_head(rw_buffer_prime);
        OPS_BARRIER(8);
    }

    { // do evict on demand!
        uint64_t iobuf_evict[4];
        for (int i = 0; i < 128; i++) {
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
    for (int i = 0; i < nr_ev; i++) {
        FLUSH_ICACHE(evset[i]);
    }
#endif

    walk_descriptor_t_copy_to_iobuf(&(pp_desc.walk_probe));
    // let's detect who has been evicted by *test_cursor
    OPS_BARRIER(8);
    walk_wrapper_head(rw_buffer_probe);
    OPS_BARRIER(8);
    for (int i = 0; i < nr_ev; i++) {
        evict_cntr += (rw_buffer_probe[i] > args.threshold_ns);
    }
    print_res_test_primeprobe(nr_ev, evict_line, evset, rw_buffer_probe);
#if defined(__aarch64__)
    if (args.pmu_event_id != (uint16_t)-1)
        printf("PMU ev_0x%x=%d\n", args.pmu_event_id, rw_buffer_probe[nr_ev]);
#endif

    free(evset);
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
    printf("\n");
}

void init_rw_buffer_shared() {
    uint64_t size = (2 << args.cache_idx_bits);
    void *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(buf != MAP_FAILED);
    rw_buffer_shared.p = buf;
    rw_buffer_shared.size = size;
}

void init(int argc, char **argv) {
    // TODO: handle different cache line size
    assert(LEN_PRIME_SNIPPET == 64);
    argp_parse(&argp, argc, argv, 0, 0, NULL);
    assert(args.offset_dbg_probe < args.tramp_size);
    os_page_size = getpagesize();
    pid = getpid();
    init_rw_buffer_shared();
    print_env();
}

int main(int argc, char **argv) {
    init(argc, argv);
    tramp = create_exec_tramp(args.tramp_size, args.tramp_base);
    assert(tramp);
#if defined(__aarch64__)
    if (args.pmu_event_id != (uint16_t)-1)
        INIT_PMU(0, args.pmu_event_id);
#endif

    void *ev_base = tramp + (args.tramp_size >> 1);
    // TODO: remove magic number
    void *test_cursor =
        ev_base + (args.offset_dbg_probe & ((1 << args.cache_idx_bits) - 1)) -
        (12 << args.cache_idx_bits);
    if (args.threshold_ns == 0) { // calibrate threshold
        uint64_t cache_fast, cache_slow;
        test_icache_latency(tramp + 0x6c0, ev_base, args.tramp_size >> 1,
                            &cache_fast, &cache_slow);
        args.threshold_ns = (cache_fast + cache_slow) / 2;
        printf("FAST:%" PRIu64 " SLOW:%" PRIu64 " THRESHOLD:%" PRIu64 "\n",
               cache_fast, cache_slow, args.threshold_ns);
    } else {
        printf("THRESHOLD:%" PRIu64 "\n", args.threshold_ns);
    }
    test_primeprobe(test_cursor, ev_base, args.tramp_size >> 1,
                    args.cache_ways);

    munmap(tramp, args.tramp_size);
}