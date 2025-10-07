/**
 * Probing executable addresses based on i$ prime+probe side channel.
 * Based on paper: *Speculative Probing: Hacking Blind in the Spectre Era*
 */

#include <argp.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h> /* open */
#include <unistd.h> /* pread, sysconf */


#define NR_BPU_ACTV 4
#define NR_BPU_TRAIN 32
#define OFFSET_PROBE_INPAGE 0x2ca0
#define FILL_BHB_LEN 600
#define __NOP(x, rsh)                                                          \
    asm volatile(".rept " MACRO_TO_STR(x >> rsh) "\n nop\n .endr")
#define NOP(x) __NOP(x, 0)

#define CALL_ADDR(x) ((void (*)(void))(x))()
#define MEM_ACCESS(p) *(volatile unsigned char *)p
#define MACRO_TO_STR(x) #x

/* uarch-dependent definitions */
#if defined(__x86_64__)
#define OPS_BARRIER(x)                                                         \
    asm volatile("mfence");                                                    \
    NOP(x);
#define OPCODE_RET (0xC3C3C3C3UL)
#define NR_OPCODE_ALIGN 0
#elif defined(__aarch64__)
#define OPS_BARRIER(x)                                                         \
    asm volatile("dsb sy");                                                    \
    asm volatile("isb");                                                       \
    NOP(x);
#define OPCODE_RET (0xD65F03C0UL)
#define NR_OPCODE_ALIGN 2
#endif

const bool dont_br = false, do_br = true;

uint64_t os_page_size;
uint64_t tramp_size = (64 << 20);
// uint64_t cache_ways = 32;
// uint64_t cache_idx_bits = 16;
// uint64_t cache_ways = 16;
// uint64_t cache_idx_bits = 10;
uint64_t cache_ways = 16;
uint64_t cache_idx_bits = 20;
uint64_t cache_line_sz = 64;
void *ret_tramp;

static struct argp_option options[] = {
    {"ways", 'w', "CACHE_WAYS", 0, "Number of ways."},
    {"bits", 'b', "CACHE_IDX_BITS", 0, "Number of index bits."},
    {"line", 'l', "CACHE_LINE_SZ", 0, "Size of cache line, default 64b."},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    switch (key) {
    case 'w':
        cache_ways = strtoul(arg, NULL, 0);
        break;
    case 'b':
        cache_idx_bits = strtoul(arg, NULL, 0);
        break;
    case 'l':
        cache_line_sz = strtoul(arg, NULL, 0);
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
    memset(buf, (int)(OPCODE_RET & 0xFF), size);
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    return buf;
}

void fill_bhb(void) {
    void *_cursor = ret_tramp + 0x9200;
    uintptr_t end = (uintptr_t)ret_tramp + tramp_size;
    for (int i = 0; i < FILL_BHB_LEN; i++) {
        _cursor += (1 << NR_OPCODE_ALIGN);
        { // _cursor = (_cursor>=(ret_tramp+tramp_size)) ? ret_tramp : _cursor;
            uintptr_t cur = (uintptr_t)_cursor;
            // all-ones if cur >= end, else 0
            uintptr_t mask = -(uintptr_t)(cur >= end);
            cur = (cur & ~mask) | ((uintptr_t)ret_tramp & mask);
            _cursor = (void *)cur;
        }
        CALL_ADDR(_cursor);
    }
}

#define NANOSECONDS_PER_SECOND 1000000000L
uint64_t read_cycles() {
    struct timespec tp;
    clockid_t clk_id = CLOCK_REALTIME;
    clock_gettime(clk_id, &tp);
    return (uint64_t)((tp.tv_sec * NANOSECONDS_PER_SECOND) + tp.tv_nsec);
}

/**
 * Jump to requested address and measure the jump latency.
 * Remember record the timer after loading the target and a memory barrier.
 */
uint64_t measure_br_latency(bool *br_cond, register void *target) {
    register uint64_t t = 0;
    // fill_bhb();
    if (*br_cond) {
        OPS_BARRIER(8);
        t = read_cycles();
        CALL_ADDR(target);
        OPS_BARRIER(8);
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

void test_icache_latency(uint64_t *fast, uint64_t *slow) {
    // test branch latency when target in icache
    // TODO: MAGIC NUMBER HERE
    void *test_target = ret_tramp + 0xc20;
    for (int i = 0; i < 4; i++)
        *fast = measure_br_latency((bool *)&do_br, test_target);
    // test branch latency when target not in icache
#if defined(__x86_64__)
    asm volatile("clflush (%0)" ::"r"(test_target));
#elif defined(__aarch64__)
    __builtin___clear_cache((char *)ret_tramp, (char *)ret_tramp + tramp_size);
#endif
    OPS_BARRIER(0x20);
    *slow = measure_br_latency((bool *)&do_br, test_target);
}

void get_evset(void *i_target, void *i_base, uint64_t i_len,
               uint64_t i_addr_bits, uint64_t *o_n, void *o_evset[]) {
    uint64_t stride = 1 << i_addr_bits;
    uint64_t mask = stride - 1;
    uint64_t index = (uint64_t)i_target & mask;
    uint64_t base_unaligned = -(((uint64_t)i_base & mask) != 0); // -1 when unaligned
    uint64_t cursor =
        (((uint64_t)i_base & ~mask) | index) + (base_unaligned & stride);
    uint64_t end = (uint64_t)i_base + i_len;
    assert(((uint64_t)i_target<cursor)||(uint64_t)i_target>end);
    uint64_t n = (1 & base_unaligned) + ((end - cursor) >> i_addr_bits);
    *o_n = n;
    *o_evset = malloc(n * sizeof(void *));
    for (int i = 0; i < n; i++) {
        assert(cursor<end);
        o_evset[i] = (void *)cursor;
        cursor += stride;
    }
}

typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

/* Parse the pagemap entry for the given virtual address.
 * https://github.com/cirosantilli/linux-kernel-module-cheat/blob/25f9913e0c1c5b4a3d350ad14d1de9ac06bfd4be/kernel_module/user/common.h
 *
 * @param[out] entry      the parsed entry
 * @param[in]  pagemap_fd file descriptor to an open /proc/pid/pagemap file
 * @param[in]  vaddr      virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr)
{
    size_t nread;
    ssize_t ret;
    uint64_t data;

    nread = 0;
    while (nread < sizeof(data)) {
        ret = pread(pagemap_fd, ((uint8_t*)&data) + nread, sizeof(data) - nread,
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
 * @param[in] vaddr virtual address to get entry for
 * @return 0 for success, 1 for failure
 */
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr)
{
	char pagemap_file[BUFSIZ];
	int pagemap_fd;

	snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap", (uintmax_t)pid);
	pagemap_fd = open(pagemap_file, O_RDONLY);
	if (pagemap_fd < 0) {
		return 1;
	}
	PagemapEntry entry;
	if (pagemap_get_entry(&entry, pagemap_fd, vaddr)) {
		return 1;
	}
	close(pagemap_fd);
	*paddr = (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
	return 0;
}

void test_evict() {
    void *test_base = ret_tramp;
    void *ev_base = ret_tramp + (tramp_size >> 1);
    void *test_cursor = test_base + OFFSET_PROBE_INPAGE;
    // load *test_cursor to L1i$
    CALL_ADDR(test_cursor);
    // let's try evicting *test_cursor
    // TODO: HANDLING CURSOR OVERFLOW
    for (void *ev_cursor = test_cursor + (tramp_size >> 1);
         ev_cursor < ret_tramp + tramp_size;
         ev_cursor += (1 << cache_idx_bits)) {
        CALL_ADDR(ev_cursor);
    }
    uint64_t lat = measure_br_latency((bool *)&do_br, test_cursor);
    printf("%llu\n", (unsigned long long)lat);
}

void test_evict2() {
    void *test_base = ret_tramp;
    void *ev_base = ret_tramp + (tramp_size >> 1);
    void *test_cursor = test_base + OFFSET_PROBE_INPAGE;
    void **evset = malloc(cache_ways * sizeof(void *));
    uint64_t *latency = malloc(cache_ways * sizeof(uint64_t));
    for (int i = 0; i < cache_ways; i++) {
        evset[i] = ev_base + OFFSET_PROBE_INPAGE + (i << cache_idx_bits);
    }
    for (int i = 0; i < cache_ways; i++) {
        for (int j = 0; j < 8; j++)
        {
            CALL_ADDR(evset[i]);
            OPS_BARRIER(8);
        }
    }
    // load *test_cursor to L1i$
    // for (int i = 0; i < 32; i++) {
    //     CALL_ADDR(test_cursor);
    //     OPS_BARRIER(8);
    // }


    // DEBUG: flush *evset[]
//     for (int i = 0; i < cache_ways; i++) {
// #if defined(__x86_64__)
//         asm volatile("clflush (%0)" ::"r"(evset[i]));
// #elif #elif defined(__aarch64__)
//         __builtin___clear_cache((char *)evset[i],
//                                 (char *)evset[i] + cache_line_sz);
// #endif
//     }


    // let's detect who has been evicted by *test_cursor
    for (int i = cache_ways - 1; i >= 0; i--) {
        OPS_BARRIER(8);
        register int idx = (i + 0) % cache_ways;
        latency[idx] = measure_br_latency((bool *)&do_br, evset[idx]);
    }
    for (int i = 0; i < cache_ways; i++) {
        printf("%llu ", (unsigned long long)latency[i]);
    }
    printf("\n");

    printf("! = %p\n", test_cursor);
    uint64_t pid = getpid();
    for (int i = 0; i < cache_ways; i++) {
        uintptr_t paddr;
        virt_to_phys_user(&paddr, pid, (uintptr_t)evset[i]);
        printf("%p %p\n", evset[i], paddr);
    }
    // getchar();

    free(evset);
    free(latency);
}

void print_env() {
    printf("=== ENV VALUES ===\n");
    printf("Page size: %" PRIu64 "\n", os_page_size);
    printf("=== USER VALUES ===\n");
    printf("Cache ways: %" PRIu64 "\n", cache_ways);
    printf("Cache index bits: %" PRIu64 " (cover %llu bytes)\n", cache_idx_bits,
           (1ULL << cache_idx_bits));
    printf("Trampoline size: %" PRIu64 " bytes\n", tramp_size);
    printf("\n");
}

int main(int argc, char **argv) {
    argp_parse(&argp, argc, argv, 0, 0, NULL);
    os_page_size = getpagesize();
    print_env();

    ret_tramp = create_ret_tramp(tramp_size, (void *)0x8003000);
    assert(ret_tramp);

    uint64_t cache_fast, cache_slow;
    test_icache_latency(&cache_fast, &cache_slow);
    printf("%llu %llu\n", (unsigned long long)cache_fast,
           (unsigned long long)cache_slow);

    test_evict2();

    uint64_t nr_evset;
    void **evset;
    get_evset((void*)0xabc0000, (void*)0x1abc0000, 0x800000, 16, &nr_evset, evset);
    // printf("%d\n", nr_evset);
    // for (int i=0; i<nr_evset; i++)
    // {
    //     printf("%p\n", evset[i]);
    // }
}