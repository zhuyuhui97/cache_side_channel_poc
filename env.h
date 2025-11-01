#ifndef _ENV_H_
#define _ENV_H_

#include <stdint.h>
#include <stdbool.h>
#include <argp.h>
#include <unistd.h>

#define OFFSET_PROBE_INPAGE 0x2ca0
#define TRAMP_BITS_DEFAULT 26 // 64MB
#define __NOP(x, rsh)                                                          \
    asm volatile(".rept " MACRO_TO_STR(x >> rsh) "\n nop\n .endr")
#define NOP(x) __NOP(x, 0)

#define CALL_ADDR(x) ((void (*)(void))(x))()
#define MEM_ACCESS(p) *(volatile unsigned char *)p
#define MACRO_TO_STR(x) #x

#define SIZE_PRIME_GAP (1 << args.cache_idx_bits)

#define SIZE_CACHE_LINE (1 << args.cache_offset_bits)
#define ALIGN_CACHE_LINE(addr) ((uint64_t)addr & ~(SIZE_CACHE_LINE - 1))
#define OFFSET_IN_CACHE_LINE(addr) ((uint64_t)addr & (SIZE_CACHE_LINE - 1))

#define ALIGN_PAGE(addr) ((void *)((uint64_t)addr & ~(os_page_size - 1)))
#define OFFSET_IN_PAGE(addr) ((uint64_t)addr & (os_page_size - 1))

typedef struct {
    uint64_t i_target;
    uint64_t o_cycle;
} walk_step_t;

typedef struct {
    void *p;
    uint64_t size;
} pagemap_t;

typedef struct {
    walk_step_t *walk_buffer;
    uint64_t len;
    pagemap_t map;
} walk_descriptor_t;

typedef struct {
    walk_descriptor_t walk_prime;
    walk_descriptor_t walk_probe;
} pp_descriptors_t;

typedef struct {
    walk_descriptor_t ev_stub;
    walk_descriptor_t ev_flag;
} ev_descriptors_t;

typedef struct {
    void **list;
    uint64_t available;
} prime_set_t;


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
    bool peek_phys_map;
    uint64_t prime_sweep;
    uint64_t prime_repeat;
    uint64_t nr_repeat;
    uint64_t evict_repeat;
} args_t;

typedef struct {
    void *ev;
    uint64_t prime_sweep;
    uint64_t prime_repeat;
    uint64_t evict_repeat;
    prime_set_t *prime_set;
    bool dbg_print_res;
    uint64_t cache_entry_size;
    args_t *args;
} ctx_t;

extern args_t args;
extern pid_t pid;
extern uint64_t os_page_size;
extern uint64_t os_page_offset_bits;

error_t init_args(int argc, char **argv);
error_t init_paging_info();

#endif