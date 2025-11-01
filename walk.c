#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "env.h"
#include "physmap.h"

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

void prime_set_t_free(prime_set_t *pr_set) {
    if (pr_set->list) {
        free(pr_set->list);
        pr_set->list = NULL;
    }
}

void ctx_t_free_prime_set(ctx_t *ctx) {
    if (ctx->prime_set) {
        prime_set_t_free(ctx->prime_set);
        free(ctx->prime_set);
        ctx->prime_set = NULL;
    }
}

void walk_descriptor_t_free(walk_descriptor_t *desc) {
    if (desc->map.p) {
        munmap(desc->map.p, desc->map.size);
        desc->map.p = NULL;
        desc->map.size = 0;
        desc->walk_buffer = NULL;
        desc->len = 0;
    }
}

void pp_descriptors_t_free(pp_descriptors_t *desc) {
    walk_descriptor_t_free(&(desc->walk_prime));
    walk_descriptor_t_free(&(desc->walk_probe));
}


#define PAGE_OFFSET_BITS 12
void get_prime_set_from_pagemap(pagemap_t pmap, ctx_t *ctx) {
    void *ev = ctx->ev;
    void *pr = pmap.p;
    uintptr_t paddr;
    virt_to_phys_user(&paddr, pid, (uintptr_t)ev);
    uint64_t group_index = (paddr & ((1<<args.cache_idx_bits)-1)) >> PAGE_OFFSET_BITS;
    physmap_decode_t *group = physmap_decode[group_index];
    physmap_decode_t *cursor = group;
    uint64_t page_count = 0;
    while (cursor) {
        page_count++;
        cursor = cursor->next;
    }
    cursor = group;

    void **o_evset = malloc(page_count * sizeof(void *));
    page_count = 0;
    while (cursor) {
        uint64_t vaddr = cursor->addr;
        cursor = cursor->next;
        vaddr &= ~((1<<PAGE_OFFSET_BITS)-1); // TODO: replace const
        vaddr |= (uint64_t) ev & ((1<<PAGE_OFFSET_BITS)-1);
        // if (abs((int)(vaddr - (uint64_t) ev))<0x40000) continue;
        if (vaddr == (uint64_t) ev) continue;
        o_evset[page_count] = (void*) vaddr;
        page_count++;
    }

    ctx->prime_set = malloc(sizeof(prime_set_t));
    ctx->prime_set->list = o_evset;
    ctx->prime_set->available = page_count;
}

void get_prime_set(pagemap_t pmap, ctx_t *ctx) {
    if (physmap_decode)
        return get_prime_set_from_pagemap(pmap, ctx);
    void *ev = ctx->ev;
    void *pr = pmap.p;
    uint64_t cache_entry_size = ctx->cache_entry_size;
    uint64_t pr_len = pmap.size;
    uint64_t idx_bits = ctx->args->cache_idx_bits;
    uint64_t stride = 1 << idx_bits;
    uint64_t in_stride_mask = stride - 1;
    uint64_t pr_in_stride_offset = (uint64_t)pr & in_stride_mask;
    uint64_t ev_in_stride_offset = (uint64_t)ev & in_stride_mask;
    // -1 when unaligned, otherwise 0
    uint64_t add_stride = -(ev_in_stride_offset < pr_in_stride_offset);

    uint64_t cursor = (((uint64_t)pr & ~in_stride_mask) | ev_in_stride_offset);
    cursor += (add_stride & stride);
    uint64_t end = (uint64_t)pr + pr_len;
    assert(((uint64_t)ev < cursor) || (uint64_t)ev > end);

    uint64_t n = (1 & add_stride) + ((end - cursor - cache_entry_size) >> idx_bits);
    void **o_evset = malloc(n * sizeof(void *));
    for (int i = 0; i < n; i++) {
        // printf("Prime set candidate[%d]: %p\n", i, (void *)cursor);
        assert(cursor < end);
        o_evset[i] = (void *)cursor;
        cursor += stride;
    }
    ctx->prime_set = malloc(sizeof(prime_set_t));
    ctx->prime_set->list = o_evset;
    ctx->prime_set->available = n;
}
