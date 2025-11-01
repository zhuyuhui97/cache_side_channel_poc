#include <stdint.h>
#include <stdio.h>
#include <fcntl.h> /* open */
#include <stdlib.h>
#include <string.h>
#include "physmap.h"
#include "env.h"
#include "assert.h"

physmap_decode_t **physmap_decode = NULL;
uint64_t nr_pm_decode_roots = 0;

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
    if (entry.pfn == 0) {
        return 1;
    }
    *paddr =
        (entry.pfn * sysconf(_SC_PAGE_SIZE)) + (vaddr % sysconf(_SC_PAGE_SIZE));
    return 0;
}

#define PAGE_OFFSET_BITS 12
#define PAGE_SIZE (1<<PAGE_OFFSET_BITS)
// This is cheating!
int peek_physmap(pagemap_t pmap, pid_t pid) {
    uint64_t base = (uint64_t) pmap.p;
    uint64_t span = pmap.size;
    char pagemap_file[BUFSIZ];
    int pagemap_fd;
    snprintf(pagemap_file, sizeof(pagemap_file), "/proc/%ju/pagemap",
             (uintmax_t)pid);
    pagemap_fd = open(pagemap_file, O_RDONLY);
    if (pagemap_fd < 0) {
        return 1;
    }
    
    // TODO: get page offset bits dynamically
    nr_pm_decode_roots = 1 << (args.cache_idx_bits - 12);
    uint64_t size = nr_pm_decode_roots * sizeof(physmap_decode_t *);
    physmap_decode = malloc(size);
    memset(physmap_decode, 0, size);
    uint64_t in_way_mask = SIZE_PRIME_GAP-1;
    uint64_t pfn_in_cway_mask = nr_pm_decode_roots - 1;
    for (uint64_t offset = 0; offset < span; offset += PAGE_SIZE) {
        uintptr_t paddr;
        uint64_t vaddr = (uint64_t) base + offset;
        *((uint64_t *) vaddr) = 0; // force mapping the physical page immediately

        PagemapEntry entry;
        pagemap_get_entry(&entry, pagemap_fd, vaddr);
        uint64_t index = entry.pfn & pfn_in_cway_mask;
        assert(index<nr_pm_decode_roots);
        
        physmap_decode_t *new = malloc(sizeof(physmap_decode_t));
        new->addr = vaddr;
        new->next = NULL;
        if (physmap_decode[index] == NULL)
            physmap_decode[index] = new;
        else {
            physmap_decode_t *cursor = physmap_decode[index];
            while (cursor->next != NULL) 
                cursor = cursor->next;
            cursor->next = new;
        }
    }

    close(pagemap_fd);
    return 0;
}

void peek_physmap_free() {
    for (int i = 0; i < nr_pm_decode_roots; i++) {
        physmap_decode_t *next = physmap_decode[i];
        physmap_decode_t *cursor = next;
        while (next != NULL) {
            next = cursor->next;
            free(cursor);
            cursor = next;
        }
    }
    free(physmap_decode);
}