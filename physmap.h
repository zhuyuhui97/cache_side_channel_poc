#ifndef _PHYSMAP_H_
#define _PHYSMAP_H_
#include <stdint.h>
#include <unistd.h> /* pread, sysconf */
#include "env.h"

typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

typedef struct pagemap_decode_t {
    uint64_t addr;
    struct pagemap_decode_t *next;
} physmap_decode_t;

extern physmap_decode_t **physmap_decode;

int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr);
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr);
int peek_physmap(pagemap_t pmap, pid_t pid);
#endif