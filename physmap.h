#include <stdint.h>
#include <unistd.h> /* pread, sysconf */

typedef struct {
    uint64_t pfn : 54;
    unsigned int soft_dirty : 1;
    unsigned int file_page : 1;
    unsigned int swapped : 1;
    unsigned int present : 1;
} PagemapEntry;

int pagemap_get_entry(PagemapEntry *entry, int pagemap_fd, uintptr_t vaddr);
int virt_to_phys_user(uintptr_t *paddr, pid_t pid, uintptr_t vaddr);