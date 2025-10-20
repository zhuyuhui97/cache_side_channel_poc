#include <stdint.h>

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
    void **list;
    uint64_t available;
} prime_set_t;
